"""
Timing-layer executor: drains due actions against the backends and
due results into the result registry (doc 05 §4.6, §4.8).

timing.py only enqueues and times; it does not act. This module is the
half doc 05 §4.6 named as not-yet-wired: "the executor that drains due
actions ... and the consumer that drains due results." Both sides ride
timing.py's one defer-then-pop substrate (pending_actions /
pending_results).

Scope (sp-uwa0v0): all four gateway write ops drain their real
backend through one _HANDLERS table - the eCash writes fund_ecash /
defund_ecash (doc 07 §3) plus the happy-path sends manage_bitcoin
(on-chain) and manage_lightning (LN pay). This is the shared
timing-layer executor the design always intended ("the same
timing-layer executor that gates the other happy-path sends",
doc 07 §9). No write op terminates at a not_implemented stub any
more; only an unknown op does, and the gateway HITL-parks that
rather than enqueueing it.

Flow (ecash mode, doc 07 §3):

  submit -> gateway gates -> timing.enqueue_action(handle, op, params)
         -> [action delay] -> execute_due_actions() runs the op handler
         -> timing.enqueue_result(handle, result)
         -> [result delay] -> deliver_due_results() -> results.deposit()
         -> petitioner polls the handle and learns the outcome.

The drainer also carries the read-snapshot refresh sweep (doc 15,
snapshots.py): each tick, refresh_read_snapshots() re-reads the
backends for any read op whose randomized refresh epoch has elapsed
and stores the presented+quantized value the gateway serves. The
sweep's clock is event-independent by design - it ticks here, off the
request path, never on wallet activity.

Threading. The gateway request path is single-threaded by design (doc
05 §4.1, for latency-normalization predictability). This drainer runs
in a SEPARATE daemon thread started at boot (arbiter.main). It never
touches the request/response path, so it does not perturb latency
normalization. It reaches the database only through state.connect() (a
fresh connection per call, safe across threads under SQLite WAL) and
audit.record() (in-process lock) - the same primitives every subsystem
uses. The exit loop drives drain explicitly (execute_due_actions(now=)
/ deliver_due_results(now=)) instead of starting the thread, so it can
force-drain a submitted action without a wall-clock wait.

Mint-boundary timing (doc 07 §6 T1). The eCash handlers sleep
timing.mint_gap_s() between mint-facing steps so back-to-back
automation does not fingerprint every funding event as one caller to
the mint. Those gaps ride INSIDE the action-delay window (they shape
micro-timing, not macro placement). mint_gap_s(), like every other
production timing path, raises NotImplementedError outside test mode -
which is consistent: production enqueue is itself
NotImplementedError-gated (timing.enqueue_action), so no production
action is ever drained until the dynamic-window work lands (doc 07
§7, §10.1). Reaching a handler at all therefore implies test mode.

Lazy backend imports. bitcoin.py / lnd.py / ecash.py are imported
INSIDE the handlers, never at module top, so importing this module at
boot pulls in none of bitcoin-cli / lncli / nutshell. A handler
imports only the backend its op needs, and only when the op is drained:
manage_bitcoin imports lnd.py in a Lightning/eCash deployment and
bitcoin.py in the onchain default; manage_lightning and the eCash writes
import only what their (Lightning / eCash) mode already implies. An
onchain deployment thus never imports lnd.py or ecash.py, and a
lightning deployment never imports ecash.py - preserving the exit
loop's no-lnd-import / no-ecash-import gates (doc 07 §9).

Hide-secrets discipline (doc 05 §4.1). The petitioner-facing result
payloads are constructed here deliberately and carry only AI-
appropriate fields: a fund returns its handoff token (the AI's float,
by design) and the requested amount (which the AI chose); a defund
returns success and the gross amount. Backend error detail, LN
preimages, proof secrets, fees, and quote ids never enter the payload;
fees and causes are audit-logged for the operator only.

Stdlib only.
"""
import json
import math
import os
import re
import threading
import time

import audit
import results
import snapshots
import timing


# Satoshis per bitcoin. bitcoin.sendtoaddress takes a BTC decimal
# string, never a float (float -> str loses sat precision); the
# manage_bitcoin handler converts the AI's integer-sat amount with
# _btc_str() using exact integer arithmetic.
_SATS_PER_BTC = 100_000_000


# === nutshell stdout parsers ========================================
#
# The cashu wrapper (ecash.py) returns raw human-oriented stdout and
# defers parsing to here (doc 07 §2). These parsers are pinned to the
# nutshell 0.18.1 CLI surface verified at sp-uy29gy against the live
# cashu.mutinynet.com mint (whose advertised version is Nutshell/0.18.1
# - the client is version-matched so the keyset/quote schemas line up).
# A shape a parser cannot read raises EcashParseError, which the
# handler turns into a uniform failed result plus an audit event,
# rather than guessing a wrong amount.

class EcashParseError(Exception):
    """A cashu stdout shape the executor could not parse. Stays
    arbiter-internal; the petitioner only ever sees a uniform failed
    result."""


# `cashu invoice <amt> --no-check` prints (amid mnemonic/balance noise)
# an `Invoice: <bolt11>` line - the funding invoice to pay - and a
# `... cashu invoice <amt> --id <quote_id>` hint line carrying the
# quote id to issue against. Match both anywhere in stdout.
_BOLT11_RE = re.compile(r"Invoice:\s*(ln[a-z0-9]+)", re.IGNORECASE)
_QUOTE_ID_RE = re.compile(r"--id\s+(\S+)")
# A serialized token: `cashuB...` (V4/CBOR) or `cashuA...` (V3/JSON),
# followed by base64url. Require a run so the literal word "cashuB" in
# prose never matches.
_TOKEN_RE = re.compile(r"(cashu[AB][A-Za-z0-9_=-]{20,})")
# `cashu pay` melt output carries a fee like `... (fee 2 sat)`.
# Best-effort: absence is not an error (fee accounting is operator
# bookkeeping, doc 07 §10.4).
_FEE_RE = re.compile(r"fee[:\s]+([0-9]+)\s*sat", re.IGNORECASE)
# A settled melt: `cashu pay` prints "Invoice paid. (Preimage: <hex>)"
# only when the mint's LN payment actually completed (a preimage is
# revealed solely on settlement). A pending or failed melt prints
# neither - the proofs go to the wallet's pending set and the target
# invoice is never paid. The defund handler requires this signal so a
# stuck melt does not report a false "defunded" (verified against
# nutshell 0.18.1 / the live cashu.mutinynet.com mint at sp-uwa0v0).
_MELT_PAID_RE = re.compile(r"invoice paid|preimage", re.IGNORECASE)


def _parse_mint_quote(stdout):
    """Return (bolt11, quote_id) from `cashu invoice <amt> --no-check`.
    Raises EcashParseError if either is absent."""
    m_inv = _BOLT11_RE.search(stdout)
    m_id = _QUOTE_ID_RE.search(stdout)
    if not m_inv or not m_id:
        raise EcashParseError("could not parse mint quote bolt11 / quote id")
    return m_inv.group(1), m_id.group(1)


def _parse_token(stdout):
    """Return the serialized cashu token from `cashu send` output. The
    longest match wins, defensive against surrounding words."""
    matches = _TOKEN_RE.findall(stdout)
    if not matches:
        raise EcashParseError("could not parse cashu token from send output")
    return max(matches, key=len)


def _parse_fee_sat(stdout):
    """Best-effort melt fee in sat from `cashu pay` output, or None."""
    m = _FEE_RE.search(stdout)
    return int(m.group(1)) if m else None


def _melt_settled(stdout):
    """True iff `cashu pay` reported the melt actually settled (the
    mint's LN payment to our invoice completed). A pending/failed melt
    returns False so the defund handler raises rather than reporting a
    false 'defunded' - the round-trip is only real when our invoice is
    paid (doc 08 §1 step 5)."""
    return bool(_MELT_PAID_RE.search(stdout or ""))


def _norm_mint_url(url):
    """Normalize a mint URL for the pin comparison: trim, drop a
    trailing slash, lowercase. Mint URLs are scheme+host(+port); this
    folds the cosmetic differences (trailing slash, host case) that
    must not let a same-mint token read as foreign."""
    return (url or "").strip().rstrip("/").lower()


# === melt fee reserve ==============================================
#
# A defund melts proofs to pay a fresh LND invoice; the mint must make
# an outgoing LN payment to reach us, for which it holds back a fee
# reserve. We therefore size the invoice below the claimed value so the
# wallet's balance covers invoice + reserve. The exact reserve is the
# mint's; this is a conservative pre-estimate for signet test mints.
# funded != received and defunded != credited by exactly these fees
# (doc 07 §10.4); the actual fee is audit-logged per op.
_MELT_RESERVE_PCT = 0.02   # 2%
_MELT_RESERVE_MIN_SAT = 2


def _melt_fee_reserve(amount_sats):
    return max(_MELT_RESERVE_MIN_SAT, math.ceil(amount_sats * _MELT_RESERVE_PCT))


def _mint_gap():
    """Sleep one randomized mint-boundary gap (doc 07 §6 T1). In test
    mode 0.5-2s; in production timing.mint_gap_s() raises (the gap
    source is unresolved, doc 07 §10.1) - unreachable here because no
    production action is ever enqueued."""
    time.sleep(timing.mint_gap_s())


# === op handlers ====================================================
#
# Each handler takes (handle, params) and returns the petitioner-facing
# result payload. Raising is allowed: execute_due_actions() catches it,
# audit-logs the cause, and enqueues a uniform failed result so the
# petitioner still gets a terminal outcome.

def _execute_fund_ecash(handle, params):
    """fund_ecash (doc 07 §3): request a mint quote, pay its bolt11 via
    our LND, issue the proofs, serialize a DLEQ handoff token for the
    AI. mint_gap_s() rides between the three mint-facing steps (quote
    -> pay -> issue)."""
    import ecash
    import lnd

    amount_sats = int(params["amount_sats"])

    # 1. Mint quote: the bolt11 to pay and the quote id to issue against
    #    (no payment yet, --no-check).
    bolt11, quote_id = _parse_mint_quote(ecash.mint_quote(amount_sats))

    _mint_gap()

    # 2. Pay the mint's bolt11 from our LND. The mint sees an HTLC
    #    arrive (doc 07 §5.1); the routing fee is operator cost.
    pay = lnd.payinvoice(bolt11)
    status = (pay.get("status") or "").upper()
    if status not in ("SUCCEEDED", "SUCCESS"):
        raise ecash.EcashError(f"funding LN payment not successful: {status!r}")
    routing_fee_msat = int(pay.get("fee_msat") or 0)

    _mint_gap()

    # 3. Issue the proofs against the now-paid quote (mint completes).
    ecash.mint(amount_sats, quote_id)

    # 4. Serialize the float into a DLEQ handoff token for the AI.
    token = _parse_token(ecash.send(amount_sats))

    # 5. Ledger: record the gross funded amount (doc 07 §8, §10.4).
    ecash.record_funded(handle, amount_sats)

    # Fee accounting (doc 07 §10.4: funded != received). The LN routing
    # fee is operator cost, audit-logged, not deducted from the float.
    audit.record(
        "ecash_fund_executed",
        {
            "handle": handle,
            "amount_sats": amount_sats,
            "ln_routing_fee_msat": routing_fee_msat,
        },
    )
    return {"status": "funded", "amount_sats": amount_sats, "token": token}


def _execute_defund_ecash(handle, params):
    """defund_ecash (doc 07 §3): swap-claim the petitioner's token at
    the pinned mint, then melt the proofs to a fresh invoice from our
    own LND so the value returns to the operator's wallet.

    The mint pin (doc 07 §2) is enforced HERE, offline, before any mint
    contact: `cashu decode` reveals the token's embedded mint URL and a
    foreign-mint token is refused without a swap. mint_gap_s() rides
    between the swap-claim and the melt."""
    import ecash
    import lnd

    token = params["token"]

    # 0. Mint-pin enforcement (doc 07 §2), offline via `cashu decode`.
    claimed_sats = _decode_and_pin(ecash, token)

    # 1. Swap-claim the token into our transient wallet.
    ecash.receive(token)

    _mint_gap()

    # 2. Melt to a fresh invoice from our LND, sized below the claimed
    #    value to leave room for the mint's melt fee reserve.
    reserve = _melt_fee_reserve(claimed_sats)
    invoice_sats = claimed_sats - reserve
    if invoice_sats <= 0:
        raise ecash.EcashError(
            "defund amount {} too small for melt reserve {}".format(
                claimed_sats, reserve
            )
        )
    bolt11 = lnd.addinvoice(invoice_sats, memo="spacer-defund")

    _mint_gap()

    # 3. Melt: the mint pays our invoice. Require an actually-settled
    #    melt (preimage revealed) - a pending or failed melt leaves the
    #    proofs in the wallet's pending set and our invoice unpaid, and
    #    must NOT report a false "defunded" (the value has not returned
    #    to our LN wallet). Raising here surfaces it as a uniform failed
    #    result and leaves the ledger untouched (the gross value did not
    #    leave the float).
    melt_out = ecash.pay(bolt11)
    if not _melt_settled(melt_out):
        raise ecash.EcashError("defund melt did not settle (pending or failed)")
    melt_fee = _parse_fee_sat(melt_out)

    # 4. Ledger: the gross claimed value left the float (doc 07 §8).
    ecash.record_defunded(handle, claimed_sats)
    audit.record(
        "ecash_defund_executed",
        {
            "handle": handle,
            "claimed_sats": claimed_sats,
            "credited_sats": invoice_sats,
            "melt_fee_sat": melt_fee,
        },
    )
    return {"status": "defunded", "amount_sats": claimed_sats}


def _decode_and_pin(ecash, token):
    """Decode the token offline, enforce the operator-pinned mint (doc
    07 §2), and return its total proof value in sats. Refuses a
    foreign-mint or zero-value token before any network contact."""
    pinned = _norm_mint_url(ecash._mint_url())  # raises if unset (doc 07 §2)
    try:
        decoded = json.loads(ecash.decode(token))
    except ValueError:
        raise ecash.EcashError("could not decode defund token")
    mint_urls, total = _token_mint_and_value(decoded)
    if not mint_urls or any(_norm_mint_url(u) != pinned for u in mint_urls):
        # Do NOT include the URLs in the petitioner-facing path; the
        # audit detail stays operator-side via the handler's catch.
        raise ecash.EcashError("defund token is not from the pinned mint")
    if total <= 0:
        raise ecash.EcashError("defund token has no value")
    return total


def _token_mint_and_value(decoded):
    """Return (set of mint URLs, total sats) from a `cashu decode` dict,
    handling both serialization shapes (verified against nutshell 0.18.1
    at sp-uy29gy):

    - V4 cashuB (the current default): compact keys - top-level "m" is
      the mint URL, "u" the unit, "t" a list of {"i": keyset, "p":
      [{"a": amount, "s","c","d"(dleq)}]}.
    - V3 cashuA (legacy --legacy output): "token" is a list of {"mint":
      <url>, "proofs": [{"amount": n}]}.

    A single mint per token in practice; the set keeps the pin check
    honest if a multi-entry token ever spans mints."""
    # V4 cashuB.
    if isinstance(decoded.get("t"), list):
        mint = decoded.get("m")
        mints = {mint} if mint else set()
        total = sum(
            int(p.get("a", 0))
            for e in decoded["t"]
            for p in (e.get("p") or [])
        )
        return mints, total
    # V3 cashuA.
    entries = decoded.get("token") or []
    mints = {e.get("mint") for e in entries if e.get("mint")}
    total = sum(
        int(p.get("amount", 0))
        for e in entries
        for p in (e.get("proofs") or [])
    )
    return mints, total


# === on-chain / lightning send handlers =============================

def _btc_str(amount_sats):
    """Format an integer sat amount as a BTC decimal string for
    bitcoin.sendtoaddress, which takes BTC and must never be handed a
    float (float -> str loses satoshi precision; see
    bitcoin.sendtoaddress). 12_345 sat -> "0.00012345". Exact integer
    arithmetic, zero-padded to eight fractional digits."""
    sats = int(amount_sats)
    return "{}.{:08d}".format(sats // _SATS_PER_BTC, sats % _SATS_PER_BTC)


def _advanced_mode():
    """True iff the deployment runs the advanced Lightning / eCash
    extension (SPACER_MODE in {lightning, full, ecash}).

    Read from the environment here rather than imported from gateway so
    the executor stays decoupled from the request path, mirroring how
    timing.py / scale.py each read their own mode env var. It selects
    the on-chain backend for manage_bitcoin: the LND on-chain wallet when
    a Lightning extension is present (the only on-chain wallet such a
    deployment runs), bitcoind in the onchain default - the same split
    query_balance makes in gateway._dispatch."""
    return os.environ.get("SPACER_MODE", "onchain").strip().lower() in (
        "lightning",
        "full",
        "ecash",
    )


def _consume_registry_token(params, consumed_by):
    """One-time-use enforcement (§4.7, GLOSSARY 'Recipient address
    registry'): flip the resolved registry entry to used once the send
    actually happened, recording the txid (Bitcoin) or payment hash
    (Lightning) as consumed_by. The token rides in the timing params
    only for the registry-gated ops (manage_bitcoin / manage_lightning
    via gateway._registry_write_params); the eCash writes carry none
    and skip this. registry is imported lazily to keep this module's
    boot import surface unchanged. A failed flip is audit-logged for
    operator triage (registry.consume logs its own refusal too); it
    never surfaces to the petitioner - the send itself already
    succeeded."""
    token = params.get("recipient_token")
    if not token:
        return
    import registry
    if not registry.consume(token, consumed_by):
        audit.record(
            "executor_consume_failed",
            {"token": token, "consumed_by": consumed_by},
        )


def _execute_manage_bitcoin(handle, params):
    """manage_bitcoin (doc 05 §4.6): broadcast an on-chain payment to the
    registry-resolved recipient address once the action-delay window has
    elapsed.

    Backend by deployment mode, mirroring query_balance's split
    (gateway._dispatch): the LND on-chain wallet (lnd.sendcoins, integer
    sats) when a Lightning/eCash extension is enabled, bitcoind
    (bitcoin.sendtoaddress, a BTC decimal string) in the onchain
    default. Either node runs coin-selection, change derivation,
    signing, and broadcast internally; only the txid returns.

    Hide-secrets discipline (doc 05 §4.1): the txid and the on-chain
    fee stay operator-side (audit only). The petitioner-facing payload
    carries just the success marker and the amount the AI chose -
    surfacing the txid would re-link the request to a public chain
    entry the privacy gateway otherwise keeps unlinked."""
    address = params["recipient_address"]
    amount_sats = int(params["amount_sats"])
    if _advanced_mode():
        import lnd
        txid = lnd.sendcoins(address, amount_sats)
    else:
        import bitcoin
        txid = bitcoin.sendtoaddress(address, _btc_str(amount_sats))
    _consume_registry_token(params, txid)
    audit.record(
        "manage_bitcoin_executed",
        {"handle": handle, "amount_sats": amount_sats, "txid": txid},
    )
    return {"status": "sent", "amount_sats": amount_sats}


def _execute_manage_lightning(handle, params):
    """manage_lightning (doc 05 §4.6): pay the registry-resolved bolt11
    over our LND node once the action-delay window has elapsed. An
    extension op, so this path only runs with the LND module present.

    recipient_address IS the bolt11 invoice: the registry resolves a
    petitioner token to the real invoice (gateway._pseudonymize_inbound),
    and payinvoice pays the invoice's own encoded amount. The gateway's
    resolved-amount gate already pinned that encoded amount equal to
    the gate-declared amount_sats (ladder + standing-approval bound run
    against it); the pre-pay assertion here re-derives it from the same
    frozen bolt11 and aborts on any divergence, so a future path that
    enqueues manage_lightning without the gate fails loudly instead of
    paying an unbounded amount. Failure lands in the standard
    executor_action_failed path: uniform failed result, cause in the
    audit log only.

    Hide-secrets discipline (doc 05 §4.1): the preimage and the routing
    fee stay operator-side (audit only); the petitioner sees only the
    success marker and the chosen amount."""
    import lnd
    bolt11 = params["recipient_address"]
    amount_sats = params.get("amount_sats")
    import registry
    invoice_sats = registry.bolt11_amount_sats(bolt11)
    if invoice_sats is None or invoice_sats != amount_sats:
        raise ValueError(
            "manage_lightning amount not bound by gate: "
            f"invoice encodes {invoice_sats!r} sats, "
            f"gate-declared {amount_sats!r} sats"
        )
    pay = lnd.payinvoice(bolt11)
    status = (pay.get("status") or "").upper()
    if status not in ("SUCCEEDED", "SUCCESS"):
        raise lnd.LndError(f"lightning payment not successful: {status!r}")
    _consume_registry_token(params, pay.get("payment_hash") or "ln_payment")
    audit.record(
        "manage_lightning_executed",
        {
            "handle": handle,
            "amount_sats": amount_sats,
            "ln_routing_fee_msat": int(pay.get("fee_msat") or 0),
        },
    )
    result = {"status": "sent"}
    if isinstance(amount_sats, int):
        result["amount_sats"] = amount_sats
    return result


# Op -> handler. All four gateway write ops resolve here. An op the
# gateway enqueues with no handler gets a logged failure (see
# execute_due_actions), never a silent drop; in practice that cannot
# happen because the gateway HITL-parks an unknown op rather than
# enqueueing it - the not_implemented stub is gone from the write path.
_HANDLERS = {
    "manage_bitcoin": _execute_manage_bitcoin,
    "manage_lightning": _execute_manage_lightning,
    "fund_ecash": _execute_fund_ecash,
    "defund_ecash": _execute_defund_ecash,
}


# === drainers =======================================================

def execute_due_actions(now=None):
    """Run every action whose action-delay window has elapsed.

    Pops due actions from timing.pending_actions, runs the matching op
    handler, and enqueues the outcome on the result side (which the
    result-delay window then holds). A handler that raises - backend
    failure, parse failure, the doc 07 §3 double-spend race - is caught
    and enqueued as a uniform failed result so the petitioner still
    gets a terminal outcome on poll. Returns the count drained. now is
    for the exit loop's forced-drain; production passes None."""
    drained = 0
    for handle, op, params in timing.due_actions(now=now):
        handler = _HANDLERS.get(op)
        if handler is None:
            audit.record("executor_no_handler", {"handle": handle, "op": op})
            result = {"status": "failed"}
        else:
            try:
                result = handler(handle, params)
            except Exception as e:
                # Cause stays arbiter-side (audit only, truncated); the
                # petitioner sees a uniform failure (doc 05 §4.1).
                audit.record(
                    "executor_action_failed",
                    {"handle": handle, "op": op, "error": str(e)[:200]},
                )
                result = {"status": "failed"}
        timing.enqueue_result(handle, result, kind="result")
        drained += 1
    return drained


def deliver_due_results(now=None):
    """Deposit every result whose result-delay window has elapsed into
    the result registry, where the petitioner's poll picks it up (doc
    05 §4.8). Returns the count delivered. now is for the exit loop's
    forced-drain; production passes None."""
    delivered = 0
    for handle, result, kind in timing.due_results(now=now):
        try:
            results.deposit(handle, result, kind=kind)
        except results.DepositError as e:
            # Duplicate or bad payload is a caller bug, not a petitioner
            # event. Audit-log and skip so one bad row cannot wedge
            # delivery of the rest.
            audit.record(
                "executor_deposit_failed",
                {"handle": handle, "error": str(e)[:200]},
            )
            continue
        delivered += 1
    return delivered


# === read-snapshot refresh sweep ====================================

# One-way latch: set after the first NotImplementedError from the
# snapshot sweep (production epochs are blocked on sp-77lxs.3, doc 15
# §4.4). Without it the drainer would re-raise - and audit-log - the
# same NotImplementedError every tick; with it the operator gets one
# loud snapshot_refresh_unavailable record and a quiet drainer, and
# the gateway keeps refusing reads uniformly (no row is ever written).
_snapshots_unavailable = False


def refresh_read_snapshots(now=None):
    """Run one read-snapshot refresh sweep (snapshots.refresh_due,
    doc 15 §4) on the drainer's clock. Returns the count of ops swept,
    0 once the production gate has latched. now= is for tests; the
    drainer passes None."""
    global _snapshots_unavailable
    if _snapshots_unavailable:
        return 0
    try:
        return snapshots.refresh_due(now=now)
    except NotImplementedError as e:
        _snapshots_unavailable = True
        audit.record("snapshot_refresh_unavailable", {"error": str(e)[:200]})
        return 0


# === background drainer thread ======================================

# How often the drainer wakes to check for due rows. Short enough that
# test-mode 5-15s windows drain promptly; in production the ~12h
# windows make the exact tick irrelevant. Override via
# SPACER_DRAIN_TICK_S.
_DEFAULT_TICK_S = 1.0

_drainer_thread = None
_drainer_stop = None


def _tick_s():
    try:
        return float(os.environ.get("SPACER_DRAIN_TICK_S", _DEFAULT_TICK_S))
    except (TypeError, ValueError):
        return _DEFAULT_TICK_S


def run_forever(stop_event):
    """Drainer loop: refresh due read snapshots, then drain due actions
    and due results, every tick until stop_event is set. A tick-level
    exception is audit-logged and swallowed so a transient backend
    hiccup cannot kill the drainer.

    The snapshot sweep rides this drainer by design (doc 15 §4): the
    refresh clock is arbiter-internal and event-independent, exactly
    like the action/result clocks, and the drainer is the one place
    that already ticks on wall time off the request path."""
    while not stop_event.is_set():
        try:
            refresh_read_snapshots()
            execute_due_actions()
            deliver_due_results()
        except Exception as e:
            audit.record("executor_tick_error", {"error": str(e)[:200]})
        stop_event.wait(_tick_s())


def start_background_drainer():
    """Start the drainer as a daemon thread (idempotent). Called from
    arbiter.main after state is configured.

    Daemon so it dies with the process. The durable record is timing.py's
    pending_actions / pending_results tables, so a killed drainer loses
    no enqueued work: the next boot's drainer picks up rows whose
    ready_at has since elapsed. Idle when nothing is deferred (onchain /
    lightning deployments enqueue no eCash actions), so it imports
    neither ecash.py nor lnd.py in those modes."""
    global _drainer_thread, _drainer_stop
    if _drainer_thread is not None and _drainer_thread.is_alive():
        return _drainer_thread
    _drainer_stop = threading.Event()
    _drainer_thread = threading.Thread(
        target=run_forever,
        args=(_drainer_stop,),
        daemon=True,
        name="spacer-timing-drainer",
    )
    _drainer_thread.start()
    audit.record("executor_drainer_start", {})
    return _drainer_thread


def stop_background_drainer():
    """Signal the drainer to stop and join briefly. For shutdown/tests."""
    global _drainer_thread, _drainer_stop
    if _drainer_stop is not None:
        _drainer_stop.set()
    if _drainer_thread is not None:
        _drainer_thread.join(timeout=2.0)
        _drainer_thread = None


if __name__ == "__main__":
    # Smoke test: drive fund and defund end-to-end through the timing
    # tables and the result registry against a fake cashu + fake lncli
    # (no live mint/node; the live round-trip is the bead's gate). Same
    # fake-subprocess pattern as ecash.py / lnd.py. Exercises the
    # parsers, the mint-pin refusal, the failure path, and the drainers'
    # forced-drain (now=) used by the exit loop.
    import shutil
    import sys
    import tempfile
    from pathlib import Path

    os.environ["SPACER_TIMING_MODE"] = "test"  # short windows + mint gaps
    work = Path(tempfile.mkdtemp(prefix="arbiter-executor-smoke-"))
    pinned_mint = "https://mint.example.test"

    # Fake cashu: outputs mirror the verified nutshell 0.18.1 formats.
    # `decode` echoes the pinned mint unless the token contains
    # "foreign", which lets the mint-pin refusal be exercised.
    fake_cashu = work / "cashu"
    fake_cashu.write_text(
        """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in --host=*|--wallet=*) shift;; *) break;; esac
done
cmd="$1"; shift
case "$cmd" in
  invoice)
    amt="$1"
    case "$*" in
      *--id*) printf 'Balance: %s sat\\nTokens minted.\\n' "$amt";;
      *) printf 'Balance: 0 sat\\nRequesting invoice for %s sat:\\n\\nInvoice: lntbs%sn1pexamplefundinvoice\\n\\nYou can use this command to check the invoice: cashu invoice %s --id QUOTEID123\\n' "$amt" "$amt" "$amt";;
    esac
    ;;
  send) printf 'cashuBfakedleqhandofftokenvectorAAABBBCCCDDD\\n';;
  receive) printf 'Received tokens.\\nBalance: 5000 sat\\n';;
  pay) printf 'Paying Lightning invoice ... Invoice paid. (Preimage: deadbeef01) (fee 3 sat).\\n';;
  balance) printf 'Balance: 5000 sat\\n';;
  decode)
    case "$*" in
      *foreign*) printf '{"t": [{"i": "00ks", "p": [{"a": 4096}, {"a": 904}]}], "m": "https://evil.example.test", "u": "sat"}\\n';;
      *) printf '{"t": [{"i": "00ks", "p": [{"a": 4096}, {"a": 512}, {"a": 256}, {"a": 128}, {"a": 8}]}], "m": "https://mint.example.test", "u": "sat"}\\n';;
    esac
    ;;
  *) echo "fake cashu: unknown $cmd" >&2; exit 64;;
esac
"""
    )
    fake_cashu.chmod(0o755)

    # Fake lncli: payinvoice succeeds; addinvoice returns a bolt11;
    # sendcoins returns a 64-hex txid (the advanced-mode manage_bitcoin
    # backend and the manage_lightning backend).
    fake_lncli = work / "lncli"
    fake_lncli.write_text(
        """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in --rpcserver=*|--tlscertpath=*|--macaroonpath=*|--network=*) shift;; *) break;; esac
done
case "$1" in
  payinvoice) printf '{"status":"SUCCEEDED","payment_preimage":"ab","fee_msat":"1100"}';;
  addinvoice) printf '{"r_hash":"cd","payment_request":"lntbs49u1pexampledefundinvoice","add_index":"9"}';;
  sendcoins) printf '{"txid":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}';;
  *) echo "fake lncli: unknown $1" >&2; exit 64;;
esac
"""
    )
    fake_lncli.chmod(0o755)

    # Fake bitcoin-cli: sendtoaddress echoes a 64-hex txid (the onchain
    # manage_bitcoin backend, used when SPACER_MODE is unset);
    # getbalance feeds the read-snapshot sweep sub-test.
    fake_bitcoin = work / "bitcoin-cli"
    fake_bitcoin.write_text(
        """#!/bin/sh
case "$1" in -datadir=*) shift;; esac
case "$1" in
  sendtoaddress) printf 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';;
  getbalance) printf '0.00050000';;
  *) echo "fake bitcoin-cli: unknown $1" >&2; exit 64;;
esac
"""
    )
    fake_bitcoin.chmod(0o755)

    os.environ["CASHU_BIN"] = str(fake_cashu)
    os.environ["CASHU_MINT_URL"] = pinned_mint
    os.environ["CASHU_DIR"] = str(work / "wallet")
    os.environ["CASHU_TIMEOUT_S"] = "5"
    os.environ["LNCLI_BIN"] = str(fake_lncli)
    os.environ["LNCLI_TIMEOUT_S"] = "5"
    os.environ["BITCOIN_CLI_BIN"] = str(fake_bitcoin)
    os.environ["BITCOIN_DATADIR"] = str(work)
    os.environ["BITCOIN_CLI_TIMEOUT_S"] = "5"
    # manage_bitcoin's backend is mode-selected; default to onchain
    # (bitcoind) and flip to advanced (LND) in the relevant sub-test.
    os.environ.pop("SPACER_MODE", None)

    audit.configure(work / "audit.log")
    # state is the framework results/timing register their tables with;
    # configure + migrate it so the smoke test's tables exist.
    import state
    state.configure(work / "state.db")
    state.migrate()

    far = time.time() + 10_000.0  # force-drain cutoff (exit-loop pattern)

    try:
        # --- parser unit checks -------------------------------------
        bolt11, qid = _parse_mint_quote(
            "Balance: 0 sat\nInvoice: lntbs50n1pabc\n"
            "...: cashu invoice 5 --id ABC_123\n"
        )
        assert bolt11 == "lntbs50n1pabc", bolt11
        assert qid == "ABC_123", qid
        assert _parse_token("Token:\ncashuBdeadbeefdeadbeefdeadbeef0123\n").startswith(
            "cashuB"
        )
        assert _parse_fee_sat("Paid invoice (fee 7 sat).") == 7
        assert _parse_fee_sat("no fee here") is None
        assert _melt_fee_reserve(5000) == 100  # 2%
        assert _melt_fee_reserve(10) == 2      # floor

        # _token_mint_and_value handles both V4 (compact m/t/p/a) and
        # V3 (token/mint/proofs/amount) decode shapes.
        m4, t4 = _token_mint_and_value(
            {"t": [{"p": [{"a": 3}, {"a": 2}]}], "m": "https://mint.x", "u": "sat"}
        )
        assert m4 == {"https://mint.x"} and t4 == 5, (m4, t4)
        m3, t3 = _token_mint_and_value(
            {"token": [{"mint": "https://mint.y", "proofs": [{"amount": 7}]}]}
        )
        assert m3 == {"https://mint.y"} and t3 == 7, (m3, t3)

        # --- fund: enqueue -> execute -> deliver -> poll ------------
        h_fund = "handle_fund_smoke"
        timing.enqueue_action(h_fund, "fund_ecash", {"amount_sats": 5000})
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, kind = results.poll(h_fund)
        assert status == "result", (status, payload)
        assert payload["status"] == "funded", payload
        assert payload["amount_sats"] == 5000, payload
        assert payload["token"].startswith("cashuB"), payload
        assert kind == "result", kind

        # Ledger moved by the gross funded amount.
        import ecash
        assert ecash.outstanding_sats() == 5000, ecash.outstanding_sats()

        # --- defund happy path: claimed 5000, melt -----------------
        h_defund = "handle_defund_smoke"
        timing.enqueue_action(h_defund, "defund_ecash", {"token": "cashuBgoodtoken"})
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_defund)
        assert status == "result", status
        assert payload == {"status": "defunded", "amount_sats": 5000}, payload
        # Ledger floored back to 0 (5000 funded - 5000 defunded).
        assert ecash.outstanding_sats() == 0, ecash.outstanding_sats()

        # --- mint-pin refusal: a foreign-mint token fails ----------
        h_foreign = "handle_defund_foreign"
        timing.enqueue_action(
            h_foreign, "defund_ecash", {"token": "cashuBforeigntoken"}
        )
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_foreign)
        assert status == "result", status
        assert payload == {"status": "failed"}, payload
        # A failed defund does NOT move the ledger (doc 07 §3).
        assert ecash.outstanding_sats() == 0, ecash.outstanding_sats()

        # --- manage_lightning: pay a bolt11 over LND (fake payinvoice) -
        # recipient_address IS the resolved bolt11; its HRP amount
        # (10u = 1000 sats) must match the gate-declared amount_sats or
        # the pre-pay assertion aborts before payinvoice.
        h_ln = "handle_manage_lightning"
        timing.enqueue_action(
            h_ln, "manage_lightning",
            {"recipient_address": "lntbs10u1pfakesendinvoice", "amount_sats": 1000},
        )
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_ln)
        assert status == "result", status
        assert payload == {"status": "sent", "amount_sats": 1000}, payload

        # --- manage_lightning, invoice amount != declared amount ------
        # The invoice encodes 10n = 1 sat but the params claim 1000:
        # the pre-pay assertion must abort (no payinvoice) and surface
        # the uniform failed result via executor_action_failed. This is
        # the executor half of the sp-l0c fix; the gateway half refuses
        # the same divergence at gate time.
        h_ln_bad = "handle_manage_lightning_mismatch"
        timing.enqueue_action(
            h_ln_bad, "manage_lightning",
            {"recipient_address": "lntbs10n1pfakesendinvoice", "amount_sats": 1000},
        )
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_ln_bad)
        assert status == "result", status
        assert payload == {"status": "failed"}, payload

        # --- manage_bitcoin, onchain default -> bitcoin.py ------------
        # SPACER_MODE unset -> _advanced_mode() False -> bitcoind. The
        # amount is converted to a BTC decimal string by _btc_str.
        os.environ.pop("SPACER_MODE", None)
        h_btc = "handle_manage_bitcoin_onchain"
        timing.enqueue_action(
            h_btc, "manage_bitcoin",
            {"recipient_address": "tb1qexampleonchain", "amount_sats": 2000},
        )
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_btc)
        assert status == "result", status
        assert payload == {"status": "sent", "amount_sats": 2000}, payload

        # --- consume-on-success: one-time-use enforcement (§4.7) -----
        # A registry-gated write whose params carry recipient_token
        # flips the entry to used after the backend send succeeds,
        # recording the txid as consumed_by. The re-lookup refuses.
        import registry
        registry.configure(work / "destinations.yaml")
        _, tok_consume = registry.add(
            "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"
        )
        h_btc_c = "handle_manage_bitcoin_consume"
        timing.enqueue_action(
            h_btc_c, "manage_bitcoin",
            {"recipient_address": "tb1qexampleonchain", "amount_sats": 500,
             "recipient_token": tok_consume},
        )
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_btc_c)
        assert payload == {"status": "sent", "amount_sats": 500}, payload
        st_c, _, _ = registry.lookup(tok_consume)
        assert st_c == "used", st_c

        # --- manage_bitcoin, advanced mode -> LND on-chain wallet ----
        # SPACER_MODE=ecash -> _advanced_mode() True -> lnd.sendcoins,
        # the same backend the live signet round-trip exercises.
        os.environ["SPACER_MODE"] = "ecash"
        h_btc2 = "handle_manage_bitcoin_lnd"
        timing.enqueue_action(
            h_btc2, "manage_bitcoin",
            {"recipient_address": "tb1qexamplelnd", "amount_sats": 3000},
        )
        assert execute_due_actions(now=far) == 1
        assert deliver_due_results(now=far) == 1
        status, payload, _ = results.poll(h_btc2)
        assert status == "result", status
        assert payload == {"status": "sent", "amount_sats": 3000}, payload
        os.environ.pop("SPACER_MODE", None)

        # --- unknown op -> logged failure, terminal result ---------
        # A genuinely unknown op (every named write op now has a
        # handler); the drainer logs executor_no_handler and still
        # delivers a uniform terminal failure.
        h_unknown = "handle_unknown_op"
        timing.enqueue_action(h_unknown, "frobnicate_op", {"x": 1})
        assert execute_due_actions(now=far) == 1
        deliver_due_results(now=far)
        status, payload, _ = results.poll(h_unknown)
        assert payload == {"status": "failed"}, payload

        # --- read-snapshot sweep (doc 15) ---------------------------
        # The drainer's per-tick sweep: onchain mode (SPACER_MODE
        # unset) refreshes query_balance from the fake bitcoin-cli
        # (0.00050000 BTC -> 50_000 sats, T0 no-cloak, grid-aligned).
        os.environ["SPACER_SCALE_MODE"] = "test"
        assert refresh_read_snapshots() == 1
        served, age = snapshots.serve("query_balance")
        assert served == 50_000, served
        assert age < 5.0, age

        # Production gate latches once: with test mode off the sweep
        # audit-logs snapshot_refresh_unavailable a single time and
        # returns 0 thereafter (no per-tick raise/log spam).
        snapshots.seed_for_test(
            "query_balance", 50_000, time.time(), time.time() - 1.0
        )  # due row, so the sweep must draw a window and hit the gate
        del os.environ["SPACER_TIMING_MODE"]
        assert refresh_read_snapshots() == 0
        assert _snapshots_unavailable is True
        assert refresh_read_snapshots() == 0  # latched, quiet
        os.environ["SPACER_TIMING_MODE"] = "test"
        _snapshots_unavailable = False  # restore for any later sub-test

        # --- audit trail carries the executor's events -------------
        events = [
            json.loads(line)["event"]
            for line in (work / "audit.log").read_text().splitlines()
            if line.strip()
        ]
        for required in (
            "ecash_fund_executed",
            "ecash_defund_executed",
            "ecash_ledger_fund",
            "ecash_ledger_defund",
            "manage_bitcoin_executed",    # onchain + LND send sub-tests
            "manage_lightning_executed",  # the LN pay sub-test
            "registry_consume",           # consume-on-success sub-test
            "executor_action_failed",  # the foreign-mint refusal
            "executor_no_handler",     # the unknown op
            "snapshot_refresh",        # the read-snapshot sweep
        ):
            assert required in events, (required, sorted(set(events)))
        # The production gate audit-logged exactly once (the latch).
        assert events.count("snapshot_refresh_unavailable") == 1, events

        print(f"OK: executor send + fund/defund round-trips (fakes) at {work}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    sys.exit(0)
