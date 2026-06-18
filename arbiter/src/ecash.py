"""
eCash extension access: subprocess wrapper for the nutshell `cashu`
CLI wallet, plus the allowance policy that bounds the AI's float.

Per design-docs/origin/07--2026-06-12-0916-ecash-extension.md §2, §3,
§8, §9.

THIS MODULE IS LAZILY IMPORTED. The gateway pulls it in via
gateway._ecash() only on an ecash-mode (SPACER_MODE=ecash) dispatch,
mirroring how lnd.py is pulled in by gateway._lnd(). An onchain or
lightning deployment never loads it and carries no nutshell
dependency at runtime (doc 07 §9). The exit-loop runner asserts this
with a no-ecash-import gate, the eCash analogue of the no-lnd-import
gate.

Wrapper choice: shells out to the nutshell `cashu` CLI via
subprocess (argv list, no shell), mirroring bitcoin.py / lnd.py. The
arbiter controls the binary path, the mint URL, and the wallet data
dir explicitly so a non-AI reviewer can audit exactly what executes
(doc 05 §2.1). nutshell sits in bin/-style upstream territory like
lncli does (doc 07 §2).

Wallet selection is by CASHU_DIR alone - the default nutshell wallet,
no `--wallet NAME`. A named wallet is deliberately avoided: nutshell
0.18.1's `receive` ignores `--wallet` and writes the swapped-in proofs
to the default wallet's DB while `balance`/`pay` read the named one, so
a defund would melt against an empty named wallet (verified live at
sp-uwa0v0). One wallet per CASHU_DIR keeps every op - mint, send,
receive, melt - on the same DB; deployment isolation is the data dir.

The mint URL is operator-pinned and NEVER AI-suppliable (doc 07 §2):
there is no default mint, and a missing CASHU_MINT_URL raises rather
than falling back to some public mint - choosing the counterparty
that custodies the float is an operator decision, full stop. A
defund token minted elsewhere is refused when the executor's
swap-claim runs against the pinned mint (the wallet only talks to
the configured mint; the mint-pin check is executor-time because
only the wallet can decode the token's embedded mint URL).

nutshell CLI surface (VERIFIED against nutshell 0.18.1 at sp-uy29gy,
the client version matched to the cashu.mutinynet.com mint's
advertised Nutshell/0.18.1): the subcommand names and flags below
were exercised against a real nutshell install and the live mint.
Confirmed: `balance`, `invoice <amt> --no-check` (request a mint
quote: prints the bolt11 to pay and a quote id) / `invoice <amt>
--id <quote>` (issue once the quote is paid), `pay -y <bolt11>`
(melt), `send -y -d <amt>` (serialize a DLEQ handoff token),
`receive <token>`, `decode <token>` (JSON), `info`. Corrections
folded in from the originally-assumed surface: `pay` and `send` need
-y because the arbiter has no operator at the cashu stdin (the
prompt would block), `send` takes -d so the handoff token carries
DLEQ proofs (doc 07 §2), and `decode` (JSON) is the executor's
offline mint-pin check (doc 07 §2). All calls except `decode` still
return raw human-oriented stdout; the executor parses it (the live
formats are pinned in arbiter/src/executor.py's parse helpers).

Timing discipline at the mint boundary: the mint is an EXTERNAL
third party, outside the trusted boundary that bitcoind and LND sit
inside - the no-internal-mitigations rule does NOT apply to it (doc
07 §1). The randomized intra-execution gaps between mint-facing
steps (doc 07 §6 T1) are picked by timing.mint_gap_s(); the
timing-layer executor sleeps them between the quote -> pay -> issue
steps when it lands. This module stays a thin wrapper and does not
sleep on its own.

Hide-secrets discipline: proof secrets, blinding factors, and the
wallet's keyset state stay inside the nutshell wallet's own storage
(CASHU_DIR). This module's callers see only command stdout; the
privacy gateway filters anything that would cross the AI-facing
boundary (doc 05 §4.1).

Stdlib only.
"""
import os
import subprocess
import time
from pathlib import Path

import audit
import state

# Deployment defaults mirror bitcoin.py / lnd.py: absolute paths under
# the user's home so the arbiter does not depend on the caller's CWD,
# env-overridable so the test harness can point elsewhere. The wallet
# data dir is the gitignored arbiter/ecash/ runtime subtree (doc 07
# §3, mirroring lnd/).
DEFAULT_BIN = Path.home() / "spacer" / "arbiter" / "bin" / "cashu"
DEFAULT_WALLET_DIR = Path.home() / "spacer" / "arbiter" / "ecash"

# Hard cap on cashu wall time. Mint calls are HTTPS round-trips to an
# external host (unlike the local-IPC daemons), and a melt waits on an
# LN payment the mint makes; 60s covers the slow path. A stall longer
# than this means the mint is unreachable or wedged; the caller treats
# the timeout as a refusal and audit-logs the cause. Override via
# CASHU_TIMEOUT_S.
DEFAULT_TIMEOUT_S = 60.0


class EcashError(Exception):
    """Raised on any cashu CLI failure: non-zero exit, timeout, binary
    missing, or missing mint configuration. The dispatch layer catches
    this at the arbiter-internals boundary, audit-logs the cause, and
    returns the uniform refusal to the petitioner. The exception
    message stays inside the arbiter; it never crosses the privacy
    gateway."""


def _bin_path():
    """Resolve the cashu binary. Env override CASHU_BIN takes
    precedence, else DEFAULT_BIN."""
    return Path(os.environ.get("CASHU_BIN", DEFAULT_BIN))


def _mint_url():
    """Resolve the operator-pinned mint URL from CASHU_MINT_URL.

    No default, deliberately: the mint custodies the float's backing
    funds (doc 07 §4), so which mint to trust is an operator decision
    made at deployment time. Raising here (rather than defaulting to
    some well-known public mint) is the fail-safe: an unconfigured
    deployment cannot run eCash ops at all."""
    url = os.environ.get("CASHU_MINT_URL", "").strip()
    if not url:
        raise EcashError(
            "CASHU_MINT_URL is not set; the mint is operator-pinned "
            "arbiter config (doc 07 §2) and has no default"
        )
    return url


def _wallet_dir():
    """Resolve the wallet data dir. Env override CASHU_DIR takes
    precedence, else DEFAULT_WALLET_DIR (the gitignored
    arbiter/ecash/ runtime subtree)."""
    return Path(os.environ.get("CASHU_DIR", DEFAULT_WALLET_DIR))


def _timeout_s():
    """Resolve the per-call wall-time cap. Env override
    CASHU_TIMEOUT_S takes precedence."""
    return float(os.environ.get("CASHU_TIMEOUT_S", DEFAULT_TIMEOUT_S))


def _run(*args):
    """Invoke the cashu CLI with connection flags prepended; return
    stdout as a string. Raises EcashError on any failure.

    Argv-list form (no shell): each argument is a separate process
    argv entry, so petitioner-supplied strings (the defund token)
    flow through without shell-metacharacter expansion. Every argv
    element is stringified explicitly.

    One connection flag (--host for the pinned mint URL) is always
    prepended, and the wallet data dir is pinned via the CASHU_DIR
    environment variable nutshell reads - set explicitly on the
    subprocess so an inherited value cannot silently redirect the
    wallet. No --wallet is passed: the default nutshell wallet is used
    (see the module docstring - a named wallet breaks `receive` in
    nutshell 0.18.1), and CASHU_DIR alone provides isolation. A reviewer
    can read this single _run helper and know the entire connection
    surface, exactly as with lnd.py's _run.
    """
    cmd = [
        str(_bin_path()),
        f"--host={_mint_url()}",
    ] + [str(a) for a in args]
    env = dict(os.environ)
    env["CASHU_DIR"] = str(_wallet_dir())
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_timeout_s(),
            check=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise EcashError(f"cashu timed out after {_timeout_s()}s")
    except FileNotFoundError:
        raise EcashError(f"cashu not found at {cmd[0]}")
    if result.returncode != 0:
        # cashu's stderr can mention amounts, the mint URL, quote ids,
        # or token fragments. Retained inside the exception so the
        # dispatch layer can audit-log the cause; the petitioner only
        # ever sees the uniform refusal. Truncated to discourage any
        # caller from surfacing it verbatim.
        raise EcashError(
            f"cashu exited {result.returncode}: "
            f"{result.stderr.strip()[:200]}"
        )
    return result.stdout


# Wallet operations. All return raw stdout text (see module docstring
# on deferred parsing). The executor orchestrates these into the fund
# and defund flows of doc 07 §3, sleeping timing.mint_gap_s() between
# the mint-facing steps (doc 07 §6 T1).

def balance():
    """Return the wallet's balance output. Arbiter-internal: the
    transient custody this wallet holds mid-execution is never a
    petitioner-visible figure."""
    return _run("balance")


def mint_quote(amount_sat):
    """Request a mint quote for amount_sat WITHOUT blocking on
    payment: step one of the fund flow (doc 07 §3). The output
    carries the bolt11 invoice the arbiter pays via lnd.payinvoice()
    and the quote id that mint() completes against."""
    return _run("invoice", int(amount_sat), "--no-check")


def mint(amount_sat, quote_id):
    """Complete issuance against a paid mint quote: the last step of
    the fund flow. Submits blinded outputs and receives proofs into
    the wallet."""
    return _run("invoice", int(amount_sat), "--id", quote_id)


def send(amount_sat):
    """Serialize amount_sat of proofs from the wallet into a V4
    cashuB token string (printed on stdout): the fund flow's handoff
    artifact, deposited in the result registry for the petitioner.

    Flags (verified against nutshell 0.18.1 at sp-uy29gy):
    - -y: skip nutshell's interactive confirmation. The arbiter has no
      operator at the cashu stdin (the operator-facing channel is the
      console, not this subprocess), mirroring lnd.payinvoice's -f.
    - -d: embed DLEQ proofs (NUT-12) in the token so the petitioner's
      wallet can verify it offline (doc 07 §2: DLEQ mandatory in both
      wallets). Without it a malicious mint's per-client signing could
      tag the handoff token undetectably."""
    return _run("send", "-y", "-d", int(amount_sat))


def receive(token):
    """Swap-claim a serialized token into the wallet: step one of the
    defund flow. The wallet only talks to the pinned mint, so a token
    minted elsewhere fails here - this is where the never-AI-
    suppliable mint rule (doc 07 §2) is enforced at execution time."""
    return _run("receive", token)


def pay(bolt11):
    """Melt wallet proofs to pay a bolt11 invoice: the defund flow's
    exit leg, paying an invoice from the arbiter's own LND node.

    -y skips nutshell's interactive melt confirmation (verified against
    nutshell 0.18.1 at sp-uy29gy): the arbiter has no operator at the
    cashu stdin, so the prompt would otherwise block forever, the
    eCash analogue of lnd.payinvoice's -f."""
    return _run("pay", "-y", bolt11)


def decode(token):
    """Decode a serialized cashuB token to nutshell's JSON form
    (printed on stdout): amounts per proof, the embedded mint URL, and
    DLEQ proofs. JSON, unlike the other wrapper calls' human text, so
    the executor parses it directly.

    The executor uses this at the START of a defund, before the
    swap-claim, to enforce the operator-pinned mint (doc 07 §2): a
    token whose embedded mint URL is not CASHU_MINT_URL is refused
    locally, without contacting any mint - decode is offline. This is
    the executor-time enforcement point the design names: only the
    wallet can decode a token's embedded mint URL, and decode does it
    without spending or swapping anything."""
    return _run("decode", token)


def info():
    """Return wallet / mint info output. Static discovery; the
    executor's pre-flight uses it the way lnd.getinfo() is used."""
    return _run("info")


# === Allowance and outstanding-float ledger =========================
#
# Doc 07 §8: the float replaces per-action control with a
# pre-committed loss bound, so the bound must be hard.
#
# ecash_allowance_sats is operator config, console-edited like the
# registry and standing approvals (one YAML file per concern, per
# arbiter/config/README.md). The gateway's fund_ecash gate refuses
# when outstanding + requested > allowance, BEFORE standing approvals
# are consulted: a HITL approval cannot exceed the allowance, so an
# operator's tired "approve" cannot widen the blast radius.
#
# A missing or unreadable config reads as allowance 0, which refuses
# every fund: the float cannot exist until the operator explicitly
# writes its bound. The optional rate cap (ecash_funding_rate,
# doc 07 §8) is deferred until the executor lands - the outstanding
# cap is the hard bound; the rate cap refines it over time and needs
# real funding traffic to tune against.

DEFAULT_ALLOWANCE_PATH = (
    Path.home() / "spacer" / "arbiter" / "config" / "ecash.yaml"
)

_ALLOWANCE_KEY = "ecash_allowance_sats"


def _allowance_path():
    raw = os.environ.get("SPACER_ECASH_ALLOWANCE_PATH")
    return Path(raw) if raw else DEFAULT_ALLOWANCE_PATH


def allowance_sats():
    """Return the operator-set allowance in sats, or 0 when unset.

    The config is one `ecash_allowance_sats: <int>` line in
    config/ecash.yaml (comments allowed). Anything unreadable or
    unparseable reads as 0 - fail toward refusing funds - and is
    audit-logged for operator triage, mirroring standing_approvals'
    read/parse error handling."""
    path = _allowance_path()
    if not path.exists():
        return 0
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        audit.record("ecash_allowance_read_error", {"reason": str(e)})
        return 0
    for raw in text.splitlines():
        idx = raw.find("#")
        if idx >= 0:
            raw = raw[:idx]
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        if key.strip() != _ALLOWANCE_KEY:
            continue
        try:
            sats = int(value.strip())
        except ValueError:
            audit.record(
                "ecash_allowance_parse_error",
                {"reason": f"{_ALLOWANCE_KEY} is not an integer"},
            )
            return 0
        if sats < 0:
            audit.record(
                "ecash_allowance_parse_error",
                {"reason": f"{_ALLOWANCE_KEY} is negative"},
            )
            return 0
        return sats
    return 0


# Outstanding-float ledger. Append-only rows, one per successful fund
# or defund execution, written by the timing-layer executor when it
# lands. outstanding = sum(fund) - sum(defund) is the upper bound on
# operator-funded value still in AI hands, maintained entirely from
# gateway-visible events (doc 07 §8: AI-direct spends are invisible
# by design; the ledger bounds operator loss, not AI wealth).
_SCHEMA = """
CREATE TABLE IF NOT EXISTS ecash_ledger (
    id          INTEGER PRIMARY KEY,
    direction   TEXT NOT NULL CHECK (direction IN ('fund', 'defund')),
    amount_sats INTEGER NOT NULL,
    handle      TEXT NOT NULL,
    recorded_at REAL NOT NULL
);
"""
state.register_schema(_SCHEMA)


def outstanding_sats():
    """Return the outstanding float: total funded minus total
    successfully defunded, floored at 0.

    The floor matters for the gate: a ledger anomaly where defunds
    exceed funds (e.g., tokens received from third parties and then
    defunded through us) must not create negative outstanding and
    thereby widen the funding headroom past the allowance."""
    with state.connect() as conn:
        row = conn.execute(
            "SELECT COALESCE(SUM(CASE direction WHEN 'fund' THEN amount_sats "
            "ELSE -amount_sats END), 0) FROM ecash_ledger"
        ).fetchone()
    return max(0, int(row[0]))


def record_funded(handle, amount_sats):
    """Record a successful fund execution. Executor-side: called after
    the mint flow completes and the handoff token is deposited.
    Audit-logs amount and outstanding before/after per doc 07 §8."""
    return _record("fund", handle, amount_sats)


def record_defunded(handle, amount_sats):
    """Record a successful defund execution. Executor-side: called
    after the swap-claim + melt completes."""
    return _record("defund", handle, amount_sats)


def _record(direction, handle, amount_sats):
    amount = int(amount_sats)
    if amount <= 0:
        raise ValueError(f"amount_sats must be positive, got {amount}")
    before = outstanding_sats()
    with state.connect() as conn:
        conn.execute(
            "INSERT INTO ecash_ledger "
            "(direction, amount_sats, handle, recorded_at) "
            "VALUES (?, ?, ?, ?)",
            (direction, amount, handle, time.time()),
        )
    after = outstanding_sats()
    audit.record(
        f"ecash_ledger_{direction}",
        {
            "handle": handle,
            "amount_sats": amount,
            "outstanding_before_sats": before,
            "outstanding_after_sats": after,
        },
    )
    return after


# This module is imported lazily, on the first ecash-mode dispatch -
# which is AFTER the boot path (arbiter.main) has already run
# state.migrate(). Re-running migrate here applies the just-registered
# ecash_ledger fragment to the live database; the call is idempotent
# (CREATE TABLE IF NOT EXISTS) and cheap, and it keeps the lazy-import
# discipline without requiring boot to know about this module. The
# state.path() guard skips the case where this module is imported
# before the host process has configured state at all (the smoke test
# below, library-style imports): there the host's own configure() +
# migrate() applies the fragment, like every other subsystem.
if state.path() is not None:
    state.migrate()


if __name__ == "__main__":
    # Smoke test: a fake cashu script exercises argv construction,
    # env pinning, and error paths without a live mint (the live mint
    # is sp-2hwco4.4); the allowance + ledger sections round-trip
    # against temp files. Same pattern as lnd.py's smoke test.
    import shutil
    import sys
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="arbiter-ecash-smoke-"))
    fake = work / "cashu"
    argv_log = work / "argv.log"
    # The fake echoes its full argv and the CASHU_DIR it saw to a side
    # file so the test can assert exact arg/env propagation, then
    # dispatches a canned reply per the first non-flag arg.
    fake.write_text(
        f"""#!/bin/sh
# Fake cashu for arbiter/src/ecash.py smoke test.
echo "CASHU_DIR=$CASHU_DIR $@" >> {argv_log}
while [ $# -gt 0 ]; do
  case "$1" in
    --host=*|--wallet=*) shift;;
    *) break;;
  esac
done
case "$1" in
  balance)
    printf 'Balance: 2500 sat\\n'
    ;;
  invoice)
    printf 'Invoice: lnbc10n1pfakeinvoice\\nQuote id: q_fake01\\n'
    ;;
  send)
    printf 'cashuBfakesmokevector\\n'
    ;;
  receive)
    printf 'Received 1000 sat\\n'
    ;;
  pay)
    printf 'Paid 1000 sat (fee 2 sat)\\n'
    ;;
  info)
    printf 'Version: nutshell/fake\\nMint URL: https://mint.example.test\\n'
    ;;
  decode)
    printf '{{"token": [{{"mint": "https://mint.example.test", "proofs": [{{"amount": 300}}, {{"amount": 200}}]}}], "unit": "sat"}}\\n'
    ;;
  failboom)
    echo "mint unreachable" >&2
    exit 1
    ;;
  slow)
    sleep 5
    ;;
  *)
    echo "unknown command: $1" >&2
    exit 64
    ;;
esac
"""
    )
    fake.chmod(0o755)
    os.environ["CASHU_BIN"] = str(fake)
    os.environ["CASHU_MINT_URL"] = "https://mint.example.test"
    os.environ["CASHU_DIR"] = str(work / "wallet")
    os.environ["CASHU_TIMEOUT_S"] = "1.0"

    tmp_audit = work / "audit.log"
    tmp_state = work / "state.db"
    audit.configure(tmp_audit)
    state.configure(tmp_state)
    state.migrate()

    try:
        # Wallet round-trips: raw stdout comes back verbatim.
        assert balance() == "Balance: 2500 sat\n"
        out = mint_quote(1000)
        assert "lnbc10n1pfakeinvoice" in out, out
        out = mint(1000, "q_fake01")
        assert "Quote id" in out, out
        assert send(500).strip() == "cashuBfakesmokevector"
        assert "Received" in receive("cashuBfakesmokevector")
        assert "Paid" in pay("lnbc10n1pfakeinvoice")
        assert "nutshell" in info()

        # decode emits JSON (unlike the human-text wallet calls); the
        # executor parses the embedded mint URL for the mint-pin check
        # and the proof amounts. The -y / -d flags reach send's argv.
        import json as _json_dec
        parsed = _json_dec.loads(decode("cashuBfakesmokevector"))
        assert parsed["token"][0]["mint"] == "https://mint.example.test", parsed
        assert sum(p["amount"] for p in parsed["token"][0]["proofs"]) == 500, parsed

        # Argv assertion: connection flags prepended in order, the
        # wallet dir pinned via CASHU_DIR on the subprocess env, args
        # stringified and propagated without shell expansion.
        argv = argv_log.read_text()
        assert "--host=https://mint.example.test" in argv, argv
        # No --wallet: the default nutshell wallet is used (a named
        # wallet breaks `receive` in nutshell 0.18.1). CASHU_DIR alone
        # isolates the wallet.
        assert "--wallet" not in argv, argv
        assert f"CASHU_DIR={work / 'wallet'}" in argv, argv
        assert "invoice 1000 --no-check" in argv, argv
        assert "invoice 1000 --id q_fake01" in argv, argv
        assert "send -y -d 500" in argv, argv

        # Missing mint URL must raise before any subprocess runs: the
        # mint is operator-pinned with no default.
        prior = os.environ.pop("CASHU_MINT_URL")
        raised = False
        try:
            balance()
        except EcashError as e:
            raised = "CASHU_MINT_URL" in str(e)
        assert raised, "missing mint URL must raise"
        os.environ["CASHU_MINT_URL"] = prior

        # Non-zero exit becomes EcashError with truncated stderr.
        raised = False
        try:
            _run("failboom")
        except EcashError as e:
            raised = "exited 1" in str(e)
        assert raised, "non-zero exit must raise"

        # Timeout: the fake sleeps 5s; the cap is 1s.
        raised = False
        try:
            _run("slow")
        except EcashError as e:
            raised = "timed out" in str(e)
        assert raised, "timeout must raise"

        # Missing binary: a clean error rather than an OSError leak.
        os.environ["CASHU_BIN"] = "/nonexistent/path/cashu"
        raised = False
        try:
            balance()
        except EcashError as e:
            raised = "not found" in str(e)
        assert raised, "missing binary must raise"
        os.environ["CASHU_BIN"] = str(fake)

        # Allowance: missing file reads as 0 (fail toward refusing).
        allowance_yaml = work / "ecash.yaml"
        os.environ["SPACER_ECASH_ALLOWANCE_PATH"] = str(allowance_yaml)
        assert allowance_sats() == 0, "missing config must read as 0"

        # Well-formed config round-trips, comments stripped.
        allowance_yaml.write_text(
            "# petty-cash bound, doc 07 §8\necash_allowance_sats: 50000\n"
        )
        assert allowance_sats() == 50000

        # Garbage and negative values read as 0 and audit-log.
        allowance_yaml.write_text("ecash_allowance_sats: lots\n")
        assert allowance_sats() == 0
        allowance_yaml.write_text("ecash_allowance_sats: -5\n")
        assert allowance_sats() == 0
        allowance_yaml.write_text("unrelated_key: 9\n")
        assert allowance_sats() == 0

        # Ledger: empty table = outstanding 0; fund/defund rows move
        # it; the floor clamps a defund surplus to 0.
        assert outstanding_sats() == 0
        assert record_funded("h_fund_1", 30000) == 30000
        assert record_funded("h_fund_2", 5000) == 35000
        assert record_defunded("h_defund_1", 10000) == 25000
        assert outstanding_sats() == 25000
        assert record_defunded("h_defund_2", 40000) == 0, (
            "defund surplus must clamp outstanding at 0"
        )
        raised = False
        try:
            record_funded("h_bad", 0)
        except ValueError:
            raised = True
        assert raised, "non-positive amount must raise"

        # Audit log carries the ledger trail with before/after.
        import json as _json
        events = [
            _json.loads(line)
            for line in tmp_audit.read_text().splitlines()
            if line.strip()
        ]
        names = [e["event"] for e in events]
        assert names.count("ecash_ledger_fund") == 2, names
        assert names.count("ecash_ledger_defund") == 2, names
        assert "ecash_allowance_parse_error" in names, names
        first_fund = next(
            e for e in events if e["event"] == "ecash_ledger_fund"
        )
        assert first_fund["payload"]["outstanding_before_sats"] == 0
        assert first_fund["payload"]["outstanding_after_sats"] == 30000

        print(f"OK: ecash wrapper + allowance ledger round-trips at {work}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    sys.exit(0)
