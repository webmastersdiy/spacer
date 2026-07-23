"""
Privacy gateway: the only network-reachable component on the arbiter.

Every petitioner request hits this module first. The exposed op set
depends on the deployment mode (SPACER_MODE; see _advanced_mode /
_ecash_mode) along the rail ladder of design doc 07: Bitcoin on-chain
(primary, default) -> Lightning (advanced) -> eCash (advanced, atop
Lightning):

- onchain (default): Bitcoin on-chain is the primary surface. The read
  is query_balance (the bitcoind wallet, snapshot-served); the write is
  manage_bitcoin. The gateway runs with NO LND dependency in this mode -
  lnd.py is never imported (module NOTE below).
- advanced (SPACER_MODE=lightning|full): the Lightning extension layers
  query_channels (read) and manage_lightning (write) back on, reading the
  LND node via arbiter/src/lnd.py.
- ecash (SPACER_MODE=ecash): the eCash extension layers fund_ecash /
  defund_ecash (writes, doc 07 §3) on top of the full Lightning
  surface (ecash implies lightning: the fund/defund legs are LN
  payments). arbiter/src/ecash.py is imported only in this mode (see
  _ecash). No new read ops: the AI counts its own float locally.

The handler routes each inbound request through one of these branches
based on op:

- Known read ops: served from the per-op read snapshot (design doc 15,
  arbiter/src/snapshots.py), refreshed on the executor drainer's
  randomized event-independent clock. The request path never touches
  bitcoind / LND, so polling at any rate only observes the snapshot.
- Known write ops: resolve the recipient_token through the recipient
  address registry during pseudonymize-inbound; on any gate miss
  (denomination, registry, standing approval) DEFER the refusal (see
  below) rather than refusing synchronously. The registry IS the
  destination gate - there is no separate outbound-policy step.
- eCash write ops in ecash mode: no recipient_token (the destination
  is structurally the operator-pinned mint), so they skip the
  registry and run allowance cap (fund only) -> standing approvals ->
  dispatch (doc 07 §3, §8); a gate miss defers the same way.
- Extension ops while their extension is disabled (Lightning or eCash
  ops in onchain mode; eCash ops in lightning mode): audit-logged
  decision_refuse_mode so the operator sees an extension-gated call
  distinctly from an unknown op. A disabled WRITE defers its refusal;
  a disabled READ (query_channels in onchain mode) refuses
  synchronously - reads are snapshot-served, never enqueued.
- Unknown ops: park in the HITL queue and defer the refusal so an
  unrecognized op is petitioner-indistinguishable at submit from a
  recognized-and-gated one; the operator decides on the directly-
  attached console.

Deferred refusal (§4.7, §4.8). A refused state-changing call does NOT
return a synchronous {"status": "refused"} - that would be an instant,
free pass-vs-refuse oracle a petitioner could use to map policy
thresholds (a standing-approval amount band, the registry, the
deployment mode). Instead the gateway returns the SAME
{"status": "received", "handle": ...} a gate-passed write returns and
enqueues a kind="rejection" on the timing layer
(_defer_rejection_and_ack); the refusal surfaces only on the
petitioner's later poll, after the rejection-delivery window, as the
uniform _REJECTION_PAYLOAD. Submit thus carries no signal - by content
or by timing - of whether the call passed or was refused, or which gate
fired. Malformed input (parse / protocol error) and the not-yet-
refreshed read path still refuse synchronously: those are not
state-changing gate decisions and leak no policy the petitioner does
not already hold.

Every branch audit-logs at each decision point, and the response is
latency-normalized regardless of which branch fired. There are no
other entry points to the arbiter from the network: bitcoind, LND,
the audit log, local state, and the timing layer all sit behind this
module.

Per design-docs/origin/05--2026-05-05-0948-architecture-overview.md
§4.1, §4.7, §6.

Several mechanisms are placeholders pending open design questions or
later beads:
- numeric banding and aggregate-by-default: blocked on sp-77lxs.4
  (band-edge randomization).
- inbound pseudonymize (recipient_token -> real address): wired up
  by sp-77lxs.13 (recipient address registry).
- dispatch into arbiter internals (timing layer, bitcoind/LND access):
  wired up by sp-77lxs.10/11/12.
- result-poll endpoint: wired up by sp-77lxs.14 (result registry).

The placeholders are kept as their own named functions so a non-AI
reviewer can confirm at a glance which mechanisms are present in
structure and which are wired in behavior.
"""
import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import audit
import denominations
import registry
import results
import snapshots
import standing_approvals
import state
import timing

# NOTE: arbiter/src/lnd.py is deliberately NOT imported here - or
# anywhere in the gateway, since reads went snapshot-served (doc 15):
# the only LND consumers are the executor's op handlers and the
# snapshot refresh sweep (snapshots._read_backend), both of which
# import it lazily in advanced modes only, so onchain (default) mode
# runs with no LND dependency at all (scope item 1: "gateway must NOT
# import lnd unconditionally").
# arbiter/src/ecash.py follows the same rule one rung up the ladder:
# pulled in lazily by _ecash() on ecash-mode calls only, so onchain AND
# lightning deployments run with no nutshell dependency (doc 07 §9).

# Loopback by default. The gateway binds the loopback interface because
# the petitioner reaches it through a transport (Tor hidden service,
# ssh tunnel, mTLS reverse proxy) that is configured outside this
# codebase. Binding a non-loopback interface from inside this module
# would be a bypass path past the deployment-time transport choice.
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8420

# Latency normalization target. Every response takes at least this many
# seconds wall-clock from request receipt to response send. Defeats
# per-response timing fingerprints (hop count, IBD state, wallet vs.
# non-wallet) per the latency-normalization mitigation. The number is
# a placeholder; the production target is set by the deployment based
# on observed worst-case backend latency.
DEFAULT_LATENCY_TARGET_S = 0.250

# Hard cap on inbound request size. Defense-in-depth against memory
# exhaustion probes and runaway deserialization. The protocol shape is
# small (one JSON object per call), so 64 KiB is generous - including
# for defund_ecash, whose request body carries a serialized V4 cashuB
# token (doc 07 §3 build note): a petty-cash float's token is a few
# hundred bytes to a few KiB, comfortably inside the cap.
MAX_REQUEST_BYTES = 65536

# Refusal response shape. A single uniform body for every refusal so
# the response itself does not leak which step refused (parse failure,
# registry miss, HITL park on unknown op, etc. all look identical to
# the petitioner). The audit log differentiates the cause for the
# operator.
_REFUSED_BODY = json.dumps({"status": "refused"}, separators=(",", ":")).encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    # Suppress BaseHTTPRequestHandler's stderr access log. That path
    # would mirror the request shape into a stream the audit log does
    # not control, defeating the tamper-resistance the audit log
    # provides (§4.5).
    def log_message(self, fmt, *args):
        pass

    def setup(self):
        # setup() is called once per request, before handle(), with
        # self.server already wired up. Stamp the latency-normalization
        # deadline at this earliest point so every response path
        # (request pipeline, protocol-error refusal, etc.) honors the
        # same floor relative to the request start.
        super().setup()
        self._latency_deadline = time.monotonic() + self.server.latency_target

    # Route every HTTP method through process_request. __getattr__
    # only fires when normal attribute lookup fails (i.e., the parent
    # class has no `do_<METHOD>` defined), so this catches every verb
    # uniformly. Defining individual do_GET / do_POST / do_PUT / ...
    # would be boilerplate, and leaving any verb undefined would let
    # BaseHTTPRequestHandler reply with its default 501 HTML page,
    # which leaks both the status code and the verb name in the
    # response body. Treat every method the same: parse, audit, route
    # through the pipeline, return the uniform response.
    def __getattr__(self, name):
        if name.startswith("do_"):
            return lambda: process_request(self)
        raise AttributeError(name)

    # send_error is called by BaseHTTPRequestHandler on protocol-level
    # parse failures (malformed request line, oversized URI, bad header,
    # etc.). The default behavior writes an HTML error page and a
    # non-200 status, which would leak both the status code and the
    # failure mode. Override to emit the same uniform refusal body the
    # request pipeline uses, so a malformed HTTP frame is petitioner-
    # visibly indistinguishable from a refused JSON request. Close the
    # connection afterward: the input stream's framing is by definition
    # uncertain after a parse failure, so reusing the connection is
    # unsafe.
    def send_error(self, code, message=None, explain=None):
        try:
            _hold_response(self, self._latency_deadline)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_REFUSED_BODY)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(_REFUSED_BODY)
            audit.record("disclosure", {"body": {"status": "refused"}})
        except Exception:
            # If the connection is already broken there is nothing to
            # write; swallow the secondary failure rather than emit a
            # different error code.
            pass
        self.close_connection = True
        audit.record("decision_refuse", {"reason": "protocol_error", "code": code})


def process_request(handler):
    """Run one petitioner request through the gateway pipeline.

    The pipeline is fixed; each step is a separate function so a
    reviewer can audit them in isolation. On any error or refusal the
    response collapses to a single uniform shape so the response itself
    does not leak which step refused. The audit log differentiates.
    """
    # The latency-normalization deadline was stamped in _Handler.setup()
    # so it covers every response path, including the protocol-error
    # path that runs before this function ever fires.
    deadline = handler._latency_deadline

    raw = _read_body(handler)
    request = _parse_request(raw)
    if request is None:
        audit.record("decision_refuse", {"reason": "parse_failure"})
        _respond_refused(handler, deadline)
        return

    op = request.get("op")
    # Record the full request, not just the op. Everything the
    # petitioner sends is by definition petitioner-known (the AI chose
    # it), so the complete request - amount, recipient_token, poll
    # handle, defund token - is safe to surface in the operator
    # console's petitioner-known (left) column and is useful forensic
    # detail in the audit log. It is bounded by MAX_REQUEST_BYTES.
    audit.record("request_received", request)

    # Read-only result poll (§4.8). The poll path is the only
    # petitioner-reachable read into arbiter state and is structurally
    # different from state-changing calls:
    # - The recipient address registry (§4.7) is the destination gate
    #   for state-changing calls; a read of arbiter-internal result
    #   storage carries no destination at all.
    # - The pseudonymize-inbound step resolves recipient tokens; a poll
    #   carries a result handle, not a recipient token.
    # - The hide-secrets / band / aggregate filters apply to backend
    #   responses; the result registry's payload was already filtered
    #   at deposit time per §4.8 ("the privacy gateway writes the
    #   filtered, banded, tokenized result into the registry").
    # - The 10-min poll floor and idempotent retrieval are enforced
    #   inside results.poll(); this fast-path just routes the call.
    # Latency normalization still applies via the deadline stamp.
    if op == "poll":
        _handle_poll(handler, request, deadline)
        return

    # Known read ops serve from the read snapshot (doc 15). No
    # recipient_token, no destination universe to resolve against, and
    # no backend call either: the gateway reads the per-op snapshot row
    # and returns the stored value verbatim. Outbound filtering still
    # applies. The exposed read set depends on the deployment mode
    # (_known_read_ops). Before the first refresh has ever completed
    # (boot gap, or production mode where the refresh sweep is blocked
    # on sp-77lxs.3) there is nothing to serve; refuse uniformly rather
    # than fall back to a live backend read - the read path touching a
    # backend even once is exactly what doc 15 removes.
    if op in _known_read_ops():
        response = _dispatch(request)
        if response is None:
            audit.record("decision_refuse_snapshot_unavailable", {"op": op})
            _respond_refused(handler, deadline)
            return
        response = _hide_secrets(response)
        response = _band_outbound(response)
        response = _aggregate_outbound(response)
        audit.record("decision_allow", {"op": op})
        _respond_ok(handler, response, deadline)
        return

    # Known write ops are gated three ways. First the amount gate
    # (denominations, doc 12 G2) - the HOW-MUCH gate - refuses any
    # amount off the standard denomination ladder before anything else
    # runs, so a distinctive AI-chosen amount can never reach the
    # network as a correlation fingerprint; checked first (ahead of the
    # registry lookup) because a malformed amount is refusable without
    # resolving a destination, and it collapses to the uniform refusal
    # audited as decision_refuse_denomination. Then the registry (§4.7) -
    # the WHO gate - resolves the recipient_token; a non-`ok` lookup
    # collapses to the uniform "destination unavailable" refusal,
    # audit-logged as decision_refuse_registry so the operator can
    # see *which* token failed and why. Then standing approvals
    # (GLOSSARY 'Standing approvals', §6) - the WHAT gate - check
    # whether the operator has pre-approved this (op, destination,
    # amount) tuple; no match parks in HITL and refuses uniformly,
    # audit-logged as decision_defer_hitl with reason
    # no_standing_approval so the operator can distinguish the
    # default-pause from the registry miss and from an unknown op.
    # All three gates must pass for dispatch to fire. The exposed write
    # set depends on the deployment mode (_known_write_ops).
    if op in _known_write_ops():
        amount = _request_amount_sats(request)
        if not denominations.is_allowed(amount):
            audit.record(
                "decision_refuse_denomination",
                {"op": op, "requested_sats": amount},
            )
            _defer_rejection_and_ack(handler, op, deadline)
            return
        resolved = _pseudonymize_inbound(request)
        if resolved is None:
            audit.record("decision_refuse_registry", {"op": op})
            _defer_rejection_and_ack(handler, op, deadline)
            return
        if not standing_approvals.matches(
            op,
            request.get("recipient_token"),
            _request_amount_sats(request),
        ):
            audit.record(
                "decision_defer_hitl",
                {"op": op, "reason": "no_standing_approval"},
            )
            _hitl_park(request)
            _defer_rejection_and_ack(handler, op, deadline)
            return
        # Both gates passed. Enqueue on the timing layer and acknowledge
        # with an opaque handle; the executor (executor.py) drains the
        # due action against the real backend (bitcoind / LND) and the
        # result registry surfaces the outcome on the petitioner's poll.
        # No synchronous dispatch, no not_implemented stub.
        _enqueue_write_and_ack(
            handler, op, _registry_write_params(op, resolved), deadline
        )
        return

    # eCash write op in ecash mode (doc 07 §3). No recipient_token -
    # the destination is structurally the operator-pinned mint - so
    # the registry step does not apply; the pipeline is allowance cap
    # (fund only) -> standing approvals -> dispatch. Outside ecash
    # mode this set is empty and the same ops land in the extension
    # gate below.
    if op in _known_ecash_write_ops():
        _handle_ecash_write(handler, request, deadline)
        return

    # Extension op while its extension is disabled: a Lightning or
    # eCash op in onchain (default) mode, or an eCash op in
    # lightning/full mode (doc 07 §9). The op is recognized but
    # deliberately disabled: it belongs to an extension the operator
    # did not enable. Refuse uniformly - the operator already decided
    # (by choosing the mode), so unlike an unknown op there is nothing
    # to HITL-park. The distinct decision_refuse_mode audit event lets
    # the operator tell an extension-gated call apart from a registry
    # miss or an unknown op; the op field disambiguates which
    # extension was asked for. In the op's home mode it is already in
    # the active known sets above and never reaches this gate.
    if op in _EXTENSION_OPS:
        audit.record(
            "decision_refuse_mode",
            {"op": op, "reason": "advanced_extension_disabled"},
        )
        # A disabled extension WRITE defers exactly like any other gate
        # refusal, so "is this extension enabled?" is not a submit-time
        # oracle: in its home mode the op passes the gates and returns
        # received+handle, so the disabled case must return that too. A
        # disabled extension READ (query_channels in onchain mode) stays a
        # synchronous refusal - reads are snapshot-served synchronously
        # (doc 15) and never enqueued, so there is no deferred-result
        # handle to hand back, and the read-path probing model is doc 15's
        # concern, not this gate's.
        if op in _ADVANCED_READ_OPS:
            _respond_refused(handler, deadline)
        else:
            _defer_rejection_and_ack(handler, op, deadline)
        return

    # Unknown op. Park in the HITL queue, then defer the refusal through
    # the result registry so an unrecognized op is petitioner-
    # indistinguishable at submit from a recognized-and-gated one (both
    # return received+handle) - the op namespace is not a submit-time
    # oracle either. The operator decides on the directly-attached console
    # (§6); until the HITL queue table lands (_hitl_park is a no-op
    # skeleton) the deferred outcome is the uniform refusal.
    audit.record("decision_defer_hitl", {"op": op})
    _hitl_park(request)
    _defer_rejection_and_ack(handler, op, deadline)


def _read_body(handler):
    """Read the request body, bounded by MAX_REQUEST_BYTES.

    Returns b"" for any malformed Content-Length so the parse step
    rejects uniformly without leaking which header was bad.
    """
    raw_len = handler.headers.get("Content-Length")
    if raw_len is None:
        return b""
    try:
        length = int(raw_len)
    except ValueError:
        return b""
    if length < 0 or length > MAX_REQUEST_BYTES:
        return b""
    return handler.rfile.read(length) if length else b""


def _parse_request(raw):
    """Parse the JSON body. Returns the request dict or None on any
    failure. No information from the parse error reaches the response;
    the caller turns None into a uniform refusal."""
    if not raw:
        return None
    try:
        obj = json.loads(raw.decode("utf-8"))
    except Exception:
        return None
    # Strict shape: a JSON object with a string `op` field. Any other
    # shape is refused at the boundary; this is the only deserialization
    # the gateway performs on petitioner input (§4.1: no untrusted
    # deserialization beyond what the protocol strictly requires).
    if not isinstance(obj, dict):
        return None
    if not isinstance(obj.get("op"), str):
        return None
    return obj


# Deployment mode (SPACER_MODE). onchain (default) makes Bitcoin
# on-chain the primary - and only - surface, with no LND dependency.
# The advanced Lightning extension (SPACER_MODE=lightning|full) layers
# the LN ops back on; the eCash extension (SPACER_MODE=ecash) layers
# the eCash writes on top of the full Lightning surface (doc 07 §9:
# ecash implies lightning exactly as lightning implies bitcoind).
# `full` stays frozen at its 2026-06 meaning (onchain + lightning) as
# a legacy alias of `lightning`: an extension that moves bearer value
# out of gateway control must never switch on without the operator
# typing its name, so `full` does not auto-grow to include ecash.
# Anything outside {lightning, full, ecash} reads as onchain so a typo
# or an empty value fails safe toward the no-extension default rather
# than silently enabling an extension.
_ADVANCED_MODES = frozenset({"lightning", "full", "ecash"})
_ECASH_MODES = frozenset({"ecash"})


def _mode():
    """Return the normalized SPACER_MODE value. Read per-request (not
    cached at import) so the exit-loop runner can exercise every mode
    in one process by setting SPACER_MODE around each variant,
    mirroring how scale.py / timing.py read their own mode env vars."""
    return os.environ.get("SPACER_MODE", "onchain").strip().lower()


def _advanced_mode():
    """True iff the deployment runs the advanced Lightning extension.
    ecash mode counts: the eCash extension cannot exist without LND
    (fund/defund are LN legs), so SPACER_MODE=ecash enables the full
    Lightning surface as well (doc 07 §9)."""
    return _mode() in _ADVANCED_MODES


def _ecash_mode():
    """True iff the deployment runs the eCash extension
    (SPACER_MODE=ecash). Implies _advanced_mode()."""
    return _mode() in _ECASH_MODES


def _ecash():
    """Lazily import the eCash extension module (arbiter/src/ecash.py),
    the same lazy-import rule lnd.py follows one rung down the ladder
    (module NOTE at top): an onchain or lightning deployment never
    imports it and carries no nutshell dependency at runtime (doc 07
    §9). First import also registers and applies the ecash_ledger
    schema (see ecash.py's tail comment)."""
    import ecash
    return ecash


# Read op exposed in onchain (default) mode. query_balance serves the
# bitcoind-wallet snapshot (doc 15; the refresh sweep reads the wallet,
# never this request path); it has no recipient_token and is not
# state-changing. Outbound filters (hide-secrets / band / aggregate)
# still apply.
_ONCHAIN_READ_OPS = frozenset({"query_balance"})

# Write op exposed in onchain (default) mode. manage_bitcoin resolves its
# recipient_token through the recipient address registry (§4.7), the
# same WHO-gate every write passes. New onchain write ops added here
# MUST also be handled in _dispatch and require a recipient_token.
_ONCHAIN_WRITE_OPS = frozenset({"manage_bitcoin"})

# Ops the advanced Lightning extension layers back on. query_channels
# (read) and manage_lightning (write) require the LND module and node; in
# onchain mode they are gated (refused uniformly, decision_refuse_mode).
_ADVANCED_READ_OPS = frozenset({"query_channels"})
_ADVANCED_WRITE_OPS = frozenset({"manage_lightning"})

# Ops the eCash extension layers on (ecash mode only; doc 07 §9).
# These are writes WITHOUT a recipient_token - the destination is
# structurally the operator-pinned mint - so they route through their
# own branch (allowance -> standing approvals -> dispatch) rather than
# the registry-gated write branch. No new read ops: the AI counts its
# own float locally, and query_balance keeps its lightning-mode
# behavior (the LND wallet) in ecash mode.
_ECASH_WRITE_OPS = frozenset({"fund_ecash", "defund_ecash"})

# The standing-approvals destination for eCash ops (doc 07 §3: rules
# match on op + amount band; the destination is structurally fixed, so
# the operator writes `destination: mint` - or `any` - in the rule).
_ECASH_DESTINATION = "mint"

# Extension-gated ops, used by the mode gate in process_request to
# refuse a recognized-but-disabled extension call uniformly rather
# than HITL-park it like an unknown op. Mode-dependent membership:
# in onchain mode every extension op is gated; in lightning/full mode
# the eCash ops are gated (doc 07 §9); in ecash mode the full ladder
# is enabled and nothing is gated. The active known sets and this
# gate are complementary by construction.
_EXTENSION_OPS = _ADVANCED_READ_OPS | _ADVANCED_WRITE_OPS | _ECASH_WRITE_OPS


def _known_read_ops():
    """Read ops the gateway dispatches directly, for the active mode."""
    if _advanced_mode():
        return _ONCHAIN_READ_OPS | _ADVANCED_READ_OPS
    return _ONCHAIN_READ_OPS


def _known_write_ops():
    """Write ops the gateway resolves through the registry, for the
    active mode. The eCash writes are NOT here: they carry no
    recipient_token and route through _known_ecash_write_ops()."""
    if _advanced_mode():
        return _ONCHAIN_WRITE_OPS | _ADVANCED_WRITE_OPS
    return _ONCHAIN_WRITE_OPS


def _known_ecash_write_ops():
    """eCash write ops for the active mode: the full set in ecash
    mode, empty otherwise (outside ecash mode the same ops fall
    through to the extension gate and refuse uniformly)."""
    return _ECASH_WRITE_OPS if _ecash_mode() else frozenset()


def _hitl_park(request):
    """Park an inbound call whose op the gateway does not have a
    recognized handler for. The operator approves or denies at the
    directly attached arbiter console; the petitioner only learns the
    outcome later, via the result registry, after the operator decides.

    The HITL queue table is TBD. For the current skeleton this is an
    audit-log-only marker; no row is written, no async path runs, and
    the call returns refused immediately. That preserves the
    petitioner-visible behavior (uniform refusal) while leaving the
    wire-up point explicit for review.
    """
    pass


def _request_amount_sats(request):
    """Pull the request's amount in satoshis for the standing-
    approvals gate.

    manage_bitcoin carries `amount_sats` directly. manage_lightning
    carries `amount_msats`; we round UP to sats so a max_amount_sats
    bound rejects a borderline request rather than slipping through
    on a sub-sat fraction. Returns None if neither field is present
    (or carries an unusable shape); standing_approvals.matches()
    treats None as failing any rule with a bound.
    """
    sats = request.get("amount_sats")
    if isinstance(sats, int):
        return sats
    msats = request.get("amount_msats")
    if isinstance(msats, int):
        # Ceiling division: 1500 msats -> 2 sats, 1000 msats -> 1 sat.
        return -(-msats // 1000)
    return None


def _pseudonymize_inbound(request):
    """Resolve the petitioner-supplied recipient_token to a real
    destination via the recipient address registry (§4.7).

    Called only on known write ops, where a recipient_token is
    mandatory by contract. Returns the request dict rewritten to
    carry both `recipient_address` (for dispatch) and the original
    `recipient_token` (so the dispatch layer can call
    registry.consume() after a successful send). On any non-`ok`
    lookup outcome (missing field, unknown token, bad checksum,
    expired, used, anomalous, wrong type) returns None so the caller
    defers the refusal through the result registry
    (_defer_rejection_and_ack) and audit-logs decision_refuse_registry.

    Per §4.7 production timing, registry refusals are deferred by the
    rejection-delivery delay (1 hour ± 30 min) before the petitioner
    sees them. This is wired (here + _defer_rejection_and_ack): the
    caller returns the same received-ack a gate-passed write returns,
    and the "destination unavailable" outcome surfaces later via the
    petitioner's normal poll cadence as the uniform _REJECTION_PAYLOAD,
    breaking the submission-to-response timing channel.
    """
    token = request.get("recipient_token")
    if token is None:
        return None
    status, real, _fmt = registry.lookup(token)
    if status != "ok":
        return None
    out = dict(request)
    out["recipient_address"] = real
    return out


def _handle_poll(handler, request, deadline):
    """Route a result-registry poll (§4.8) to results.poll() and emit
    the binary-state response.

    Petitioner-visible response shape:
      {"status": "result", "result": <payload>}  - first successful
                                                    retrieval; the
                                                    deposited payload
                                                    is returned verbatim.
      {"status": "not_yet"}                       - every other case
                                                    (floor throttle,
                                                    unknown handle,
                                                    already consumed,
                                                    bad input).

    The "result" / "not_yet" pair is the §4.8 binary state; there is
    no "in progress", no progress percentage, no estimated time
    remaining. The deposited payload is whatever the depositor
    placed in the registry; the registry kind ("result" /
    "rejection") is recorded for audit triage but is not part of
    the wire response (§4.8: the payload is self-describing).

    Bad input (missing or non-string handle) maps to the same
    "not_yet" wire response as a floor throttle or unknown handle.
    The audit log differentiates inside results.poll() and here.
    """
    handle = request.get("handle")
    if not isinstance(handle, str) or not handle:
        # Wire-indistinguishable from a floor throttle / unknown
        # handle; uniform "not_yet" body, latency-normalized.
        audit.record("decision_poll_bad_input", {"op": "poll"})
        _respond_ok(handler, {"status": "not_yet"}, deadline)
        return
    status, payload, _kind = results.poll(handle)
    if status == "result":
        response = {"status": "result", "result": payload}
    else:
        response = {"status": "not_yet"}
    audit.record("decision_allow", {"op": "poll"})
    _respond_ok(handler, response, deadline)


def _new_handle():
    """Mint an opaque, unpredictable acknowledgment handle for a
    deferred write. The petitioner gets it at submit and polls the
    result registry with it later (doc 05 §3, §4.8). Unpredictable by
    construction: the handle is the petitioner-binding identifier, so a
    guessable one would let another party probe for someone else's
    result (§4.8 caveat)."""
    return secrets.token_urlsafe(16)


def _ecash_action_params(op, request):
    """The minimal params the executor needs for an eCash write, so the
    timing queue stores only what the action requires rather than the
    whole request. fund_ecash carries amount_sats (already allowance-
    checked); defund_ecash carries the serialized token (doc 07 §3)."""
    if op == "fund_ecash":
        return {"amount_sats": _request_amount_sats(request)}
    return {"token": request.get("token")}


def _registry_write_params(op, resolved):
    """The minimal params the executor needs for a registry-gated write
    (manage_bitcoin / manage_lightning). Both carry the registry-resolved
    real destination - a Bitcoin address for manage_bitcoin, a bolt11 for
    manage_lightning (_pseudonymize_inbound wrote it into
    recipient_address) - the AI's declared amount in sats
    (informational for manage_lightning, whose bolt11 carries its own
    amount), and the original recipient_token so the executor can flip
    the registry entry used after a successful send (one-time-use,
    §4.7). Only what the action requires reaches the timing queue, not
    the whole request."""
    return {
        "recipient_address": resolved.get("recipient_address"),
        "recipient_token": resolved.get("recipient_token"),
        "amount_sats": _request_amount_sats(resolved),
    }


def _enqueue_write_and_ack(handler, op, params, deadline):
    """Hand a gate-passed write to the timing layer and acknowledge it -
    the single tail every write op shares (doc 05 §3, §4.6).

    Mint an opaque handle, enqueue the action (deferred by the
    action-delay window), and acknowledge at once with that handle. The
    executor (executor.py) drains the due action against the real
    backend (bitcoind / LND / the pinned mint), and the result registry
    surfaces the outcome on the petitioner's poll (doc 05 §4.8). A known
    write op never blocks the single-threaded request path on a backend
    call, and the not_implemented dispatch stub is gone from the write
    path entirely.

    Production timing windows are not yet computable (doc 05 §4.6,
    doc 07 §7: blocked on the dynamic-window work), so enqueue_action
    raises NotImplementedError there. The safe failure mode is "does
    not run": refuse uniformly rather than execute on an un-vetted
    window. SPACER_TIMING_MODE=test supplies windows and reaches the
    executor.

    The action_enqueued audit event records the ready_at the timing
    layer committed to, so the operator console can see the §4.6
    submit-to-execute hold as a scheduled decision (and how far out it
    landed, hold_s) rather than inferring it later from the executed
    event's timestamp. Operator-side only; the petitioner sees just
    the received-ack."""
    handle = _new_handle()
    try:
        ready_at = timing.enqueue_action(handle, op, params)
    except NotImplementedError:
        audit.record("decision_refuse_timing_unavailable", {"op": op})
        _respond_refused(handler, deadline)
        return
    audit.record("decision_allow", {"op": op})
    audit.record(
        "action_enqueued",
        {
            "op": op,
            "handle": handle,
            "ready_at": round(ready_at, 3),
            "hold_s": round(ready_at - time.time(), 3),
        },
    )
    _respond_ok(handler, {"status": "received", "handle": handle}, deadline)


# Uniform deferred-rejection payload. A gate-refused state-changing call
# is deposited into the result registry under this body (kind="rejection")
# once the rejection-delivery window elapses. It is the SAME shape the
# executor emits for a dispatched-but-failed action (executor.py's
# {"status": "failed"}), so a policy refusal is indistinguishable at poll
# from a genuine execution failure - and it is uniform across every gate
# (denomination, registry, standing approval, allowance, mode,
# unknown op), so the deferred outcome never leaks WHICH gate refused,
# the same non-leak the synchronous _REFUSED_BODY gives at submit. Treated
# as immutable (only ever handed to json.dumps in the timing layer).
_REJECTION_PAYLOAD = {"status": "failed"}


def _defer_rejection_and_ack(handler, op, deadline):
    """Defer a gate refusal through the result registry and acknowledge
    it with the SAME {"status": "received", "handle": ...} shape a
    gate-passed write returns (§4.7, §4.8; GLOSSARY 'Recipient address
    registry' probing-infeasibility / refusal-behavior).

    The point: a petitioner cannot tell at submit time - by response
    content OR by response timing - whether a state-changing call passed
    its gates or was refused. Both paths mint an opaque handle and return
    the received-ack, latency-normalized to the same deadline. The refusal
    surfaces only later, on the petitioner's poll, after the
    rejection-delivery window elapses (timing.py's rejection band, a
    randomized 1h ± 30min in production, §4.7), when the executor's result
    drainer deposits _REJECTION_PAYLOAD against the handle
    (executor.deliver_due_results). This closes the probing oracle the
    synchronous refusal used to be: an amount above a standing-approval
    band, or a token off the registry, no longer refuses instantly and for
    free - the outcome costs a delivery-window wait and carries no
    submit-to-response timing correlation. The caller already audit-logged
    the specific gate (decision_refuse_* / decision_defer_hitl), which
    stays operator-side; this tail records only the deferral, its
    handle, and the ready_at the timing layer committed to (so the
    console can tell a deferred-refusal handle from a real
    pending-action handle, and see when the uniform failure becomes
    deliverable - doc 13). ready_at/hold_s never cross the gateway.

    Production timing is blocked on sp-77lxs.3, so enqueue_result raises
    NotImplementedError there - exactly as enqueue_action does on the pass
    path (_enqueue_write_and_ack). The fallback is the SAME synchronous
    refusal the pass path falls back to, so pass and refuse stay
    wire-identical in production too: both collapse to the uniform
    {"status": "refused"} until the timing layer is wired, never a
    received-vs-refused split that would re-open the channel."""
    handle = _new_handle()
    try:
        ready_at = timing.enqueue_result(
            handle, _REJECTION_PAYLOAD, kind="rejection"
        )
    except NotImplementedError:
        audit.record("decision_refuse_timing_unavailable", {"op": op})
        _respond_refused(handler, deadline)
        return
    audit.record(
        "decision_defer_rejection",
        {
            "op": op,
            "handle": handle,
            "ready_at": round(ready_at, 3),
            "hold_s": round(ready_at - time.time(), 3),
        },
    )
    _respond_ok(handler, {"status": "received", "handle": handle}, deadline)


def _handle_ecash_write(handler, request, deadline):
    """Run an eCash write (fund_ecash / defund_ecash) through its
    gate pipeline (doc 07 §3, §8). Only reachable in ecash mode.

    fund_ecash: allowance cap -> standing approvals -> dispatch.
    defund_ecash: standing approvals -> dispatch (no allowance check -
    defund only shrinks exposure).

    The allowance check precedes standing approvals BY DESIGN (doc 07
    §8): a HITL approval cannot exceed the allowance, so raising the
    cap is a console config edit, never an approval click - the
    operator's tired "approve" cannot widen the blast radius.

    Standing approvals match on (op, _ECASH_DESTINATION, amount): the
    destination is structurally the operator-pinned mint, so no
    recipient_token exists to resolve and the registry step does not
    apply. defund_ecash carries no amount (the token's value is not
    parseable at the gate), so only an unbounded rule (no
    max_amount_sats) matches it - which is the right shape: defund
    reduces exposure regardless of size.

    The defund token itself is NOT validated here: decoding a cashuB
    token is the wallet's job, and the mint-pin rule (doc 07 §2) is
    enforced at execution time when the executor's swap-claim runs
    against the pinned mint. The gate's job is mode, allowance, and
    approval - not token parsing.

    Once the gates pass the write is enqueued on the timing layer (an
    opaque handle is returned synchronously) and drained by the
    executor (executor.py) against the pinned mint + our LND; the
    result registry surfaces the outcome on the petitioner's poll
    (doc 07 §3; doc 05 §3, §4.6, §4.8). The mint-facing steps are
    spaced by timing.mint_gap_s() (doc 07 §6 T1)."""
    op = request.get("op")
    amount = _request_amount_sats(request)
    if op == "fund_ecash":
        # Amount gate first (doc 12 G2): the funded amount is minted and
        # paid over LN exactly, so it must be a standard ladder
        # denomination or it is a fingerprint. Checked ahead of the
        # allowance cap - a malformed amount is refused on shape before
        # any float-headroom question. defund_ecash is exempt (no
        # gate-time amount; the token's value is already ladder-funded).
        if not denominations.is_allowed(amount):
            audit.record(
                "decision_refuse_denomination",
                {"op": op, "requested_sats": amount},
            )
            _defer_rejection_and_ack(handler, op, deadline)
            return
        ecash = _ecash()
        outstanding = ecash.outstanding_sats()
        allowance = ecash.allowance_sats()
        # A missing, non-integer, or non-positive amount fails the
        # allowance check: an amount the gate cannot bound is refused,
        # mirroring the standing-approvals rule that an unknown amount
        # fails any bounded rule. A missing config reads as allowance
        # 0 (ecash.allowance_sats), so the float cannot exist until
        # the operator explicitly writes its bound.
        if (
            not isinstance(amount, int)
            or amount <= 0
            or outstanding + amount > allowance
        ):
            audit.record(
                "decision_refuse_allowance",
                {
                    "op": op,
                    "requested_sats": amount,
                    "outstanding_sats": outstanding,
                    "allowance_sats": allowance,
                },
            )
            _defer_rejection_and_ack(handler, op, deadline)
            return
    if not standing_approvals.matches(op, _ECASH_DESTINATION, amount):
        audit.record(
            "decision_defer_hitl",
            {"op": op, "reason": "no_standing_approval"},
        )
        _hitl_park(request)
        _defer_rejection_and_ack(handler, op, deadline)
        return
    # Gates passed: hand the write to the timing layer + executor, which
    # drains it against the pinned mint + our LND (doc 07 §3; doc 05 §3,
    # §4.6, §4.8). Same enqueue-and-acknowledge tail every write shares.
    _enqueue_write_and_ack(
        handler, op, _ecash_action_params(op, request), deadline
    )


def _dispatch(request):
    """Serve a read op from its snapshot row and return the response,
    or None when no snapshot exists yet (the caller refuses uniformly).

    Only the read-only query ops reach here now. Every write op is
    enqueued on the timing layer and drained by executor.py
    (_enqueue_write_and_ack), so a write never calls _dispatch and the
    not_implemented fallback at the tail is reachable only by an
    unrecognized read op - a defensive default, since _known_read_ops()
    admits only query_balance / query_channels.

    Both ops serve the stored value verbatim (doc 15 §4): the refresh
    sweep (snapshots.refresh_due, driven by the executor drainer on a
    randomized event-independent clock) already ran the full
    presentation - backend read -> scale.present() -> quantize to the
    serve grid - at refresh time. Running present() here, per request,
    would let a mid-epoch tier shift move the served value at poll
    resolution, which is exactly the change-timing channel doc 15
    closes. Wire shapes are unchanged: balance_sats / capacity_sats
    carry the same integer-sat figures as before, only their freshness
    semantics changed. Which backend feeds each op (bitcoind vs the
    LND wallet for query_balance; LND channel totals, aggregated per
    §4.3, for query_channels) is the refresh sweep's concern now
    (snapshots._read_backend), mode-split exactly as dispatch used to.

    The per-request audit record is the served value plus the snapshot
    age (doc 15 §4.8): the operator sees what was told and how stale it
    was. The refresh-time real-vs-presented-vs-served pairing material
    lives in the snapshot_refresh event, once per refresh instead of
    once per read. The disclosure record is unchanged.

    Per GLOSSARY 'Read snapshot' and 'Scale cloaking'.
    """
    op = request.get("op")
    if op == "query_balance":
        snap = snapshots.serve("query_balance")
        if snap is None:
            return None
        served, age_s = snap
        audit.record(
            "balance_served",
            {"served_sats": served, "snapshot_age_s": round(age_s, 3)},
        )
        return {"status": "ok", "balance_sats": served}
    if op == "query_channels":
        # query_channels is an advanced-extension read; the onchain
        # router gates it before dispatch, so this branch only runs in
        # advanced mode (where the refresh sweep keeps a capacity row).
        snap = snapshots.serve("query_channels")
        if snap is None:
            return None
        served, age_s = snap
        audit.record(
            "capacity_served",
            {"served_sats": served, "snapshot_age_s": round(age_s, 3)},
        )
        return {"status": "ok", "capacity_sats": served}
    return {"status": "not_implemented", "op": op}


def _hide_secrets(response):
    """Strip arbiter-side secrets from outbound responses.

    Per-field filter rules land with the bitcoind/LND access work
    (sp-77lxs.10, sp-77lxs.11). The skeleton's dispatch returns no
    real data, so this is a structural no-op.
    """
    return response


def _band_outbound(response):
    """Replace numeric values on outbound with banded equivalents.

    Blocked on sp-77lxs.4 (band-edge randomization). The skeleton's
    dispatch returns no numeric values, so this is a structural no-op.
    """
    return response


def _aggregate_outbound(response):
    """Collapse outbound list-style responses to aggregates by default;
    per-item detail requires per-call audit-logged justification.

    Blocked on sp-77lxs.4. The skeleton's dispatch returns no list
    responses, so this is a structural no-op.
    """
    return response


def _respond_refused(handler, deadline):
    """Single uniform refusal. No reason field in the body, no
    distinguishing status code. Latency-normalized to the request
    deadline. Records the sent body in the disclosure record (doc 13
    §3: the petitioner-known column is projected from what actually
    crossed the gateway; this event is the minimal producer, its
    formalization tracked by sp-gm4)."""
    _hold_response(handler, deadline)
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(_REFUSED_BODY)))
    handler.end_headers()
    handler.wfile.write(_REFUSED_BODY)
    audit.record("disclosure", {"body": {"status": "refused"}})


def _respond_ok(handler, response, deadline):
    """Emit a well-formed response. Latency-normalized to the request
    deadline. Records the sent body verbatim in the disclosure record
    (doc 13 §3; see _respond_refused)."""
    body = json.dumps(response, separators=(",", ":"), sort_keys=True).encode("utf-8")
    _hold_response(handler, deadline)
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)
    audit.record("disclosure", {"body": response})


def _hold_response(handler, deadline):
    """Latency-normalize one response and make the hold operator-visible.

    Every response path funnels through here just before bytes go out:
    audit-log how long the pipeline actually worked (work_s) and how
    long the response is being held back to reach the uniform floor
    (held_s), then sleep to the deadline. The event is the mitigation's
    operator-side evidence: work_s varies by branch (a parse refusal is
    sub-millisecond, a snapshot read is not) while the petitioner-
    observable total is floor_s regardless - and a work_s at or above
    floor_s (held_s 0) is an overrun the operator should treat as a
    timing leak and raise the floor. Petitioner-facing timing is
    unchanged: the event is audit-only and never crosses the gateway."""
    floor_s = handler.server.latency_target
    held_s = deadline - time.monotonic()
    if held_s < 0:
        held_s = 0.0
    audit.record(
        "latency_normalized",
        {
            "floor_s": floor_s,
            "work_s": round(floor_s - held_s, 4),
            "held_s": round(held_s, 4),
        },
    )
    _wait_until(deadline)


def _wait_until(deadline):
    """Sleep until the monotonic deadline. The latency normalization
    floor: a request that finishes early is held back so per-response
    timing carries no information about which backend ran or how far
    along the pipeline progressed."""
    remaining = deadline - time.monotonic()
    if remaining > 0:
        time.sleep(remaining)


def make_server(host=None, port=None, latency_target=None):
    """Construct (but do not start) the gateway HTTPServer. Returns the
    server. The caller starts it with serve_forever() and stops it with
    shutdown(). Used by serve() below and by the smoke test."""
    bind_host = host or os.environ.get("ARBITER_HOST", DEFAULT_HOST)
    bind_port = int(port if port is not None else os.environ.get("ARBITER_PORT") or DEFAULT_PORT)
    target_s = (
        latency_target
        if latency_target is not None
        else float(os.environ.get("ARBITER_LATENCY_S", DEFAULT_LATENCY_TARGET_S))
    )
    server = HTTPServer((bind_host, bind_port), _Handler)
    # Stash the latency target on the server so _Handler instances can
    # reach it via self.server. HTTPServer is single-threaded by intent
    # (see serve()'s docstring).
    server.latency_target = target_s
    # Audit-log immediately after a successful bind: the OS socket is
    # listening at this point, even if serve_forever has not yet been
    # called. Logging here covers both the production boot path (via
    # serve() below) and the smoke-test path that calls make_server()
    # directly. If HTTPServer construction raises (e.g., port already
    # in use) no entry is written, so the log only ever shows real
    # gateway starts.
    audit.record("gateway_start", {
        "host": server.server_address[0],
        "port": server.server_address[1],
    })
    return server


def serve(host=None, port=None, latency_target=None):
    """Block-and-serve.

    Single-threaded by intent: the audit log and request pipeline
    serialize naturally on the underlying SQLite WAL and audit Lock,
    and threading would only buy throughput an arbiter that talks to
    one petitioner does not need. Single-threading also keeps the
    timing characteristics of the gateway predictable, which the
    latency-normalization mitigation depends on.
    """
    server = make_server(host, port, latency_target)
    try:
        server.serve_forever()
    finally:
        audit.record("gateway_stop", {})


if __name__ == "__main__":
    # Smoke test: spin up the gateway on an ephemeral port, send one
    # POST, verify the response shape and the audit-log records.
    import sys
    import tempfile
    import threading
    import urllib.request
    from pathlib import Path

    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-gateway-smoke.log"
    tmp_state = Path(tempfile.gettempdir()) / "arbiter-gateway-smoke.db"
    for p in (tmp_audit, tmp_state):
        if p.exists():
            p.unlink()
    audit.configure(tmp_audit)
    state.configure(tmp_state)
    state.migrate()
    # Test mode: snapshots.seed_for_test (the read-path sub-test) and the
    # deferred-rejection path both need it. A gate-refused write now
    # enqueues a kind="rejection" on the timing layer (the rejection band,
    # 1-5s in test mode) instead of refusing synchronously, so the
    # manage_bitcoin / unknown-op probes below exercise enqueue_result.
    os.environ["SPACER_TIMING_MODE"] = "test"

    # Bind port 0 so the OS picks a free ephemeral port; avoids
    # collisions if the smoke test runs concurrently.
    server = make_server(host="127.0.0.1", port=0, latency_target=0.05)
    bind_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        # Send a well-formed request with an unknown op. Unknown ops park
        # in HITL, but the gateway no longer refuses synchronously: it
        # defers the refusal through the result registry and returns the
        # SAME received-ack a gate-passed write returns, so submit carries
        # no recognized-vs-unknown-op signal. The petitioner sees only
        # received+handle; the HITL park and the deferral are audit-logged
        # for the operator.
        body = json.dumps({"op": "smoke_ping"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        t0 = time.monotonic()
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200, f"expected 200, got {resp.status}"
            response_body = resp.read()
        elapsed = time.monotonic() - t0
        # Latency normalization floor was 0.05s; the actual response must
        # not return faster than the floor (it applies to the deferred-
        # refusal path identically to a pass). Allow a small jitter
        # tolerance below the floor for clock granularity.
        assert elapsed >= 0.045, f"latency floor not enforced: elapsed {elapsed:.3f}s"
        unknown_ack = json.loads(response_body.decode("utf-8"))
        # Received-ack shape: exactly {status: received, handle: <str>},
        # byte-shape-identical to what a gate-passed write returns.
        assert set(unknown_ack) == {"status", "handle"}, unknown_ack
        assert unknown_ack["status"] == "received", unknown_ack
        assert isinstance(unknown_ack["handle"], str) and unknown_ack["handle"], unknown_ack

        # Send a known write op (manage_bitcoin) with an off-ladder
        # amount. The denomination gate (doc 12 G2) is checked first,
        # ahead of the registry, so an off-ladder amount is refused and
        # audits decision_refuse_denomination without needing a configured
        # registry. 1234 is not on DEFAULT_LADDER. The refusal is deferred:
        # the response is the received-ack, not a synchronous refusal.
        body = json.dumps(
            {"op": "manage_bitcoin", "recipient_token": "ABCDE4", "amount_sats": 1234}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            denom_ack = json.loads(resp.read().decode("utf-8"))
        assert isinstance(denom_ack.get("handle"), str) and denom_ack["handle"], denom_ack
        assert denom_ack == {"status": "received", "handle": denom_ack["handle"]}, denom_ack

        # Probe-cost / indistinguishability check (the property this bead
        # restores): the unknown-op refusal and the denomination refusal
        # are wire-indistinguishable from each other AND from a
        # gate-passed write - identical key set, identical status - so a
        # petitioner cannot tell at submit which gate fired, or whether
        # one fired at all. Only the random per-call handle differs; which
        # gate actually refused lives in the audit log, operator-side.
        assert set(unknown_ack) == set(denom_ack) == {"status", "handle"}, (
            unknown_ack,
            denom_ack,
        )
        assert unknown_ack["status"] == denom_ack["status"] == "received"

        # The deferred refusal is real, not dropped: a kind="rejection"
        # entry sits on the result side under the ack's handle, carrying
        # the uniform _REJECTION_PAYLOAD - the same {"status": "failed"}
        # the executor emits for a dispatched-but-failed action. Inspected
        # arbiter-internally; this never crosses the gateway.
        pend = timing.pending_result(denom_ack["handle"])
        assert pend is not None, "a gate refusal must queue a deferred rejection"
        _ready, rej_payload, rej_kind = pend
        assert rej_kind == "rejection", pend
        assert rej_payload == {"status": "failed"}, pend

        # Drive it through the result registry (what
        # executor.deliver_due_results does once the rejection window
        # elapses) and poll via HTTP: the refusal surfaces only now, in
        # the SAME {"status": "result", "result": {...}} envelope a real
        # outcome uses, with a payload uniform with a dispatched-but-
        # failed send. This is the "indistinguishable at the wire until
        # result delivery" property (doc 05 §4.7, §4.8).
        for _h, _res, _kind in timing.due_results(now=time.time() + 60.0):
            results.deposit(_h, _res, kind=_kind)
        body = json.dumps(
            {"op": "poll", "handle": denom_ack["handle"]}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            rej_poll = json.loads(resp.read().decode("utf-8"))
        assert rej_poll == {"status": "result", "result": {"status": "failed"}}, rej_poll

        # Send a malformed request (not JSON). Should also refuse
        # uniformly, with no information about the parse failure.
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=b"not json",
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8")) == {"status": "refused"}

        # Read path, pre-first-refresh (doc 15): no snapshot row exists,
        # so query_balance refuses uniformly - wire-indistinguishable
        # from every other refusal - and never touches a backend (none
        # is configured in this smoke; a live read would error, not
        # refuse). Audit logs decision_refuse_snapshot_unavailable.
        body = json.dumps({"op": "query_balance"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert json.loads(resp.read().decode("utf-8")) == {"status": "refused"}

        # Read path, snapshot present: the gateway serves the stored
        # value verbatim (no present(), no quantize, no backend - all
        # of that ran at refresh time) and audit-logs balance_served
        # with the snapshot age.
        snapshots.seed_for_test(
            "query_balance", 14_000, time.time() - 2.0, time.time() + 100.0
        )
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            served_body = json.loads(resp.read().decode("utf-8"))
        assert served_body == {"status": "ok", "balance_sats": 14_000}, served_body

        # Result-poll path (§4.8). Deposit a result behind the gateway,
        # then exercise the poll fast-path end-to-end via HTTP. The
        # poll has its own routing branch (read-only, no destination
        # gate) and returns the binary {"status": "result"|"not_yet"}
        # envelope.
        H = "smoke_handle"
        results.deposit(H, {"txid": "deadbeef"}, kind="result")

        body = json.dumps({"op": "poll", "handle": H}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            poll_body = json.loads(resp.read().decode("utf-8"))
        assert poll_body == {
            "status": "result",
            "result": {"txid": "deadbeef"},
        }, f"unexpected poll body: {poll_body!r}"

        # Second poll within the 10-min floor: indistinguishable
        # "not_yet" envelope, registry state untouched.
        body = json.dumps({"op": "poll", "handle": H}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            poll_body = json.loads(resp.read().decode("utf-8"))
        assert poll_body == {"status": "not_yet"}, (
            f"floor-throttled poll must return not_yet: {poll_body!r}"
        )

        # Poll for a never-existed handle: "not_yet", same envelope as
        # floor throttle and as already-consumed.
        body = json.dumps({"op": "poll", "handle": "never_existed"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            poll_body = json.loads(resp.read().decode("utf-8"))
        assert poll_body == {"status": "not_yet"}

        # Poll with no handle field: "not_yet" (bad input maps to the
        # uniform envelope on the wire).
        body = json.dumps({"op": "poll"}).encode("utf-8")
        req = urllib.request.Request(
            f"http://127.0.0.1:{bind_port}/",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            poll_body = json.loads(resp.read().decode("utf-8"))
        assert poll_body == {"status": "not_yet"}
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2)

    # Verify the audit log captured the boot event, every request
    # receipt, the HITL deferral, the two deferred-rejection tails, the
    # parse-failure refusal, and the result-poll path (deposit, ok,
    # throttled, unknown, bad_input, decision_allow for the poll calls).
    with open(tmp_audit) as f:
        records = [json.loads(line) for line in f if line.strip()]
    events = [r["event"] for r in records]
    assert "gateway_start" in events, events
    # 9 well-formed requests reach _parse_request: the smoke_ping
    # (unknown op), the off-ladder manage_bitcoin, the poll of the
    # deferred rejection, the two query_balance reads (pre-snapshot
    # refusal, snapshot-served), plus four more polls. The malformed
    # "not json" request is rejected at _parse_request before
    # request_received.
    assert events.count("request_received") == 9, events
    # Every sent response lands in the disclosure record (doc 13 §3):
    # the two write refusals (now received-acks), the deferred-rejection
    # poll, the parse-failure refusal, the two read responses, and the
    # four poll responses = 10.
    assert events.count("disclosure") == 10, events
    # Every sent response is latency-normalized AND audited as such:
    # one latency_normalized record per disclosure, carrying the floor,
    # the pipeline's actual work time, and the hold that padded it to
    # the floor. work_s + held_s == floor_s within rounding whenever
    # the pipeline finished early (held_s > 0).
    latency_recs = [r for r in records if r["event"] == "latency_normalized"]
    assert len(latency_recs) == 10, events
    for r in latency_recs:
        pl = r["payload"]
        assert pl["floor_s"] == 0.05, pl
        assert pl["held_s"] >= 0, pl
        assert set(pl) == {"floor_s", "work_s", "held_s"}, pl
    assert "decision_defer_hitl" in events, events
    # Both write refusals (unknown op, off-ladder denomination) defer
    # through the result registry rather than refusing synchronously,
    # each recording a decision_defer_rejection tail with its handle
    # and the rejection window's committed ready_at (a future epoch
    # timestamp; hold_s is its distance from enqueue, 1-5s in test
    # mode).
    assert events.count("decision_defer_rejection") == 2, events
    for r in records:
        if r["event"] != "decision_defer_rejection":
            continue
        pl = r["payload"]
        assert pl["ready_at"] > 0 and 0 < pl["hold_s"] <= 5.5, pl
    assert events.count("decision_refuse") == 1, events
    # The off-ladder manage_bitcoin was refused at the amount gate,
    # ahead of the registry (doc 12 G2) - now deferred, not synchronous.
    assert "decision_refuse_denomination" in events, events
    # Read path (doc 15): the pre-snapshot read refused with its own
    # audit marker; the served read recorded the served value + age.
    assert "decision_refuse_snapshot_unavailable" in events, events
    assert "balance_served" in events, events
    # Poll path: deposit, ok, throttled, unknown, bad_input must all
    # appear. The bad-input case audit-logs at the gateway layer
    # (decision_poll_bad_input) without reaching results.poll().
    for required in (
        "result_deposit",
        "result_poll_ok",
        "result_poll_throttled",
        "result_poll_unknown",
        "decision_poll_bad_input",
    ):
        assert required in events, f"audit missing {required}: {events!r}"
    # Four successful poll routings (the deferred-rejection poll, plus
    # ok, throttled, unknown) plus the snapshot-served read log
    # decision_allow; the bad-input poll uses its own marker
    # (decision_poll_bad_input), so decision_allow appears exactly 5 times.
    assert events.count("decision_allow") == 5, events
    print(f"OK: gateway pipeline round-trips at audit={tmp_audit}, port={bind_port}")
    sys.exit(0)
