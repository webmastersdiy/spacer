"""
Privacy gateway: the only network-reachable component on the arbiter.

Every petitioner request hits this module first. The handler runs each
inbound request through a fixed pipeline of mechanisms (parse,
allowlist, pseudonymize-inbound, dispatch, hide-secrets, band-outbound,
aggregate-outbound, latency-normalize) and audit-logs at every decision
point. There are no other entry points to the arbiter from the network:
bitcoind, LND, the audit log, local state, and the timing layer all sit
behind this module.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.1.

Several mechanisms are placeholders pending open design questions or
later beads:
- outbound allowlist: blocked on sp-77lxs.2 (policy table format).
- numeric banding and aggregate-by-default: blocked on sp-77lxs.4
  (band-edge randomization).
- inbound pseudonymize (token-to-real lookup): wired up by sp-77lxs.13
  (recipient address registry).
- dispatch into arbiter internals (timing layer, bitcoind/LND access):
  wired up by sp-77lxs.10/11/12.
- result-poll endpoint: wired up by sp-77lxs.14 (result registry).

The placeholders are kept as their own named functions so a non-AI
reviewer can confirm at a glance which mechanisms are present in
structure and which are wired in behavior.
"""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import audit
import lnd
import registry
import results
import state

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
# small (one JSON object per call), so 64 KiB is generous.
MAX_REQUEST_BYTES = 65536

# Refusal response shape. A single uniform body for every refusal so
# the response itself does not leak which step refused (parse failure,
# allowlist refusal, HITL deferral, etc. all look identical to the
# petitioner). The audit log differentiates the cause for the operator.
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
            _wait_until(self._latency_deadline)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(_REFUSED_BODY)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(_REFUSED_BODY)
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
    audit.record("request_received", {"op": op})

    # Read-only result poll (§4.8). The poll path is the only
    # petitioner-reachable read into arbiter state and is structurally
    # different from state-changing calls:
    # - The outbound allowlist gates state-changing or network-touching
    #   calls; a read of arbiter-internal storage is not state-changing.
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

    # Outbound allowlist gate. State-changing or network-touching calls
    # must be admitted by policy before they reach bitcoind/LND. Calls
    # that fall outside the allowlist fast path park in the HITL queue
    # for an out-of-band human assent (§6).
    if not _allowlist_admits(request):
        audit.record("decision_defer_hitl", {"op": op})
        _hitl_park(request)
        _respond_refused(handler, deadline)
        return

    # Inbound pseudonymize: resolve any petitioner-supplied tokens
    # to the real identifiers held in local state. The recipient
    # address registry (§4.7) is consulted for the recipient_token
    # field; on refusal the request collapses to the uniform
    # "destination unavailable" body, audit-differentiated by the
    # registry. None signals refuse-to-petitioner.
    request = _pseudonymize_inbound(request)
    if request is None:
        _respond_refused(handler, deadline)
        return

    # Dispatch into arbiter internals. The internals do not exist yet
    # (timing layer + bitcoind/LND clients are downstream beads), so
    # every call lands on the not-implemented stub. Keeping this as a
    # single function call makes the no-bypass property auditable: a
    # reviewer can confirm by inspection that the gateway never reaches
    # past _dispatch into anything else.
    response = _dispatch(request)

    # Outbound filtering. Each step is a placeholder until the
    # corresponding read-path APIs land; structure is here so wiring
    # is mechanical when the policy lands.
    response = _hide_secrets(response)
    response = _band_outbound(response)
    response = _aggregate_outbound(response)

    audit.record("decision_allow", {"op": op})
    _respond_ok(handler, response, deadline)


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


# Read-only ops the gateway admits without consulting a policy table.
# These touch arbiter-internal node state (LND wallet / channel
# balances), have no recipient_token, are not state-changing, and the
# response is banded before egress so per-call values do not leak
# precise satoshi totals to the petitioner. sp-77lxs.2's policy table
# format will replace this hardcoded set with a queryable schema; until
# then this minimal frozenset is the partial allowlist the read-only
# exit-loop variants exercise end-to-end. State-changing ops
# (send_bitcoin, send_lightning) remain default-refused.
_ALLOWED_READ_OPS = frozenset({"query_balance", "query_channels"})


def _allowlist_admits(request):
    """Outbound allowlist gate.

    Backed by policy tables in local state. Schema for those tables is
    blocked on sp-77lxs.2; until that lands, the gateway admits the
    fixed read-only set in _ALLOWED_READ_OPS and refuses every other
    call. State-changing ops therefore still hit the strict-default
    refuse path - no send_bitcoin or send_lightning request escapes
    this gate while the policy is unwritten.
    """
    return request.get("op") in _ALLOWED_READ_OPS


def _hitl_park(request):
    """Park an inbound call that fell outside the allowlist fast path
    in the HITL queue. The operator approves or denies at the directly
    attached arbiter console; the petitioner only learns the outcome
    later, via the result registry, after the operator decides.

    The HITL queue table lands with sp-77lxs.7's local state schema
    (table TBD). For the skeleton this is an audit-log-only marker;
    no row is written, no async path runs, and the call returns
    refused immediately. That preserves the petitioner-visible
    behavior (uniform refusal) while leaving the wire-up point
    explicit for review.
    """
    pass


def _pseudonymize_inbound(request):
    """Resolve petitioner-supplied tokens to real identifiers.

    Looks for an optional `recipient_token` field. If present, the
    recipient address registry (§4.7) resolves the token to the real
    address, and the request is rewritten to carry both the
    `recipient_address` (for dispatch) and the original
    `recipient_token` (so the dispatch layer can call
    registry.consume() after a successful send). On any registry
    refusal (unknown / expired / used / bad checksum / anomalous /
    wrong type), returns None so the caller emits the uniform
    "destination unavailable" body. If the field is absent, returns
    the request unchanged.

    Per §4.7 production timing, registry refusals are deferred by
    the rejection-delivery delay (1 hour ± 30 min) before the
    petitioner sees them. The current gateway refuses synchronously;
    sp-77lxs.14 (result registry) wires the deferred-rejection path
    so the petitioner picks up "destination unavailable" via the
    normal poll cadence, breaking the submission-to-response timing
    channel.
    """
    token = request.get("recipient_token")
    if token is None:
        return request
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


# Fixed band resolution for the read-only query responses. Production
# banding (sp-77lxs.4) replaces this with randomized band edges that
# rotate per call; the floored form here is deterministic so the
# exit-loop test artifacts diff cleanly across runs. The 10_000-sat
# (~0.0001 BTC) resolution is wide enough that wallet-level dust
# movements do not change the banded value.
_BAND_SATS = 10_000


def _band_sats(amount):
    """Floor-band an integer satoshi amount to _BAND_SATS resolution."""
    return (int(amount) // _BAND_SATS) * _BAND_SATS


def _dispatch(request):
    """Hand the (post-allowlist, post-pseudonymize) request to arbiter
    internals.

    Only the read-only query ops are wired in this skeleton. State-
    changing ops never reach this function (the allowlist refuses
    them above) so dispatch's "not_implemented" fallback covers
    forward-compatibility for any op that slips past a future
    allowlist change without a matching dispatch entry.

    query_balance returns the LND on-chain wallet's total balance,
    floor-banded to _BAND_SATS so the precise satoshi value never
    leaves the arbiter (mitigation map: numeric banding).

    query_channels returns the LND channel pool's aggregate capacity
    (local + remote, also banded). Aggregate-by-default per §4.3:
    per-channel detail is suppressed without a per-call justification.
    """
    op = request.get("op")
    if op == "query_balance":
        raw = lnd.walletbalance()
        total = int(raw.get("total_balance", "0"))
        return {"status": "ok", "balance_sats": _band_sats(total)}
    if op == "query_channels":
        raw = lnd.channelbalance()
        local = int(raw.get("local_balance", {}).get("sat", "0"))
        remote = int(raw.get("remote_balance", {}).get("sat", "0"))
        return {"status": "ok", "capacity_sats": _band_sats(local + remote)}
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
    deadline."""
    _wait_until(deadline)
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(_REFUSED_BODY)))
    handler.end_headers()
    handler.wfile.write(_REFUSED_BODY)


def _respond_ok(handler, response, deadline):
    """Emit a well-formed response. Latency-normalized to the request
    deadline."""
    body = json.dumps(response, separators=(",", ":"), sort_keys=True).encode("utf-8")
    _wait_until(deadline)
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


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

    # Bind port 0 so the OS picks a free ephemeral port; avoids
    # collisions if the smoke test runs concurrently.
    server = make_server(host="127.0.0.1", port=0, latency_target=0.05)
    bind_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        # Send a well-formed request. The skeleton refuses everything
        # via the allowlist (allowlist is unwritten), so the response
        # is the uniform refusal body.
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
        # Latency normalization floor was 0.05s; the actual response
        # must not return faster than the floor. Allow a small jitter
        # tolerance below the floor for clock granularity.
        assert elapsed >= 0.045, f"latency floor not enforced: elapsed {elapsed:.3f}s"
        decoded = json.loads(response_body.decode("utf-8"))
        assert decoded == {"status": "refused"}, f"unexpected body: {decoded!r}"

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

        # Result-poll path (§4.8). Deposit a result behind the gateway,
        # then exercise the poll fast-path end-to-end via HTTP. The
        # poll bypasses the allowlist (read-only) and returns the
        # binary {"status": "result"|"not_yet"} envelope.
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
    # receipt, the HITL deferral, the parse-failure refusal, and the
    # result-poll path (deposit, ok, throttled, unknown, bad_input,
    # decision_allow for the four poll calls).
    with open(tmp_audit) as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    assert "gateway_start" in events, events
    # 5 well-formed requests reach _parse_request: the original
    # smoke_ping, plus four polls. The malformed request is rejected
    # before request_received via send_error.
    assert events.count("request_received") == 5, events
    assert "decision_defer_hitl" in events, events
    assert events.count("decision_refuse") == 1, events
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
    # Three successful poll routings (ok, throttled, unknown) plus
    # the bad-input case all log decision_allow / decision_poll_bad_input;
    # decision_allow appears exactly 3 times (one per non-bad-input
    # poll) - the bad-input path uses its own marker.
    assert events.count("decision_allow") == 3, events
    print(f"OK: gateway pipeline round-trips at audit={tmp_audit}, port={bind_port}")
    sys.exit(0)
