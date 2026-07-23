#!/usr/bin/env python3
"""
live_sequence_t_runner.py - sequence T: the timing + amount-gate showcase.

One LIVE run against the captain-loop arbiter (Mutinynet signet, test-mode
timing windows) capturing the raw material for the two timing demos:

  T1 (amount gate + deferred refusal): two manage_bitcoin submits to the
     SAME registry token - 1234 sat (off the denomination ladder) and
     1000 sat (on it, cleared by standing approval). Both return
     byte-shape-identical received-acks on the wire; the audit log shows
     decision_refuse_denomination + decision_defer_rejection for one and
     the registry -> approval -> action_enqueued chain for the other.
     The refusal surfaces only on a later poll, as the SAME uniform
     {"status": "failed"} a genuinely failed send would produce.

  T2 (the timing shield): the passing send's full timeline - the
     latency-normalized ack, the action_enqueued ready_at commitment,
     the executor firing inside the 5-15 s test action window, the
     result-delay deposit, an early poll returning the binary not_yet,
     and the one successful poll after the 10-minute poll floor. Plus
     client-measured wire latencies showing every response type (read,
     pass-write, refuse-write, malformed) landing on the same 250 ms
     floor.

Unlike sequence D (a capability tour), this sequence deliberately
submits one refused call; unlike the exit loop, everything here is the
real gateway process, real windows, real chain. Submits and polls go
over raw HTTP - the petitioner's exact wire view - and every round-trip
is timed client-side. The 10-minute result-poll floor is honored: the
early poll is the FIRST poll on its handle (it anchors the floor), and
the retrieving poll waits out the full floor from that anchor.

Artifacts:
  ~/spacer/captain-loop/sequence-t/   step TUI captures, timings.json,
                                      summary.txt
  ~/spacer/demo/captures/T1-amount-gate/    audit.jsonl + tui.txt + notes.md
  ~/spacer/demo/captures/T2-timing-shield/  audit.jsonl + tui.txt + notes.md

The demo capture tui.txt is rendered from each demo's exact audit slice
through the real operator-console Renderer (arbiter/src/tui.py), same as
the mode-demo suite. Cost per run: one on-chain self-send mining fee.
Stdlib only.
"""
import io
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_sequence_runner as R  # noqa: E402  (also puts arbiter/src on path)
import tui                        # noqa: E402  (the real console renderer)

# Amounts (doc 12 G2). 1000 is the smallest DEFAULT_LADDER rung; 1234 is
# deliberately off-ladder - the same probe pair the S7 negatives and the
# exit-loop refused-denomination variants use.
AMOUNT_PASS = 1000
AMOUNT_OFF_LADDER = 1234

# The §4.8 poll floor (results.POLL_FLOOR_S) plus slack: the retrieving
# poll on the passing handle waits this long after that handle's first
# (floor-anchoring) poll.
POLL_FLOOR_WAIT_S = 605

T_DIR = R.SESSION / "sequence-t"
CAPTURES = Path.home() / "spacer" / "demo" / "captures"

# Render geometry, pinned like the mode-demo builder's (byte-stable
# captures; small PAD keeps the doc-13 secret blocks short).
_TUI_WIDTH = 150
_TUI_PAD = 6

# Gateway-thread audit events (as opposed to executor/drainer-thread
# ones). Used to slice per-request chains out of the shared live log:
# a request's records run contiguously from its request_received to its
# disclosure except where a background thread interleaves, so chain
# collection skips non-gateway events and drainer events are picked by
# handle/token instead.
_GATEWAY_EVENTS = {
    "request_received", "decision_refuse", "decision_refuse_denomination",
    "decision_refuse_registry", "decision_refuse_mode",
    "decision_refuse_allowance", "decision_refuse_snapshot_unavailable",
    "decision_refuse_timing_unavailable", "decision_defer_hitl",
    "decision_defer_rejection", "decision_allow", "decision_poll_bad_input",
    "action_enqueued", "registry_lookup_ok", "registry_lookup_failed",
    "standing_approval_match", "standing_approval_no_match",
    "balance_served", "capacity_served", "result_poll_ok",
    "result_poll_throttled", "result_poll_unknown",
    "result_poll_already_consumed", "latency_normalized", "disclosure",
}


def timed_post(label, data, timings, timeout=30):
    """raw HTTP POST, client-side wall-clock timed - the petitioner's
    exact wire view of one round-trip."""
    t0 = time.monotonic()
    resp = R.raw_post(data, timeout=timeout)
    elapsed = time.monotonic() - t0
    timings.append({"label": label, "elapsed_s": round(elapsed, 4)})
    R.log(f"  {label}: {elapsed*1000:.0f} ms -> {json.dumps(resp)[:80]}")
    return resp


def timed_op(label, obj, timings):
    return timed_post(label, json.dumps(obj).encode("utf-8"), timings)


def read_run_records(audit_path, start_pos):
    """All audit records this run appended (from the watch-start byte
    offset), in order."""
    out = []
    with open(audit_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(start_pos)
        for line in f.read().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def gateway_chains(records):
    """Split the run's records into per-request gateway chains.

    Returns a list of chains, each the contiguous gateway-thread records
    of one request, ending at its disclosure. A body-parse failure has
    no request_received; its chain opens at the decision_refuse
    (reason=parse_failure) the gateway logs first. Non-gateway events
    (snapshot_refresh, executor/drainer records) are skipped - they are
    selected separately, by handle/token."""
    chains = []
    current = None
    for rec in records:
        e = rec.get("event")
        if e not in _GATEWAY_EVENTS:
            continue
        if e == "request_received":
            if current:
                chains.append(current)
            current = [rec]
            continue
        if current is None:
            current = [rec]
        else:
            current.append(rec)
        if e == "disclosure":
            chains.append(current)
            current = None
    if current:
        chains.append(current)
    return chains


def chain_for(chains, pred):
    for c in chains:
        if pred(c):
            return c
    raise R.StepError(f"no gateway chain matched {pred.__doc__ or pred}")


def req_matches(op=None, amount=None, handle=None):
    def pred(chain):
        head = chain[0]
        if head.get("event") != "request_received":
            return False
        pl = head.get("payload") or {}
        if op is not None and pl.get("op") != op:
            return False
        if amount is not None and pl.get("amount_sats") != amount:
            return False
        if handle is not None and pl.get("handle") != handle:
            return False
        return True
    pred.__doc__ = f"request op={op} amount={amount} handle={handle}"
    return pred


def parse_failure_chain(chains):
    for c in chains:
        if any(r.get("event") == "decision_refuse"
               and (r.get("payload") or {}).get("reason") == "parse_failure"
               for r in c):
            return c
    raise R.StepError("no parse-failure chain found")


def drainer_events(records, names, handle=None, token=None):
    out = []
    for rec in records:
        if rec.get("event") not in names:
            continue
        pl = rec.get("payload") or {}
        if handle is not None and pl.get("handle") != handle:
            continue
        if token is not None and pl.get("token") != token:
            continue
        out.append(rec)
    return out


def render_slice(records):
    """Feed a slice through the real operator-console Renderer, return
    the plain-text two-column grid (ANSI stripped) - the same render
    path the mode-demo builder uses."""
    out = io.StringIO()
    r = tui.Renderer(out=out, pad=_TUI_PAD, width=_TUI_WIDTH)
    r.header()
    for rec in records:
        r.feed(rec)
    r.flush_pending()
    text = out.getvalue()
    for code in (tui._GREEN, tui._DIM_GREEN, tui._RED, tui._DIM_RED,
                 tui._BOLD, tui._YELLOW, tui._RESET):
        text = text.replace(code, "")
    return text


def write_capture(name, records, notes):
    cdir = CAPTURES / name
    cdir.mkdir(parents=True, exist_ok=True)
    with open(cdir / "audit.jsonl", "w") as f:
        for rec in records:
            f.write(json.dumps(rec) + "\n")
    (cdir / "tui.txt").write_text(render_slice(records))
    (cdir / "notes.md").write_text(notes)
    R.log(f"  capture {name}: {len(records)} events -> {cdir}")


def run():
    p = R.paths()
    if not R.gateway_up():
        raise R.StepError("gateway not up; run sequence-A setup first")
    if not R.tui_acknowledged():
        raise R.StepError("TUI not acknowledged - clear the console safety gate first")
    T_DIR.mkdir(parents=True, exist_ok=True)
    watch = R.AuditWatch(p["audit"])
    start_pos = watch.pos
    timings = []
    t_run0 = time.time()

    wb0, cb0 = R.node_balances()
    R.log(f"T start: onchain={wb0} ln_local={cb0}")

    # --- latency probes: a read and a malformed frame ----------------
    qb = timed_op("probe query_balance", {"op": "query_balance"}, timings)
    if qb.get("status") != "ok":
        raise R.StepError(f"probe read failed: {qb}")
    bad = timed_post("probe malformed", b"not json", timings)
    if bad != {"status": "refused"}:
        raise R.StepError(f"malformed probe unexpected: {bad}")

    # --- provision: one fresh self-send destination token ------------
    watch.mark()
    addr = R.lncli("newaddress", "p2wkh")["address"]
    tok = R.registry_add(addr)
    R.log(f"T provision: tok={tok} (fresh self-send address)")

    # --- the two submits: off-ladder vs ladder, SAME token -----------
    ack_a = timed_op(
        f"submit manage_bitcoin {AMOUNT_OFF_LADDER} (off-ladder)",
        {"op": "manage_bitcoin", "recipient_token": tok,
         "amount_sats": AMOUNT_OFF_LADDER}, timings)
    watch.wait_for(R.ev("decision_refuse_denomination", op="manage_bitcoin"),
                   10, "denomination refusal")
    ack_b = timed_op(
        f"submit manage_bitcoin {AMOUNT_PASS} (ladder)",
        {"op": "manage_bitcoin", "recipient_token": tok,
         "amount_sats": AMOUNT_PASS}, timings)
    h_a, h_b = ack_a.get("handle"), ack_b.get("handle")
    # The wire property under test: identical key set, identical status;
    # only the random per-call handle differs.
    if not (set(ack_a) == set(ack_b) == {"status", "handle"}
            and ack_a["status"] == ack_b["status"] == "received"
            and h_a and h_b and h_a != h_b):
        raise R.StepError(f"acks not shape-identical: {ack_a} vs {ack_b}")
    R.log("  acks are shape-identical (status=received + opaque handle)")
    enq = watch.wait_for(R.ev("action_enqueued", op="manage_bitcoin"),
                         10, "action_enqueued commitment")
    R.log(f"  action_enqueued: hold_s={enq['payload'].get('hold_s')}")

    # --- early poll on the passing handle: binary not_yet ------------
    time.sleep(2)
    early = timed_op("poll B early (t+2s)", {"op": "poll", "handle": h_b},
                     timings)
    t_floor_anchor = time.time()
    if early != {"status": "not_yet"}:
        raise R.StepError(f"early poll unexpected: {early}")

    # --- the deferred refusal surfaces: poll A after its deposit -----
    watch.wait_for(R.ev("result_deposit", handle=h_a), 30,
                   "rejection deposit (A)")
    res_a = timed_op("poll A (after rejection deposit)",
                     {"op": "poll", "handle": h_a}, timings)
    if res_a != {"status": "result", "result": {"status": "failed"}}:
        raise R.StepError(f"deferred refusal poll unexpected: {res_a}")
    R.log("  refusal surfaced as the uniform failed result")

    # --- the passing send executes inside its window -----------------
    exe = watch.wait_for(R.ev("manage_bitcoin_executed", handle=h_b), 60,
                         "on-chain execution (B)")
    watch.wait_for(R.ev("registry_consume", token=tok), 30, "token consume")
    watch.wait_for(R.ev("result_deposit", handle=h_b), 60,
                   "result deposit (B)")
    R.log(f"  executed: txid={str(exe['payload'].get('txid'))[:16]}... "
          "(operator-only)")
    R.tui_capture(T_DIR, "t-mid",
                  ["decision_refuse_denomination", "action_enqueued",
                   "manage_bitcoin_executed"])

    # --- wait out the poll floor, then the ONE retrieving poll -------
    wait_s = max(0, POLL_FLOOR_WAIT_S - (time.time() - t_floor_anchor))
    R.log(f"T floor: waiting {wait_s:.0f}s (10-min poll floor from the "
          "early poll)")
    time.sleep(wait_s)
    res_b = timed_op("poll B (past the floor)", {"op": "poll", "handle": h_b},
                     timings)
    if res_b != {"status": "result",
                 "result": {"status": "sent", "amount_sats": AMOUNT_PASS}}:
        raise R.StepError(f"final poll unexpected: {res_b}")
    R.tui_capture(T_DIR, "t-final", ["result_poll_ok"])

    # --- summary -----------------------------------------------------
    wb1, cb1 = R.node_balances()
    dur = round(time.time() - t_run0, 1)
    fee = (wb0 + cb0) - (wb1 + cb1)
    R.log(f"T DONE ({dur}s). onchain {wb0} -> {wb1} (self-send; loss "
          f"{fee} sat = mining fee)")
    (T_DIR / "timings.json").write_text(json.dumps(timings, indent=2))
    (T_DIR / "summary.txt").write_text(
        f"seqT {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ({dur}s)\n"
        f"handles: refused={h_a} passed={h_b} token={tok}\n"
        f"onchain {wb0} -> {wb1}; ln_local {cb0} -> {cb1}; loss={fee}\n"
        + "".join(f"{t['label']}: {t['elapsed_s']*1000:.0f} ms\n"
                  for t in timings))
    # Enough to rebuild the demo captures from the recorded run (the
    # `rebuild` subcommand) after a renderer or notes change, without
    # re-running the live beats.
    (T_DIR / "run-meta.json").write_text(json.dumps(
        {"start_pos": start_pos, "h_a": h_a, "h_b": h_b, "token": tok,
         "timings": timings}, indent=2))

    build_captures(read_run_records(p["audit"], start_pos),
                   h_a, h_b, tok, timings)
    return 0


def build_captures(records, h_a, h_b, tok, timings):
    """Slice one recorded sequence-T run into the two demo capture dirs."""
    chains = gateway_chains(records)

    reg_add = drainer_events(records, {"registry_add"}, token=tok)
    ch_sub_a = chain_for(chains, req_matches(op="manage_bitcoin",
                                            amount=AMOUNT_OFF_LADDER))
    ch_sub_b = chain_for(chains, req_matches(op="manage_bitcoin",
                                            amount=AMOUNT_PASS))
    ch_poll_a = chain_for(chains, req_matches(op="poll", handle=h_a))
    ch_poll_b1 = chain_for(chains, req_matches(op="poll", handle=h_b))
    ch_poll_b2 = None
    for c in chains:
        if req_matches(op="poll", handle=h_b)(c) and c is not ch_poll_b1:
            ch_poll_b2 = c
    if ch_poll_b2 is None:
        raise R.StepError("second poll-B chain not found")
    ch_read = chain_for(chains, req_matches(op="query_balance"))
    ch_bad = parse_failure_chain(chains)
    dep_a = drainer_events(records, {"result_deposit"}, handle=h_a)
    dep_b = drainer_events(records, {"result_deposit"}, handle=h_b)
    exe_b = drainer_events(records, {"manage_bitcoin_executed"}, handle=h_b)
    consume = drainer_events(records, {"registry_consume"}, token=tok)

    t1 = (reg_add + ch_sub_a + ch_sub_b + dep_a + ch_poll_a
          + exe_b + consume + dep_b + ch_poll_b2)
    # T2's latency beat compares all four pipeline branches, so the
    # refused submit's chain belongs in this slice too (T1 tells its
    # policy story; here it is one of the latency data points).
    t2 = (ch_read + ch_bad + ch_sub_a + ch_sub_b + ch_poll_b1
          + exe_b + consume + dep_b + ch_poll_b2)

    # The run's own date (from its first record), stable across rebuilds.
    run_date = (records[0].get("ts") or "")[:10] if records else "unknown"

    def fmt_ms(label):
        for t in timings:
            if t["label"].startswith(label):
                return f"{t['elapsed_s']*1000:.0f}"
        return "?"

    t1_notes = f"""# T1-amount-gate - capture provenance

Two-column operator-console render (`tui.txt`) of the audit slice this demo
cites (`audit.jsonl`). LEFT column = PETITIONER-KNOWN (what the sandboxed AI
sees); RIGHT column = PETITIONER-NEVER-KNOWN (operator ground truth). Mutinynet
signet; every sat is a valueless test sat.

Single live run (sequence T, {run_date}): one
wall clock, real chronology - submits over raw HTTP against the live gateway
:8420, real test-mode timing windows, real chain. The adversary in this threat
model is the operator's OWN sandboxed AI agent; the capture shows the
operator's own gateway protecting the operator's own data.

Beats, in order:
- registry_add: the operator mints token {tok} for a fresh self-send address
- submit manage_bitcoin {AMOUNT_OFF_LADDER} sat (OFF the denomination ladder), token
  {tok} -> decision_refuse_denomination + decision_defer_rejection; the wire
  still says received + handle ({fmt_ms('submit manage_bitcoin 1234')} ms)
- submit manage_bitcoin {AMOUNT_PASS} sat (ladder rung), same token -> registry
  resolves, standing approval matches, decision_allow + action_enqueued; the
  wire says received + handle ({fmt_ms('submit manage_bitcoin 1000')} ms) -
  byte-shape-identical to the refused ack
- result_deposit (rejection band) then poll: the refusal surfaces as the
  uniform {{"status": "failed"}} - indistinguishable from a genuinely failed
  send; which gate fired stays operator-side
- manage_bitcoin_executed + registry_consume + result_deposit + the one
  retrieving poll past the 10-min floor: the passing send's real outcome
  (txid operator-only; the AI sees status=sent + its own chosen amount)

Regenerate: `python3 test-harness/scripts/live_sequence_t_runner.py`
(a fresh run re-executes everything live; handles, txids, and timestamps
change, the shapes and the refusal behavior do not).
"""

    t2_notes = f"""# T2-timing-shield - capture provenance

Two-column operator-console render (`tui.txt`) of the audit slice this demo
cites (`audit.jsonl`). LEFT column = PETITIONER-KNOWN (what the sandboxed AI
sees); RIGHT column = PETITIONER-NEVER-KNOWN (operator ground truth). Mutinynet
signet; every sat is a valueless test sat.

Single live run (sequence T, {run_date}), same
run as T1-amount-gate. Client-measured wire round-trips (the petitioner's own
clock): query_balance {fmt_ms('probe query_balance')} ms, malformed frame
{fmt_ms('probe malformed')} ms, refused submit
{fmt_ms('submit manage_bitcoin 1234')} ms, passing submit
{fmt_ms('submit manage_bitcoin 1000')} ms, polls
{fmt_ms('poll B early')} / {fmt_ms('poll A')} /
{fmt_ms('poll B (past the floor)')} ms - every branch lands on the same
250 ms latency floor (ARBITER_LATENCY_S default; latency_normalized events
carry each response's real work_s vs held_s on the operator side).

Beats, in order:
- query_balance read + a malformed (non-JSON) frame: two pipeline branches,
  identical wire latency
- submit manage_bitcoin {AMOUNT_OFF_LADDER} sat (off-ladder, refused-deferred):
  the gate-refused write branch of the latency comparison
- submit manage_bitcoin {AMOUNT_PASS} sat -> received-ack at the floor;
  action_enqueued records the ready_at the timing layer committed to
  (hold inside the 5-15 s test action window; production is a ~12 h floor)
- early poll at t+2 s -> binary not_yet (result_poll_unknown operator-side);
  this first poll anchors the handle's 10-minute poll floor
- manage_bitcoin_executed inside the window; result_deposit after the
  result-delay window
- the ONE retrieving poll, {POLL_FLOOR_WAIT_S} s after the anchor ->
  status=sent; polling faster than the floor would have returned the same
  not_yet and revealed nothing

Regenerate: `python3 test-harness/scripts/live_sequence_t_runner.py`
(a fresh run re-executes everything live; handles, txids, and timestamps
change, the shapes and the windows' bounds do not).
"""

    write_capture("T1-amount-gate", t1, t1_notes)
    write_capture("T2-timing-shield", t2, t2_notes)
    return 0


def rebuild():
    """Rebuild both demo capture dirs from the most recent recorded run
    (run-meta.json), without re-running the live beats - for iterating
    on the slice composition, notes, or renderer. Assumes the audit log
    still holds the run's records at the recorded offset."""
    meta = json.loads((T_DIR / "run-meta.json").read_text())
    records = read_run_records(R.paths()["audit"], meta["start_pos"])
    return build_captures(records, meta["h_a"], meta["h_b"],
                          meta["token"], meta["timings"])


if __name__ == "__main__":
    try:
        if len(sys.argv) > 1 and sys.argv[1] == "rebuild":
            sys.exit(rebuild())
        sys.exit(run())
    except R.StepError as e:
        R.log(f"FAIL: {e}")
        try:
            w = R.AuditWatch(R.paths()["audit"])
            w.pos = max(0, w.pos - 6000)
            for rec in w.tail(20):
                R.log(f"  audit: {json.dumps(rec)[:200]}")
        except Exception:
            pass
        sys.exit(1)
