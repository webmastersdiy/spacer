"""
Result registry (§4.8).

Arbiter-side storage for completed results - and for delayed
rejections - awaiting petitioner pickup. After the result-delay
window elapses on a valid action, or after the rejection-delivery
window elapses on a §4.7 "destination unavailable" outcome, the
(filtered, banded, tokenized) result is deposited into this
registry against the original handle. The petitioner retrieves it
by polling the privacy gateway for that handle.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.8.

Four properties:

1. Pull-only. The arbiter never initiates contact with the
   petitioner. There is no callback, no push, no notification
   channel. Implemented by absence: nothing in this module reaches
   outward; results sit in storage until the petitioner asks.

2. Binary state. Every poll returns either ("result", payload, kind)
   or ("not_yet", None, None). There is no "in progress", no
   progress percentage, no estimated time remaining. The petitioner
   reasons about elapsed time entirely from its own local estimate
   (§5.2).

3. 10-minute poll floor. Successive polls for the same handle are
   throttled to a minimum interval of POLL_FLOOR_S seconds. Polls
   issued faster than the floor get the same "not yet" response
   without consulting the results table, so a polling cadence
   faster than 10 min reveals nothing the cadence at 10 min would
   not. The floor (a) matches bitcoin block cadence, (b) caps
   inference precision against the multi-hour delay window, (c)
   flattens result-shape-specific cadences so chain-vs-LN cannot
   be inferred from polling rhythm, (d) caps the load the AI can
   put on the gateway by poll-storming.

4. Idempotent retrieval. A successful poll marks the entry consumed.
   Subsequent polls for the same handle return "not yet"
   indistinguishably from a never-existed handle, so the petitioner
   cannot replay a result by re-asking, and a handle that was
   retrieved cannot be distinguished from a handle that never
   existed.

The petitioner-visible payload shape inside "result" is open
(sp-77lxs.1); this module is agnostic to it. Whatever JSON-
serializable value the deposit caller passes is what the polling
caller gets back. The kind parameter ("result" / "rejection") is
recorded for audit triage but is not part of the petitioner-visible
poll response - the deposited payload is self-describing on its own.

Stdlib only.
"""
import json
import sqlite3
import time

import audit
import state


# §4.8: 10-minute poll floor. Aligned with bitcoin block cadence so
# polling resolution sits well below any inference precision useful
# against the multi-hour delay window.
POLL_FLOOR_S = 600.0


# Two tables.
#
# results holds the deposited outcome, one row per handle.
# UNIQUE-by-PRIMARY-KEY enforces that a handle is deposited at most
# once; the timing layer's pending_results table guarantees exactly-
# once delivery to here by deleting the pending entry when due.
# consumed flips from 0 to 1 on the first successful poll and never
# flips back, giving idempotent retrieval. consumed_at is recorded
# for operator triage only; it never crosses the privacy gateway.
#
# result_poll_floor holds the wall-clock timestamp of the most
# recent poll that was NOT throttled by the floor. Throttled polls
# do not update this row, so the floor is measured from the last
# "real" poll: a petitioner cannot push the next real check
# arbitrarily far out by repeated probing. The floor is keyed by
# handle alone, not (handle, petitioner): the handle itself is the
# petitioner-binding identifier (§4.8 caveat on handle leakage),
# and the arbiter has no notion of petitioner identity at this
# layer (transport-layer authentication is configured outside this
# codebase, §4.1).
_SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    handle       TEXT PRIMARY KEY,
    result_json  TEXT NOT NULL,
    kind         TEXT NOT NULL CHECK (kind IN ('result', 'rejection')),
    created_at   REAL NOT NULL,
    consumed     INTEGER NOT NULL DEFAULT 0,
    consumed_at  REAL
);

CREATE TABLE IF NOT EXISTS result_poll_floor (
    handle       TEXT PRIMARY KEY,
    last_poll_at REAL NOT NULL
);
"""
state.register_schema(_SCHEMA)


class DepositError(Exception):
    """Raised on operator-internal deposit failures: bad input shape,
    duplicate handle, or non-JSON-serializable payload. The petitioner-
    facing path never sees this - deposit happens behind the gateway,
    on the arbiter-internal side of the trust boundary."""


def deposit(handle, result, kind="result"):
    """Deposit a completed outcome against handle.

    Called by the timing-layer drainer after the result-delay window
    elapses on a regular result, or after the rejection-delivery
    window elapses on a §4.7 "destination unavailable" rejection.

    Arguments:
      handle: opaque acknowledgment string returned at submission time.
              Must be a non-empty string.
      result: the (filtered, banded, tokenized) outcome body. Must be
              JSON-serializable; the petitioner sees this verbatim on
              the next non-throttled poll.
      kind:   "result" for regular outcomes, "rejection" for the
              §4.7 destination-unavailable flow. Recorded for audit
              triage; not exposed in the petitioner-visible response.

    Returns the wall-clock timestamp at which the entry was deposited.
    Raises DepositError on bad input, duplicate handle, or non-JSON
    payload. The arbiter is single-process by design (§4.1), so a
    duplicate-deposit raise indicates a logic bug in the caller, not
    a race.
    """
    if not isinstance(handle, str) or not handle:
        raise DepositError("handle must be a non-empty string")
    if kind not in ("result", "rejection"):
        raise DepositError(
            f"unknown kind {kind!r}; expected 'result' or 'rejection'"
        )
    try:
        encoded = json.dumps(result, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError) as e:
        raise DepositError(f"result is not JSON-serializable: {e}")
    now = time.time()
    try:
        with state.connect() as conn:
            conn.execute(
                "INSERT INTO results "
                "(handle, result_json, kind, created_at) "
                "VALUES (?, ?, ?, ?)",
                (handle, encoded, kind, now),
            )
    except sqlite3.IntegrityError as e:
        # Duplicate handle. The timing layer should drain each handle
        # exactly once; a duplicate here means the executor double-
        # deposited. Audit-log full detail so the operator can
        # investigate; raise so the bug surfaces immediately.
        audit.record(
            "result_deposit_duplicate",
            {"handle": handle, "kind": kind, "error": str(e)},
        )
        raise DepositError(f"duplicate deposit for handle {handle!r}: {e}")
    audit.record(
        "result_deposit",
        {"handle": handle, "kind": kind, "created_at": now},
    )
    return now


def poll(handle, now=None):
    """Petitioner-side poll, called from the privacy gateway.

    Returns one of:
      ("result", payload, kind)   - first successful retrieval; entry
                                    marked consumed atomically.
      ("not_yet", None, None)     - one of:
                                    - input was not a non-empty string
                                    - 10-min poll floor not yet elapsed
                                    - handle has no entry in registry
                                    - handle was already retrieved
                                    - mark-consumed lost a race

    All "not_yet" cases are indistinguishable to the petitioner: the
    caller (gateway) emits a uniform response shape regardless of
    which subcase fired. The audit log differentiates the cause for
    operator triage.

    The now parameter is for testability (smoke test injects elapsed
    time without sleeping); production callers leave it None.
    """
    if not isinstance(handle, str) or not handle:
        # Bad input never reaches the floor or the results table; we
        # treat it the same as a never-existed handle on the wire.
        # No floor row is recorded so a bad-input poll is invisible
        # to the floor (we cannot key the floor by a non-string).
        audit.record(
            "result_poll_refuse",
            {"reason": "bad_handle", "type": type(handle).__name__},
        )
        return ("not_yet", None, None)
    cutoff = time.time() if now is None else now
    with state.connect() as conn:
        # Floor check first. Any poll within POLL_FLOOR_S of the last
        # non-throttled poll returns "not yet" without consulting the
        # results table - this is the §4.8 invariant ("without
        # consulting registry state").
        row = conn.execute(
            "SELECT last_poll_at FROM result_poll_floor WHERE handle = ?",
            (handle,),
        ).fetchone()
        if row is not None:
            last = row[0]
            since = cutoff - last
            if since < POLL_FLOOR_S:
                audit.record(
                    "result_poll_throttled",
                    {"handle": handle, "since_last_s": since},
                )
                return ("not_yet", None, None)
        # Floor cleared (or first poll for this handle). Anchor the
        # floor at now BEFORE consulting registry state, so a crash
        # between this UPSERT and the consume UPDATE cannot leave the
        # next poll bypassing the floor.
        conn.execute(
            "INSERT INTO result_poll_floor (handle, last_poll_at) "
            "VALUES (?, ?) "
            "ON CONFLICT(handle) DO UPDATE SET "
            "last_poll_at = excluded.last_poll_at",
            (handle, cutoff),
        )
        # Look up the result.
        row = conn.execute(
            "SELECT result_json, kind, consumed FROM results "
            "WHERE handle = ?",
            (handle,),
        ).fetchone()
        if row is None:
            # Never-existed handle. Indistinguishable on the wire from
            # already-consumed; the audit log records the difference.
            audit.record("result_poll_unknown", {"handle": handle})
            return ("not_yet", None, None)
        result_json, kind, consumed = row
        if consumed:
            audit.record("result_poll_already_consumed", {"handle": handle})
            return ("not_yet", None, None)
        # Atomically flip consumed. The WHERE consumed = 0 guard makes
        # this a no-op if a concurrent poll already won the race; the
        # arbiter is single-threaded by design (§4.1) so the race
        # cannot fire in practice, but the guard is defense-in-depth
        # against any future multi-process layout.
        cur = conn.execute(
            "UPDATE results SET consumed = 1, consumed_at = ? "
            "WHERE handle = ? AND consumed = 0",
            (cutoff, handle),
        )
        if cur.rowcount == 1:
            audit.record(
                "result_poll_ok",
                {"handle": handle, "kind": kind},
            )
            return ("result", json.loads(result_json), kind)
        audit.record("result_poll_race_lost", {"handle": handle})
        return ("not_yet", None, None)


if __name__ == "__main__":
    # Smoke test. Exercises every documented status path: floor
    # enforcement, idempotent retrieval, never-existed handle,
    # rejection kind, duplicate deposit, bad input. Uses the now=
    # injection on poll() to step through the 10-minute floor without
    # actually sleeping; deposit always uses real time.time().
    import sys
    import tempfile
    from pathlib import Path

    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-results-smoke.log"
    tmp_state = Path(tempfile.gettempdir()) / "arbiter-results-smoke.db"
    for p in (tmp_audit, tmp_state):
        if p.exists():
            p.unlink()
    audit.configure(tmp_audit)
    state.configure(tmp_state)
    state.migrate()

    # --- Bad input on poll: never-string and empty-string both refuse
    # uniformly without touching either table.
    for bad in (None, b"abc", 42, "", []):
        status, payload, kind = poll(bad)
        assert (status, payload, kind) == ("not_yet", None, None), (bad, status)

    # --- Bad input on deposit: empty handle, non-string, bad kind,
    # non-JSON payload all raise DepositError.
    for bad_handle in ("", None, 42):
        raised = False
        try:
            deposit(bad_handle, {"ok": True})
        except DepositError:
            raised = True
        assert raised, f"deposit must reject bad handle {bad_handle!r}"
    raised = False
    try:
        deposit("h_kind", {}, kind="bogus")
    except DepositError:
        raised = True
    assert raised, "deposit must reject unknown kind"
    raised = False
    try:
        deposit("h_json", {"x": object()})
    except DepositError:
        raised = True
    assert raised, "deposit must reject non-JSON-serializable payload"

    # --- Happy path: deposit + immediate poll returns the result and
    # marks consumed.
    H = "handle_alpha"
    payload = {"txid": "deadbeef", "confirmations": 1}
    t_dep = deposit(H, payload, kind="result")
    assert t_dep > 0
    # Poll at t_dep + 0.1s (just after deposit, well inside the floor
    # since this is the first poll on H).
    status, got, kind = poll(H, now=t_dep + 0.1)
    assert status == "result", status
    assert got == payload, got
    assert kind == "result", kind

    # --- Idempotent retrieval: a second poll within the floor returns
    # not_yet (floor violation), and a third poll past the floor also
    # returns not_yet (consumed).
    status, got, kind = poll(H, now=t_dep + 1.0)  # 0.9s after first poll
    assert (status, got, kind) == ("not_yet", None, None), "floor must throttle"
    status, got, kind = poll(H, now=t_dep + 0.1 + POLL_FLOOR_S + 1.0)
    assert (status, got, kind) == ("not_yet", None, None), (
        "consumed handle must return not_yet past the floor"
    )

    # --- Never-existed handle: poll returns not_yet. The floor is
    # anchored after the first poll, so a second poll within the floor
    # is throttled (no registry consultation), and a third poll past
    # the floor still returns not_yet.
    H2 = "handle_never"
    t_first = time.time()
    status, *_ = poll(H2, now=t_first)
    assert status == "not_yet", "never-existed must return not_yet"
    status, *_ = poll(H2, now=t_first + 1.0)
    assert status == "not_yet", "second poll within floor must throttle"
    status, *_ = poll(H2, now=t_first + POLL_FLOOR_S + 1.0)
    assert status == "not_yet", "still not_yet (no deposit ever happened)"

    # --- Floor anchoring on a never-existed handle blocks late
    # deposits from being picked up before the floor clears: deposit
    # happens 1 second after the first poll, and a poll inside the
    # floor must still throttle even though a result is now present.
    H3 = "handle_late_deposit"
    t_pre = time.time()
    status, *_ = poll(H3, now=t_pre)  # anchor floor at t_pre
    assert status == "not_yet"
    deposit(H3, {"x": 1}, kind="result")  # deposit AFTER first poll
    status, *_ = poll(H3, now=t_pre + 1.0)  # still inside floor
    assert status == "not_yet", "late deposit must still be floor-throttled"
    status, got, kind = poll(H3, now=t_pre + POLL_FLOOR_S + 1.0)
    assert status == "result" and got == {"x": 1} and kind == "result", (
        "result must be retrievable after floor clears"
    )

    # --- Rejection kind round-trip: deposit kind=rejection, poll
    # returns kind=rejection in the tuple. The petitioner-visible
    # payload is whatever was passed; the kind field is internal.
    H4 = "handle_reject"
    rej_payload = {"status": "destination_unavailable"}
    deposit(H4, rej_payload, kind="rejection")
    status, got, kind = poll(H4)
    assert status == "result", "rejection still returns 'result' status"
    assert got == rej_payload, got
    assert kind == "rejection", kind

    # --- Duplicate deposit raises.
    raised = False
    try:
        deposit(H4, {"x": 2}, kind="rejection")
    except DepositError as e:
        raised = "duplicate" in str(e)
    assert raised, "duplicate deposit must raise DepositError"

    # --- Floor violation does NOT advance the floor anchor: a
    # throttled poll at T+1 leaves the anchor at T, so a poll at
    # T+POLL_FLOOR_S+epsilon still passes (computed against T,
    # not T+1).
    H5 = "handle_anchor"
    t_anchor = time.time()
    deposit(H5, {"v": 1})
    status, *_ = poll(H5, now=t_anchor)  # anchor at t_anchor; consumes
    assert status == "result"
    # Throttled poll: anchor must NOT advance to t_anchor + 1.0
    status, *_ = poll(H5, now=t_anchor + 1.0)
    assert status == "not_yet"
    # Poll at t_anchor + POLL_FLOOR_S clears the floor measured against
    # t_anchor; if the throttled poll had moved the anchor, this would
    # still be inside the floor and we would see not_yet for a
    # different reason. Verify by direct table inspection.
    with state.connect() as conn:
        anchor = conn.execute(
            "SELECT last_poll_at FROM result_poll_floor WHERE handle = ?",
            (H5,),
        ).fetchone()[0]
    assert abs(anchor - t_anchor) < 0.001, (
        f"throttled poll must not advance the floor anchor: "
        f"anchor={anchor}, expected={t_anchor}"
    )

    # --- Audit log differentiates every status path. We've exercised
    # bad_handle, throttled, unknown, ok, already_consumed, deposit,
    # deposit_duplicate; check all appear in the recorded events.
    with open(tmp_audit) as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    for required in (
        "result_poll_refuse",
        "result_poll_throttled",
        "result_poll_unknown",
        "result_poll_ok",
        "result_poll_already_consumed",
        "result_deposit",
        "result_deposit_duplicate",
    ):
        assert required in events, (
            f"audit log missing event {required!r}: {sorted(set(events))!r}"
        )

    print(f"OK: result registry round-trips at audit={tmp_audit}, state={tmp_state}")
    sys.exit(0)
