"""
Timing layer: enforces action delay and result delay (§4.6) and the
rejection-delivery delay (§4.7).

Two delays apply to every state-changing call:
- Action delay: between the petitioner submitting a state-changing
  action and the arbiter actually executing it against bitcoind / LND.
- Result delay: between the arbiter completing the action and the
  petitioner being able to learn the result via the result registry
  poll path.

Rejections (e.g., the recipient address registry's "destination
unavailable" outcome from §4.7) flow through the result side on a
separate, shorter band so rejection-delivery does not leak the
submission-to-response timing channel.

Mode selection (SPACER_TIMING_MODE):
- Test mode (SPACER_TIMING_MODE=test): windows compressed for
  iteration. Action 5-15s, result 5-15s, rejection 1-5s. (§10.)
- Production mode (any other value, including unset): windows are
  computed dynamically against observed global activity, with a ~12h
  floor. Production windows are blocked on sp-77lxs.3 (dynamic window
  calculation), so every production-mode call raises
  NotImplementedError. This is intentional: the safe failure mode for
  a misconfigured environment is "does not run" rather than "runs
  with the wrong window". An environment that has not explicitly
  opted into test mode therefore cannot accidentally use test-mode
  timing, and an environment that has not opted out of production
  cannot run at all until sp-77lxs.3 lands.

The arbiter is single-process and single-threaded by design (§4.1,
gateway.serve()), so the database operations here run without
contention and need no explicit locking.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.6, §4.7,
§10.
"""
import json
import os
import random
import time

import state

# Test-mode window bounds (§10).
_TEST_ACTION_MIN_S = 5.0
_TEST_ACTION_MAX_S = 15.0
_TEST_RESULT_MIN_S = 5.0
_TEST_RESULT_MAX_S = 15.0
# Rejection-delivery delay is "compressed proportionally" against §4.7's
# production 1h ± 30min band. A 1-5s window is shorter than the regular
# 5-15s result window in the same proportional sense.
_TEST_REJECTION_MIN_S = 1.0
_TEST_REJECTION_MAX_S = 5.0

# Two tables. pending_actions holds calls awaiting execution against
# bitcoind/LND; pending_results holds outcomes awaiting delivery to the
# petitioner via the result registry. Both keyed by the opaque handle
# returned at submission time (§3). ready_at is wall-clock epoch
# seconds; the arbiter is a controlled host so we trust the system
# clock at this scale of delay.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS pending_actions (
    handle      TEXT PRIMARY KEY,
    op          TEXT NOT NULL,
    params_json TEXT NOT NULL,
    ready_at    REAL NOT NULL,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_actions_ready_at
    ON pending_actions(ready_at);

CREATE TABLE IF NOT EXISTS pending_results (
    handle      TEXT PRIMARY KEY,
    result_json TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('result', 'rejection')),
    ready_at    REAL NOT NULL,
    created_at  REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_pending_results_ready_at
    ON pending_results(ready_at);
"""
state.register_schema(_SCHEMA)


def _mode():
    """Return "test" if and only if SPACER_TIMING_MODE=test; otherwise
    "production". Test mode is an explicit opt-in so no environment can
    accidentally use compressed windows."""
    return "test" if os.environ.get("SPACER_TIMING_MODE") == "test" else "production"


def _action_window_s():
    """Pick a randomized action delay in seconds for the active mode."""
    if _mode() == "test":
        return random.uniform(_TEST_ACTION_MIN_S, _TEST_ACTION_MAX_S)
    raise NotImplementedError(
        "production action-delay window is blocked on sp-77lxs.3 "
        "(dynamic window calculation); set SPACER_TIMING_MODE=test "
        "to use the test-mode 5-15s window for iteration"
    )


def _result_window_s(kind):
    """Pick a randomized result-side delay in seconds for the active
    mode. kind is 'result' (regular result delivery) or 'rejection'
    (the §4.7 rejection-delivery band, shorter than the regular
    result-delivery band)."""
    if _mode() != "test":
        raise NotImplementedError(
            "production result-delay window is blocked on sp-77lxs.3 "
            "(dynamic window calculation); set SPACER_TIMING_MODE=test "
            "to use the test-mode 5-15s window for iteration"
        )
    if kind == "result":
        return random.uniform(_TEST_RESULT_MIN_S, _TEST_RESULT_MAX_S)
    if kind == "rejection":
        return random.uniform(_TEST_REJECTION_MIN_S, _TEST_REJECTION_MAX_S)
    raise ValueError(f"unknown kind {kind!r}; expected 'result' or 'rejection'")


def enqueue_action(handle, op, params):
    """Defer a state-changing action by the action-delay window.

    Records the call in pending_actions and returns the wall-clock
    epoch timestamp at which the executor should run it. The executor
    (lands with sp-77lxs.10/11) consumes due entries via due_actions().
    """
    delay_s = _action_window_s()
    now = time.time()
    ready_at = now + delay_s
    with state.connect() as conn:
        conn.execute(
            "INSERT INTO pending_actions "
            "(handle, op, params_json, ready_at, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                handle,
                op,
                json.dumps(params, separators=(",", ":"), sort_keys=True),
                ready_at,
                now,
            ),
        )
    return ready_at


def enqueue_result(handle, result, kind="result"):
    """Defer a result (or rejection) by the result-delay window.

    Records the outcome in pending_results and returns the wall-clock
    epoch timestamp at which it becomes deliverable. The result
    registry (lands with sp-77lxs.14) consumes due entries via
    due_results() and deposits them so the petitioner's poll picks
    them up.
    """
    delay_s = _result_window_s(kind)
    now = time.time()
    ready_at = now + delay_s
    with state.connect() as conn:
        conn.execute(
            "INSERT INTO pending_results "
            "(handle, result_json, kind, ready_at, created_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (
                handle,
                json.dumps(result, separators=(",", ":"), sort_keys=True),
                kind,
                ready_at,
                now,
            ),
        )
    return ready_at


def due_actions(now=None):
    """Pop and return every pending action whose ready_at has elapsed.

    Returns a list of (handle, op, params) tuples in ready_at order,
    oldest first. Rows are deleted in the same connection scope so a
    row is only ever returned once.
    """
    cutoff = time.time() if now is None else now
    out = []
    with state.connect() as conn:
        rows = conn.execute(
            "SELECT handle, op, params_json FROM pending_actions "
            "WHERE ready_at <= ? ORDER BY ready_at ASC",
            (cutoff,),
        ).fetchall()
        for handle, op, params_json in rows:
            out.append((handle, op, json.loads(params_json)))
        if rows:
            conn.execute(
                "DELETE FROM pending_actions WHERE ready_at <= ?", (cutoff,)
            )
    return out


def due_results(now=None):
    """Pop and return every pending result whose ready_at has elapsed.

    Returns a list of (handle, result, kind) tuples in ready_at order,
    oldest first. Rows are deleted in the same connection scope.
    """
    cutoff = time.time() if now is None else now
    out = []
    with state.connect() as conn:
        rows = conn.execute(
            "SELECT handle, result_json, kind FROM pending_results "
            "WHERE ready_at <= ? ORDER BY ready_at ASC",
            (cutoff,),
        ).fetchall()
        for handle, result_json, kind in rows:
            out.append((handle, json.loads(result_json), kind))
        if rows:
            conn.execute(
                "DELETE FROM pending_results WHERE ready_at <= ?", (cutoff,)
            )
    return out


def pending_action(handle):
    """Return (ready_at, op, params) for the named pending action, or
    None. Arbiter-internal inspection; never crosses the privacy
    gateway."""
    with state.connect() as conn:
        row = conn.execute(
            "SELECT ready_at, op, params_json FROM pending_actions "
            "WHERE handle = ?",
            (handle,),
        ).fetchone()
    if row is None:
        return None
    ready_at, op, params_json = row
    return (ready_at, op, json.loads(params_json))


def pending_result(handle):
    """Return (ready_at, result, kind) for the named pending result, or
    None. Arbiter-internal inspection; never crosses the privacy
    gateway."""
    with state.connect() as conn:
        row = conn.execute(
            "SELECT ready_at, result_json, kind FROM pending_results "
            "WHERE handle = ?",
            (handle,),
        ).fetchone()
    if row is None:
        return None
    ready_at, result_json, kind = row
    return (ready_at, json.loads(result_json), kind)


if __name__ == "__main__":
    # Smoke test: register schema, enqueue one of each kind, verify
    # nothing is due immediately, drain with a future cutoff, verify
    # production mode raises with no SPACER_TIMING_MODE.
    import sys
    import tempfile
    from pathlib import Path

    os.environ["SPACER_TIMING_MODE"] = "test"

    tmp = Path(tempfile.gettempdir()) / "arbiter-timing-smoke.db"
    if tmp.exists():
        tmp.unlink()
    state.configure(tmp)
    state.migrate()
    # Re-running migrate must be a no-op.
    state.migrate()

    # Window pickers stay inside their declared bounds across many
    # samples. The randomization is uniform; checking 100 samples
    # exercises the boundary handling.
    for _ in range(100):
        a = _action_window_s()
        assert _TEST_ACTION_MIN_S <= a <= _TEST_ACTION_MAX_S, a
        r = _result_window_s("result")
        assert _TEST_RESULT_MIN_S <= r <= _TEST_RESULT_MAX_S, r
        j = _result_window_s("rejection")
        assert _TEST_REJECTION_MIN_S <= j <= _TEST_REJECTION_MAX_S, j

    # Enqueue one of each kind.
    h_action = "smoke-action"
    h_reject = "smoke-rejection"
    ra = enqueue_action(h_action, "send", {"to": "tok_X", "amount": 1000})
    rr = enqueue_result(h_action, {"txid": "deadbeef"}, kind="result")
    rj = enqueue_result(h_reject, {"status": "destination_unavailable"}, kind="rejection")
    now = time.time()
    assert ra > now, f"action ready_at must be in the future: {ra} <= {now}"
    assert rr > now, f"result ready_at must be in the future: {rr} <= {now}"
    assert rj > now, f"rejection ready_at must be in the future: {rj} <= {now}"

    # Nothing is due yet at the moment of enqueue.
    assert due_actions(now=now) == [], "action must not be due yet"
    assert due_results(now=now) == [], "result must not be due yet"

    # Inspection round-trip.
    pa = pending_action(h_action)
    assert pa is not None and pa[1] == "send" and pa[2] == {"to": "tok_X", "amount": 1000}
    pr = pending_result(h_action)
    assert pr is not None and pr[1] == {"txid": "deadbeef"} and pr[2] == "result"

    # Drain with a future cutoff; verify deletion and ordering.
    far = time.time() + 60.0
    drained_a = due_actions(now=far)
    assert len(drained_a) == 1 and drained_a[0][0] == h_action, drained_a
    drained_r = due_results(now=far)
    assert len(drained_r) == 2, drained_r
    assert {d[0] for d in drained_r} == {h_action, h_reject}, drained_r
    assert pending_action(h_action) is None, "action must be drained"
    assert pending_result(h_action) is None, "result must be drained"
    assert pending_result(h_reject) is None, "rejection must be drained"

    # Re-draining is a no-op (no rows left).
    assert due_actions(now=far) == []
    assert due_results(now=far) == []

    # Bad kind on enqueue_result must raise.
    raised = False
    try:
        enqueue_result("bad", {}, kind="bogus")
    except ValueError:
        raised = True
    assert raised, "unknown kind must raise ValueError"

    # Production mode (any other env value, including unset) must
    # raise on every enqueue path. This is the structural guarantee
    # that an environment which has not opted into test mode cannot
    # use the timing layer until sp-77lxs.3 lands.
    del os.environ["SPACER_TIMING_MODE"]
    for op_name, fn in (
        ("enqueue_action", lambda: enqueue_action("nope", "send", {})),
        ("enqueue_result(result)", lambda: enqueue_result("nope", {}, kind="result")),
        ("enqueue_result(rejection)", lambda: enqueue_result("nope", {}, kind="rejection")),
    ):
        raised = False
        try:
            fn()
        except NotImplementedError:
            raised = True
        assert raised, f"production {op_name} must raise NotImplementedError (sp-77lxs.3)"

    # An unrelated SPACER_TIMING_MODE value (typo, "TEST" miscased,
    # etc.) must also land in production mode rather than silently
    # fall through to test windows.
    os.environ["SPACER_TIMING_MODE"] = "TEST"
    raised = False
    try:
        enqueue_action("nope", "send", {})
    except NotImplementedError:
        raised = True
    assert raised, "non-exact SPACER_TIMING_MODE value must not enable test mode"

    print(f"OK: timing layer round-trips at {tmp}")
    sys.exit(0)
