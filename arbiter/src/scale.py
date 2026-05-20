"""
Scale cloaking layer: hides the order of magnitude of the wallet's
real total. Every petitioner read of balance or channel capacity is
rescaled before egress so the AI sees a number in a fixed presentation
window (nominally 0-100k sats) regardless of whether the wallet holds
50k, 5M, or 500M.

The mechanism has three pieces (mirrors the GLOSSARY 'Scale cloaking'
entry):

- Cloak tier. The arbiter assigns the wallet to a tier based on its
  real total. T0 = [0, 100k) scale 1.0 (no scaling); T1 = [100k, 1M)
  scale ~0.1; T2 = [1M, 10M) scale ~0.01; ... by powers of 10.

- Tier shift. When the real total crosses a tier boundary the arbiter
  schedules a transition with a multi-day randomized delay (test mode
  collapses to seconds). During the delay the wallet keeps presenting
  under the OLD tier's scale, so the petitioner-visible drift is
  gradual and decoupled from the moment of the underlying send /
  receive. When the shift fires, the active scale flips and the
  petitioner sees a discrete change that looks identical to a normal
  payment in / out.

- Drift > range. Privacy beats range-fidelity. During a pending tier
  shift the presented value can briefly fall outside 0-100k (e.g.,
  real grew to 150k but active tier is still T0, presented = 150k).
  This is acceptable per the GLOSSARY entry.

The arbiter is single-process and single-threaded by design (§4.1,
gateway.serve()), so the singleton scale_state row is read-modify-
written without explicit locking; SQLite's WAL serializes writers.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.1, §4.3,
§6, and GLOSSARY 'Scale cloaking'.

Mode selection (SPACER_SCALE_MODE) mirrors timing.py:

- Test mode (SPACER_SCALE_MODE=test): transitions delayed 5-15s,
  per-tier scales deterministic (0.1^tier) so exit-loop variants diff
  cleanly across runs.
- Production mode (any other value, including unset): transitions
  delayed multi-day, per-tier scales randomized within a band (per
  GLOSSARY). Currently blocked: every entry point raises
  NotImplementedError. The safe failure mode for an environment that
  has not opted in is 'does not run' rather than 'runs with the wrong
  scale or window'.
"""
import os
import random
import time

import audit
import state

# Test-mode transition delay window, matching timing.py's action /
# result 5-15s band so the cloak responds on the same compressed scale
# as the rest of the timing layer during exit-loop validation.
_TEST_TRANSITION_MIN_S = 5.0
_TEST_TRANSITION_MAX_S = 15.0

# T0 ceiling. Each higher tier covers the next decade: T1 [100k, 1M),
# T2 [1M, 10M), ... by powers of 10.
_T0_CEILING = 100_000

# Singleton-row table. The wallet has exactly one active cloak state
# at any moment. The id=1 CHECK + PRIMARY KEY makes a second insert
# impossible at the schema level; present() and seed_for_test() always
# read-modify-write through INSERT OR REPLACE / UPDATE.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS scale_state (
    id                  INTEGER PRIMARY KEY CHECK (id = 1),
    active_tier         INTEGER NOT NULL,
    active_scale        REAL NOT NULL,
    target_tier         INTEGER,
    target_scale        REAL,
    transition_due_at   REAL,
    created_at          REAL NOT NULL,
    updated_at          REAL NOT NULL
);
"""
state.register_schema(_SCHEMA)


def _mode():
    """Return 'test' iff SPACER_SCALE_MODE=test; otherwise 'production'.
    Test mode is an explicit opt-in so no environment accidentally uses
    compressed windows or deterministic scales."""
    return "test" if os.environ.get("SPACER_SCALE_MODE") == "test" else "production"


def _require_test_mode():
    """Production mode is blocked. Multi-day randomized transitions
    and within-tier scale randomization are open work; until they
    land, every entry point funnels through this guard so an
    environment that has not opted into test mode cannot use the
    cloak at all."""
    if _mode() != "test":
        raise NotImplementedError(
            "production scale-cloak window is not implemented; set "
            "SPACER_SCALE_MODE=test to use the test-mode 5-15s "
            "transition window and deterministic per-tier scales "
            "for iteration. Production needs multi-day randomized "
            "delays and within-tier scale randomization (GLOSSARY "
            "'Scale cloaking')."
        )


def _tier_for(real_sats):
    """Map a real satoshi total to its natural cloak tier.

    T0 = [0, 100_000): no scaling
    T1 = [100_000, 1_000_000)
    T2 = [1_000_000, 10_000_000)
    Tn = [10^(n+4), 10^(n+5))
    """
    if real_sats < _T0_CEILING:
        return 0
    tier = 1
    threshold = 1_000_000
    while real_sats >= threshold:
        tier += 1
        threshold *= 10
    return tier


def _test_scale_for(tier):
    """Test-mode deterministic per-tier scale: 0.1^tier. Picked so the
    bottom of any tier presents at ~10_000 sat (e.g., 100k*0.1=10k,
    1M*0.01=10k) and the top of any tier presents at ~100k (e.g.,
    (1M-1)*0.1~=100k). The presentation window therefore naturally
    spans ~[10_000, 100_000) for any non-T0 wallet, regardless of
    order of magnitude."""
    return 0.1 ** tier


def _pick_transition_delay_s():
    """Pick a transition delay. Test-mode 5-15s, matching timing.py's
    action / result bands. Production needs a multi-day randomized
    delay (GLOSSARY) and is gated upstream by _require_test_mode()."""
    return random.uniform(_TEST_TRANSITION_MIN_S, _TEST_TRANSITION_MAX_S)


def _read_state(conn):
    """Return the singleton scale_state row as a dict, or None if the
    row has not been initialized yet."""
    row = conn.execute(
        "SELECT active_tier, active_scale, target_tier, target_scale, "
        "transition_due_at FROM scale_state WHERE id = 1"
    ).fetchone()
    if row is None:
        return None
    return {
        "active_tier": row[0],
        "active_scale": row[1],
        "target_tier": row[2],
        "target_scale": row[3],
        "transition_due_at": row[4],
    }


def _init_state(conn, real_sats):
    """Initialize the singleton scale_state row for a wallet whose
    current real total is real_sats. Picks the natural tier and the
    deterministic test-mode scale. Audit-logs scale_tier_init."""
    tier = _tier_for(real_sats)
    scale = _test_scale_for(tier)
    now = time.time()
    conn.execute(
        "INSERT INTO scale_state "
        "(id, active_tier, active_scale, target_tier, target_scale, "
        "transition_due_at, created_at, updated_at) "
        "VALUES (1, ?, ?, NULL, NULL, NULL, ?, ?)",
        (tier, scale, now, now),
    )
    audit.record("scale_tier_init", {
        "tier": tier,
        "scale": scale,
        "real_sats": real_sats,
    })
    return {
        "active_tier": tier,
        "active_scale": scale,
        "target_tier": None,
        "target_scale": None,
        "transition_due_at": None,
    }


def _schedule_transition(conn, st, real_sats, target_tier):
    """Schedule a tier shift to target_tier with the test-mode delay.
    Updates the singleton row's target_* + transition_due_at columns
    and audit-logs scale_tier_shift_scheduled."""
    target_scale = _test_scale_for(target_tier)
    due_at = time.time() + _pick_transition_delay_s()
    conn.execute(
        "UPDATE scale_state SET target_tier = ?, target_scale = ?, "
        "transition_due_at = ?, updated_at = ? WHERE id = 1",
        (target_tier, target_scale, due_at, time.time()),
    )
    audit.record("scale_tier_shift_scheduled", {
        "active_tier": st["active_tier"],
        "active_scale": st["active_scale"],
        "target_tier": target_tier,
        "target_scale": target_scale,
        "real_sats": real_sats,
        "due_at": due_at,
    })
    st["target_tier"] = target_tier
    st["target_scale"] = target_scale
    st["transition_due_at"] = due_at
    return st


def _apply_transition(conn, st, real_sats):
    """Apply a pending tier shift: copy target_* over active_*, clear
    target_*, audit-log scale_tier_shift_applied with the presented
    value before and after the flip (computed against the current
    real_sats so the operator can correlate)."""
    prev_tier = st["active_tier"]
    prev_scale = st["active_scale"]
    new_tier = st["target_tier"]
    new_scale = st["target_scale"]
    presented_before = int(real_sats * prev_scale)
    presented_after = int(real_sats * new_scale)
    conn.execute(
        "UPDATE scale_state SET active_tier = ?, active_scale = ?, "
        "target_tier = NULL, target_scale = NULL, "
        "transition_due_at = NULL, updated_at = ? WHERE id = 1",
        (new_tier, new_scale, time.time()),
    )
    audit.record("scale_tier_shift_applied", {
        "prev_tier": prev_tier,
        "prev_scale": prev_scale,
        "new_tier": new_tier,
        "new_scale": new_scale,
        "real_sats": real_sats,
        "presented_before": presented_before,
        "presented_after": presented_after,
        "delta": presented_after - presented_before,
    })
    st["active_tier"] = new_tier
    st["active_scale"] = new_scale
    st["target_tier"] = None
    st["target_scale"] = None
    st["transition_due_at"] = None
    return st


def present(real_sats):
    """Return the cloaked presentation value for a real satoshi total.

    Reads (and lazily initializes) the singleton cloak state. If a
    pending transition is past its due_at, applies it atomically. If
    the natural tier of real_sats differs from the active tier and no
    transition is pending, schedules one. Returns int(real_sats *
    active_scale), floor-rounded.
    """
    _require_test_mode()
    real_sats = int(real_sats)
    with state.connect() as conn:
        st = _read_state(conn)
        if st is None:
            st = _init_state(conn, real_sats)
        elif (
            st["target_tier"] is not None
            and st["transition_due_at"] is not None
            and st["transition_due_at"] <= time.time()
        ):
            st = _apply_transition(conn, st, real_sats)
        natural_tier = _tier_for(real_sats)
        if (
            natural_tier != st["active_tier"]
            and st["target_tier"] is None
        ):
            st = _schedule_transition(conn, st, real_sats, natural_tier)
    return int(real_sats * st["active_scale"])


def seed_for_test(active_tier, active_scale, target_tier, target_scale, due_at):
    """Direct write of the singleton scale_state row for test fixtures.
    Bypasses present()'s init / schedule / apply logic; used by the
    exit-loop runner to set up transition-pending and
    transition-applied variants. NOT a petitioner-reachable path.

    target_tier, target_scale, due_at may be None to seed a 'no
    pending transition' state."""
    _require_test_mode()
    now = time.time()
    with state.connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO scale_state "
            "(id, active_tier, active_scale, target_tier, target_scale, "
            "transition_due_at, created_at, updated_at) "
            "VALUES (1, ?, ?, ?, ?, ?, ?, ?)",
            (active_tier, active_scale, target_tier, target_scale, due_at, now, now),
        )


if __name__ == "__main__":
    # Smoke test: round-trip every code path.
    import json
    import sys
    import tempfile
    from pathlib import Path

    os.environ["SPACER_SCALE_MODE"] = "test"

    tmp_state = Path(tempfile.gettempdir()) / "arbiter-scale-smoke.db"
    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-scale-smoke.log"
    for p in (tmp_state, tmp_audit):
        if p.exists():
            p.unlink()
    state.configure(tmp_state)
    state.migrate()
    audit.configure(tmp_audit)

    # Tier function spot checks across the boundaries.
    assert _tier_for(0) == 0
    assert _tier_for(99_999) == 0
    assert _tier_for(100_000) == 1
    assert _tier_for(999_999) == 1
    assert _tier_for(1_000_000) == 2
    assert _tier_for(50_000_000) == 3
    assert _tier_for(500_000_000) == 4

    # First present() on a T0 wallet: init only, no transition.
    assert present(50_000) == 50_000
    with state.connect() as c:
        st = _read_state(c)
    assert st == {
        "active_tier": 0,
        "active_scale": 1.0,
        "target_tier": None,
        "target_scale": None,
        "transition_due_at": None,
    }, st

    # Wallet grew to 150k: schedules a transition to T1. Presented
    # value uses the OLD scale (T0 / 1.0) since the transition is not
    # yet due. drift > range: 150_000 > 100_000 is acceptable.
    assert present(150_000) == 150_000
    with state.connect() as c:
        st = _read_state(c)
    assert st["active_tier"] == 0 and st["active_scale"] == 1.0
    assert st["target_tier"] == 1 and st["target_scale"] == 0.1
    assert st["transition_due_at"] is not None
    due_at = st["transition_due_at"]

    # Second present() before due_at: no new schedule (target already
    # set), still presents at the old scale, due_at unchanged.
    assert present(160_000) == 160_000
    with state.connect() as c:
        st2 = _read_state(c)
    assert st2["transition_due_at"] == due_at, "due_at must not be re-rolled"

    # Rewind due_at to the past; next present() applies the transition.
    with state.connect() as c:
        c.execute(
            "UPDATE scale_state SET transition_due_at = ? WHERE id = 1",
            (time.time() - 1.0,),
        )
    assert present(150_000) == 15_000   # 150k * 0.1
    with state.connect() as c:
        st3 = _read_state(c)
    assert st3["active_tier"] == 1 and st3["active_scale"] == 0.1
    assert st3["target_tier"] is None
    assert st3["transition_due_at"] is None

    # Seed-and-apply path used by exit-loop fixtures: precondition
    # seeds a past-due transition; present() applies on first call.
    with state.connect() as c:
        c.execute("DELETE FROM scale_state")
    seed_for_test(0, 1.0, 1, 0.1, time.time() - 5.0)
    assert present(150_000) == 15_000
    with state.connect() as c:
        st4 = _read_state(c)
    assert st4["active_tier"] == 1

    # Seed a future-due transition: present() must NOT apply, must use
    # the active (old) scale.
    with state.connect() as c:
        c.execute("DELETE FROM scale_state")
    far_future = time.time() + 3600.0
    seed_for_test(0, 1.0, 1, 0.1, far_future)
    assert present(150_000) == 150_000
    with state.connect() as c:
        st5 = _read_state(c)
    assert st5["transition_due_at"] == far_future, "pending must not be applied early"

    # Production mode raises uniformly.
    del os.environ["SPACER_SCALE_MODE"]
    raised = False
    try:
        present(100_000)
    except NotImplementedError:
        raised = True
    assert raised, "production must raise"
    raised = False
    try:
        seed_for_test(0, 1.0, None, None, None)
    except NotImplementedError:
        raised = True
    assert raised, "seed_for_test must also be production-blocked"

    # Audit events: every milestone fires.
    with open(tmp_audit) as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    for required in (
        "scale_tier_init",
        "scale_tier_shift_scheduled",
        "scale_tier_shift_applied",
    ):
        assert required in events, f"audit missing {required}: {events!r}"

    print(f"OK: scale layer round-trips at {tmp_state}")
    sys.exit(0)
