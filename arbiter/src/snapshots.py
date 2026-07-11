"""
Read-path snapshot serving: the petitioner-facing read ops
(query_balance, query_channels) are served from a per-op snapshot row
in the state DB instead of reading live backend state per request.

Design doc 15 is the authority. The refresh sweep here is driven by
the executor's background drainer (executor.refresh_read_snapshots);
the gateway serves the stored value verbatim (gateway._dispatch). The
petitioner-reachable read path therefore never touches bitcoind/LND:
polling at any rate only ever observes the snapshot, so a balance or
capacity change is localized to one refresh epoch rather than to the
moment it happened (GLOSSARY 'Read snapshot').

Invariants carried by this module (doc 15 §4):

1. Event independence (oblivious sampling). The refresh clock is a
   randomized renewal process: next_refresh_at = refresh time + a
   uniform draw from the band. It is never triggered, advanced, or
   delayed by wallet events - including refresh FAILURES, which
   reschedule on the same draw so the attempt cadence is identical
   whether values change, hold, or the backend is down.
2. Full presentation runs at refresh time. Refresh = backend read ->
   scale.present() -> quantize -> store. A tier shift that comes due
   mid-epoch is applied by present() at the NEXT refresh, so the shift
   is never visible at poll resolution.
3. Quantization is delta hygiene, not magnitude privacy. The presented
   value is floored to a coarse grid before storing, so sub-grid churn
   produces no served-value transition at all and a known real delta
   calibrates the cloak only to +-grid. Floor (not nearest) so the
   served figure never overstates the presented one, matching
   present()'s own floor rounding.
4. Backend outage is invisible on the read path. A failed refresh
   keeps the last stored row serving, audit-logs operator-side, and
   reschedules on the renewal clock.

Mode selection mirrors timing.py exactly - the refresh epoch is a
timing window under the delay-scaling principle (doc 15 §4.4), gated
behind the same dynamic-window work as the action/result windows:

- Test mode (SPACER_TIMING_MODE=test): the standard 5-15s band, so
  exit-loop variants diff cleanly against the other timing paths.
- Production mode (any other value, including unset): epochs must be
  computed per-rail against observed global activity (sp-77lxs.3);
  until then every refresh attempt raises NotImplementedError and the
  safe failure mode is "does not run" - no row is ever written, so
  the gateway refuses reads uniformly rather than serving on an
  un-vetted epoch.

Lazy backend imports: bitcoin.py / lnd.py are imported inside the
refresh, never at module top, preserving the no-lnd-import /
no-ecash-import guarantees for modes that do not need them (the same
rule the executor's op handlers follow).

Stdlib only.
"""
import os
import random
import time

import audit
import scale
import state

# Test-mode refresh band: the standard 5-15s test window (doc 15 §4.4),
# matching timing.py's action/result bands so the whole timing surface
# compresses uniformly under one opt-in.
_TEST_REFRESH_MIN_S = 5.0
_TEST_REFRESH_MAX_S = 15.0

# Served-value grid (doc 15 §4.5). The presented value is floored to
# this grid at refresh time; placeholder 1k sats on the 0-100k
# presentation window pending production sizing.
_SERVE_GRID_SATS = 1_000

# Satoshis per bitcoin. bitcoin.getbalance() returns a Decimal in BTC;
# the snapshot stores integer sats (the wire shape both read ops
# present). Int literal so Decimal * int stays exact.
_SATS_PER_BTC = 100_000_000

# One row per read op. served_sats is the presented-and-quantized value
# the gateway returns verbatim; refreshed_at / next_refresh_at are
# wall-clock epoch seconds (same clock-trust stance as timing.py).
_SCHEMA = """
CREATE TABLE IF NOT EXISTS read_snapshots (
    op              TEXT PRIMARY KEY
                    CHECK (op IN ('query_balance', 'query_channels')),
    served_sats     INTEGER NOT NULL,
    refreshed_at    REAL NOT NULL,
    next_refresh_at REAL NOT NULL
);
"""
state.register_schema(_SCHEMA)


def _mode():
    """Return "test" iff SPACER_TIMING_MODE=test; otherwise
    "production". Same env var as timing.py by design: the refresh
    epoch is a timing window (doc 15 §4.4), so the one explicit test
    opt-in compresses it together with the action/result windows."""
    return "test" if os.environ.get("SPACER_TIMING_MODE") == "test" else "production"


def _advanced_mode():
    """True iff the deployment runs the advanced Lightning / eCash
    extension (SPACER_MODE in {lightning, full, ecash}). Read from the
    environment per call, mirroring gateway._mode() / the executor's
    own copy, so the sweep stays decoupled from the request path."""
    return os.environ.get("SPACER_MODE", "onchain").strip().lower() in (
        "lightning",
        "full",
        "ecash",
    )


def _active_read_ops():
    """The read ops the active mode exposes - the set the sweep must
    keep fresh. Mirrors gateway._known_read_ops(): query_balance in
    every mode, query_channels only with the Lightning extension."""
    if _advanced_mode():
        return ("query_balance", "query_channels")
    return ("query_balance",)


def _refresh_window_s():
    """Pick one randomized renewal interval for the active mode.

    Production epochs are per-rail dynamic windows (doc 15 §4.4),
    blocked on sp-77lxs.3 like every other production timing path;
    raising here means no row is ever written outside test mode, so
    the gateway's no-snapshot refusal is the production behavior."""
    if _mode() == "test":
        return random.uniform(_TEST_REFRESH_MIN_S, _TEST_REFRESH_MAX_S)
    raise NotImplementedError(
        "production snapshot-refresh epoch is blocked on sp-77lxs.3 "
        "(dynamic window calculation, per-rail floors); set "
        "SPACER_TIMING_MODE=test to use the test-mode 5-15s band for "
        "iteration"
    )


def _quantize(presented_sats):
    """Floor the presented value to the serve grid (doc 15 §4.5)."""
    return (int(presented_sats) // _SERVE_GRID_SATS) * _SERVE_GRID_SATS


def _read_backend(op):
    """Read the real backend figure for one op, in integer sats.

    This is the arbiter-internal half the gateway dispatch used to do
    per request; it now runs only on the refresh clock, inside the
    trust boundary. Backend module imports stay lazy so each mode
    pulls in only what it needs (onchain never imports lnd.py)."""
    if op == "query_balance":
        if _advanced_mode():
            # Advanced extension: the LND on-chain wallet total.
            import lnd
            raw = lnd.walletbalance()
            return int(raw.get("total_balance", "0"))
        # onchain (default): the bitcoind wallet's confirmed balance,
        # a BTC Decimal scaled to integer sats.
        import bitcoin
        return int(bitcoin.getbalance() * _SATS_PER_BTC)
    if op == "query_channels":
        # Advanced extension only; the sweep never asks for this op in
        # onchain mode (_active_read_ops).
        import lnd
        raw = lnd.channelbalance()
        local = int(raw.get("local_balance", {}).get("sat", "0"))
        remote = int(raw.get("remote_balance", {}).get("sat", "0"))
        return local + remote
    raise ValueError(f"unknown read op {op!r}")


def _next_refresh_at(op):
    """Return the row's next_refresh_at, or None if no row exists."""
    with state.connect() as conn:
        row = conn.execute(
            "SELECT next_refresh_at FROM read_snapshots WHERE op = ?",
            (op,),
        ).fetchone()
    return None if row is None else row[0]


def refresh_due(now=None):
    """Refresh every active read op whose snapshot is missing or due.

    Called by the executor's background drainer each tick (production
    boot path) and by the exit-loop runner directly (forced refreshes
    via now=). Returns the number of ops refreshed or attempted. A
    backend failure on one op does not stop the sweep; the failed op
    keeps its last row serving and reschedules on the renewal clock
    (doc 15 §4.7). Raises NotImplementedError outside test mode
    (production epochs are blocked on sp-77lxs.3)."""
    cutoff = time.time() if now is None else now
    swept = 0
    for op in _active_read_ops():
        due_at = _next_refresh_at(op)
        if due_at is not None and due_at > cutoff:
            continue
        _refresh_one(op)
        swept += 1
    return swept


def _refresh_one(op):
    """Run one refresh: backend read -> scale.present() -> quantize ->
    store, plus the operator-side audit record (doc 15 §4.2, §4.8).

    The renewal draw happens FIRST so production mode raises before
    any backend contact, and so a failed backend read can reschedule
    on the same oblivious clock (invariant 1: attempt cadence is
    event-independent, success or failure)."""
    delay_s = _refresh_window_s()
    now = time.time()
    try:
        real = _read_backend(op)
    except Exception as e:
        # Backend outage (doc 15 §4.7): keep the last row serving,
        # surface the failure operator-side only, stay on the clock.
        # With no row yet (outage at first-ever refresh) there is
        # nothing to serve or reschedule; the next sweep retries and
        # the gateway keeps refusing reads uniformly until the first
        # successful refresh.
        audit.record(
            "snapshot_refresh_failed", {"op": op, "error": str(e)[:200]}
        )
        with state.connect() as conn:
            conn.execute(
                "UPDATE read_snapshots SET next_refresh_at = ? WHERE op = ?",
                (now + delay_s, op),
            )
        return
    # Full presentation at refresh time (doc 15 §4.2): a pending tier
    # shift past its due moment applies here, inside present(), so the
    # shift becomes visible only at an epoch boundary.
    presented = scale.present(real)
    served = _quantize(presented)
    with state.connect() as conn:
        conn.execute(
            "INSERT INTO read_snapshots "
            "(op, served_sats, refreshed_at, next_refresh_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(op) DO UPDATE SET "
            "served_sats = excluded.served_sats, "
            "refreshed_at = excluded.refreshed_at, "
            "next_refresh_at = excluded.next_refresh_at",
            (op, served, now, now + delay_s),
        )
    # The refresh-time real-vs-presented-vs-served record: the doc 13
    # column-2 material the per-request balance_read event used to
    # carry, now emitted once per refresh instead of once per read.
    audit.record(
        "snapshot_refresh",
        {
            "op": op,
            "real_sats": real,
            "presented_sats": presented,
            "served_sats": served,
        },
    )


def serve(op):
    """Return (served_sats, age_s) for one op's snapshot, or None if
    no snapshot exists yet (pre-first-refresh boot gap, or production
    mode where the sweep never runs). The gateway serves the value
    verbatim and refuses uniformly on None - it must never fall back
    to a live backend read (doc 15 §4)."""
    with state.connect() as conn:
        row = conn.execute(
            "SELECT served_sats, refreshed_at FROM read_snapshots "
            "WHERE op = ?",
            (op,),
        ).fetchone()
    if row is None:
        return None
    served_sats, refreshed_at = row
    return int(served_sats), max(0.0, time.time() - refreshed_at)


def seed_for_test(op, served_sats, refreshed_at, next_refresh_at):
    """Direct write of one snapshot row for test fixtures, bypassing
    the refresh pipeline (mirrors scale.seed_for_test). NOT a
    petitioner-reachable path; test-mode-gated like every other
    compressed-window entry point."""
    if _mode() != "test":
        raise NotImplementedError(
            "seed_for_test is a test fixture; set SPACER_TIMING_MODE=test"
        )
    with state.connect() as conn:
        conn.execute(
            "INSERT INTO read_snapshots "
            "(op, served_sats, refreshed_at, next_refresh_at) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(op) DO UPDATE SET "
            "served_sats = excluded.served_sats, "
            "refreshed_at = excluded.refreshed_at, "
            "next_refresh_at = excluded.next_refresh_at",
            (op, int(served_sats), refreshed_at, next_refresh_at),
        )


if __name__ == "__main__":
    # Smoke test: quantization, the refresh -> serve round-trip against
    # fake backends, staleness across a backend change, sub-grid
    # invisibility, outage behavior, per-mode op sets, the production
    # gate, and the audit trail.
    import json
    import shutil
    import sys
    import tempfile
    from pathlib import Path

    os.environ["SPACER_TIMING_MODE"] = "test"
    os.environ["SPACER_SCALE_MODE"] = "test"
    os.environ.pop("SPACER_MODE", None)

    work = Path(tempfile.mkdtemp(prefix="arbiter-snapshots-smoke-"))

    # Fake bitcoin-cli: getbalance prints a BTC decimal selected by
    # $BITCOIN_CLI_SCENARIO (same pattern as the exit-loop runner).
    fake_bitcoin = work / "bitcoin-cli"
    fake_bitcoin.write_text(
        """#!/bin/sh
case "$1" in -datadir=*) shift;; esac
case "$1" in
  getbalance)
    case "${BITCOIN_CLI_SCENARIO:-funded}" in
      subgrid) printf '0.00050400';;
      subgrid-moved) printf '0.00050900';;
      grown) printf '0.00150000';;
      *) printf '0.00050000';;
    esac
    ;;
  *) echo "fake bitcoin-cli: unknown $1" >&2; exit 64;;
esac
"""
    )
    fake_bitcoin.chmod(0o755)

    # Fake lncli for the advanced-mode sweep (both read ops).
    fake_lncli = work / "lncli"
    fake_lncli.write_text(
        """#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in --rpcserver=*|--tlscertpath=*|--macaroonpath=*|--network=*) shift;; *) break;; esac
done
case "$1" in
  walletbalance) printf '{"total_balance":"60000","confirmed_balance":"60000","unconfirmed_balance":"0"}';;
  channelbalance) printf '{"local_balance":{"sat":"50000","msat":"0"},"remote_balance":{"sat":"30000","msat":"0"}}';;
  *) echo "fake lncli: unknown $1" >&2; exit 64;;
esac
"""
    )
    fake_lncli.chmod(0o755)

    os.environ["BITCOIN_CLI_BIN"] = str(fake_bitcoin)
    os.environ["BITCOIN_DATADIR"] = str(work)
    os.environ["BITCOIN_CLI_TIMEOUT_S"] = "5"
    os.environ["LNCLI_BIN"] = str(fake_lncli)
    os.environ["LNCLI_TIMEOUT_S"] = "5"
    os.environ.pop("BITCOIN_CLI_SCENARIO", None)

    audit.configure(work / "audit.log")
    state.configure(work / "state.db")
    state.migrate()

    far = time.time() + 10_000.0

    try:
        # Quantization: floor to the 1k grid.
        assert _quantize(0) == 0
        assert _quantize(999) == 0
        assert _quantize(1000) == 1000
        assert _quantize(50_400) == 50_000
        assert _quantize(50_999) == 50_000
        assert _quantize(51_000) == 51_000

        # Nothing to serve before the first refresh.
        assert serve("query_balance") is None

        # First sweep (onchain mode): only query_balance is active;
        # missing row counts as due. 50_000 is T0 (cloak no-op) and
        # grid-aligned, so served == real.
        assert _active_read_ops() == ("query_balance",)
        assert refresh_due() == 1
        served, age = serve("query_balance")
        assert served == 50_000, served
        assert 0.0 <= age < 5.0, age
        # The renewal clock landed inside the band.
        due_at = _next_refresh_at("query_balance")
        assert due_at is not None
        lo = time.time() + _TEST_REFRESH_MIN_S - 5.0  # refresh ran moments ago
        hi = time.time() + _TEST_REFRESH_MAX_S
        assert lo <= due_at <= hi, (due_at, lo, hi)

        # Not due again yet: an immediate sweep refreshes nothing.
        assert refresh_due() == 0

        # Staleness across a change: the backend moves (50_000 ->
        # 150_000) but the row is not due, so the served value holds.
        os.environ["BITCOIN_CLI_SCENARIO"] = "grown"
        assert refresh_due() == 0
        served, _ = serve("query_balance")
        assert served == 50_000, "must keep serving the stale snapshot"

        # Forced refresh past the clock: the change lands, presented
        # under the still-active T0 scale (present() schedules the
        # tier shift for later - epoch-boundary semantics), quantized.
        assert refresh_due(now=far) == 1
        served, _ = serve("query_balance")
        assert served == 150_000, served

        # Sub-grid churn is invisible: 50_400 -> 50_000 served; then
        # 50_900 -> still 50_000 served (no transition at all).
        os.environ["BITCOIN_CLI_SCENARIO"] = "subgrid"
        assert refresh_due(now=far) == 1
        assert serve("query_balance")[0] == 50_000
        os.environ["BITCOIN_CLI_SCENARIO"] = "subgrid-moved"
        assert refresh_due(now=far) == 1
        assert serve("query_balance")[0] == 50_000, "sub-grid change must not move the served value"

        # Backend outage: the last row keeps serving; the clock
        # advances on the same renewal draw; the failure is audited.
        os.environ["BITCOIN_CLI_BIN"] = str(work / "missing-binary")
        before = serve("query_balance")[0]
        assert refresh_due(now=far) == 1  # attempted
        assert serve("query_balance")[0] == before, "outage must keep serving"
        assert _next_refresh_at("query_balance") > time.time(), "outage must reschedule"
        os.environ["BITCOIN_CLI_BIN"] = str(fake_bitcoin)

        # Advanced mode: both ops are active; the sweep creates the
        # capacity row (50k + 30k = 80k, grid-aligned) and reads the
        # LND wallet for balance (60k).
        os.environ["SPACER_MODE"] = "lightning"
        assert _active_read_ops() == ("query_balance", "query_channels")
        assert refresh_due(now=far) == 2
        assert serve("query_channels")[0] == 80_000
        assert serve("query_balance")[0] == 60_000
        os.environ.pop("SPACER_MODE", None)

        # seed_for_test round-trips (the fixture path).
        seed_for_test("query_balance", 42_000, time.time() - 3.0, far)
        served, age = serve("query_balance")
        assert served == 42_000 and age >= 3.0, (served, age)

        # Production gate: any non-test SPACER_TIMING_MODE raises on
        # refresh (before any backend contact) and on seeding; serve
        # itself stays readable (it is petitioner-facing and must
        # never raise NotImplementedError into the request path).
        # Make the row due first - a sweep with nothing due draws no
        # window and returns 0 without raising, in any mode.
        seed_for_test("query_balance", 42_000, time.time() - 3.0, time.time() - 1.0)
        del os.environ["SPACER_TIMING_MODE"]
        for fn in (refresh_due, lambda: seed_for_test("query_balance", 1, 0, 0)):
            raised = False
            try:
                fn()
            except NotImplementedError:
                raised = True
            assert raised, "production mode must raise"
        assert serve("query_balance")[0] == 42_000
        os.environ["SPACER_TIMING_MODE"] = "test"

        # Audit trail: refreshes and the outage both left records.
        events = [
            json.loads(line)["event"]
            for line in (work / "audit.log").read_text().splitlines()
            if line.strip()
        ]
        assert events.count("snapshot_refresh") >= 5, events
        assert "snapshot_refresh_failed" in events, events

        print(f"OK: read-snapshot refresh/serve round-trips at {work}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    sys.exit(0)
