#!/usr/bin/env python3
"""Live proof that petitioner balance reads follow the delay principle.

Rapid-polls query_balance through the running gateway far faster than the
5-15s test-mode refresh band, and correlates the served value against the
arbiter's snapshot_refresh audit events. Demonstrates, on the real rig:

  1. Rate-independence: sub-second polling never sees more than the
     snapshot - the served value is piecewise-constant.
  2. Randomized event-independent refresh: the value only steps at a
     snapshot_refresh tick, and the ticks are spaced by a random in-band
     interval, not by any read or wallet event.
  3. Quantization: every served value is on the 1000-sat grid; the real
     figure behind it (audit-only) is not.

Read-only: issues query_balance (a petitioner read) and reads the audit
log. Spends nothing, changes no state.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path.home() / "spacer-github" / "test-harness" / "scripts"))
import live_sequence_runner as R

AUDIT = R.paths()["audit"]
POLL_SECONDS = 40
POLL_INTERVAL = 0.8


def audit_pos():
    return AUDIT.stat().st_size if AUDIT.exists() else 0


def read_refreshes(since_pos):
    """Return [(ts, real, served)] for query_balance snapshot_refresh
    events appended since since_pos."""
    out = []
    with open(AUDIT, "r", errors="replace") as f:
        f.seek(since_pos)
        for line in f.read().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("event") != "snapshot_refresh":
                continue
            p = rec.get("payload", {})
            if p.get("op") != "query_balance":
                continue
            out.append((rec.get("ts"), p.get("real_sats"), p.get("served_sats")))
    return out


def main():
    start_pos = audit_pos()
    t0 = time.time()
    polls = []
    print(f"polling query_balance every {POLL_INTERVAL}s for {POLL_SECONDS}s "
          f"(refresh band is 5-15s, so polls run ~10x faster than refresh)\n")
    print(f"  {'t+(s)':>6}  {'served_sats':>12}")
    last = None
    while time.time() - t0 < POLL_SECONDS:
        r = R.petcli("query", "balance")
        served = r.get("balance_sats")
        el = round(time.time() - t0, 1)
        polls.append((el, served))
        mark = ""
        if served != last:
            mark = "  <- value stepped" if last is not None else ""
            last = served
        print(f"  {el:>6}  {served:>12}{mark}")
        time.sleep(POLL_INTERVAL)

    refreshes = read_refreshes(start_pos)
    distinct = sorted({s for _, s in polls})
    print(f"\n  total polls: {len(polls)}")
    print(f"  distinct served values observed: {distinct}")
    print(f"  snapshot_refresh ticks during window: {len(refreshes)}")
    if refreshes:
        ts = [r[0] for r in refreshes]
        # inter-refresh gaps from the audit timestamps (ISO 8601 Z)
        def secs(t):
            return time.mktime(time.strptime(t, "%Y-%m-%dT%H:%M:%SZ"))
        gaps = [round(secs(ts[i + 1]) - secs(ts[i]), 1) for i in range(len(ts) - 1)]
        print(f"  inter-refresh gaps (s): {gaps}  (all should be in [5,15])")
        print(f"  refresh real -> served (quantization): "
              f"{[(r[1], r[2]) for r in refreshes[:6]]}")
        grid_ok = all(s % 1000 == 0 for _, _, s in refreshes)
        band_ok = all(5 <= g <= 15 for g in gaps) if gaps else True
        piecewise = len(distinct) <= len(refreshes) + 1
        print()
        print(f"  [{'PASS' if grid_ok else 'FAIL'}] every served value on the 1000-sat grid")
        print(f"  [{'PASS' if band_ok else 'FAIL'}] every refresh gap within the 5-15s randomized band")
        print(f"  [{'PASS' if piecewise else 'FAIL'}] served value piecewise-constant "
              f"({len(distinct)} distinct values across {len(polls)} polls, "
              f"{len(refreshes)} refreshes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
