"""
Operator-visibility TUI: the two-column console (design doc 13).

Reads the arbiter's audit log (append-only JSONL, doc 05 §4.5) and
renders each record as one row on a shared, append-only grid:

- Column 1 (calm / green): PETITIONER-KNOWN. Projected from the
  disclosure record - the gateway's "disclosure" events carry the
  verbatim body of every reply actually sent (gateway._respond_ok /
  _respond_refused; the minimal producer for doc 13 §3, formalization
  tracked by sp-gm4). Requests the petitioner sent (request_received)
  render dimmed in the same column: the petitioner knows what it asked.
- Column 2 (alert / red): PETITIONER-NEVER-KNOWN. Every other audit
  event: gateway decisions, registry activity, executor results with
  real txids / amounts / fees, timing deposits, ledger movements.
  Default-to-never on any doubt (doc 13 §3): an event this module does
  not recognize lands in column 2.

Deferred-disclosure pairing (doc 13 §2): when the timing layer later
releases a result, the poll reply's disclosure row re-prints the
withheld internal summary beside it (dimmed, column 2) so the two
align on one row without moving the original column-2 line. The
pairing is display-only state: result_poll_ok names the handle, and
the executor / deposit events seeded a handle -> summary map.

Display-only by design (doc 13 §4): reads arbiter-local state, takes
no input, writes nothing anywhere but the terminal. Colour is
load-bearing (col 1 green, col 2 red); the append-only scroll IS the
row grid, so nothing already printed ever moves.

Run on the arbiter console (a tmux window qualifies):

    AUDIT_LOG_PATH=... python3 arbiter/src/tui.py

Stdlib only.
"""
import json
import os
import sys
import time
from pathlib import Path

# Same default resolution as audit.py: src/ -> ../state/audit.log.
DEFAULT_AUDIT_PATH = Path(__file__).resolve().parent.parent / "state" / "audit.log"

# Fixed grid geometry. Wide enough for a real invoice fragment in
# column 1 and an executor summary in column 2; a narrower terminal
# simply soft-wraps in tmux history, which capture-pane still greps.
_TS_W = 8
_COL1_W = 88
_COL2_W = 116

# ANSI. Colour-coding is load-bearing, not decoration (doc 13 §2).
_GREEN = "\033[32m"
_DIM_GREEN = "\033[2;32m"
_RED = "\033[31m"
_DIM_RED = "\033[2;31m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

# Events projected into column 1. disclosure is the reply record;
# request_received is the petitioner's own submission (dimmed).
_COL1_EVENTS = ("disclosure", "request_received")

# How many trailing records to backfill on start (quiescent display:
# recent history, then live-only; doc 13 §7).
_BACKFILL = 25

# Longest string fragment shown before truncation with a one-char
# ellipsis marker. Tokens / invoices / txids stay identifiable by
# prefix while never flooding the row.
_FRAG = 28


def _shorten(value, limit=_FRAG):
    s = str(value)
    return s if len(s) <= limit else s[: limit - 1] + "~"


def _compact(payload, prefix=""):
    """Render a payload dict as `k=v` pairs with long values
    truncated. One level of nesting flattens to dotted keys
    (result.status=sent) so a released result's fields stay readable
    rather than vanishing inside a truncated JSON blob. Deterministic
    order for stable captures."""
    if not isinstance(payload, dict):
        return _shorten(payload, 60)
    parts = []
    for k in sorted(payload):
        v = payload[k]
        key = f"{prefix}{k}"
        if isinstance(v, dict) and not prefix:
            inner = _compact(v, prefix=f"{k}.")
            parts.append(inner if inner else f"{key}={{}}")
            continue
        if isinstance(v, dict):
            v = json.dumps(v, separators=(",", ":"), sort_keys=True)
        parts.append(f"{key}={_shorten(v)}")
    return " ".join(parts)


def _pad(text, width):
    if len(text) > width:
        text = text[: width - 1] + "~"
    return text.ljust(width)


class Renderer:
    """Classify audit records into the two columns and emit rows.

    Holds the display-only pairing state: handle -> internal summary
    (seeded by executor / deposit events), and the handle named by the
    most recent result_poll_ok, which the next disclosure row pairs
    with (the gateway is single-threaded, so the poll's reply is the
    next disclosure after its result_poll_ok record)."""

    def __init__(self, out=sys.stdout):
        self.out = out
        self._handle_notes = {}
        self._pending_poll_handle = None

    def header(self):
        h1 = _pad("PETITIONER-KNOWN (disclosure record)", _COL1_W)
        h2 = _pad("PETITIONER-NEVER-KNOWN (arbiter-internal)", _COL2_W)
        self.out.write(
            f"{_BOLD}{_pad('UTC', _TS_W)} | {_GREEN}{h1}{_RESET}{_BOLD} | "
            f"{_RED}{h2}{_RESET}\n"
        )
        self.out.write("-" * (_TS_W + 3 + _COL1_W + 3 + _COL2_W) + "\n")
        self.out.flush()

    def _row(self, ts, col1, col2, col1_style=_GREEN, col2_style=_RED):
        c1 = f"{col1_style}{_pad(col1, _COL1_W)}{_RESET}" if col1 else _pad("", _COL1_W)
        c2 = f"{col2_style}{_pad(col2, _COL2_W)}{_RESET}" if col2 else _pad("", _COL2_W)
        self.out.write(f"{_pad(ts[-9:][:8], _TS_W)} | {c1} | {c2}\n")
        self.out.flush()

    def _note_handle(self, event, payload):
        """Seed the deferred-disclosure pairing map from internal
        events that name a handle. Result-registry plumbing events
        (deposit / poll bookkeeping) are skipped so the re-print keeps
        the substantive internal summary - the executor's txid /
        amounts / fees - rather than the last piece of plumbing."""
        if event == "result_deposit" or event.startswith("result_poll"):
            return
        handle = payload.get("handle")
        if not handle:
            return
        summary = f"{event} {_compact({k: v for k, v in payload.items() if k != 'handle'})}"
        self._handle_notes[handle] = _shorten(summary, _COL2_W - 24)

    def feed(self, record):
        """Render one parsed audit record."""
        event = record.get("event", "?")
        payload = record.get("payload") or {}
        ts = record.get("ts", "")

        if event == "disclosure":
            body = payload.get("body")
            col2 = ""
            style2 = _DIM_RED
            if (
                isinstance(body, dict)
                and body.get("status") == "result"
                and self._pending_poll_handle
            ):
                # Deferred disclosure: re-print the withheld internal
                # summary beside the released reply (doc 13 §2).
                note = self._handle_notes.get(self._pending_poll_handle, "")
                col2 = _shorten(
                    f"re-print handle={self._pending_poll_handle} {note}",
                    _COL2_W,
                )
            self._pending_poll_handle = None
            self._row(ts, f"<- {_compact(body)}", col2, _GREEN, style2)
            return

        if event == "request_received":
            self._row(ts, f"-> op={payload.get('op')}", "", _DIM_GREEN)
            return

        # Everything else is column 2 (default-to-never, doc 13 §3).
        if event == "result_poll_ok":
            self._pending_poll_handle = payload.get("handle")
        self._note_handle(event, payload)
        self._row(ts, "", f"{event} {_compact(payload)}")


def follow(path, renderer, poll_s=0.25, once=False):
    """Tail the audit log forever (or one pass when once=True, for the
    smoke test). Backfills the last _BACKFILL records, then follows
    appended lines. Tolerates a not-yet-existing file and partial
    trailing lines (audit.py appends whole fsynced lines, but a reader
    can still catch a line mid-write)."""
    renderer.header()
    pos = 0
    buf = ""
    backfilled = False
    while True:
        if not path.exists():
            if once:
                return
            time.sleep(poll_s)
            continue
        size = path.stat().st_size
        if size < pos:
            pos = 0  # rotated/truncated: start over (should not happen)
            buf = ""
        if size > pos:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(pos)
                chunk = f.read()
                pos = f.tell()
            buf += chunk
            lines = buf.split("\n")
            buf = lines.pop()
            if not backfilled:
                lines = lines[-_BACKFILL:]
                backfilled = True
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except ValueError:
                    renderer._row("", "", _shorten(line, _COL2_W), _RED, _DIM_RED)
                    continue
                renderer.feed(record)
        elif not backfilled:
            backfilled = True
        if once:
            return
        time.sleep(poll_s)


def main():
    path = Path(os.environ.get("AUDIT_LOG_PATH", DEFAULT_AUDIT_PATH))
    renderer = Renderer()
    try:
        follow(path, renderer)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__" and os.environ.get("TUI_SMOKE") != "1":
    main()


if __name__ == "__main__" and os.environ.get("TUI_SMOKE") == "1":
    # Smoke test: feed a canned audit sequence through the renderer
    # and assert the column placement, the default-to-never rule, and
    # the deferred-disclosure re-print pairing. TUI_SMOKE=1 selects
    # this path so the default invocation stays the live console.
    import io
    import tempfile

    out = io.StringIO()
    r = Renderer(out=out)
    r.header()
    seq = [
        {"ts": "2026-07-10T12:00:00Z", "event": "request_received", "payload": {"op": "manage_bitcoin"}},
        {"ts": "2026-07-10T12:00:00Z", "event": "decision_allow", "payload": {"op": "manage_bitcoin"}},
        {"ts": "2026-07-10T12:00:00Z", "event": "disclosure", "payload": {"body": {"status": "received", "handle": "H1"}}},
        {"ts": "2026-07-10T12:00:09Z", "event": "manage_bitcoin_executed", "payload": {"handle": "H1", "amount_sats": 1500, "txid": "ab" * 32}},
        {"ts": "2026-07-10T12:00:21Z", "event": "result_deposit", "payload": {"handle": "H1", "kind": "result", "created_at": 1}},
        {"ts": "2026-07-10T12:00:30Z", "event": "request_received", "payload": {"op": "poll"}},
        {"ts": "2026-07-10T12:00:30Z", "event": "result_poll_ok", "payload": {"handle": "H1", "kind": "result"}},
        {"ts": "2026-07-10T12:00:30Z", "event": "disclosure", "payload": {"body": {"status": "result", "result": {"status": "sent", "amount_sats": 1500}}}},
        {"ts": "2026-07-10T12:00:31Z", "event": "made_up_event", "payload": {"x": 1}},
    ]
    for rec in seq:
        r.feed(rec)
    text = out.getvalue()
    plain = text
    for code in (_GREEN, _DIM_GREEN, _RED, _DIM_RED, _BOLD, _RESET):
        plain = plain.replace(code, "")
    lines = plain.splitlines()
    # Header + rule + 9 rows.
    assert len(lines) == 2 + len(seq), (len(lines), text)
    # Row 1: request in column 1 side (starts right after ts + sep).
    assert "-> op=manage_bitcoin" in lines[2], lines[2]
    # Row 2: decision is column 2 - column 1 cell is blank.
    assert lines[3].split("|")[1].strip() == "", lines[3]
    assert "decision_allow" in lines[3], lines[3]
    # Row 3: the reply disclosure lands in column 1.
    assert "<- handle=H1 status=received" in lines[4], lines[4]
    # Row 4: executor secret (txid) is column 2 only, and the txid is
    # truncated (never a full 64-hex on screen).
    assert "manage_bitcoin_executed" in lines[5] and "ab" in lines[5]
    assert "ab" * 32 not in lines[5], "txid must be truncated"
    assert lines[5].split("|")[1].strip() == "", lines[5]
    # Row 8: the released result pairs with a re-print naming H1.
    assert "<- result=" in lines[9] or "<- " in lines[9], lines[9]
    assert "re-print handle=H1" in lines[9], lines[9]
    assert "manage_bitcoin_executed" in lines[9], lines[9]
    # Row 9: unknown event defaults to column 2 (never-known).
    assert "made_up_event" in lines[10], lines[10]
    assert lines[10].split("|")[1].strip() == "", lines[10]

    # follow(once=True) end-to-end over a real temp file: header +
    # the same placement invariants hold when parsing from disk.
    tmp = Path(tempfile.gettempdir()) / "arbiter-tui-smoke.log"
    with open(tmp, "w") as f:
        for rec in seq:
            f.write(json.dumps(rec) + "\n")
        f.write("this line is not json\n")
    out2 = io.StringIO()
    follow(tmp, Renderer(out=out2), once=True)
    got = out2.getvalue()
    assert "PETITIONER-KNOWN" in got and "PETITIONER-NEVER-KNOWN" in got
    assert "-> op=manage_bitcoin" in got and "made_up_event" in got
    assert "this line is not json" in got  # garbage renders, never crashes
    tmp.unlink()
    print("OK: tui renderer classifies, pairs, and follows")
    sys.exit(0)
