"""
Operator-visibility TUI: the two-column console (design doc 13).

Reads the arbiter's audit log (append-only JSONL, doc 05 §4.5) and
renders each record as one row on a shared, append-only grid:

- Every row carries a LAYER tag - [chain] / [ ln  ] / [ecash] - naming
  which of the three value rails the event belongs to ([  -  ] for
  rail-neutral plumbing like polls and unknown ops), derived from the
  op, the event name, a registry entry's format, or the handle's
  remembered rail.
- Column 1 (calm / green): PETITIONER-KNOWN. Projected from the
  disclosure record - the gateway's "disclosure" events carry the
  verbatim body of every reply actually sent (gateway._respond_ok /
  _respond_refused; the minimal producer for doc 13 §3, formalization
  tracked by sp-gm4). Requests the petitioner sent (request_received)
  render dimmed in the same column: the petitioner knows what it asked.
  Numbers here are what the AI was TOLD: its own chosen amounts on
  write results, cloak-presented figures on reads.
- Column 2 (alert / red): PETITIONER-NEVER-KNOWN. Every other audit
  event: gateway decisions, registry activity, executor results with
  real txids / amounts / fees, timing deposits, ledger movements, and
  the balance_read / capacity_read events that record the REAL backend
  figure beside the cloak-presented one on every read. Default-to-never
  on any doubt (doc 13 §3): an event this module does not recognize
  lands in column 2.

Real-vs-told pairing (doc 13 §2): when a reply that carries a number
is released, the same row's column 2 re-prints the withheld ground
truth beside it - `real: ...` - so the operator reads told-vs-real at
a glance:
- read disclosures (balance / capacity) pair with the preceding
  balance_read / capacity_read event's real_sats;
- released results pair with the executor's remembered summary for
  that handle (real settled amounts, fees stay in the log).

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

# Fixed grid geometry, sized to fit a ~190-column terminal without
# wrapping: 8 (ts) + 1 + 7 (layer) + 3 + 76 + 3 + 92 = 190.
_TS_W = 8
_TAG_W = 7
_COL1_W = 76
_COL2_W = 92

# ANSI. Colour-coding is load-bearing, not decoration (doc 13 §2).
_GREEN = "\033[32m"
_DIM_GREEN = "\033[2;32m"
_RED = "\033[31m"
_DIM_RED = "\033[2;31m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

# How many trailing records to backfill on start (quiescent display:
# recent history, then live-only; doc 13 §7).
_BACKFILL = 25

# Longest string fragment shown before truncation with a one-char
# ellipsis marker. Tokens / invoices / txids stay identifiable by
# prefix while never flooding the row.
_FRAG = 28

# Rail attribution. Ops name their rail directly; registry entries
# name it through their address format; executor / ledger events name
# it in the event itself; result plumbing inherits it from the handle.
_LAYER_BY_OP = {
    "query_balance": "chain",
    "manage_bitcoin": "chain",
    "query_channels": "ln",
    "manage_lightning": "ln",
    "fund_ecash": "ecash",
    "defund_ecash": "ecash",
}
_LAYER_BY_FORMAT = {
    "bech32": "chain",
    "bech32m": "chain",
    "base58check": "chain",
    "bolt11": "ln",
    "bolt12": "ln",
    "lightning_address": "ln",
}
_TAGS = {
    "chain": "[chain]",
    "ln": "[ ln  ]",
    "ecash": "[ecash]",
    None: "[  -  ]",
}


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

    Holds display-only pairing state:
    - handle -> internal summary (seeded by executor / ledger events)
      and handle -> rail, for the deferred-disclosure `real:` re-print
      and for tagging result plumbing;
    - the handle named by the most recent result_poll_ok, which the
      next disclosure row pairs with (the gateway is single-threaded,
      so the poll's reply is the next disclosure after its
      result_poll_ok record);
    - the most recent balance_read / capacity_read payload, which the
      next read disclosure pairs with (`real:` beside the presented
      figure);
    - the most recent request op, for tagging acks and refusals with
      their rail."""

    def __init__(self, out=sys.stdout):
        self.out = out
        self._handle_notes = {}
        self._handle_layer = {}
        self._pending_poll_handle = None
        self._last_read = None
        self._last_op = None

    def header(self):
        h1 = _pad("PETITIONER-KNOWN (what the AI was told)", _COL1_W)
        h2 = _pad("PETITIONER-NEVER-KNOWN (ground truth: real amounts, ids)", _COL2_W)
        self.out.write(
            f"{_BOLD}{_pad('UTC', _TS_W)} {_pad('LAYER', _TAG_W)} | "
            f"{_GREEN}{h1}{_RESET}{_BOLD} | {_RED}{h2}{_RESET}\n"
        )
        self.out.write(
            "-" * (_TS_W + 1 + _TAG_W + 3 + _COL1_W + 3 + _COL2_W) + "\n"
        )
        self.out.flush()

    def _row(self, ts, layer, col1, col2, col1_style=_GREEN, col2_style=_RED):
        tag = _TAGS.get(layer, _TAGS[None])
        c1 = f"{col1_style}{_pad(col1, _COL1_W)}{_RESET}" if col1 else _pad("", _COL1_W)
        c2 = f"{col2_style}{_pad(col2, _COL2_W)}{_RESET}" if col2 else _pad("", _COL2_W)
        self.out.write(
            f"{_pad(ts[-9:][:8], _TS_W)} {_pad(tag, _TAG_W)} | {c1} | {c2}\n"
        )
        self.out.flush()

    def _layer_for(self, event, payload):
        op = payload.get("op")
        if op in _LAYER_BY_OP:
            return _LAYER_BY_OP[op]
        if event == "balance_read" or event.startswith("scale_"):
            return "chain"
        if event == "capacity_read":
            return "ln"
        if event.startswith("ecash_"):
            return "ecash"
        if event == "manage_bitcoin_executed":
            return "chain"
        if event == "manage_lightning_executed":
            return "ln"
        if event == "registry_add":
            return _LAYER_BY_FORMAT.get(payload.get("format"))
        if event == "result_deposit" or event.startswith("result_poll"):
            return self._handle_layer.get(payload.get("handle"))
        return None

    def _note_handle(self, event, payload, layer):
        """Seed the deferred-disclosure pairing maps from internal
        events that name a handle. Result-registry plumbing events
        (deposit / poll bookkeeping) are skipped so the `real:`
        re-print keeps the substantive internal summary - the
        executor's amounts / txid / fees - rather than the last piece
        of plumbing."""
        if event == "result_deposit" or event.startswith("result_poll"):
            return
        handle = payload.get("handle")
        if not handle:
            return
        summary = f"{event} {_compact({k: v for k, v in payload.items() if k != 'handle'})}"
        self._handle_notes[handle] = _shorten(summary, _COL2_W - 30)
        if layer:
            self._handle_layer[handle] = layer

    def _disclosure(self, ts, body):
        """Render one reply row: column 1 verbatim, column 2 the
        paired ground truth where one exists."""
        col2 = ""
        layer = None
        if isinstance(body, dict):
            if "balance_sats" in body or "capacity_sats" in body:
                layer = "chain" if "balance_sats" in body else "ln"
                if self._last_read is not None:
                    col2 = "real: " + _compact(self._last_read[1])
                    self._last_read = None
            elif body.get("status") == "received" and body.get("handle"):
                layer = _LAYER_BY_OP.get(self._last_op)
                if layer:
                    self._handle_layer[body["handle"]] = layer
            elif body.get("status") == "result" and self._pending_poll_handle:
                h = self._pending_poll_handle
                layer = self._handle_layer.get(h)
                note = self._handle_notes.get(h, "")
                col2 = _shorten(f"real: handle={h} {note}", _COL2_W)
            elif body.get("status") in ("refused", "not_yet"):
                layer = _LAYER_BY_OP.get(self._last_op)
        self._pending_poll_handle = None
        self._row(ts, layer, f"<- {_compact(body)}", col2, _GREEN, _DIM_RED)

    def feed(self, record):
        """Render one parsed audit record."""
        event = record.get("event", "?")
        payload = record.get("payload") or {}
        ts = record.get("ts", "")

        if event == "disclosure":
            self._disclosure(ts, payload.get("body"))
            return

        if event == "request_received":
            op = payload.get("op")
            self._last_op = op
            self._row(ts, _LAYER_BY_OP.get(op), f"-> op={op}", "", _DIM_GREEN)
            return

        # Everything else is column 2 (default-to-never, doc 13 §3).
        layer = self._layer_for(event, payload)
        if event == "result_poll_ok":
            self._pending_poll_handle = payload.get("handle")
        if event in ("balance_read", "capacity_read"):
            self._last_read = (event, dict(payload))
        self._note_handle(event, payload, layer)
        self._row(ts, layer, "", f"{event} {_compact(payload)}")


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
                    renderer._row("", None, "", _shorten(line, _COL2_W), _RED, _DIM_RED)
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
    # and assert column placement, layer tags, the default-to-never
    # rule, the read real-vs-told pairing, and the deferred-disclosure
    # `real:` re-print. TUI_SMOKE=1 selects this path so the default
    # invocation stays the live console.
    import io
    import tempfile

    out = io.StringIO()
    r = Renderer(out=out)
    r.header()
    seq = [
        {"ts": "2026-07-10T12:00:00Z", "event": "request_received", "payload": {"op": "query_balance"}},
        {"ts": "2026-07-10T12:00:00Z", "event": "balance_read", "payload": {"real_sats": 142686, "presented_sats": 14268}},
        {"ts": "2026-07-10T12:00:00Z", "event": "decision_allow", "payload": {"op": "query_balance"}},
        {"ts": "2026-07-10T12:00:00Z", "event": "disclosure", "payload": {"body": {"balance_sats": 14268, "status": "ok"}}},
        {"ts": "2026-07-10T12:00:01Z", "event": "request_received", "payload": {"op": "manage_bitcoin"}},
        {"ts": "2026-07-10T12:00:01Z", "event": "decision_allow", "payload": {"op": "manage_bitcoin"}},
        {"ts": "2026-07-10T12:00:01Z", "event": "disclosure", "payload": {"body": {"status": "received", "handle": "H1"}}},
        {"ts": "2026-07-10T12:00:09Z", "event": "manage_bitcoin_executed", "payload": {"handle": "H1", "amount_sats": 1500, "txid": "ab" * 32}},
        {"ts": "2026-07-10T12:00:21Z", "event": "result_deposit", "payload": {"handle": "H1", "kind": "result", "created_at": 1}},
        {"ts": "2026-07-10T12:00:30Z", "event": "request_received", "payload": {"op": "poll"}},
        {"ts": "2026-07-10T12:00:30Z", "event": "result_poll_ok", "payload": {"handle": "H1", "kind": "result"}},
        {"ts": "2026-07-10T12:00:30Z", "event": "disclosure", "payload": {"body": {"status": "result", "result": {"status": "sent", "amount_sats": 1500}}}},
        {"ts": "2026-07-10T12:00:31Z", "event": "ecash_fund_executed", "payload": {"handle": "H2", "amount_sats": 512, "ln_routing_fee_msat": 1000}},
        {"ts": "2026-07-10T12:00:31Z", "event": "made_up_event", "payload": {"x": 1}},
    ]
    for rec in seq:
        r.feed(rec)
    text = out.getvalue()
    plain = text
    for code in (_GREEN, _DIM_GREEN, _RED, _DIM_RED, _BOLD, _RESET):
        plain = plain.replace(code, "")
    lines = plain.splitlines()
    assert len(lines) == 2 + len(seq), (len(lines), text)

    def cell(i, col):
        return lines[2 + i].split("|")[col].strip()

    def tag(i):
        return lines[2 + i].split("|")[0][_TS_W + 1:].strip()

    # Read flow: request tagged [chain]; balance_read is col-2 with
    # the REAL figure; the disclosure pairs presented (col 1) with
    # real (col 2) on one row.
    assert tag(0) == "[chain]" and cell(0, 1) == "-> op=query_balance", lines[2]
    assert "balance_read" in cell(1, 2) and "real_sats=142686" in cell(1, 2)
    assert cell(3, 1).startswith("<- balance_sats=14268"), lines[5]
    assert "real: " in cell(3, 2) and "real_sats=142686" in cell(3, 2), lines[5]
    assert tag(3) == "[chain]", lines[5]
    # Write flow: ack row remembers the rail; executor secret is
    # col-2 only with truncated txid; released result re-prints the
    # real summary beside it, tagged with the handle's rail.
    assert tag(6) == "[chain]" and "<- handle=H1 status=received" in cell(6, 1)
    assert cell(7, 1) == "" and "manage_bitcoin_executed" in cell(7, 2)
    assert "ab" * 32 not in lines[9], "txid must be truncated"
    assert tag(8) == "[chain]", "deposit inherits the handle's rail"
    assert tag(9) == "[  -  ]", "poll request is rail-neutral"
    assert "real: handle=H1" in cell(11, 2), lines[13]
    assert "manage_bitcoin_executed" in cell(11, 2), lines[13]
    assert tag(11) == "[chain]", lines[13]
    # eCash executor event tags its rail; unknown events stay
    # rail-neutral column 2 (default-to-never).
    assert tag(12) == "[ecash]", lines[14]
    assert tag(13) == "[  -  ]" and "made_up_event" in cell(13, 2), lines[15]

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
    print("OK: tui renderer classifies, tags rails, pairs real-vs-told")
    sys.exit(0)
