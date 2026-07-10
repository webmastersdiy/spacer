"""
Operator-visibility TUI: the two-column console (design doc 13).

Reads the arbiter's audit log (append-only JSONL, doc 05 §4.5) and
renders it as a two-column grid whose LEFT column is safe to expose
(screenshot, paste, photograph) while the RIGHT column holds material
the petitioner must never learn.

Safety gate (doc 13 §5). On start the console prints the KVM/production
warning and requires a typed acknowledgment. It is unsafe to run the
arbiter OR this console on the same host as the AI/petitioner, or over
any non-KVM attachment (SSH, screen-share, remote desktop): the
never-known column would then be reachable off the arbiter host. The
supported deployment is a keyboard+monitor physically attached to the
arbiter. SPACER_TUI_ACK=1 pre-acknowledges for a known-safe automated
harness; a persistent one-line banner keeps the warning on screen
regardless.

Two columns (doc 13 §2, §3):
- Column 1 (calm / green): PETITIONER-KNOWN. Projected from the
  disclosure record - the gateway's "disclosure" events carry the
  verbatim body of every reply actually sent (gateway._respond_ok /
  _respond_refused; the minimal producer for doc 13 §3, sp-gm4).
  Requests (request_received) render dimmed in the same column.
- Column 2 (alert / red): PETITIONER-NEVER-KNOWN. Every other audit
  event: gateway decisions, registry activity, executor results with
  real txids / amounts / fees, ledger movements, and the balance_read /
  capacity_read events that record the REAL backend figure. Default-to-
  never (doc 13 §3): an unrecognized event lands in column 2.

Three leak-closing rules make the LEFT column safe to expose on its own:

1. Per-column timestamps. The timestamp is NOT a shared row prefix.
   A petitioner row carries its timestamp on the LEFT only. A secret
   event carries its timestamp on the RIGHT only - so a secret event's
   time (and the spacing around it) never appears in the left column.
   When a disclosure and the secret it pairs with share one timestamp
   (the real-vs-told re-print, below), the timestamp prints once on the
   left and the right shows a spacer, never a duplicate.

2. Fixed-height secret reservation (SPACER_TUI_PAD, default 20).
   Secret events are not printed as their own interleaved rows (whose
   count would leak through the left column's spacing). They buffer and
   flush into a block of exactly PAD lines whose LEFT side is entirely
   blank; the right side is filled top-down with the buffered events.
   Because the block is always PAD lines, the left column's rhythm does
   not vary with how many secret events occurred. If a burst exceeds
   the block, the right shows a visible truncation marker and the
   remainder carries to the next block - never more than PAD lines of
   spacer (raise PAD to see more at once). SPACER_TUI_ALWAYS_PAD=1
   emits the block after every petitioner row even when empty, hiding
   even whether any secret event happened (off by default: it scrolls
   the console continuously).

3. Real-vs-told pairing (doc 13 §2). When a reply carrying a number is
   released, the same row's right side re-prints the withheld ground
   truth (`real: ...`) beside it, so the operator reads told-vs-real at
   a glance: read disclosures pair with the preceding balance_read /
   capacity_read real figure; released results pair with the executor's
   remembered real summary. This re-print shares the disclosure's
   timestamp, so per rule 1 the right timestamp is a spacer.

Every row also carries a LAYER tag per column - [chain] / [ ln  ] /
[ecash] ([  -  ] for rail-neutral plumbing) - naming which value rail
each side's event belongs to.

Display-only by design (doc 13 §4): reads arbiter-local state, takes no
input beyond the one-time acknowledgment, writes nothing anywhere but
the terminal. Colour is load-bearing (col 1 green, col 2 red).

Run on the arbiter console (a KVM-attached tmux window qualifies):

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

# Grid geometry. Two independent (timestamp, tag) prefixes now - one
# per column - so a secret timestamp never rides in the left column.
# 8 (ts) + 1 + 7 (tag) + 1 = 17 prefix per side. Sized to fit a
# ~190-column terminal: 17 + 62 + 3 (" | ") + 17 + 86 = 185.
_TS_W = 8
_TAG_W = 7
_COL1_W = 62
_COL2_W = 86
_SEP = " | "

# ANSI. Colour-coding is load-bearing, not decoration (doc 13 §2).
_GREEN = "\033[32m"
_DIM_GREEN = "\033[2;32m"
_RED = "\033[31m"
_DIM_RED = "\033[2;31m"
_BOLD = "\033[1m"
_YELLOW = "\033[33m"
_RESET = "\033[0m"

# Trailing records to backfill on start (quiescent display, doc 13 §7).
_BACKFILL = 25
# Longest fragment before truncation with a one-char ellipsis marker.
_FRAG = 28

_DEFAULT_PAD = 20

# Rail attribution. Ops name their rail directly; registry entries name
# it through their address format; executor / ledger events name it in
# the event itself; result plumbing inherits it from the handle.
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
_TAGS = {"chain": "[chain]", "ln": "[ ln  ]", "ecash": "[ecash]", None: "[  -  ]"}

# Events consumed for real-vs-told pairing rather than shown as their
# own secret-block line (they surface as the `real:` beside the read
# disclosure they belong to).
_PAIR_ONLY = ("balance_read", "capacity_read")


_WARNING = f"""{_BOLD}{_YELLOW}
======================================================================
  SPACER OPERATOR CONSOLE - READ BEFORE CONTINUING
======================================================================
  This console shows PETITIONER-NEVER-KNOWN material: real balances,
  node/ mint identity, txids, fees, monitoring internals.

  It is SAFE ONLY on a keyboard+monitor PHYSICALLY ATTACHED to the
  arbiter host (KVM). It is UNSAFE to run this console, or the arbiter
  itself, when any of the following is true:

    - the AI / petitioner runs on this same host;
    - you are attached over SSH, mosh, tmux-over-ssh, screen-share,
      VNC/RDP, or any other remote / networked path;
    - the terminal's scrollback can be read off-host.

  Any of these puts the never-known column within reach of the AI and
  breaks the whole point of Spacer.
======================================================================{_RESET}
"""


def _shorten(value, limit=_FRAG):
    s = str(value)
    return s if len(s) <= limit else s[: limit - 1] + "~"


def _compact(payload, prefix=""):
    """Render a payload dict as `k=v` pairs with long values truncated.
    One level of nesting flattens to dotted keys (result.status=sent) so
    a released result's fields stay readable rather than vanishing
    inside a truncated JSON blob. Deterministic order for stable
    captures."""
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


def _hhmmss(ts):
    """HH:MM:SS from an ISO 'YYYY-MM-DDTHH:MM:SSZ' string, or ''."""
    return ts[-9:][:8] if ts else ""


def _fit(text, width):
    if len(text) > width:
        text = text[: width - 1] + "~"
    return text.ljust(width)


def _region(ts, tag, text, width):
    """One column's fixed-width cell: ts(8) tag(7) text(width). Blank
    ts / tag render as spaces so an empty side reveals nothing."""
    return f"{_fit(ts, _TS_W)} {_fit(tag, _TAG_W)} {_fit(text, width)}"


class Renderer:
    """Classify audit records into the two columns and emit rows,
    honoring the three leak-closing rules (per-column timestamps,
    fixed-height secret reservation, real-vs-told pairing).

    Display-only pairing state:
    - _secret_buf: secret events awaiting a fixed-height block flush,
      each (ts, tag, text);
    - _handle_notes / _handle_layer: handle -> real summary and rail,
      for the released-result `real:` re-print and result-plumbing tags;
    - _pending_poll_handle: the handle named by the most recent
      result_poll_ok, which the next disclosure re-prints (the gateway
      is single-threaded, so the poll reply is the next disclosure);
    - _last_read: the most recent balance_read / capacity_read payload,
      re-printed beside the read disclosure it belongs to;
    - _last_op: the most recent request op, for tagging acks/refusals.
    """

    def __init__(self, out=sys.stdout, pad=_DEFAULT_PAD, always_pad=False):
        self.out = out
        self.pad = max(1, pad)
        self.always_pad = always_pad
        self._secret_buf = []
        self._handle_notes = {}
        self._handle_layer = {}
        self._pending_poll_handle = None
        self._last_read = None
        self._last_op = None

    # --- output primitives ------------------------------------------

    def _line(self, left, right, lstyle, rstyle):
        l = f"{lstyle}{left}{_RESET}" if left.strip() else left
        r = f"{rstyle}{right}{_RESET}" if right.strip() else right
        self.out.write(l + _SEP + r + "\n")
        self.out.flush()

    def _blank_left(self):
        return _region("", "", "", _COL1_W)

    def _blank_right(self):
        return _region("", "", "", _COL2_W)

    def header(self):
        self.out.write(
            f"{_BOLD}{_YELLOW}[ KVM-only console - unsafe over SSH or "
            f"on an AI-sharing host; see banner above ]{_RESET}\n"
        )
        left = _region("UTC", "LAYER", "PETITIONER-KNOWN (told)", _COL1_W)
        right = _region(
            "UTC", "LAYER", "PETITIONER-NEVER-KNOWN (ground truth)", _COL2_W
        )
        self.out.write(f"{_BOLD}{_GREEN}{left}{_RESET}{_SEP}{_BOLD}{_RED}{right}{_RESET}\n")
        self.out.write("-" * (len(left) + len(_SEP) + len(right)) + "\n")
        self.out.flush()

    # --- rail attribution -------------------------------------------

    def _layer_for(self, event, payload):
        op = payload.get("op")
        if op in _LAYER_BY_OP:
            return _LAYER_BY_OP[op]
        if event in ("balance_read",) or event.startswith("scale_"):
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

    # --- secret buffering + fixed-height flush ----------------------

    def _buffer_secret(self, event, payload):
        layer = self._layer_for(event, payload)
        ts = _hhmmss(payload_ts(payload) or self._cur_ts)
        text = f"{event} {_compact(payload)}"
        self._secret_buf.append((ts, _TAGS.get(layer, _TAGS[None]), text))
        # Remember substantive per-handle summaries for the later
        # released-result re-print (skip result-registry plumbing so the
        # re-print keeps the real amounts/txid, not the last plumbing).
        if not (event == "result_deposit" or event.startswith("result_poll")):
            h = payload.get("handle")
            if h:
                self._handle_notes[h] = _shorten(
                    f"{event} {_compact({k: v for k, v in payload.items() if k != 'handle'})}",
                    _COL2_W - 30,
                )
                if layer:
                    self._handle_layer[h] = layer

    def flush_pending(self, force_empty=False):
        """Emit one fixed-height (PAD-line) secret block, left blank.

        Rule 2: the block is always exactly PAD lines, so the left
        column's spacing never varies with the secret-event count. A
        burst larger than the block shows PAD-1 events plus a visible
        truncation marker and carries the remainder to the next block.
        With no pending events the block is emitted only when
        force_empty (always_pad mode)."""
        if not self._secret_buf:
            if force_empty:
                for _ in range(self.pad):
                    self._line(self._blank_left(), self._blank_right(),
                               _GREEN, _RED)
            return
        if len(self._secret_buf) > self.pad:
            shown = self._secret_buf[: self.pad - 1]
            self._secret_buf = self._secret_buf[self.pad - 1:]
            trunc = ("", "", f"(+{len(self._secret_buf)} more secret events "
                              f"- raise SPACER_TUI_PAD)")
            rows = shown + [trunc]
        else:
            rows = self._secret_buf + [("", "", "")] * (self.pad - len(self._secret_buf))
            self._secret_buf = []
        for ts, tag, text in rows:
            right = _region(ts, tag, text, _COL2_W)
            self._line(self._blank_left(), right, _GREEN, _RED)

    # --- petitioner (left) rows -------------------------------------

    def _left_row(self, ts, layer, text, style, right=None, rstyle=_DIM_RED):
        left = _region(_hhmmss(ts), _TAGS.get(layer, _TAGS[None]), text, _COL1_W)
        self._line(left, right if right is not None else self._blank_right(),
                   style, rstyle)

    def _disclosure(self, ts, body):
        """Render one reply row: verbatim on the left, the paired ground
        truth on the right where one exists. Rule 1: the paired re-print
        shares this row's timestamp, so its right timestamp is a spacer
        (blank), never a duplicate."""
        right = None
        layer = None
        if isinstance(body, dict):
            if "balance_sats" in body or "capacity_sats" in body:
                layer = "chain" if "balance_sats" in body else "ln"
                if self._last_read is not None:
                    right = _region("", _TAGS[layer],
                                    "real: " + _compact(self._last_read[1]), _COL2_W)
                    self._last_read = None
            elif body.get("status") == "received" and body.get("handle"):
                layer = _LAYER_BY_OP.get(self._last_op)
                if layer:
                    self._handle_layer[body["handle"]] = layer
            elif body.get("status") == "result" and self._pending_poll_handle:
                h = self._pending_poll_handle
                layer = self._handle_layer.get(h)
                note = self._handle_notes.get(h, "")
                right = _region("", _TAGS.get(layer, _TAGS[None]),
                                _shorten(f"real: handle={h} {note}", _COL2_W), _COL2_W)
            elif body.get("status") in ("refused", "not_yet"):
                layer = _LAYER_BY_OP.get(self._last_op)
        self._pending_poll_handle = None
        self._left_row(ts, layer, f"<- {_compact(body)}", _GREEN, right=right)

    def feed(self, record):
        """Render one parsed audit record."""
        event = record.get("event", "?")
        payload = record.get("payload") or {}
        self._cur_ts = record.get("ts", "")

        if event == "disclosure":
            self.flush_pending(force_empty=self.always_pad)
            self._disclosure(self._cur_ts, payload.get("body"))
            return
        if event == "request_received":
            self.flush_pending(force_empty=self.always_pad)
            op = payload.get("op")
            self._last_op = op
            self._left_row(self._cur_ts, _LAYER_BY_OP.get(op), f"-> op={op}", _DIM_GREEN)
            return

        # Never-known (column 2). Pairing-only reads are consumed for the
        # inline `real:`; result_poll_ok arms the next disclosure's
        # re-print. Everything else buffers for the next block flush.
        if event in _PAIR_ONLY:
            self._last_read = (event, dict(payload))
            return
        if event == "result_poll_ok":
            self._pending_poll_handle = payload.get("handle")
        self._buffer_secret(event, payload)


def payload_ts(payload):
    """Some events carry their own timestamp field; none do today, so
    this returns None and the record's ts is used. Kept as the single
    hook for a future per-event timestamp without touching feed()."""
    return None


def follow(path, renderer, poll_s=0.25, once=False):
    """Tail the audit log. Backfill the last _BACKFILL records, then
    follow appended lines. On an idle tick with pending secret events,
    flush a block so a quiet burst (e.g. registry adds with no
    surrounding petitioner call) surfaces without waiting for the next
    petitioner event. Tolerates a missing file and partial trailing
    lines."""
    renderer.header()
    pos = 0
    buf = ""
    backfilled = False
    while True:
        if not path.exists():
            if once:
                renderer.flush_pending()
                return
            time.sleep(poll_s)
            continue
        size = path.stat().st_size
        if size < pos:
            pos = 0
            buf = ""
        progressed = False
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
                progressed = True
                try:
                    record = json.loads(line)
                except ValueError:
                    renderer._line(renderer._blank_left(),
                                   _region("", "", _shorten(line, _COL2_W), _COL2_W),
                                   _GREEN, _DIM_RED)
                    continue
                renderer.feed(record)
        else:
            backfilled = True
        if once:
            renderer.flush_pending()
            return
        if not progressed:
            renderer.flush_pending()
        time.sleep(poll_s)


def _acknowledge():
    """Print the safety warning and require a typed acknowledgment
    before the live console runs (doc 13 §5). SPACER_TUI_ACK=1
    pre-acknowledges for a known-safe automated harness. A
    non-interactive stdin with no pre-ack refuses rather than running
    unacknowledged.

    Re-prompts on a mismatch rather than exiting: a typo must not tear
    down the operator's terminal. Only an explicit 'abort' (or EOF /
    Ctrl-C) declines."""
    sys.stderr.write(_WARNING)
    sys.stderr.flush()
    if os.environ.get("SPACER_TUI_ACK") == "1":
        sys.stderr.write("[SPACER_TUI_ACK=1: pre-acknowledged]\n\n")
        return True
    if not sys.stdin or not sys.stdin.isatty():
        sys.stderr.write(
            "\nstdin is not interactive. Set SPACER_TUI_ACK=1 only on a "
            "KVM-attached arbiter console.\n"
        )
        return False
    while True:
        try:
            resp = input(
                "\nType 'I understand' to run the console, or 'abort' to "
                "quit: "
            ).strip().lower().rstrip(".")
        except (EOFError, KeyboardInterrupt):
            sys.stderr.write("\naborted.\n")
            return False
        if resp == "i understand":
            return True
        if resp in ("abort", "quit", "exit", "q"):
            return False
        sys.stderr.write(
            "  not recognized. Type exactly: I understand   "
            "(or 'abort' to quit)\n"
        )


def main():
    if not _acknowledge():
        sys.exit(3)
    path = Path(os.environ.get("AUDIT_LOG_PATH", DEFAULT_AUDIT_PATH))
    try:
        pad = int(os.environ.get("SPACER_TUI_PAD", _DEFAULT_PAD))
    except ValueError:
        pad = _DEFAULT_PAD
    renderer = Renderer(
        pad=pad, always_pad=os.environ.get("SPACER_TUI_ALWAYS_PAD") == "1"
    )
    try:
        follow(path, renderer)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__" and os.environ.get("TUI_SMOKE") != "1":
    main()


if __name__ == "__main__" and os.environ.get("TUI_SMOKE") == "1":
    # Smoke test: feed a canned audit sequence and assert the three
    # leak-closing rules - per-column timestamps (a secret event's time
    # never appears in the left column), fixed-height secret blocks with
    # a truncation marker beyond PAD, and the real-vs-told pairing - plus
    # per-column layer tags and the default-to-never rule. TUI_SMOKE=1
    # selects this path so the default invocation stays the live console.
    import io
    import tempfile

    def strip(s):
        for code in (_GREEN, _DIM_GREEN, _RED, _DIM_RED, _BOLD, _YELLOW, _RESET):
            s = s.replace(code, "")
        return s

    PAD = 4
    out = io.StringIO()
    r = Renderer(out=out, pad=PAD)
    r.header()
    # A secret timestamp (12:00:09) that is NEVER part of a petitioner
    # disclosure - it must never appear in any left column cell.
    SECRET_TS = "2026-07-10T12:00:09Z"
    seq = [
        {"ts": "2026-07-10T12:00:00Z", "event": "request_received", "payload": {"op": "query_balance"}},
        {"ts": "2026-07-10T12:00:00Z", "event": "balance_read", "payload": {"real_sats": 142686, "presented_sats": 14268}},
        {"ts": "2026-07-10T12:00:00Z", "event": "decision_allow", "payload": {"op": "query_balance"}},
        {"ts": "2026-07-10T12:00:00Z", "event": "disclosure", "payload": {"body": {"balance_sats": 14268, "status": "ok"}}},
        {"ts": "2026-07-10T12:00:01Z", "event": "request_received", "payload": {"op": "manage_bitcoin"}},
        {"ts": "2026-07-10T12:00:01Z", "event": "decision_allow", "payload": {"op": "manage_bitcoin"}},
        {"ts": "2026-07-10T12:00:01Z", "event": "disclosure", "payload": {"body": {"status": "received", "handle": "H1"}}},
        {"ts": SECRET_TS, "event": "manage_bitcoin_executed", "payload": {"handle": "H1", "amount_sats": 1500, "txid": "ab" * 32}},
        {"ts": SECRET_TS, "event": "registry_consume", "payload": {"handle": "H1", "token": "JZG4GQ"}},
        {"ts": SECRET_TS, "event": "result_deposit", "payload": {"handle": "H1", "kind": "result"}},
        {"ts": SECRET_TS, "event": "ecash_ledger_fund", "payload": {"handle": "H9", "amount_sats": 512, "outstanding_after_sats": 512}},
        {"ts": SECRET_TS, "event": "ecash_fund_executed", "payload": {"handle": "H9", "amount_sats": 512}},
        {"ts": "2026-07-10T12:00:30Z", "event": "request_received", "payload": {"op": "poll"}},
        {"ts": "2026-07-10T12:00:30Z", "event": "result_poll_ok", "payload": {"handle": "H1", "kind": "result"}},
        {"ts": "2026-07-10T12:00:30Z", "event": "disclosure", "payload": {"body": {"status": "result", "result": {"status": "sent", "amount_sats": 1500}}}},
        {"ts": "2026-07-10T12:00:31Z", "event": "made_up_event", "payload": {"x": 1}},
    ]
    for rec in seq:
        r.feed(rec)
    r.flush_pending()
    lines = strip(out.getvalue()).splitlines()

    def left(line):
        return line.split(_SEP, 1)[0]

    def right(line):
        parts = line.split(_SEP, 1)
        return parts[1] if len(parts) > 1 else ""

    body = lines[3:]  # drop banner + header + rule (3 header lines)

    # Rule 1: the secret timestamp 12:00:09 NEVER appears in any left
    # cell; it appears only on the right.
    assert any("12:00:09" in right(ln) for ln in body), "secret ts must show on right"
    for ln in body:
        assert "12:00:09" not in left(ln), f"secret ts leaked into left: {ln!r}"

    # Petitioner rows: left carries ts + tag + content; the read request
    # is tagged [chain].
    req = [ln for ln in body if "-> op=query_balance" in left(ln)]
    assert req and "12:00:00" in left(req[0]) and "[chain]" in left(req[0])
    assert right(req[0]).strip() == "", "petitioner request has no right content"

    # Read pairing (rule 3): the balance disclosure shows the presented
    # figure on the left and the REAL figure on the right, same row.
    bal = [ln for ln in body if "balance_sats=14268" in left(ln)]
    assert bal and "real_sats=142686" in right(bal[0]), bal
    # Its right timestamp is a spacer (rule 1: same-ts pair, left only).
    assert "12:00:00" not in right(bal[0]).split("real:")[0], "paired right ts must be blank"

    # Rule 2: secret events render in a fixed PAD-line block, left blank.
    exec_rows = [ln for ln in body if "manage_bitcoin_executed" in right(ln)]
    assert exec_rows and left(exec_rows[0]).strip() == "", "secret block left must be blank"
    # The full txid is never shown (truncated).
    assert not any("ab" * 32 in ln for ln in body), "txid must be truncated"
    # The 5-event burst exceeds PAD=4: a truncation marker appears and
    # no single flush exceeds PAD lines.
    assert any("more secret events" in right(ln) for ln in body), "truncation marker expected"

    # Released-result re-print (rule 3): pairs with the real summary and
    # is tagged with the handle's rail.
    res = [ln for ln in body if "result.status=sent" in left(ln)]
    assert res and "real: handle=H1" in right(res[0]) and "[chain]" in right(res[0]), res

    # Per-column tags + default-to-never: the eCash secret shows [ecash]
    # on the right; an unknown event still lands right, tagged neutral.
    assert any("[ecash]" in right(ln) and "ecash_fund_executed" in right(ln) for ln in body)
    made = [ln for ln in body if "made_up_event" in right(ln)]
    assert made and left(made[0]).strip() == "", "unknown event defaults to right"

    # always_pad emits a PAD-line block even with no pending secrets.
    out2 = io.StringIO()
    r2 = Renderer(out=out2, pad=3, always_pad=True)
    r2.feed({"ts": "2026-07-10T13:00:00Z", "event": "request_received", "payload": {"op": "poll"}})
    r2.feed({"ts": "2026-07-10T13:00:01Z", "event": "request_received", "payload": {"op": "poll"}})
    lines2 = strip(out2.getvalue()).splitlines()
    # always_pad flushes a fixed block BEFORE each petitioner row, so
    # two requests yield two 3-line (empty) blocks + two rows = 8 lines,
    # and the left column's rhythm is identical whether or not any
    # secret event occurred - which is the point (hide even existence).
    assert len(lines2) == 2 * (3 + 1), ("always_pad: block-then-row per event", lines2)
    assert sum(1 for ln in lines2 if ln.strip() == "|") == 6, ("6 blank block lines", lines2)

    # follow(once=True) over a real temp file: header + placement hold
    # from disk, trailing secrets flush, garbage never crashes.
    tmp = Path(tempfile.gettempdir()) / "arbiter-tui-smoke.log"
    with open(tmp, "w") as f:
        for rec in seq:
            f.write(json.dumps(rec) + "\n")
        f.write("this line is not json\n")
    out3 = io.StringIO()
    follow(tmp, Renderer(out=out3, pad=PAD), once=True)
    got = strip(out3.getvalue())
    assert "PETITIONER-KNOWN" in got and "PETITIONER-NEVER-KNOWN" in got
    assert "-> op=manage_bitcoin" in got and "made_up_event" in got
    assert "this line is not json" in got
    tmp.unlink()
    print("OK: tui closes left-column leaks (per-column ts, fixed block, pairing)")
    sys.exit(0)
