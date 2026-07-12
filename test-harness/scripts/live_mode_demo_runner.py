#!/usr/bin/env python3
"""
live_mode_demo_runner.py - build the deployment-mode demo capture suite.

Produces the three cumulative-mode demo captures under ~/spacer/demo/captures/
(D1 onchain, D2 +lightning, D3 +ecash). Each capture pairs a two-column
operator-TUI render (`tui.txt`, the exposable | secret grid the operator watches
in arbiter/src/tui.py) with the exact audit-event slice it cites (`audit.jsonl`)
and a provenance note (`notes.md`). The rendered PNG/MD demo pages are built
separately, out of repo, from these captures.

Two sources, both real, no fabrication:

  1. Value-carrying events (query_balance / query_channels reads, manage_bitcoin /
     manage_lightning sends, fund/defund, the allowance-cap refusal) are verbatim
     slices of the live captain-loop audit log, staged under
     ~/spacer/demo/captures/_source/ (see that dir's provenance.md). These carry
     the operator's real Mutinynet-signet testbed figures - real balance 12103 ->
     served 12000, real channel capacity 72833 -> served 72000, a real on-chain
     txid, the real 100-sat defund melt haircut - which the mode gate cannot
     produce and which must never be invented.

  2. The `decision_refuse_mode` events are generated fresh here by exercising the
     real gateway mode gate (arbiter/src/gateway.py) in-process under
     SPACER_MODE=onchain / SPACER_MODE=lightning. The live captain-loop gateway
     runs in ecash (full) mode, so it never refuses an extension op by mode; the
     mode gate refuses BEFORE any backend is touched (lnd.py / ecash.py are never
     imported), so an in-process refusal on fake backends is byte-identical to a
     production one. This is the "currently-demonstrable behavior" the demo ships.

Each demo's audit.jsonl arranges its op-blocks in the demo's NARRATIVE order
(capability, then boundary), so the absolute per-event timestamps reflect each
round-trip's real capture time rather than one wall clock - it is a composed
evidence slice, not a single session. Every payload is verbatim; only which real
round-trips appear, and in what order, is editorial. notes.md records this.

Subcommands:
  smoke    (default) exercise the mode gate in-process and assert the three
           decision_refuse_mode events + the uniform refusal. Self-contained:
           no ~/spacer, no _source fixtures, no network. This is the CI check.
  build    compose the three captures under ~/spacer/demo/captures/ from the
           _source fixtures + fresh refuse-mode records, rendering tui.txt via
           the real arbiter/src/tui.py Renderer.

Stdlib only. Scope guard (bead sp-6md): depicts only petitioner-facing gateway
mitigations; the arbiter <-> bitcoind/LND link is trusted and out of scope.
"""
import io
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
DEMO = Path.home() / "spacer" / "demo"
SRC = DEMO / "captures" / "_source"
CAPTURES = DEMO / "captures"

# arbiter/src on path for the gateway (mode gate) and the TUI renderer.
sys.path.insert(0, str(REPO / "arbiter" / "src"))
import audit      # noqa: E402
import gateway    # noqa: E402
import registry   # noqa: E402
import state      # noqa: E402
import tui        # noqa: E402  (the real two-column operator console renderer)

# Render geometry for the captured grid. Pinned (not terminal-detected) so a
# capture is byte-stable across hosts; PAD is the doc-13 fixed-height secret
# block, kept small here since the demo bursts are short.
_TUI_WIDTH = 150
_TUI_PAD = 6


# === fresh decision_refuse_mode via the real in-process mode gate ==========

def _refuse_mode_records(mode, op, payload):
    """Start an isolated in-process arbiter under SPACER_MODE=mode, POST one
    extension op, and return its [request_received, decision_refuse_mode,
    disclosure] records verbatim from the arbiter's own audit log.

    No backend is touched: an extension op in a mode that disables it refuses
    at the gateway mode gate before dispatch (gateway.py process_request), so
    the event equals a production deployment's. Isolated temp audit/state/
    registry paths keep this off the live captain-loop log."""
    d = Path(tempfile.mkdtemp(prefix="mode-demo-"))
    saved_mode = os.environ.get("SPACER_MODE")
    os.environ["SPACER_MODE"] = mode
    os.environ.setdefault("SPACER_TIMING_MODE", "test")
    try:
        audit.configure(d / "audit.log")
        state.configure(d / "state.db")
        state.migrate()
        registry.configure(d / "destinations.yaml")
        server = gateway.make_server(host="127.0.0.1", port=0, latency_target=0.05)
        port = server.server_address[1]
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        try:
            body = json.dumps({"op": op, **payload}).encode()
            req = urllib.request.Request(
                f"http://127.0.0.1:{port}/", data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            resp = json.loads(urllib.request.urlopen(req, timeout=10).read())
        finally:
            server.shutdown()
            server.server_close()
            t.join(timeout=2.0)
        records = [json.loads(line) for line in
                   (d / "audit.log").read_text().splitlines() if line.strip()]
    finally:
        if saved_mode is None:
            os.environ.pop("SPACER_MODE", None)
        else:
            os.environ["SPACER_MODE"] = saved_mode
    keep = ("request_received", "decision_refuse_mode", "disclosure")
    return resp, [r for r in records if r.get("event") in keep]


# === demo composition ======================================================
#
# Each demo is a list of op-blocks in narrative order. A "src" block is a
# verbatim fixture slice; a "refuse_mode" block is generated fresh here. The
# per-demo set mirrors the sp-6md spec's bullets exactly; the cumulative
# framing ("D2 = D1 + Lightning") lives in the demo docs, not the capture.

DEMOS = {
    "D1-onchain": {
        "mode": "onchain",
        "blocks": [
            {"src": "read-balance"},          # cloak + snapshot + quantization
            {"src": "write-manage-bitcoin"},  # token + standing approval + handle + floor
            {"refuse_mode": ("onchain", "manage_lightning",
                             {"recipient_token": "R9469W", "amount_msats": 5000000})},
        ],
    },
    "D2-onchain-lightning": {
        "mode": "lightning",
        "blocks": [
            {"src": "read-channels"},          # cloaked + snapshot-served capacity
            {"src": "write-manage-lightning"}, # allowed by standing approval
            {"refuse_mode": ("lightning", "fund_ecash", {"amount_sats": 5000})},
        ],
    },
    "D3-onchain-lightning-ecash": {
        "mode": "ecash",
        "blocks": [
            {"src": "write-fund-ecash"},    # allowed by standing approval; AI gets bearer float
            {"src": "write-defund-ecash"},  # defund via the AI custody hop; outstanding -> 0
            {"src": "refuse-allowance"},    # over the cap -> refused BEFORE approvals
        ],
    },
}


def _load_src(name):
    path = SRC / f"{name}.jsonl"
    if not path.exists():
        raise SystemExit(f"missing source fixture {path} (see captures/_source/)")
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _compose(demo):
    """Return (records, refuse_summary) for one demo: fixture slices verbatim,
    refuse_mode blocks generated fresh, in narrative order."""
    records, refusals = [], []
    for block in demo["blocks"]:
        if "src" in block:
            records.extend(_load_src(block["src"]))
        else:
            mode, op, payload = block["refuse_mode"]
            resp, recs = _refuse_mode_records(mode, op, payload)
            if resp != {"status": "refused"} or not any(
                    r["event"] == "decision_refuse_mode" for r in recs):
                raise SystemExit(f"mode gate did not refuse {op} in {mode}: {resp}")
            records.extend(recs)
            refusals.append((mode, op))
    return records, refusals


# === two-column render via the real Renderer ===============================

def _strip_ansi(s):
    for code in (tui._GREEN, tui._DIM_GREEN, tui._RED, tui._DIM_RED,
                 tui._BOLD, tui._YELLOW, tui._RESET):
        s = s.replace(code, "")
    return s


def _render_tui(records):
    """Feed records through the real operator-console Renderer and return the
    plain-text (ANSI-stripped) two-column grid, header included."""
    out = io.StringIO()
    r = tui.Renderer(out=out, pad=_TUI_PAD, width=_TUI_WIDTH)
    r.header()
    for rec in records:
        r.feed(rec)
    r.flush_pending()
    return _strip_ansi(out.getvalue())


# === build =================================================================

_NOTES = """# {name} - capture provenance

Two-column operator-console render (`tui.txt`) of the audit slice this demo
cites (`audit.jsonl`). LEFT column = PETITIONER-KNOWN (what the sandboxed AI
sees); RIGHT column = PETITIONER-NEVER-KNOWN (operator ground truth). Mutinynet
signet; every sat is a valueless test sat.

Composed evidence slice: each op-block below is a verbatim real round-trip;
blocks are ordered by the demo's narrative (capability, then boundary), so the
absolute timestamps are each round-trip's real capture time, not one clock.
Every payload is verbatim - see ../\_source/provenance.md for each slice's origin
and the live captain-loop audit log for the untouched records.

Blocks, in order:
{blocks}

Regenerate: `python3 test-harness/scripts/live_mode_demo_runner.py build`
(the decision_refuse_mode events are re-exercised against the real gateway mode
gate each run, so their timestamps update; all other values are stable).
"""

_BLOCK_DESC = {
    "read-balance": "query_balance read - scale cloaking + snapshot serving + "
                    "served-value quantization: real 12103 -> served 12000 (floored to a "
                    "1000-sat grid), from a snapshot 2.6 s old, never a live lookup",
    "read-channels": "query_channels read - cloaked + snapshot-served capacity: real "
                     "72833 -> served 72000, snapshot 6.2 s old",
    "write-manage-bitcoin": "manage_bitcoin send - recipient registry token 9BJY3W "
                            "resolved, standing approval cleared -> decision_allow + opaque "
                            "handle; the real txid/amount stay operator-only; result rides "
                            "the handle, polled once past the result-poll floor",
    "write-manage-lightning": "manage_lightning send - tokenized bolt11 (token ZHQB0H), "
                              "allowed by standing approval; 5000 sat settles on the fast "
                              "rail, real routing fee operator-only",
    "write-fund-ecash": "fund_ecash - allowed by standing approval; the AI receives a real "
                        "5000-sat bearer cashu token (allowance cap 6000)",
    "write-defund-ecash": "defund_ecash - the AI hands bearer money back through the custody "
                          "hop; 5000 claimed, 4900 credited (100-sat melt haircut), "
                          "outstanding ledger returns to 0",
    "refuse-allowance": "fund_ecash over the allowance cap - requested 5000 > cap 3000 -> "
                        "decision_refuse_allowance; the allowance check runs BEFORE standing "
                        "approvals, so no approval can widen the blast radius",
}


def _block_line(block):
    if "src" in block:
        return f"- `{block['src']}`: {_BLOCK_DESC.get(block['src'], block['src'])}"
    mode, op, _ = block["refuse_mode"]
    return (f"- refuse_mode (fresh): `{op}` in {mode} mode -> decision_refuse_mode "
            f"reason=advanced_extension_disabled (the advanced rail does not exist for "
            f"this Pet); refused before any backend is touched")


def build():
    if not SRC.exists():
        raise SystemExit(f"source fixtures missing at {SRC}; cannot build")
    for name, demo in DEMOS.items():
        records, _ = _compose(demo)
        cdir = CAPTURES / name
        cdir.mkdir(parents=True, exist_ok=True)
        with open(cdir / "audit.jsonl", "w") as f:
            for rec in records:
                f.write(json.dumps(rec) + "\n")
        (cdir / "tui.txt").write_text(_render_tui(records))
        blocks = "\n".join(_block_line(b) for b in demo["blocks"])
        (cdir / "notes.md").write_text(_NOTES.format(name=name, blocks=blocks))
        print(f"built {name}: {len(records)} events -> {cdir}")
    return 0


# === smoke =================================================================

def smoke():
    """Self-contained: assert the mode gate refuses each extension op the demos
    rely on, emitting a real decision_refuse_mode. No ~/spacer, no fixtures."""
    cases = [
        ("onchain", "manage_lightning", {"recipient_token": "R9469W", "amount_msats": 5000000}),
        ("onchain", "fund_ecash", {"amount_sats": 5000}),
        ("lightning", "fund_ecash", {"amount_sats": 5000}),
    ]
    for mode, op, payload in cases:
        resp, recs = _refuse_mode_records(mode, op, payload)
        assert resp == {"status": "refused"}, (mode, op, resp)
        refuse = [r for r in recs if r["event"] == "decision_refuse_mode"]
        assert refuse, f"no decision_refuse_mode for {op} in {mode}: {recs}"
        pl = refuse[0]["payload"]
        assert pl.get("op") == op, pl
        assert pl.get("reason") == "advanced_extension_disabled", pl
    # The renderer places a petitioner request left and the secret refusal right.
    resp, recs = _refuse_mode_records("onchain", "manage_lightning",
                                      {"recipient_token": "R9469W", "amount_msats": 5000000})
    grid = _render_tui(recs)
    assert "PETITIONER-KNOWN" in grid and "PETITIONER-NEVER-KNOWN" in grid, grid[:200]
    assert "-> op=manage_lightning" in grid, "request must render on the left"
    assert "decision_refuse_mode" in grid, "refusal must render on the right"
    print("OK: mode gate refuses manage_lightning/fund_ecash by mode "
          "(decision_refuse_mode, advanced_extension_disabled)")
    return 0


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "smoke"
    if cmd == "smoke":
        return smoke()
    if cmd == "build":
        return build()
    print(f"unknown subcommand {cmd!r}; use 'smoke' or 'build'", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
