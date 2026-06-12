"""
Smoke test for the petcli command tree.

Lives beside petcli.py because petcli.py's `if __name__ == "__main__":`
block is the CLI dispatch path - putting smoke-test logic there would
make `petcli` mean two different things depending on how it was
invoked. This file imports petcli and exercises its parser instead.

Verifies that:
- The expected commands and subcommands are present.
- --help works at every node (top, intermediate, leaf).
- The local `estimate window` path runs end-to-end without an
  arbiter.
- Submit/query/result paths round-trip through an in-process echo
  HTTP server, exercising the full parse -> protocol.submit -> render
  pipeline against a known wire shape.
"""
import contextlib
import io
import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import petcli


def _capture_help(parser, argv):
    """Run argparse on argv and capture the --help / usage output.
    argparse exits with status 0 on --help; the caller asserts on the
    captured text."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            parser.parse_args(argv)
        except SystemExit as e:
            assert e.code == 0, (argv, e.code)
    return buf.getvalue()


def _capture_main(argv):
    """Run petcli.main() against argv and capture stdout."""
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        petcli.main(argv)
    return buf.getvalue()


def _expected_command_tree():
    """Source-of-truth for what petcli must expose at scaffolding
    time. The smoke test fails closed if a leaf is renamed or dropped
    without updating this map - the AI's discovery surface (`--help`
    walking) depends on these names."""
    return {
        # Bitcoin on-chain is the primary surface: send-bitcoin and
        # balance sit at the top of the tree. The Lightning and eCash
        # commands live under `advanced` (the opt-in extension
        # namespace); the eCash leaves nest one level deeper and are
        # checked separately in main().
        "submit": {"send-bitcoin"},
        "query": {"balance"},
        "result": {"poll"},
        "estimate": {"window"},
        "advanced": {"send-lightning", "channels", "ecash"},
    }


def _expected_ecash_leaves():
    """The third-level leaves under `advanced ecash` (design doc 07
    §9): fund/defund are arbiter-mediated; balance/send/receive/info
    are local wallet operations."""
    return {"fund", "defund", "balance", "send", "receive", "info"}


def main():
    parser = petcli._build_parser()

    # Top-level subparsers expose the four command groups.
    [top_action] = [
        a
        for a in parser._actions
        if hasattr(a, "choices") and a.dest == "cmd"
    ]
    expected = _expected_command_tree()
    assert set(top_action.choices.keys()) == set(expected.keys()), (
        top_action.choices.keys()
    )

    # Each group exposes the expected leaf set under its own
    # subparsers action (named <group>_op for clarity in --help).
    for group, leaves in expected.items():
        sp = top_action.choices[group]
        [leaf_action] = [
            a
            for a in sp._actions
            if hasattr(a, "choices") and a.dest == f"{group}_op"
        ]
        assert (
            set(leaf_action.choices.keys()) == leaves
        ), (group, leaf_action.choices.keys())

    # The eCash group nests a third level under advanced (the only
    # three-deep node in the tree); verify its leaf set the same way.
    advanced_sp = top_action.choices["advanced"]
    [advanced_action] = [
        a
        for a in advanced_sp._actions
        if hasattr(a, "choices") and a.dest == "advanced_op"
    ]
    ecash_sp = advanced_action.choices["ecash"]
    [ecash_action] = [
        a
        for a in ecash_sp._actions
        if hasattr(a, "choices") and a.dest == "ecash_op"
    ]
    assert set(ecash_action.choices.keys()) == _expected_ecash_leaves(), (
        ecash_action.choices.keys()
    )

    # --help works at every node. Spot-check distinguishing strings
    # from the description so the test fails meaningfully if a
    # description regresses, not just on missing words like "petcli".
    out = _capture_help(parser, ["--help"])
    assert "Spacer petitioner CLI" in out, out
    assert "submit" in out and "query" in out, out

    out = _capture_help(parser, ["submit", "--help"])
    assert "send-bitcoin" in out, out

    out = _capture_help(parser, ["submit", "send-bitcoin", "--help"])
    assert "to-token" in out and "amount-sats" in out, out

    out = _capture_help(parser, ["query", "--help"])
    assert "balance" in out, out

    # The Lightning commands moved under the `advanced` extension
    # namespace; the group and its leaves must be discoverable there.
    out = _capture_help(parser, ["advanced", "--help"])
    assert "send-lightning" in out and "channels" in out, out

    out = _capture_help(parser, ["advanced", "send-lightning", "--help"])
    assert "to-token" in out and "amount-msats" in out, out

    # The eCash extension namespace and its custody split must be
    # discoverable: fund/defund (arbiter-mediated) and the local
    # wallet leaves all appear under `advanced ecash`.
    out = _capture_help(parser, ["advanced", "ecash", "--help"])
    for leaf in ("fund", "defund", "balance", "send", "receive", "info"):
        assert leaf in out, (leaf, out)

    out = _capture_help(parser, ["advanced", "ecash", "fund", "--help"])
    assert "amount-sats" in out and "SPACER_MODE=ecash" in out, out

    out = _capture_help(parser, ["advanced", "ecash", "defund", "--help"])
    assert "token" in out and "standing approvals" in out, out

    out = _capture_help(parser, ["advanced", "ecash", "balance", "--help"])
    assert "Local-only" in out, out

    out = _capture_help(parser, ["result", "poll", "--help"])
    assert "handle" in out, out

    out = _capture_help(parser, ["estimate", "window", "--help"])
    assert "upper-bound" in out, out

    # `estimate window` runs without an arbiter (local-only per §5.2)
    # and emits a parseable JSON object on stdout.
    if "PETCLI_TEST_TIMING" in os.environ:
        del os.environ["PETCLI_TEST_TIMING"]
    out = _capture_main(["estimate", "window"]).strip()
    decoded = json.loads(out)
    assert decoded["method"] == "placeholder_upper_bound", decoded
    assert isinstance(decoded["estimate_window_seconds"], (int, float)), decoded
    # Default regime is the production-placeholder 24h.
    assert decoded["estimate_window_seconds"] == 86400.0, decoded

    # Test-deployment regime gives the 30s upper bound (§10).
    os.environ["PETCLI_TEST_TIMING"] = "1"
    out = _capture_main(["estimate", "window"]).strip()
    decoded = json.loads(out)
    assert decoded["estimate_window_seconds"] == 30.0, decoded
    del os.environ["PETCLI_TEST_TIMING"]

    # Wire up an in-process echo HTTP server and exercise each
    # arbiter-bound path. The server returns the request body
    # verbatim so we can assert on what the petcli wrote on the
    # wire AND on what it printed back.
    captured_requests = []

    class _Echo(BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            captured_requests.append(json.loads(raw.decode("utf-8")))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = HTTPServer(("127.0.0.1", 0), _Echo)
    bind_port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        common = ["--host", "127.0.0.1", "--port", str(bind_port), "--timeout-s", "5"]

        out = _capture_main(
            ["submit", "send-bitcoin", "--to-token", "tok_X", "--amount-sats", "1000"]
            + common
        ).strip()
        decoded = json.loads(out)
        # petcli stamps the local estimate annotation on submit
        # responses; the rest is whatever the (echo) arbiter
        # returned. The CLI flag is --to-token for operator brevity,
        # but the wire field is `recipient_token` per §4.7 / gateway
        # (petcli renames at the wire boundary in _do_submit_*).
        assert decoded["op"] == "send_bitcoin", decoded
        assert decoded["recipient_token"] == "tok_X", decoded
        assert decoded["amount_sats"] == 1000, decoded
        assert "_petcli_estimate_window_s" in decoded, decoded
        assert captured_requests[-1] == {
            "op": "send_bitcoin",
            "recipient_token": "tok_X",
            "amount_sats": 1000,
        }, captured_requests[-1]

        # Lightning send now lives under `advanced`; the wire op is
        # still send_lightning (only the command path moved).
        out = _capture_main(
            [
                "advanced",
                "send-lightning",
                "--to-token",
                "tok_Y",
                "--amount-msats",
                "12345",
            ]
            + common
        ).strip()
        decoded = json.loads(out)
        assert decoded["op"] == "send_lightning", decoded
        assert decoded["amount_msats"] == 12345, decoded
        assert "_petcli_estimate_window_s" in decoded, decoded

        # eCash fund/defund are arbiter-mediated writes: wire ops
        # fund_ecash / defund_ecash, estimate annotation stamped like
        # every other submit. fund carries only the amount (no
        # recipient token - the destination is structurally the
        # arbiter's pinned mint); defund carries the serialized token.
        out = _capture_main(
            ["advanced", "ecash", "fund", "--amount-sats", "5000"] + common
        ).strip()
        decoded = json.loads(out)
        assert decoded["op"] == "fund_ecash", decoded
        assert decoded["amount_sats"] == 5000, decoded
        assert "_petcli_estimate_window_s" in decoded, decoded
        assert captured_requests[-1] == {
            "op": "fund_ecash",
            "amount_sats": 5000,
        }, captured_requests[-1]

        out = _capture_main(
            ["advanced", "ecash", "defund", "--token", "cashuBsmokevector"]
            + common
        ).strip()
        decoded = json.loads(out)
        assert decoded["op"] == "defund_ecash", decoded
        assert decoded["token"] == "cashuBsmokevector", decoded
        assert "_petcli_estimate_window_s" in decoded, decoded

        out = _capture_main(["query", "balance"] + common).strip()
        decoded = json.loads(out)
        assert decoded == {"op": "query_balance"}, decoded

        # Channels query now lives under `advanced`; wire op unchanged.
        out = _capture_main(["advanced", "channels"] + common).strip()
        decoded = json.loads(out)
        assert decoded == {"op": "query_channels"}, decoded

        out = _capture_main(
            ["result", "poll", "--handle", "h_abc"] + common
        ).strip()
        decoded = json.loads(out)
        # Wire op is "poll" (gateway's single-token routing key); the
        # petcli command path is still "result poll".
        assert decoded == {"op": "poll", "handle": "h_abc"}, decoded
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2)

    # Local eCash wallet commands: petcli shells to the cashu CLI
    # (PETCLI_CASHU_BIN) and presents stdout/stderr verbatim under the
    # _petcli_local envelope. A fake binary covers the full argv ->
    # subprocess -> envelope pipeline; the missing-binary path must
    # surface as a structured error, not a traceback.
    import stat
    import tempfile
    from pathlib import Path

    work = Path(tempfile.mkdtemp(prefix="petcli-cashu-smoke-"))
    try:
        fake = work / "cashu"
        fake.write_text(
            """#!/bin/sh
case "$1" in
  balance) printf 'Balance: 2500 sat\\n';;
  send) printf 'cashuBfakesmokevector\\n';;
  receive) printf 'Received 1000 sat\\n';;
  info) printf 'Version: nutshell/fake\\n';;
  *) echo "unknown command: $1" >&2; exit 64;;
esac
"""
        )
        fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
        os.environ["PETCLI_CASHU_BIN"] = str(fake)

        out = _capture_main(["advanced", "ecash", "balance"]).strip()
        decoded = json.loads(out)
        assert decoded == {
            "_petcli_local": True,
            "exit_code": 0,
            "stdout": "Balance: 2500 sat\n",
            "stderr": "",
        }, decoded

        # Args propagate as separate argv entries (no shell): send
        # passes the amount through, receive passes the token.
        out = _capture_main(
            ["advanced", "ecash", "send", "--amount-sats", "500"]
        ).strip()
        decoded = json.loads(out)
        assert decoded["exit_code"] == 0, decoded
        assert decoded["stdout"].strip() == "cashuBfakesmokevector", decoded

        out = _capture_main(
            ["advanced", "ecash", "receive", "--token", "cashuBfakesmokevector"]
        ).strip()
        decoded = json.loads(out)
        assert "Received" in decoded["stdout"], decoded

        # A failing wallet command surfaces its exit code and stderr
        # verbatim; petcli does not interpret.
        os.environ["PETCLI_CASHU_BIN"] = str(fake)
        out = _capture_main(["advanced", "ecash", "info"]).strip()
        decoded = json.loads(out)
        assert decoded["exit_code"] == 0, decoded

        # Missing binary: structured error envelope.
        os.environ["PETCLI_CASHU_BIN"] = "/nonexistent/petcli-cashu"
        out = _capture_main(["advanced", "ecash", "balance"]).strip()
        decoded = json.loads(out)
        assert decoded == {
            "_petcli_local": True,
            "error": "cashu binary not found: /nonexistent/petcli-cashu",
        }, decoded
    finally:
        del os.environ["PETCLI_CASHU_BIN"]
        import shutil

        shutil.rmtree(work, ignore_errors=True)

    print(f"OK: petcli command tree round-trips against echo at port={bind_port}")


if __name__ == "__main__":
    main()
    sys.exit(0)
