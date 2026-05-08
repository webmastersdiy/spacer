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
        "submit": {"send-bitcoin", "send-lightning"},
        "query": {"balance", "channels"},
        "result": {"poll"},
        "estimate": {"window"},
    }


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

    # --help works at every node. Spot-check distinguishing strings
    # from the description so the test fails meaningfully if a
    # description regresses, not just on missing words like "petcli".
    out = _capture_help(parser, ["--help"])
    assert "Spacer petitioner CLI" in out, out
    assert "submit" in out and "query" in out, out

    out = _capture_help(parser, ["submit", "--help"])
    assert "send-bitcoin" in out and "send-lightning" in out, out

    out = _capture_help(parser, ["submit", "send-bitcoin", "--help"])
    assert "to-token" in out and "amount-sats" in out, out

    out = _capture_help(parser, ["query", "--help"])
    assert "balance" in out and "channels" in out, out

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
        # returned.
        assert decoded["op"] == "send_bitcoin", decoded
        assert decoded["to_token"] == "tok_X", decoded
        assert decoded["amount_sats"] == 1000, decoded
        assert "_petcli_estimate_window_s" in decoded, decoded
        assert captured_requests[-1] == {
            "op": "send_bitcoin",
            "to_token": "tok_X",
            "amount_sats": 1000,
        }, captured_requests[-1]

        out = _capture_main(
            [
                "submit",
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

        out = _capture_main(["query", "balance"] + common).strip()
        decoded = json.loads(out)
        assert decoded == {"op": "query_balance"}, decoded

        out = _capture_main(["query", "channels"] + common).strip()
        decoded = json.loads(out)
        assert decoded == {"op": "query_channels"}, decoded

        out = _capture_main(
            ["result", "poll", "--handle", "h_abc"] + common
        ).strip()
        decoded = json.loads(out)
        assert decoded == {"op": "result_poll", "handle": "h_abc"}, decoded
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2)

    print(f"OK: petcli command tree round-trips against echo at port={bind_port}")


if __name__ == "__main__":
    main()
    sys.exit(0)
