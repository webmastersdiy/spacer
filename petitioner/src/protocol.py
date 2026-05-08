"""
Spacer protocol shim.

The single first-class function of the petitioner is to translate AI
requests into spacer-protocol messages and present the arbiter's
responses back. This module is the protocol layer.

Per design-docs/2026-05-05-0948-architecture-overview.md §5.1, §3, §4.1.

Wire format (matches arbiter/src/gateway.py):
- Transport: HTTP POST to http://<host>:<port>/, Content-Type:
  application/json.
- Request body: a JSON object with a string "op" field and any
  op-specific fields. The arbiter's privacy gateway parses strictly;
  any other shape is refused at the boundary.
- Response: HTTP 200 with a JSON object body. Refusals collapse to the
  uniform {"status": "refused"} shape; allowed calls return op-specific
  shape. The petitioner does not interpret the body, only present it.

The petitioner holds no secrets. Connection settings are not secret -
the AI may already know them - so they are exposed via env vars
(PETCLI_HOST, PETCLI_PORT, PETCLI_TIMEOUT_S) and per-call kwargs.
"""
import json
import os
import urllib.error
import urllib.request

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8420
DEFAULT_TIMEOUT_S = 60.0


def submit(op, params=None, host=None, port=None, timeout_s=None):
    """Send one request to the arbiter privacy gateway and return the
    parsed JSON response.

    Transport-level failures (connection refused, timeout, DNS error)
    are surfaced as a structured petitioner-side response with a
    leading-underscore field, so the CLI stays JSON-shaped end-to-end
    even when the arbiter is unreachable. Surfacing rather than
    masking these keeps the AI-visible distinction between arbiter
    refusals (which carry meaning under the privacy model) and
    petitioner-side transport errors (which do not).
    """
    bind_host = host or os.environ.get("PETCLI_HOST", DEFAULT_HOST)
    bind_port = int(
        port if port is not None else os.environ.get("PETCLI_PORT") or DEFAULT_PORT
    )
    timeout = float(
        timeout_s
        if timeout_s is not None
        else os.environ.get("PETCLI_TIMEOUT_S") or DEFAULT_TIMEOUT_S
    )

    body = {"op": op}
    if params:
        body.update(params)
    encoded = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    req = urllib.request.Request(
        f"http://{bind_host}:{bind_port}/",
        data=encoded,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
    except urllib.error.URLError as e:
        return {"_petcli_transport_error": str(e.reason)}
    if not raw:
        return {}
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeDecodeError) as e:
        # The arbiter contract is JSON; a non-JSON body is itself a
        # transport-level anomaly, not an arbiter decision. Surface it
        # the same way as a connection error.
        return {"_petcli_transport_error": f"non-json response: {e}"}


if __name__ == "__main__":
    # Smoke test: spin up an in-process echo HTTP server, verify the
    # request shape (POST, JSON Content-Type, op-bearing body) and the
    # parsed-response round-trip. Also covers the transport-error path
    # by aiming submit() at a guaranteed-closed port.
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    captured = {}

    class _Echo(BaseHTTPRequestHandler):
        # Suppress access-log noise on stderr; we are inside a smoke
        # test and any stray log line creates flaky output diffs.
        def log_message(self, fmt, *args):
            pass

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(length) if length else b""
            captured["method"] = self.command
            captured["content_type"] = self.headers.get("Content-Type")
            captured["body"] = raw
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
        # Empty params -> body is just {"op": "ping"}.
        r = submit("ping", host="127.0.0.1", port=bind_port, timeout_s=5)
        assert captured["method"] == "POST", captured
        assert captured["content_type"] == "application/json", captured
        assert json.loads(captured["body"].decode()) == {"op": "ping"}, captured
        assert r == {"op": "ping"}, r

        # Param-bearing request: arbitrary fields merged into the body.
        r = submit(
            "send_bitcoin",
            params={"to_token": "abc", "amount_sats": 1000},
            host="127.0.0.1",
            port=bind_port,
            timeout_s=5,
        )
        assert r == {
            "op": "send_bitcoin",
            "to_token": "abc",
            "amount_sats": 1000,
        }, r
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2)

    # Transport-error path: send to a port that nothing is listening
    # on. urllib raises URLError; submit() must turn it into a
    # structured petitioner-side response, not propagate.
    # Bind an ephemeral port, capture it, then close so the port is
    # known-free for the duration of the next call. Race with the OS
    # is acceptable in a smoke test.
    probe = HTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler)
    closed_port = probe.server_address[1]
    probe.server_close()
    r = submit("ping", host="127.0.0.1", port=closed_port, timeout_s=2)
    assert "_petcli_transport_error" in r, r

    print(f"OK: protocol shim round-trips at port={bind_port}")
    sys.exit(0)
