"""
Operator console for the recipient address registry (§4.7).

Run from the directly-attached arbiter console only - the keyboard
physically connected to the arbiter host. The petitioner has no
path to this command. Reads the real address from the operator's
keyboard, validates via registry.add(), and prints the local id and
public token to the console for the operator to write down or read
aloud across to the AI side.

Per §4.7: "The operator runs a registry-add command at the console
and types the real address. ... On a successful add the arbiter
prints the entry's local-only numeric ID and the public-facing
token back to the console."

Two subcommands:
- add:  issue a fresh (id, token) for an operator-typed address.
- list: enumerate every registry entry, with the namespace-
        utilization summary at the end.

Stdlib only.
"""
import argparse
import sys
import time

import audit
import registry
import state


def cmd_add(args):
    """Read the address from argv or prompt, validate, and print the
    issued (id, token). On invalid input print the refusal cause to
    stderr and exit non-zero so the operator sees it immediately."""
    if args.address is None:
        # Prompt-mode: read one line from the operator's keyboard.
        # No clipboard between the console and the AI side, so the
        # operator types the address here. Trim outer whitespace; do
        # not otherwise transform.
        sys.stdout.write("address> ")
        sys.stdout.flush()
        addr = sys.stdin.readline().rstrip("\n").strip()
    else:
        addr = args.address.strip()
    try:
        rid, token = registry.add(addr, expires_in_days=args.expires_in_days)
    except registry.RegistryError as e:
        sys.stderr.write(f"refused: {e}\n")
        return 1
    sys.stdout.write(f"id={rid} token={token}\n")
    return 0


def cmd_list(args):
    """Print every registry entry in id order, then the namespace-
    utilization summary. Operator-facing only; never crosses the
    privacy gateway. Real addresses ARE included for operator
    triage."""
    rows = registry.list_entries()
    if not rows:
        sys.stdout.write("(empty)\n")
    for rid, token, fmt, real, created_at, expires_at, used, consumed_by in rows:
        sys.stdout.write(
            f"id={rid} token={token} format={fmt} "
            f"created={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(created_at))} "
            f"expires={time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(expires_at))} "
            f"used={'yes' if used else 'no'} "
            f"consumed_by={consumed_by or '-'} "
            f"real={real}\n"
        )
    total, ns, frac = registry.utilization()
    pct = frac * 100.0
    marker = " WARN" if frac >= registry.WARN_UTILIZATION else ""
    sys.stdout.write(f"# utilization: {total}/{ns} ({pct:.4f}%){marker}\n")
    return 0


def main(argv=None):
    """argparse-based dispatcher. Configures audit/state from the
    process environment (or defaults under ~/spacer/arbiter/data/)
    and applies any registered schema fragments. The arbiter daemon
    and this CLI share the same SQLite database (WAL mode handles
    concurrent access) and the same audit log (O_APPEND + fsync per
    line is concurrency-safe within PIPE_BUF)."""
    audit.configure()
    state.configure()
    state.migrate()
    p = argparse.ArgumentParser(
        prog="registry",
        description="Operator console for the recipient address registry.",
    )
    sub = p.add_subparsers(dest="cmd", required=True)
    p_add = sub.add_parser("add", help="add a new recipient address")
    p_add.add_argument(
        "address",
        nargs="?",
        default=None,
        help="address to add (prompts on stdin if omitted)",
    )
    p_add.add_argument(
        "--expires-in-days",
        type=int,
        default=registry.DEFAULT_EXPIRY_DAYS,
        help=(
            f"days until the entry expires "
            f"(default: {registry.DEFAULT_EXPIRY_DAYS})"
        ),
    )
    p_add.set_defaults(handler=cmd_add)
    p_list = sub.add_parser("list", help="list registry entries")
    p_list.set_defaults(handler=cmd_list)
    args = p.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    # Smoke test: invoke add via argv (non-prompt mode) and list via
    # the same in-process state, verify both paths against a temp DB.
    import json
    import os
    import tempfile
    from pathlib import Path

    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-registry-cli-smoke.log"
    tmp_state = Path(tempfile.gettempdir()) / "arbiter-registry-cli-smoke.db"
    for p in (tmp_audit, tmp_state):
        if p.exists():
            p.unlink()
    os.environ["AUDIT_LOG_PATH"] = str(tmp_audit)
    os.environ["STATE_DB_PATH"] = str(tmp_state)

    import io

    # Capture stdout/stderr around each call so we can assert the
    # printed (id, token) shape without a real TTY.
    saved_out, saved_err = sys.stdout, sys.stderr

    def run(argv):
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()
        try:
            rc = main(argv)
            return rc, sys.stdout.getvalue(), sys.stderr.getvalue()
        finally:
            sys.stdout, sys.stderr = saved_out, saved_err

    # add a known-good testnet bech32 address
    addr = "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"
    rc, out, err = run(["add", addr])
    assert rc == 0, (rc, out, err)
    # Output: "id=<int> token=<6-char token>\n"
    parts = dict(p.split("=") for p in out.strip().split())
    assert "id" in parts and "token" in parts, out
    rid = int(parts["id"])
    token = parts["token"]
    assert len(token) == registry.TOKEN_TOTAL_LEN, token
    assert registry.validate_token_format(token), token

    # list shows the row plus the utilization summary
    rc, out, err = run(["list"])
    assert rc == 0, (rc, out, err)
    assert f"id={rid}" in out and f"token={token}" in out, out
    assert "utilization:" in out, out

    # Refusal: invalid address exits non-zero with a "refused:" prefix.
    rc, out, err = run(["add", "not_a_btc_address"])
    assert rc == 1, (rc, out, err)
    assert err.startswith("refused:"), err

    # Mainnet refused (no-mainnet hard rule).
    rc, out, err = run(
        ["add", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"]
    )
    assert rc == 1, (rc, out, err)
    assert err.startswith("refused:"), err

    # --expires-in-days=0 still adds (already-expired entry); the
    # operator might want a one-shot stub for testing.
    rc, out, err = run(["add", addr, "--expires-in-days=0"])
    assert rc == 0, (rc, out, err)

    # Audit log captured both add and refusal events.
    with open(tmp_audit) as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    assert "registry_add" in events, events
    assert "registry_add_invalid" in events, events

    print(f"OK: registry CLI round-trips at state={tmp_state}")
    sys.exit(0)
