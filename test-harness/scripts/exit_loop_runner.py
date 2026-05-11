#!/usr/bin/env python3
"""
End-to-end validation runner for the spacer implementation closed
loop (§10 of design-docs/2026-05-05-0948-architecture-overview.md).

For every variant declared in VARIANTS:
  1. Spin up a fresh arbiter in a daemon thread, isolated to its own
     audit log and state DB and bound to an ephemeral port. Test-mode
     timing windows are enforced via SPACER_TIMING_MODE=test.
  2. Apply preconditions: deposit a result/rejection, anchor the
     result-poll floor, mark a result already-consumed. Preconditions
     run on the arbiter-internal side of the trust boundary so the
     gateway never sees them.
  3. Invoke petcli as a subprocess with the variant's argv and the
     ephemeral port. Capture stdout, stderr, the variant-specific
     audit log, the parsed petcli response, and a placeholder
     infra-events.log under exit-loop/petcli/<command-path>/<variant-name>/.
  4. Tear the arbiter down and apply the variant's expected check to
     the parsed response. A failed check leaves the artifacts in
     place so a non-AI reviewer can confirm what actually executed
     (per §2.1 auditability).

Validations that pass are populated under exit-loop/; validations
that fail leave failure artifacts on disk and the runner exits
non-zero so the §10 iterative cycle can pick them up. Variants whose
underlying code paths are not yet wired (e.g., happy-path send via
the still-unwritten allowlist policy) are absent from the manifest;
their artifact directories therefore stay empty per §10's "an empty
one signals not-yet-validated" convention.

The runner uses an in-thread arbiter rather than a subprocess for
deterministic teardown and direct access to the arbiter-internal
deposit / floor-anchor / consume primitives. That coupling is
acceptable because the runner lives next to the arbiter source in
this repo and rebuilds in lockstep with it.

Stdlib only. No bitcoind / LND infrastructure is exercised through
the gateway dispatch in the current code base (dispatch is a stub
pending sp-77lxs.2's allowlist policy table format), so
infra-events.log records that fact rather than capturing real RPC
traffic.

Per design-docs/2026-05-05-0948-architecture-overview.md §10.
"""
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# Repo layout. test-harness/scripts/exit_loop_runner.py -> ../../ is repo root.
REPO_ROOT = Path(__file__).resolve().parents[2]
ARBITER_SRC = REPO_ROOT / "arbiter" / "src"
PETCLI_BIN = REPO_ROOT / "petitioner" / "bin" / "petcli"
EXIT_LOOP_ROOT = REPO_ROOT / "exit-loop"

# Importing arbiter modules requires arbiter/src on sys.path. Done at
# module-import time so the imports below are visible to type checkers
# and `python -m` invocations land cleanly.
sys.path.insert(0, str(ARBITER_SRC))
import audit  # noqa: E402
import gateway  # noqa: E402
import results  # noqa: E402
import state  # noqa: E402

# registry and timing register their own SQLite schemas at import time
# (their _SCHEMA fragments call state.register_schema). The arbiter
# boot path imports them for that side effect; mirror it here so the
# in-thread arbiter sees the full schema, not just gateway+results.
import registry  # noqa: E402, F401
import timing  # noqa: E402, F401

# Test-mode timing on the arbiter side: SPACER_TIMING_MODE=test
# selects the §10 5-15s windows. The gateway dispatch is currently a
# stub so the timing layer is not actually exercised end-to-end via
# any variant in this manifest, but the env var is set anyway: any
# import-time check that lands later will see the test-mode value
# without a re-run of the runner.
os.environ["SPACER_TIMING_MODE"] = "test"

# Test-deployment estimate regime on the petitioner side (§10): the
# petcli's estimate.py honors this when stamping the local upper-bound
# estimate on submit responses, so submit-* variants see the 30s bound
# rather than the 24h production-placeholder default.
os.environ["PETCLI_TEST_TIMING"] = "1"


# === Fake lncli for the read-only query variants ====================
#
# gateway._dispatch wires query_balance / query_channels through
# arbiter/src/lnd.py, which shells out to `lncli`. The runner stands up
# a fake lncli script (same pattern lnd.py's own smoke test uses) so
# the read-only variants exercise the full gateway -> dispatch -> lnd
# argv-construction -> JSON parse stack without a live lnd. Real-lnd
# coverage will land alongside the test-harness's bitcoind/LND
# fixtures; the §10 exit gate only requires that each variant
# traverse the gateway and produce a verifiable result, which the
# fake covers deterministically.
_LNCLI_FAKE_DIR = Path(tempfile.mkdtemp(prefix="exit-loop-lncli-"))
_LNCLI_FAKE = _LNCLI_FAKE_DIR / "lncli"
_LNCLI_FAKE.write_text(
    """#!/bin/sh
# Fake lncli for the exit-loop runner. Strips the connection flags
# the way arbiter/src/lnd.py prepends them, then dispatches on the
# RPC name. The scenario is selected via $LNCLI_SCENARIO so the same
# fake binary can stand in for different node states (funded vs.
# empty wallet, channels vs. no channels) across variants without
# swapping the binary. Values are deterministic; the runner's
# variant matchers encode the banded form (floor to 10_000 sats)
# directly.
while [ $# -gt 0 ]; do
  case "$1" in
    --rpcserver=*|--tlscertpath=*|--macaroonpath=*|--network=*) shift;;
    *) break;;
  esac
done
scenario="${LNCLI_SCENARIO:-funded}"
case "$1" in
  walletbalance)
    case "$scenario" in
      empty)
        printf '{"total_balance":"0","confirmed_balance":"0","unconfirmed_balance":"0"}'
        ;;
      *)
        printf '{"total_balance":"100000","confirmed_balance":"100000","unconfirmed_balance":"0"}'
        ;;
    esac
    ;;
  channelbalance)
    case "$scenario" in
      no-channels)
        printf '{"local_balance":{"sat":"0","msat":"0"},"remote_balance":{"sat":"0","msat":"0"}}'
        ;;
      *)
        printf '{"local_balance":{"sat":"50000","msat":"50000000"},"remote_balance":{"sat":"30000","msat":"30000000"}}'
        ;;
    esac
    ;;
  *)
    echo "unknown rpc: $1" >&2
    exit 64
    ;;
esac
"""
)
_LNCLI_FAKE.chmod(
    _LNCLI_FAKE.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
)
os.environ["LNCLI_BIN"] = str(_LNCLI_FAKE)
os.environ["LNCLI_TLSCERT"] = str(_LNCLI_FAKE_DIR / "tls.cert")
os.environ["LNCLI_MACAROON"] = str(_LNCLI_FAKE_DIR / "admin.macaroon")
os.environ["LNCLI_RPCSERVER"] = "fake:10009"
os.environ["LNCLI_NETWORK"] = "signet"
os.environ["LNCLI_TIMEOUT_S"] = "5.0"


# === Arbiter lifecycle ==============================================

def _start_arbiter(audit_path, state_path):
    """Configure audit + state to fresh isolated paths and start the
    privacy gateway in a daemon thread on an ephemeral port. Returns
    (server, port, thread). The caller is responsible for tearing the
    server down via _stop_arbiter()."""
    audit.configure(audit_path)
    state.configure(state_path)
    state.migrate()
    server = gateway.make_server(host="127.0.0.1", port=0, latency_target=0.05)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    return server, port, t


def _stop_arbiter(server, thread):
    """Shut the in-thread arbiter down. Bounded join: a hung thread
    means the gateway's serve_forever did not honor shutdown, which
    is a bug worth surfacing rather than waiting on indefinitely."""
    server.shutdown()
    server.server_close()
    thread.join(timeout=2.0)


def _apply_precondition(precondition):
    """Apply one declarative precondition to the running arbiter's
    state. Operations bypass the gateway because they represent
    arbiter-internal setup (timing-layer drainer would do this in
    production) rather than petitioner-visible state.

    Supported ops:
      ("deposit", handle, payload, kind)
        results.deposit(handle, payload, kind=kind). Puts a result
        ("result") or rejection ("rejection") in the registry.
      ("anchor_floor", handle, seconds_ago)
        Inserts a result_poll_floor row with last_poll_at = now -
        seconds_ago. A subsequent poll on the handle within the
        10-min floor window returns "not_yet" without consulting the
        results table, exercising the §4.8 throttle path without
        having to run a prior consuming poll.
      ("consume", handle)
        Marks a deposited result already-consumed. Exercises the
        idempotent-retrieval path without a prior poll.
    """
    op = precondition[0]
    if op == "deposit":
        _, handle, payload, kind = precondition
        results.deposit(handle, payload, kind=kind)
    elif op == "anchor_floor":
        _, handle, seconds_ago = precondition
        anchor = time.time() - float(seconds_ago)
        with state.connect() as conn:
            conn.execute(
                "INSERT INTO result_poll_floor (handle, last_poll_at) "
                "VALUES (?, ?) "
                "ON CONFLICT(handle) DO UPDATE SET last_poll_at = excluded.last_poll_at",
                (handle, anchor),
            )
    elif op == "consume":
        _, handle = precondition
        with state.connect() as conn:
            conn.execute(
                "UPDATE results SET consumed = 1, consumed_at = ? WHERE handle = ?",
                (time.time(), handle),
            )
    else:
        raise ValueError(f"unknown precondition op {op!r}")


# === Variant manifest ===============================================
#
# Each variant declares:
#   path:            tuple of path components under exit-loop/petcli/
#                    forming the artifact directory.
#   petcli_args:     argv passed to petitioner/bin/petcli (without the
#                    --host/--port flags; those are appended for
#                    arbiter-bound variants).
#   uses_arbiter:    True if the variant talks to the gateway over
#                    HTTP. False for local-only commands (estimate
#                    window, §5.2).
#   preconditions:   list of declarative ops applied before the
#                    petcli run; see _apply_precondition().
#   expected:        callable(parsed_response_dict) -> bool. The
#                    runner records the variant as "passed" iff this
#                    returns True. Any exception in the callable also
#                    counts as a failure.
#   description:     human-readable note on what the variant
#                    exercises and which audit events fire.
#
# Variants in this list are the ones that exercise distinct code
# paths reachable in the current code base. Read-only query_balance
# and query_channels now traverse the partial allowlist
# (_ALLOWED_READ_OPS in gateway.py) and dispatch through
# arbiter/src/lnd.py against a fake lncli the runner installs at
# module-import time, producing deterministic banded responses.
# Happy-path send-bitcoin / send-lightning and registry-token
# rejection paths (unknown / expired / used / bad checksum) remain
# not-yet-validatable end-to-end: the allowlist still refuses every
# state-changing call until sp-77lxs.2 lands the full policy table
# format. Those variants will be added once their code paths are
# reachable.
VARIANTS = [
    # --- estimate window: local-only, no arbiter ---
    {
        "path": ("estimate", "window", "default"),
        "petcli_args": ["estimate", "window"],
        "uses_arbiter": False,
        "preconditions": [],
        "expected": lambda r: (
            r.get("method") == "placeholder_upper_bound"
            and r.get("estimate_window_seconds") == 30.0
            and "note" in r
        ),
        "description": (
            "petcli estimate window in test-deployment regime "
            "(PETCLI_TEST_TIMING=1). Returns the 30s upper bound for "
            "action+result delay. Local-only per §5.2 - never touches "
            "the arbiter."
        ),
    },
    # --- result poll: every distinct path through results.poll() ---
    {
        "path": ("result", "poll", "never-existed"),
        "petcli_args": ["result", "poll", "--handle", "h_never_existed"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {"status": "not_yet"},
        "description": (
            "Poll a handle that has no entry in the registry. The "
            "wire response is the §4.8 binary-state 'not_yet' "
            "envelope, indistinguishable from already-consumed. "
            "Audit logs result_poll_unknown."
        ),
    },
    {
        "path": ("result", "poll", "result-deposited"),
        "petcli_args": ["result", "poll", "--handle", "h_result"],
        "uses_arbiter": True,
        "preconditions": [
            ("deposit", "h_result",
             {"txid": "deadbeef01", "confirmations": 1}, "result"),
        ],
        "expected": lambda r: r == {
            "status": "result",
            "result": {"txid": "deadbeef01", "confirmations": 1},
        },
        "description": (
            "Deposit a result, then petcli polls and retrieves it. "
            "The deposited payload is returned verbatim. Audit logs "
            "result_deposit (precondition) and result_poll_ok."
        ),
    },
    {
        "path": ("result", "poll", "rejection-deposited"),
        "petcli_args": ["result", "poll", "--handle", "h_rejection"],
        "uses_arbiter": True,
        "preconditions": [
            ("deposit", "h_rejection",
             {"status": "destination_unavailable"}, "rejection"),
        ],
        "expected": lambda r: r == {
            "status": "result",
            "result": {"status": "destination_unavailable"},
        },
        "description": (
            "Deposit a §4.7-style rejection (kind='rejection'). "
            "The petitioner-visible wire response is still 'result'; "
            "the deposited payload differentiates - here, the §4.7 "
            "'destination_unavailable' marker. Audit logs "
            "result_deposit and result_poll_ok."
        ),
    },
    {
        "path": ("result", "poll", "floor-throttle"),
        "petcli_args": ["result", "poll", "--handle", "h_throttle"],
        "uses_arbiter": True,
        "preconditions": [
            ("deposit", "h_throttle", {"x": 1}, "result"),
            # Anchor the floor 60s ago: well inside §4.8's 10-min
            # window, so the next poll throttles without consulting
            # the results table.
            ("anchor_floor", "h_throttle", 60),
        ],
        "expected": lambda r: r == {"status": "not_yet"},
        "description": (
            "Poll throttled by the §4.8 10-minute floor. The result "
            "is present but the floor anchors only 60s ago; the "
            "gateway returns 'not_yet' without reaching the results "
            "table. Audit logs result_poll_throttled."
        ),
    },
    {
        "path": ("result", "poll", "already-consumed"),
        "petcli_args": ["result", "poll", "--handle", "h_consumed"],
        "uses_arbiter": True,
        "preconditions": [
            ("deposit", "h_consumed", {"x": 1}, "result"),
            ("consume", "h_consumed"),
        ],
        "expected": lambda r: r == {"status": "not_yet"},
        "description": (
            "Poll a handle whose entry was already retrieved. The "
            "§4.8 idempotent-retrieval invariant: subsequent polls "
            "return 'not_yet' indistinguishably from never-existed. "
            "Audit logs result_poll_already_consumed."
        ),
    },
    {
        "path": ("result", "poll", "empty-handle"),
        "petcli_args": ["result", "poll", "--handle", ""],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {"status": "not_yet"},
        "description": (
            "petcli sends a blank handle. The gateway's poll fast-"
            "path treats a non-string-or-empty handle as the same "
            "uniform 'not_yet' wire response, audit-logged as "
            "decision_poll_bad_input so the operator can see a "
            "malformed petitioner request without it leaking on the "
            "wire."
        ),
    },
    # --- submit / query: currently allowlist-refused. Until
    # sp-77lxs.2 lands the policy table format, every state-changing
    # or non-poll-read call refuses uniformly at the gateway. The
    # variant exercises that default-refuse path, which is the
    # current end-to-end behavior for all four leaves.
    {
        "path": ("submit", "send-bitcoin", "refused-by-default"),
        "petcli_args": [
            "submit", "send-bitcoin",
            "--to-token", "ABCDEF",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "description": (
            "Allowlist defaults to refusing every state-changing "
            "call until sp-77lxs.2 lands the policy table format. "
            "petcli stamps the §5.2 local 30s estimate alongside "
            "the refusal. Audit logs decision_defer_hitl."
        ),
    },
    {
        "path": ("submit", "send-lightning", "refused-by-default"),
        "petcli_args": [
            "submit", "send-lightning",
            "--to-token", "ABCDEF",
            "--amount-msats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "description": (
            "Allowlist refuses Lightning sends by default for the "
            "same reason as Bitcoin sends. Audit logs "
            "decision_defer_hitl."
        ),
    },
    {
        "path": ("query", "balance", "allowlisted"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 100000,
        },
        "description": (
            "Read-only balance query traverses the partial allowlist "
            "(query_balance is in _ALLOWED_READ_OPS), dispatch reads "
            "lnd.walletbalance() via the fake lncli (total_balance=100000),"
            " and the gateway floor-bands the value to 10_000-sat "
            "resolution. The fake's value is already a band multiple "
            "so the banded result matches verbatim. Audit logs "
            "request_received and decision_allow."
        ),
    },
    {
        "path": ("query", "channels", "allowlisted"),
        "petcli_args": ["query", "channels"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 80000,
        },
        "description": (
            "Channels query traverses the partial allowlist, dispatch "
            "reads lnd.channelbalance() via the fake lncli "
            "(local=50000, remote=30000), and the gateway returns "
            "the aggregate capacity (80000) floor-banded to 10_000 sat. "
            "Per-channel detail is suppressed (aggregate-by-default, "
            "§4.3). Audit logs request_received and decision_allow."
        ),
    },
    {
        "path": ("query", "balance", "empty-wallet"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "lncli_scenario": "empty",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 0,
        },
        "description": (
            "Same dispatch path as the funded variant, but the fake "
            "lncli reports total_balance=0 under LNCLI_SCENARIO=empty. "
            "The gateway's banded response is balance_sats=0, which is "
            "petitioner-visibly indistinguishable from any wallet "
            "balance below the 10_000-sat band. Confirms the dispatch "
            "and banding logic handle the zero-balance edge without "
            "leaking the precise (zero) figure as a different status."
        ),
    },
    {
        "path": ("query", "channels", "no-channels"),
        "petcli_args": ["query", "channels"],
        "uses_arbiter": True,
        "lncli_scenario": "no-channels",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 0,
        },
        "description": (
            "Channels query when lncli reports zero local + zero "
            "remote capacity (LNCLI_SCENARIO=no-channels). The gateway "
            "returns capacity_sats=0; same status as a funded pool "
            "below the 10_000-sat band, so the wire response does not "
            "distinguish 'no channels' from 'sub-band channels'."
        ),
    },
]


# === Per-variant runner =============================================

def _run_variant(variant):
    """Execute one variant. Returns (passed, error_message)."""
    artifact_dir = EXIT_LOOP_ROOT / "petcli" / Path(*variant["path"])
    artifact_dir.mkdir(parents=True, exist_ok=True)

    audit_dir = Path(tempfile.mkdtemp(prefix="exit-loop-audit-"))
    state_dir = Path(tempfile.mkdtemp(prefix="exit-loop-state-"))
    audit_path = audit_dir / "audit.log"
    state_path = state_dir / "state.db"

    # Per-variant fake-lncli scenario. The fake binary reads
    # $LNCLI_SCENARIO to pick which canned reply to print; the runner
    # sets it to the variant's "lncli_scenario" (default "funded")
    # before the in-thread arbiter dispatches to lnd.py, and restores
    # the prior value after the variant runs so a later variant's
    # env is not contaminated.
    saved_lncli_scenario = os.environ.get("LNCLI_SCENARIO")
    os.environ["LNCLI_SCENARIO"] = variant.get("lncli_scenario", "funded")

    server = thread = port = None
    try:
        if variant.get("uses_arbiter", True):
            server, port, thread = _start_arbiter(audit_path, state_path)
            for pc in variant.get("preconditions", []):
                _apply_precondition(pc)

        cmd = [str(PETCLI_BIN)] + list(variant["petcli_args"])
        if variant.get("uses_arbiter", True):
            cmd += [
                "--host", "127.0.0.1",
                "--port", str(port),
                "--timeout-s", "10",
            ]

        # Subprocess inherits SPACER_TIMING_MODE / PETCLI_TEST_TIMING
        # from the runner's environment, set at module import. petcli
        # does not need SPACER_TIMING_MODE itself (that is arbiter-side)
        # but the arbiter thread inherits the import-time setting via
        # os.environ.
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        (artifact_dir / "stdout.log").write_text(proc.stdout)
        (artifact_dir / "stderr.log").write_text(proc.stderr)

        # Tear the arbiter down BEFORE reading the audit log so the
        # gateway_stop event is included verbatim. If the arbiter
        # never started (uses_arbiter=False), audit_path may not exist;
        # write an empty file in that case so every variant directory
        # has the same five files.
        if server is not None:
            _stop_arbiter(server, thread)
            server = thread = None

        if audit_path.exists():
            (artifact_dir / "arbiter-events.log").write_text(
                audit_path.read_text()
            )
        else:
            (artifact_dir / "arbiter-events.log").write_text("")

        # Bitcoind / LND infrastructure events. Variants that dispatch
        # through the read-only allowlist exercise lnd.py against a
        # fake lncli installed at module-import time; everything else
        # remains stubbed. The runner does not capture per-variant
        # lncli stdout (the fake's reply lands in the petcli response
        # and is therefore already in result.json); the log records
        # which mode this variant ran under so a non-AI reviewer can
        # tell at a glance.
        if variant.get("uses_arbiter", True):
            infra_note = (
                "# Read-only variants dispatch through arbiter/src/lnd.py "
                "to the fake lncli at $LNCLI_BIN; state-changing variants "
                "remain refused at the allowlist and never reach the "
                "lnd module. No live bitcoind / LND traffic for any "
                "variant in the current manifest.\n"
            )
        else:
            infra_note = (
                "# Local-only variant: never reaches the arbiter, so no "
                "bitcoind / LND interaction is possible.\n"
            )
        (artifact_dir / "infra-events.log").write_text(infra_note)

        # The petcli prints one JSON object on stdout (compact, key-
        # sorted). Parse for the expected check and re-emit pretty-
        # printed under result.json so a reviewer can read the
        # outcome without unwrapping the compact form.
        stdout_stripped = proc.stdout.strip()
        try:
            parsed = json.loads(stdout_stripped) if stdout_stripped else None
            parse_error = None
        except json.JSONDecodeError as e:
            parsed = None
            parse_error = str(e)

        if parsed is None:
            result_doc = {
                "_runner_error": "petcli stdout was not a single JSON object",
                "raw_stdout": proc.stdout,
                "parse_error": parse_error,
                "exit_code": proc.returncode,
            }
        else:
            result_doc = parsed

        # Indent for human review; sort keys so re-runs diff cleanly.
        # Default separators (with space after colon) are more readable
        # than the compact form petcli emits on stdout.
        (artifact_dir / "result.json").write_text(
            json.dumps(result_doc, sort_keys=True, indent=2) + "\n"
        )

        if parsed is None:
            return (False, f"petcli output not JSON: {parse_error}; "
                           f"raw={proc.stdout!r}")
        try:
            ok = bool(variant["expected"](parsed))
        except Exception as e:
            return (False, f"expected raised: {e}; result={parsed}")
        if not ok:
            return (False, f"expected returned False; result={parsed}")
        return (True, None)
    finally:
        if server is not None:
            _stop_arbiter(server, thread)
        # Restore the prior LNCLI_SCENARIO so cross-variant env state
        # is not sticky. Setting a None back means "delete the var"
        # rather than setting it to the literal string "None".
        if saved_lncli_scenario is None:
            os.environ.pop("LNCLI_SCENARIO", None)
        else:
            os.environ["LNCLI_SCENARIO"] = saved_lncli_scenario
        # Best-effort cleanup of the per-variant tempdirs.
        for d in (audit_dir, state_dir):
            try:
                shutil.rmtree(d)
            except OSError:
                pass


# === Driver =========================================================

def main(argv=None):
    """Run every variant, populate exit-loop/petcli/, print a per-
    variant pass/fail line and a summary.

    The runner clears exit-loop/petcli/ at the start so the on-disk
    artifact set always reflects the current manifest run. exit-loop/
    README.md is left in place (documentation, not a run artifact).

    Exit code is 0 only when every variant passes; the §10 closed
    loop terminates only on that condition.
    """
    argv = sys.argv[1:] if argv is None else argv
    if argv:
        # Unknown flags fail loudly. The runner has no options today;
        # if a future caller passes one we want to surface that rather
        # than silently ignore.
        print(f"unknown arguments: {argv}", file=sys.stderr)
        return 2

    petcli_root = EXIT_LOOP_ROOT / "petcli"
    if petcli_root.exists():
        shutil.rmtree(petcli_root)
    petcli_root.mkdir(parents=True, exist_ok=True)

    passed_paths = []
    failed = []
    for variant in VARIANTS:
        path_str = "/".join(variant["path"])
        ok, err = _run_variant(variant)
        status = "PASS" if ok else "FAIL"
        print(f"{status}  {path_str}")
        if ok:
            passed_paths.append(path_str)
        else:
            failed.append((path_str, err))
            # Print error on its own line for readability.
            print(f"      -> {err}")

    print()
    print(f"--- exit-loop summary ---")
    print(f"passed: {len(passed_paths)}/{len(VARIANTS)}")
    if failed:
        print(f"failed: {len(failed)}")
        for path_str, err in failed:
            print(f"  - {path_str}: {err}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
