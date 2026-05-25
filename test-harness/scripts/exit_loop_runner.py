#!/usr/bin/env python3
"""
End-to-end validation runner for the spacer implementation closed
loop (§10 of design-docs/origin/05--2026-05-05-0948-architecture-overview.md).

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
the still-unwritten timing-layer executor) are absent from the
manifest; their artifact directories therefore stay empty per §10's
"an empty one signals not-yet-validated" convention.

The runner uses an in-thread arbiter rather than a subprocess for
deterministic teardown and direct access to the arbiter-internal
deposit / floor-anchor / consume primitives. That coupling is
acceptable because the runner lives next to the arbiter source in
this repo and rebuilds in lockstep with it.

Stdlib only. No bitcoind / LND infrastructure is exercised through
the gateway dispatch in the current code base for state-changing
ops (no executor wires the timing layer to bitcoin.py / lnd.py yet),
so infra-events.log records that fact rather than capturing real
RPC traffic. Read-only ops exercise the fake lncli installed below.

Per design-docs/origin/05--2026-05-05-0948-architecture-overview.md §10.
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

# registry, timing, and scale register their own SQLite schemas at
# import time (their _SCHEMA fragments call state.register_schema). The
# arbiter boot path imports them for that side effect; mirror it here
# so the in-thread arbiter sees the full schema, not just
# gateway+results.
import registry  # noqa: E402
import scale  # noqa: E402
import standing_approvals  # noqa: E402
import timing  # noqa: E402, F401

# Test-mode timing on the arbiter side: SPACER_TIMING_MODE=test
# selects the §10 5-15s windows. The gateway dispatch is currently a
# stub so the timing layer is not actually exercised end-to-end via
# any variant in this manifest, but the env var is set anyway: any
# import-time check that lands later will see the test-mode value
# without a re-run of the runner.
os.environ["SPACER_TIMING_MODE"] = "test"

# Scale cloak in test mode: deterministic per-tier scales (0.1^tier)
# and 5-15s transition windows. Production scale-cloak (multi-day
# randomized delays, randomized within-tier scales) is gated behind a
# NotImplementedError in scale.py, so without this opt-in every
# read-only query variant would refuse uniformly at dispatch time.
os.environ["SPACER_SCALE_MODE"] = "test"

# Test-deployment estimate regime on the petitioner side (§10): the
# petcli's estimate.py honors this when stamping the local upper-bound
# estimate on submit responses, so submit-* variants see the 30s bound
# rather than the 24h production-placeholder default.
os.environ["PETCLI_TEST_TIMING"] = "1"

# Standing-approvals config path (GLOSSARY 'Standing approvals' / §6).
# One temp file per runner process; each variant clears it before
# preconditions run, so a variant without seed_standing_approvals
# starts with the default-pause empty config (= HITL every write).
# The seed_standing_approvals precondition writes the file before
# the petcli call so the gateway's matches() call sees the rules.
_STANDING_APPROVALS_DIR = Path(tempfile.mkdtemp(prefix="exit-loop-standing-"))
_STANDING_APPROVALS_PATH = _STANDING_APPROVALS_DIR / "standing_approvals.yaml"
os.environ["SPACER_STANDING_APPROVALS_PATH"] = str(_STANDING_APPROVALS_PATH)

# Pre-computed valid recipient token + a real testnet address. Used
# by the seed_registry precondition so the new send-bitcoin /
# send-lightning variants can exercise the post-registry path
# (registry resolves -> standing-approvals gate fires). Generated
# once at module load so the petcli_args and the precondition agree
# on the same token string. The address is BIP-173's testnet P2WPKH
# reference example; format detection in registry.py classifies it
# as bech32 testnet.
_VALID_TOKEN = registry.generate_token()
_VALID_REAL = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"
_VALID_FMT = "bech32"


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
# empty wallet, channels vs. no channels, cloak-tier 1 vs 2) across
# variants without swapping the binary. Values are deterministic;
# the runner's variant matchers encode the cloaked-and-presented
# form (scale.present(real) at the active tier) directly.
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
      tier-1)
        # 150_000 sat -> natural cloak tier T1.
        printf '{"total_balance":"150000","confirmed_balance":"150000","unconfirmed_balance":"0"}'
        ;;
      tier-2)
        # 1_500_000 sat -> natural cloak tier T2.
        printf '{"total_balance":"1500000","confirmed_balance":"1500000","unconfirmed_balance":"0"}'
        ;;
      *)
        # Default funded scenario: 50_000 sat is clearly inside T0
        # so the cloak is a no-op (scale 1.0) and the wire response
        # is the raw figure - the simplest legible reference variant.
        printf '{"total_balance":"50000","confirmed_balance":"50000","unconfirmed_balance":"0"}'
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
      ("seed_scale_state", active_tier, active_scale, target_tier,
                           target_scale, due_at_delta_s)
        Direct write of the singleton scale_state row via
        scale.seed_for_test(). due_at_delta_s is interpreted relative
        to now (positive = future, negative = past, None = no pending
        transition); the runner converts it to an absolute epoch
        timestamp before handing to scale. Lets cloaked-tier variants
        exercise the pending-transition and applied-transition paths
        without driving a real wall-clock delay.
      ("seed_registry", token, real, fmt)
        Direct INSERT of a (token, real, format) row into the
        recipient_addresses table. Bypasses registry.add()'s
        operator-side validation so a variant can stage a known-good
        token without going through generate_token/checksum/insert.
        Used by the send-bitcoin / send-lightning variants that
        exercise the post-registry path (the registry resolves; the
        standing-approvals gate decides). created_at = now,
        expires_at = now + 7d, used = 0.
      ("seed_standing_approvals", [rule_dicts])
        Renders the rule list as YAML and writes it to the standing-
        approvals config path. Lets a variant pre-stage a matching
        rule so the gateway's standing_approvals.matches() returns
        True and dispatch fires (or omit and rely on the runner's
        per-variant clear for the default-pause path).
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
    elif op == "seed_scale_state":
        (_, active_tier, active_scale, target_tier, target_scale,
         due_at_delta_s) = precondition
        due_at = (
            None if due_at_delta_s is None
            else time.time() + float(due_at_delta_s)
        )
        scale.seed_for_test(
            active_tier, active_scale, target_tier, target_scale, due_at,
        )
    elif op == "seed_registry":
        _, token, real, fmt = precondition
        now = time.time()
        expires = now + 7 * 86400.0
        with state.connect() as conn:
            conn.execute(
                "INSERT INTO recipient_addresses "
                "(token, real, format, created_at, expires_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (token, real, fmt, now, expires),
            )
    elif op == "seed_standing_approvals":
        _, rules = precondition
        _STANDING_APPROVALS_PATH.write_text(
            standing_approvals.render_yaml(rules)
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
# and query_channels are known-read ops in gateway._KNOWN_READ_OPS
# and dispatch through arbiter/src/lnd.py against a fake lncli the
# runner installs at module-import time, producing deterministic
# cloak-presented responses. State-changing send_bitcoin /
# send_lightning are known-write ops; the runner currently exercises
# only the registry-miss refusal path against an unknown test token
# (decision_refuse_registry on the audit side, uniform refusal on
# the wire). Happy-path sends and the other registry-rejection
# subcases (expired / used / bad checksum / anomalous) become
# reachable once the timing-layer executor lands and the runner
# can seed registry entries to exercise each subcase distinctly.
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
    # --- submit / query: state-changing ops resolve through the
    # recipient address registry (§4.7). Sending with a token that
    # is not in the registry (here, the made-up 'ABCDEF') refuses
    # uniformly at the registry gate. The wire shape is the standard
    # refusal body; the audit log carries decision_refuse_registry
    # so the operator can see *which* token failed and why. These
    # variants exercise that miss path; happy-path sends become
    # reachable once registry seeding + the timing-layer executor land.
    {
        "path": ("submit", "send-bitcoin", "refused-unknown-token"),
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
            "send_bitcoin is a known write op; the gateway calls "
            "registry.lookup() on recipient_token=ABCDEF, which "
            "fails (bad checksum or unknown - either way non-`ok`), "
            "and the gateway refuses uniformly. petcli stamps the "
            "§5.2 local 30s estimate alongside the refusal. Audit "
            "logs decision_refuse_registry."
        ),
    },
    {
        "path": ("submit", "send-lightning", "refused-unknown-token"),
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
            "Same registry-miss path as send-bitcoin/refused-unknown-"
            "token, but for the Lightning send op. Audit logs "
            "decision_refuse_registry."
        ),
    },
    # --- submit: post-registry, standing-approvals gate. The token
    # resolves through the registry; whether dispatch fires depends
    # on the operator's standing-approvals config (GLOSSARY 'Standing
    # approvals', §6). The parked-* variants exercise the default-
    # pause path (empty config = HITL every write); the allowed-by-*
    # variants stage a matching rule and let the call through to
    # dispatch (which currently returns the not_implemented marker
    # because the write executor is still a stub). These two
    # variants together prove the standing-approvals gate fires
    # AFTER the registry and is distinct from the unknown-op HITL.
    {
        "path": ("submit", "send-bitcoin", "parked-no-standing-approval"),
        "petcli_args": [
            "submit", "send-bitcoin",
            "--to-token", _VALID_TOKEN,
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            # No seed_standing_approvals: default-pause path.
        ],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "description": (
            "send_bitcoin with a valid (registry-resolved) recipient "
            "token but NO matching standing-approval rule. The "
            "registry resolves; the standing-approvals check fails "
            "(default-pause = empty config); the gateway HITL-parks "
            "and refuses uniformly. arbiter-events.log must contain "
            "decision_defer_hitl with reason no_standing_approval, "
            "distinct from the refused-unknown-token variants' "
            "decision_refuse_registry."
        ),
    },
    {
        "path": ("submit", "send-bitcoin", "allowed-by-standing-approval"),
        "petcli_args": [
            "submit", "send-bitcoin",
            "--to-token", _VALID_TOKEN,
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            ("seed_standing_approvals", [
                {"op": "send_bitcoin",
                 "destination": _VALID_TOKEN,
                 "max_amount_sats": 50000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": lambda r: r == {
            "status": "not_implemented",
            "op": "send_bitcoin",
            "_petcli_estimate_window_s": 30.0,
        },
        "description": (
            "send_bitcoin where the registry token resolves AND a "
            "standing-approval rule matches (op + destination + "
            "amount under max). The gate passes; dispatch fires; "
            "the write executor is still a stub so dispatch returns "
            "the not_implemented marker. The variant proves the gate "
            "let the call through. arbiter-events.log must contain "
            "standing_approval_match and decision_allow."
        ),
    },
    {
        "path": ("submit", "send-lightning", "parked-no-standing-approval"),
        "petcli_args": [
            "submit", "send-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
        ],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "description": (
            "Same default-pause path as send-bitcoin/parked-no-"
            "standing-approval but for the Lightning send op. "
            "amount_msats=1_000_000 (= 1000 sats post-ceiling) is "
            "irrelevant here because no rule exists; arbiter-events."
            "log records decision_defer_hitl with reason "
            "no_standing_approval."
        ),
    },
    {
        "path": ("submit", "send-lightning", "allowed-by-standing-approval"),
        "petcli_args": [
            "submit", "send-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            ("seed_standing_approvals", [
                {"op": "send_lightning",
                 "destination": _VALID_TOKEN,
                 "max_amount_sats": 50000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": lambda r: r == {
            "status": "not_implemented",
            "op": "send_lightning",
            "_petcli_estimate_window_s": 30.0,
        },
        "description": (
            "send_lightning analogue of send-bitcoin/allowed-by-"
            "standing-approval. amount_msats=1_000_000 rounds up to "
            "1000 sats; max_amount_sats=50000 admits it. The gate "
            "passes; dispatch returns the not_implemented stub. "
            "arbiter-events.log contains standing_approval_match "
            "and decision_allow."
        ),
    },
    {
        "path": ("query", "balance", "default"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "description": (
            "query_balance is a known read op (gateway._KNOWN_READ_OPS), "
            "dispatch reads lnd.walletbalance() via the fake lncli "
            "(total_balance=50000), and the gateway routes it through "
            "scale.present(). 50k is comfortably inside T0 [0, 100k) "
            "so the cloak is a no-op (scale 1.0) and the wire response "
            "is the raw figure. Confirms the no-cloak branch of "
            "dispatch is wired correctly. Audit logs request_received, "
            "scale_tier_init, decision_allow."
        ),
    },
    {
        "path": ("query", "channels", "default"),
        "petcli_args": ["query", "channels"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 80000,
        },
        "description": (
            "query_channels is a known read op, dispatch reads "
            "lnd.channelbalance() via the fake lncli (local=50000, "
            "remote=30000), aggregates to 80000, and the gateway "
            "routes it through scale.present(). 80k is inside T0 "
            "[0, 100k) so the cloak is a no-op. Per-channel detail "
            "is suppressed (aggregate-by-default, §4.3). Audit logs "
            "request_received, scale_tier_init, decision_allow."
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
            "0 is inside T0 so the cloak is a no-op (scale 1.0) and "
            "the wire response is balance_sats=0. Confirms the zero-"
            "balance edge without leaking the precise (zero) figure as "
            "a different status."
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
            "remote capacity (LNCLI_SCENARIO=no-channels). 0 is inside "
            "T0 so the cloak is a no-op; the gateway returns "
            "capacity_sats=0, petitioner-visibly indistinguishable "
            "from any wallet that has channels but real capacity below "
            "the cloak's sub-tier resolution."
        ),
    },
    # --- scale cloaking: GLOSSARY 'Scale cloaking'. The first two
    # exercise the no-pending-transition path at higher tiers (cloak
    # init picks the natural tier and the deterministic test-mode
    # scale). The last two exercise the transition state machine:
    # one with a future due_at (drift > range allowed) and one with a
    # past due_at (apply on next present() call).
    {
        "path": ("query", "balance", "cloaked-tier-1"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "lncli_scenario": "tier-1",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Wallet real total 150_000 sat -> natural tier T1. With "
            "no prior scale_state row, scale.present() initializes "
            "the cloak at T1 (test-mode deterministic scale 0.1) and "
            "presents 150_000 * 0.1 = 15_000. Confirms the cloak's "
            "init path picks the natural tier from a non-T0 wallet "
            "and the petitioner sees a sat figure compressed by an "
            "order of magnitude. Audit logs scale_tier_init."
        ),
    },
    {
        "path": ("query", "balance", "cloaked-tier-2"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "lncli_scenario": "tier-2",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Wallet real total 1_500_000 sat -> natural tier T2 "
            "(scale 0.01). scale.present() initializes at T2 and "
            "presents 1_500_000 * 0.01 = 15_000. The wire response "
            "is IDENTICAL to the cloaked-tier-1 variant despite the "
            "real total being 10x larger - that is the point of the "
            "cloak (GLOSSARY 'Scale cloaking'). Audit logs "
            "scale_tier_init."
        ),
    },
    {
        "path": ("query", "balance", "transition-pending"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "lncli_scenario": "tier-1",
        "preconditions": [
            # Seed: wallet was at T0 (scale 1.0); a transition to T1
            # (scale 0.1) has been scheduled for 1h in the future.
            # present() must NOT apply it yet; presented value comes
            # from the OLD active scale (1.0), so 150_000 * 1.0 =
            # 150_000 is the wire response. This is the GLOSSARY's
            # 'drift > range' property: real grew past 100k while
            # active_tier is still T0, presented = 150_000 deliberately
            # exceeds the 0-100k window.
            ("seed_scale_state", 0, 1.0, 1, 0.1, 3600.0),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 150000,
        },
        "description": (
            "Pending tier shift, future due_at. scale_state was seeded "
            "with active_tier=0 / target_tier=1 / due_at=now+1h before "
            "the petitioner's call; present(150_000) sees the pending "
            "transition is not yet due, uses the OLD active scale "
            "(1.0), and returns 150_000. The presented value briefly "
            "falls outside the 0-100k cloak window - this is the "
            "GLOSSARY 'drift > range' property: privacy beats range-"
            "fidelity because forcing the range immediately would "
            "re-couple the tier shift to the underlying fund movement. "
            "Audit log does NOT contain scale_tier_shift_applied for "
            "this variant."
        ),
    },
    {
        "path": ("query", "balance", "transition-applied"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "lncli_scenario": "tier-1",
        "preconditions": [
            # Seed: wallet was at T0; a transition to T1 was scheduled
            # 5s AGO. present() must auto-apply the shift, audit-log
            # scale_tier_shift_applied, and present at the new scale:
            # 150_000 * 0.1 = 15_000.
            ("seed_scale_state", 0, 1.0, 1, 0.1, -5.0),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Past-due tier shift. scale_state was seeded with "
            "active_tier=0 / target_tier=1 / due_at=now-5s. The "
            "petitioner's first call drives present(150_000), which "
            "applies the pending shift atomically (active becomes T1 / "
            "0.1, target_* cleared, audit-logs "
            "scale_tier_shift_applied) and returns 150_000 * 0.1 = "
            "15_000. The petitioner-visible drop from a presumably "
            "higher pre-shift presented value (under the old T0 scale) "
            "to 15_000 is by construction indistinguishable from a "
            "real send. arbiter-events.log MUST contain a "
            "scale_tier_shift_applied entry for this variant."
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

    # Standing-approvals config is process-global state shared across
    # variants via the env var; clear it here so a variant without a
    # seed_standing_approvals precondition sees the empty-default
    # (HITL every write), not whatever the previous variant wrote.
    try:
        _STANDING_APPROVALS_PATH.unlink()
    except FileNotFoundError:
        pass

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
        # through the known-read branch exercise lnd.py against a fake
        # lncli installed at module-import time; known-write variants
        # refuse at the recipient address registry gate and never
        # reach the lnd module. The runner does not capture per-variant
        # lncli stdout (the fake's reply lands in the petcli response
        # and is therefore already in result.json); the log records
        # which mode this variant ran under so a non-AI reviewer can
        # tell at a glance.
        if variant.get("uses_arbiter", True):
            infra_note = (
                "# Known-read variants dispatch through arbiter/src/lnd.py "
                "to the fake lncli at $LNCLI_BIN; known-write variants "
                "refuse at the recipient address registry gate and never "
                "reach the lnd module. No live bitcoind / LND traffic for "
                "any variant in the current manifest.\n"
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
