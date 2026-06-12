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
  4. Tear the arbiter down, apply the variant's expected check to
     the parsed response, and assert any expected_audit_events
     against the captured audit log (refusals are wire-uniform by
     design, so the audit event is what distinguishes which gate
     fired). A failed check leaves the artifacts in place so a
     non-AI reviewer can confirm what actually executed (per §2.1
     auditability).

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

Stdlib only. No bitcoind / LND / mint infrastructure is exercised
through the gateway dispatch in the current code base for
state-changing ops (no executor wires the timing layer to
bitcoin.py / lnd.py / ecash.py yet), so infra-events.log records
that fact rather than capturing real RPC traffic. Read-only
query_balance exercises a fake bitcoin-cli in onchain (default)
mode and a fake lncli in the advanced Lightning extension;
query_channels exercises the fake lncli (advanced only). The local
petcli eCash wallet commands exercise a fake cashu CLI (petitioner-
side, $PETCLI_CASHU_BIN) - the arbiter-side cashu wrapper is never
reached because eCash writes stop at the gateway gates or the
not_implemented dispatch stub. All three fakes are installed below.

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

# timing and scale register their own SQLite schemas at import time
# (their _SCHEMA fragments call state.register_schema). The arbiter
# boot path imports them for that side effect; mirror it here so the
# in-thread arbiter sees the full schema, not just gateway+results.
# registry is also imported here, but its storage substrate is the
# YAML file at arbiter/config/destinations.yaml (bead bl-2lbqu4) not
# SQLite, so it is wired via registry.configure() in _start_arbiter()
# rather than via state.migrate(). standing_approvals is imported
# for its render_yaml helper used by the seed_standing_approvals
# precondition (the gateway picks the path up via the env var).
import registry  # noqa: E402
import scale  # noqa: E402
import standing_approvals  # noqa: E402
import timing  # noqa: E402, F401

# Structural no-LND guarantee: importing the gateway (and every other
# arbiter module above) must not pull in lnd.py. The LND wrapper is the
# advanced Lightning extension's dependency, imported lazily by
# gateway._lnd() only on an advanced-mode dispatch. If this fires, some
# arbiter module regained a top-level lnd import and onchain (default)
# mode no longer runs LND-free. A second, runtime check fires in main()
# after all onchain-mode variants have run (see the no-lnd-import gate).
assert "lnd" not in sys.modules, (
    "importing arbiter modules pulled in lnd.py; onchain (default) "
    "mode must carry no LND dependency"
)

# Structural no-eCash guarantee, one rung up the ladder (doc 07 §9):
# ecash.py is imported lazily by gateway._ecash() only on an
# ecash-mode call, so onchain AND lightning deployments carry no
# nutshell dependency. The runtime check fires in main() just before
# the first ecash-mode variant (see the no-ecash-import gate).
assert "ecash" not in sys.modules, (
    "importing arbiter modules pulled in ecash.py; only ecash mode "
    "may carry the eCash extension dependency"
)

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

# eCash allowance config path (doc 07 §8, ecash.allowance_sats). Same
# per-variant lifecycle as standing approvals: cleared before each
# variant's preconditions, so a variant without seed_ecash_allowance
# sees the missing-config default - allowance 0, every fund refused -
# which is itself the fail-safe behavior one variant asserts.
_ECASH_ALLOWANCE_DIR = Path(tempfile.mkdtemp(prefix="exit-loop-ecash-allow-"))
_ECASH_ALLOWANCE_PATH = _ECASH_ALLOWANCE_DIR / "ecash.yaml"
os.environ["SPACER_ECASH_ALLOWANCE_PATH"] = str(_ECASH_ALLOWANCE_PATH)

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


# === Fake bitcoin-cli for the onchain-mode query variants ===========
#
# In onchain (default) mode gateway._dispatch wires query_balance
# through arbiter/src/bitcoin.py, which shells out to `bitcoin-cli`.
# Same pattern as the fake lncli above (and as bitcoin.py's own smoke
# test): a fake binary covers the full gateway -> dispatch -> bitcoin
# argv-construction -> Decimal parse stack without a live bitcoind.
# Scenario selection via $BITCOIN_CLI_SCENARIO; balances are the same
# sat figures the lncli scenarios use (getbalance prints BTC, so each
# value here is the lncli scenario's sats / 1e8), keeping the cloak-
# tier expectations identical across the two backends.
_BITCOIN_FAKE_DIR = Path(tempfile.mkdtemp(prefix="exit-loop-bitcoin-"))
_BITCOIN_FAKE = _BITCOIN_FAKE_DIR / "bitcoin-cli"
_BITCOIN_FAKE.write_text(
    """#!/bin/sh
# Fake bitcoin-cli for the exit-loop runner. Strips the -datadir=
# flag the way arbiter/src/bitcoin.py prepends it, then dispatches
# on the RPC name. Scenario via $BITCOIN_CLI_SCENARIO (default
# "funded"); values are deterministic BTC decimals that the gateway
# scales to integer sats before cloaking.
case "$1" in -datadir=*) shift;; esac
scenario="${BITCOIN_CLI_SCENARIO:-funded}"
case "$1" in
  getbalance)
    case "$scenario" in
      empty)
        printf '0.00000000'
        ;;
      tier-1)
        # 150_000 sat -> natural cloak tier T1.
        printf '0.00150000'
        ;;
      tier-2)
        # 1_500_000 sat -> natural cloak tier T2.
        printf '0.01500000'
        ;;
      *)
        # Default funded scenario: 50_000 sat, inside T0 so the
        # cloak is a no-op and the wire response is the raw figure.
        printf '0.00050000'
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
_BITCOIN_FAKE.chmod(
    _BITCOIN_FAKE.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
)
os.environ["BITCOIN_CLI_BIN"] = str(_BITCOIN_FAKE)
os.environ["BITCOIN_DATADIR"] = str(_BITCOIN_FAKE_DIR)
os.environ["BITCOIN_CLI_TIMEOUT_S"] = "5.0"


# === Fake cashu for the local petcli eCash wallet variants ===========
#
# The local eCash commands (petcli advanced ecash balance/send/receive/
# info) shell out to the petitioner-side cashu CLI ($PETCLI_CASHU_BIN)
# and never touch the arbiter - they operate the AI's own bearer
# wallet (doc 07 §3 custody split). The fake covers the full petcli ->
# subprocess -> _petcli_local envelope pipeline deterministically,
# mirroring the fake bitcoin-cli / fake lncli pattern with scenario
# selection via $CASHU_SCENARIO. The ARBITER-side cashu wrapper
# (arbiter/src/ecash.py) deliberately gets no fake here: no manifest
# variant can reach it (eCash writes stop at the gateway gates or the
# not_implemented dispatch stub), and leaving CASHU_BIN/CASHU_MINT_URL
# unset means any unexpected arbiter-side mint call would error loudly
# instead of being quietly absorbed by a fake.
_CASHU_FAKE_DIR = Path(tempfile.mkdtemp(prefix="exit-loop-cashu-"))
_CASHU_FAKE = _CASHU_FAKE_DIR / "cashu"
_CASHU_FAKE.write_text(
    """#!/bin/sh
# Fake petitioner-side cashu for the exit-loop runner. Dispatches on
# the wallet subcommand; scenario via $CASHU_SCENARIO (default
# "funded"). Values are deterministic so result.json artifacts are
# byte-stable across runs.
scenario="${CASHU_SCENARIO:-funded}"
case "$1" in
  balance)
    case "$scenario" in
      empty)
        printf 'Balance: 0 sat\\n'
        ;;
      *)
        printf 'Balance: 2500 sat\\n'
        ;;
    esac
    ;;
  send)
    printf 'cashuBfakeexitloopvector\\n'
    ;;
  receive)
    printf 'Received 1000 sat\\n'
    ;;
  info)
    printf 'Version: nutshell/fake\\nWallet: petitioner\\nMint URL: https://mint.example.test\\n'
    ;;
  *)
    echo "unknown command: $1" >&2
    exit 64
    ;;
esac
"""
)
_CASHU_FAKE.chmod(
    _CASHU_FAKE.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH
)


# === Arbiter lifecycle ==============================================

def _start_arbiter(audit_path, state_path, registry_yaml_path):
    """Configure audit, state, and the recipient registry to fresh
    isolated paths and start the privacy gateway in a daemon thread
    on an ephemeral port. Returns (server, port, thread). The caller
    is responsible for tearing the server down via _stop_arbiter().

    The registry's storage substrate is the YAML file at
    arbiter/config/destinations.yaml in production (bead bl-2lbqu4);
    isolating it per variant via configure() keeps each variant from
    seeing entries from any other variant. Variants that need a
    resolvable token stage it via the seed_registry precondition;
    the refused-unknown-token sends rely on the fresh registry being
    empty by construction."""
    audit.configure(audit_path)
    state.configure(state_path)
    state.migrate()
    registry.configure(registry_yaml_path)
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
        Direct injection of a (token, real, format) entry into the
        per-variant destinations.yaml. Bypasses registry.add()'s
        operator-side validation and token generation so a variant
        can stage a known-good token (the petcli_args reference it
        verbatim). Used by the send-bitcoin / send-lightning
        variants that exercise the post-registry path (the registry
        resolves; the standing-approvals gate decides). created_at
        = now, expires_at = now + 7d, used = False. Reaches into
        registry._persist() under registry._lock for the write -
        the public registry.add() API would mint its own random
        token rather than honor the one the test wants.
      ("seed_standing_approvals", [rule_dicts])
        Renders the rule list as YAML and writes it to the standing-
        approvals config path. Lets a variant pre-stage a matching
        rule so the gateway's standing_approvals.matches() returns
        True and dispatch fires (or omit and rely on the runner's
        per-variant clear for the default-pause path).
      ("seed_ecash_allowance", sats)
        Writes `ecash_allowance_sats: <sats>` to the eCash allowance
        config path (doc 07 §8). Lets a fund_ecash variant pass (or
        deliberately exceed) the allowance gate; omit and rely on
        the runner's per-variant clear for the missing-config
        default (allowance 0 = every fund refused).
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
        with registry._lock:
            existing = list(registry._entries)
            next_id = (max((e["id"] for e in existing), default=0)) + 1
            new_entry = {
                "id": next_id,
                "token": token,
                "real": real,
                "format": fmt,
                "created_at": now,
                "expires_at": expires,
                "used": False,
                "consumed_by": None,
            }
            registry._persist(existing + [new_entry])
    elif op == "seed_standing_approvals":
        _, rules = precondition
        _STANDING_APPROVALS_PATH.write_text(
            standing_approvals.render_yaml(rules)
        )
    elif op == "seed_ecash_allowance":
        _, sats = precondition
        _ECASH_ALLOWANCE_PATH.write_text(
            f"ecash_allowance_sats: {int(sats)}\n"
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
#   expected_audit_events / forbidden_audit_events:
#                    event names that must / must not appear in the
#                    variant's arbiter-events.log (see the assertion
#                    block in _run_variant for why).
#   description:     human-readable note on what the variant
#                    exercises and which audit events fire.
#
#   spacer_mode:     SPACER_MODE value for the variant, or absent to
#                    run with the variable UNSET - the onchain default
#                    deployment. Advanced-extension variants set
#                    "lightning" or "full" (both enable the extension;
#                    the manifest exercises each at least once);
#                    eCash-extension variants set "ecash" (the full
#                    ladder, doc 07 §9).
#   bitcoin_cli_scenario / lncli_scenario / cashu_scenario:
#                    canned-reply selector for the fake bitcoin-cli /
#                    fake lncli / fake cashu (default "funded" for
#                    all three).
#   petcli_cashu_bin:
#                    override for $PETCLI_CASHU_BIN (default: the
#                    fake cashu installed above). The missing-binary
#                    variant points it at a fixed nonexistent path so
#                    the artifact stays deterministic.
#
# Variants in this list are the ones that exercise distinct code
# paths reachable in the current code base, across the deployment
# modes (gateway SPACER_MODE):
#
# - onchain (default, SPACER_MODE unset): query_balance dispatches
#   through arbiter/src/bitcoin.py against a fake bitcoin-cli the
#   runner installs at module-import time; send_bitcoin exercises the
#   registry-miss refusal and both standing-approvals branches. The
#   extension ops (query_channels / send_lightning / fund_ecash /
#   defund_ecash) are extension-gated: recognized but refused
#   uniformly (decision_refuse_mode).
# - advanced (SPACER_MODE=lightning|full): the Lightning extension
#   layers query_channels / send_lightning back on, and query_balance
#   reads the LND wallet instead of bitcoind - all through
#   arbiter/src/lnd.py against the fake lncli. The eCash ops remain
#   extension-gated (doc 07 §9: full is frozen at onchain+lightning).
# - ecash (SPACER_MODE=ecash): the full ladder. The Lightning surface
#   stays on (the ladder regression variants assert it) and the eCash
#   writes run their gate pipeline: allowance cap (fund only,
#   doc 07 §8) -> standing approvals -> the not_implemented dispatch
#   stub pending the timing-layer executor.
# - local petcli eCash wallet commands (no arbiter): petcli shells to
#   the fake cashu ($PETCLI_CASHU_BIN) and wraps its output in the
#   _petcli_local envelope.
#
# ORDER MATTERS twice: every onchain-mode variant precedes every
# advanced-mode variant so the no-lnd-import gate in main() can
# verify, just before the first advanced variant runs, that no
# onchain code path imported lnd.py (the "no LND dependency at
# runtime" claim); and every onchain- and lightning-mode variant
# precedes every ecash-mode variant so the no-ecash-import gate can
# verify, just before the first ecash variant runs, that both lower
# rungs ran mint-free (doc 07 §9).
#
# Happy-path sends (including fund/defund) and the other registry-
# rejection subcases (expired / used / bad checksum / anomalous)
# become reachable once the timing-layer executor lands; their
# artifact directories stay absent per §10's "an empty one signals
# not-yet-validated".
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
    # --- submit send-bitcoin: the primary (onchain) write op. State-
    # changing ops resolve through the recipient address registry
    # (§4.7). Sending with a token that is not in the registry (here,
    # the made-up 'ABCDEF') refuses uniformly at the registry gate.
    # The wire shape is the standard refusal body; the audit log
    # carries decision_refuse_registry so the operator can see *which*
    # token failed and why. The advanced-extension send_lightning
    # analogues live in the advanced-mode group at the end of the
    # manifest.
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
        "expected_audit_events": ["decision_defer_hitl"],
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
        "expected_audit_events": ["standing_approval_match", "decision_allow"],
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
        "path": ("query", "balance", "default"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "description": (
            "query_balance in onchain (default) mode: a known read op, "
            "dispatch reads bitcoin.getbalance() via the fake "
            "bitcoin-cli (0.00050000 BTC), the gateway scales the BTC "
            "Decimal to 50_000 integer sats and routes it through "
            "scale.present(). 50k is comfortably inside T0 [0, 100k) "
            "so the cloak is a no-op (scale 1.0) and the wire response "
            "is the raw figure. Confirms the no-cloak branch of the "
            "bitcoind-backed dispatch is wired correctly. Audit logs "
            "request_received, scale_tier_init, decision_allow."
        ),
    },
    {
        "path": ("query", "balance", "empty-wallet"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "empty",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 0,
        },
        "description": (
            "Same onchain dispatch path as the funded variant, but the "
            "fake bitcoin-cli reports 0.00000000 BTC under "
            "BITCOIN_CLI_SCENARIO=empty. 0 is inside T0 so the cloak "
            "is a no-op (scale 1.0) and the wire response is "
            "balance_sats=0. Confirms the zero-balance edge without "
            "leaking the precise (zero) figure as a different status."
        ),
    },
    # --- scale cloaking: GLOSSARY 'Scale cloaking'. The first two
    # exercise the no-pending-transition path at higher tiers (cloak
    # init picks the natural tier and the deterministic test-mode
    # scale). The last two exercise the transition state machine:
    # one with a future due_at (drift > range allowed) and one with a
    # past due_at (apply on next present() call). All four run in
    # onchain (default) mode - the cloak sits between dispatch and
    # the wire regardless of which backend produced the figure.
    {
        "path": ("query", "balance", "cloaked-tier-1"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-1",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Wallet real total 150_000 sat (0.00150000 BTC from the "
            "fake bitcoin-cli) -> natural tier T1. With no prior "
            "scale_state row, scale.present() initializes the cloak "
            "at T1 (test-mode deterministic scale 0.1) and presents "
            "150_000 * 0.1 = 15_000. Confirms the cloak's init path "
            "picks the natural tier from a non-T0 wallet and the "
            "petitioner sees a sat figure compressed by an order of "
            "magnitude. Audit logs scale_tier_init."
        ),
    },
    {
        "path": ("query", "balance", "cloaked-tier-2"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-2",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Wallet real total 1_500_000 sat (0.01500000 BTC) -> "
            "natural tier T2 (scale 0.01). scale.present() "
            "initializes at T2 and presents 1_500_000 * 0.01 = "
            "15_000. The wire response is IDENTICAL to the "
            "cloaked-tier-1 variant despite the real total being 10x "
            "larger - that is the point of the cloak (GLOSSARY 'Scale "
            "cloaking'). Audit logs scale_tier_init."
        ),
    },
    {
        "path": ("query", "balance", "transition-pending"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-1",
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
        "forbidden_audit_events": ["scale_tier_shift_applied"],
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
            "this variant (the runner asserts the absence)."
        ),
    },
    {
        "path": ("query", "balance", "transition-applied"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-1",
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
        "expected_audit_events": ["scale_tier_shift_applied"],
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
    # --- extension gate: Lightning ops while the arbiter runs onchain
    # (default) mode. The ops are recognized but deliberately disabled;
    # the gateway refuses uniformly BEFORE the registry or standing-
    # approvals gates are consulted and audit-logs decision_refuse_mode
    # (distinct from decision_refuse_registry / decision_defer_hitl).
    # The send variant stages a resolvable token + a matching standing-
    # approval rule to prove the mode gate wins over an otherwise-
    # allowable call.
    {
        "path": ("advanced", "send-lightning", "refused-onchain-mode"),
        "petcli_args": [
            "advanced", "send-lightning",
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
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "send_lightning against an onchain (default) arbiter. The "
            "registry token resolves and a standing-approval rule "
            "matches - in advanced mode this exact call dispatches "
            "(advanced/send-lightning/allowed-by-standing-approval) - "
            "but the mode gate refuses first: the op belongs to the "
            "disabled Lightning extension. Wire shape is the standard "
            "uniform refusal; arbiter-events.log carries "
            "decision_refuse_mode with reason "
            "advanced_extension_disabled (the runner asserts the "
            "event), distinct from a registry miss or an unknown op."
        ),
    },
    {
        "path": ("advanced", "channels", "refused-onchain-mode"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: r == {"status": "refused"},
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "query_channels against an onchain (default) arbiter: the "
            "Lightning read is extension-gated, so the gateway refuses "
            "uniformly without dispatching (lnd.py is never imported). "
            "arbiter-events.log carries decision_refuse_mode (the "
            "runner asserts the event); the wire body is the same "
            "uniform refusal every other refusal cause produces."
        ),
    },
    # --- extension gate, eCash rung (doc 07 §9): the eCash writes are
    # recognized in every mode but honored only in ecash mode. Against
    # an onchain (default) arbiter they refuse uniformly at the same
    # mode gate as the Lightning ops - decision_refuse_mode, op field
    # disambiguating which extension was asked for - and ecash.py is
    # never imported (the no-ecash-import gate asserts that later).
    {
        "path": ("advanced", "ecash", "fund", "refused-onchain-mode"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "fund_ecash against an onchain (default) arbiter. The op "
            "belongs to the disabled eCash extension, so the gateway "
            "refuses uniformly at the mode gate before any allowance "
            "or standing-approvals logic runs (arbiter/src/ecash.py "
            "is never imported). arbiter-events.log carries "
            "decision_refuse_mode with reason "
            "advanced_extension_disabled; the op field tells the "
            "operator it was the eCash extension being probed."
        ),
    },
    {
        "path": ("advanced", "ecash", "defund", "refused-onchain-mode"),
        "petcli_args": [
            "advanced", "ecash", "defund",
            "--token", "cashuBfakeexitloopvector",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "defund_ecash against an onchain (default) arbiter: same "
            "mode-gate refusal as the fund variant. The canned token "
            "string is never parsed - the gate fires on the op alone, "
            "so no token validation surface exists outside ecash mode."
        ),
    },
    # =================================================================
    # Advanced-extension group (SPACER_MODE=lightning|full). Every
    # variant below runs with the Lightning extension enabled; every
    # variant above runs onchain (SPACER_MODE unset). main()'s
    # no-lnd-import gate fires between the two groups. The first
    # advanced-mode dispatch lazily imports lnd.py (gateway._lnd) and
    # Python caches it for the rest of the run; that is expected.
    # =================================================================
    {
        "path": ("query", "balance", "advanced-lnd-wallet"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "bitcoin_cli_scenario": "empty",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "description": (
            "query_balance in advanced mode reads the LND on-chain "
            "wallet (lnd.walletbalance() via the fake lncli, "
            "total_balance=50000) instead of bitcoind. The fake "
            "bitcoin-cli is pinned to the empty scenario (0 BTC) for "
            "this variant, so the 50_000-sat response proves dispatch "
            "took the LND path - had it read bitcoind, the wire "
            "response would be balance_sats=0. Same T0 no-cloak "
            "presentation as query/balance/default."
        ),
    },
    {
        "path": ("advanced", "channels", "default"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 80000,
        },
        "description": (
            "query_channels (petcli: advanced channels) with the "
            "extension enabled: dispatch reads lnd.channelbalance() "
            "via the fake lncli (local=50000, remote=30000), "
            "aggregates to 80000, and the gateway routes it through "
            "scale.present(). 80k is inside T0 [0, 100k) so the cloak "
            "is a no-op. Per-channel detail is suppressed (aggregate-"
            "by-default, §4.3). Audit logs request_received, "
            "scale_tier_init, decision_allow."
        ),
    },
    {
        "path": ("advanced", "channels", "no-channels"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "spacer_mode": "full",
        "lncli_scenario": "no-channels",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 0,
        },
        "description": (
            "Channels query when lncli reports zero local + zero "
            "remote capacity (LNCLI_SCENARIO=no-channels). 0 is "
            "inside T0 so the cloak is a no-op; the gateway returns "
            "capacity_sats=0, petitioner-visibly indistinguishable "
            "from any wallet that has channels but real capacity "
            "below the cloak's sub-tier resolution. Runs under "
            "SPACER_MODE=full to confirm the second advanced value "
            "enables the extension identically to 'lightning'."
        ),
    },
    {
        "path": ("advanced", "send-lightning", "refused-unknown-token"),
        "petcli_args": [
            "advanced", "send-lightning",
            "--to-token", "ABCDEF",
            "--amount-msats", "1000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_registry"],
        "description": (
            "Same registry-miss path as submit/send-bitcoin/refused-"
            "unknown-token, but for the Lightning send op with the "
            "extension enabled. Audit logs decision_refuse_registry."
        ),
    },
    {
        "path": ("advanced", "send-lightning", "parked-no-standing-approval"),
        "petcli_args": [
            "advanced", "send-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
        ],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "Same default-pause path as submit/send-bitcoin/parked-no-"
            "standing-approval but for the Lightning send op with the "
            "extension enabled. amount_msats=1_000_000 (= 1000 sats "
            "post-ceiling) is irrelevant here because no rule exists; "
            "arbiter-events.log records decision_defer_hitl with "
            "reason no_standing_approval."
        ),
    },
    {
        "path": ("advanced", "send-lightning", "allowed-by-standing-approval"),
        "petcli_args": [
            "advanced", "send-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
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
        "expected_audit_events": ["standing_approval_match", "decision_allow"],
        "description": (
            "send_lightning analogue of submit/send-bitcoin/allowed-"
            "by-standing-approval, with the extension enabled. "
            "amount_msats=1_000_000 rounds up to 1000 sats; "
            "max_amount_sats=50000 admits it. The gate passes; "
            "dispatch returns the not_implemented stub. arbiter-"
            "events.log contains standing_approval_match and "
            "decision_allow."
        ),
    },
    # --- extension gate, eCash rung against the LIGHTNING extension:
    # doc 07 §9 freezes `full` (and `lightning`) at onchain+lightning,
    # so the eCash writes refuse at the mode gate even with the
    # Lightning extension fully enabled. One variant runs under
    # SPACER_MODE=lightning and one under SPACER_MODE=full to pin the
    # frozen-alias behavior on both advanced values: neither silently
    # arms ecash.
    {
        "path": ("advanced", "ecash", "fund", "refused-lightning-mode"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "fund_ecash against a lightning-mode arbiter. The "
            "Lightning extension is on, but the eCash extension is "
            "its own opt-in rung (doc 07 §9): the mode gate refuses "
            "uniformly with decision_refuse_mode, and ecash.py stays "
            "unimported (the no-ecash-import gate asserts that "
            "lightning-mode variants ran mint-free)."
        ),
    },
    {
        "path": ("advanced", "ecash", "defund", "refused-lightning-mode"),
        "petcli_args": [
            "advanced", "ecash", "defund",
            "--token", "cashuBfakeexitloopvector",
        ],
        "uses_arbiter": True,
        "spacer_mode": "full",
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "defund_ecash against a SPACER_MODE=full arbiter: `full` "
            "stays frozen at its 2026-06 meaning (onchain + "
            "lightning, a legacy alias of `lightning`), so the eCash "
            "write refuses at the mode gate exactly as under "
            "`lightning`. This is the doc 07 §9 no-silent-arming "
            "guarantee: an existing full deployment does not gain "
            "bearer-value ops at upgrade."
        ),
    },
    # =================================================================
    # eCash-extension group (SPACER_MODE=ecash). Every variant below
    # this divider runs the full ladder; every variant above runs
    # onchain or lightning/full. main()'s no-ecash-import gate fires
    # between the two groups, asserting both lower rungs ran with
    # ecash.py unimported. The first fund_ecash gate check lazily
    # imports ecash.py (gateway._ecash) for the allowance lookup;
    # Python caches it for the rest of the run; that is expected.
    # =================================================================
    {
        "path": ("query", "balance", "ecash-lnd-wallet"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "bitcoin_cli_scenario": "empty",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "description": (
            "query_balance under SPACER_MODE=ecash keeps its "
            "lightning-mode behavior - the LND on-chain wallet via "
            "the fake lncli (50_000 sat), NOT bitcoind (pinned to "
            "the empty scenario to prove which path dispatched) and "
            "NOT any eCash figure (doc 07 §9: no new read ops; the "
            "AI counts its own float locally). Ladder regression: "
            "ecash mode is lightning mode plus the eCash writes."
        ),
    },
    {
        "path": ("advanced", "channels", "ecash-mode"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 80000,
        },
        "description": (
            "query_channels under SPACER_MODE=ecash: identical "
            "behavior to the lightning-mode default variant "
            "(local 50000 + remote 30000 = 80000, T0 no-cloak). "
            "Ladder regression: enabling the eCash rung leaves the "
            "Lightning read surface exactly as it was."
        ),
    },
    # --- fund_ecash gate pipeline (doc 07 §3, §8): allowance cap ->
    # standing approvals -> dispatch stub. The allowance check fires
    # FIRST and is config-bounded (a HITL approval cannot exceed it).
    {
        "path": ("advanced", "ecash", "fund", "refused-no-allowance-config"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            # No seed_ecash_allowance: the missing-config default.
        ],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_allowance"],
        "description": (
            "fund_ecash in ecash mode with NO allowance config "
            "written. ecash.allowance_sats() reads a missing config "
            "as 0, so outstanding(0) + 1000 > 0 refuses at the "
            "allowance gate: the float cannot exist until the "
            "operator explicitly writes its bound (doc 07 §8 "
            "fail-safe). arbiter-events.log carries "
            "decision_refuse_allowance with the requested/outstanding/"
            "allowance figures."
        ),
    },
    {
        "path": ("advanced", "ecash", "fund", "refused-over-allowance"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "100000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            ("seed_ecash_allowance", 50000),
            # A matching standing-approval rule is deliberately staged
            # to prove the allowance check fires FIRST (doc 07 §8: a
            # HITL approval cannot exceed the allowance - the rule
            # would admit the amount, but it is never consulted).
            ("seed_standing_approvals", [
                {"op": "fund_ecash",
                 "destination": "mint",
                 "max_amount_sats": 200000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_refuse_allowance"],
        "forbidden_audit_events": ["standing_approval_match"],
        "description": (
            "fund_ecash for 100_000 sat against a 50_000-sat "
            "allowance (outstanding 0). A standing-approval rule "
            "admitting up to 200_000 sat is staged and must NOT "
            "rescue the call: the allowance check precedes standing "
            "approvals by design, so no approval - standing or HITL - "
            "can widen the blast radius past the console-edited cap. "
            "arbiter-events.log carries decision_refuse_allowance and "
            "must NOT carry standing_approval_match (the runner "
            "asserts both)."
        ),
    },
    {
        "path": ("advanced", "ecash", "fund", "parked-no-standing-approval"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            ("seed_ecash_allowance", 50000),
            # No seed_standing_approvals: default-pause path.
        ],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "fund_ecash inside the allowance (1000 of 50_000) but "
            "with NO standing-approval rule: the allowance gate "
            "passes, the standing-approvals check fails (default-"
            "pause = empty config), the gateway HITL-parks and "
            "refuses uniformly. arbiter-events.log carries "
            "decision_defer_hitl with reason no_standing_approval, "
            "distinct from the allowance refusal."
        ),
    },
    {
        "path": ("advanced", "ecash", "fund", "allowed-by-standing-approval"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            ("seed_ecash_allowance", 50000),
            ("seed_standing_approvals", [
                {"op": "fund_ecash",
                 "destination": "mint",
                 "max_amount_sats": 50000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": lambda r: r == {
            "status": "not_implemented",
            "op": "fund_ecash",
            "_petcli_estimate_window_s": 30.0,
        },
        "expected_audit_events": ["standing_approval_match", "decision_allow"],
        "description": (
            "fund_ecash where the allowance admits the amount AND a "
            "standing-approval rule matches (op fund_ecash, "
            "destination 'mint' - the structural constant for eCash "
            "ops, doc 07 §3 - amount under max). Both gates pass; "
            "dispatch fires and returns the not_implemented stub "
            "(the fund executor lands with the timing-layer "
            "executor). arbiter-events.log contains "
            "standing_approval_match and decision_allow."
        ),
    },
    # --- defund_ecash gate pipeline: standing approvals -> dispatch
    # stub. No allowance check (defund only shrinks exposure), and no
    # gate-time amount (the token's value is the wallet's to decode at
    # execution), so only an unbounded rule matches.
    {
        "path": ("advanced", "ecash", "defund", "parked-no-standing-approval"),
        "petcli_args": [
            "advanced", "ecash", "defund",
            "--token", "cashuBfakeexitloopvector",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [],
        "expected": lambda r: (
            r.get("status") == "refused"
            and r.get("_petcli_estimate_window_s") == 30.0
        ),
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "defund_ecash in ecash mode with no standing-approval "
            "rule: no allowance check applies (defund only shrinks "
            "the float), the standing-approvals default-pause parks "
            "it in HITL and refuses uniformly. arbiter-events.log "
            "carries decision_defer_hitl with reason "
            "no_standing_approval. No allowance config is seeded - "
            "defund must not require one."
        ),
    },
    {
        "path": ("advanced", "ecash", "defund", "allowed-by-standing-approval"),
        "petcli_args": [
            "advanced", "ecash", "defund",
            "--token", "cashuBfakeexitloopvector",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            # The rule is UNBOUNDED (no max_amount_sats): defund
            # carries no gate-time amount, and an unknown amount fails
            # any bounded rule, so a bounded defund rule would never
            # match. Unbounded is the right shape - defund reduces
            # exposure regardless of size.
            ("seed_standing_approvals", [
                {"op": "defund_ecash",
                 "destination": "mint",
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": lambda r: r == {
            "status": "not_implemented",
            "op": "defund_ecash",
            "_petcli_estimate_window_s": 30.0,
        },
        "expected_audit_events": ["standing_approval_match", "decision_allow"],
        "description": (
            "defund_ecash with an unbounded standing-approval rule "
            "(op defund_ecash, destination 'mint', no amount bound): "
            "the gate passes and dispatch returns the "
            "not_implemented stub (the defund executor - swap-claim "
            "at the pinned mint, melt to our LND - lands with the "
            "timing-layer executor). arbiter-events.log contains "
            "standing_approval_match and decision_allow."
        ),
    },
    # =================================================================
    # Local petcli eCash wallet commands (no arbiter). The custody
    # split's other half (doc 07 §3): balance/send/receive/info
    # operate the AI's own bearer wallet by shelling to the
    # petitioner-side cashu CLI - here the fake at $PETCLI_CASHU_BIN.
    # Position in the manifest is irrelevant to the import gates
    # (petcli runs in its own subprocess and never touches arbiter
    # modules); they sit last as their own group.
    # =================================================================
    {
        "path": ("advanced", "ecash", "balance", "default"),
        "petcli_args": ["advanced", "ecash", "balance"],
        "uses_arbiter": False,
        "preconditions": [],
        "expected": lambda r: r == {
            "_petcli_local": True,
            "exit_code": 0,
            "stdout": "Balance: 2500 sat\n",
            "stderr": "",
        },
        "description": (
            "petcli advanced ecash balance: local wallet count via "
            "the fake cashu (funded scenario, 2500 sat). The "
            "_petcli_local envelope wraps the CLI's stdout verbatim; "
            "petcli interprets nothing. The float is precisely "
            "countable by design - scale cloaking does not apply to "
            "a bearer instrument in hand (doc 07 §5.2)."
        ),
    },
    {
        "path": ("advanced", "ecash", "balance", "empty-wallet"),
        "petcli_args": ["advanced", "ecash", "balance"],
        "uses_arbiter": False,
        "cashu_scenario": "empty",
        "preconditions": [],
        "expected": lambda r: r == {
            "_petcli_local": True,
            "exit_code": 0,
            "stdout": "Balance: 0 sat\n",
            "stderr": "",
        },
        "description": (
            "Same local path under CASHU_SCENARIO=empty: a zero "
            "float renders as the wallet's own zero line, exit 0."
        ),
    },
    {
        "path": ("advanced", "ecash", "balance", "missing-binary"),
        "petcli_args": ["advanced", "ecash", "balance"],
        "uses_arbiter": False,
        "petcli_cashu_bin": "/nonexistent/petcli-cashu",
        "preconditions": [],
        "expected": lambda r: r == {
            "_petcli_local": True,
            "error": "cashu binary not found: /nonexistent/petcli-cashu",
        },
        "description": (
            "petcli advanced ecash balance with $PETCLI_CASHU_BIN "
            "pointing at a fixed nonexistent path: the wallet-missing "
            "failure surfaces as a structured _petcli_local error "
            "envelope (not a traceback), keeping petcli JSON-shaped "
            "end-to-end."
        ),
    },
    {
        "path": ("advanced", "ecash", "send", "default"),
        "petcli_args": [
            "advanced", "ecash", "send",
            "--amount-sats", "500",
        ],
        "uses_arbiter": False,
        "preconditions": [],
        "expected": lambda r: r == {
            "_petcli_local": True,
            "exit_code": 0,
            "stdout": "cashuBfakeexitloopvector\n",
            "stderr": "",
        },
        "description": (
            "petcli advanced ecash send: serialize float value into "
            "a handoff token, locally - the autonomy the extension "
            "buys (doc 07 §3: no gateway mediation inside the "
            "float). The fake returns the canned token string."
        ),
    },
    {
        "path": ("advanced", "ecash", "receive", "default"),
        "petcli_args": [
            "advanced", "ecash", "receive",
            "--token", "cashuBfakeexitloopvector",
        ],
        "uses_arbiter": False,
        "preconditions": [],
        "expected": lambda r: r == {
            "_petcli_local": True,
            "exit_code": 0,
            "stdout": "Received 1000 sat\n",
            "stderr": "",
        },
        "description": (
            "petcli advanced ecash receive: swap-claim a token into "
            "the local wallet (the token string passes through as a "
            "single argv entry - no shell expansion surface)."
        ),
    },
    {
        "path": ("advanced", "ecash", "info", "default"),
        "petcli_args": ["advanced", "ecash", "info"],
        "uses_arbiter": False,
        "preconditions": [],
        "expected": lambda r: (
            r.get("_petcli_local") is True
            and r.get("exit_code") == 0
            and "nutshell/fake" in r.get("stdout", "")
            and "mint.example.test" in r.get("stdout", "")
        ),
        "description": (
            "petcli advanced ecash info: local wallet / mint info "
            "via the fake cashu. The mint URL appearing here is by "
            "design - the AI can always see which mint its tokens "
            "embed (doc 07 §5.2); the mitigations are mint CHOICE, "
            "not mint secrecy."
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
    registry_dir = Path(tempfile.mkdtemp(prefix="exit-loop-registry-"))
    audit_path = audit_dir / "audit.log"
    state_path = state_dir / "state.db"
    registry_yaml_path = registry_dir / "destinations.yaml"

    # Per-variant environment. The fake binaries read their scenario
    # vars to pick which canned reply to print; SPACER_MODE selects the
    # gateway's deployment mode (the gateway reads it per request, so
    # one runner process exercises every mode). A None value means the
    # variable must be UNSET for the variant - that is how onchain
    # variants prove onchain is the no-configuration default. Prior
    # values are restored in the finally block so a later variant's
    # env is not contaminated. PETCLI_CASHU_BIN is always pinned (to
    # the fake by default) so the local eCash wallet variants never
    # fall through to a real `cashu` on the host PATH.
    env_overrides = {
        "LNCLI_SCENARIO": variant.get("lncli_scenario", "funded"),
        "BITCOIN_CLI_SCENARIO": variant.get("bitcoin_cli_scenario", "funded"),
        "CASHU_SCENARIO": variant.get("cashu_scenario", "funded"),
        "PETCLI_CASHU_BIN": variant.get("petcli_cashu_bin", str(_CASHU_FAKE)),
        "SPACER_MODE": variant.get("spacer_mode"),
    }
    saved_env = {k: os.environ.get(k) for k in env_overrides}
    for k, v in env_overrides.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v

    # Standing-approvals and eCash-allowance configs are process-
    # global state shared across variants via their env vars; clear
    # them here so a variant without the corresponding seed
    # precondition sees the empty default (HITL every write;
    # allowance 0 = every fund refused), not whatever the previous
    # variant wrote.
    for stale in (_STANDING_APPROVALS_PATH, _ECASH_ALLOWANCE_PATH):
        try:
            stale.unlink()
        except FileNotFoundError:
            pass

    server = thread = port = None
    try:
        if variant.get("uses_arbiter", True):
            server, port, thread = _start_arbiter(
                audit_path, state_path, registry_yaml_path
            )
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

        # Bitcoind / LND infrastructure events. Read variants dispatch
        # against the fake backend binaries installed at module-import
        # time; write variants stop at a gateway gate or the
        # not_implemented dispatch stub before reaching a backend
        # module. The runner does not capture per-variant fake-binary
        # stdout (the fake's reply lands in the petcli response and is
        # therefore already in result.json); the log records which
        # deployment mode this variant ran under so a non-AI reviewer
        # can tell at a glance.
        if not variant.get("uses_arbiter", True):
            if variant["path"][:2] == ("advanced", "ecash"):
                infra_note = (
                    "# Local petitioner-side eCash wallet command: petcli "
                    "shells to the cashu CLI at $PETCLI_CASHU_BIN (the "
                    "runner's fake) and never reaches the arbiter. No "
                    "bitcoind / LND / arbiter-side mint interaction is "
                    "possible; the doc 07 §3 custody split puts these ops "
                    "on the AI's side of the boundary by design.\n"
                )
            else:
                infra_note = (
                    "# Local-only variant: never reaches the arbiter, so no "
                    "bitcoind / LND interaction is possible.\n"
                )
        elif variant.get("spacer_mode") is None:
            infra_note = (
                "# onchain (default) mode - SPACER_MODE unset. Read "
                "variants dispatch through arbiter/src/bitcoin.py to the "
                "fake bitcoin-cli at $BITCOIN_CLI_BIN; write variants stop "
                "at the recipient-address-registry / standing-approvals "
                "gates or the not_implemented dispatch stub before "
                "reaching bitcoin.py; Lightning- and eCash-extension ops "
                "refuse at the mode gate (decision_refuse_mode). "
                "arbiter/src/lnd.py and arbiter/src/ecash.py are never "
                "imported in this mode (the runner asserts both). "
                "No live bitcoind / LND / mint traffic for any variant in "
                "the current manifest.\n"
            )
        elif variant.get("spacer_mode") == "ecash":
            infra_note = (
                "# ecash mode - SPACER_MODE=ecash (the full ladder, doc 07 "
                "§9). Lightning reads (and query_balance, which reads the "
                "LND wallet in this mode) dispatch through "
                "arbiter/src/lnd.py to the fake lncli at $LNCLI_BIN; eCash "
                "writes stop at the allowance / standing-approvals gates "
                "or the not_implemented dispatch stub before any mint "
                "call - arbiter/src/ecash.py is imported only for the "
                "fund_ecash allowance lookup and no cashu subprocess ever "
                "runs (CASHU_BIN / CASHU_MINT_URL are deliberately unset; "
                "an unexpected arbiter-side mint call would error loudly). "
                "No live bitcoind / LND / mint traffic for any variant in "
                "the current manifest.\n"
            )
        else:
            infra_note = (
                f"# advanced mode - SPACER_MODE={variant['spacer_mode']}. "
                "Lightning reads (and query_balance, which reads the LND "
                "wallet in this mode) dispatch through arbiter/src/lnd.py "
                "to the fake lncli at $LNCLI_BIN; Lightning writes stop "
                "at the registry / standing-approvals gates or the "
                "not_implemented dispatch stub; eCash-extension ops "
                "refuse at the mode gate (decision_refuse_mode - the "
                "eCash rung is its own opt-in; arbiter/src/ecash.py "
                "stays unimported, the runner asserts it). No live "
                "bitcoind / LND / mint traffic for any variant in the "
                "current manifest.\n"
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

        # Optional audit-event assertions. Refusal wire shapes are
        # deliberately uniform across causes (§4.1), so a variant whose
        # whole point is WHICH gate fired (mode gate vs. registry miss
        # vs. allowance vs. standing-approvals park) cannot be told
        # apart by the response alone; the distinguishing audit event
        # in arbiter-events.log is the evidence, and the runner checks
        # it here. forbidden_audit_events is the complement: a variant
        # whose point is that a gate did NOT fire (the allowance check
        # preceding standing approvals; a pending tier shift not yet
        # applied) asserts the event's absence.
        required_events = variant.get("expected_audit_events", [])
        forbidden_events = variant.get("forbidden_audit_events", [])
        if required_events or forbidden_events:
            audit_events = [
                json.loads(line)["event"]
                for line in (artifact_dir / "arbiter-events.log")
                .read_text().splitlines()
                if line.strip()
            ]
            for required in required_events:
                if required not in audit_events:
                    return (False, f"audit log missing {required!r}; "
                                   f"events={audit_events}")
            for forbidden in forbidden_events:
                if forbidden in audit_events:
                    return (False, f"audit log must not contain "
                                   f"{forbidden!r}; events={audit_events}")
        return (True, None)
    finally:
        if server is not None:
            _stop_arbiter(server, thread)
        # Restore the prior per-variant env so cross-variant state is
        # not sticky. A saved None means "the var was unset" - delete
        # it rather than setting the literal string "None".
        for k, prior in saved_env.items():
            if prior is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = prior
        # Best-effort cleanup of the per-variant tempdirs.
        for d in (audit_dir, state_dir, registry_dir):
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
    checks_total = 0
    lnd_gate_pending = any(
        v.get("spacer_mode") is not None for v in VARIANTS
    )
    ecash_gate_pending = any(
        v.get("spacer_mode") == "ecash" for v in VARIANTS
    )
    for variant in VARIANTS:
        # The no-lnd-import gate: fires once, immediately before the
        # first advanced-mode variant. Every variant above it in the
        # manifest ran in onchain (default) mode; if any of them caused
        # lnd.py to be imported, the "no LND dependency at runtime"
        # claim is broken even if each variant's wire response looked
        # right. (After this point advanced-mode dispatches import
        # lnd.py legitimately, so the claim is only checkable here.)
        if lnd_gate_pending and variant.get("spacer_mode") is not None:
            lnd_gate_pending = False
            checks_total += 1
            gate_name = "no-lnd-import gate (onchain variants ran LND-free)"
            if "lnd" in sys.modules:
                print(f"FAIL  {gate_name}")
                failed.append((
                    gate_name,
                    "lnd.py was imported while only onchain-mode "
                    "variants had run",
                ))
            else:
                print(f"PASS  {gate_name}")
                passed_paths.append(gate_name)
        # The no-ecash-import gate, one rung up (doc 07 §9): fires
        # once, immediately before the first ecash-mode variant.
        # Every variant above it ran onchain or lightning/full; if
        # any of them caused ecash.py to be imported, an onchain or
        # lightning deployment would be carrying the eCash
        # extension's nutshell dependency. (After this point the
        # fund_ecash allowance gate imports ecash.py legitimately.)
        if ecash_gate_pending and variant.get("spacer_mode") == "ecash":
            ecash_gate_pending = False
            checks_total += 1
            gate_name = (
                "no-ecash-import gate "
                "(onchain+lightning variants ran mint-free)"
            )
            if "ecash" in sys.modules:
                print(f"FAIL  {gate_name}")
                failed.append((
                    gate_name,
                    "ecash.py was imported while only onchain- and "
                    "lightning-mode variants had run",
                ))
            else:
                print(f"PASS  {gate_name}")
                passed_paths.append(gate_name)
        path_str = "/".join(variant["path"])
        ok, err = _run_variant(variant)
        checks_total += 1
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
    print(f"passed: {len(passed_paths)}/{checks_total}")
    if failed:
        print(f"failed: {len(failed)}")
        for path_str, err in failed:
            print(f"  - {path_str}: {err}")
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
