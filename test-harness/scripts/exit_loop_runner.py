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
for state-changing ops in the default suite (writes stop at the
timing-layer acknowledgment; the runner never drains the queue -
the executor's real round-trips run under --live), so
infra-events.log records that fact rather than capturing real RPC
traffic. The read ops are
snapshot-served (doc 15): the gateway never reads a backend per
request, so read variants stage their snapshot via the
refresh_snapshots precondition, whose refresh sweep
(snapshots.refresh_due) reads a fake bitcoin-cli in onchain
(default) mode and a fake lncli in the advanced Lightning extension.
The local petcli eCash wallet commands exercise a fake cashu CLI
(petitioner-side, $PETCLI_CASHU_BIN) - the arbiter-side cashu
wrapper is never reached because eCash writes stop at the gateway
gates or the not_implemented dispatch stub. All three fakes are
installed below.

Per design-docs/origin/05--2026-05-05-0948-architecture-overview.md §10.
"""
import json
import os
import re
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
import snapshots  # noqa: E402
import standing_approvals  # noqa: E402
import timing  # noqa: E402, F401

# Structural no-LND guarantee: importing the gateway (and every other
# arbiter module above) must not pull in lnd.py. The LND wrapper is the
# advanced Lightning extension's dependency, imported lazily only by
# the executor's advanced-mode handlers and the snapshot refresh sweep
# (snapshots._read_backend). If this fires, some arbiter module
# regained a top-level lnd import and onchain (default) mode no longer
# runs LND-free. A second, runtime check fires in main() after all
# onchain-mode variants have run (see the no-lnd-import gate).
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

# Allowed submission denominations (doc 12 G2, arbiter/src/denominations.py).
# The gateway refuses any state-changing amount off this set before the
# registry / allowance / standing-approvals gates. This test deployment
# declares the exact sat-amounts its write variants submit as its
# allowed set (the union of every --amount-sats value and every
# --amount-msats value divided to sats: 1, 100, 500, 1000, 2000, 5000,
# 50000, 100000, 200000), so the denomination gate always PASSES here
# and every existing variant keeps exercising the registry / allowance /
# standing-approval / HITL path it was written for. The gate's own
# refusal path is exercised in-loop by the refused-denomination
# variants, whose amount 1234 is deliberately OFF this set (and stays
# off it: adding 1234 here would silently turn those variants into
# registry/allowance tests). Also covered by the gateway smoke, the
# denominations smoke, and the live sequence runner. Overrides the
# built-in ladder for this process only.
os.environ["SPACER_DENOMINATIONS"] = "1,100,500,1000,2000,5000,50000,100000,200000"

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
# by the seed_registry precondition so the new manage-bitcoin /
# manage-lightning variants can exercise the post-registry path
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
      subgrid)
        # 50_400 sat: floors to 50_000 on the doc 15 1k serve grid.
        printf '0.00050400'
        ;;
      subgrid-moved)
        # 50_900 sat: same grid cell as subgrid, so the move is
        # sub-grid and the served value must not transition.
        printf '0.00050900'
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
        verbatim). Used by the manage-bitcoin / manage-lightning
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
      ("refresh_snapshots",)
        Run one read-snapshot refresh sweep (snapshots.refresh_due,
        doc 15) - the arbiter-internal step the executor drainer
        performs on its randomized clock in production. Every read
        variant needs at least one: the gateway serves reads from
        the snapshot row and refuses uniformly before the first
        refresh. A missing row always counts as due, so the first
        sweep refreshes unconditionally.
      ("refresh_snapshots_forced",)
        Same sweep with a far-future cutoff, forcing a refresh even
        though the row's randomized next_refresh_at has not elapsed -
        the runner's stand-in for "the next epoch tick arrived"
        without a wall-clock wait (the drainer pattern used by
        execute_due_actions(now=)).
      ("set_scenario", env_key, value)
        Point one of the fake-backend scenario vars (e.g.
        BITCOIN_CLI_SCENARIO) at a different canned reply MID-
        variant, between two refreshes, so a variant can move the
        backend value underneath an existing snapshot. Only keys
        already managed per-variant by env_overrides are safe here
        (the teardown restore covers them).
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
    elif op == "refresh_snapshots":
        snapshots.refresh_due()
    elif op == "refresh_snapshots_forced":
        snapshots.refresh_due(now=time.time() + 1e9)
    elif op == "set_scenario":
        _, env_key, value = precondition
        os.environ[env_key] = value
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
# modes (gateway SPACER_MODE). Read ops are snapshot-served (doc 15):
# the refresh_snapshots precondition stands in for the executor
# drainer's randomized refresh clock, and it is the REFRESH - never
# the petitioner's request - that touches a backend:
#
# - onchain (default, SPACER_MODE unset): the query_balance refresh
#   reads arbiter/src/bitcoin.py against a fake bitcoin-cli the
#   runner installs at module-import time; manage_bitcoin exercises the
#   registry-miss refusal and both standing-approvals branches. The
#   extension ops (query_channels / manage_lightning / fund_ecash /
#   defund_ecash) are extension-gated (decision_refuse_mode):
#   recognized but disabled. The disabled WRITES defer the refusal to
#   a received-ack (sp-tb0); the disabled READ (query_channels) refuses
#   synchronously.
# - advanced (SPACER_MODE=lightning|full): the Lightning extension
#   layers query_channels / manage_lightning back on, and the
#   query_balance refresh reads the LND wallet instead of bitcoind -
#   all through arbiter/src/lnd.py against the fake lncli. The eCash
#   ops remain extension-gated (doc 07 §9: full is frozen at
#   onchain+lightning).
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
# The other registry-rejection subcases (expired / used / bad checksum
# / anomalous) become reachable with their own seed preconditions; their
# artifact directories stay absent per §10's "an empty one signals
# not-yet-validated". The happy-path sends (including fund/defund) now
# run the real executor: in the fake-backed suite the four allowed-by-
# standing-approval variants assert the timing-layer acknowledgment
# (_is_received_ack), and the live executor round-trips run under --live
# (see run_live_roundtrips).


def _is_received_ack(r):
    """The timing-layer acknowledgment - status 'received' plus an opaque
    handle the petitioner later polls (doc 05 §3, §4.6, §4.8) - with
    petcli's local estimate-window stamp (§5.2) layered on. The handle is
    random per call, so variants assert the shape, not an exact dict.

    As of sp-tb0 this is the shape a gate-REFUSED state-changing call
    returns too, not only a gate-passed one: a refusal is deferred through
    the result registry and acknowledged identically, so submit carries no
    pass-vs-refuse signal (GLOSSARY 'Recipient address registry'
    probing-infeasibility; doc 05 §4.7). The refused-* / parked-* variants
    and the allowed-by-standing-approval variants therefore share this
    exact predicate - they are wire-indistinguishable by construction, and
    the expected_audit_events (decision_refuse_* / decision_defer_hitl vs.
    standing_approval_match + decision_allow) are the only evidence that
    tells them apart, operator-side. The one exception is the READ mode
    gate (query_channels in onchain mode), which still refuses
    synchronously - reads are snapshot-served, never enqueued."""
    return (
        set(r) == {"status", "handle", "_petcli_estimate_window_s"}
        and r.get("status") == "received"
        and isinstance(r.get("handle"), str)
        and bool(r.get("handle"))
        and r.get("_petcli_estimate_window_s") == 30.0
    )


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
    # --- submit manage-bitcoin: the denomination gate (doc 12 G2) is
    # the FIRST write gate, ahead of the registry, so an off-ladder
    # amount refuses before any destination is resolved. 1234 is
    # deliberately outside this deployment's SPACER_DENOMINATIONS set
    # (see the env block near the top - and must stay outside it).
    {
        "path": ("submit", "manage-bitcoin", "refused-denomination"),
        "petcli_args": [
            "submit", "manage-bitcoin",
            "--to-token", "ABCDEF",
            "--amount-sats", "1234",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": _is_received_ack,
        "expected_audit_events": [
            "decision_refuse_denomination",
            "decision_defer_rejection",
        ],
        "forbidden_audit_events": [
            "decision_refuse_registry",
            "standing_approval_match",
            "decision_defer_hitl",
        ],
        "description": (
            "manage_bitcoin with amount_sats=1234, off the "
            "deployment's denomination set. The amount gate (doc 12 "
            "G2) refuses FIRST: the registry never runs "
            "(decision_refuse_registry must NOT appear even though "
            "token ABCDEF is unknown - that absence is the gate-order "
            "proof), no standing-approvals check, no HITL park. The "
            "refusal is DEFERRED like every write-gate refusal: the "
            "wire carries the same received-ack a pass returns; audit "
            "carries decision_refuse_denomination with the requested "
            "amount plus the decision_defer_rejection tail (handle + "
            "the rejection window's committed ready_at)."
        ),
    },
    # --- submit manage-bitcoin: the registry gate. State-changing ops
    # resolve through the recipient address registry (§4.7). Sending
    # with a token that is not in the registry (here, the made-up
    # 'ABCDEF') fails at the registry gate. The refusal is DEFERRED
    # (sp-tb0): the wire shape is the same received-ack a pass
    # returns, and the audit log carries decision_refuse_registry so the
    # operator can see *which* token failed and why. The advanced-
    # extension manage_lightning analogues live in the advanced-mode
    # group at the end of the manifest.
    {
        "path": ("submit", "manage-bitcoin", "refused-unknown-token"),
        "petcli_args": [
            "submit", "manage-bitcoin",
            "--to-token", "ABCDEF",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": _is_received_ack,
        "description": (
            "manage_bitcoin is a known write op; the gateway calls "
            "registry.lookup() on recipient_token=ABCDEF, which "
            "fails (bad checksum or unknown - either way non-`ok`). "
            "The refusal is DEFERRED: the gateway returns the same "
            "received-ack a gate-passed write returns (petcli stamps "
            "the §5.2 local 30s estimate on it), so submit is "
            "indistinguishable from a pass and the refusal surfaces "
            "only on a later poll. Audit logs decision_refuse_registry."
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
        "path": ("submit", "manage-bitcoin", "parked-no-standing-approval"),
        "petcli_args": [
            "submit", "manage-bitcoin",
            "--to-token", _VALID_TOKEN,
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            # No seed_standing_approvals: default-pause path.
        ],
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "manage_bitcoin with a valid (registry-resolved) recipient "
            "token but NO matching standing-approval rule. The "
            "registry resolves; the standing-approvals check fails "
            "(default-pause = empty config); the gateway HITL-parks "
            "and DEFERS the refusal (received-ack, not a synchronous "
            "refusal). arbiter-events.log must contain "
            "decision_defer_hitl with reason no_standing_approval, "
            "distinct from the refused-unknown-token variants' "
            "decision_refuse_registry."
        ),
    },
    {
        "path": ("submit", "manage-bitcoin", "allowed-by-standing-approval"),
        "petcli_args": [
            "submit", "manage-bitcoin",
            "--to-token", _VALID_TOKEN,
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            ("seed_standing_approvals", [
                {"op": "manage_bitcoin",
                 "destination": _VALID_TOKEN,
                 "max_amount_sats": 50000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": _is_received_ack,
        "expected_audit_events": ["standing_approval_match", "decision_allow",
                                  "action_enqueued"],
        "description": (
            "manage_bitcoin where the registry token resolves AND a "
            "standing-approval rule matches (op + destination + amount "
            "under max). Both gates pass; the gateway enqueues the write "
            "on the timing layer and acknowledges with an opaque handle "
            "(status 'received') - the real executor path, no "
            "not_implemented stub - which the petitioner later polls for "
            "the drained on-chain result. arbiter-events.log must "
            "contain standing_approval_match and decision_allow."
        ),
    },
    {
        "path": ("query", "balance", "default"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "expected_audit_events": ["snapshot_refresh", "balance_served"],
        "forbidden_audit_events": ["balance_read"],
        "description": (
            "query_balance in onchain (default) mode, snapshot-served "
            "(doc 15): the refresh precondition reads "
            "bitcoin.getbalance() via the fake bitcoin-cli (0.00050000 "
            "BTC), scales the BTC Decimal to 50_000 integer sats, "
            "routes it through scale.present() (50k is inside T0 so "
            "the cloak is a no-op), floors it onto the 1k serve grid "
            "(already aligned), and stores it; the petitioner's read "
            "then serves the row verbatim - the request path never "
            "touches bitcoind. Audit logs snapshot_refresh at refresh "
            "and balance_served (served value + snapshot age) at the "
            "read; the per-request balance_read event is gone (the "
            "runner asserts both directions)."
        ),
    },
    {
        "path": ("query", "balance", "empty-wallet"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "empty",
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 0,
        },
        "description": (
            "Same onchain refresh-then-serve path as the funded "
            "variant, but the fake bitcoin-cli reports 0.00000000 BTC "
            "under BITCOIN_CLI_SCENARIO=empty. 0 is inside T0 so the "
            "cloak is a no-op (scale 1.0), on-grid, and the wire "
            "response is balance_sats=0. Confirms the zero-balance "
            "edge without leaking the precise (zero) figure as a "
            "different status."
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
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Wallet real total 150_000 sat (0.00150000 BTC from the "
            "fake bitcoin-cli) -> natural tier T1. With no prior "
            "scale_state row, the refresh's scale.present() call "
            "initializes the cloak at T1 (test-mode deterministic "
            "scale 0.1) and presents 150_000 * 0.1 = 15_000 (on-grid); "
            "the read serves it verbatim. Confirms the cloak's init "
            "path picks the natural tier from a non-T0 wallet and the "
            "petitioner sees a sat figure compressed by an order of "
            "magnitude. Audit logs scale_tier_init."
        ),
    },
    {
        "path": ("query", "balance", "cloaked-tier-2"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-2",
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "description": (
            "Wallet real total 1_500_000 sat (0.01500000 BTC) -> "
            "natural tier T2 (scale 0.01). The refresh initializes at "
            "T2 and presents 1_500_000 * 0.01 = 15_000. The wire "
            "response is IDENTICAL to the cloaked-tier-1 variant "
            "despite the real total being 10x larger - that is the "
            "point of the cloak (GLOSSARY 'Scale cloaking'). Audit "
            "logs scale_tier_init."
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
            # The refresh's present() must NOT apply it yet; the
            # stored value comes from the OLD active scale (1.0), so
            # 150_000 * 1.0 = 150_000 is the wire response. This is
            # the GLOSSARY's 'drift > range' property: real grew past
            # 100k while active_tier is still T0, presented = 150_000
            # deliberately exceeds the 0-100k window.
            ("seed_scale_state", 0, 1.0, 1, 0.1, 3600.0),
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 150000,
        },
        "forbidden_audit_events": ["scale_tier_shift_applied"],
        "description": (
            "Pending tier shift, future due_at. scale_state was seeded "
            "with active_tier=0 / target_tier=1 / due_at=now+1h before "
            "the snapshot refresh; present(150_000) at refresh time "
            "sees the pending transition is not yet due, uses the OLD "
            "active scale (1.0), and stores 150_000. The presented "
            "value briefly falls outside the 0-100k cloak window - "
            "this is the GLOSSARY 'drift > range' property: privacy "
            "beats range-fidelity because forcing the range "
            "immediately would re-couple the tier shift to the "
            "underlying fund movement. Audit log does NOT contain "
            "scale_tier_shift_applied for this variant (the runner "
            "asserts the absence)."
        ),
    },
    {
        "path": ("query", "balance", "transition-applied"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-1",
        "preconditions": [
            # Seed: wallet was at T0; a transition to T1 was scheduled
            # 5s AGO. The refresh's present() must auto-apply the
            # shift, audit-log scale_tier_shift_applied, and store at
            # the new scale: 150_000 * 0.1 = 15_000.
            ("seed_scale_state", 0, 1.0, 1, 0.1, -5.0),
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 15000,
        },
        "expected_audit_events": ["scale_tier_shift_applied"],
        "description": (
            "Past-due tier shift applies at the epoch boundary (doc 15 "
            "invariant 2). scale_state was seeded with active_tier=0 / "
            "target_tier=1 / due_at=now-5s; the snapshot refresh "
            "drives present(150_000), which applies the pending shift "
            "atomically (active becomes T1 / 0.1, target_* cleared, "
            "audit-logs scale_tier_shift_applied) and stores 150_000 * "
            "0.1 = 15_000; the read serves it. The petitioner-visible "
            "drop from a presumably higher pre-shift served value "
            "(under the old T0 scale) to 15_000 lands exactly on a "
            "refresh epoch boundary and is by construction "
            "indistinguishable from a real send. arbiter-events.log "
            "MUST contain a scale_tier_shift_applied entry for this "
            "variant. The mid-epoch half of the invariant - a shift "
            "coming due between refreshes stays invisible - is the "
            "snapshot-shift-held-mid-epoch variant below."
        ),
    },
    # --- read-path snapshot serving (doc 15 §6): the four variants the
    # implementation bead names. Fresh serve is the baseline; the other
    # three each prove one invariant the per-request read could never
    # have provided: staleness across a real backend change (the whole
    # point - change timing is localized to the refresh epoch),
    # quantization hiding sub-grid churn entirely, and a tier shift
    # coming due mid-epoch staying invisible until a refresh boundary.
    # All four run onchain (default) mode; the treatment is rail-
    # uniform, and the capacity analog rides the advanced channel
    # variants' refresh preconditions.
    {
        "path": ("query", "balance", "snapshot-fresh-serve"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "expected_audit_events": ["snapshot_refresh", "balance_served"],
        "forbidden_audit_events": ["balance_read"],
        "description": (
            "Fresh serve (doc 15 §6 variant 1): one refresh (fake "
            "bitcoind 50_000 sat -> T0 no-cloak -> on-grid), then one "
            "read. The wire shape is unchanged from the pre-snapshot "
            "gateway (status ok + integer balance_sats; petcli "
            "untouched); what changed is where the figure came from - "
            "the snapshot row, not a live backend call. Audit: "
            "snapshot_refresh (refresh-time real/presented/served) "
            "plus balance_served (served value + snapshot age); no "
            "balance_read."
        ),
    },
    {
        "path": ("query", "balance", "snapshot-stale-across-change"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "preconditions": [
            # Snapshot taken while the wallet held 50_000 sat...
            ("refresh_snapshots",),
            # ...then the real balance moves to 150_000 sat (a 3x
            # change, and a tier-crossing one at that) with NO second
            # refresh - the next epoch tick has not arrived.
            ("set_scenario", "BITCOIN_CLI_SCENARIO", "tier-1"),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "expected_audit_events": ["snapshot_refresh", "balance_served"],
        "forbidden_audit_events": ["balance_read", "scale_tier_shift_scheduled"],
        "description": (
            "Stale serve across a change (doc 15 §6 variant 2): the "
            "backend moved 50_000 -> 150_000 sat after the last "
            "refresh, and the read still serves 50_000 - the change "
            "is invisible until the next refresh epoch, which is the "
            "entire mitigation (a poller cannot timestamp the move). "
            "Had the read path touched the live backend it would have "
            "returned 150_000 and scheduled a tier shift; the runner "
            "asserts the wire value AND the absence of "
            "scale_tier_shift_scheduled (present() never ran after "
            "the change - reads do not drive the cloak)."
        ),
    },
    {
        "path": ("query", "balance", "snapshot-quantization-edge"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "subgrid",
        "preconditions": [
            # First refresh: real 50_400 -> presented 50_400 (T0) ->
            # floors to 50_000 on the 1k serve grid.
            ("refresh_snapshots",),
            # The wallet churns by 500 sat WITHIN one grid cell...
            ("set_scenario", "BITCOIN_CLI_SCENARIO", "subgrid-moved"),
            # ...and the next epoch arrives (forced past the renewal
            # clock): real 50_900 still floors to 50_000.
            ("refresh_snapshots_forced",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "expected_audit_events": ["snapshot_refresh", "balance_served"],
        "description": (
            "Quantization edge (doc 15 §6 variant 3): two refreshes "
            "bracket a sub-grid change (50_400 -> 50_900 sat, both "
            "inside the [50_000, 51_000) cell of the 1k serve grid), "
            "and the served value never transitions - 50_000 before "
            "and after. Sub-grid operator churn produces NO petitioner-"
            "observable event at all (doc 15 §4.5 delta hygiene: the "
            "grid hides the existence of small changes, not just their "
            "size). The non-round backend figures also prove the floor "
            "quantization actually ran (nothing else in the pipeline "
            "rounds 50_400 to 50_000)."
        ),
    },
    {
        "path": ("query", "balance", "snapshot-shift-held-mid-epoch"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "bitcoin_cli_scenario": "tier-1",
        "preconditions": [
            # A tier shift is pending but far from due when the epoch's
            # refresh runs: present(150_000) stores under the OLD T0
            # scale (drift > range), served 150_000.
            ("seed_scale_state", 0, 1.0, 1, 0.1, 3600.0),
            ("refresh_snapshots",),
            # The shift comes due MID-epoch (due_at rewound to the
            # past, no refresh afterwards). A live-read gateway would
            # apply it on the next present() call and move the value
            # at poll resolution - leaking the shift moment.
            ("seed_scale_state", 0, 1.0, 1, 0.1, -5.0),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 150000,
        },
        "forbidden_audit_events": ["scale_tier_shift_applied"],
        "description": (
            "Epoch-boundary tier shift, mid-epoch half (doc 15 §6 "
            "variant 4, invariant 2): a pending tier shift becomes due "
            "BETWEEN refreshes and the read still serves the pre-shift "
            "150_000 - present() runs at refresh time only, so the "
            "shift cannot become visible mid-epoch and the glossary's "
            "fast-poller caveat (flagging the exact shift moment) is "
            "closed. The runner asserts scale_tier_shift_applied is "
            "absent: the petitioner's read did not drive the cloak. "
            "The boundary half - the shift landing at the NEXT refresh "
            "- is query/balance/transition-applied."
        ),
    },
    # --- extension gate: Lightning ops while the arbiter runs onchain
    # (default) mode. The ops are recognized but deliberately disabled;
    # the mode gate fires BEFORE the registry or standing-approvals
    # gates are consulted and audit-logs decision_refuse_mode (distinct
    # from decision_refuse_registry / decision_defer_hitl). A disabled
    # WRITE (manage_lightning) DEFERS the refusal to a received-ack; a
    # disabled READ (query_channels, next variant) refuses
    # synchronously. The send variant stages a resolvable token + a
    # matching standing-approval rule to prove the mode gate wins over
    # an otherwise-allowable call.
    {
        "path": ("advanced", "manage-lightning", "refused-onchain-mode"),
        "petcli_args": [
            "advanced", "manage-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            ("seed_standing_approvals", [
                {"op": "manage_lightning",
                 "destination": _VALID_TOKEN,
                 "max_amount_sats": 50000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "manage_lightning against an onchain (default) arbiter. The "
            "registry token resolves and a standing-approval rule "
            "matches - in advanced mode this exact call dispatches "
            "(advanced/manage-lightning/allowed-by-standing-approval) - "
            "but the mode gate refuses first: the op belongs to the "
            "disabled Lightning extension. Wire shape is the deferred "
            "received-ack (identical to a pass, so 'is Lightning on?' "
            "is not a submit-time oracle); arbiter-events.log carries "
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
            "SYNCHRONOUSLY without dispatching (lnd.py is never "
            "imported). arbiter-events.log carries decision_refuse_mode "
            "(the runner asserts the event). Unlike the write gates, a "
            "read refusal is NOT deferred - reads are snapshot-served "
            "and never enqueued, so there is no result handle to hand "
            "back (the read-path probing model is doc 15's; sp-tb0)."
        ),
    },
    # --- extension gate, eCash rung (doc 07 §9): the eCash writes are
    # recognized in every mode but honored only in ecash mode. Against
    # an onchain (default) arbiter they hit the same mode gate as the
    # Lightning WRITE ops and DEFER the refusal to a received-ack -
    # decision_refuse_mode, op field disambiguating which extension was
    # asked for - and ecash.py is never imported (the deferral enqueues
    # via the timing layer, not the mint; the no-ecash-import gate
    # asserts that later).
    {
        "path": ("advanced", "ecash", "fund", "refused-onchain-mode"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1000",
        ],
        "uses_arbiter": True,
        "preconditions": [],
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "fund_ecash against an onchain (default) arbiter. The op "
            "belongs to the disabled eCash extension, so the mode gate "
            "fires before any allowance or standing-approvals logic "
            "runs (arbiter/src/ecash.py is never imported - the "
            "deferral enqueues via the timing layer, which needs no "
            "eCash import). The refusal is deferred to a received-ack; "
            "arbiter-events.log carries decision_refuse_mode with reason "
            "advanced_extension_disabled, the op field telling the "
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
        "expected": _is_received_ack,
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
    # advanced-mode snapshot refresh lazily imports lnd.py
    # (snapshots._read_backend) and Python caches it for the rest of
    # the run; that is expected.
    # =================================================================
    {
        "path": ("query", "balance", "advanced-lnd-wallet"),
        "petcli_args": ["query", "balance"],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "bitcoin_cli_scenario": "empty",
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "description": (
            "query_balance in advanced mode: the refresh sweep reads "
            "the LND on-chain wallet (lnd.walletbalance() via the fake "
            "lncli, total_balance=50000) instead of bitcoind. The fake "
            "bitcoin-cli is pinned to the empty scenario (0 BTC) for "
            "this variant, so the 50_000-sat response proves the "
            "refresh took the LND path - had it read bitcoind, the "
            "wire response would be balance_sats=0. Same T0 no-cloak "
            "presentation as query/balance/default."
        ),
    },
    {
        "path": ("advanced", "channels", "default"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 80000,
        },
        "expected_audit_events": ["snapshot_refresh", "capacity_served"],
        "forbidden_audit_events": ["capacity_read"],
        "description": (
            "query_channels (petcli: advanced channels) with the "
            "extension enabled, snapshot-served (doc 15: capacity gets "
            "the same treatment as balance - capacity changes are "
            "public funding/closing txs, so their timestamps are "
            "maximally identifying). The refresh reads "
            "lnd.channelbalance() via the fake lncli (local=50000, "
            "remote=30000), aggregates to 80000, presents (T0 no-op), "
            "grids, and stores; the read serves it verbatim and audit-"
            "logs capacity_served (+ age), with capacity_read gone. "
            "Per-channel detail is suppressed (aggregate-by-default, "
            "§4.3). In advanced mode the sweep refreshes BOTH read "
            "ops, so this variant's audit also carries the balance "
            "row's snapshot_refresh."
        ),
    },
    {
        "path": ("advanced", "channels", "no-channels"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "spacer_mode": "full",
        "lncli_scenario": "no-channels",
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 0,
        },
        "description": (
            "Channels query when lncli reports zero local + zero "
            "remote capacity (LNCLI_SCENARIO=no-channels) at refresh "
            "time. 0 is inside T0 so the cloak is a no-op; the gateway "
            "serves capacity_sats=0, petitioner-visibly "
            "indistinguishable from any wallet that has channels but "
            "real capacity below the cloak's sub-tier resolution. Runs "
            "under SPACER_MODE=full to confirm the second advanced "
            "value enables the extension identically to 'lightning'."
        ),
    },
    {
        "path": ("advanced", "manage-lightning", "refused-unknown-token"),
        "petcli_args": [
            "advanced", "manage-lightning",
            "--to-token", "ABCDEF",
            "--amount-msats", "1000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [],
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_refuse_registry"],
        "description": (
            "Same registry-miss path as submit/manage-bitcoin/refused-"
            "unknown-token, but for the Lightning send op with the "
            "extension enabled. Audit logs decision_refuse_registry."
        ),
    },
    {
        "path": ("advanced", "manage-lightning", "parked-no-standing-approval"),
        "petcli_args": [
            "advanced", "manage-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
        ],
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "Same default-pause path as submit/manage-bitcoin/parked-no-"
            "standing-approval but for the Lightning send op with the "
            "extension enabled. amount_msats=1_000_000 (= 1000 sats "
            "post-ceiling) is irrelevant here because no rule exists; "
            "arbiter-events.log records decision_defer_hitl with "
            "reason no_standing_approval."
        ),
    },
    {
        "path": ("advanced", "manage-lightning", "allowed-by-standing-approval"),
        "petcli_args": [
            "advanced", "manage-lightning",
            "--to-token", _VALID_TOKEN,
            "--amount-msats", "1000000",
        ],
        "uses_arbiter": True,
        "spacer_mode": "lightning",
        "preconditions": [
            ("seed_registry", _VALID_TOKEN, _VALID_REAL, _VALID_FMT),
            ("seed_standing_approvals", [
                {"op": "manage_lightning",
                 "destination": _VALID_TOKEN,
                 "max_amount_sats": 50000,
                 "rationale": "exit-loop test rule"},
            ]),
        ],
        "expected": _is_received_ack,
        "expected_audit_events": ["standing_approval_match", "decision_allow",
                                  "action_enqueued"],
        "description": (
            "manage_lightning analogue of submit/manage-bitcoin/allowed-"
            "by-standing-approval, with the extension enabled. "
            "amount_msats=1_000_000 rounds up to 1000 sats; "
            "max_amount_sats=50000 admits it. Both gates pass; the "
            "gateway enqueues the write and acknowledges with a handle "
            "(status 'received') - the real executor path, no "
            "not_implemented stub. arbiter-events.log contains "
            "standing_approval_match and decision_allow."
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
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_refuse_mode"],
        "description": (
            "fund_ecash against a lightning-mode arbiter. The "
            "Lightning extension is on, but the eCash extension is "
            "its own opt-in rung (doc 07 §9): the mode gate fires "
            "(decision_refuse_mode) and DEFERS the refusal to a "
            "received-ack, and ecash.py stays unimported (the deferral "
            "goes through the timing layer, not the mint; the "
            "no-ecash-import gate asserts lightning-mode variants ran "
            "mint-free)."
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
        "expected": _is_received_ack,
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
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "balance_sats": 50000,
        },
        "description": (
            "query_balance under SPACER_MODE=ecash keeps its "
            "lightning-mode behavior - the refresh reads the LND "
            "on-chain wallet via the fake lncli (50_000 sat), NOT "
            "bitcoind (pinned to the empty scenario to prove which "
            "path refreshed) and NOT any eCash figure (doc 07 §9: no "
            "new read ops; the AI counts its own float locally). "
            "Ladder regression: ecash mode is lightning mode plus the "
            "eCash writes."
        ),
    },
    {
        "path": ("advanced", "channels", "ecash-mode"),
        "petcli_args": ["advanced", "channels"],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            ("refresh_snapshots",),
        ],
        "expected": lambda r: r == {
            "status": "ok",
            "capacity_sats": 80000,
        },
        "description": (
            "query_channels under SPACER_MODE=ecash: identical "
            "behavior to the lightning-mode default variant "
            "(local 50000 + remote 30000 = 80000, T0 no-cloak, "
            "snapshot-served). Ladder regression: enabling the eCash "
            "rung leaves the Lightning read surface exactly as it was."
        ),
    },
    # --- fund_ecash gate pipeline (doc 07 §3, §8): denomination gate
    # (doc 12 G2) -> allowance cap -> standing approvals -> dispatch.
    # The amount gate fires ahead of the allowance, so an off-ladder
    # amount refuses on shape before any float-headroom question.
    {
        "path": ("advanced", "ecash", "fund", "refused-denomination"),
        "petcli_args": [
            "advanced", "ecash", "fund",
            "--amount-sats", "1234",
        ],
        "uses_arbiter": True,
        "spacer_mode": "ecash",
        "preconditions": [
            # No seed_ecash_allowance: a consulted allowance would
            # refuse everything here (missing config reads as 0) and
            # log decision_refuse_allowance - so that event's absence
            # below is the gate-order proof.
        ],
        "expected": _is_received_ack,
        "expected_audit_events": [
            "decision_refuse_denomination",
            "decision_defer_rejection",
        ],
        "forbidden_audit_events": [
            "decision_refuse_allowance",
            "standing_approval_match",
            "decision_defer_hitl",
        ],
        "description": (
            "fund_ecash for 1234 sat - off the deployment's "
            "denomination set - in ecash mode with no allowance "
            "config. The amount gate refuses first (doc 12 G2 "
            "precedes the doc 07 §8 allowance): "
            "decision_refuse_denomination appears and "
            "decision_refuse_allowance does NOT, even though the "
            "missing-config allowance would refuse every fund. Same "
            "deferred-refusal wire shape as every write-gate refusal "
            "(received-ack; uniform failure surfaces only on a later "
            "poll)."
        ),
    },
    # --- fund_ecash allowance cap: fires after the amount gate and
    # ahead of standing approvals; config-bounded (a HITL approval
    # cannot exceed it).
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
        "expected": _is_received_ack,
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
        "expected": _is_received_ack,
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
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "fund_ecash inside the allowance (1000 of 50_000) but "
            "with NO standing-approval rule: the allowance gate "
            "passes, the standing-approvals check fails (default-"
            "pause = empty config), the gateway HITL-parks and DEFERS "
            "the refusal (received-ack). arbiter-events.log carries "
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
        "expected": _is_received_ack,
        "expected_audit_events": ["standing_approval_match", "decision_allow",
                                  "action_enqueued"],
        "description": (
            "fund_ecash where the allowance admits the amount AND a "
            "standing-approval rule matches (op fund_ecash, "
            "destination 'mint' - the structural constant for eCash "
            "ops, doc 07 §3 - amount under max). Both gates pass; the "
            "gateway enqueues the fund and acknowledges with a handle "
            "(status 'received'); the executor drains it against the "
            "pinned mint + our LND (run under --live). arbiter-"
            "events.log contains standing_approval_match and "
            "decision_allow."
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
        "expected": _is_received_ack,
        "expected_audit_events": ["decision_defer_hitl"],
        "description": (
            "defund_ecash in ecash mode with no standing-approval "
            "rule: no allowance check applies (defund only shrinks "
            "the float), the standing-approvals default-pause parks "
            "it in HITL and DEFERS the refusal (received-ack). "
            "arbiter-events.log carries decision_defer_hitl with reason "
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
        "expected": _is_received_ack,
        "expected_audit_events": ["standing_approval_match", "decision_allow",
                                  "action_enqueued"],
        "description": (
            "defund_ecash with an unbounded standing-approval rule "
            "(op defund_ecash, destination 'mint', no amount bound): "
            "the gate passes, the gateway enqueues the defund and "
            "acknowledges with a handle (status 'received'); the "
            "executor drains it - swap-claim at the pinned mint, melt "
            "to our LND (run under --live). arbiter-events.log contains "
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
                "# onchain (default) mode - SPACER_MODE unset. Reads are "
                "snapshot-served (doc 15): the refresh_snapshots "
                "precondition reads arbiter/src/bitcoin.py against the "
                "fake bitcoin-cli at $BITCOIN_CLI_BIN, and the petcli "
                "read itself never touches a backend; write variants stop "
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
                "§9). Reads are snapshot-served (doc 15): the "
                "refresh_snapshots precondition reads arbiter/src/lnd.py "
                "(the LND wallet backs query_balance in this mode, and "
                "query_channels always) against the fake lncli at "
                "$LNCLI_BIN; eCash writes stop at the allowance / "
                "standing-approvals gates or the not_implemented dispatch "
                "stub before any mint call - arbiter/src/ecash.py is "
                "imported only for the fund_ecash allowance lookup and no "
                "cashu subprocess ever runs (CASHU_BIN / CASHU_MINT_URL "
                "are deliberately unset; an unexpected arbiter-side mint "
                "call would error loudly). No live bitcoind / LND / mint "
                "traffic for any variant in the current manifest.\n"
            )
        else:
            infra_note = (
                f"# advanced mode - SPACER_MODE={variant['spacer_mode']}. "
                "Reads are snapshot-served (doc 15): the "
                "refresh_snapshots precondition reads arbiter/src/lnd.py "
                "(the LND wallet backs query_balance in this mode, and "
                "query_channels always) against the fake lncli at "
                "$LNCLI_BIN, and the petcli read itself never touches a "
                "backend; Lightning writes stop at the registry / "
                "standing-approvals gates or the not_implemented dispatch "
                "stub; eCash-extension ops refuse at the mode gate "
                "(decision_refuse_mode - the eCash rung is its own "
                "opt-in; arbiter/src/ecash.py stays unimported, the "
                "runner asserts it). No live bitcoind / LND / mint "
                "traffic for any variant in the current manifest.\n"
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
        # deliberately uniform across causes (§4.1) - and, as of sp-tb0,
        # uniform with a gate-PASS too: a refused write defers and
        # returns the same received-ack a passed write returns (doc 05
        # §4.7). So a variant whose whole point is WHICH gate fired (mode
        # gate vs. registry miss vs. allowance vs. standing-approvals
        # park), or even WHETHER one fired, cannot be told apart by the
        # response alone; the distinguishing audit event in
        # arbiter-events.log is the only evidence, and the runner checks
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


# === Live signet round-trips (--live) ===============================
#
# The default suite above is fake-backed and proves the gateway hands
# every gate-passed write to the timing layer (status 'received', not
# the old not_implemented stub). --live adds the other half of the
# acceptance bar: it drives the SAME executor the gateway enqueues to
# against the real Mutinynet signet infra - the LND node and the mint -
# and exercises all four write ops for real. The three round-trips
# cover the four ops: an on-chain send (manage_bitcoin), a Lightning pay
# (manage_lightning), and an eCash mint+melt (fund_ecash + defund_ecash).
# Each asserts a real executor result (sent / funded / defunded), never
# a failure or the not_implemented stub.
#
# No bitcoind runs in this deployment, so manage_bitcoin uses the LND
# on-chain wallet (lnd.sendcoins) under SPACER_MODE=ecash - the same
# backend split query_balance already makes (gateway._dispatch). The
# round-trips force-drain (now=far) past the action/result delay
# windows; the handlers' own mint-boundary gaps (doc 07 §6 T1) still
# run.

_LIVE_LNCLI = Path.home() / "spacer" / "arbiter" / "bin" / "lncli"
_LIVE_LND_DIR = Path.home() / "spacer" / "arbiter" / "lnd"
_LIVE_CASHU = Path.home() / "spacer" / "arbiter" / "bin" / "cashu"
_LIVE_RPCSERVER = "first-test.u.voltageapp.io:10009"
_LIVE_MINT_URL = "https://cashu.mutinynet.com"


def _live_env():
    """Point the backend wrappers at the real signet infra, overriding
    the fake binaries the module installed at import. Each wrapper reads
    these per call, so setting them before driving the executor is
    enough. SPACER_MODE=ecash selects the LND on-chain wallet for
    manage_bitcoin and arms the eCash writes; SPACER_TIMING_MODE=test
    keeps the windows short and supplies the mint-boundary gaps. The
    longer timeouts cover live LN pathfinding / mint round-trips.

    The arbiter cashu wallet uses a FRESH temp CASHU_DIR per run, not
    the persistent ~/spacer/arbiter/ecash: that wallet accumulates
    stuck pending proofs across runs (the residue of any melt that does
    not settle) which corrupt a later receive/melt, making the gate
    flaky. A clean dir per run keeps the round-trip deterministic; the
    real mint + LND node are still exercised - only the local wallet DB
    is test-scoped. No CASHU_WALLET: ecash.py uses the default wallet
    (a named wallet breaks nutshell 0.18.1 `receive`)."""
    os.environ["LNCLI_BIN"] = str(_LIVE_LNCLI)
    os.environ["LNCLI_RPCSERVER"] = _LIVE_RPCSERVER
    os.environ["LNCLI_TLSCERT"] = str(_LIVE_LND_DIR / "tls.cert")
    os.environ["LNCLI_MACAROON"] = str(_LIVE_LND_DIR / "admin.macaroon")
    os.environ["LNCLI_NETWORK"] = "signet"
    os.environ["LNCLI_TIMEOUT_S"] = "120"
    os.environ["CASHU_BIN"] = str(_LIVE_CASHU)
    os.environ["CASHU_MINT_URL"] = _LIVE_MINT_URL
    os.environ.pop("CASHU_WALLET", None)
    os.environ["CASHU_DIR"] = tempfile.mkdtemp(prefix="exit-loop-live-arb-")
    os.environ["CASHU_TIMEOUT_S"] = "120"
    os.environ["SPACER_MODE"] = "ecash"
    os.environ["SPACER_TIMING_MODE"] = "test"


def _ai_custody_hop(token):
    """Pass a fund token through a separate petitioner-side cashu wallet
    - receive, then re-send - so it returns as a fresh token whose
    proofs the arbiter has NOT already minted.

    This mirrors the doc 07 §3 custody split: the AI holds the float in
    its own wallet, and a defund returns a token the AI re-serialized.
    nutshell will not swap-claim a token whose proofs are already in the
    receiving wallet, so the arbiter cannot defund its own just-minted
    token directly; the hop is what makes the live defund a genuine
    round-trip. Uses the default wallet in its own CASHU_DIR (named
    wallets break `receive`)."""
    pet_dir = tempfile.mkdtemp(prefix="exit-loop-live-pet-")
    env = dict(os.environ, CASHU_DIR=pet_dir)
    base = [str(_LIVE_CASHU), f"--host={_LIVE_MINT_URL}"]

    def run(*a):
        return subprocess.run(
            base + list(a), capture_output=True, text=True, timeout=120, env=env
        )

    r = run("receive", token)
    if r.returncode != 0:
        raise RuntimeError(f"AI-hop receive failed: {r.stderr.strip()[:150]}")
    m = re.search(r"Balance:\s*([0-9]+)\s*sat", run("balance").stdout)
    amount = int(m.group(1)) if m else 0
    if amount <= 0:
        raise RuntimeError("AI-hop wallet empty after receive")
    s = run("send", "-y", "-d", str(amount))
    m2 = re.search(r"(cashu[AB][A-Za-z0-9_=-]{20,})", s.stdout)
    if not m2:
        raise RuntimeError(f"AI-hop send produced no token: {s.stdout.strip()[:150]}")
    return m2.group(1)


def _lncli_json(*args):
    """Call the real lncli with the connection flags and parse its JSON
    stdout. Live-test setup only (a fresh receive address); the executor
    itself drives lnd.py, not this helper."""
    cmd = [
        str(_LIVE_LNCLI),
        f"--rpcserver={_LIVE_RPCSERVER}",
        f"--tlscertpath={_LIVE_LND_DIR / 'tls.cert'}",
        f"--macaroonpath={_LIVE_LND_DIR / 'admin.macaroon'}",
        "--network=signet",
    ] + [str(a) for a in args]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError(f"lncli {args}: {proc.stderr.strip()}")
    return json.loads(proc.stdout)


def _live_audit_field(live_dir, event, field):
    """Best-effort: the `field` from the latest audit record of `event`
    in the live run's log, or None. For the human-readable fee / txid
    report lines only (audit payload, doc 05 §4.5)."""
    log = live_dir / "audit.log"
    if not log.exists():
        return None
    found = None
    for line in log.read_text().splitlines():
        if not line.strip():
            continue
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if rec.get("event") == event:
            found = (rec.get("payload") or {}).get(field, found)
    return found


def _drive_executor(handle, op, params, far):
    """Enqueue one action and force-drain it through the real executor -
    the production execute -> deliver -> poll path - returning
    (poll_status, payload). now=far bypasses the action/result delay
    windows so the live test does not wait them out; the handler's own
    mint-boundary sleeps still run."""
    import executor
    timing.enqueue_action(handle, op, params)
    executor.execute_due_actions(now=far)
    executor.deliver_due_results(now=far)
    status, payload, _kind = results.poll(handle)
    return status, payload


def run_live_roundtrips():
    """Run the three live signet round-trips against the real LND node
    and mint, driving the same executor the gateway enqueues to. Returns
    True iff all three pass. Prints a PASS/FAIL line per round-trip plus
    the operator-side fees (funded != received, doc 07 §10.4) from the
    audit log; on any failure it dumps the live audit events so the
    cause is debuggable."""
    print()
    print("--- live signet round-trips (--live) ---")
    _live_env()

    live_dir = Path(tempfile.mkdtemp(prefix="exit-loop-live-"))
    audit.configure(live_dir / "audit.log")
    state.configure(live_dir / "state.db")
    state.migrate()
    import ecash
    import executor  # noqa: F401  (used via _drive_executor)
    far = time.time() + 10_000.0

    oks = []

    # --- round-trip 1: manage_bitcoin (on-chain, LND wallet) ----------
    try:
        addr = _lncli_json("newaddress", "p2wkh")["address"]
        status, payload = _drive_executor(
            "live_manage_bitcoin", "manage_bitcoin",
            {"recipient_address": addr, "amount_sats": 2000}, far,
        )
        ok = status == "result" and payload.get("status") == "sent"
        txid = _live_audit_field(live_dir, "manage_bitcoin_executed", "txid")
        print(f"{'PASS' if ok else 'FAIL'}  live/manage_bitcoin  "
              f"(2000 sat on-chain -> {addr}; txid={txid})")
        if not ok:
            print(f"      -> result={payload}")
        oks.append(ok)
    except Exception as e:
        print(f"FAIL  live/manage_bitcoin  -> {e}")
        oks.append(False)

    # --- round-trip 2: manage_lightning (pay a bolt11 over the channel)
    # A fresh mint quote is a real, payable bolt11 that routes over our
    # one channel (us -> faucet -> mint), exercising lnd.payinvoice end
    # to end; we pay it without issuing proofs (the value parks at the
    # mint, a small deliberate test cost).
    try:
        bolt11, _qid = executor._parse_mint_quote(ecash.mint_quote(100))
        status, payload = _drive_executor(
            "live_manage_lightning", "manage_lightning",
            {"recipient_address": bolt11, "amount_sats": 100}, far,
        )
        ok = status == "result" and payload.get("status") == "sent"
        fee = _live_audit_field(
            live_dir, "manage_lightning_executed", "ln_routing_fee_msat"
        )
        print(f"{'PASS' if ok else 'FAIL'}  live/manage_lightning  "
              f"(100 sat; routing_fee_msat={fee})")
        if not ok:
            print(f"      -> result={payload}")
        oks.append(ok)
    except Exception as e:
        print(f"FAIL  live/manage_lightning  -> {e}")
        oks.append(False)

    # --- round-trip 3: eCash fund 5000 -> AI hop -> defund ----------
    # Fund pushes 5000 outbound (creating the inbound the defund needs);
    # the token then passes through a petitioner wallet (the AI custody
    # hop, doc 07 §3) so the arbiter defunds a token it did not mint;
    # defund melts back a fresh invoice sized below 5000 for the mint's
    # melt-fee reserve, so funded (5000) != received (credited).
    try:
        s_fund, p_fund = _drive_executor(
            "live_fund_ecash", "fund_ecash", {"amount_sats": 5000}, far,
        )
        fund_ok = (
            s_fund == "result"
            and p_fund.get("status") == "funded"
            and isinstance(p_fund.get("token"), str)
            and p_fund["token"].startswith("cashu")
        )
        fund_fee = _live_audit_field(
            live_dir, "ecash_fund_executed", "ln_routing_fee_msat"
        )
        print(f"{'PASS' if fund_ok else 'FAIL'}  live/ecash_fund  "
              f"(5000 sat minted; ln_routing_fee_msat={fund_fee})")
        if not fund_ok:
            print(f"      -> result={p_fund}")
        defund_ok = False
        if fund_ok:
            defund_token = _ai_custody_hop(p_fund["token"])
            s_def, p_def = _drive_executor(
                "live_defund_ecash", "defund_ecash",
                {"token": defund_token}, far,
            )
            defund_ok = s_def == "result" and p_def.get("status") == "defunded"
            credited = _live_audit_field(
                live_dir, "ecash_defund_executed", "credited_sats"
            )
            melt_fee = _live_audit_field(
                live_dir, "ecash_defund_executed", "melt_fee_sat"
            )
            claimed = p_def.get("amount_sats") if isinstance(p_def, dict) else None
            print(f"{'PASS' if defund_ok else 'FAIL'}  live/ecash_defund  "
                  f"({claimed} claimed; credited={credited}, "
                  f"melt_fee_sat={melt_fee})")
            if not defund_ok:
                print(f"      -> result={p_def}")
        oks.append(fund_ok and defund_ok)
    except Exception as e:
        print(f"FAIL  live/ecash_roundtrip  -> {e}")
        oks.append(False)

    all_ok = len(oks) == 3 and all(oks)
    print()
    print(f"live round-trips: {sum(1 for o in oks if o)}/3 passed")
    if not all_ok:
        log = live_dir / "audit.log"
        if log.exists():
            print("--- live audit events ---")
            print(log.read_text())
    return all_ok


# === Driver =========================================================

def main(argv=None):
    """Run every variant, populate exit-loop/petcli/, print a per-
    variant pass/fail line and a summary.

    The runner clears exit-loop/petcli/ at the start so the on-disk
    artifact set always reflects the current manifest run. exit-loop/
    README.md is left in place (documentation, not a run artifact).

    Default (no flags): exit 0 only when every fake-backed variant
    passes; the §10 closed loop terminates only on that condition.

    --live: ALSO run the three live signet round-trips against the real
    LND node + mint (run_live_roundtrips), exercising all four write
    ops through the real executor. Exit 0 only when the fake-backed
    suite AND all three live round-trips pass - the sp-uwa0v0 acceptance
    bar. If the fake-backed suite fails the live round-trips are skipped
    (the wiring is already broken; no point spending real sats).
    """
    argv = sys.argv[1:] if argv is None else argv
    live = argv == ["--live"]
    if argv and not live:
        # Unknown flags fail loudly. The only option is --live; anything
        # else is surfaced rather than silently ignored.
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

    # The mint-contract gate (design doc 10 §3; impl companion §2):
    # the build-time cashu CLI contract test under arbiter/ops/. Its
    # parser fixtures run everywhere; the live layer (version pin +
    # ephemeral loopback mint + settled/pending melt + DLEQ-at-
    # receive) runs when the pinned nutshell CLI is installed and
    # self-SKIPs otherwise, so this suite stays hermetic on mint-less
    # checkouts while a checkout with the CLI cannot land green on a
    # drifted or DLEQ-regressed nutshell. A subprocess, not an
    # import: the contract test re-execs into the nutshell python and
    # spawns a mint, none of which may perturb this runner's
    # in-process arbiter (or its no-ecash-import bookkeeping).
    checks_total += 1
    gate_name = "mint-contract gate (build-time cashu CLI contract)"
    contract_script = (
        REPO_ROOT / "arbiter" / "ops" / "mint_contract_test.py"
    )
    try:
        gate_proc = subprocess.run(
            [sys.executable, str(contract_script)],
            capture_output=True,
            text=True,
            timeout=300,
        )
        gate_ok = gate_proc.returncode == 0
        gate_err = "" if gate_ok else " | ".join(
            line for line in (
                gate_proc.stdout + gate_proc.stderr
            ).strip().splitlines()[-12:] if line.strip()
        )
    except subprocess.TimeoutExpired:
        gate_ok = False
        gate_err = "mint contract test timed out after 300s"
    if gate_ok:
        print(f"PASS  {gate_name}")
        passed_paths.append(gate_name)
    else:
        print(f"FAIL  {gate_name}")
        failed.append((gate_name, gate_err))
        print(f"      -> {gate_err}")

    print()
    print(f"--- exit-loop summary ---")
    print(f"passed: {len(passed_paths)}/{checks_total}")
    if failed:
        print(f"failed: {len(failed)}")
        for path_str, err in failed:
            print(f"  - {path_str}: {err}")

    if not live:
        return 0 if not failed else 1

    # --live: the fake-backed suite must pass before spending real sats.
    if failed:
        print()
        print("skipping live round-trips: fake-backed suite failed")
        return 1
    return 0 if run_live_roundtrips() else 1


if __name__ == "__main__":
    sys.exit(main())
