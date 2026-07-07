# arbiter/ops/

Operational scaffolding for the deployed arbiter. The snapshot and
audit pieces are reference-only until the operator installs them;
the mint contract test is active in every build via the exit-loop
suite.

Three concerns live here:

- **Continuous git snapshot** (this directory): the per-minute cron
  loop that commits the arbiter tree, plus reference deployment
  units for launchd and systemd. See
  `../../design-docs/origin/06--2026-05-24-0623-arb-auditability.md`.
- **Manual audit scripts** (`audit/`): operator-facing wrappers that
  translate the snapshot history into plain English. See §8 of the
  same design doc.
- **Build-time mint contract test** (`mint_contract_test.py`): fails
  the build when the cashu (nutshell) CLI drifts from the parse
  contract the eCash rail depends on. See below.

## Files in this directory

| File | Role |
|------|------|
| `snapshot.sh` | The actual cron loop body. Trivial by design - three git commands. |
| `snapshot.launchd.plist` | macOS launchd reference unit. Per-minute via `StartInterval`. |
| `snapshot.service` | Linux systemd service unit. Type=oneshot; paired with the timer. |
| `snapshot.timer` | Linux systemd timer driving snapshot.service every minute. |
| `audit/` | Manual audit scripts (`arb-today`, `arb-since`, ...). See `audit/README.md`. |
| `mint_contract_test.py` | Build-time cashu CLI contract gate (design doc 10 §3). Run by the exit-loop suite. |

## Build-time mint contract test

Design doc 10 §3 requires that a cashu CLI output drift or a DLEQ
verification regression fail the **build**, not the M1/M2 monitoring
signals silently at runtime. `mint_contract_test.py` is that gate:
it pins the CLI version to `../config/cashu-pin.yaml`, asserts the
arbiter's melt-settlement parser against a settled AND a pending
melt driven through the real CLI (the pending-exit-0 trap), and
asserts a corrupted-DLEQ proof is rejected at receive. Mechanics,
layers, and environment knobs are in the script's docstring.

It runs on every exit-loop suite invocation
(`test-harness/scripts/exit_loop_runner.py`). Checkouts without the
pinned CLI installed run the parser-fixture layer and skip the live
layer; an eCash deployment build sets `MINT_CONTRACT_REQUIRE_CLI=1`
so a missing CLI is itself a failure. Bumping the nutshell version
is therefore always a reviewed change: install the new CLI, update
the pin, and let this test re-verify the parse contract before
anything lands.

## First-deploy bootstrap

The snapshot loop assumes the arbiter root is already a git
repository. On a fresh install:

```sh
cd /path/to/arbiter
git init
git add -A
git commit -m 'initial'
```

That one-shot bootstrap establishes the baseline; the cron then
appends commits over time. Re-bootstrapping is destructive (it
discards the prior snapshot history), so do it once at install time
and never again.

## Install (per platform)

Pick one. Both substrates run the same `snapshot.sh`; the choice is
about which scheduler is already managing the host.

### macOS (launchd, user agent)

```sh
# 1. Edit snapshot.launchd.plist and replace /Users/operator/arbiter
#    with your actual arbiter root. Update the WorkingDirectory and
#    the ProgramArguments path together.
cp snapshot.launchd.plist ~/Library/LaunchAgents/spacer.arbiter.snapshot.plist
launchctl load ~/Library/LaunchAgents/spacer.arbiter.snapshot.plist
```

Verify with `audit/arb-status` within a minute; it should report a
commit within the last 60 seconds.

### Linux (systemd, user units)

```sh
# 1. Edit snapshot.service and replace /opt/arbiter with your actual
#    arbiter root. Remove the User= line if installing as a user
#    unit. Update snapshot.timer if you want a different cadence.
mkdir -p ~/.config/systemd/user
cp snapshot.service snapshot.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now spacer-arbiter-snapshot.timer
```

Verify with `audit/arb-status`.

### Plain crontab (any UNIX)

```cron
* * * * * /path/to/arbiter/ops/snapshot.sh
```

Cron has no per-minute retry; if a firing is missed (machine off,
load spike) the next minute picks up. The snapshot loop body is
idempotent so there is no harm in running it more or less than once
per minute - it commits only when there is change.

## Cadence tuning

The design fixes cadence at one minute (06-- §4: lower risks missing
edits to outages between save and snapshot; higher grows history
without telling us anything new). If you have a reason to deviate,
the only knob is the timer / launchd cadence; everything else in the
loop is fixed by design.
