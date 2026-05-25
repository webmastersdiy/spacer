# arbiter/ops/

Operational scaffolding for the deployed arbiter. Reference only;
nothing here is active until the operator installs and enables it.

Two concerns live here:

- **Continuous git snapshot** (this directory): the per-minute cron
  loop that commits the arbiter tree, plus reference deployment
  units for launchd and systemd. See
  `../../design-docs/origin/06--2026-05-24-0623-arb-auditability.md`.
- **Manual audit scripts** (`audit/`): operator-facing wrappers that
  translate the snapshot history into plain English. See §8 of the
  same design doc.

## Files in this directory

| File | Role |
|------|------|
| `snapshot.sh` | The actual cron loop body. Trivial by design - three git commands. |
| `snapshot.launchd.plist` | macOS launchd reference unit. Per-minute via `StartInterval`. |
| `snapshot.service` | Linux systemd service unit. Type=oneshot; paired with the timer. |
| `snapshot.timer` | Linux systemd timer driving snapshot.service every minute. |
| `audit/` | Manual audit scripts (`arb-today`, `arb-since`, ...). See `audit/README.md`. |

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
