# Arb-auditability via continuous git snapshot

**Date:** 2026-05-24
**Context:** A second audit primitive on the arbiter, complementing the in-process [audit log](../../GLOSSARY.md#audit-log). This one captures *what was deployed and configured* over time, not *what was requested at runtime*.
**Related:**
- `../../GLOSSARY.md#audit-log` - the existing runtime audit log (per-request decisions, append-only).
- `05--2026-05-05-0948-architecture-overview.md#21-arbiter-implementation-discipline` - the manual-auditability discipline this doc operationalizes.
- `05--2026-05-05-0948-architecture-overview.md#45-audit-log` - runtime audit log section.

---

## 1. Purpose and scope

The [arbiter](../../GLOSSARY.md#arbiter) is the trust anchor. Per §2.1 of the architecture overview, it must be small enough that a non-AI human can read every line and convince themselves the gateway is the only path through. That discipline only holds if *what is actually running* matches *what was reviewed*, and stays matched over time.

Today the runtime audit log records every request and every decision the running gateway made. That covers behavior but not provenance: it does not show that the code on disk yesterday is the code on disk today, nor that a config file the operator edited at noon was edited by the operator (not by a process that should not have write access).

This doc defines a second audit primitive: a **continuous git snapshot** of the arbiter's deployed code and configuration. A cron-driven job commits the arbiter's tree to a local git repository every minute. The resulting history answers, for any point in time:

- What code was deployed?
- What was the config?
- Did anything change since the last snapshot? If so, what diff?

Out of scope: the runtime audit log (already covered by §4.5 of the architecture overview); intrusion detection alarms or alerting (this primitive produces the evidence, not the notification path); shipping snapshots off-host (open question, §6).

---

## 2. The two audit primitives

The arbiter now has two complementary audit primitives:

| Primitive | What it captures | Granularity | Lifecycle |
|-----------|------------------|-------------|-----------|
| Runtime audit log (§4.5) | Every request and every gateway decision | Per-request | Append-only, never edited |
| Git snapshot (this doc) | The arbiter's deployed code + config on disk | Per-minute | Periodic commits to a local repo |

Neither subsumes the other. A request that the gateway refuses appears in the runtime log; a config edit that *would have* changed how the gateway refuses appears in the snapshot history. An attacker who edits gateway source to weaken a check leaves a fingerprint in the snapshot history; the runtime log alone would only show that future requests started being decided differently.

---

## 3. Required arbiter layout

The continuous snapshot only works if the arbiter's directory structure separates the things that *should* be in the snapshot from the things that should not. Without that separation the snapshot is noise: a runtime SQLite WAL ticking over every few seconds would produce a meaningless commit every minute and bury the signal under thrash.

The arbiter tree splits into four kinds of content:

```
arbiter/
  src/          # Python source - changes only on a deploy
  config/       # operator-editable config (YAML) - changes on edits
  bin/          # built binaries / wrappers - changes only on a deploy
  state/        # runtime SQLite, WAL files, scratch - GITIGNORED
  bitcoin/      # bitcoind datadir - GITIGNORED
  lnd/          # LND datadir - GITIGNORED
  data/         # any other transient runtime - GITIGNORED
```

The first three are part of the snapshot; the rest are excluded by `.gitignore` and never appear in commit diffs.

The arbiter implementation invariant this requires: **no module writes transient files outside the gitignored subtrees**. A module that drops a scratch file into `src/` or `config/` would generate a snapshot commit every minute it exists, polluting the history. Concretely:

- SQLite databases and their `-wal` / `-shm` sidecars live under `state/`.
- The runtime audit log file lives under `state/` (the file is append-only but it changes constantly, so it does not belong in the snapshot history; its own integrity is covered by the §4.5 mechanism).
- Per-process scratch and lock files live under `state/` or `data/`.
- Build artifacts, if any, land under `bin/` only after the build completes (no intermediate `*.o` / `*.pyc` chatter in `src/`).

The runner-style temp directories already used elsewhere in the codebase (e.g., `tempfile.mkdtemp` in the exit-loop runner) are unaffected: those land in the system temp directory, well outside the arbiter tree.

---

## 4. The snapshot cron

The cron job is intentionally trivial. The whole design rests on the fact that there is *nothing clever* in the snapshot loop - a non-AI reviewer can read it in five seconds.

```sh
cd /path/to/arbiter
git add -A
git diff --cached --quiet || git commit -q -m "snapshot: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

- `git add -A` stages every change in the tree (respecting `.gitignore`).
- `git diff --cached --quiet` returns non-zero when there is something staged. The `||` clause therefore commits only when there is real change; quiescent minutes produce no commit.
- The commit message is a UTC timestamp so `git log` reads chronologically by message even without rewriting committer dates.

Cadence: every minute. Lower than that and a fast-fingered operator edit can be missed by an outage between save and snapshot; higher than that and the history grows without telling us anything new.

Cadence is the only tunable; everything else (paths, commit message, ignore set) is fixed.

The cron substrate (launchd on macOS, systemd timer on Linux, plain crontab) is a deployment detail, not a design choice. The job is small enough that any of them is fine.

---

## 5. What the operator gets

The operator works at the directly-attached arbiter console (the same KVM used for [HITL](../../GLOSSARY.md#human-in-the-loop-approval) and the [recipient address registry](../../GLOSSARY.md#recipient-address-registry)). From that console, the snapshot history is queried with the standard git porcelain:

- `git log --since=1.day` - everything that changed in the last day.
- `git log -- config/` - only operator-facing config changes (answers "did anyone edit the config?").
- `git log -- src/ bin/` - only deploys (answers "did a release land?").
- `git diff HEAD~10 HEAD -- src/` - what changed in the source across the last ten snapshots.
- `git blame config/destinations.yaml` - per-line provenance of a config file.
- `git log --grep snapshot --since=2026-05-20` filtered by author / message for forensics.

The split between `src/` + `bin/` (deploys) and `config/` (operator edits) is the load-bearing distinction. A typical week should produce many `config/` commits (operator activity) and few `src/` / `bin/` commits (deploys are rare events). A burst of `src/` commits outside a deploy window is by itself a flag.

---

## 6. Open design questions

- **Repo location.** Same volume as the arbiter or a separate volume? Same-volume is simpler; separate-volume survives a disk failure or rootkit that targets the arbiter tree. Recommendation: separate, with a write-only path from the arbiter to the snapshot volume.
- **Signing.** Should snapshot commits be signed with an operator-held GPG key? Signing makes tampering with history detectable; it also introduces key management on the arbiter. Defer until the deployment story has a clear answer on where the signing key lives.
- **Off-host backup.** Pushing snapshots to a remote git host gives off-machine durability but introduces an egress network path on the arbiter (a privacy concern - currently the arbiter has no outbound network beyond bitcoind/LND). If we want it, the path is via the same out-of-band channel as HITL: the operator manually mirrors the repo from the console, not the arbiter itself.
- **Pruning.** The arbiter is expected to run for years; the snapshot repo grows. Periodic `git gc --aggressive` is safe; full pruning of old commits would defeat the audit purpose. Likely answer: keep all history forever, accept the linear-in-time disk cost.
- **Interaction with the runtime audit log.** The runtime log lives under `state/` (gitignored). It has its own integrity story (§4.5). Should the snapshot ever capture audit-log *metadata* (e.g., the file's size or hash at snapshot time) for cross-checking? Probably not - it would couple two primitives that are clearer when independent.

---

## 7. Acceptance for the implementation

The implementation closed loop (§10 of the architecture overview) does not directly cover this primitive - it is operational, not request-path - but the implementer should land:

1. The arbiter tree restructured so `src/` / `config/` / `bin/` are the only checked-in subtrees; `state/`, `bitcoin/`, `lnd/`, `data/` exist under a tracked `.gitignore`.
2. Any module currently writing transient files outside `state/` (or equivalent) moved to do so under `state/`. A new exit-loop variant would catch regressions: spin up the arbiter against an empty `arbiter/` tree, run a representative request, then assert `git status --porcelain` shows no untracked files outside the gitignored set.
3. A sample cron definition for the chosen platform shipped under `arbiter/ops/` (or similar) - reference only, not active until the deployment turns it on.
4. The architecture overview's §4.5 (runtime audit log) updated to point at this doc as the companion primitive, and the §2.1 implementation discipline updated to require the no-transient-files-in-source invariant.

Tests for the cron itself are deployment-time, not exit-loop-time: confirm the timer fires, confirm a touch-and-wait produces a commit, confirm a quiescent minute produces no commit.

---

## 8. Manual audit scripts

`git log --since=1.day` is fine for someone who knows git, but the operator at the arbiter console may not. The auditability primitive is only as good as the operator's willingness to actually look, and that bar is set by the friction of looking. Ship a handful of single-purpose scripts that translate the git history into plain English. One command, one question answered, no flags to remember.

The scripts live under `arbiter/ops/audit/` and are designed so a non-technical operator (the §2.1 "non-AI human" the whole discipline is for) can run them by name and read the output unaided. Each is a thin wrapper around `git log` / `git show` with output reshaped for readability.

### `arb-today`

What changed today? The daily-glance script.

```
$ arb-today
Today (2026-05-24):
  14:32  config edit    config/destinations.yaml         (+1 line)
  09:15  code deploy    src/gateway.py, src/scale.py + 2 more
  09:15  binary update  bin/arb

3 changes today.
```

### `arb-since <when>`

What changed since a given date or time?

```
$ arb-since 2026-05-20
Since 2026-05-20 (4 days):
  2026-05-24 14:32  config edit    config/destinations.yaml
  2026-05-24 09:15  code deploy    src/gateway.py + 3 other source files
  2026-05-23 11:08  config edit    config/policy.yaml
  2026-05-22 08:00  code deploy    src/scale.py

4 changes in this window.
```

Accepts the same loose date forms `git log --since` accepts ("2 days ago", "last sunday", "2026-05-20", etc.), so the operator does not have to learn a new date language.

### `arb-config-only`

Only operator-driven config edits. Hides every code deploy. Use this to answer "who has been editing my YAML?"

```
$ arb-config-only
Config edits (most recent first):
  2026-05-24 14:32  config/destinations.yaml  (+1 line)
  2026-05-23 11:08  config/policy.yaml        (-2 lines, +3 lines)
  2026-05-21 16:44  config/destinations.yaml  (+2 lines)
```

### `arb-deploys-only`

Only code / binary deploys. Hides config edits. Use this to answer "when did the code actually change?"

```
$ arb-deploys-only
Code deploys (most recent first):
  2026-05-24 09:15  10 source files changed
  2026-05-22 08:00  1 source file changed
  2026-05-18 14:00  3 source files changed
```

### `arb-show <when>`

What was the change at this moment? Accepts the same date forms as `arb-since`; resolves to the snapshot commit closest to that time and shows the diff in friendly form.

```
$ arb-show '2026-05-24 14:32'
Snapshot at 2026-05-24 14:32 (UTC):
  File:    config/destinations.yaml
  Change:  +1 line

  + tb1qexampleaddress...   # Coffee shop, added 2026-05-24
```

### `arb-status`

Is the snapshot system itself healthy? A green-or-red one-shot.

```
$ arb-status
Snapshot cron:       RUNNING (last commit 12 seconds ago)
Pending changes:     NONE
Last snapshot:       2026-05-24 14:32:00 UTC
Quiet for:           18 seconds
Repo size:           4.2 MB, 1287 commits
Status:              OK
```

Failure modes show up as concrete states the operator can act on:

```
Snapshot cron:       NOT FIRING (last commit 47 minutes ago)
Pending changes:     3 files
Status:              WARN: cron may have stopped. Check the timer.
```

### `arb-anomalies`

Run a fixed set of cheap heuristic checks across the recent history and flag anything that does not fit normal operation. Read-only; suggests follow-up commands but does not act on anything.

```
$ arb-anomalies
Checking for anomalies in the last 7 days...

  OK    No commits at unusual hours (00:00-06:00 local).
  OK    No config changes when the console was likely unattended.
  OK    Cron has fired every minute (no gaps over 2 minutes).
  FLAG  bin/arb hash changed at 2026-05-23 09:08 without any src/ change in the same window.
  FLAG  Three commits in the same minute at 2026-05-22 03:14 (UTC night hours).

2 flags. Review with:
  arb-show '2026-05-23 09:08'
  arb-show '2026-05-22 03:14'
```

The heuristics are intentionally simple and over-flag: the cost of a false positive is the operator running one extra `arb-show`; the cost of a false negative is missing real tampering. Tunable later, but never to suppress signals.

---

## 9. Audit hygiene

The scripts in §8 produce evidence. Detecting anomalies still requires the operator to actually look at the evidence on a regular cadence. The point of this section is to make that cadence concrete enough that an operator with no security background can follow it.

The whole routine should fit in 1-2 minutes a day, plus a few longer touchpoints. The arbiter console (the same KVM used for HITL approvals and the recipient address registry) is the single workplace.

### Daily (1 minute, every day at the console)

1. Run `arb-today`.
2. Read each line. For each one ask: *did I do that, and at roughly that time?*
3. Anything that doesn't match memory: run `arb-show <time>` to see the diff. Either you forgot, or it's a flag.

### Weekly (5 minutes, once a week)

1. Run `arb-since 'last sunday'` (or the equivalent). Skim for anything you missed in the daily reviews.
2. Run `arb-anomalies`. Investigate every FLAG with `arb-show` until you can explain it or it is escalated.
3. Run `arb-status`. The repo should be healthy; if WARN, the snapshot system itself is at risk.

### After every deploy (30 seconds, right after pushing new code)

1. Run `arb-since <deploy time>` immediately after.
2. Confirm the changes are only under `src/` and `bin/`. Any `config/` change in the same window is a flag - the deploy should not be editing operator config.

### After every config edit (30 seconds, right after saving)

1. Run `arb-since <edit time>`.
2. Confirm the change is only under `config/`. Any `src/` or `bin/` change in the same window is a flag - config edits should never touch code.

### Anomaly signatures - escalate if seen

- **Code changes outside a deploy window.** `src/` or `bin/` commits at a time you weren't deploying. The arbiter's source is not supposed to drift between deploys.
- **Config changes when the console was unattended.** A `config/` commit at 3am if you were asleep, or while the console was locked.
- **Binary swap without source.** `bin/arb` hash changed but no `src/` change in the same window - the binary on disk no longer corresponds to the source you can read.
- **Burst of commits in a single minute.** The cron commits at most once per minute by design. Multiple commits in the same minute means something is writing the tree faster than expected.
- **Snapshot gap.** Quiet periods over a few minutes when the cron should be firing every minute. Either the cron died, or something killed it.
- **Untracked files outside the four allowed subtrees.** `arb-status` reports pending changes you can't account for. A module is leaking transient state into a snapshotted path (a code bug at best, an intrusion artifact at worst).

A flag is not by itself an incident; it is a question the operator owes themselves an answer to. The discipline is that every flag gets explained or escalated - never ignored, never deferred.

### Escalation

Spacer does not ship its own incident channel; escalation lands wherever the operator runs their normal security response (mail, phone, in-person to someone they trust). The arbiter console produces evidence in the form of `arb-show` output that pastes cleanly into a message; that is the entire interface between the audit primitive and whatever response process the operator has.
