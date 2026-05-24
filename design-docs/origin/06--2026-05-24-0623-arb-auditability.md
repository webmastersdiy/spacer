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
