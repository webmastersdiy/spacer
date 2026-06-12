# Arb-auditability via continuous git snapshot

**Date:** 2026-05-24
**Context:** A second audit primitive on the arbiter, complementing the runtime [audit log](../../GLOSSARY.md#audit-log): it captures *what was deployed and configured* over time, not *what was requested at runtime*.
**Related:**
- `05--2026-05-05-0948-architecture-overview.md#21-arbiter-implementation-discipline` - the manual-auditability discipline this operationalizes.
- `05--2026-05-05-0948-architecture-overview.md#45-audit-log` - the runtime audit log (companion primitive).

---

## 1. Purpose and scope

The [arbiter](../../GLOSSARY.md#arbiter) is the trust anchor: per architecture overview §2.1 it must be small enough that a non-AI human can read every line and confirm the gateway is the only path through. That holds only if *what is running* matches *what was reviewed*, and stays matched. The runtime audit log covers behavior but not provenance - it does not show that today's code on disk equals yesterday's, or that a config file was edited by the operator rather than by a process that should not have write access.

This doc adds a **continuous git snapshot**: a cron job commits the arbiter's tree to a local git repo every minute, so for any point in time the history answers what code was deployed, what the config was, and what changed since the last snapshot.

Out of scope: the runtime audit log (overview §4.5); alerting (this primitive produces evidence, not notifications); off-host shipping (§6).

## 2. The two audit primitives

| Primitive | Captures | Granularity | Lifecycle |
|-----------|----------|-------------|-----------|
| Runtime audit log (overview §4.5) | every request and gateway decision | per-request | append-only |
| Git snapshot (this doc) | deployed code + config on disk | per-minute | periodic commits |

Neither subsumes the other: a refused request appears in the runtime log; a config edit that *would have* changed how the gateway refuses appears in the snapshot history. An attacker who edits gateway source to weaken a check leaves a fingerprint in the snapshot; the runtime log alone would only show that decisions later changed.

## 3. Required arbiter layout

The snapshot only works if the tree separates what *should* be tracked from what should not - otherwise a runtime SQLite WAL ticking over buries the signal under a commit every minute. The split:

```
arbiter/
  src/          # Python source - changes only on a deploy
  config/       # operator-editable config (YAML) - changes on edits
  bin/          # built binaries / wrappers - changes only on a deploy
  ops/          # cron loop + operator audit scripts (§4, §8) - changes on a deploy
  state/        # runtime SQLite, WAL, audit log, scratch - GITIGNORED
  bitcoin/      # bitcoind datadir - GITIGNORED
  lnd/          # LND datadir - GITIGNORED
  ecash/        # nutshell eCash wallet datadir (doc 07 §3) - GITIGNORED
  data/         # any other transient runtime - GITIGNORED
```

The first four are snapshotted; the rest are gitignored. `ops/` is tracked because the cron body, deploy units, and audit scripts are themselves part of the deployed surface a reviewer audits. `arbiter/.gitignore` also catches file-pattern noise (`__pycache__/`, `*.pyc`, `*.db`, `*.db-wal`/`-shm`, `.DS_Store`) as belt-and-suspenders, so a misrouted file stays out of the snapshot even if it lands in a tracked subtree.

This requires one implementation invariant: **no module writes transient files outside the gitignored subtrees** - SQLite and its sidecars, the runtime audit-log file, and scratch / lock files all live under `state/`; build artifacts land in `bin/` only when complete. (System-temp dirs like the exit-loop runner's `tempfile.mkdtemp` are outside the tree and unaffected.)

## 4. The snapshot cron

Intentionally trivial - the design rests on a non-AI reviewer reading the loop in five seconds:

```sh
cd /path/to/arbiter
git add -A
git diff --cached --quiet || git commit -q -m "snapshot: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
```

It commits only when something staged actually changed (quiescent minutes produce nothing), and the UTC-timestamp message makes `git log` read chronologically without rewriting committer dates. Cadence is every minute and is the only tunable: lower risks missing an edit to an outage between save and snapshot; higher grows history without saying anything new. Reference units for both substrates ship under `arbiter/ops/` (`snapshot.sh`, `snapshot.launchd.plist`, `snapshot.service`, `snapshot.timer`, plus an install README); `snapshot.sh` derives `ARBITER_ROOT` from its own path, so the operator never edits it to deploy.

## 5. What the operator gets

From the arbiter console (the same KVM used for [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval) and the [recipient address registry](../../GLOSSARY.md#recipient-address-registry)), standard git porcelain queries the history: `git log --since=1.day`, `git log -- config/` ("did anyone edit config?"), `git log -- src/ bin/` ("did a release land?"), `git blame config/destinations.yaml` for per-line provenance. The load-bearing distinction is `src/` + `bin/` (deploys, rare) vs. `config/` (operator edits, frequent); a burst of `src/` commits outside a deploy window is itself a flag. §8 wraps these in plain-English scripts for operators who do not know git.

## 6. Open design questions

- **Repo location.** Same volume (simpler) vs. separate (survives a disk failure or a rootkit targeting the arbiter tree). Recommendation: separate, with a write-only path from the arbiter.
- **Signing.** GPG-signed commits make history-tampering detectable but add key management on the arbiter; defer until the deployment decides where the key lives.
- **Off-host backup.** A remote git push gives durability but adds an arbiter egress path (currently none beyond bitcoind/LND); if wanted, mirror manually from the console rather than from the arbiter.
- **Pruning.** The repo grows for years. `git gc --aggressive` is safe; dropping old commits defeats the purpose. Likely: keep all history, accept the linear disk cost.
- **Runtime-log cross-check.** Should a snapshot capture audit-log metadata (size / hash)? Probably not - it couples two primitives that are clearer independent.

## 7. Acceptance for the implementation

Not on the request-path closed loop (overview §10); it is operational. The implementer should land: (1) the arbiter tree restructured so `src/` / `config/` / `bin/` (and `ops/`) are the only tracked subtrees with `state/` / `bitcoin/` / `lnd/` / `data/` gitignored; (2) any module writing transient files outside `state/` moved under it, with a new exit-loop variant asserting `git status --porcelain` is clean outside the gitignored set after a representative request; (3) sample cron units under `arbiter/ops/` (reference only); (4) overview §4.5 pointing here as the companion primitive and §2.1 requiring the no-transient-files-in-source invariant. Cron tests are deployment-time (timer fires; touch-and-wait commits; a quiescent minute does not). Implementation status: §10.

## 8. Manual audit scripts

The primitive is only as good as the operator's willingness to look, and that bar is set by friction. Ship single-purpose scripts under `arbiter/ops/audit/` - thin `git log` / `git show` wrappers a non-technical operator runs by name and reads unaided. One command, one question, no flags:

- **`arb-today`** - what changed today (the daily glance).
- **`arb-since <when>`** - changes since a date/time (accepts `git log --since` forms: "2 days ago", "last sunday").
- **`arb-config-only`** / **`arb-deploys-only`** - config edits only / code + binary deploys only.
- **`arb-show <when>`** - the diff at the snapshot closest to a time.
- **`arb-status`** - is the snapshot system healthy? Cron state (RUNNING / WARN), pending changes, last snapshot, repo size.
- **`arb-anomalies`** - cheap heuristic checks flagging anything off; read-only, suggests follow-up `arb-show` commands.

Two outputs show the plain-English style:

```
$ arb-today
Today (2026-05-24):
  14:32  config edit    config/destinations.yaml         (+1 line)
  09:15  code deploy    src/gateway.py, src/scale.py + 2 more
  09:15  binary update  bin/arb

3 changes today.
```

```
$ arb-anomalies
Checking for anomalies in the last 7 days...

  OK    No commits at unusual hours (00:00-06:00 UTC).
  OK    Cron has fired every minute (no gaps over 2 minutes).
  FLAG  bin/arb hash changed at 2026-05-23 09:08 without any src/ change in the same window.
  FLAG  Three commits in the same minute at 2026-05-22 03:14 (UTC night hours).

2 flags. Review with:
  arb-show '2026-05-23 09:08'
  arb-show '2026-05-22 03:14'
```

The heuristics over-flag by design: a false positive costs one extra `arb-show`; a false negative misses tampering. Tunable, but never to suppress signals.

## 9. Audit hygiene

Evidence is only useful if reviewed on a cadence. The whole routine fits in 1-2 minutes a day plus a few touchpoints, all at the console:

- **Daily (1 min).** `arb-today`; for each line ask "did I do that, at about that time?"; anything that does not match memory -> `arb-show <time>`.
- **Weekly (5 min).** `arb-since 'last sunday'` for anything missed; `arb-anomalies`, investigating every FLAG to explanation or escalation; `arb-status` for snapshot-system health.
- **After a deploy (30 s).** `arb-since <deploy time>`; confirm only `src/` + `bin/` changed - any `config/` change in that window is a flag.
- **After a config edit (30 s).** `arb-since <edit time>`; confirm only `config/` changed - any `src/` / `bin/` change is a flag.

**Escalate if seen:** code changes outside a deploy window; config changes while the console was unattended; a `bin/arb` hash change with no matching `src/` change (the binary no longer matches readable source); multiple commits in one minute (something writes faster than the cron); snapshot gaps over a few minutes (cron died); untracked files outside the tracked subtrees (a module leaking state - a bug at best, an intrusion artifact at worst). A flag is a question owed an answer, not an incident: every flag gets explained or escalated, never deferred. Escalation goes wherever the operator runs normal security response; `arb-show` output pastes cleanly into a message.

## 10. Implementation status

The design landed in five commits on `webmastersdiy/spacer` main (bead `bl-hu56z9`, through `c80ebe7`), with a later reconciliation pass (`bl-cctvcg`):

| Commit | What landed |
|--------|-------------|
| `17d2a5a` | §3 tree split (`src/`+`config/`+`bin/` tracked; `state/`+`data/`+`bitcoin/`+`lnd/` gitignored) + `arbiter/.gitignore`, launcher, `config/README.md` |
| `75da243` | §3 invariant: `state.py` / `audit.py` defaults moved under `arbiter/state/` (env overrides preserved) |
| `83764cd` | §4 cron: `ops/snapshot.sh` + launchd plist + systemd service/timer + `ops/README.md` |
| `52f148c` | §8/§9: `ops/audit/` with the seven wrappers + `audit/README.md` |
| `c80ebe7` | 05-- cross-refs: §2.1 third invariant + §4.5 companion-primitive framing |

The reconciliation pass corrected §3 (added `ops/` as a fourth tracked subtree + the file-pattern gitignores) and §4 (the shipped units + auto-derived `ARBITER_ROOT`). An empty-tree smoke test confirmed `state.db` / `audit.log` / WAL sidecars land under gitignored `arbiter/state/` with `git status` clean outside it (17/17 exit-loop variants pass). The 2026-06-12 eCash build (sp-2hwco4.2, doc 07 §3) added `ecash/` to §3 as a fifth gitignored runtime subtree - the arbiter's transient eCash custody wallet - in both `.gitignore` copies.

**Deliberate script divergences from the §8/§9 narrative:**

- **UTC, not local,** for the anomaly night-window (snapshot timestamps are UTC; comparing against local time would create a DST/relocation bug). Tunable via `ARB_NIGHT_START` / `ARB_NIGHT_END`.
- **"Untracked files outside the tracked subtrees" lives in `arb-status`,** not `arb-anomalies` - it is a current-state check; `arb-anomalies` walks history only.
- **Two §9 signatures are not heuristics:** "config change while unattended" needs an operator-schedule model the system lacks (substitute: `arb-config-only` + the daily routine); "burst of commits in a minute" is structurally prevented by the once-per-minute cron.
- **A heuristic was added - mixed `config/` + `src/`/`bin/` change** - flagging any commit that crosses the boundary §3 relies on (follows from §9's post-deploy / post-config routines).
- **Env knobs:** `ARB_AUDIT_LIMIT` (50), `ARB_ANOMALIES_DAYS` (7), the night-window vars, and `ARBITER_ROOT` for non-canonical install paths.

**§9 signature -> script:** code-outside-deploy -> `arb-deploys-only`; config-while-unattended -> `arb-config-only`; binary-swap-without-source -> `arb-anomalies`; commit-burst -> structurally prevented; snapshot-gap -> `arb-anomalies` / `arb-status`; untracked-files -> `arb-status`.
