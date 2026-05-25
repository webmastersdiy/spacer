# arbiter/ops/audit/

Operator-facing scripts that translate the continuous-snapshot git
history into plain English. Per
`../../../design-docs/origin/06--2026-05-24-0623-arb-auditability.md`
§8.

These scripts are the interface between the snapshot primitive and a
non-technical operator. Each one answers exactly one question, takes
no flags (or one date argument), and produces output a reader with
no git knowledge can act on.

## Scripts

| Script | Question it answers |
|--------|----------------------|
| `arb-today` | What changed today? |
| `arb-since <when>` | What changed since `<when>` (date or relative)? |
| `arb-config-only` | What operator-driven config edits have happened? |
| `arb-deploys-only` | When did the code actually change? |
| `arb-show <when>` | What was the change closest to `<when>`? |
| `arb-status` | Is the snapshot system itself healthy? |
| `arb-anomalies` | Anything in recent history that does not fit normal operation? |

Run each by name. Read the output. There is no flag system to learn.
The two scripts that take an argument accept any date form `git log
--since` accepts (`'2 days ago'`, `'last sunday'`, `'2026-05-20'`,
`'5 minutes ago'`, etc.) so the operator never has to learn a new
date language.

## Hygiene routine (§9)

The scripts are useful only if someone actually runs them. The §9
routine fits in 1-2 minutes a day:

- **Daily**: `arb-today`. For each line, ask "did I do that, around
  then?" Unrecognized line -> `arb-show <time>` to see the diff.
- **Weekly**: `arb-since 'last sunday'` + `arb-anomalies` +
  `arb-status`.
- **After every deploy**: `arb-since <deploy time>`. Confirm only
  `src/` / `bin/` changed. A `config/` change in the same window is a
  flag.
- **After every config edit**: `arb-since <edit time>`. Confirm only
  `config/` changed. A `src/` / `bin/` change in the same window is a
  flag.

Anomaly signatures and escalation guidance are in 06-- §9.

## Working with the scripts

These are thin shell wrappers around `git`. They locate the arbiter
root from the script's own location (`$ARBITER_ROOT` overrides if
needed), `cd` there, and run a few `git log` / `git show` commands
with the output reshaped. No clever logic.

That trivality is intentional. The auditability primitive is only as
trustworthy as the scripts the operator runs on top of it; making
each script short enough to read end-to-end means the operator (or a
reviewer) can convince themselves the script is faithful to the
underlying git history without taking it on faith. If a script grows
past ~100 lines, simplify it before adding to it.
