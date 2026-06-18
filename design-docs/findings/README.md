# Design docs - findings

A sibling directory to [`origin/`](../origin/README.md) for the
**inconclusive and operational residue** of design work: material that
supports an origin design doc but does not belong in it.

The standing split rule (why this folder exists):

- **Conclusive decisions and durable design** - the chosen approach and
  the reason, the protocol, the flow - live in `origin/` (or whichever
  initiative directory owns the design).
- **Inconclusive and operational bits** - un-run test results, fee
  specifics, CLI-surface verification status, install gaps, point-in-time
  snapshots, reference-only config for paths not taken - live here, so the
  origin design record is not polluted by detail that is volatile, not yet
  verified, or operational rather than architectural.

Each findings doc names the origin doc it **supports** in its header, and
gets reconciled (or retired) when the open items it tracks resolve - at
which point the conclusive part migrates to the origin doc and this one
records what was learned.

## Naming

Same convention as the rest of `design-docs/` (see the top-level
[`design-docs/README.md`](../README.md)): `NN--YYYY-MM-DD-HHMM-<name>.md`,
with `NN` a two-digit chronological index that restarts at `00` within
this directory.
