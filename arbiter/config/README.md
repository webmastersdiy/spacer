# Arbiter config

Operator-editable YAML lives here. Files in this directory are part of
the [continuous git snapshot](../../design-docs/origin/06--2026-05-24-0623-arb-auditability.md);
every save shows up as a `config/` commit in the snapshot history, which
is the load-bearing distinction that lets `arb-config-only` (under
`../ops/audit/`) answer "who has been editing my YAML?" without dragging
in source-tree noise.

Conventions:

- One YAML file per concern. Adding a new concern is a new file, not a
  new top-level key in an existing one - it keeps `git log -- config/<file>`
  precise.
- Hand-edited at the directly-attached arbiter console (the same KVM
  used for HITL approvals and the recipient address registry). No
  automated writer touches this directory.
- The arbiter reads these files on every relevant request; there is no
  reload command. An edit takes effect on the next call that reads it.

Files:

- `destinations.yaml` - the recipient address registry (architecture
  overview §4.7): the WHO gate for state-changing calls.
- `standing_approvals.yaml` - standing approvals (§4.1, §6): the WHAT
  gate. Ships absent; copy `standing_approvals.yaml.example` and edit.
- `ecash.yaml` - the eCash allowance (design doc 07 §8): the hard cap
  on the AI's outstanding eCash float, checked before standing
  approvals so no approval can exceed it. Ships absent (missing file =
  allowance 0 = every fund refused); copy `ecash.yaml.example` and
  edit. Only consulted in ecash mode (`SPACER_MODE=ecash`).
- `cashu-pin.yaml` - the pinned nutshell (cashu) CLI version the
  eCash parse contract was verified against (design doc 10 §3). The
  one exception to "operator-editable" in this directory: it is
  repo-tracked and consumed by the build-time contract test
  (`../ops/mint_contract_test.py`), which fails the build when the
  installed CLI reports any other version. Bump it only together
  with a contract-test rerun against the new CLI.

This README exists so `config/` is tracked in git even before any YAML
lands; without a file the empty directory would not appear in the
snapshot history.
