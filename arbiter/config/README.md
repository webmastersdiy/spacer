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

Per architecture overview §4.7 the recipient address registry will land
its YAML (`destinations.yaml`) here as part of the SQLite -> YAML
migration. Other operator-facing configs (e.g., standing approvals,
§4.1) will follow the same pattern.

This README exists so `config/` is tracked in git even before any YAML
lands; without a file the empty directory would not appear in the
snapshot history.
