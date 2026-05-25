"""
Arbiter entry point.

Wires the audit log and local state into the privacy gateway and
starts the network listener. There is no other way to launch the
arbiter from inside this codebase; this is the single audit-loggable
boot path. Operator-side commands (registry-add, HITL-approve, etc.)
arrive in their own files in later beads and reach state directly,
not through the gateway.

Per design-docs/origin/05--2026-05-05-0948-architecture-overview.md §2.1, §3, §4.1.
"""
import audit
import gateway
import registry
import state
# Subsystems with their own SQLite tables are imported here so their
# state.register_schema() calls run at import time, before
# state.migrate() applies the union. A subsystem that is not imported
# at boot does not get its tables created. Adding a new subsystem is
# a one-line edit here plus its own module.
#
# The recipient address registry (§4.7) is backed by a YAML file at
# arbiter/config/destinations.yaml, not the SQLite state.db, so it
# does not appear in this list. It is wired up via registry.configure()
# in main() instead.
import results  # noqa: F401  (registers results, result_poll_floor)
import timing  # noqa: F401  (registers pending_actions, pending_results)


def main(host=None, port=None, latency_target=None):
    """Boot the arbiter. Configure the audit log, the state DB, and
    the recipient registry YAML path; apply any registered schema
    fragments (the subsystems imported above register their own);
    then start the privacy gateway. The call blocks until the
    gateway is shut down."""
    audit.configure()
    state.configure()
    state.migrate()
    registry.configure()
    gateway.serve(host=host, port=port, latency_target=latency_target)


if __name__ == "__main__":
    main()
