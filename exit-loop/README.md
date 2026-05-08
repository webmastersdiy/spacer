# exit-loop/

Implementation closed loop artifacts. See §10 of
`../design-docs/2026-05-05-0948-architecture-overview.md` for the
exit gate, coverage scope, test-mode timing rules, parallel-execution
guidance, iteration loop, and artifact layout.

The validation runner is `../test-harness/scripts/exit_loop_runner.py`.
It rebuilds `petcli/` from the runner's manifest on every invocation.
A populated `<variant-name>/` signals that variant has been validated
end-to-end against the current arbiter; an absent or empty one signals
not-yet-validated.

Variants currently absent from the manifest correspond to code paths
that are not yet reachable end-to-end (happy-path send-bitcoin /
send-lightning, real query-balance / query-channels, registry-token
rejection paths). They will be added once the gateway's allowlist
policy table format (sp-77lxs.2) lands and the gateway dispatch is
wired through to bitcoin / LND clients.
