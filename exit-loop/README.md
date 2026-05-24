# exit-loop/

Implementation closed loop artifacts. See §10 of
`../design-docs/origin/05--2026-05-05-0948-architecture-overview.md` for the
exit gate, coverage scope, test-mode timing rules, parallel-execution
guidance, iteration loop, and artifact layout.

The validation runner is `../test-harness/scripts/exit_loop_runner.py`.
It rebuilds `petcli/` from the runner's manifest on every invocation.
A populated `<variant-name>/` signals that variant has been validated
end-to-end against the current arbiter; an absent or empty one signals
not-yet-validated.

Variants currently absent from the manifest correspond to code paths
that are not yet reachable end-to-end (happy-path send-bitcoin /
send-lightning, registry-token rejection paths). They will be added
once the gateway's allowlist policy table format (sp-77lxs.2) lands
for the state-changing ops and the gateway dispatch is wired through
to the bitcoin client. Read-only query-balance / query-channels are
already wired: the gateway admits them through a hardcoded read-only
allowlist (a partial sp-77lxs.2 stand-in), dispatch reads
arbiter/src/lnd.py, and the runner installs a fake lncli so the
variants validate deterministically.

[Scale cloaking](../GLOSSARY.md#scale-cloaking) is wired for the
read-only balance path. Four cloaked variants exercise the cloak's
distinct branches: `query/balance/cloaked-tier-1` (T1 init, real 150k
presents 15k), `query/balance/cloaked-tier-2` (T2 init, real 1.5M
presents the same 15k as tier-1 - the cloak's whole point), and the
transition state machine via `query/balance/transition-pending`
(future due_at, presented value deliberately exceeds the 0-100k
window per the GLOSSARY's `drift > range` property) and
`query/balance/transition-applied` (past due_at, scale shifts
atomically and audit-logs `scale_tier_shift_applied`). The runner
sets `SPACER_SCALE_MODE=test` to unlock deterministic per-tier scales
and 5-15s transition windows; production-mode delays are blocked
behind a NotImplementedError pending the within-tier randomization
work.
