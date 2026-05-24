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
send-lightning, registry-rejection subcases beyond the bare miss).
They will be added once the timing-layer executor wires the
arbiter's send pipeline through to bitcoin.py / lnd.py and the
runner gains the ability to seed registry entries to exercise each
rejection subcase distinctly.

The gateway currently routes inbound requests on a small fixed set
of recognized ops: query_balance and query_channels (known reads,
dispatch directly), send_bitcoin and send_lightning (known writes,
resolve recipient_token through the recipient address registry per
§4.7 and refuse uniformly on miss), and poll (the result-registry
fast path). Any other op parks in HITL and refuses. Read-only
query-balance / query-channels are validated end-to-end via the
fake lncli installed by the runner; state-changing sends are
currently validated only on the registry-miss path
(refused-unknown-token variants) against a made-up test token.

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
