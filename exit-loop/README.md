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
arbiter's send pipeline through to bitcoin.py / lnd.py; the runner
can already seed registry entries and standing-approval rules per
variant.

The gateway routes inbound requests on a small fixed set of
recognized ops, and the exposed set depends on the deployment mode
(`SPACER_MODE`; onchain is the default): query_balance (known read -
the bitcoind wallet in onchain mode, the LND wallet under the
advanced Lightning extension), send_bitcoin (known write - the
recipient_token resolves through the recipient address registry per
§4.7, miss = uniform refusal, then the
[standing approvals](../GLOSSARY.md#standing-approvals) gate decides
default-pause vs dispatch), poll (the result-registry fast path),
and, only under `SPACER_MODE=lightning|full`, the Lightning ops
query_channels / send_lightning. In onchain mode the Lightning ops
refuse uniformly at the mode gate (audit `decision_refuse_mode`) and
`arbiter/src/lnd.py` is never imported; the runner asserts both.
Unknown ops HITL-park.

Artifact paths mirror the petcli command tree: Bitcoin on-chain
commands are the primary surface (`submit/send-bitcoin`,
`query/balance`) and the Lightning commands live under the opt-in
`advanced` namespace, so their artifacts live under
`petcli/advanced/`. Read-only queries are validated end-to-end via
the fake bitcoin-cli / fake lncli the runner installs;
state-changing sends are validated on the registry-miss path
(refused-unknown-token) and both standing-approvals branches
(parked-no-standing-approval / allowed-by-standing-approval; the
allowed branch ends at dispatch's not_implemented stub pending the
timing-layer executor).

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
