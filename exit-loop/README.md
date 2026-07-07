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
that are not yet reachable end-to-end (happy-path manage-bitcoin /
manage-lightning / fund-ecash / defund-ecash, registry-rejection
subcases beyond the bare miss). They will be added once the
timing-layer executor wires the arbiter's send pipeline through to
bitcoin.py / lnd.py / ecash.py; the runner can already seed registry
entries, standing-approval rules, and the eCash allowance per
variant.

The gateway routes inbound requests on a small fixed set of
recognized ops, and the exposed set depends on the deployment mode
(`SPACER_MODE`; onchain is the default) along the design doc 07 rail
ladder: query_balance (known read - the bitcoind wallet in onchain
mode, the LND wallet under the advanced Lightning extension AND in
ecash mode), manage_bitcoin (known write - the recipient_token
resolves through the recipient address registry per §4.7, miss =
uniform refusal, then the
[standing approvals](../GLOSSARY.md#standing-approvals) gate decides
default-pause vs dispatch), poll (the result-registry fast path),
under `SPACER_MODE=lightning|full` the Lightning ops query_channels
/ manage_lightning, and under `SPACER_MODE=ecash` the full ladder plus
the eCash writes fund_ecash / defund_ecash (no recipient_token - the
destination is structurally the pinned mint - so the pipeline is the
[allowance](../GLOSSARY.md#ecash-allowance) cap on fund, then
standing approvals against `destination: mint`). When an extension
is disabled its ops refuse uniformly at the mode gate (audit
`decision_refuse_mode`; eCash ops refuse this way in BOTH onchain
and lightning/full modes - `full` is frozen at onchain+lightning and
never silently arms ecash). `arbiter/src/lnd.py` is never imported
in onchain mode and `arbiter/src/ecash.py` is never imported outside
ecash mode; the runner asserts all of it via the no-lnd-import and
no-ecash-import gates. Unknown ops HITL-park.

Artifact paths mirror the petcli command tree: Bitcoin on-chain
commands are the primary surface (`submit/manage-bitcoin`,
`query/balance`) and the Lightning and eCash commands live under the
opt-in `advanced` namespace, so their artifacts live under
`petcli/advanced/`. Read-only queries are validated end-to-end via
the fake bitcoin-cli / fake lncli the runner installs;
state-changing sends are validated on the registry-miss path
(refused-unknown-token) and both standing-approvals branches
(parked-no-standing-approval / allowed-by-standing-approval; the
allowed branch ends at dispatch's not_implemented stub pending the
timing-layer executor).

The eCash variants (design doc 07 §9) cover both halves of the §3
custody split. Arbiter-mediated: fund/defund mode-gate refusals
against onchain and lightning/full arbiters, the fund_ecash
allowance gate (missing-config default-deny in
`refused-no-allowance-config`; `refused-over-allowance` stages a
matching standing-approval rule and asserts - via
forbidden_audit_events - that the allowance refusal fires WITHOUT
consulting it, the doc 07 §8 "no approval can widen the blast
radius" property), both standing-approvals branches for fund and
defund (defund rules are unbounded: no gate-time amount), and
ladder-regression variants (`query/balance/ecash-lnd-wallet`,
`advanced/channels/ecash-mode`) proving ecash mode leaves the
Lightning surface exactly as lightning mode has it. AI-side local:
`advanced/ecash/{balance,send,receive,info}` shell the petitioner's
cashu CLI - a fake at `$PETCLI_CASHU_BIN` with `$CASHU_SCENARIO`
canned replies, mirroring the other fakes - and never touch the
arbiter; petcli wraps their output in the `_petcli_local` envelope
(plus a deterministic missing-binary error variant). No fake is
installed for the ARBITER-side cashu wrapper: no manifest variant
can reach it (eCash writes stop at the gates or the dispatch stub),
and leaving `CASHU_BIN`/`CASHU_MINT_URL` unset means an unexpected
arbiter-side mint call errors loudly instead of being absorbed.

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
