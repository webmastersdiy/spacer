# Petitioner Read Freshness: Snapshot-Served Balance and Capacity Reads

**Date:** 2026-07-10
**Context:** Design investigation (sp-q6m, from the human via the spacer captain): should petitioner reads (`query_balance`, `query_channels`) get a random delay, an on-disk randomly-refreshed snapshot, or both? Verdict: the read path is today the one live, ungated observation channel through the gateway; close it with snapshot serving, not a per-request delay. This doc is the authority for the read-path freshness mitigation.
**Related:**
- `01--2026-05-02-1601-privacy-and-timing-leaks.md`, `03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` - the per-call leak maps whose polling-cadence rows and probing open questions this doc partially answers.
- `05--2026-05-05-0948-architecture-overview.md` §6 - the mitigation map this adds a row to.
- `09--2026-06-26-1626-dynamic-timing-window-and-lightning-floor.md` §3 - the lightning-floor rationale whose premise this doc repairs.
- `12--2026-06-27-1337-external-value-boundary-and-scale-tradeoff.md` - G1 endpoint privacy, the guardrail the kill chain in §2 breaks.

---

## 1. The gap

Reads dispatch synchronously and unconditionally (doc 05 §6). Every existing timing mitigation scopes them out, explicitly or structurally:

- [Action delay](../../GLOSSARY.md#action-delay): "read-only queries are out of scope" (by definition, in its glossary entry).
- [Result delay](../../GLOSSARY.md#result-delay) + 10-min poll floor: gate only the result-registry path (`op=poll`, per-handle).
- [Latency normalization](../../GLOSSARY.md#latency-normalization): hides per-response *processing* time, not *state-change* time.
- [Scale cloaking](../../GLOSSARY.md#scale-cloaking): `present()` is linear within a tier, so the served value moves at the exact moment the real value moves. The cloak hides magnitude, and transmits change timing unmodified.

Net: the petitioner can sample wallet state at the latency floor (~250 ms/request against the single-threaded gateway) and observe every balance change with sub-second timestamps. The audit trail confirms it: `request_received`, `balance_read`, `decision_allow`, `disclosure` land in the same second.

The gap matters more than a missing mitigation, because the corpus already *claims* coverage that only holds if reads are gated:

- Doc 03 §4 lead: "the AI never polls chain state" - false for `query_balance`.
- Glossary Result delay: "the petitioner only learns anything through the result-delivery path" - false while a live read exists.
- Doc 09 §3 rests the ~1h lightning floor (vs ~12h onchain) on "petitioner-submit -> petitioner-observable-consequence is already broken by Result delay", and even names "a later balance/channel read" as such a consequence. An ungated live read falsifies the premise; this doc is what makes it true.

## 2. What a frequently-polling petitioner learns

The petitioner can observe public chain data (the action-delay rationale already assumes this). Balance-change timestamps are the missing join key:

1. **Own-write execution pinning.** Submit `manage_bitcoin`, poll until the balance drops: the drop timestamp names the broadcast block, the block names the tx, the tx names the operator's inputs and change. That breaks G1 endpoint privacy (doc 12) and collapses the action delay's anonymity set by the factor window/epoch: knowing the execution moment to ±epsilon reduces "any similar tx in a 12-36h window" to "the txs in one block".
2. **Result-delay bypass.** The drop itself is the outcome, learned hours before the result registry delivers it.
3. **Operator activity surveillance.** Operator-initiated moves (deposits, consolidations, funding, defund arrivals) become petitioner-visible the moment they confirm; block correlation clusters operator addresses, and move timing fingerprints operator hours (the doc 01 §4.3 time-of-day channel, aimed at the operator instead of the petitioner).
4. **Delta ledger + cloak self-calibration.** Full-resolution presented values give a timestamped ledger of every movement. Worse, one *known* real delta calibrates the cloak: after its own ladder-denominated write, the petitioner solves `active_scale = presented_delta / known_real_delta` (fee noise only) and inverts every presented value to real sats for the rest of the tier epoch. The randomized in-band production scale defeats cross-wallet comparison, not this self-calibration.
5. **Tier-shift observation.** The scale-cloaking glossary caveat already concedes that a fast poller can flag the exact shift moment and its implausible magnitude.
6. **Capacity reads are worse, not better.** `query_channels` serves local+remote total, which moves only on channel open/close - events that are *public on-chain transactions*. A capacity-change timestamp correlates 1:1 with a public funding/closing tx. LN payments do not move it (local+remote is invariant under settlement), so the channel is sparse but each event is maximally identifying. Same treatment, mandatory.

## 3. Random per-request read delay: evaluated and rejected as primary

The proposed "Action-delay analog for reads" - hold each read response for a random `d ~ U[0, D]` - does less than it appears to:

- **Only sample-late semantics do anything.** If the backend is sampled at request receipt and the *response* is held (the natural implementation, matching the latency floor), the sample time is still the request time and a poller brackets every change exactly as before. The delay must sit *before* the backend read. Even then, continuous polling brackets a change to ~D regardless of poll rate.
- **To carry anonymity-set load, D must be hours.** Per §2.1 the protection factor is window/epoch; a D of seconds against a 12-36h action window protects nothing. But the read path is synchronous on a deliberately single-threaded gateway (doc 05 §2.1, timing predictability): holding responses for hours means either blocking all traffic or introducing threading that the architecture explicitly avoids. The delay is the wrong shape for a synchronous read.
- **On top of a snapshot it adds ~nothing.** Once the served value only changes at refresh epochs, blurring *when the petitioner observes the epoch boundary* by D << epoch widens its posterior on the true change time by a negligible D.

Keep [latency normalization](../../GLOSSARY.md#latency-normalization) exactly as is - it covers the residual per-response processing channel (snapshot hit vs miss, tier bookkeeping), which is a different leak.

## 4. Decision: randomized-refresh snapshot serving

Serve both read ops from a per-op snapshot row in the state DB, written by a refresh sweep in the executor's existing background drainer, on a randomized clock. The gateway read path never touches a backend. ("On disk" is satisfied by the state DB: WAL-serialized, same durability as every other arbiter singleton; a separate flat file would add partial-write failure modes for nothing. The property the human asked for is the *serving* discipline, not the storage medium.)

Invariants, in priority order:

1. **Event independence (oblivious sampling).** The refresh clock must never be triggered, advanced, or delayed by wallet events. A refresh-on-change "optimization" (ZMQ/LND subscriptions) reintroduces the leak exactly: transition time = change time + epsilon. This invariant dominates the distribution choice.
2. **Full presentation runs at refresh time.** Refresh = backend read -> `scale.present()` -> quantize (below) -> store; serve the stored value verbatim. Running `present()` per-request against a stored *real* value would let a mid-epoch tier shift move the served value at poll resolution, leaking the shift moment. Evaluating at refresh quantizes shift visibility to epoch boundaries and closes the §2.5 glossary caveat as a side effect (a shift due mid-epoch applies at the next refresh; against a multi-day shift delay the added latency is noise).
3. **Distribution: randomized renewal, uniform `[a, b]`.** Bounded worst-case staleness (an operational guarantee) and a bounded posterior for any observed transition (the true change lies within the one containing interval, at most `b`). Memoryless refresh buys schedule-inference resistance the design does not need: a refresh that serves an unchanged value is wire-invisible, so the petitioner observes refresh times only at value changes - too sparse to learn a schedule from. Fixed-period refresh stays forbidden (a learnable phase halves the posterior and fingerprints the deployment).
4. **Epoch sizing is a timing window under the [delay-scaling principle](../../GLOSSARY.md#delay-scaling-principle).** A change is localized to one epoch, so the petitioner's candidate set is (bucket arrival rate x epoch) - the same math as doc 09 §4.2, and the epoch must be commensurate with the action window or §2.1 pinning collapses the write-side set. Per-rail floors apply (capacity changes ride the onchain rail's public ledger; balance likewise in onchain mode). Production epochs are therefore gated behind the same dynamic-window work as everything else (sp-77lxs.3, `NotImplementedError` outside test mode); test mode uses the standard 5-15s band so exit-loop variants diff cleanly.
5. **Quantize the served value at refresh.** Round presented to a coarse grid (placeholder: 1k sats on the 0-100k presentation window) before storing. Purpose is *delta hygiene*, not magnitude privacy: it degrades §2.4 self-calibration to ±grid/(scale x known_delta), hides sub-grid operator churn entirely (no transition at all), and blunts the delta ledger. This is not a re-litigation of the rejected banding-atop-cloak layering (doc 01 §5): that rejection concerned hiding the value's magnitude, which the cloak already does; the grid hides the existence and size of *changes*.
6. **Intra-epoch aggregation is a feature.** Multiple movements inside one epoch collapse into one observed delta; count and individual sizes are hidden. No extra mechanism needed - state it so nobody "fixes" it.
7. **Backend outage becomes invisible on the read path.** Refresh failure keeps serving the last snapshot and audit-logs operator-side; the petitioner keeps getting a value. This tightens the [latency-fingerprinting](../../GLOSSARY.md#latency-fingerprinting) posture (outage no longer narrows below arbiter-as-a-whole granularity via reads; only writes reveal it, after their delay, as "failed temporary").
8. **Audit split preserves the doc 13 pairing.** Per-request `balance_read` (real + presented) becomes: `snapshot_refresh` (refresh-time: real, presented, served) and per-request `balance_served` / `capacity_served` (served value + snapshot age). The operator's two-column pairing survives; the operator gains snapshot age as a visible health fact. The disclosure record is unchanged.

**Read rate limit: optional, availability-only.** Under snapshot serving a throttled poller and an unthrottled one receive identical bytes at identical latency floors, so a rate limit is petitioner-indistinguishable and buys zero privacy; its only value is protecting the single-threaded gateway from a 4 Hz poller monopolizing request slots. If added, add it for that reason and say so.

**Composition answer (the bead's direct question):** the snapshot subsumes the per-request delay for change-timing; they do not usefully compose. Snapshot + latency normalization (existing) + optional availability throttle is the full read-side stack.

## 5. What this does not change

- **No arbiter-internal mitigation.** The refresh sweep reads bitcoind/LND from inside the trust boundary on its own clock; that is the mechanism's home, not a mitigated channel. The standing rule stands: mitigations fire at the petitioner-facing gateway boundary only.
- Writes, the result registry, HITL, registry gating, and the petcli wire shapes are untouched. `balance_sats` / `capacity_sats` keep their shapes; only their freshness semantics change.
- Scale cloaking internals are untouched; `present()` just moves from request time to refresh time.

## 6. Follow-up implementation scope (one bead)

Snapshot table + randomized-renewal refresh in the executor drainer; gateway `_dispatch` reads the row; audit events per §4.8; TUI event mapping; exit-loop variants (fresh serve, stale serve across a change, quantization edge, epoch-boundary tier shift); test-mode 5-15s band; production gate shared with sp-77lxs.3. Doc reconciliation (01, 03, 05 §6, 09 §3, glossary) lands with this doc.
