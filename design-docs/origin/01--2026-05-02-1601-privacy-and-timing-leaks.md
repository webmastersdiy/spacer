# Privacy and Timing Leaks in the LND API Surface (AI-Facing)

**Date:** 2026-05-02 (reconciled 2026-06-12)
**Context:** AI-facing leak map for the LND surface - what each `lncli` call exposes and which arbiter mitigation covers it. This surface ships as the **advanced Lightning extension** (`SPACER_MODE=lightning|full`, and equally under `SPACER_MODE=ecash` - ecash implies lightning, doc 07 §9; doc 05 §2.2); the default onchain deployment exposes none of it, and doc 03 (bitcoind) is the primary surface. In the rail ladder this is the middle rail: Bitcoin on-chain (primary) -> Lightning (advanced) -> eCash (advanced, atop Lightning). Mitigation mechanics and caveats live in the [glossary](../../GLOSSARY.md#mitigations); this doc is the per-call inventory.
**Related:**
- `2026-05-02-1600-lnd-mutinynet-test-flow.md` - the run these calls came from.
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` - the primary (default onchain) surface; read together for the gateway policy layer.
- `07--2026-06-12-0916-ecash-extension.md` - the eCash extension one rail up: its fund/defund legs are LN payments from this surface, and the mint observes them (doc 07 §5-§6 own that leak map).
- `~/spacer/archive/2026-05-02-1700-node-privacy-from-the-world.md` - world-facing privacy (archived; separate concern).

---

## 1. Scope

The adversary is the AI client itself; see [AI-facing privacy](../../GLOSSARY.md#ai-facing-privacy) for the threat axes. The boundary is AI <-> [privacy gateway](../../GLOSSARY.md#privacy-gateway) <-> LND ([Node A](../../GLOSSARY.md#node-a), Voltage-hosted, Mutinynet/signet) - a boundary that exists only when the operator enables the advanced Lightning extension (`SPACER_MODE=lightning|full|ecash`; ecash mode enables this surface unchanged, doc 07 §9). The default onchain arbiter refuses `query_channels` / `send_lightning` uniformly at its mode gate (audit `decision_refuse_mode`) and never imports the LND client, so none of this surface is reachable there; the per-call policies below apply as written whenever the extension is on. World-facing threats (LN gossip, peers, explorers, hosting) are out of scope - see the archived world-facing doc.

## 2. Threat model

| Adversary | Observes | Concern |
|---|---|---|
| **The AI client** | every response; request/response timing; any identifier or amount surfaced | malicious by design, compromised, or prompt-injected; may exfiltrate, probe via crafted queries, or induce fund movement |
| **Network observer** (AI <-> gateway link) | traffic metadata even under TLS | timing, connection-count, size fingerprinting |

Out of scope: the LND host operator ([Voltage](../../GLOSSARY.md#voltage) sees everything at OS level); LN gossip / routing / faucet / counterparty observers (world-facing); the bitcoind operator (doc 03); OS or hypervisor compromise; physical access.

## 3. Per-call leak surface

Severity: **HIGH** = full identifier or balance reveal; **MED** = counts / patterns / partial; **LOW** = flags. The mitigation column tags the glossary mechanism that applies; mechanics and caveats are defined there.

### 3.1 Identity

| Call | Returns | Sev | Mitigation |
|---|---|---|---|
| `newaddress` | fresh bech32 address | HIGH | [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) to an opaque funding-pool token |
| `connect` | exposes our pubkey + outbound IP to the peer | HIGH | gate the target through the [recipient address registry](../../GLOSSARY.md#recipient-address-registry); log every attempt |
| `decodepayreq` | destination pubkey, payment_hash, amount, route hints | MED | decode internally; surface only policy predicates ("amount <= ceiling: yes") |

### 3.2 Balance

| Call | Returns | Sev | Mitigation |
|---|---|---|---|
| `walletbalance` | total / confirmed / unconfirmed / locked / reserved / per-account | HIGH | [scale cloaking](../../GLOSSARY.md#scale-cloaking) before egress; banding is deliberately *not* layered on top (§5) |
| `listunspent` | per-[UTXO](../../GLOSSARY.md#utxo) address, amount, pk_script, outpoint, confirmations | HIGH | never surface; [aggregate](../../GLOSSARY.md#aggregate-by-default) ("≥X confirmed UTXO available: yes") |
| `channelbalance` | aggregate local + remote channel balance | HIGH | as `walletbalance`: scale cloaking, not banding |

### 3.3 Peer / channel state

| Call | Returns | Sev | Mitigation |
|---|---|---|---|
| `listpeers` | per-peer pubkey, address, feature bitmask, traffic counters | HIGH | [aggregate](../../GLOSSARY.md#aggregate-by-default) to a count; per-peer detail needs per-call justification |
| `pendingchannels` | per-pending remote pubkey, capacity, confirmation height | MED | "pending: yes/no" unless detail is justified |
| `listchannels` | per-channel remote pubkey, [channel_point](../../GLOSSARY.md#channel-point), [SCID](../../GLOSSARY.md#scid), capacity, local/remote balance, commit fee, total_sats_sent/received, num_updates, alias, flags | HIGH | [aggregate](../../GLOSSARY.md#aggregate-by-default); strip `total_satoshis_*` and `num_updates` (activity history) |

### 3.4 Payments

| Call | Returns | Sev | Mitigation |
|---|---|---|---|
| `payinvoice` | per-attempt [HTLC](../../GLOSSARY.md#htlc) table (state, timings, fee, chan_out, route); [preimage](../../GLOSSARY.md#payment-hash-and-preimage) on success | HIGH | surface only `{succeeded, paid_amount: banded, fee: banded}`; [hide](../../GLOSSARY.md#hide-secrets) route / chan_out / preimage |
| `listpayments` | full history: amounts, payment hashes, preimages, statuses, timestamps | HIGH | never dump; [aggregate](../../GLOSSARY.md#aggregate-by-default) ("total paid this session: ~1k sats") |

### 3.5 On-chain and channel open / close

| Call | Returns | Sev | Mitigation |
|---|---|---|---|
| `sendcoins` | txid; publishes our UTXOs + change address on-chain | HIGH | gate destination through the [recipient address registry](../../GLOSSARY.md#recipient-address-registry); coin-select inside the arbiter |
| `openchannel` | funding txid; channel_point + counterparty pubkey via follow-ups | HIGH | [default --private](../../GLOSSARY.md#default---private-channels); band channel sizes; resolve counterparty via the registry; hold funding txid internally |
| `closechannel` | closing txid; channel_point identifies the channel | HIGH | channel-to-close is a policy decision, not AI choice; [force-close](../../GLOSSARY.md#cooperative-close-vs-force-close) needs elevated authorization |

World-facing carve-outs (handled in the archived world-facing doc): the faucet `POST /api/onchain` binds our address to our GitHub identity; `openchannel`'s gossip publication of pubkey-pair / capacity / SCID. The AI-facing concern is only what each response reveals.

### 3.6 ldk-node extra surface (second backend)

The [ldk-node](../../GLOSSARY.md#ldk-node) API (v0.7.0) mirrors LND, with four additions to block or gate: `export_pathfinding_scores()` reveals which paths were used (strongly fingerprintable, no LND equivalent - block); `sign_message(bytes)` is a challenge-response deanon (operator approval only); [bolt12](../../GLOSSARY.md#bolt12) offers are linkable across payers (withhold the offer string); the event stream (`next_event`) carries amount + payment_hash and counterparty + channel_id, so filter at event level, not just API level.

## 4. Timing as a leak channel

These surface to the AI as variation in gateway response timing. The [action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay) timing layer closes them inside the trust boundary (see §5); the measured values below are what an unmitigated proxy would expose.

| # | Channel | What it leaks / how the AI sees it |
|---|---------|-------------------------------------|
| 4.1 | Payment-path latency | LN round-trip time scales ~linearly with hop count, so correlating "invoice at T0, settled at T1" estimates graph distance to the destination. Baseline: **0.22 s** for a 1-hop direct payment (Mutinynet clearnet, Voltage); a 3-hop mainnet-Tor path might be 2-5 s. Many test payments let the AI map who is peered with whom. |
| 4.2 | Polling cadence | Fixed-schedule polling of `walletbalance` / `listchannels` / `pendingchannels` publishes the schedule; a 30 s heartbeat fingerprints software + version, and zero jitter marks automation vs. human. |
| 4.3 | Time-of-day | Operations tracking business hours leak the operator's timezone; 24/7 vs. 09:00-18:00 vs. an exact 02:00 UTC batch are each distinct fingerprints. |
| 4.4 | Inter-event timing | Request-to-broadcast gap: sub-second = bot, 30 s+ with read/click variance = human. The proxy can run the channel in reverse to spoof human-like timing. |
| 4.5 | Proxy-introduced latency | Any mitigation (rate-limit, batch, jitter) is itself visible: real local LND latency was ~50-100 ms, so a systematic +300 ms is conspicuous. |
| 4.6 | Channel open/close vs. payments | A [JIT-liquidity](../../GLOSSARY.md#jit-liquidity) pattern - a channel absent from the previous `listchannels` and present just before `payinvoice` - is visible from the API-state sequence. |
| 4.7 | Payment retry timing | A failed `payinvoice` then a retweaked retry leaks route discovery; the retry gap reveals fixed backoff (bot) vs. human input, and decreasing-timeout retries expose liquidity constraints. |

Routing-node timing (onion latency at intermediate hops) is world-facing (archived doc).

## 5. Mitigations

Every per-call mitigation in §3 is one of the standard arbiter mechanisms, defined with its residual-leak caveat in the [glossary Mitigations section](../../GLOSSARY.md#mitigations): [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization), [banding](../../GLOSSARY.md#banding-numeric-value-banding), [scale cloaking](../../GLOSSARY.md#scale-cloaking), the [recipient address registry](../../GLOSSARY.md#recipient-address-registry), [aggregate-by-default](../../GLOSSARY.md#aggregate-by-default), [hide secrets](../../GLOSSARY.md#hide-secrets), [default --private channels](../../GLOSSARY.md#default---private-channels), and the [audit log](../../GLOSSARY.md#audit-log).

One reconciled choice worth stating inline: **balance reads (`walletbalance`, `channelbalance`) use scale cloaking, not banding.** The gateway routes them through `scale.present()` rather than layering banding on an already order-of-magnitude-compressed value - the two together would muddy the math without adding privacy (see §6).

The §4 timing channels are **not** addressed by per-response padding. Earlier drafts listed constant-time padding, jittered polling, and batched broadcast as separate proxy mitigations; the current design subsumes all three into the [action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay) layer (see [latency fingerprinting](../../GLOSSARY.md#latency-fingerprinting), [polling cadence](../../GLOSSARY.md#polling-cadence)). Tor, multi-peer broadcast, and self-hosted esplora are world-facing.

## 6. Open questions

1. **Hop-count latency through the proxy.** Run `payinvoice` over known 1/2/3-hop Mutinynet routes; confirm whether the 0.22 s baseline is visible before the timing layer absorbs it.
2. **`listpayments` vs. event stream.** Quantify the privacy cost of a full-history call versus the forward-only `next_event` window (which never exposes settled-payment preimages).
3. **Private-channel close behavior.** When a `--private` channel closes, can the AI infer the final balance split from the pending-channel-disappears / balance-rises sequence alone, without the closing txid?
4. **Binary-search balance probing.** Test [scale cloaking](../../GLOSSARY.md#scale-cloaking) and banding against a sequence of "can fund X?" capability queries; design the rate-limit + noise policy that makes it infeasible per session.
5. **`export_pathfinding_scores` fingerprint.** Measure how distinguishable two nodes' score exports are after an identical payment sequence.

## 7. Implementation learnings

- **2026-05-24:** reconciled against `arbiter/src/lnd.py` and the cloak/banding decisions in `arbiter/src/gateway.py`. The §3.2 `walletbalance` / `channelbalance` cells and the §5 scale-cloaking note reflect the gateway's deliberate choice (`_dispatch`) to route balance reads through `scale.present()` rather than layering banding on an already-compressed value. Registry-gated ops (`sendcoins`, `openchannel`, `payinvoice`) verified consistent with the "registry IS the destination gate" framing - no edits needed there.
- **2026-06-12:** Bitcoin-first mode split (doc 05 §2.2): this surface is now the opt-in advanced extension. petcli moved the Lightning commands under the `advanced` namespace (`advanced send-lightning`, `advanced channels`); the wire ops are unchanged, and `lnd.py` is imported lazily so an onchain deployment never loads it. Nothing in §3-§5 changes when the extension is enabled.
- **2026-06-12 (eCash build, sp-2hwco4.2):** `SPACER_MODE=ecash` now also enables this surface, unchanged - ecash implies lightning (doc 07 §9), and the exit loop's ladder-regression variants (`query/balance/ecash-lnd-wallet`, `advanced/channels/ecash-mode`) hold the LN surface identical to lightning mode. The eCash extension adds no LN ops here; its fund/defund executions will ride this rail arbiter-internally (`payinvoice` of mint quote invoices; melt paying invoices from our own node), and the mint-facing leak map and timing mitigations for those legs are owned by doc 07 §5-§6 (including first-hop attribution toward the mint's node). Nothing in §3-§5 changes.
