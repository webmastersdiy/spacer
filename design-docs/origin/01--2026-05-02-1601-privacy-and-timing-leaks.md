# Privacy and Timing Leaks in the LND API Surface (AI-Facing)

**Date:** 2026-05-02
**Context:** AI ↔ privacy-proxy ↔ LND threat model and mitigation menu. AI-facing only.
**Related:**
- `2026-05-02-1600-lnd-mutinynet-test-flow.md` (test setup and session ledger)
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` (bitcoind AI-facing companion)
- `2026-05-02-1700-node-privacy-from-the-world.md` (world-facing privacy - separate concern)

---

## 1. Purpose and Scope

This document defines the **AI-facing** privacy threat model for a proxy that mediates
between an AI client and a Voltage-hosted LND node (Mutinynet/signet). The adversary
modeled here is the AI client itself - potentially malicious by design, compromised at
runtime, or prompt-injected by a fetched URL. The proxy's job is to prevent the AI from
learning more about the operator's node than it needs to fulfill a given task.

The boundary under analysis is the AI ↔ proxy ↔ LND interface.

World-facing threats (LN gossip, P2P peer observers, block explorer operators, hosting
providers) are out of scope here; see
`2026-05-02-1700-node-privacy-from-the-world.md`.

---

## 2. Threat Model

### Adversary capabilities in scope

| Adversary | What they can observe | Key concern |
|---|---|---|
| **The AI client** | Every response the proxy returns; request/response timing; any identifier or amount the proxy surfaces | May be malicious by design, compromised at runtime, or prompt-injected by a fetched URL. Could attempt to exfiltrate data to its operator, probe for info via crafted queries, or induce unauthorized fund movement. |
| **Network observer** (AI ↔ proxy channel) | Traffic metadata (timing, packet sizes, connection frequency) even if payload is TLS-encrypted | Timing analysis, connection-count patterns, size fingerprinting. |

World-facing threats (LN gossip network, routing nodes on payment paths, counterparty
observers, hosting operators) are out of scope here; see
`2026-05-02-1700-node-privacy-from-the-world.md`.

### Out of scope

- LND host operator (Voltage or self-hosted equivalent) - they see everything at the
  process and OS level regardless of what the proxy does.
- LN gossip network and routing node observers - world-facing; covered in the world-facing doc.
- Counterparty / faucet observers - world-facing.
- bitcoind operator - covered in `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`.
- OS-level or hypervisor-level compromise.
- Physical access to the node hardware.

---

## 3. Per-API Leak Surface

Severity: **HIGH** = full identifier or balance reveal; **MEDIUM** = counts, patterns, or
partial identifiers; **LOW** = status flags or booleans.

### 3.1 Identity

| Call | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `newaddress` | Fresh bech32 address | HIGH | Return opaque funding-pool token; proxy holds address↔pool mapping. |
| `connect` | Exposes our pubkey + outbound IP to peer | HIGH | Allowlist-gate every connect target; log all attempts. |
| `decodepayreq` | Destination pubkey, payment_hash, amount, route hints | MEDIUM | Run internally; surface only policy predicates ("amount ≤ ceiling: yes"). |

### 3.2 Balance

| Call | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `walletbalance` | Total / confirmed / unconfirmed / locked / reserved / per-account | HIGH | Return banded values ("≥50k", "100k-1M") or boolean capability predicates. |
| `listunspent` | Per-UTXO address, amount, pk_script, outpoint, confirmations | HIGH | Never surface to AI. Proxy answers higher-level questions ("≥X confirmed UTXO available: yes"). |
| `channelbalance` | Aggregate channel balance + buckets | HIGH | Same banding as `walletbalance`. |

### 3.3 Peer / Channel State

| Call | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `listpeers` | Per-peer: pubkey, address, feature bitmask, traffic counters | HIGH | Default to count only; per-peer detail requires explicit justification per call. |
| `pendingchannels` | Per-pending: remote pubkey, capacity, confirmation height | MEDIUM | AI gets "pending: yes/no" unless detail is explicitly needed. |
| `listchannels` | Per-channel: remote pubkey, channel_point, SCID, capacity, local/remote balance, commit fee, total_sats_sent, total_sats_received, num_updates, peer_alias, constraints, flags, commitment_type | HIGH | Default = counts + aggregate balances. Strip `total_satoshis_*` and `num_updates` (activity history). Per-channel detail requires explicit per-call justification. |

### 3.4 Payments

| Call | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `payinvoice` | Per-attempt HTLC table: state, attempt_time, resolve_time, receiver_amt, fee, timelock, chan_out, route alias chain; final preimage on success | HIGH | Surface only `{succeeded: bool, paid_amount: banded, fee: banded}`. Hold route, chan_out, preimage inside proxy. |
| `listpayments` | Full history: amounts, payment hashes, preimages, statuses, timestamps | HIGH | Never dump full history to AI. Proxy answers aggregate queries ("total paid this session: ~1k sats"). |

### 3.5 On-Chain Operations

| Call | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `sendcoins` | txid; tx itself is a permanent on-chain publication of our UTXOs and change address | HIGH | Validate destination against allowlist before broadcast; coin selection stays inside proxy. |

Note: the faucet `POST /api/onchain` call exposes our address to the faucet operator and
links it to our GitHub identity. That is a world-facing leak (faucet as adversary), not
an AI-facing one. See `2026-05-02-1700-node-privacy-from-the-world.md` §3.6.

### 3.6 Channel Open / Close

| Call | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `openchannel` | Funding txid returned to AI; channel_point and counterparty pubkey available via follow-up calls | HIGH | Policy-driven: default `--private`; band channel sizes (10k/50k/200k tiers); allowlist counterparty. Proxy holds funding txid internally; surfaces only success/fail status. |
| `closechannel` | Closing txid returned to AI; channel_point identifies which channel was closed | HIGH | Channel-to-close = policy decision, not AI choice. Force-close requires explicit elevated authorization (irreversible signal of distrust). |

Note: the gossip consequence of `openchannel` (pubkey-pair + capacity + SCID broadcast to the
LN graph) is a world-facing leak, not an AI-facing one. The AI-facing concern is the
channel_point, funding txid, and counterparty pubkey the AI can learn via the API response.
See `2026-05-02-1700-node-privacy-from-the-world.md` §3.4 for gossip details.

### 3.7 ldk-node additional surface (second-backend perspective)

The ldk-node Python API (v0.7.0) broadly mirrors LND's surface. A few items add nuance:

- `export_pathfinding_scores()` - reveals which channels/paths have been successfully or
  unsuccessfully used. Strongly fingerprintable; no LND equivalent exposes this as a
  discrete call. Should be blocked at proxy.
- `sign_message(bytes)` - proves control of node_id pubkey to anyone with the result.
  Classic "prove who you are" vector; allowlist-gate with explicit operator approval only.
- `bolt12_payment()` offers - long-lived offer identifiers share the same pubkey as the
  node; repeated use of the same offer is linkable across payers. The AI learning the
  offer identifier can cross-reference it against on-chain data if it also knows the
  node pubkey; therefore withhold the offer string at the proxy layer.
- Event stream (`next_event` / `wait_next_event`) - each event carries full details
  (`PAYMENT_RECEIVED` includes amount + payment_hash; `CHANNEL_READY` carries
  counterparty + channel id). Proxy must filter at event level, not just API level.

---

## 4. Timing as a Leak Channel

Timing attacks are largely absent from the existing per-call notes. This section treats
them as a first-class leak channel.

### 4.1 Latency fingerprinting of payment paths

LN payment round-trip time scales roughly linearly with hop count. Each additional hop
adds propagation delay plus HTLC processing latency at intermediate nodes. An observer
who can correlate "invoice presented at time T₀, payment settled at time T₁" can
estimate the payer's graph distance from the destination.

Measured in this session: **0.22 s** for a 1-hop direct payment (LND node → faucet node,
Mutinynet clearnet, Voltage-hosted). This is the baseline. A 3-hop payment on mainnet
Tor might be 2-5 s; the gap is attributable to hop count + Tor latency. An AI that can
issue many test payments and observe their latencies can build a partial map of who is
directly peered with whom.

### 4.2 Polling cadence as side-channel

Tools that poll `walletbalance`, `listchannels`, or `pendingchannels` on a fixed schedule
publish the schedule itself to anyone watching the LND host's network or process
activity. If the poll interval is 30 s, that 30 s heartbeat is a fingerprint of what is
running on top of LND. Two nodes with identical 30 s polling intervals are likely running
the same software version. A jitter-free schedule also reveals whether the caller is
human (irregular) or automated (metronomic).

### 4.3 Time-of-day patterns

Sequences of operations correlated to business hours leak the operator's timezone and
daily routine. An AI-driven flow that runs continuously 24/7 is a different fingerprint
from a human-driven flow that operates 09:00-18:00. Conversely, an AI batch job that
runs at exactly 02:00 UTC is trivially identifiable as scheduled automation.

### 4.4 Inter-event timing: automation vs. human

The gap between a request arriving at the proxy and the resulting transaction broadcast
is a strong automation signal visible to the AI. Sub-second gap = bot. A 30 s+ gap with
variance consistent with reading + clicking = human. The AI can observe this signal in
the response latency it receives from the proxy and can use it to fingerprint the
operator's workflow. Conversely, the proxy can use this channel to spoof human-like
timing.

### 4.5 Proxy-introduced latency as its own signal

Any mitigation the proxy applies - rate-limiting, batching, response jitter - is itself
observable by the AI through the latency of responses. A proxy that always adds 200-500 ms
of artificial latency has a distinct signature: real LND latency at this setup was
~50-100 ms for local calls, so a systematic 300 ms extra is conspicuous. Variable-jitter
proxies may signal "AI automation present" if the variance distribution differs from
organic human usage - leaking the proxy's presence to a sophisticated AI.

### 4.6 Channel open/close timing relative to payments

Opening a channel immediately before a payment is a "just-in-time liquidity" fingerprint
that the AI can observe via the sequence of API calls it makes and their success/failure
states. A channel that did not exist in the previous `listchannels` result and now
exists just before a `payinvoice` call is visible to the AI. The AI cannot observe
on-chain block timing directly (unless the proxy surfaces block heights), but it can
observe the sequence of API states.

### 4.7 Payment retry timing

A failed payment followed by a retry with slightly different parameters leaks the route
discovery process to the AI via the sequence of `payinvoice` call results. The gap
between first attempt and retry reveals whether the proxy is using a fixed backoff (bot)
or waiting for human input. Multiple retries with decreasing timeouts reveal that
alternative routes are being explored - the AI can infer liquidity constraints from
the pattern of failures and successes.

Note: timing as observed by routing nodes (onion latency at intermediate hops) is a
world-facing concern; see `2026-05-02-1700-node-privacy-from-the-world.md` §2.6.

---

## 5. Mitigation Menu

Each mitigation is listed with its target threat and a note on its own residual leak.

| Mitigation | Targets | Own leak / caveat |
|---|---|---|
| **Identifier tokenization** - addresses, pubkeys, channel_ids, payment_hashes replaced with opaque proxy-scoped tokens | AI exfiltration, prompt injection probing node identity | Token vocabulary size can itself be a leak (number of unique tokens ≈ number of channels/addresses the operator has). |
| **Numeric value banding** - balances, fees, amounts surfaced as buckets (e.g., <10k / 10k-100k / 100k-1M / >1M sats) | Precision balance leakage to AI | Band boundaries are themselves a policy fingerprint; an attacker who can probe "can fund X?" across many X values can binary-search the exact balance. |
| **Outbound allowlist** - every `connect`, `sendcoins`, `openchannel`, `payinvoice` gated against a policy table | Prompt-injection-induced fund movement; generic TCP-connect abuse | Allowlist staleness: a static allowlist that never changes is itself a fingerprint ("this operator only ever pays 3 destinations"). |
| **Aggregate-by-default** - list-style calls return counts/summaries; per-item detail requires per-call justification logged | History dump via `listpayments`, `listchannels`, `listpeers` | Counts themselves can leak: "37 payments this session" is more information than "some payments." |
| **Withhold proofs** - preimages, signatures, macaroons stay inside proxy and are never returned to AI | Proof-of-payment exfiltration; macaroon reuse for unauthorized calls | Proxy becomes a single point of failure for proof custody. |
| **Default `--private` channels** - unless announcement is explicitly required by use case | AI learning channel_point + counterparty pubkey via `openchannel` / `listchannels` responses; also prevents gossip layer publication (world-facing benefit, see world-facing doc) | Private channels still appear on-chain; channel funding tx is public. HTLC amounts on private channels are still visible to routing peers on those channels. |
| **Constant-time response padding** - proxy returns response after a fixed wall-clock delay (e.g., always 500 ms) regardless of actual LND completion time | Latency fingerprinting of hop count (§4.1); automation vs. human timing (§4.4) | The constant itself is a fingerprint: an observer who measures exactly 500 ms responses every time knows this is padded, and knows the padding value. |
| **Jittered polling** - proxy queries LND on a randomized interval (base ± uniform or Gaussian jitter) instead of a fixed schedule | Polling cadence side-channel visible to AI (§4.2) | Jitter distribution is itself fingerprintable if the same PRNG seed or the same distribution parameters are always used. |
| **Batch tx broadcasts to fixed time windows** - on-chain transactions broadcast only at the next fixed slot (e.g., once per 10-minute window aligned to expected block time) | Inter-event automation fingerprint visible to AI (§4.4); JIT liquidity fingerprint (§4.6) | Fixed windows are themselves a fingerprint; if only one operator uses this proxy, the window alignment is identifying. |
| **Audit log of every AI request + proxy decision** | Forensics for prompt injection and unauthorized exfiltration attempts | Audit log itself is a high-value target; must be stored outside the AI's read access. |

Note: Tor routing, multi-peer broadcast, and self-hosted esplora are world-facing
infrastructure choices; they do not change what the AI can observe through the proxy.
Those mitigations belong in `2026-05-02-1700-node-privacy-from-the-world.md` §5.

---

## 6. Open Questions / Things to Test Next

1. **Hop-count latency visible to AI** - run `payinvoice` across a set of known 1-hop,
   2-hop, and 3-hop routes on Mutinynet. Measure what latency the AI observes (proxy
   response time) at each depth. Determine whether the 0.22 s 1-hop baseline is visible
   through the proxy before padding, and whether constant-time padding successfully flattens
   the distribution.

2. **`listpayments` history dump vs. streaming events** - quantify the incremental
   privacy cost of allowing `listpayments` (full history in one call) versus only allowing
   the event stream (`next_event` in ldk-node). The event stream limits the AI to a
   forward-only sliding window; `listpayments` gives a complete retrospective view
   including preimages for settled payments.

3. **Private channel AI-visible behavior at close** - when a `--private` channel closes,
   verify what the AI can observe through the proxy: does the closing sequence (pending
   channel disappears, wallet balance increases) allow the AI to infer the final balance
   split, even without the AI ever seeing the closing txid?

4. **Binary-search balance probing** - test whether the banded-value mitigation is
   actually robust against an AI issuing a sequence of capability queries
   ("can fund 75k: yes/no?", "can fund 80k: yes/no?") to resolve the exact balance.
   Design a rate-limit + noise policy that makes this infeasible within a session.

5. **`export_pathfinding_scores` fingerprint** - measure how distinguishable two nodes'
   pathfinding score exports are after an identical payment sequence. If scores converge
   quickly, the export is a reliable fingerprint of payment history even without
   payment-hash data - and is therefore a high-value thing the AI could exfiltrate.

6. **Constant-time padding detectability by AI** - run the proxy with 500 ms padding and
   measure whether an AI issuing many queries can distinguish the padded distribution from
   a natural one via standard statistical tests (KS test or similar). Determine the minimum
   jitter envelope needed to defeat the test at p < 0.05.

---

## 7. See Also

- `2026-05-02-1700-node-privacy-from-the-world.md` - world-facing privacy (Bitcoin P2P
  peers, LN gossip, block explorers, hosting providers). This is the sibling doc for
  concerns that are out of scope here.
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` - bitcoind AI-facing privacy,
  same proxy model applied to the bitcoind RPC surface. Read together with this doc
  when designing the proxy policy layer.
