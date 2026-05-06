# Privacy and Timing Leaks in the bitcoind RPC Surface (AI-Facing)

**Date:** 2026-05-02
**Context:** AI ↔ privacy-proxy ↔ bitcoind threat model and mitigation menu. AI-facing only.
**Related:**
- `2026-05-02-1601-privacy-and-timing-leaks.md` (LND AI-facing companion - read together)
- `2026-05-02-1602-bitcoind-mutinynet-test-flow.md` (Mutinynet testbed details)
- `2026-05-02-1700-node-privacy-from-the-world.md` (world-facing privacy - separate concern)

---

## 1. Purpose and Scope

This document defines the **AI-facing** privacy threat model for a proxy that mediates
between an AI client and a locally-run Bitcoin Core node (v25.99.0 Mutinynet/covtools
fork, signet). The adversary modeled here is the AI client itself - potentially malicious
by design, compromised at runtime, or prompt-injected by a fetched URL. The proxy's job
is to prevent the AI from learning more about the operator's wallet and node than it
needs to fulfill a given task.

The boundary under analysis is the AI ↔ proxy ↔ bitcoind interface.

World-facing threats (Bitcoin P2P peers, block explorer operators, the single Mutinynet
peer at 45.79.52.207, hosting providers) are out of scope here; see
`2026-05-02-1700-node-privacy-from-the-world.md`.

This document is the bitcoind-side counterpart to the LND AI-facing doc. The two
documents are meant to be read together when designing the proxy's policy layer.

---

## 2. Threat Model

### Adversary capabilities in scope

| Adversary | What they can observe | Key concern |
|---|---|---|
| **The AI client** | Every response the proxy returns; request/response timing; any identifier, amount, or address the proxy surfaces | May be malicious by design, compromised at runtime, or prompt-injected by a fetched URL. Could attempt to exfiltrate wallet data, probe for UTXOs or xpubs, or induce unauthorized fund movement. |
| **Network observer** (AI ↔ proxy channel) | Traffic metadata (timing, packet sizes, connection frequency) even if payload is TLS-encrypted | Timing analysis, connection-count patterns, size fingerprinting of RPC responses. |

World-facing threats (Bitcoin P2P peers, single Mutinynet peer, counterparty/recipient
observers) are out of scope here; see `2026-05-02-1700-node-privacy-from-the-world.md`.

### AI-facing characteristics specific to bitcoind (vs. LND)

- **Wallet metadata is uniquely toxic.** A single leaked xpub deanonymizes every address
  derived from that account - past and future - in one call. `listdescriptors` on a freshly
  created wallet returned 8 descriptors, each with a distinct account-level tpub. Leaking
  one tpub compromises the entire receive + change chain for that account, unboundedly.
  This is the highest-severity single-call leak in the entire proxy surface.
- **`getpeerinfo` leaks our public IP to the AI.** Every entry in `getpeerinfo` contains
  `addrlocal: "73.93.99.82:<port>"`. If the proxy surfaces this call, the AI learns our
  public IP. Proxy must deny or redact. The world-facing aspect (the peer also learns our
  IP) is covered in the world-facing doc.
- **`getnetworkinfo` leaks Tor configuration state to the AI.** The field
  `onion: reachable=false, proxy=""` tells the AI that Tor is not configured. This is an
  AI-facing concern because an AI that knows we are on clearnet can reason about what
  P2P-layer mitigations we lack.

### Out of scope

- bitcoind host OS / disk operator - they see everything regardless of what the proxy does.
- Bitcoin P2P peers - world-facing; covered in `2026-05-02-1700-node-privacy-from-the-world.md`.
- LND operator - covered in the LND AI-facing doc.
- OS-level or hypervisor-level compromise.
- Physical access to the node hardware.

---

## 3. Per-RPC Leak Surface

Severity: **HIGH** = full identifier, key material, or balance reveal; **MED** = partial
identifiers, counts, patterns, or confirmable state; **LOW** = status flags, booleans,
or public chain data.

### 3.1 Chain / Network Info

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `getblockchaininfo` | chain, height, headers, `verificationprogress`, `initialblockdownload`, pruneheight, `size_on_disk`, best block hash | MED | Safe to surface height and confirmation count. Strip `size_on_disk` and `pruneheight` (reveals prune window). Redact `warnings` text (may contain internal path info). |
| `getnetworkinfo` | `subversion`, local services bitmap, per-transport reachability, proxy settings, relay fee, `localaddresses` | MED | Strip `subversion` (version fingerprint), proxy settings (reveals whether Tor is configured), `localaddresses`. Surface only `relayfee` and connected-network booleans. |
| `getpeerinfo` | Per peer: remote IP, `addrlocal` (our public IP), `addrbind` (our LAN IP), `subver`, bytes per message, permissions, connection time | **HIGH** | Never surface to AI in raw form. Proxy may return peer count only. `addrlocal` confirmed to expose `73.93.99.82`; `addrbind` exposes `192.168.50.12` (LAN). |
| `getconnectioncount` | Integer peer count | LOW | Safe to surface. |
| `uptime` | Seconds since start | LOW | Reveals daemon restart history; surface with care or strip. |
| `getnodeaddresses N` | N entries from our address manager (IPs + ports of gossip-discovered peers) | MED | Exposes our peer-discovery state. Default deny; only useful for network diagnostics. |
| `getindexinfo` | Which optional indexes are enabled (txindex, blockfilterindex, coinstatsindex) | MED | Reveals node configuration. Confirmed empty `{}` on this build (all indexes off). Strip or return fixed stub. |

### 3.2 Mempool

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `getmempoolinfo` | size, bytes, fee floor, unbroadcast count | LOW | Safe; no identity linkage. |
| `getrawmempool [verbose]` | List of all txids in local mempool; verbose adds fee, size, ancestors, descendants, time | MED | The *set* of txids our node sees can fingerprint our peer topology (different nodes see slightly different mempools). Strip verbose details; return count only unless AI has explicit diagnostic need. |
| `getmempoolentry <txid>` | Fee, size, ancestor/descendant info for one tx | MED | Exposes our node's first-seen time for the tx. Return sanitized fee/size if needed; withhold time. |
| `gettxspendingprevout` | Whether a given outpoint is spent in our mempool | MED | Caller can probe "is my UTXO being spent?" - maps to UTXO ownership. Gate on allowlist of txids the proxy already knows about. |

### 3.3 Wallet / Keys (Critical)

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `listdescriptors` | All active descriptors with account-level xpubs (8 on fresh wallet: BIP44/49/84/86 × receive+change); `private=true` returns xprvs | **HIGH - CATASTROPHIC** | **Never expose to AI under any circumstance.** Each xpub unlocks entire address chain. Proxy must deny at the method level. |
| `getaddressinfo <addr>` | For owned address: full derivation path, `parent_desc` with account-level xpub, `hdmasterfingerprint`, `pubkey`, `scriptPubKey`, labels | **HIGH - CATASTROPHIC** | **Never expose to AI.** One call on a known address returns the account xpub in `parent_desc`. Deny by default. |
| `listwallets` | Names of loaded wallets | MED | Wallet names can be identifying ("kyc-account", "alice-cold"). Return count only or a fixed opaque alias. |
| `getwalletinfo` | Wallet name, format, balance, unconfirmed, txcount, keypoolsize, `private_keys_enabled`, `lastprocessedblock` | **HIGH** | Never surface raw. If wallet health is needed, return boolean predicate only ("wallet loaded: yes"). |
| `dumpprivkey` (legacy) | WIF private key | **HIGH - KEY MATERIAL** | Deny absolutely. Proxy never returns key material. |
| `walletpassphrase` / `walletlock` | Wallet unlock state (timing-sensitive) | **HIGH** | Deny. Proxy controls unlock state; AI must not be able to trigger or observe it. |
| `signmessage <addr> <msg>` | Signature proving control of `addr` | **HIGH** | Deny by default. Caller controls the message; this is a classic challenge-response deanon. |
| `importdescriptors` / `importprivkey` / `importaddress` | Injects keys/scripts into wallet watch list | **HIGH** | Deny to AI absolutely. Only operator can modify the watch list. Arbitrary descriptor import is both a DoS vector and a privacy poisoning vector. |
| `rescanblockchain` | Forces a wallet rescan (expensive) | MED | Deny to AI. Rescan duration leaks wallet depth and content to anyone monitoring host CPU. |

### 3.4 Balance / UTXO

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `getbalances` | `mine.trusted`, `mine.untrusted_pending`, `mine.immature`, `watchonly.*` | **HIGH** | Return banded values (e.g., `<10k / 10k-100k / 100k-1M / >1M sats`) or boolean capability predicates. |
| `listunspent [min] [max] [addrs]` | Every UTXO: txid, vout, address, amount, scriptPubKey, descriptor, confirmations | **HIGH** | Never dump full UTXO set to AI. Proxy answers aggregate queries ("≥X sats confirmed: yes"). If specific UTXO is needed for tx construction, proxy selects it internally. |
| `scantxoutset` | Scans the UTXO set for any descriptor/address the caller supplies | **HIGH** | Deny to AI. A caller can probe arbitrary addresses to learn balances - including addresses that are not the operator's. |
| `scanblocks` | Scans block range for descriptor matches (pruned: range-limited) | HIGH | Deny to AI. Same as `scantxoutset` but also reveals how far back our block history goes. |

### 3.5 Tx Construction

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `createrawtransaction` | Raw tx hex (no wallet involvement) | LOW | Safe to expose. Input txids and output addresses in the request are controlled by the caller - but those came from the AI, so the proxy must validate inputs against its UTXO allowlist before passing through. |
| `decoderawtransaction` | Full decoded tx: inputs, outputs, amounts, addresses, sizes | LOW | Safe to expose; the AI supplied the hex. Proxy can use this internally to audit tx structure before signing. |
| `decodescript` | Script type, address forms (p2sh, segwit), asm | LOW | Safe to expose. |
| `getdescriptorinfo` | Checksum, `isrange`, `issolvable`, `hasprivatekeys` | LOW/MED | `hasprivatekeys: true` confirms key material is present on the node. Gate: proxy may expose for operator-supplied descriptors; deny for AI-supplied descriptors. |
| `walletcreatefundedpsbt` | PSBT with proxy-selected inputs, change address, fee | **HIGH** | Never expose directly; proxy constructs PSBTs internally. The returned PSBT contains input descriptors and change address - both HIGH. |
| `walletprocesspsbt` | Signs/finalizes a PSBT using wallet keys | **HIGH** | Proxy controls which PSBTs are presented for signing. AI should never submit arbitrary PSBTs; proxy must inspect inputs and outputs first. |
| `signrawtransactionwithwallet` | Signed tx hex | **HIGH** | Proxy controls which inputs are signed. AI must not choose inputs; proxy performs coin selection. |
| `estimatesmartfee <target>` | `feerate` (BTC/kvB) or error if no data | MED | Safe to return feerate value. Timing and error-vs-result path reveal IBD state (see §4.7). |

### 3.6 Tx Broadcast

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `sendrawtransaction` | txid (tx immediately hits P2P network) | **HIGH** | Allowlist-gate every broadcast: proxy validates destination, amount, and change address before calling. Once called, the tx is globally visible and irreversible. |
| `sendtoaddress` / `sendmany` / `send` / `sendall` | txid + coin selection + change address | **HIGH** | Same as `sendrawtransaction`. Proxy performs coin selection; AI supplies only a destination and an amount ceiling. Destinations validated against allowlist. |
| `bumpfee` / `psbtbumpfee` | Replacement tx or PSBT; creates RBF-flagged replacement | **HIGH** | Allowlist-gate. Reveals that a prior tx exists and is stuck - confirming the UTXO being spent. |

### 3.7 Tx History

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `listtransactions` | Full per-wallet tx history: txids, amounts, addresses, fees, timestamps, confirmations, category | **HIGH** | Never dump to AI. Proxy answers aggregate queries ("sent this session: ~1k sats"). |
| `listsinceblock` | All wallet txs since a given block hash | **HIGH** | Same as `listtransactions`. Deny. |
| `gettransaction <txid>` | Full wallet tx detail including which addresses are *ours*, fee, blocktime, wallet annotations | **HIGH** | For the proxy's own txid, never return raw. Proxy may surface: `{confirmed: bool, block_height: N}` only. The `details[].category` field ("send"/"receive") and `details[].address` confirm wallet ownership. |
| `listreceivedbyaddress` | Per-address receive totals + funding txids | **HIGH** | Deny. Directly maps our addresses to our tx graph. |
| `listreceivedbylabel` / `listlabels` / `getaddressesbylabel` | Label-to-address mappings | **HIGH** | Deny. Label names are operator-chosen and may be identifying. |
| `getnewaddress [label] [type]` | Fresh address derived from HD wallet | **HIGH** | Proxy holds address ↔ session-token mapping. Return opaque token to AI. Unrestricted access lets AI enumerate our HD chain. |

### 3.8 Peer / Node Operations

| RPC | What it returns | Severity | Proxy mitigation |
|---|---|---|---|
| `addnode <addr>` | Adds a peer (state-changing) | **HIGH** | Deny to AI. An adversary can force a connection to a peer they control and observe our tx-relay timing to mount an eclipse/sybil attack. |
| `disconnectnode` / `setnetworkactive` / `setban` / `clearbanned` | Peer manipulation | **HIGH** | Deny to AI. Network topology is operator-only. |
| `submitblock` / `submitheader` | Injects blocks/headers | **HIGH** | Deny to AI. |
| `getrpcinfo` | Active in-flight RPC calls + log path | **HIGH** | Deny to AI. In a multi-caller proxy, `getrpcinfo` leaks what other callers are currently doing. `logpath` also reveals the filesystem path to the debug log. |
| `stop` | Graceful shutdown | **HIGH** | Deny to AI absolutely. |

---

## 4. Timing as a Leak Channel

This section covers timing leaks that are AI-facing: patterns the AI client can observe
through the proxy's request/response interval. World-facing timing leaks (e.g., the first
P2P peer inferring tx origination from broadcast timing) are covered in
`2026-05-02-1700-node-privacy-from-the-world.md` §3.8 and §4.

### 4.1 Polling cadence on chain state calls

Regular polling of `getblockchaininfo`, `getbalances`, or `getrawmempool` on a fixed
schedule is visible to the AI: the AI can observe the response latency pattern and
infer the polling interval. A fixed 30-second cadence is a fingerprint of the specific
software and version running on top of bitcoind. Metronomic polling (zero jitter) signals
automation; irregular intervals suggest a human. Any automation running in a fixed cron
pattern (e.g., every 10 minutes aligned to wall clock) is trivially identifiable as
scheduled.

### 4.2 Sync-state-dependent response timing

Response time for `gettxout <txid> <vout>` and `getrawtransaction <txid>` differs
depending on whether `txindex` is enabled and whether the tx is in the mempool or a
confirmed block. With `txindex=0` (our configuration), `getrawtransaction` succeeds
instantly for mempool txs but fails for confirmed non-wallet txs. The error-vs-success
path and the response latency directly reveal the node's index configuration to the AI
without calling `getindexinfo`. Similarly, `estimatesmartfee` returns an error during IBD
and a real feerate post-sync; the error path confirms IBD state to the AI.

### 4.3 Mempool query patterns as intent fingerprints

A sequence of `getrawmempool` followed by `gettxout <txid> <vout>` for a specific output
is a recognizable fingerprint of "watching for this specific transaction" - visible to the
AI through the sequence of calls and responses. The AI can also deliberately probe
arbitrary txids to map our mempool state. The proxy should gate which txids can be queried
based on its internal allowlist of known txids.

### 4.4 Block-height correlation and IBD-state inference

The AI observing repeated `getblockchaininfo` responses can track the rate of IBD
progress and estimate when on-chain operations will begin. The `blocks` vs. `headers`
gap reveals IBD state more reliably than `verificationprogress` (which this build reports
as `1` even mid-IBD). The transition from `initialblockdownload: true` to `false` is a
meaningful event the AI can timestamp to anchor the node's operational history.

### 4.5 Time gap between AI request and `sendrawtransaction` response

The interval between a payment task arriving from the AI and the proxy returning a txid
is observable by the AI as response latency. A sub-second gap signals fully automated
coin selection, signing, and broadcast. A 10-60 second gap with natural variance suggests
human review is in the loop. This signal is AI-facing: the AI measures it as response
latency from the proxy. (The world-facing analogue - first P2P peer timing the broadcast
- is covered in the world-facing doc.)

### 4.6 `estimatesmartfee` cache TTL as a tell

The AI can issue a sequence of `estimatesmartfee` calls and observe latency variance. A
cache miss (higher latency) near the time of a broadcast signals that a tx is being
constructed. A run of identical feerate responses with sub-millisecond latency confirms
cache-hit behavior. An AI that instruments this pattern can correlate fee-estimate requests
to impending broadcast events, narrowing the temporal window of the operator's tx workflow.

### 4.7 Wallet rescan timing (AI-observable via getwalletinfo)

`importdescriptors` and `rescanblockchain` trigger a wallet rescan whose duration scales
with the number of blocks scanned and the number of wallet addresses. The AI can observe
progress if permitted to call `getwalletinfo`: the `lastprocessedblock` height advances
visibly during the scan. From the duration and starting height, the AI can infer wallet
depth - how far back the key history goes and roughly when the wallet was created.

### 4.8 Pruned-mode latency fingerprint

With `prune=2200`, queries for pruned blocks via `getblock` fail instantly with an RPC
error. Queries for in-window blocks return after a disk read. An AI that can issue
`getblock` calls at varying heights and observe latency vs. error can binary-search the
exact prune horizon, revealing both the `prune_target_size` setting and how much chain
history the operator has retained. The proxy should return a uniform stub error for all
out-of-window block requests rather than the raw bitcoind error.

---

## 5. Mitigation Menu

Each mitigation is listed with its target threats and a note on its own residual leak.

| Mitigation | Targets | Own leak / caveat |
|---|---|---|
| **Identifier tokenization** - txids, addresses, descriptor strings, label names replaced with opaque proxy-scoped tokens | AI exfiltration of txids/addresses; prompt injection probing wallet identity | Token vocabulary size can leak: number of unique tokens ≈ number of UTXOs/addresses the proxy has tracked in this session. |
| **Numeric value banding** - balances, UTXO amounts, fees surfaced as buckets (e.g., `<10k / 10k-100k / 100k-1M / >1M sats`) | Precision balance/amount leak via `getbalances`, `listunspent`, tx history | Band boundaries are themselves a policy fingerprint. An AI can binary-search the exact balance by probing "can fund X?" across many values. Must be paired with rate limiting. |
| **Outbound allowlist** - every `sendtoaddress`, `sendrawtransaction`, `addnode`, and peer-manipulation call gated against a policy table | Prompt-injection-induced fund movement; peer-manipulation abuse; eclipse attack setup | Allowlist staleness: a static allowlist that never changes is itself a fingerprint ("this node only ever sends to 2 destinations"). |
| **Aggregate-by-default** - list-style calls (`listunspent`, `listtransactions`, `listsinceblock`) return counts/summaries; per-item detail requires per-call justification logged | History dump; UTXO enumeration | Counts themselves can leak: "14 UTXOs" is more information than "some UTXOs." |
| **Withhold seed material absolutely** - xpubs, xprvs, descriptor private parts, `dumpprivkey` output: proxy never returns these under any circumstance | `listdescriptors`, `getaddressinfo`, `dumpprivkey` exfiltration | Proxy becomes the single custodian of key-derivation metadata; its own security is now the key-material boundary. |
| **Deny wallet-import / descriptor-import to AI** - `importdescriptors`, `importprivkey`, `importaddress`, `importmulti` require operator-level auth only | Watch-list poisoning; DoS via expensive rescan; injection of adversarial descriptors | Operator must have an out-of-band channel to add keys. In-band import is unavailable even for legitimate AI use cases. |
| **Default to PSBT-style flows** - proxy constructs and inspects PSBTs before presenting to `walletprocesspsbt`; AI never sees unsigned or signed tx directly | Arbitrary input selection by AI; `signrawtransactionwithwallet` abuse | PSBT round-trip adds at least one extra RPC call; latency increase is observable. |
| **Coin selection inside proxy** - AI provides only destination and amount ceiling; proxy selects UTXOs internally | `listunspent` exposure; UTXO clustering by AI | Proxy coin selection policy becomes a fingerprint: if the proxy always picks the smallest UTXOs, that's a recognizable pattern on-chain. |
| **Constant-time response padding** - proxy returns wallet-op responses after a fixed wall-clock delay regardless of actual bitcoind completion time | Sync-state-dependent timing (§4.2); rescan timing (§4.7); automation vs. human timing (§4.5) | The padding constant is itself a fingerprint. An observer who consistently measures the same delay knows this is padded and knows the delay budget. Use variable jitter instead of a fixed floor. |
| **Jittered polling** - proxy queries `getblockchaininfo` / `getbalances` on a randomized interval (base ± uniform or Gaussian jitter) | Polling cadence side-channel (§4.1); IBD-state timing (§4.4) | Jitter distribution is fingerprintable if the same PRNG seed or fixed distribution parameters are always used. |
| **Tx broadcast delay / time-window batching** - hold signed txs until the next fixed broadcast slot | Automation timing fingerprint visible to AI (§4.5) | Fixed windows are themselves a fingerprint if only one operator uses this proxy. Align windows to expected block arrival times to blend with organic traffic. |
| **Audit log of every AI request + proxy decision** | Forensics for prompt injection and unauthorized exfiltration attempts | Audit log itself is a high-value target; must be stored outside the AI's read access and outside the bitcoind datadir. |
| **`getrpcinfo` denied to AI** | Cross-caller side-channel in multi-user proxy; log path leak | No residual leak from the denial itself. |

Note: Tor routing and self-hosted esplora (for IP-to-txid link avoidance) are world-facing
infrastructure choices; they do not change what the AI observes through the proxy. Those
mitigations belong in `2026-05-02-1700-node-privacy-from-the-world.md` §5.

---

## 6. bitcoind vs. LND - Comparison Callout

The two API surfaces have different risk profiles. Both require a proxy with active
filtering, but the policies differ in kind rather than just degree.

| Dimension | bitcoind | LND |
|---|---|---|
| **Most dangerous single call** | `listdescriptors` - 8 account xpubs in one response; one call compromises entire wallet address space past and future | `listchannels` - per-channel remote pubkeys, balances, activity counters, total sats sent/received for every channel in one call |
| **Key material exposure** | xpubs via `getaddressinfo` / `listdescriptors`; xprvs if `private=true`; WIF keys via `dumpprivkey` | Preimages via `listpayments`; macaroons via credential download |
| **AI-visible topology** | Peer IPs via `getpeerinfo`; no channel graph (bitcoind has no LN layer) | Full channel graph via `listchannels`; node pubkey + peer IPs via `listpeers` |
| **AI-visible transaction metadata** | On-chain: amounts, addresses, UTXOs linked to wallet via `gettransaction`, `listtransactions` | Off-chain: payment hashes, HTLCs, route data visible in `payinvoice` / `listpayments` responses |
| **Descriptor sensitivity** | xpubs in `listdescriptors` and `getaddressinfo` - one call compromises all future addresses | No xpub equivalent; preimages and macaroons are the analogous key-material leaks |
| **IP leakage to AI** | `getpeerinfo.addrlocal` returns our public IP `73.93.99.82` in every peer row - proxy must deny or redact | `listpeers` exposes peer IPs; `connect` logs our IP against a target |
| **Irreversibility for proxy** | On-chain broadcast via `sendrawtransaction` is permanent and immediately public | LN payment can fail via HTLC timeout; channel close is on-chain but has a cooperative-close window |
| **Proxy policy complexity** | Higher on wallet/UTXO side: coin selection, PSBT inspection, xpub lockdown | Higher on channel/route side: channel policy, payment routing, pathfinding score lockdown |

**Summary (AI-facing):** bitcoind is more dangerous on the wallet and key-derivation side;
a single negligent `getaddressinfo` or `listdescriptors` call ends wallet privacy
permanently by giving the AI all future receive and change addresses. LND is more
dangerous on the topology and payment-correlation side; channel graph data in
`listchannels` gives the AI a complete map of our LN relationships.

Note: world-facing comparison aspects (on-chain broadcast vs. LN gossip permanence, IP
exposure to peers vs. esplora operators) are covered in
`2026-05-02-1700-node-privacy-from-the-world.md` §4.

---

## 7. Open Questions / Things to Test Next

1. **Quantify rescan timing leak to AI.** Import a descriptor with known depth (e.g.,
   1000 addresses derived vs. 3000) and measure `rescanblockchain` duration at our
   current chain height (~309k blocks). Determine whether the duration is distinguishable
   by depth bucket at the granularity an AI polling `getwalletinfo.lastprocessedblock`
   could observe - and what rate limit on `getwalletinfo` is needed to prevent this.

2. **Test PSBT round-trip with a watch-only wallet.** Set up the proxy-side as a
   watch-only wallet (descriptors, no private keys) and a separate signing device (hardware
   wallet model or an offline `bitcoin-wallet`). Measure the full PSBT-construct → sign →
   broadcast round-trip and identify which steps the proxy must perform vs. delegate.
   Verify the proxy can inspect all inputs and outputs before presenting the PSBT for signing.

3. **Measure `estimatesmartfee` cache behavior.** After sync completes, call
   `estimatesmartfee` at multiple targets (2, 6, 144 blocks) in rapid succession and
   measure latency variance. Determine the cache TTL and whether two concurrent AI callers
   see the same cached value or trigger separate computations. A shared cache is a
   cross-caller timing side-channel in multi-user proxy deployments.

4. **Verify pruned-mode proxy behavior.** With `prune=2200`, test what happens when an
   AI asks for a block below the prune horizon via `getblock`. Verify that the proxy
   returns a uniform stub error for all out-of-window block requests, rather than the raw
   bitcoind error (which confirms the block is pruned and reveals the exact prune horizon).

5. **Binary-search balance probing resilience.** Verify that the banded-balance mitigation
   is robust against an AI issuing a sequence of `walletcreatefundedpsbt` calls with
   increasing amounts to resolve the exact UTXO balance. Design and test a rate-limit +
   noise policy that makes this infeasible within a session budget.

6. **`getrpcinfo` cross-caller leak in proxy.** Simulate two concurrent AI callers
   hitting the proxy and verify whether either can observe the other's in-flight RPC
   call names via `getrpcinfo`. The call should be denied entirely; this test confirms
   no timing side-channel persists after denial.

---

## 8. See Also

- `2026-05-02-1700-node-privacy-from-the-world.md` - world-facing privacy (Bitcoin P2P
  peers, single Mutinynet peer at 45.79.52.207, block explorers, hosting operators).
  World-facing mitigations (Tor, multi-peer, self-hosted esplora) belong there.
- `2026-05-02-1601-privacy-and-timing-leaks.md` - LND AI-facing privacy, same proxy
  model applied to the LND RPC surface. Read together with this doc when designing the
  proxy policy layer.
