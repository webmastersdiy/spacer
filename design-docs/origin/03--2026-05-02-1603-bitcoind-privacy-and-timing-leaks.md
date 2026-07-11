# Privacy and Timing Leaks in the bitcoind RPC Surface (AI-Facing)

**Date:** 2026-05-02 (reconciled 2026-06-12)
**Context:** AI-facing leak map for the bitcoind RPC surface - what each `bitcoin-cli` call exposes and which arbiter mitigation covers it. **bitcoind is the primary surface**: the default deployment mode (onchain, doc 05 §2.2) serves everything from it, with the opt-in advanced extensions stacking above it as the doc 07 rail ladder - Lightning (doc 01), then eCash atop Lightning (doc 07). Mitigation mechanics and caveats live in the [glossary](../../GLOSSARY.md#mitigations); this doc is the per-RPC inventory. Read together with the LND doc for the gateway policy layer.
**Related:**
- `01--2026-05-02-1601-privacy-and-timing-leaks.md` - the LND surface (advanced extension).
- `07--2026-06-12-0916-ecash-extension.md` - the eCash extension two rails up (advanced, atop Lightning).
- `02--2026-05-02-1602-bitcoind-mutinynet-test-flow.md` - testbed details.
- `../../archive/2026-05-02-1700-node-privacy-from-the-world.md` - world-facing (archived; separate concern).

---

## 1. Scope

The adversary is the AI client itself; see [AI-facing privacy](../../GLOSSARY.md#ai-facing-privacy). The boundary is AI <-> [privacy gateway](../../GLOSSARY.md#privacy-gateway) <-> [local bitcoind](../../GLOSSARY.md#local-bitcoind) (v25.99.0 covtools fork, pruned signet) - the primary boundary: the default onchain mode serves reads and writes from bitcoind alone and never imports the LND client (doc 01 covers the advanced extension that adds the LN surface back). The arbiter <-> bitcoind link is on the *trusted* side of the gateway and carries no local anti-timing mitigation by design - [action delay](../../GLOSSARY.md#action-delay), [result delay](../../GLOSSARY.md#result-delay), and the gateway's latency normalization cover it in aggregate from the petitioner side. World-facing threats (P2P peers, the single Mutinynet peer, explorers, hosting) are out of scope - see the archived world-facing doc.

## 2. Threat model

| Adversary | Observes | Concern |
|---|---|---|
| **The AI client** | every response; request/response timing; any identifier, amount, or address surfaced | malicious by design, compromised, or prompt-injected; may exfiltrate wallet data, probe for UTXOs or xpubs, or induce fund movement |
| **Network observer** (AI <-> gateway link) | traffic metadata even under TLS | timing, connection-count, response-size fingerprinting |

**What makes bitcoind distinct from LND (the non-obvious bits):**

- **Wallet metadata is uniquely toxic.** One leaked [xpub](../../GLOSSARY.md#xpub--descriptor) deanonymizes an account's entire receive + change chain, past and future, in one call. `listdescriptors` on a fresh wallet returned 8 of them. Highest-severity single-call leak in the surface.
- **`getpeerinfo` leaks our public IP to the AI** - `addrlocal: "73.93.99.82"` in every peer row (LAN `addrbind: 192.168.50.12`). Deny or redact.
- **`getnetworkinfo` leaks Tor state** - `onion: reachable=false, proxy=""` tells the AI we are on clearnet, so it can reason about which P2P-layer mitigations we lack.

Out of scope: the bitcoind host OS / disk operator; Bitcoin P2P peers (world-facing); the LND operator (doc 01); OS or hypervisor compromise; physical access.

## 3. Per-RPC leak surface

> **Live surface vs. policy.** The exposed op set depends on the deployment mode (doc 05 §2.2; onchain is the default). Onchain mode - this doc's surface - exposes `query_balance` (read, the bitcoind wallet) and `manage_bitcoin` (write, routed through `sendtoaddress` after the registry and standing-approvals gates). The advanced Lightning extension layers `query_channels` / `manage_lightning` back on, and the eCash extension (`SPACER_MODE=ecash`, doc 07) adds `fund_ecash` / `defund_ecash` on top of the full Lightning surface; against an onchain arbiter every extension op refuses uniformly at the mode gate (audit `decision_refuse_mode`, the op field disambiguating which extension). Every other inbound op parks in [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval) and returns the uniform refusal, so no raw RPC below is directly petitioner-reachable. The cells define policy for any future expansion of the AI-reachable set.

Severity: **HIGH** = full identifier, key material, or balance reveal; **MED** = partial identifiers, counts, patterns, or confirmable state; **LOW** = flags, booleans, or public chain data. The mitigation column tags the glossary mechanism; mechanics and caveats are defined there.

### 3.1 Chain / network info

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `getblockchaininfo` | chain, height, headers, `verificationprogress`, `initialblockdownload`, pruneheight, `size_on_disk`, best hash | MED | surface height + confirmations; strip `size_on_disk` / `pruneheight` (prune window); redact `warnings` (may carry paths) |
| `getnetworkinfo` | `subversion`, services bitmap, reachability, proxy settings, relay fee, `localaddresses` | MED | surface only `relayfee` + connected-network booleans; strip `subversion`, proxy settings (Tor state), `localaddresses` |
| `getpeerinfo` | remote IP, `addrlocal` (our public IP), `addrbind` (LAN IP), `subver`, byte counts, permissions, conn time | **HIGH** | never surface raw; count only. Confirmed `addrlocal=73.93.99.82`, `addrbind=192.168.50.12` |
| `getconnectioncount` | peer count | LOW | safe |
| `uptime` | seconds since start | LOW | reveals restart history; surface with care or strip |
| `getnodeaddresses N` | addrman entries (peer IPs/ports) | MED | default deny (peer-discovery state) |
| `getindexinfo` | which optional indexes are enabled | MED | strip / fixed stub (empty `{}` on this build) |

### 3.2 Mempool

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `getmempoolinfo` | size, bytes, fee floor, unbroadcast count | LOW | safe; no identity linkage |
| `getrawmempool [verbose]` | all local txids; verbose adds fee, size, ancestors, time | MED | return count only (the txid *set* fingerprints our peer topology); strip verbose unless justified |
| `getmempoolentry <txid>` | fee, size, ancestor/descendant info | MED | return sanitized fee/size; withhold first-seen time |
| `gettxspendingprevout` | whether an outpoint is spent in our mempool | MED | gate on the proxy's known-txid set (else maps [UTXO](../../GLOSSARY.md#utxo) ownership) |

### 3.3 Wallet / keys (critical)

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `listdescriptors` | account-level [xpubs](../../GLOSSARY.md#xpub--descriptor) (8 on fresh wallet); xprvs if `private=true` | **HIGH - CATASTROPHIC** | deny at the method level, always |
| `getaddressinfo <addr>` | derivation path, `parent_desc` (account xpub), fingerprint, pubkey, scriptPubKey, labels | **HIGH - CATASTROPHIC** | deny by default - one call returns the account xpub |
| `listwallets` | loaded wallet names | MED | wallet names are identifying ("kyc-account"); return count / fixed alias |
| `getwalletinfo` | name, format, balance, txcount, keypoolsize, `lastprocessedblock` | **HIGH** | never raw; boolean predicate only ("wallet loaded: yes") |
| `dumpprivkey` | WIF private key | **HIGH - KEY MATERIAL** | deny absolutely ([hide secrets](../../GLOSSARY.md#hide-secrets)) |
| `walletpassphrase` / `walletlock` | unlock state (timing-sensitive) | **HIGH** | deny; the arbiter controls unlock state |
| `signmessage <addr> <msg>` | signature proving control of `addr` | **HIGH** | deny by default - caller-controlled challenge-response deanon |
| `importdescriptors` / `importprivkey` / `importaddress` | inject keys/scripts into the watch list | **HIGH** | deny to AI; operator-only (watch-list poisoning + rescan-DoS vector) |
| `rescanblockchain` | forces an expensive wallet rescan | MED | deny; rescan duration leaks wallet depth (see §4.7) |

### 3.4 Balance / UTXO

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `getbalances` | `mine.trusted` / `untrusted_pending` / `immature` / `watchonly.*` | **HIGH** | wallet totals are [scale-cloaked](../../GLOSSARY.md#scale-cloaking) to a fixed presentation window (not banded); per-call fee fields stay on [banding](../../GLOSSARY.md#banding-numeric-value-banding) |
| `listunspent` | every [UTXO](../../GLOSSARY.md#utxo): txid, vout, address, amount, scriptPubKey, descriptor, confirmations | **HIGH** | never dump; [aggregate](../../GLOSSARY.md#aggregate-by-default) ("≥X sats confirmed: yes"); proxy coin-selects internally |
| `scantxoutset` | scans the UTXO set for any caller-supplied descriptor/address | **HIGH** | deny - lets the AI probe arbitrary (even non-operator) addresses |
| `scanblocks` | scans a block range for descriptor matches | HIGH | deny - same as `scantxoutset`, also reveals block-history depth |

### 3.5 Tx construction

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `createrawtransaction` | raw tx hex (no wallet) | LOW | safe, but validate AI-supplied inputs against the known-UTXO set first |
| `decoderawtransaction` | decoded inputs/outputs/amounts/addresses | LOW | safe (AI supplied the hex); use internally to audit before signing |
| `decodescript` | script type, address forms, asm | LOW | safe |
| `getdescriptorinfo` | checksum, `isrange`, `issolvable`, `hasprivatekeys` | LOW/MED | expose for operator-supplied descriptors; deny for AI-supplied (`hasprivatekeys` confirms key material) |
| `walletcreatefundedpsbt` / `walletprocesspsbt` / `signrawtransactionwithwallet` | [PSBT](../../GLOSSARY.md#psbt) / signed tx | **HIGH** | not on the live path - the arbiter sends via the `sendtoaddress` black box (§3.6), so no PSBT contents ever leave bitcoind |
| `estimatesmartfee <target>` | feerate or error | MED | safe to return the feerate; the error-vs-result path reveals IBD state (§4.2) |

### 3.6 Tx broadcast

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `sendtoaddress` / `sendmany` / `send` / `sendall` | txid only (bitcoind does coin selection, change derivation, signing, broadcast internally) | **HIGH** | the live write path: a black box. The arbiter validates destination (via the [recipient address registry](../../GLOSSARY.md#recipient-address-registry)) and amount; it never sees the change address, and no PSBT leaves bitcoind. Irreversible once called |
| `sendrawtransaction` | txid (immediately hits the P2P network) | **HIGH** | not on the live path; if exposed, gate through the registry as above |
| `bumpfee` / `psbtbumpfee` | RBF replacement tx/PSBT | **HIGH** | operator-approval gate; reveals a prior stuck tx exists |

### 3.7 Tx history

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `listtransactions` | full wallet history: txids, amounts, addresses, fees, timestamps, category | **HIGH** | never dump; [aggregate](../../GLOSSARY.md#aggregate-by-default) ("sent this session: ~1k sats") |
| `listsinceblock` | all wallet txs since a block | **HIGH** | deny (as `listtransactions`) |
| `gettransaction <txid>` | wallet tx detail: which addresses are *ours*, fee, blocktime, annotations | **HIGH** | surface only `{confirmed, block_height}`; `category` + `address` confirm wallet ownership |
| `listreceivedbyaddress` | per-address receive totals + funding txids | **HIGH** | deny - maps our addresses to our tx graph |
| `listreceivedbylabel` / `listlabels` / `getaddressesbylabel` | label-to-address mappings | **HIGH** | deny - labels are operator-chosen and identifying |
| `getnewaddress` | fresh HD address | **HIGH** | [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) to a session token; unrestricted access enumerates our HD chain |

### 3.8 Peer / node operations

| RPC | What it returns | Sev | Mitigation |
|---|---|---|---|
| `addnode` | adds a peer (state-changing) | **HIGH** | deny - an adversary can force a connection to a peer they control (eclipse/sybil setup) |
| `disconnectnode` / `setnetworkactive` / `setban` / `clearbanned` | peer manipulation | **HIGH** | deny - network topology is operator-only |
| `submitblock` / `submitheader` | inject blocks/headers | **HIGH** | deny |
| `getrpcinfo` | in-flight RPC calls + log path | **HIGH** | deny - leaks other callers' activity and the debug-log path |
| `stop` | graceful shutdown | **HIGH** | deny absolutely |

## 4. Timing as a leak channel

In the implemented async-result model the AI never polls chain state - it submits an action and polls the [result registry](../../GLOSSARY.md#result-delay) at a fixed 10-min floor (doc 05 §4.8). So §4.1 (polling cadence) and §4.5 (request-gap) apply to a *passthrough-proxy* model, not the live arbiter; the rest are intrinsic to any model. One caveat: `query_balance` is a live synchronous read today, so "never polls chain state" holds only once reads are snapshot-served ([Read snapshot](../../GLOSSARY.md#read-snapshot-snapshot-served-reads); doc 15 owns the read-freshness leak and its closure). Either way the [action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay) layer closes these inside the trust boundary; the values below are what an unmitigated proxy would expose.

| # | Channel | What the AI can infer |
|---|---------|------------------------|
| 4.1 | Polling cadence | Fixed-schedule polling of `getblockchaininfo` / `getbalances` / `getrawmempool` shows as a latency pattern; a 30s cadence fingerprints software + version (moot under the async-result model). |
| 4.2 | Sync-state-dependent timing | `gettxout` / `getrawtransaction` latency and the error-vs-success path reveal `txindex=0` without `getindexinfo`; `estimatesmartfee` erroring confirms IBD state. |
| 4.3 | Mempool query patterns | `getrawmempool` then `gettxout <out>` is a recognizable "watching for this tx" fingerprint; gate queries on the known-txid set. |
| 4.4 | Block-height / IBD inference | Repeated `getblockchaininfo` tracks IBD rate and timestamps the `initialblockdownload: true -> false` transition. The `blocks` vs. `headers` gap beats `verificationprogress` (reports `1` mid-IBD on this build). |
| 4.5 | Request -> send gap | Sub-second = automated coin-selection/sign/broadcast; a 10-60s gap with variance suggests human review (moot under the async-result model). |
| 4.6 | `estimatesmartfee` cache TTL | Latency variance (cache miss vs. hit) correlates fee-estimate calls to impending broadcasts. |
| 4.7 | Wallet rescan timing | `importdescriptors` / `rescanblockchain` duration scales with blocks x addresses; an AI watching `getwalletinfo.lastprocessedblock` advance infers wallet depth and creation date. |
| 4.8 | Pruned-mode latency | `getblock` fails instantly for pruned heights but reads from disk for in-window ones, so the AI can binary-search the prune horizon. Return a uniform stub error for all out-of-window requests. |

## 5. Mitigations

Every per-RPC mitigation in §3 is a standard arbiter mechanism, defined with its residual-leak caveat in the [glossary Mitigations section](../../GLOSSARY.md#mitigations): [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization), [banding](../../GLOSSARY.md#banding-numeric-value-banding) / [scale cloaking](../../GLOSSARY.md#scale-cloaking), the [recipient address registry](../../GLOSSARY.md#recipient-address-registry) (the WHO gate), [standing approvals](../../GLOSSARY.md#standing-approvals) (the WHAT gate - which `(op, destination, amount)` tuples dispatch without a [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval) pause), [aggregate-by-default](../../GLOSSARY.md#aggregate-by-default), [hide secrets](../../GLOSSARY.md#hide-secrets), and the [audit log](../../GLOSSARY.md#audit-log). Two bitcoind-specific applications: coin selection and signing stay inside bitcoind via the `sendtoaddress` black box (stronger than a PSBT round-trip - no PSBT ever leaves the daemon), and wallet/descriptor import is operator-only.

The §4 timing channels are **not** addressed by per-response padding. The [action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay) layer absorbs the sync-state, rescan, and cache-TTL variation inside the trust boundary before any result surfaces (see [latency fingerprinting](../../GLOSSARY.md#latency-fingerprinting)). Tor and self-hosted esplora are world-facing.

## 6. bitcoind vs. LND

Both need active filtering, but the policies differ in kind, not just degree.

| Dimension | bitcoind | LND |
|---|---|---|
| Most dangerous single call | `listdescriptors` - account xpubs compromise the whole address space, past and future | `listchannels` - every channel's pubkeys, balances, and activity counters in one call |
| Key material | xpubs (`getaddressinfo` / `listdescriptors`), xprvs, WIF (`dumpprivkey`) | preimages (`listpayments`), macaroons |
| AI-visible topology | peer IPs (`getpeerinfo`); no channel graph | full channel graph (`listchannels`), node pubkey + peer IPs (`listpeers`) |
| IP leak to AI | `getpeerinfo.addrlocal` = our public IP in every row | `listpeers` peer IPs; `connect` logs our IP against a target |
| Irreversibility | `sendtoaddress` broadcast is permanent and immediate | LN payment can fail via HTLC timeout; close has a cooperative window |
| Policy weight | wallet/UTXO: coin selection, xpub lockdown | channel/route: channel policy, routing, pathfinding-score lockdown |

bitcoind is more dangerous on the wallet / key-derivation side (one `getaddressinfo` or `listdescriptors` ends wallet privacy permanently); LND on the topology / payment-correlation side (`listchannels` maps every LN relationship).

## 7. Open questions

1. **Rescan timing leak.** Import descriptors of known depth (1000 vs. 3000 addresses), measure `rescanblockchain` duration, and find the `getwalletinfo` rate limit that stops an AI inferring wallet depth from `lastprocessedblock`.
2. **`estimatesmartfee` cache behavior.** Measure latency variance across targets; determine the cache TTL and whether two concurrent callers share a cached value (a cross-caller side-channel).
3. **Pruned-mode behavior.** With `prune=2200`, confirm the proxy returns a uniform stub error for sub-horizon `getblock` rather than the raw bitcoind error.
4. **Binary-search balance probing.** Test [scale cloaking](../../GLOSSARY.md#scale-cloaking) against a sequence of send attempts with rising amounts; design the rate-limit + noise policy.
5. **`getrpcinfo` cross-caller leak.** If ever exposed, confirm two concurrent callers cannot see each other's in-flight RPC names.

## 8. Reconciliation status

**2026-05-24, updated 2026-06-12**, reconciled against `arbiter/src/bitcoin.py`, `gateway.py`, and `scale.py` (triggering commits a12b1c8 "allowlist deleted, registry IS the destination gate", 99bcc49 "standing approvals as the WHAT gate", and 9081f46 "onchain (Bitcoin-first) default mode"). The findings are folded into the body above: the allowlist->registry rename is complete; §3.4 and §5 use scale cloaking for wallet/channel totals (not banding); §3.5/§3.6 reflect the `sendtoaddress` black box rather than a PSBT round-trip, and drop the change-address validation the arbiter never performs; §5 names standing approvals as the WHAT gate beside the registry's WHO gate (wired, both branches exit-loop-validated); §3's lead note marks the per-RPC table as forward-looking policy beyond the live mode-dependent op surface; §1 records the arbiter <-> bitcoind link as intentionally un-mitigated locally; and the 2026-06-12 pass marks bitcoind as the primary surface, with `query_balance` served from the bitcoind wallet (`getbalance()` scaled to integer sats, then scale-cloaked) and the LN ops extension-gated per doc 05 §2.2. None of this changed the threat model (§2-§4) or the mitigation catalogue (§5).

The 2026-06-12 eCash-build pass (sp-2hwco4.2, reconciled in doc 07 §11) left this surface untouched: onchain stays primary, its exit-loop artifacts stayed byte-identical modulo timestamps/ports, and `arbiter/src/ecash.py` joins `lnd.py` in the never-imported set for onchain deployments (asserted by the no-ecash-import gate). The §3 lead note now counts the eCash writes among the extension-gated ops an onchain arbiter refuses.
