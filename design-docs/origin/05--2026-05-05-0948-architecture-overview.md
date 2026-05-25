# Spacer Architecture Overview

**Date:** 2026-05-05
**Context:** Logical architecture of the spacer system: the components, the trust boundary between them, the end-to-end data flow of a state-changing call.
**Related:**
- `../GLOSSARY.md` - vocabulary; this doc references glossary terms by link rather than redefining them.
- `2026-05-02-1601-privacy-and-timing-leaks.md` - per-API leak surface for LND.
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` - per-API leak surface for bitcoind.
- `~/spacer/archive/2026-05-02-1700-node-privacy-from-the-world.md` - world-facing privacy (separate threat model).

---

## 1. Purpose and scope

[Spacer](../../GLOSSARY.md#spacer) lets an AI client drive a Bitcoin and Lightning node without learning more about the operator's wallet, balances, or identifiers than the task requires. The design splits into two processes joined by a protocol; the protocol is the trust boundary.

Out of scope for this doc: [world-facing privacy](../../GLOSSARY.md#world-facing-privacy) (what the public networks, peers, explorers, and hosting providers can observe), wire formats, API shapes, data model schemas, code structure inside either component, and the bitcoin/LN primitives the design relies on. Each of those is either already in the glossary as background vocabulary or will get its own per-decision design doc.

---

## 2. The two components and the trust boundary

The system is two processes:

- The [petitioner](../../GLOSSARY.md#petitioner): client-side, runs in the AI's environment, holds no secrets.
- The [arbiter](../../GLOSSARY.md#arbiter): server-side, the AI cannot reach it; it bundles the [privacy gateway](../../GLOSSARY.md#privacy-gateway), the bitcoin and LND client access, the local state, the [audit log](../../GLOSSARY.md#audit-log), and the timing layer that enforces [action delay](../../GLOSSARY.md#action-delay) and [result delay](../../GLOSSARY.md#result-delay).

The spacer protocol is the boundary between them. The asymmetric naming is intentional and reflects the trust direction: a petitioner asks, an arbiter decides. Putting any sensitive logic on the petitioner side places it in reach of the AI and defeats the point.

### 2.1 Arbiter implementation discipline

The arbiter implementation lives at `spacer/arbiter/`, with all runnable code under `spacer/arbiter/src/`. Two hard constraints on what goes there:

- **Minimal**: small line count, small dependency footprint. The entire codebase must fit in a human's head during a single review pass.
- **Inline-documented only**: documentation lives in code comments. No separate Markdown or other doc files inside `src/`. Anything that needs explaining is explained where the code is.

The arbiter must be **manually auditable**: a human can copy, install, and read the entire codebase without any AI assistance. The arbiter never runs AI itself, so any AI-generated implementation reaching it has to survive a non-AI human review pass first. This trades implementation ergonomics for a hard auditability floor and is the central design constraint on the arbiter.

---

## 3. End-to-end data flow

A single state-changing call from AI to on-chain effect to AI-visible result:

```
AI
  |  invokes
  v
[petitioner]                              (in AI's environment; no secrets)
  |  spacer protocol over network
  v
[privacy gateway]                         (network entry point on arbiter)
  |  filtered, gated, audit-logged
  v
[arbiter internals]                       (out of AI reach)
  |
  +--> [recipient address registry]       (resolve recipient_token to real destination;
  |                                        miss = uniform refusal)
  +--> [standing approvals check]         (resolved (op, destination, amount) match
  |                                        a rule in the operator's YAML? no = HITL park;
  |                                        unknown op = also HITL park)
  +--> [token-to-real mapping]            (resolve other pseudonyms to concrete identifiers)
  +--> [audit log]                        (request, decision, and outcome appended)
  |
  v
[timing layer: action delay window]      (~12h floor, randomized within dynamic window)
  |
  v
[bitcoind / LND client access]           (bitcoin-cli, lncli, gRPC/REST)
  |
  v
[on-chain / LN-network effect]           (broadcast, channel open, payment, etc.)
  |
  v
[timing layer: result delay window]      (~12h floor; result held back regardless)
  |
  v
[privacy gateway]                         (filter outbound result; band, tokenize, redact)
  |  deposit into result registry (arbiter-side)
  v
[result registry]                         (pull-only, 10-min poll floor; §4.8)
  |  petitioner polls; "result" or "not yet", nothing in between
  v
[petitioner]
  |
  v
AI                                        (sees only banded/tokenized outcome)
```

The petitioner gets an immediate synchronous acknowledgment ("received: opaque-handle") at submission time, but every AI-observable consequence of the call - on-chain visibility and result knowledge - is deferred by the timing layer.

Read-only queries take the same petitioner -> privacy gateway -> arbiter internals path but skip the timing layer; their response shape is filtered by the same outbound mechanisms ([banding](../../GLOSSARY.md#banding-numeric-value-banding), [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization), [aggregate-by-default](../../GLOSSARY.md#aggregate-by-default), [hide secrets](../../GLOSSARY.md#hide-secrets)) and stamped with [latency normalization](../../GLOSSARY.md#latency-normalization).

---

## 4. Components on the arbiter

### 4.1 Privacy gateway

The [privacy gateway](../../GLOSSARY.md#privacy-gateway) is the **only** network-reachable component on the arbiter. Every petitioner request hits it first. Because it is the entry point, it must be:

- **Limited**: small surface, narrow responsibilities, few dependencies.
- **Airtight**: no bypass paths to bitcoind, LND, or arbiter state; no information leakage through error messages, timing, or response shape; no untrusted deserialization beyond what the protocol strictly requires.

Anything that does not need to be exposed to the network does not live in the privacy gateway. Long-term storage (preimages, descriptors, PSBTs, the audit log itself, the token-to-real mapping) lives elsewhere on the arbiter.

Concrete mechanisms the privacy gateway applies on each request: [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) identifiers (which for state-changing calls doubles as the destination gate by resolving the recipient_token through the [recipient address registry](#47-recipient-address-registry) and uniformly refusing on miss), check the resolved call against the operator's [standing approvals](../../GLOSSARY.md#standing-approvals) config (state-changing calls only; no match parks in HITL), [band](../../GLOSSARY.md#banding-numeric-value-banding) numeric values on cloak-ineligible fields, [scale-cloak](../../GLOSSARY.md#scale-cloaking) wallet-level totals (a stronger sibling of banding that hides the order of magnitude as well as the precise figure - applied to balance / channel-capacity reads **in place of** banding; the per-tier scale already compresses 10x+ so layering a fixed-resolution band on top adds no privacy), defer unrecognized ops to a human via [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval), append every request and decision to the [audit log](../../GLOSSARY.md#audit-log), and [latency-normalize](../../GLOSSARY.md#latency-normalization) every outbound response to a deployment-configured floor so per-response timing carries no information about which step refused or how far the pipeline progressed.

**Implementation status.** The skeleton at `arbiter/src/gateway.py` wires the HTTP entry, JSON parsing, audit logging, latency normalization, registry-gated resolution for write ops, the HITL park for unrecognized ops, the result-poll fast path (§4.8), and dispatch for read-only ops (`query_balance`, `query_channels`) through scale cloaking. Pending wire-ups: the standing-approvals check between registry resolution and write dispatch; the timing layer (§4.6) + bitcoind / LND executor that convert resolved write requests into on-chain effect; band-edge randomization for numeric banding and aggregate-by-default on cloak-ineligible fields; the HITL queue table that backs `_hitl_park` (the current stub audit-logs the deferral and returns the uniform refused body but writes no queue row). Each pending mechanism is a named function (`_hitl_park`, `_band_outbound`, `_aggregate_outbound`, the write-dispatch fallthrough in `_dispatch`) so a non-AI reviewer can confirm at a glance what is wired in behavior vs present in structure.

### 4.2 Bitcoin client access

Wrapped access to the [local bitcoind](../../GLOSSARY.md#local-bitcoind). The arbiter shells out via `bitcoin-cli` against the locally self-hosted bitcoind under `spacer/arbiter/bitcoin/`. Coin selection and signing stay inside the arbiter; PSBTs constructed during signing never leave (see [hide secrets](../../GLOSSARY.md#hide-secrets)). The [btccli](../../GLOSSARY.md#btccli) wrapper currently lives in `test-harness/scripts/`; the production arbiter will use its own wrapper or call `bitcoin-cli` directly.

### 4.3 LND client access

Wrapped access to LND over `lncli` plus gRPC/REST. The current testbed wrapper [lncliA](../../GLOSSARY.md#lnclia) is testbed-scoped (Voltage-hosted Node A); the arbiter's production access will follow the same pattern but against the deployment's LND instance.

Read-only balance and channel-capacity responses (`walletbalance`, `channelbalance`) are subject to [scale cloaking](../../GLOSSARY.md#scale-cloaking) before they cross the privacy gateway: the petitioner sees a sat figure projected into a fixed 0-100k presentation window regardless of whether the underlying wallet holds 50k, 5M, or 500M. Aggregate-by-default (§4.1) still applies on top of cloaking for channel-list responses, so per-channel detail is suppressed even when the aggregate is cloak-presented.

### 4.4 Local state

Holds:

- The token-to-real mapping that backs [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization). For outbound recipient destinations specifically, this is the [recipient address registry](#47-recipient-address-registry) described in §4.7.
- The pending [HITL approval](../../GLOSSARY.md#human-in-the-loop-hitl-approval) queue.
- Any pending action+result deferrals being tracked by the timing layer.

All of it stays on the arbiter. The petitioner cannot reach any of it.

### 4.5 Audit log

The append-only [audit log](../../GLOSSARY.md#audit-log) records every AI request and every arbiter decision (allow, deny, redact, band, defer-to-human). The log lives in the arbiter's environment, which the petitioner does not own and cannot reach, so tampering from the AI side is structurally impossible.

**Format.** One JSON object per line (JSONL). Each record carries a UTC ISO-8601 timestamp, a short event tag (`request_received`, `decision_allow`, `decision_refuse_registry`, etc.), and a JSON-serializable payload.

**Durability and atomicity.** Every record is fsynced before `record()` returns, so a successful return means the bytes are on disk. The underlying write uses `O_APPEND`, which on POSIX is atomic for buffers up to `PIPE_BUF` (4096 bytes); an in-process lock serializes any longer records. The single-process arbiter discipline (§4.1) is load-bearing here: it removes the need to coordinate across writers via filesystem locking.

**Immutability rests on structure, not enforcement.** The module exposes only `configure()` and `record()`; there is no code path that edits or deletes existing records. Combined with the structural unreachability above, that absence is the entire immutability story.

**Location.** `arbiter/state/audit.log`, gitignored alongside other runtime state per the [arb-auditability](06--2026-05-24-0623-arb-auditability.md) tree (§3). Overridable at startup via the `AUDIT_LOG_PATH` environment variable or an explicit `configure(path)` call, primarily for tests and for sites that put runtime state on a separate volume.

**Companion primitive.** The runtime log captures every request and decision but says nothing about *what was deployed* when those decisions were made. The [continuous git snapshot](06--2026-05-24-0623-arb-auditability.md) covers that complementary axis: arbiter code and config on disk, committed every minute. Neither subsumes the other.

### 4.6 Timing layer

The arbiter component that enforces both anonymity-set delays:

- [Action delay](../../GLOSSARY.md#action-delay): wait between the petitioner submitting a state-changing action and the arbiter actually executing it against the network. ~12h floor, randomized within a window that the arbiter computes dynamically from observed global activity for similar actions, targeting a configurable anonymity set.
- [Result delay](../../GLOSSARY.md#result-delay): wait between the arbiter completing the action and the petitioner being able to learn the result. Same window construction, same ~12h floor, computed against observed network activity for similar result-shapes.

The dynamic window calculation observes global activity for actions or results of the same shape and stretches or compresses the window to keep the anonymity set above a target. Constant or naive parameters defeat the mechanism (the distribution itself becomes a fingerprint), so the calculation is part of the security surface, not just a tuning knob.

The same module also enforces the §4.7 rejection-delivery delay. The three delays share one defer-then-pop substrate: state-changing actions park in `pending_actions` with a `ready_at`; outcomes (results or rejections) park in `pending_results` with the same shape plus a kind tag; a future executor drains due entries by elapsed `ready_at` in arrival order.

**Status: partial.** Test-mode windows are wired end-to-end (5-15s action, 5-15s result, 1-5s rejection-delivery; see §10). Production mode is blocked behind the dynamic-window calculation (§7) and raises `NotImplementedError` on every enqueue path until that lands - the safe failure mode for a misconfigured environment is "does not run," not "runs with the wrong window." Mode selection is conservative: only an exact `SPACER_TIMING_MODE=test` enables test mode, so a typo, miscased value, or unset variable lands in production and refuses. The `enqueue` / `due` / `pending` APIs and both pending-deferral tables exist; the action executor that drains due actions against bitcoind/LND and the result-registry consumer that drains due results for petitioner pickup are not yet implemented.

### 4.7 Recipient address registry

Manages the pseudonymized handles the petitioner uses to refer to Bitcoin and Lightning destinations the operator has approved as send targets. Concrete implementation of [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) for outbound destinations, combined with one-time-use enforcement and an explicit human-driven creation flow.

**This section IS the destination gate.** The arbiter has a single universe of approved physical destinations - the registry - and there is no separate outbound-policy step stacked on top of it. A state-changing call carries a `recipient_token`; the privacy gateway calls `registry.lookup()` during pseudonymize-inbound; any outcome other than `ok` (bad checksum, unknown, expired, already used, anomalous) collapses to the uniform "destination unavailable" refusal at the gate. The lookup *is* the gate.

**Storage substrate.** A YAML file at a known path on the arbiter, hand-edited by the operator at the directly-attached console. The arbiter is deliberately minimal and manually managed (§2.1); adding a destination, retiring one, or auditing what is in the universe should be one open-file / edit / save round-trip in any text editor, with no tool, no schema migration, and no query language between the operator and the data. The registry module reads the YAML; the operator owns the file. (Migration note: as of this writing the registry is backed by a SQLite table in arbiter local state. The YAML migration is the next milestone in this chain.)

**Entry creation.** Real recipient addresses enter the registry **only** via direct human interaction with the arbiter: a keyboard and monitor physically connected to the arbiter host, plus a text editor on that console for the YAML file. The petitioner has no way to add an entry; the AI never sees the real address.

The operator runs a registry-add command at the console and **types** the real address. There is no clipboard between this console and any other system, so the address must arrive in a form a human can hand-transcribe in one sitting. The arbiter validates the address's built-in checksum before creating an entry. A typo that breaks the checksum is rejected at parse time, so the operator gets immediate feedback rather than discovering the mistake at send time hours later.

The accepted on-chain encodings are: **bech32** (P2WPKH, P2WSH segwit, BIP-173), **bech32m** (P2TR taproot, BIP-350), and **base58check** (P2PKH, P2SH legacy, BIP-13). Format detection runs in fixed order (bech32m, bech32, base58check); the three polymods are non-overlapping so at most one matches in practice. Lightning-side encodings (BOLT-11 invoices, BOLT-12 offers, Lightning Address) are not yet supported - they are either too long to retype reliably (BOLT-11) or introduce trust dependencies (Lightning Address resolution touches an outside host); the set of acceptable LN-side input encodings is open (§7).

**No-mainnet hard rule.** The registry refuses mainnet at add time: bech32 / bech32m HRP must be `tb` (testnet/signet) or `bcrt` (regtest); base58 version byte must be `0x6F` (testnet/signet P2PKH) or `0xC4` (testnet/signet P2SH). Mainnet HRPs `bc` and base58 versions `0x00` / `0x05` are rejected with the same refusal path as a malformed address. This is enforced at the registry boundary rather than only at dispatch, so a fat-fingered mainnet address never lands in storage.

On a successful add the arbiter prints the entry's local-only numeric ID and the public-facing token back to the console.

**Entry shape (logical).**

- `id`: monotonically increasing local sequence number (1, 2, 3, ...), assigned at creation. **Local-only.** Never crosses the privacy gateway, never appears in petitioner-visible responses. It exists so the operator at the console can refer to "address number 42" in their own notes - giving the human a stable, ordered, easy-to-speak handle without exposing creation order to the petitioner.
- `token`: 5 random characters from the [Crockford-base32](https://www.crockford.com/base32.html) alphabet (`0-9` + `A-Z` minus the visually ambiguous `I`, `L`, `O`, `U`) followed by 1 Damm32 check character, for a total length of 6. This is the **only** handle the petitioner sees. The token is hand-transcribed on the petitioner side too (operator reads it off the console, hands it to the AI via voice / paper / out-of-band channel). The Damm32 check character is computed over the random portion in GF(2^5) with reduction polynomial `x^5 + x^2 + 1`; the resulting quasigroup detects **every** single-character substitution and **every** adjacent transposition of distinct characters - the two transcription-error classes that dominate hand-typed short tokens. The arbiter validates the checksum at the privacy gateway and returns the same uniform "destination unavailable" response on a checksum failure as on any other refusal (§Refusal behavior), so checksum failures do not leak whether the rest of the token matched a real entry. The 25-bit random namespace (`32^5` = 33,554,432) keeps the 1% utilization warning rare in practice (see Namespace pressure below).
- `real`: the actual destination (Bitcoin address or LN invoice / offer / pubkey). Held only on the arbiter; subject to [hide secrets](../../GLOSSARY.md#hide-secrets).
- `created_at` / `expires_at`: timestamp pair. Default expiry is `created_at + 7 days` if the entry has not been used by then; operator can override at creation.
- `used`: boolean, default `false`. Flipped to `true` on the first successful send against this entry and never flipped back.
- `consumed_by`: when `used == true`, the txid (Bitcoin) or payment hash (Lightning) that consumed the entry, for audit traceability.

**Token generation.** The 5-character random portion is drawn from 25 bits of `os.urandom`; the Damm32 check character is then computed deterministically from the random portion. On creation the arbiter checks for token-namespace collisions on the random portion and re-rolls; after 10 consecutive collisions on the same add (a sign the namespace is full enough that probabilistic retry is no longer cheap) the add raises a `namespace unhealthy` error rather than looping forever, signaling the operator to clean up expired or unused entries. The sequential numeric `id` is indexed independently of `token` and cannot collide.

**Input normalization.** Crockford-base32 omits `I`, `L`, `O`, and `U`. On lookup, the registry maps `I` and `L` to `1` and `O` to `0` before validation, so an operator who reads "1" over the wire and the petitioner side transcribes it as "I" (or vice versa) still resolves to the canonical token. `U` has no canonical mapping and is excluded entirely from the alphabet; a typed `U` fails alphabet validation rather than silently mapping to `V`. Outer whitespace is stripped and case is uppercased before lookup.

**One-time use.** Every send-to-token call is gated on `used == false` and `expires_at > now` **at lookup time**. On a successful send the arbiter sets `used = true` and records `consumed_by`. Subsequent sends to the same token are refused. This prevents on-chain / on-LN address reuse independent of operator discipline: the petitioner cannot reuse a destination even if it remembers the token. The consume step is a single atomic UPDATE gated only on `used == false`; it deliberately does **not** re-check `expires_at`, because the [Action delay](../../GLOSSARY.md#action-delay) window can span hours and an entry may cross its expiry between gateway-side lookup and dispatch-side consume. Once the action was authorized at lookup, post-action record-keeping must record use - otherwise a long-delayed send would land on-chain without an `used = true` flip and the token could be reused.

**Refusal behavior.** A lookup returns one of five outcomes: `ok`, `bad_checksum` (typo, alphabet error, length mismatch, or non-string input), `unknown` (passes checksum but no row), `expired` (past `expires_at`), `used` (already consumed), or `anomalous` (defense in depth: a re-validation of the stored real address failed, indicating storage corruption or a validator change since add-time; should never fire in normal operation). The petitioner-visible signal collapses to one bit: `ok` (action proceeds) or refused (a single generic "destination unavailable" response, with no differentiation across the four refusal cases - five if `anomalous` fires). The audit log differentiates the actual cause for operator triage; differentiating in the petitioner response would let the petitioner probe registry state by submission.

**Probing infeasibility.** An AI cannot map the destination universe by submitting candidate tokens in a tight loop. Four mechanisms compose to make the probing strategy prohibitively expensive in any realistic threat model:

- [Action delay](../../GLOSSARY.md#action-delay) imposes a ~12h floor on every state-changing call (§4.6). 100 probes is ~50 days; the namespace is much larger than that.
- [HITL approval](../../GLOSSARY.md#human-in-the-loop-hitl-approval) fires on every state-changing call that does not match a [standing approval](../../GLOSSARY.md#standing-approvals) and on every inbound op the gateway does not recognize, so unusual submission patterns surface to the operator on the directly-attached console.
- One-time-use enforcement (above) means a token that *does* resolve is consumed on first use; the petitioner cannot re-test a successful hit to confirm it.
- The [audit log](../../GLOSSARY.md#audit-log) records every attempt for non-AI human review, and [latency normalization](../../GLOSSARY.md#latency-normalization) (§4.1) collapses the per-response timing channel that would otherwise distinguish "miss" from "hit but pending consume" by response time.

**Rejection-delivery delay.** Rejections do not reach the petitioner immediately. The arbiter holds the "destination unavailable" response for **1 hour ± 30 minutes** (randomized per rejection) before depositing it into the [result registry](#48-result-registry); the petitioner picks it up via the normal poll path. This (a) closes the submission-to-response timing channel that would otherwise let the petitioner probe token validity by measuring how fast a "destination unavailable" comes back, and (b) decouples the rejection's appearance to the AI from any operator reaction on the arbiter console - the operator can see the invalid attempt in the audit log and hand-retype a corrected token across to the AI without their reaction time being timing-coupled to what the AI eventually observes. The 1-hour window is shorter than the multi-hour Action delay because no on-chain anonymity-set defense is needed (nothing went on-chain); the only adversary the rejection-delivery delay defends against is the petitioner's correlation of submission time with response time, which a 1-hour ± 30-min window already breaks at the relevant resolution.

**Operator guidance for invalid-token attempts.** When the operator sees an invalid-token entry in the audit log, they should not react in less than the 1 hour ± 30 min rejection window. The arbiter is enforcing the delay automatically; an operator who hand-retypes a corrected token across to the AI within minutes of seeing the audit entry only consumes the privacy budget the delay was designed to provide. Reacting fast does not help the AI receive the corrected token any sooner - the AI only learns of the invalid token after the rejection-delivery delay anyway.

**Namespace pressure and cleanup.** Used and expired entries are retained by default for audit and operator tracking; the registry is not aggressive about garbage-collecting them. The arbiter monitors namespace utilization (live entry count / token-namespace size) and warns the operator when it crosses **1%**. At that point the operator manually removes old entries to keep collision probability and re-roll cost low. With a sensibly-sized token length this threshold is rarely reached in practice; cleanup is an operator decision, not a hot-path concern.

**Caveats.**

- The numeric `id` is local-only by intent, but anything the operator writes down or speaks aloud while reading it from the console is outside the trust boundary. Operator-side discipline is part of the security surface.
- The 7-day default expiry trades usability (longer = more time to actually send) against exposure window (shorter = real-address mapping discarded sooner). Tunable at creation; not yet measured against real workflows.

### 4.8 Result registry

Arbiter-side storage for completed results - and for delayed rejections - queried by the petitioner via a polling endpoint on the privacy gateway. Deposits arrive via the [timing layer](#46-timing-layer): the privacy gateway filters / bands / tokenizes the outcome and enqueues it on the timing layer's `pending_results` side; after the [result delay](../../GLOSSARY.md#result-delay) window elapses on a valid action (or the §4.7 rejection-delivery window on a "destination unavailable" rejection), the timing-layer drainer deposits it into this registry against the original handle. The registry records the `kind` (`result` vs `rejection`) for audit-log triage only; the wire response is identical for both, so the petitioner cannot distinguish a rejection from a regular result on the wire - which is the property the §4.7 rejection-delivery delay relies on. The petitioner retrieves whatever is there by polling for that handle. The registry itself never reaches over the wire to the petitioner; the petitioner only ever sees the gateway's poll response.

**Pull-only.** The arbiter never initiates contact with the petitioner; the petitioner asks. There is no callback, no push, no notification channel. This keeps every outbound timing signal on the petitioner side and avoids any arbiter-initiated traffic that could correlate with internal completions.

**Binary state.** A poll returns either the result for a given handle or "not yet." There is no "in progress," no "running," no progress percentage, no estimated time remaining. The petitioner reasons about elapsed time entirely from its own local estimate (§5.2).

**10-minute poll floor.** Successive polls for the same handle are throttled to a minimum interval of **10 minutes**. The floor is keyed by handle alone, not by petitioner identity: the handle is itself the petitioner-binding identifier (see the caveat below), and the arbiter has no notion of petitioner identity at this layer - transport-layer authentication is configured outside the codebase (§4.1). The privacy gateway routes polls into the registry, which enforces the floor; poll requests issued more frequently get the same "not yet" response without consulting result-table state, so a polling cadence faster than 10 min reveals nothing the cadence at 10 min would not. The 10-min floor (a) matches the natural bitcoin block cadence, (b) pins polling resolution well below any inference precision useful against the multi-hour delay window, (c) flattens result-shape-specific cadences so chain-vs-LN cannot be inferred from polling rhythm, and (d) caps the load the AI can put on the gateway by poll-storming.

**Idempotent retrieval.** A successful retrieval marks the entry consumed. Subsequent polls for the same handle return "not yet" indistinguishably from a never-existed handle, so the petitioner cannot replay a result by re-asking and a handle that was retrieved cannot be distinguished from a handle that never existed. The floor anchor advances on the first non-throttled poll *before* the result table is consulted, so a crash between anchor-set and consume cannot let the next poll bypass the floor; a throttled poll inside the floor does *not* advance the anchor, so polling spam cannot push the next allowed poll further out. A poll on a never-existed handle still anchors the floor, so a deposit that arrives between the first poll and the next allowed poll surfaces no earlier than that next allowed poll. All "not yet" cases (floor throttle, never-existed, already-consumed, bad-input) are wire-indistinguishable, but the audit log differentiates them for operator triage.

**Caveat.** The handle (the opaque acknowledgment string returned at submission time) is itself a stable identifier and links submission to retrieval. The petitioner can correlate "I submitted with handle H, then later got a result for H." This is intentional - the AI must be able to find its own results - but it means the handle is sensitive on the petitioner side; if it leaks elsewhere (e.g., into another AI's context), that other party can probe for the result.

---

## 5. Components on the petitioner

### 5.1 Protocol shim

The only first-class function of the [petitioner](../../GLOSSARY.md#petitioner) is translating AI requests into spacer-protocol messages and presenting the arbiter's responses back. It holds no secrets, no policy, no state that the AI cannot already reach.

The petitioner is exposed to the AI as a single CLI tool named **`petcli`**. The implementer is asked to organize `petcli` as a nested tree of commands and subcommands with informative `--help` at every node, so the AI can discover available operations by walking the help output rather than relying on external documentation. The specific command shape - which commands, what subcommand structure, what flags - is deliberately not enumerated in this doc; that is an implementation decision.

**Transport-error envelope.** The shim distinguishes two failure classes on the AI-visible surface. Arbiter refusals come back in the gateway's uniform `{"status": "refused"}` body (§4.1, §4.7), which carries privacy-model meaning. Petitioner-side transport failures - connection refused, timeout, non-JSON body - come back as `{"_petcli_transport_error": "<reason>"}` instead. The leading underscore is the convention: any top-level key the petitioner adds to a response (transport errors, the §5.2 estimate stamp on submit responses) is prefixed with `_petcli_` so the AI can tell at a glance which fields the arbiter emitted and which the shim annotated. Surfacing transport errors as a structured petitioner-side response - rather than masking them as refusals or letting an exception escape - keeps the boundary between "the arbiter said no under the privacy model" and "the petitioner could not reach the arbiter" load-bearing on the AI side.

### 5.2 Estimate display

Because [result delay](../../GLOSSARY.md#result-delay) makes results asynchronous, the petitioner needs an estimate of total elapsed time (action delay + result delay) so the AI can reason about the decision tree:

- Still within window -> wait.
- Past the upper bound and no result -> assume lost; decide whether to re-initiate.
- Result arrived -> success / failure.

The petitioner computes this estimate locally. It estimates the anonymity set size from its own view of similar global activity and derives an upper bound on the window from that. No estimate information comes from the arbiter, and the arbiter offers no guarantee on the bound. The exact local-estimation method is open (see §7).

**Current implementation.** A placeholder hardcoded upper bound, accepted for early scaffolding: **24 hours** in default deployments (comfortably above the 2 * ~12h floor of §4.6) and **30 seconds** when the petitioner is told the arbiter runs in test-mode timing (`PETCLI_TEST_TIMING=1`, mirroring the per-environment opt-in pattern of the arbiter's `SPACER_TIMING_MODE=test`; §10). The placeholder does not yet observe similar global activity - the petitioner-side observation infrastructure is gated on the same sp-77lxs.3 dynamic-window calculation that gates the arbiter's window (§7 "Dynamic window calculation"). The "still within window vs assume lost" decision tolerates a loose upper bound (extra waiting) far better than a tight one (false "assume lost" before the result actually arrives), so the placeholder errs high. The shim stamps this estimate onto every state-changing submit response under the `_petcli_estimate_window_s` annotation (per the §5.1 underscore convention) so the AI sees the handle and the window in the same envelope.

---

## 6. Mitigation map

Where each glossary mitigation fires in the data flow.

- [Pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) / [recipient address registry](#47-recipient-address-registry): privacy gateway, on outbound responses for general pseudonymization; the registry (§4.7) handles outbound recipient destinations and gates *who* can be a destination - state-changing calls resolve `recipient_token` through `registry.lookup()` during pseudonymize-inbound, and a non-`ok` outcome collapses to the uniform "destination unavailable" refusal. One-time-use enforcement, human-driven YAML-file creation flow, and the probing-infeasibility argument all live in the registry.
- [Standing approvals](../../GLOSSARY.md#standing-approvals): privacy gateway, after the registry has resolved the destination and before dispatch fires. Gates *which* actions to a resolved destination flow through without a HITL pause. The config is an operator-edited YAML file at a known path on the arbiter; the file ships empty, so every state-changing call HITLs by default. Operators ratify trusted patterns by hand-adding rules; the friction is the pedagogy. Applies to state-changing ops only; reads dispatch unconditionally.
- [Banding](../../GLOSSARY.md#banding-numeric-value-banding): privacy gateway, on outbound responses to amount / fee fields. For wallet-level balance and channel-capacity totals specifically, [scale cloaking](../../GLOSSARY.md#scale-cloaking) replaces straight banding because hiding the order of magnitude is the load-bearing property there; per-call fee / amount fields stay on banding.
- [Scale cloaking](../../GLOSSARY.md#scale-cloaking): privacy gateway, on outbound responses to wallet-balance and channel-capacity reads. Stronger sibling of banding: projects the real total into a fixed 0-100k presentation window so two wallets at vastly different scales present the same number for identical real balances, and uses a multi-day randomized tier-shift delay so a presented-value step looks identical to a normal payment in/out rather than to a tier crossing. **Status: open.** Test-mode delays (5-15s) and deterministic per-tier scales are wired and validated end-to-end via the exit-loop's cloaked-tier-1, cloaked-tier-2, transition-pending, and transition-applied variants; production needs multi-day randomized delays and within-tier scale randomization, and is gated behind a NotImplementedError until those land.
- [Human-in-the-loop approval](../../GLOSSARY.md#human-in-the-loop-hitl-approval): triggered by the privacy gateway in two cases: (a) a state-changing call that resolved a valid `recipient_token` but matches no rule in [standing approvals](#41-privacy-gateway) (default-pause: empty config = every write HITLs), and (b) an inbound op the gateway does not recognize - anything outside the known read set (`query_balance`, `query_channels`) and the known write set (`send_bitcoin`, `send_lightning`). The call parks in the HITL queue (local state) until an out-of-band human assent arrives. The out-of-band channel is the directly-attached arbiter console (the same KVM used by the [recipient address registry](#47-recipient-address-registry) in §4.7 and the standing approvals YAML) - never the petitioner's RPC channel. The operator sees the pending request on the console and approves or denies at the keyboard. Anything that needs to flow back to the AI side from a HITL decision (e.g., a freshly-issued recipient token) does so by the operator manually retyping it on the AI / petitioner side; there is no clipboard between the arbiter console and the AI's environment. (Recognized ops with a recipient_token miss do not HITL; they refuse uniformly at the registry gate.)
- [Aggregate-by-default](../../GLOSSARY.md#aggregate-by-default): privacy gateway, on outbound responses to list-style calls. Per-item detail requires per-call justification audit-logged at the gateway.
- [Hide secrets](../../GLOSSARY.md#hide-secrets): arbitrarily wide rule applied across the arbiter. The privacy gateway enforces it on every outbound response; longer-lived secrets (preimages, signatures, macaroons, descriptors, xpubs, PSBTs, raw values behind any pseudonym) live only in arbiter local state.
- [Default --private channels](../../GLOSSARY.md#default---private-channels): policy on the LND client access path. The arbiter passes `--private` (LND) or `open_channel` (ldk-node) by default when calling channel-open. AI-facing this hides the channel from `listchannels`; world-facing it suppresses the gossip entry.
- [Latency normalization](../../GLOSSARY.md#latency-normalization): privacy gateway, on every outbound response. Defeats per-response timing fingerprints (hop count, IBD state, wallet vs. non-wallet).
- [Action delay](../../GLOSSARY.md#action-delay) and [result delay](../../GLOSSARY.md#result-delay): the timing layer (§4.6). These operate on a different timescale from latency normalization (per-response, ms): action and result delay are per-action, hours-to-days. They subsume per-poll cadence concerns - the arbiter <-> bitcoind / LND link is inside the trust boundary, and result delay decorrelates any internal poll pattern from what the petitioner can observe. **Status: partial.** Test-mode 5-15s windows are wired (and 1-5s for the §4.7 rejection-delivery delay enforced in the same module); production needs §7's dynamic window calculation and is gated behind a NotImplementedError until that lands.

The privacy gateway is the primary AI-facing defense; world-facing mitigations (Tor, multi-peer broadcast, self-hosted esplora) sit underneath as defense-in-depth and are out of scope here.

---

## 7. Open design questions

- **Result-delivery status enum (payload shape).** The "result or not yet" envelope itself is resolved by §4.8: the wire response is binary status with an opaque payload, and the registry's `kind` field is audit-internal. The residual question is the shape of that payload - the set of terminal states the petitioner can observe (success / failure / "failed temporary (try again)" per the [Latency fingerprinting](../../GLOSSARY.md#latency-fingerprinting) entry / others?) and how each is signaled inside it; the payload must carry whatever discriminator the petitioner needs because the wire envelope does not. Tracked under sp-77lxs.1 (petitioner-visible payload shape). Source: [result delay](../../GLOSSARY.md#result-delay) status callout.
- **Dynamic window calculation.** The algorithm by which the arbiter observes "global activity for similar actions" and converts it into a window. Includes: what counts as "similar," where the observation comes from (gossip, mempool, block stats, esplora?), and how the parameters are bounded so the window itself does not become a fingerprint.
- **Band-edge randomization for aggregate counts.** How the arbiter randomizes anonymity-set bucket boundaries (per [Aggregate-by-default](../../GLOSSARY.md#aggregate-by-default) and [JIT liquidity](../../GLOSSARY.md#jit-liquidity)) so that band transitions cannot be triangulated back to specific underlying events: scheme for choosing per-arbiter offsets, how often they rotate, how they avoid becoming a fingerprint themselves.
- **LN-side recipient ingestion encoding.** The on-chain encodings landed in §4.7 (bech32, bech32m, base58check, no-mainnet). LN-side input is still open: BOLT-11 invoices are too long to retype reliably; BOLT-12 offers (~100 chars, bech32-checksummed) are borderline retypeable; Lightning Address (`user@host.tld`) resolves at add-time but introduces an outbound HTTPS dependency and a recipient-side observer; a non-keyboard input device such as a QR scanner attached to the arbiter would preserve no-clipboard-to-petitioner but adds hardware. Each option has its own trust and operational implications.
- **Standing approvals YAML schema.** The on-disk format of the [standing approvals](../../GLOSSARY.md#standing-approvals) config (§4.1, §6): how a rule names an op, how it names a destination (registry token, or a class like "any destination"), how amount bands are expressed (inclusive upper bound, exact match, range), how the free-text rationale field is structured for the operator's own use, and how the gateway resolves precedence on multiple matching rules. The schema must be readable enough that a non-technical operator can edit it without tooling - that constraint is load-bearing. Sample shapes in the implementation should drive the final decision.

---

## 8. What is NOT in this doc

This is the logical architecture: the components, the boundary, the data flow, and where mitigations fire. The following are deliberately out of scope and will get their own design docs in `design-docs/` (named per the `YYYY-MM-DD-HHMM-<slug>.md` convention) when they are decided:

- Bitcoin and Lightning primitives (UTXO, xpub, bolt11/12, HTLC, SCID, channel point, PSBT, signet, etc.) - background vocabulary; defined in the glossary.
- Specific API shapes of the spacer protocol (request/response schemas, error model, transport).
- Data model schemas for the token-to-real mapping, policy tables, HITL queue, audit log records.
- Wire formats (transport, framing, encoding).
- Code structure inside the arbiter or petitioner beyond the auditability constraints in §2.1.
- World-facing privacy mitigations (Tor, multi-peer broadcast, self-hosted esplora, channel announcement choices for world-facing reasons). Covered in `~/spacer/archive/2026-05-02-1700-node-privacy-from-the-world.md`.
- Per-API filter rules (which RPC fields get banded, tokenized, dropped). Covered in `2026-05-02-1601-privacy-and-timing-leaks.md` (LND) and `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` (bitcoind).

---

## 9. Current physical layout

Every parent folder under `~/spacer/` lives under one of three top-level homes: `arbiter/`, `petitioner/`, or `test-harness/`. Project-level artifacts (`design-docs/`, `archive/`, `GLOSSARY.md`) sit at the root because they are not specific to any one home.

```
~/spacer/
  arbiter/                # everything that must stay out of the AI's reach
    bin/                  # arbiter-side clients: lncli, bitcoind, bitcoin-cli, bitcoin-tx, bitcoin-wallet
    bitcoin/              # bitcoind datadir (signet only)
    lnd/                  # LND credentials (admin.macaroon, tls.cert)
  petitioner/             # client-side process; not yet implemented
  test-harness/           # testbed scaffolding: wrappers, smoke tests, session ledger, tooling
    bin/                  # test-harness tooling: uv, uvx
    cache/                # uv install cache
    downloads/            # source tarballs and checksums
    ldk-data/             # ldk-node data directory (currently unused; ldk-node install blocked)
    python/               # uv-managed CPython interpreters
    scripts/              # wrappers (lncliA, btccli) and smoke tests (ldk_smoke.py)
    state/                # session ledger, env files, RPC notes
    venv/                 # Python venv (uv-managed)
  archive/                # long-term archive of historical project files
  design-docs/            # design docs, named YYYY-MM-DD-HHMM-<slug>.md
  GLOSSARY.md             # project vocabulary
```

The directory tree is itself part of the vocabulary: "under `arbiter/`", "in `test-harness/state/`" are precise references to specific roles.

The following directories also exist at the root but fall outside the arbiter/petitioner/test-harness split: `go/` and `go-cache/` (Go module/build caches populated by other tooling; not part of spacer's own dependency surface) and `first-game/` (an unrelated C# project that predates spacer in this workspace).

This is a snapshot. Paths cited in §2-§5 (`spacer/arbiter/src/`, `test-harness/scripts/`) reflect the layout at the time of writing and may move; the logical architecture in this doc is the load-bearing description.

---

## 10. Exit criteria for the implementation closed loop

This section defines the gate for declaring the implementation done. It is process-side rather than a logical-architecture concern; it lives here for convenience because the gate references components defined elsewhere in this doc.

**Definition of done.** Implementation is complete when, for every command and variant in the [petcli](#51-protocol-shim) command tree, an end-to-end validation run executes the command, traverses the privacy gateway, the timing layer, the relevant arbiter components, and the test-harness's bitcoind / LND infrastructure, and returns a result via the [result registry](#48-result-registry) that matches the validation's expected outcome - and the raw artifacts of that run are preserved verbatim under `exit-loop/`.

**Coverage scope.** Every leaf of the `petcli` command tree (whatever shape the implementer chooses; see §5.1) **and** every argument variant that exercises a distinct code path inside the arbiter. Both happy-path and rejection-path variants. Both Bitcoin and Lightning send paths where the underlying command applies to either.

Current coverage status: read-only `query/balance`, `query/channels`, `result/poll`, and local-only `estimate/window` are exercised end-to-end. The `scale.present()` paths covered are the T0 no-cloak branch (taken by `query/balance/default`, `query/balance/empty-wallet`, `query/channels/default`, `query/channels/no-channels`) and the four cloaked branches: T1 init (`cloaked-tier-1`), T2 init (`cloaked-tier-2` - identical wire response to T1, which is the cloak's whole point), transition-pending (future `due_at`, presented value deliberately exceeds the 0-100k window per the GLOSSARY's `drift > range` property), and transition-applied (past `due_at`, the shift auto-applies and audit-logs `scale_tier_shift_applied`). State-changing `submit/send-bitcoin` and `submit/send-lightning` are exercised only on the registry-miss refusal path (`decision_refuse_registry`); happy-path sends and the per-cause registry rejection subcases (expired, used, bad checksum, anomalous) are absent because the gateway's `_dispatch` for write ops currently returns `{"status": "not_implemented"}` - the timing-layer executor that would consume the queue in `arbiter/src/timing.py` (`due_actions()` / `due_results()`) and run the call against `bitcoin.py` / `lnd.py` has not yet been wired into the gateway's write-op path. Those variants land alongside that wiring.

**Test-mode timing.** Production [action delay](../../GLOSSARY.md#action-delay) and [result delay](../../GLOSSARY.md#result-delay) windows have ~12-hour floors, the rejection-delivery delay (§4.7) is 1 hour ± 30 min, and the [scale cloaking](../../GLOSSARY.md#scale-cloaking) tier-transition delay (§4.1) is multi-day. Validating at production timing would take days per pass and is impractical at the volume needed for full coverage and iteration. Each timing layer therefore exposes its own test-mode opt-in that compresses the relevant window:

- Action delay: `SPACER_TIMING_MODE=test` -> randomized **5-15 seconds** (`arbiter/src/timing.py`).
- Result delay: `SPACER_TIMING_MODE=test` -> randomized **5-15 seconds** (same module).
- Rejection-delivery delay: `SPACER_TIMING_MODE=test` -> randomized **1-5 seconds**, proportionally compressed against the production 1h ± 30 min band.
- Scale-cloak tier transition: `SPACER_SCALE_MODE=test` -> randomized 5-15s transition delay and deterministic per-tier scales `0.1^tier` (`arbiter/src/scale.py`).
- Petitioner-side estimate window: `PETCLI_TEST_TIMING=1` -> 30s upper bound (action 15s + result 15s), replacing the default 24h placeholder (`petitioner/src/estimate.py`).

The opt-ins are orthogonal because the production code path for each subsystem is currently a `NotImplementedError`: nothing runs in production until the dynamic-window calculation (action / result / rejection) and the multi-day randomized scale-transition work land. That is the **safe failure mode** for §10 - a misconfigured environment that does not opt into test mode cannot accidentally execute with compressed windows, because it cannot execute at all. Production timing is therefore not just "restored before any environment that observes real bitcoin or lightning traffic" - until the production-mode work lands, it is the default and it refuses to run.

**Parallel execution.** Validations are independent at the state level (different handles, different recipient tokens, separate arbiter instances spun up per-variant by the runner) and parallelize cleanly in principle. The fan-out target is the workspace's existing parallel-dispatch infrastructure - the bead queue under `.beads/` driven via the Gas City rigs under `.gc/` - the same way implementation tasks are dispatched. The current runner (`test-harness/scripts/exit_loop_runner.py`) executes the manifest sequentially in a single process: each variant spins a fresh in-thread arbiter on an ephemeral port, runs `petcli` as a subprocess, tears the arbiter down, and moves on. Sequential is acceptable at the current variant count (17 variants, ~12s wall-clock per full pass) and avoids the coordination cost of a bead-queue fan-out before the volume justifies it; the parallel design remains the target if iteration cost rises.

**Iteration loop.** Failed validations feed back into the implementation cycle: the failure's raw output is captured under `exit-loop/`, the cause is fixed, and the validation re-runs. The loop terminates only when every validation passes. There is no manual sign-off; the gate is binary on the artifact set.

**Exit gate.** The implementation closed loop closes when:

1. Every `petcli` command and variant has at least one passing end-to-end validation run on file under `exit-loop/`.
2. The raw output of each run is preserved verbatim - not summarized - so a non-AI human reviewer (per §2.1's auditability discipline) can confirm the run actually executed.
3. No validation is in failed state.

**Artifact layout.** Validation artifacts live under `exit-loop/`. The expected layout is:

```
exit-loop/
  README.md                 # pointer back to this section, current coverage notes
  petcli/
    <command>/              # one directory per petcli command (leaf or intermediate)
      <variant-name>/       # one directory per validated argument variant
        stdout.log          # raw petcli stdout for this run
        stderr.log          # raw petcli stderr for this run
        arbiter-events.log  # arbiter-side audit / state transitions for this run
        infra-events.log    # bitcoind / LND test-harness events for this run
        result.json         # final result returned via the result-registry poll
```

The tree is scaffolded empty initially. A populated `<variant-name>/` directory signals that variant has been validated; an empty one signals not-yet-validated. The runner rebuilds `petcli/` from its manifest on every invocation, so a variant that has been removed from the manifest stops appearing on disk and a variant that has been added shows up populated on the next pass; `README.md` is left in place (documentation, not a run artifact).

`infra-events.log` is a per-variant marker file in the current pass: the read-only variants dispatch through `arbiter/src/lnd.py` against a fake `lncli` shell script the runner installs at module-import time (deterministic canned replies selected via `$LNCLI_SCENARIO`), and the write-op variants refuse at the registry gate without reaching `lnd.py` or `bitcoin.py`. No variant in the current manifest exercises live bitcoind / LND traffic. The fake-lncli substrate is sufficient for confirming gateway -> dispatch -> argv-construction -> JSON-parse round-trip and for exercising every `scale.present()` branch deterministically; live-infrastructure coverage lands alongside the test-harness's bitcoind / LND fixtures and the timing-layer executor.

---

## 11. Implementation learnings

- 2026-05-24: §4.7 token format ratified - 5 random Crockford-base32 + 1 Damm32 check character (6 total, 25-bit namespace). Crockford alphabet omits `I`, `L`, `O`, `U`; input normalization maps `I`/`L` → `1` and `O` → `0`. Damm32 quasigroup uses GF(2^5) with `x^5 + x^2 + 1`, detecting every single-character substitution and every adjacent transposition. Closed the §7 "Recipient address registry token format" open question.
- 2026-05-24: §4.7 ingestion encodings ratified for on-chain - bech32 (P2WPKH/P2WSH), bech32m (P2TR), base58check (P2PKH/P2SH). Detection runs in fixed order (bech32m, bech32, base58check); polymods are non-overlapping. LN-side encodings (BOLT-11/12, Lightning Address) remain open in §7; narrowed the original open question to that residual.
- 2026-05-24: §4.7 no-mainnet hard rule landed - testnet/signet HRPs (`tb`, `bcrt`) and base58 versions (`0x6F`, `0xC4`) only; mainnet refused at add time, same refusal path as a malformed address. This was not in the previous doc text.
- 2026-05-24: §4.7 refusal-outcome enumeration reconciled to five (`bad_checksum`, `unknown`, `expired`, `used`, `anomalous`) - the previous Refusal-behavior paragraph listed four while the destination-gate paragraph already listed five; `anomalous` is a defense-in-depth re-validation of the stored real address.
- 2026-05-24: §4.7 One-time use clarified - the consume step does **not** re-check `expires_at`. Rationale: the Action delay window can span hours; once a lookup authorized the action, post-action record-keeping must record use even if the entry crossed its expiry between lookup and consume.
- 2026-05-24: Storage substrate paragraph (YAML migration) intentionally left untouched; the migration (bl-2lbqu4) has not landed yet. Once it does, this learnings section gets an entry for the mtime-reload behavior and YAML schema.
- 2026-05-24: §4.1 "not yet implemented" caveat retired - the privacy gateway skeleton at `arbiter/src/gateway.py` is in place: HTTP entry, JSON parsing, audit logging, latency normalization, registry-gated write-path resolution, HITL park stub for unrecognized ops, result-poll fast path (§4.8), and read-op dispatch (`query_balance` / `query_channels`) through scale cloaking. The caveat became stale once the skeleton landed; the new "Implementation status" paragraph enumerates wired vs structurally-present mechanisms.
- 2026-05-24: §4.1 scale cloaking ratified as **in place of** banding for balance / channel-capacity reads, not layered on top. `_dispatch` routes `query_balance` and `query_channels` through `scale.present()` and deliberately drops `_band_sats`; the per-tier scale already compresses 10x+, so a fixed-resolution band on top would muddy the math without adding privacy. The §4.1 mechanisms list previously read "on top of or in place of banding"; the implementation closed that ambiguity.
- 2026-05-24: §4.1 latency normalization added to the concrete-mechanisms list - it was previously only enumerated in §6 and referenced from §4.7, absent from §4.1's own list. The skeleton stamps `_latency_deadline` in `_Handler.setup` and `_wait_until(deadline)` runs on every response path including the protocol-error `send_error` override, so a malformed HTTP frame is petitioner-visibly indistinguishable from a refused JSON request in both body shape and response time.
- 2026-05-24: §4.5 audit-log event vocabulary observed at gateway entry, recorded here for future cross-referencing: `gateway_start` / `gateway_stop` (boot lifecycle), `request_received` (every parsed inbound), `decision_allow` (every passed path including each `poll` routing), `decision_refuse` with `reason: parse_failure` or `protocol_error`, `decision_refuse_registry` (registry-gate miss on a known write op), `decision_defer_hitl` (unknown op), `decision_poll_bad_input` (poll fast-path with missing or non-string handle).
- 2026-05-24: §3 / §4.1 / §6 standing-approvals reconciliation intentionally left untouched; the implementation (bl-gfxsxx, itself blocked on bl-hu56z9) has not landed. Mechanism-list reference, §3 ASCII data-flow arrow, and §6 mitigation-map entry remain accurate forward-looking design. Once `arbiter/src/standing_approvals.py` lands and `gateway.py` gains the check between `_pseudonymize_inbound` and write-dispatch, a follow-up entry here will note the wire-up. (Mirrors the storage-substrate-deferred pattern above.)
- 2026-05-24: reconciled §10 against `test-harness/scripts/exit_loop_runner.py`, `exit-loop/README.md`, and the `exit-loop/petcli/` artifact tree. Expanded the **Test-mode timing** paragraph to enumerate the three orthogonal opt-ins (`SPACER_TIMING_MODE`, `SPACER_SCALE_MODE`, `PETCLI_TEST_TIMING`) and the deliberate `NotImplementedError` safety property (production windows refuse to run rather than silently use compressed ones). Walked the **Parallel execution** paragraph back from "validations run in parallel" to "sequential by design at current variant volume; bead-queue fan-out remains the target if iteration cost rises." Added a **current coverage status** paragraph to **Coverage scope** that names which variants are wired today (every read leaf, plus the T0 no-cloak branch and four cloaked `scale.present()` branches) and what is blocked behind the timing-layer executor wire-up in `arbiter/src/gateway.py:_dispatch` (happy-path sends + per-cause registry rejection subcases). Rewrote the **Artifact layout** paragraph's `infra-events.log` description to match the fake-lncli reality (deterministic shell-script stub, no live bitcoind / LND traffic for any variant in the current manifest).
- 2026-05-24: reconciled §5 (petitioner) against `petitioner/src/petcli.py`, `protocol.py`, `estimate.py`, and `petcli_smoke.py`. §5.1 gained a "Transport-error envelope" paragraph documenting the `_petcli_transport_error` / `_petcli_*` underscore convention that distinguishes petitioner-side annotations from arbiter-emitted fields; the convention was already load-bearing in the shim (`protocol.submit` returns `{"_petcli_transport_error": ...}` on URLError / non-JSON; `petcli` stamps `_petcli_estimate_window_s` on every state-changing submit response) but was nowhere on paper. §5.2 gained a "Current implementation" paragraph naming the placeholder bound concretely (24h default, 30s under `PETCLI_TEST_TIMING=1`) and the sp-77lxs.3 gating chain - sp-77lxs.9 explicitly accepted the placeholder, sp-77lxs.3 (dynamic-window calculation) is the dep that would let either side stop hardcoding.
- 2026-05-24: command tree (`submit/{send-bitcoin,send-lightning}`, `query/{balance,channels}`, `result/poll`, `estimate/window`) verified consistent with the arbiter's `_KNOWN_READ_OPS = {query_balance, query_channels}`, `_KNOWN_WRITE_OPS = {send_bitcoin, send_lightning}`, plus the `op == "poll"` fast-path (gateway.py:176, 263, 271). The wire op for `result poll` is `"poll"` (single-token gateway routing key), not `"result_poll"` - the petcli command path is descriptive but the wire stays terse. Doc kept §5.1's "command shape deliberately not enumerated" guidance: the alignment is now stable across both sides but enumeration in the architecture doc still buys nothing over the live `--help` walk.
- 2026-05-24: confirmed the petitioner-side field rename `--to-token` CLI flag -> `recipient_token` wire field happens at `petcli._do_submit_send_{bitcoin,lightning}`. The arbiter looks up `request.get("recipient_token")` (gateway.py:311) and §4.7 names the wire field `recipient_token`. The CLI flag stays `--to-token` for operator brevity; the rename is an explicit one-line transform at the wire boundary with an inline comment. Fixed a stale assertion in `petcli_smoke.py` that still expected `to_token` on the wire (left over from before the rename); the smoke test was failing on that assertion. No doc change for this - §5.1 does not enumerate flags by design, and §4.7 already names the wire field.
- 2026-05-24: §4.8 reconciled against `arbiter/src/results.py`. The 10-minute poll floor is keyed by handle alone, not by petitioner identity - the handle is the petitioner-binding identifier and the arbiter has no notion of petitioner identity at this layer. See [§4.8 10-minute poll floor](#48-result-registry).
- 2026-05-24: §4.8 deposit path goes via the [timing layer](#46-timing-layer)'s `pending_results` table and a drainer, not directly from the gateway; the doc's "the privacy gateway writes the result into the registry" elided the staging step. See [§4.8 opening](#48-result-registry).
- 2026-05-24: §4.8 wire response is binary; the `kind` field (`result` / `rejection`) is audit-internal so the petitioner cannot distinguish a rejection from a regular result on the wire. This composes with the §4.7 rejection-delivery delay and is load-bearing for it. See [§4.8 opening](#48-result-registry).
- 2026-05-24: §4.8 floor-anchor invariants made explicit - anchor advances on the first non-throttled poll *before* the result table is consulted (so a crash cannot bypass the floor), and throttled polls do not advance the anchor (so polling spam cannot push the next allowed poll further out). A poll on a never-existed handle still anchors the floor. See [§4.8 Idempotent retrieval](#48-result-registry).
- 2026-05-24: §7 "Result-delivery status enum" partially resolved - registry envelope is settled (binary status + opaque payload + audit-internal kind); residual is the payload shape, tracked under sp-77lxs.1. See [§7](#7-open-design-questions).
- 2026-05-24: reconciled §4.6 (and §6's action/result timing entry) against `arbiter/src/timing.py`. Added a partial-status block to §4.6 noting test-mode 5-15s windows wired end-to-end, production blocked behind §7's dynamic window calculation with NotImplementedError gating on every enqueue path, conservative `SPACER_TIMING_MODE=test`-only mode selection (typo / miscased / unset all land in production), and that the same module also enforces the §4.7 rejection-delivery delay (test-mode 1-5s; production 1h ± 30 min) over a shared `pending_actions` / `pending_results` defer-then-pop substrate. §7's "Dynamic window calculation" open Q is the exact gating issue for production and needs no edit; the action executor (drains due actions) and result-registry consumer (drains due results) are not yet implemented.
- 2026-05-24: §4.5 expanded to document the JSONL / fsync-per-write / atomic-within-PIPE_BUF / in-process-lock properties that `arbiter/src/audit.py` already carries; on-disk path moved from `arbiter/data/audit.log` to `arbiter/state/audit.log` per [arb-auditability §3](06--2026-05-24-0623-arb-auditability.md), and the snapshot primitive linked as the §4.5 companion (the §7 acceptance item from that doc). Note: `arbiter/src/state.py` still defaults to `arbiter/data/state.db`, and `.gitignore` covers `arbiter/data/` but not `arbiter/state/`; both follow-ups belong to the broader arb-auditability tree migration.
