# Spacer Architecture Overview

**Date:** 2026-05-05
**Context:** Logical architecture of the spacer system: the components, the trust boundary between them, the end-to-end data flow of a state-changing call.
**Related:**
- `../GLOSSARY.md` - vocabulary; this doc references glossary terms by link rather than redefining them.
- `2026-05-02-1601-privacy-and-timing-leaks.md` - per-API leak surface for LND.
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` - per-API leak surface for bitcoind.
- `2026-05-02-1700-node-privacy-from-the-world.md` - world-facing privacy (separate threat model).

---

## 1. Purpose and scope

[Spacer](../GLOSSARY.md#spacer) lets an AI client drive a Bitcoin and Lightning node without learning more about the operator's wallet, balances, or identifiers than the task requires. The design splits into two processes joined by a protocol; the protocol is the trust boundary.

Out of scope for this doc: [world-facing privacy](../GLOSSARY.md#world-facing-privacy) (what the public networks, peers, explorers, and hosting providers can observe), wire formats, API shapes, data model schemas, code structure inside either component, and the bitcoin/LN primitives the design relies on. Each of those is either already in the glossary as background vocabulary or will get its own per-decision design doc.

---

## 2. The two components and the trust boundary

The system is two processes:

- The [petitioner](../GLOSSARY.md#petitioner): client-side, runs in the AI's environment, holds no secrets.
- The [arbiter](../GLOSSARY.md#arbiter): server-side, the AI cannot reach it; it bundles the [privacy gateway](../GLOSSARY.md#privacy-gateway), the bitcoin and LND client access, the local state, the [audit log](../GLOSSARY.md#audit-log), and the timing layer that enforces [action delay](../GLOSSARY.md#action-delay) and [result delay](../GLOSSARY.md#result-delay).

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
  +--> [policy + HITL queue]              (allowlist check; HITL if outside fast path)
  +--> [token-to-real mapping]            (resolve pseudonyms to concrete identifiers)
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
  |  asynchronous delivery (poll or callback; see open questions)
  v
[petitioner]
  |
  v
AI                                        (sees only banded/tokenized outcome)
```

The petitioner gets an immediate synchronous acknowledgment ("received: opaque-handle") at submission time, but every AI-observable consequence of the call - on-chain visibility and result knowledge - is deferred by the timing layer.

Read-only queries take the same petitioner -> privacy gateway -> arbiter internals path but skip the timing layer; their response shape is filtered by the same outbound mechanisms ([banding](../GLOSSARY.md#banding-numeric-value-banding), [pseudonymize](../GLOSSARY.md#pseudonymize-identifier-pseudonymization), [aggregate-by-default](../GLOSSARY.md#aggregate-by-default), [hide secrets](../GLOSSARY.md#hide-secrets)) and stamped with [latency normalization](../GLOSSARY.md#latency-normalization).

---

## 4. Components on the arbiter

### 4.1 Privacy gateway

The [privacy gateway](../GLOSSARY.md#privacy-gateway) is the **only** network-reachable component on the arbiter. Every petitioner request hits it first. Because it is the entry point, it must be:

- **Limited**: small surface, narrow responsibilities, few dependencies.
- **Airtight**: no bypass paths to bitcoind, LND, or arbiter state; no information leakage through error messages, timing, or response shape; no untrusted deserialization beyond what the protocol strictly requires.

Anything that does not need to be exposed to the network does not live in the privacy gateway. Long-term storage (preimages, descriptors, PSBTs, the audit log itself, the token-to-real mapping) lives elsewhere on the arbiter.

Concrete mechanisms the privacy gateway applies on each request: [pseudonymize](../GLOSSARY.md#pseudonymize-identifier-pseudonymization) identifiers, [band](../GLOSSARY.md#banding-numeric-value-banding) numeric values, gate state-changing calls against the [outbound allowlist](../GLOSSARY.md#outbound-allowlist), defer anomalies to a human via [HITL](../GLOSSARY.md#human-in-the-loop-approval), append every request and decision to the [audit log](../GLOSSARY.md#audit-log).

Caveat: not yet implemented; the design docs in `design-docs/` are the current artifact.

### 4.2 Bitcoin client access

Wrapped access to the [local bitcoind](../GLOSSARY.md#local-bitcoind). The arbiter shells out via `bitcoin-cli` against the locally self-hosted bitcoind under `spacer/arbiter/bitcoin/`. Coin selection and signing stay inside the arbiter; PSBTs constructed during signing never leave (see [hide secrets](../GLOSSARY.md#hide-secrets)). The [btccli](../GLOSSARY.md#btccli) wrapper currently lives in `test-harness/scripts/`; the production arbiter will use its own wrapper or call `bitcoin-cli` directly.

### 4.3 LND client access

Wrapped access to LND over `lncli` plus gRPC/REST. The current testbed wrapper [lncliA](../GLOSSARY.md#lnclia) is testbed-scoped (Voltage-hosted Node A); the arbiter's production access will follow the same pattern but against the deployment's LND instance.

### 4.4 Local state

Holds:

- The token-to-real mapping that backs [pseudonymize](../GLOSSARY.md#pseudonymize-identifier-pseudonymization). For outbound recipient destinations specifically, this is the [recipient address registry](#47-recipient-address-registry) described in §4.7.
- The policy tables that back the [outbound allowlist](../GLOSSARY.md#outbound-allowlist).
- The pending [HITL approval](../GLOSSARY.md#human-in-the-loop-approval) queue.
- Any pending action+result deferrals being tracked by the timing layer.

All of it stays on the arbiter. The petitioner cannot reach any of it.

### 4.5 Audit log

The immutable, append-only [audit log](../GLOSSARY.md#audit-log) records every AI request and every arbiter decision (allow, deny, redact, band, defer-to-human). The petitioner cannot reach it, so the AI cannot tamper with the record even if it fully owns its environment.

### 4.6 Timing layer

The arbiter component that enforces both anonymity-set delays:

- [Action delay](../GLOSSARY.md#action-delay): wait between the petitioner submitting a state-changing action and the arbiter actually executing it against the network. ~12h floor, randomized within a window that the arbiter computes dynamically from observed global activity for similar actions, targeting a configurable anonymity set.
- [Result delay](../GLOSSARY.md#result-delay): wait between the arbiter completing the action and the petitioner being able to learn the result. Same window construction, same ~12h floor, computed against observed network activity for similar result-shapes.

The dynamic window calculation observes global activity for actions or results of the same shape and stretches or compresses the window to keep the anonymity set above a target. Constant or naive parameters defeat the mechanism (the distribution itself becomes a fingerprint), so the calculation is part of the security surface, not just a tuning knob.

### 4.7 Recipient address registry

Manages the pseudonymized handles the petitioner uses to refer to Bitcoin and Lightning destinations the operator has approved as send targets. Concrete implementation of [pseudonymize](../GLOSSARY.md#pseudonymize-identifier-pseudonymization) for outbound destinations, combined with one-time-use enforcement and an explicit human-driven creation flow.

**Entry creation.** Real recipient addresses (Bitcoin addresses, BOLT-11 invoices, BOLT-12 offers, or LN node pubkeys depending on the send type) enter the registry **only** via direct human interaction with the arbiter: a keyboard and monitor physically connected to the arbiter host. The petitioner has no way to add an entry; the AI never sees the real address.

The operator runs a registry-add command at the console and **types** the real address. There is no clipboard between this console and any other system, so the address must arrive in a form a human can hand-transcribe in one sitting. The arbiter validates the address's built-in checksum before creating an entry: bech32 / bech32m for Bitcoin addresses, the BOLT-11 / BOLT-12 invoice checksum for LN. A typo that breaks the checksum is rejected at parse time, so the operator gets immediate feedback rather than discovering the mistake at send time hours later.

Some destination types are too long to retype reliably - BOLT-11 invoices in particular run hundreds of characters. Supporting those requires either a shorter recipient-supplied encoding ([Lightning Address](https://lightningaddress.com) like `user@host.tld`, BOLT-12 offers, on-chain bech32 addresses) or an additional out-of-band input device on the arbiter (e.g., a QR scanner) that preserves the no-clipboard-to-petitioner property. The set of acceptable input encodings is open (§7).

On a successful add the arbiter prints the entry's local-only numeric ID and the public-facing token back to the console.

**Entry shape (logical).**

- `id`: monotonically increasing local sequence number (1, 2, 3, ...), assigned at creation. **Local-only.** Never crosses the privacy gateway, never appears in petitioner-visible responses. It exists so the operator at the console can refer to "address number 42" in their own notes - giving the human a stable, ordered, easy-to-speak handle without exposing creation order to the petitioner.
- `token`: short randomly-generated alphanumeric string with a trailing checksum character. This is the **only** handle the petitioner sees. The token is hand-transcribed on the petitioner side too (operator reads it off the console, hands it to the AI via voice / paper / out-of-band channel), so the checksum catches single-character typos and most adjacent-pair transpositions before they reach the registry. The arbiter validates the checksum at the privacy gateway and returns the same uniform "destination unavailable" response on a checksum failure as on any other refusal (§Refusal behavior), so checksum failures do not leak whether the rest of the token matched a real entry. Length, alphabet, and checksum algorithm are chosen so the namespace is large enough to keep collisions improbable while staying short enough for a human to retype; exact values are open (§7).
- `real`: the actual destination (Bitcoin address or LN invoice / offer / pubkey). Held only on the arbiter; subject to [hide secrets](../GLOSSARY.md#hide-secrets).
- `created_at` / `expires_at`: timestamp pair. Default expiry is `created_at + 7 days` if the entry has not been used by then; operator can override at creation.
- `used`: boolean, default `false`. Flipped to `true` on the first successful send against this entry and never flipped back.
- `consumed_by`: when `used == true`, the txid (Bitcoin) or payment hash (Lightning) that consumed the entry, for audit traceability.

**Token generation.** The random portion of the token is drawn uniformly at random from a fixed character set with no visually ambiguous characters (no `0/O`, no `1/I/l`); the checksum character is then computed deterministically from the random portion. On creation the arbiter checks for token-namespace collisions on the random portion and re-rolls until it finds a free token. The sequential numeric `id` is indexed independently of `token` and cannot collide.

**One-time use.** Every send-to-token call is gated on `used == false` and `expires_at > now`. On a successful send the arbiter sets `used = true` and records `consumed_by`. Subsequent sends to the same token are refused. This prevents on-chain / on-LN address reuse independent of operator discipline: the petitioner cannot reuse a destination even if it remembers the token.

**Refusal behavior.** When the petitioner submits a send to a token that does not exist, has expired, or has already been used, the arbiter returns a single generic "destination unavailable" response that does not differentiate the cases. Differentiating them would let the petitioner probe registry state by submission.

**Namespace pressure and cleanup.** Used and expired entries are retained by default for audit and operator tracking; the registry is not aggressive about garbage-collecting them. The arbiter monitors namespace utilization (live entry count / token-namespace size) and warns the operator when it crosses **1%**. At that point the operator manually removes old entries to keep collision probability and re-roll cost low. With a sensibly-sized token length this threshold is rarely reached in practice; cleanup is an operator decision, not a hot-path concern.

**Caveats.**

- The numeric `id` is local-only by intent, but anything the operator writes down or speaks aloud while reading it from the console is outside the trust boundary. Operator-side discipline is part of the security surface.
- The 7-day default expiry trades usability (longer = more time to actually send) against exposure window (shorter = real-address mapping discarded sooner). Tunable at creation; not yet measured against real workflows.

---

## 5. Components on the petitioner

### 5.1 Protocol shim

The only first-class function of the [petitioner](../GLOSSARY.md#petitioner) is translating AI requests into spacer-protocol messages and presenting the arbiter's responses back. It holds no secrets, no policy, no state that the AI cannot already reach.

### 5.2 Estimate display

Because [result delay](../GLOSSARY.md#result-delay) makes results asynchronous, the petitioner needs an estimate of total elapsed time (action delay + result delay) so the AI can reason about the decision tree:

- Still within window -> wait.
- Past the upper bound and no result -> assume lost; decide whether to re-initiate.
- Result arrived -> success / failure.

The petitioner computes this estimate locally. It estimates the anonymity set size from its own view of similar global activity and derives an upper bound on the window from that. No estimate information comes from the arbiter, and the arbiter offers no guarantee on the bound. The exact local-estimation method is open (see §7).

---

## 6. Mitigation map

Where each glossary mitigation fires in the data flow.

- [Pseudonymize](../GLOSSARY.md#pseudonymize-identifier-pseudonymization): privacy gateway, on outbound responses. The token-to-real mapping lives in arbiter local state. Outbound recipient destinations are handled by the [recipient address registry](#47-recipient-address-registry) (§4.7), which adds one-time-use enforcement and a human-driven creation flow on top of the pseudonymize mapping.
- [Banding](../GLOSSARY.md#banding-numeric-value-banding): privacy gateway, on outbound responses to balance / amount / fee fields.
- [Outbound allowlist](../GLOSSARY.md#outbound-allowlist): privacy gateway, on every state-changing or network-touching call before it reaches bitcoind/LND. Backed by policy tables in local state.
- [Human-in-the-loop approval](../GLOSSARY.md#human-in-the-loop-approval): triggered by the privacy gateway when an inbound call falls outside the allowlist fast path; the call parks in the HITL queue (local state) until an out-of-band human assent arrives. The out-of-band channel is intentionally not the petitioner's RPC channel; whether it shares plumbing with result delivery is open (§7).
- [Aggregate-by-default](../GLOSSARY.md#aggregate-by-default): privacy gateway, on outbound responses to list-style calls. Per-item detail requires per-call justification audit-logged at the gateway.
- [Hide secrets](../GLOSSARY.md#hide-secrets): arbitrarily wide rule applied across the arbiter. The privacy gateway enforces it on every outbound response; longer-lived secrets (preimages, signatures, macaroons, descriptors, xpubs, PSBTs, raw values behind any pseudonym) live only in arbiter local state.
- [Default --private channels](../GLOSSARY.md#default---private-channels): policy on the LND client access path. The arbiter passes `--private` (LND) or `open_channel` (ldk-node) by default when calling channel-open. AI-facing this hides the channel from `listchannels`; world-facing it suppresses the gossip entry.
- [Latency normalization](../GLOSSARY.md#latency-normalization): privacy gateway, on every outbound response. Defeats per-response timing fingerprints (hop count, IBD state, wallet vs. non-wallet).
- [Action delay](../GLOSSARY.md#action-delay) and [result delay](../GLOSSARY.md#result-delay): the timing layer (§4.6). These operate on a different timescale from latency normalization (per-response, ms): action and result delay are per-action, hours-to-days. They subsume per-poll cadence concerns - the arbiter <-> bitcoind / LND link is inside the trust boundary, and result delay decorrelates any internal poll pattern from what the petitioner can observe.

The privacy gateway is the primary AI-facing defense; world-facing mitigations (Tor, multi-peer broadcast, self-hosted esplora) sit underneath as defense-in-depth and are out of scope here.

---

## 7. Open design questions

- **Result delivery mechanism.** Poll, callback, mailbox, or some combination. Source: [result delay](../GLOSSARY.md#result-delay) ("the petitioner polls or receives a callback").
- **Result-delivery status enum.** The set of terminal states the petitioner can observe (success / failure / lost-or-expired / others?) and how each is signaled. Source: [result delay](../GLOSSARY.md#result-delay) status callout.
- **HITL channel sharing.** Whether [HITL approval](../GLOSSARY.md#human-in-the-loop-approval) requests and assents travel on the same out-of-band plumbing as result delivery, or a dedicated separate one. Both are out-of-band relative to the petitioner's RPC channel, but they may or may not share transport.
- **Policy table format.** The schema for the [outbound allowlist](../GLOSSARY.md#outbound-allowlist)'s policy tables: how destinations and amounts are expressed, how staleness is handled, how new entries are added without leaking the change to the AI. Source: outbound allowlist status callout.
- **Dynamic window calculation.** The algorithm by which the arbiter observes "global activity for similar actions" and converts it into a window. Includes: what counts as "similar," where the observation comes from (gossip, mempool, block stats, esplora?), and how the parameters are bounded so the window itself does not become a fingerprint.
- **Band-edge randomization for aggregate counts.** How the arbiter randomizes anonymity-set bucket boundaries (per [Aggregate-by-default](../GLOSSARY.md#aggregate-by-default) and [JIT liquidity](../GLOSSARY.md#jit-liquidity)) so that band transitions cannot be triangulated back to specific underlying events: scheme for choosing per-arbiter offsets, how often they rotate, how they avoid becoming a fingerprint themselves.
- **Recipient address registry token format.** Token length, character set, and checksum algorithm for the [recipient address registry](#47-recipient-address-registry) (§4.7): the tradeoff between human-retypeable shortness and namespace size large enough that the 1% cleanup warning is rarely hit; whether the checksum is one character or two; choice of alphabet (Crockford-base32, no-ambiguous-character base32, etc.) and checksum scheme (Damm, mod-N, single-character bech32-style).
- **Recipient address ingestion encoding.** The set of input formats the registry-add console accepts for real destination addresses (§4.7). Bitcoin bech32 / bech32m addresses are short enough to retype with care and self-validate via the built-in checksum; BOLT-11 invoices are not. Options for LN: accept Lightning Address (`user@host.tld`) and resolve at add-time (introduces an outbound HTTPS dependency and a recipient-side observer); accept BOLT-12 offers (~100 chars, bech32-checksummed, borderline retypeable); add a non-keyboard input device such as a QR scanner attached to the arbiter that preserves no-clipboard-to-petitioner. Each option has its own trust and operational implications.
- **Recipient address registry refusal severity.** Whether the audit log differentiates "token does not exist" / "token expired" / "token already used" / "token checksum failed" even though the petitioner-visible response is uniformly "destination unavailable" (§4.7). Differentiating in audit only would help the operator triage suspicious activity without giving the petitioner a probe channel.

---

## 8. What is NOT in this doc

This is the logical architecture: the components, the boundary, the data flow, and where mitigations fire. The following are deliberately out of scope and will get their own design docs in `design-docs/` (named per the `YYYY-MM-DD-HHMM-<slug>.md` convention) when they are decided:

- Bitcoin and Lightning primitives (UTXO, xpub, bolt11/12, HTLC, SCID, channel point, PSBT, signet, etc.) - background vocabulary; defined in the glossary.
- Specific API shapes of the spacer protocol (request/response schemas, error model, transport).
- Data model schemas for the token-to-real mapping, policy tables, HITL queue, audit log records.
- Wire formats (transport, framing, encoding).
- Code structure inside the arbiter or petitioner beyond the auditability constraints in §2.1.
- World-facing privacy mitigations (Tor, multi-peer broadcast, self-hosted esplora, channel announcement choices for world-facing reasons). Covered in `2026-05-02-1700-node-privacy-from-the-world.md`.
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
