# Spacer Architecture Overview

**Date:** 2026-05-05 (reconciled 2026-07-07)
**Context:** Logical architecture of the spacer system - the components, the trust boundary, and the end-to-end data flow of a state-changing call. Mitigation mechanics live in the [glossary](../../GLOSSARY.md#mitigations); this doc places them in the flow and records how each component is reconciled against the implementation.
**Related:**
- `01--2026-05-02-1601-privacy-and-timing-leaks.md` / `03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` - per-API leak surfaces.
- `07--2026-06-12-0916-ecash-extension.md` - the eCash extension: custody split, mint threat model, delay scaling.
- `../../archive/2026-05-02-1700-node-privacy-from-the-world.md` - world-facing privacy (archived; separate threat model).

---

## 1. Purpose and scope

[Spacer](../../GLOSSARY.md#spacer) lets an AI client drive a Bitcoin node without learning more about the operator's wallet, balances, or identifiers than the task requires; operator-enabled **advanced extensions** add Lightning (LND) and, atop it, [Chaumian eCash](../../GLOSSARY.md#chaumian-ecash-cashu) - a mint-backed bearer float the AI transacts with directly, doc 07 - under the same protections (§2.2). Two processes joined by a protocol; the protocol is the trust boundary. Out of scope here (and listed in §8): [world-facing privacy](../../GLOSSARY.md#world-facing-privacy), wire formats, API shapes, data-model schemas, code structure, and the bitcoin/LN primitives (all in the glossary or their own per-decision docs).

## 2. The two components and the trust boundary

- The [petitioner](../../GLOSSARY.md#petitioner): client-side, runs in the AI's environment, holds no secrets.
- The [arbiter](../../GLOSSARY.md#arbiter): server-side, unreachable by the AI; bundles the [privacy gateway](../../GLOSSARY.md#privacy-gateway), the bitcoind client access (plus LND under the advanced extension, §2.2), local state, the [audit log](../../GLOSSARY.md#audit-log), and the timing layer ([action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay)).

The spacer protocol is the boundary. The asymmetric naming reflects the trust direction - a petitioner asks, an arbiter decides - and any sensitive logic placed petitioner-side falls into the AI's reach and defeats the point.

### 2.1 Arbiter implementation discipline

All runnable code lives under `spacer/arbiter/src/`. Three hard constraints:

- **Minimal**: small line count and dependency footprint - the whole codebase fits in a human's head during one review pass.
- **Inline-documented only**: documentation lives in code comments; no Markdown inside `src/`.
- **No transient files outside the gitignored subtrees**: every module writes only under `state/` / `data/` / `bitcoin/` / `lnd/` / `ecash/` (gitignored per `06--2026-05-24-0623-arb-auditability.md` §3). Churn inside `src/` / `config/` / `bin/` would pollute the [continuous-snapshot](06--2026-05-24-0623-arb-auditability.md) history the manual audit primitive depends on.

The arbiter must be **manually auditable**: a human can copy, install, and read the entire codebase without any AI help. The arbiter never runs AI itself, so any AI-generated implementation must survive a non-AI human review pass first. This trades implementation ergonomics for a hard auditability floor and is the central design constraint.

### 2.2 Deployment modes: onchain default, Lightning and eCash as advanced extensions

`SPACER_MODE` selects the arbiter's exposed op surface; anything but the exact extension values - including unset - runs **onchain**, the default. There Bitcoin on-chain is the whole surface: `query_balance` reads the bitcoind wallet, `send_bitcoin` is the only write, and `lnd.py` is never imported, so the default deployment carries no LND dependency at runtime. The **advanced Lightning extension** (`SPACER_MODE=lightning|full`) layers `query_channels` / `send_lightning` back on and serves `query_balance` from the LND wallet instead. An extension op against an arbiter without its extension refuses uniformly at the gateway's mode gate, audit-logged `decision_refuse_mode` (reason `advanced_extension_disabled`; the op field disambiguates which extension) so the operator can tell an extension-gated call from an unknown op. petcli mirrors the framing: on-chain commands are the primary tree, the extensions live under the `advanced` namespace (§5.1).

The **eCash extension** (`SPACER_MODE=ecash`, doc 07) enables the full rail ladder: the entire Lightning surface exactly as lightning mode has it (ecash implies lightning - the fund/defund legs are LN payments - just as lightning implies bitcoind), plus the eCash writes `fund_ecash` / `defund_ecash`. Those carry no `recipient_token` (the destination is structurally the operator-pinned [mint](../../GLOSSARY.md#mint)), so they skip the registry and route [allowance](../../GLOSSARY.md#ecash-allowance) cap (fund only) -> standing approvals against the literal destination `mint` -> dispatch (doc 07 §3, §8). `full` stays frozen at its 2026-06 meaning (onchain + lightning, a legacy alias of `lightning`): an extension that moves bearer value out of gateway control never switches on without the operator typing its name, so `full` does not auto-grow to include ecash, and eCash ops refuse at the mode gate in both onchain and lightning/full modes. The fail-safe parse is unchanged - anything outside `{lightning, full, ecash}` runs onchain.

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
[bitcoind client access]                 (bitcoin-cli; advanced extensions: lncli, cashu)
  |
  v
[on-chain effect]                        (broadcast; advanced: LN payment, channel open;
                                          ecash: mint/melt at the pinned mint)
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

The petitioner gets an immediate synchronous acknowledgment ("received: opaque-handle") at submission, but every AI-observable consequence - on-chain visibility and result knowledge - is deferred by the timing layer.

Read-only queries take the same petitioner -> gateway -> arbiter path but skip the timing layer; their responses are filtered by the same outbound mechanisms ([banding](../../GLOSSARY.md#banding-numeric-value-banding), [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization), [aggregate-by-default](../../GLOSSARY.md#aggregate-by-default), [hide secrets](../../GLOSSARY.md#hide-secrets)) and stamped with [latency normalization](../../GLOSSARY.md#latency-normalization).

The eCash writes (`fund_ecash` / `defund_ecash`, ecash mode only) follow the write flow with two differences: there is no registry step - they carry no `recipient_token`; the destination is structurally the pinned mint - and `fund_ecash` passes an [allowance](../../GLOSSARY.md#ecash-allowance)-cap check before standing approvals (doc 07 §3, §8). The AI's direct token operations within its float (hold, send, receive at the mint) never enter this flow at all; that unmediated channel is the extension's point and its deployment cost (doc 07 §1, §3).

---

## 4. Components on the arbiter

### 4.1 Privacy gateway

The [privacy gateway](../../GLOSSARY.md#privacy-gateway) is the **only** network-reachable component; every request hits it first. It must be **limited** (small surface, few dependencies) and **airtight** (no bypass to bitcoind / LND / state, no leakage via error messages, timing, or response shape, no untrusted deserialization beyond the protocol). Deeper storage (preimages, descriptors, PSBTs, the audit log, the token-to-real mapping) lives elsewhere on the arbiter.

Per request, in order: [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) (which for writes doubles as the destination gate, resolving `recipient_token` through the [recipient address registry](#47-recipient-address-registry) and refusing uniformly on miss; the eCash writes skip this step - their destination is structurally the pinned mint), an [eCash allowance](../../GLOSSARY.md#ecash-allowance) cap on `fund_ecash` ahead of any approval (ecash mode; §2.2, doc 07 §8), a [standing approvals](../../GLOSSARY.md#standing-approvals) check (writes only; eCash writes match the literal destination `mint`; no match parks in [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval)), [band](../../GLOSSARY.md#banding-numeric-value-banding) cloak-ineligible numeric fields, [scale-cloak](../../GLOSSARY.md#scale-cloaking) wallet/channel totals (**in place of** banding - the per-tier scale already compresses 10x+), refuse extension-gated ops whose extension the mode does not enable (§2.2; no HITL park - the operator already decided by choosing the mode), [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval)-defer unrecognized ops, [audit log](../../GLOSSARY.md#audit-log) append, and [latency-normalize](../../GLOSSARY.md#latency-normalization) every response to a configured floor so timing carries no information about which step refused or how far the pipeline got.

**Implementation status.** The `arbiter/src/gateway.py` skeleton wires the HTTP entry, JSON parsing, audit logging, latency normalization, mode routing (§2.2; lazy LND and eCash imports, `decision_refuse_mode` on extension-gated ops), registry-gated write resolution, the eCash write branch (allowance gate then standing approvals, `decision_refuse_allowance` on the cap; §2.2, doc 07 §8), the standing-approvals gate (both branches: HITL park on no-match, dispatch on match), the HITL park for unrecognized ops, the result-poll fast path (§4.8), and read-op dispatch (`query_balance` from the bitcoind wallet in onchain mode or the LND wallet under the extensions; `query_channels` extension-only) through scale cloaking. As of sp-uwa0v0 (2026-06-18) an approved write - all four named ops, fund/defund included - enqueues on the timing layer and `executor.py` drains it against the daemons / the mint; the `not_implemented` tail in `_dispatch` is reachable only by an unknown op. Still pending: band-edge randomization and aggregate-by-default on cloak-ineligible fields, the HITL queue table behind `_hitl_park` (currently audit-logs the deferral and returns the refusal but writes no queue row), and production timing / cloak windows (§4.6). Each pending mechanism is a named function (`_hitl_park`, `_band_outbound`), so a reviewer sees wired behavior vs present structure at a glance.

### 4.2 Bitcoin client access (primary surface)

The onchain (default) mode's backend: `bitcoin-cli` against the [local bitcoind](../../GLOSSARY.md#local-bitcoind) under `spacer/arbiter/bitcoin/`, via `arbiter/src/bitcoin.py` (stdlib subprocess, no shell, four RPCs; full detail in `02--2026-05-02-1602-bitcoind-mutinynet-test-flow.md` §6). `query_balance` is served here (`getbalance()`, a BTC Decimal scaled to integer sats, then scale-cloaked; §4.1), and `send_bitcoin` dispatches through `sendtoaddress` once the §4.6 executor lands. Coin selection and signing stay inside bitcoind; PSBTs never leave ([hide secrets](../../GLOSSARY.md#hide-secrets)).

### 4.3 LND client access (advanced extension)

Enabled under `SPACER_MODE=lightning|full|ecash` (§2.2; ecash mode layers the eCash extension on this surface unchanged); the module is imported lazily on advanced-mode dispatch, so an onchain deployment never loads it (asserted by the exit loop's no-lnd-import gate, §10). `lncli` via a subprocess argv list (no shell) in `arbiter/src/lnd.py` - deliberately **not** the test-harness [lncliA](../../GLOSSARY.md#lnclia) shell script, so a reviewer (§2.1) reads one `_run` helper and sees the whole connection surface (binary, TLS cert, macaroon, RPC server, network). `lncli` already speaks gRPC, so "lncli plus gRPC/REST" collapses to "lncli only" (a direct gRPC client remains a future swap). Reconciled behavior:

- Balance / channel-capacity reads (`walletbalance`, `channelbalance`) are [scale-cloaked](../../GLOSSARY.md#scale-cloaking) into a fixed 0-100k window **in place of** [banding](../../GLOSSARY.md#banding-numeric-value-banding) (the per-tier scale already gives 10x+ compression). Banding stays for non-cloak fields (per-call fee / amount on send paths).
- Channel-pool aggregation is structural: the wrapper uses `channelbalance` (aggregate local + remote), not `listchannels`, so [aggregate-by-default](../../GLOSSARY.md#aggregate-by-default) is enforced at RPC selection rather than as a filter on per-channel detail.
- State-changing calls reach this layer only after the gateway resolved `recipient_token` through the registry, so the destination is the real address by construction. `openchannel` defaults `private=True` ([default --private](../../GLOSSARY.md#default---private-channels)); `payinvoice` always uses `-f` (no operator at `lncli` stdin). HTLC secrets stay in `lnd`; the gateway redacts before responses cross the boundary ([hide secrets](../../GLOSSARY.md#hide-secrets)).
- Cloak production mode (multi-day randomized transitions, within-tier randomization) is open; gated behind `NotImplementedError`, runs only under `SPACER_SCALE_MODE=test` (5-15s) for exit-loop validation (§10).

### 4.4 Local state

The token-to-real mapping behind [pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) (the [recipient address registry](#47-recipient-address-registry), §4.7, for outbound destinations), the pending [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval) queue, and the timing layer's pending action + result deferrals. All on the arbiter; unreachable by the petitioner.

### 4.5 Audit log

The append-only [audit log](../../GLOSSARY.md#audit-log) of every request and arbiter decision, in the arbiter's environment (unreachable by the petitioner, so AI-side tampering is structurally impossible). Reconciled properties of `arbiter/src/audit.py`:

- **JSONL** - one JSON object per line: UTC ISO-8601 timestamp, a short event tag (`request_received`, `decision_refuse_registry`, ...), and a JSON payload.
- **Durable + atomic** - every record is fsynced before `record()` returns; `O_APPEND` is atomic up to `PIPE_BUF` (4096 B) and an in-process lock serializes longer records (the single-process discipline removes any cross-writer locking need).
- **Immutability by structure** - the module exposes only `configure()` and `record()`; no code path edits or deletes records.
- **Location** `arbiter/state/audit.log`, gitignored; overridable via `AUDIT_LOG_PATH`.
- **Companion primitive** - the [continuous git snapshot](06--2026-05-24-0623-arb-auditability.md) captures *what was deployed*, this log *what was decided*; neither subsumes the other (06-- §2).

### 4.6 Timing layer

Enforces both anonymity-set delays - [action delay](../../GLOSSARY.md#action-delay) (submit -> execute) and [result delay](../../GLOSSARY.md#result-delay) (complete -> petitioner can learn the result) - each with a ~12h floor, randomized within a window the arbiter computes from observed global activity for similar action / result shapes. The dynamic window is itself part of the security surface: constant or naive parameters make the distribution a fingerprint. The same module enforces the §4.7 rejection-delivery delay; all three share one defer-then-pop substrate (`pending_actions` / `pending_results`, each with a `ready_at` plus a kind tag, drained by elapsed `ready_at` in arrival order).

**Status: partial.** Test-mode windows are wired end-to-end (5-15s action, 5-15s result, 1-5s rejection-delivery; §10), and the drain side landed with sp-uwa0v0: `executor.py` runs due actions against bitcoind / LND / the mint and deposits due results into the result registry. Production windows remain blocked behind the dynamic-window calculation (§7, resolved in doc 09; implementation open) and raise `NotImplementedError` on every enqueue path until they land - the safe failure mode is "does not run," not "runs with the wrong window." Mode selection is conservative: only exact `SPACER_TIMING_MODE=test` enables test mode (a typo, miscase, or unset lands in production and refuses).

### 4.7 Recipient address registry

The destination gate: a state-changing call carries a `recipient_token`, the gateway resolves it through `registry.lookup()`, and any non-`ok` outcome collapses to the uniform "destination unavailable" refusal - the lookup *is* the gate, with no separate outbound-policy step. The standard treatment (storage YAML, entry shape, one-time-use, probing infeasibility, refusal behavior) is the glossary [Recipient address registry](../../GLOSSARY.md#recipient-address-registry) entry. The implementation specifics beyond it:

- **Token format** (closed the §7 open question): 5 random [Crockford-base32](https://www.crockford.com/base32.html) chars (`0-9A-Z` minus `I L O U`) + 1 Damm32 check char (length 6, 25-bit namespace `32^5` = 33.5M). The Damm32 quasigroup is computed over GF(2^5) with reduction polynomial `x^5 + x^2 + 1`, detecting every single-character substitution and every adjacent transposition. On lookup, input is uppercased, outer whitespace stripped, and `I`/`L` -> `1`, `O` -> `0`; `U` is excluded (a typed `U` fails alphabet validation). Generation re-rolls on collision and after 10 consecutive collisions raises `namespace unhealthy` rather than looping forever.
- **On-chain encodings:** bech32 (P2WPKH/P2WSH), bech32m (P2TR), base58check (P2PKH/P2SH), detected in fixed order (polymods are non-overlapping). LN-side encodings (BOLT-11/12, Lightning Address) are open (§7).
- **No-mainnet hard rule, enforced at add time** (not just at dispatch): bech32 / bech32m HRP must be `tb` / `bcrt`, base58 version `0x6F` / `0xC4`; mainnet `bc` / `0x00` / `0x05` is refused on the same path as a malformed address, so a fat-fingered mainnet address never lands in storage.
- **One-time use:** `used` flips true on the first successful send. The consume is a single atomic UPDATE gated only on `used == false` and deliberately does **not** re-check `expires_at` - the [action delay](../../GLOSSARY.md#action-delay) window can span hours and an entry may cross expiry between lookup and consume; once authorized at lookup, record-keeping must record use, else a long-delayed send lands on-chain without the flip and the token could be reused.
- **Refusal outcomes (five):** `bad_checksum`, `unknown`, `expired`, `used`, `anomalous` (a defense-in-depth re-validation of the stored address; should never fire). All collapse to one petitioner-visible bit; the audit log differentiates for operator triage.
- **Rejection-delivery delay:** the refusal is held **1 hour ± 30 min** (randomized) before deposit into the [result registry](#48-result-registry), closing the submission-to-response timing channel and decoupling the rejection's appearance from operator console reaction. Shorter than the multi-hour action delay because nothing went on-chain. Operator consequence: reacting fast to an invalid-token entry in the audit log does not help the AI receive a corrected token sooner (it only learns after the delay) and just spends the privacy budget.

(Storage landed as the §4.7-described YAML - `arbiter/config/destinations.yaml`, stdlib-parsed, operator-hand-editable; bl-2lbqu4.)

### 4.8 Result registry

Arbiter-side storage for completed results and delayed rejections, read by the petitioner via a gateway poll endpoint. Deposits arrive via the [timing layer](#46-timing-layer): the gateway filters / bands / tokenizes the outcome and enqueues it on `pending_results`; after the [result delay](../../GLOSSARY.md#result-delay) (or the §4.7 rejection window) elapses, the drainer deposits it against the original handle. The registry records `kind` (`result` / `rejection`) for audit triage only - the **wire response is identical for both**, which is what the §4.7 rejection delay relies on.

- **Pull-only.** The arbiter never initiates contact; no callback, push, or notification. Keeps every outbound timing signal on the petitioner side.
- **Binary state.** A poll returns the result or "not yet" - never progress or ETA. The petitioner reasons about elapsed time only from its local estimate (§5.2).
- **10-min poll floor,** keyed by handle alone (the handle is the petitioner-binding identifier; the arbiter has no petitioner-identity notion at this layer). Faster polls get "not yet" without consulting result state. The floor matches block cadence, pins resolution below the multi-hour window, flattens chain-vs-LN cadence, and caps poll-storm load.
- **Idempotent retrieval.** A successful read marks the entry consumed; later polls return "not yet," indistinguishable from a never-existed handle. The floor anchor advances on the first non-throttled poll *before* the result table is consulted (a crash cannot bypass the floor), and throttled polls do not advance it (spam cannot push the next poll out). All "not yet" cases are wire-indistinguishable; the audit log differentiates.
- **Caveat.** The handle links submission to retrieval (intentional - the AI must find its own results), so it is sensitive petitioner-side; if it leaks into another context, that party can probe for the result.

### 4.9 eCash client access and allowance (eCash extension)

Enabled only under `SPACER_MODE=ecash` (§2.2); imported lazily on ecash-mode dispatch via `gateway._ecash()`, so onchain and lightning deployments never load it and carry no nutshell dependency (asserted by the exit loop's no-ecash-import gate, §10). nutshell's `cashu` CLI via a subprocess argv list (no shell) in `arbiter/src/ecash.py`, one `_run` helper exposing the whole connection surface for the §2.1 review pass: binary (`CASHU_BIN`), operator-pinned [mint](../../GLOSSARY.md#mint) URL (`CASHU_MINT_URL` - **no default**: unset raises before any subprocess runs, so an unconfigured deployment cannot fall back to a public mint), wallet name, and wallet data dir (`CASHU_DIR`, pinned on the subprocess env; the gitignored `arbiter/ecash/` runtime subtree). The default timeout is 60 s - mint calls are HTTPS round-trips to an external host and a melt waits on an LN payment, unlike the local-IPC daemons. Wrapper calls return raw stdout: the nutshell subcommand surface is modeled from its documented CLI and stays unverified against a live mint until sp-2hwco4.4, so structured parsing is deferred to the executor (doc 07 §2).

The module also owns the doc 07 §8 [allowance](../../GLOSSARY.md#ecash-allowance): `config/ecash.yaml` (missing or unparseable reads as allowance 0, refusing every fund) and the append-only `ecash_ledger` outstanding-float ledger (executor-written; floored at 0 so a defund surplus cannot widen funding headroom). The arbiter's eCash custody is transient by design - tokens pass through during fund/defund execution; the AI's float wallet lives petitioner-side (doc 07 §3).

---

## 5. Components on the petitioner

### 5.1 Protocol shim

The [petitioner](../../GLOSSARY.md#petitioner)'s only job is translating AI requests into spacer-protocol messages and presenting responses back; it holds no secrets, policy, or state the AI cannot already reach. It is exposed to the AI as a single CLI, **`petcli`**, organized as a nested command tree with informative `--help` at every node so the AI discovers operations by walking help output. The command shape is an implementation decision. Bitcoin on-chain commands are the primary tree (`submit manage-bitcoin`, `query balance`, `result poll`, `estimate window`); the Lightning and eCash commands live under the opt-in `advanced` namespace (`advanced manage-lightning`, `advanced channels`, `advanced ecash {fund, defund, balance, send, receive, info}`). The ecash group splits along the doc 07 §3 custody boundary: `fund` / `defund` are arbiter-mediated writes, while the rest operate the AI's own bearer wallet through a petitioner-side `cashu` CLI (`PETCLI_CASHU_BIN`) and never touch the arbiter. The namespace is always exposed for discovery and the wire ops are unchanged - petcli holds no policy, so the mode gate lives arbiter-side (§2.2).

**Transport-error envelope.** Two failure classes stay distinct on the AI-visible surface: arbiter refusals come back in the gateway's uniform `{"status": "refused"}` body (privacy-model meaning), while petitioner-side transport failures (connection refused, timeout, non-JSON body) come back as `{"_petcli_transport_error": "<reason>"}`. Every top-level key the petitioner adds is prefixed `_petcli_` (transport errors, the §5.2 estimate stamp, and `_petcli_local` - the envelope the eCash local wallet commands wrap the wallet CLI's verbatim stdout/stderr/exit code in), so the AI can tell shim annotations from arbiter-emitted fields - keeping "the arbiter said no under the privacy model" distinct from "the petitioner could not reach the arbiter" and from "the local wallet said this."

### 5.2 Estimate display

Because [result delay](../../GLOSSARY.md#result-delay) makes results asynchronous, the petitioner shows a local estimate of total elapsed time (action + result delay) so the AI can decide: within window -> wait; past the upper bound with no result -> assume lost; result arrived -> success / failure. Computed petitioner-side from its own view of similar global activity; the arbiter supplies nothing and guarantees no bound.

**Current implementation.** A placeholder hardcoded bound: **24 h** by default (above the 2x ~12h floor) and **30 s** under `PETCLI_TEST_TIMING=1`. It does not yet observe global activity (gated on the same dynamic-window calculation as the arbiter's window, §7); erring high is safe (extra waiting beats a false "assume lost"). The shim stamps it onto every state-changing submit response as `_petcli_estimate_window_s`.

---

## 6. Mitigation map

Where each glossary mitigation fires in the flow; mechanics and caveats are in the glossary.

- [Pseudonymize](../../GLOSSARY.md#pseudonymize-identifier-pseudonymization) / [recipient address registry](#47-recipient-address-registry): gateway, outbound (general) and inbound (the registry gates *who* can be a destination; §4.7).
- [Standing approvals](../../GLOSSARY.md#standing-approvals): gateway, after registry resolution (or, for the eCash writes, after the allowance gate - their destination is structurally `mint`, doc 07 §3), gating *which* writes dispatch without a [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval) pause. Empty by default, so every write HITLs until the operator ratifies patterns. Writes only; reads dispatch unconditionally. (Wired; both branches exercised in the exit loop, §10.)
- [eCash allowance](../../GLOSSARY.md#ecash-allowance): gateway, `fund_ecash` only, checked **before** standing approvals so no approval - standing or tired-HITL - can widen the blast radius (ecash mode; doc 07 §8). Missing config reads as allowance 0: the float cannot exist until the operator writes its bound. (Wired; default-deny, over-allowance, and ordering all exercised in the exit loop, §10.)
- [Banding](../../GLOSSARY.md#banding-numeric-value-banding) / [scale cloaking](../../GLOSSARY.md#scale-cloaking): gateway, outbound numeric fields; wallet/channel totals use scale cloaking in place of banding. **Scale-cloak status: open** - test-mode (5-15s, deterministic tiers) is wired and validated via the exit-loop cloaked-tier / transition variants; production (multi-day randomized delays, within-tier randomization) is gated behind `NotImplementedError`.
- [HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval): gateway parks a write matching no standing approval, or any op outside the mode's recognized set (§2.2). Assent arrives out-of-band at the arbiter console; anything crossing back to the AI is hand-retyped (no clipboard). A recognized write with a `recipient_token` miss refuses at the registry gate, not HITL; an extension-gated op in a mode without its extension (Lightning or eCash ops in onchain mode; eCash ops in lightning/full mode) refuses at the mode gate, also without a park (the operator already decided by choosing the mode).
- [Aggregate-by-default](../../GLOSSARY.md#aggregate-by-default): gateway, outbound list-style calls; per-item detail needs audit-logged justification.
- [Hide secrets](../../GLOSSARY.md#hide-secrets): arbiter-wide; preimages, signatures, macaroons, descriptors, xpubs, PSBTs, and raw values behind any pseudonym never leave local state.
- [Default --private channels](../../GLOSSARY.md#default---private-channels): LND client path on channel-open (§4.3; advanced extension only).
- [Latency normalization](../../GLOSSARY.md#latency-normalization): gateway, every outbound response - defeats per-response hop-count / IBD / wallet-vs-non-wallet timing fingerprints.
- [Action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay): the timing layer (§4.6), per-action across hours-to-days; they subsume per-poll cadence (the arbiter <-> daemon link is inside the trust boundary). The ~12 h floor is the onchain rail's; floors are per-rail under the [delay-scaling principle](../../GLOSSARY.md#delay-scaling-principle) (doc 07 §7), and the mint-boundary micro-gaps (`timing.mint_gap_s()`, doc 07 §6 T1) ride inside the window on eCash executions. **Status: partial** - test-mode wired (mint gaps included); production gated behind §7's dynamic window.

The gateway is the primary AI-facing defense; world-facing mitigations (archived doc) are defense-in-depth and out of scope here.

---

## 7. Open design questions

- **Result-delivery payload shape.** The "result or not yet" envelope is settled (binary status + opaque payload + audit-internal kind, §4.8); the residual is the payload's terminal-state set (success / failure / "failed temporary (try again)" per [latency fingerprinting](../../GLOSSARY.md#latency-fingerprinting) / others?) and how each is signaled inside it (sp-77lxs.1).
- **Dynamic window calculation.** How the arbiter turns "global activity for similar actions" into a window: what counts as "similar," where the observation comes from (gossip, mempool, block stats, esplora?), and how parameters are bounded so the window does not become a fingerprint. Gates production timing.
- **Band-edge randomization for aggregate counts** (per [aggregate-by-default](../../GLOSSARY.md#aggregate-by-default) and [JIT liquidity](../../GLOSSARY.md#jit-liquidity)) so band transitions cannot be triangulated back to specific events.
- **LN-side recipient ingestion encoding.** On-chain landed (§4.7); LN-side is open - BOLT-11 is too long to retype, BOLT-12 (~100 chars) is borderline, Lightning Address adds an outbound HTTPS dependency and a recipient-side observer, a QR scanner adds hardware. Each has its own trust and operational implications.
- **Standing approvals YAML schema** - how a rule names op / destination / amount band / rationale, and how the gateway resolves precedence on multiple matches; must stay readable enough for a non-technical operator to edit without tooling.

---

## 8. What is NOT in this doc

The logical architecture only. Deliberately out of scope, each to get its own design doc when decided:

- Bitcoin/LN primitives (UTXO, xpub, bolt11/12, HTLC, SCID, channel point, PSBT, signet) - glossary vocabulary.
- The spacer protocol's API shapes, error model, and wire formats.
- Data-model schemas (token-to-real mapping, policy tables, HITL queue, audit log records).
- Code structure inside either component beyond the §2.1 auditability constraints.
- World-facing mitigations - the archived world-facing doc.
- Per-API filter rules (which fields get banded / tokenized / dropped) - docs 01 (LND) and 03 (bitcoind).

---

## 9. Current physical layout

Parent folders under `~/spacer/` live under one of three homes - `arbiter/`, `petitioner/`, `test-harness/` - with project-level artifacts (`design-docs/`, `archive/`, `GLOSSARY.md`) at the root. The tree is itself vocabulary: "under `arbiter/`", "in `test-harness/state/`" are precise role references.

```
~/spacer/
  arbiter/                # everything that must stay out of the AI's reach
    bin/                  # arbiter-side clients: lncli, bitcoind, bitcoin-cli, bitcoin-tx, bitcoin-wallet
    bitcoin/              # bitcoind datadir (signet only)
    lnd/                  # LND credentials (admin.macaroon, tls.cert)
    ecash/                # nutshell wallet datadir (eCash extension; arrives with the live mint, sp-2hwco4.4)
  petitioner/             # client-side process: petcli, the protocol shim (§5.1)
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
  design-docs/            # origin/ + findings/ + implementation/; naming per design-docs/README.md
  GLOSSARY.md             # project vocabulary
```

Also at the root, outside that split: `go/` and `go-cache/` (Go build caches from other tooling) and `first-game/` (an unrelated C# project predating spacer). This is a snapshot; cited paths may move, but the logical architecture above is the load-bearing description.

---

## 10. Exit criteria for the implementation closed loop

A process-side gate (here for convenience; it references components above). **Done** = for every `petcli` command and variant, an end-to-end run traverses the gateway, the timing layer, the relevant arbiter components, and the test-harness's bitcoind / LND, returns a [result registry](#48-result-registry) result matching the expected outcome, with the raw artifacts preserved verbatim under `exit-loop/`. **Coverage** = every `petcli` leaf and every argument variant exercising a distinct arbiter path (happy + rejection, Bitcoin + Lightning).

**Current coverage:** read-only `query/balance` (the bitcoind wallet in onchain mode, the LND wallet under the advanced extension), `advanced/channels`, `result/poll`, and `estimate/window` are exercised end-to-end, including the T0 no-cloak branch and the four cloaked `scale.present()` branches (T1 init; T2 init = identical wire response to T1, which is the cloak's point; transition-pending with `drift > range`; transition-applied, which audit-logs `scale_tier_shift_applied`). The mode gate (§2.2) is exercised by `refused-onchain-mode` and `refused-lightning-mode` variants (Lightning and eCash ops against arbiters without their extension; audit `decision_refuse_mode`), and the no-lnd-import / no-ecash-import gates assert every onchain variant ran LND-free and every non-ecash variant ran mint-free. State-changing sends are exercised on the registry-miss refusal path and both standing-approvals branches (`parked-no-standing-approval` / `allowed-by-standing-approval`). The eCash surface (doc 07 §9) is covered on both custody halves: the fund allowance gate (missing-config default-deny; the over-allowance refusal asserted - via forbidden audit events - to fire without consulting a staged matching approval), both standing-approvals branches for fund and defund (`destination: mint`; defund rules unbounded), ladder-regression variants holding the Lightning surface exactly as lightning mode has it (`query/balance/ecash-lnd-wallet`, `advanced/channels/ecash-mode`), and the local wallet commands against a petitioner-side fake `cashu` (the `_petcli_local` envelope, plus a deterministic missing-binary error variant). As of sp-uwa0v0 the happy-path sends ride the landed executor: the four `allowed-by-standing-approval` variants assert the timing-layer acknowledgment (`status: received` + handle), and the runner's `--live` mode drives all four write ops through the real executor against Node A + the live mint (doc 07 §9, doc 08). Still pending: the per-cause rejection subcases (expired, used, bad checksum, anomalous), which need the deferred-rejection delivery path (§4.7).

**Test-mode timing:** production windows have ~12h floors (rejection 1h ± 30 min, scale-cloak transition multi-day), impractical to validate against. Three orthogonal test opt-ins compress them - `SPACER_TIMING_MODE=test` (action / result 5-15s, rejection 1-5s), `SPACER_SCALE_MODE=test` (5-15s transitions, deterministic `0.1^tier`), and `PETCLI_TEST_TIMING=1` (30s petitioner estimate). Because each production path is a `NotImplementedError` until the dynamic-window and scale-transition work lands, a misconfigured environment that does not opt in cannot run with compressed windows - it cannot run at all (the safe failure mode).

**Execution:** validations are state-independent and parallelize in principle (target: the `.beads/` queue via the Gas City rigs), but the current runner (`test-harness/scripts/exit_loop_runner.py`) is sequential - 42 variants plus the no-lnd-import and no-ecash-import gates (44 checks), ~25s per pass, each spinning a fresh in-thread arbiter on an ephemeral port (per-variant `SPACER_MODE` across all three modes; unset = onchain default) and running `petcli` as a subprocess. The loop is binary with no manual sign-off: a failure's raw output is captured under `exit-loop/`, fixed, and re-run until every variant passes.

**Artifacts** live under `exit-loop/petcli/<command>/<variant>/` (`stdout.log`, `stderr.log`, `arbiter-events.log`, `infra-events.log`, `result.json`), mirroring the petcli tree - Lightning artifacts sit under `petcli/advanced/`; the runner rebuilds the tree from its manifest each pass. In the current pass `infra-events.log` is a marker file: onchain reads dispatch through `bitcoin.py` against a runner-installed fake `bitcoin-cli` (canned replies via `$BITCOIN_CLI_SCENARIO`), advanced-mode variants through `lnd.py` against a fake `lncli` (`$LNCLI_SCENARIO`), the eCash local wallet variants through a fake petitioner-side `cashu` (`$CASHU_SCENARIO` at `$PETCLI_CASHU_BIN`), and write variants stop at the mode / allowance / registry / standing-approvals gates or assert the timing-layer acknowledgment against the fakes - no manifest variant reaches a real daemon (only `--live` does). Deliberately, no fake exists for the arbiter-side cashu wrapper: no manifest variant can reach it, and unset `CASHU_BIN` / `CASHU_MINT_URL` make an unexpected arbiter-side mint call error loudly instead of being absorbed (doc 07 §9). No variant exercises live bitcoind / LND / mint yet.

---

## 11. Reconciliation status

Reconciled 2026-06-12 against `gateway.py`, `lnd.py`, `bitcoin.py`, `audit.py`, `scale.py`, `timing.py`, `results.py`, `standing_approvals.py`, and the petitioner shim; the bodies of §2.2, §4-§5, and §10 reflect the implementation as landed (including the onchain-default mode split with LND as the advanced extension, the wired standing-approvals gate, the token format, no-mainnet rule, audit-log durability, the cloak-replaces-banding decision, and the transport-error envelope).

**2026-06-12, eCash build (sp-2hwco4.2):** reconciled again, against `ecash.py` and the extended `gateway.py` / `timing.py` / `standing_approvals.py` / petcli; §§1-6 and §10 fold in the eCash extension as landed - the three-mode ladder with `full` frozen at onchain + lightning, the allowance-before-approvals gate, the structural `mint` destination, the `_petcli_local` envelope, §4.9, and the no-ecash-import gate. Doc 07 §11 is the detailed eCash reconcile.

**2026-07-07:** reconciled against main. Landed since the 06-12 pass, and folded into §§4-5 and §10 above: the **timing-layer executor and result drain** (`executor.py`, sp-uwa0v0 - approved writes enqueue and drain end-to-end; doc 07 §11, doc 08); the **registry YAML migration** (bl-2lbqu4 - `arbiter/config/destinations.yaml`, stdlib-parsed); the **state-defaults split** resolved (`state.py` and `audit.py` both default under `arbiter/state/`); the **live mint environment** (doc 08 + its findings companion - the nutshell CLI surface §4.9 assumed is now verified against nutshell 0.18.1); and the **`manage_*` op rename** (sp-3mm - code, petcli commands, and the exit-loop tree all renamed; the reframe rationale is doc 12 and PR #6). Still deferred (forward-looking design, not yet wired):

- **Production timing** (action / result / rejection windows, and the eCash mint-boundary gaps) - the window *algorithm* is now designed (doc 09) but unimplemented; `NotImplementedError`-gated, per-rail under the delay-scaling principle (doc 07 §7; mint-activity source doc 07 §10.1).
- **Scale-cloak production mode** (multi-day randomized transitions, within-tier randomization) - `NotImplementedError`-gated; only `SPACER_SCALE_MODE=test` is wired.
- **`ecash_funding_rate` rate cap** (doc 07 §8) - deferred until real funding traffic exists to tune against.
