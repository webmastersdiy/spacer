# AI-driven Lightning availability probing and autonomous channel management

**Date:** 2026-06-29
**Status:** DRAFT (design-first; no implementation implied)
**Context:** `manage_lightning` (doc 12: internal-management-only) gains a **probing + self-healing**
capability: probe whether specific LN nodes are reachable and whether paths between node pairs work,
and act on it - close a channel to a failed node / path and open a fresh one. Managing LN liquidity by
hand is hard; an agent that keeps it healthy autonomously is real differentiated value. The hard part,
and why this is its own doc: docs 01 / 03 treat AI probing as a **threat to block** (topology mapping,
balance discovery, fingerprinting); this doc is the **constructive counterpart** - it must deliver basic
availability probing while *living inside* those defenses, never relaxing them.
**Related:**
- [`01--2026-05-02-1601-privacy-and-timing-leaks.md`](01--2026-05-02-1601-privacy-and-timing-leaks.md) - the AI-facing LN leak map and timing-channel defenses this capability lives inside: §3.3 (per-peer / channel aggregation), §3.5 (channel open / close), §4.1 (payment-path latency -> hop-count -> graph distance), §4.2 (polling cadence), §4.6 (channel open / close sequence leak), §4.7 (retry-timing route discovery), §3.6 (`export_pathfinding_scores` - blocked), OQ3 (private-close balance inference), OQ4 (binary-search balance probing), OQ5 (pathfinding-score fingerprint). The defensive envelope; this doc reconciles against it, does not re-derive it.
- [`10--2026-06-26-1930-ecash-mint-monitoring-and-rotation.md`](10--2026-06-26-1930-ecash-mint-monitoring-and-rotation.md) §4 / §5 - the active-probe-with-randomized-timing, idle-only, arbiter-local pattern, and the "arbiter acts autonomously up to the fail-closed line, never chooses the counterparty" autonomy bound, both reused here.
- [archived: node privacy from the world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) - the **world-facing** threat model for the probing traffic itself (gossip, routing-node HTLC timing, on-chain channel funding / close, esplora polling) and its mitigation menu (Tor, private channels, multi-peer broadcast, local esplora). Cited as the privacy spine for the outward direction; stays archived (world-facing is out of active design scope), its applicable mitigations adopted here as constraints.
- doc 11 (cross-rail fee accounting) - cost: probes, rebalances, and channel open / close incur fees (LN routing fee §3; channel open / close are on-chain mining fees §3), booked exact in the arbiter cost ledger (§4), banded / often-0 to the petitioner (§2). This doc owns the *capability + privacy bounds*; doc 11 owns the *cost*.
- doc 12 (external-value boundary) - `manage_lightning` is internal-management-only (§2 / §6); the petitioner sees only cloaked proportions, never absolute amounts (G2, §1 / §4).
- doc 07 §5-§6 - the eCash fund / defund legs ride this LN surface; their mint-facing leak map and timing are doc 07's.
- GLOSSARY: [recipient address registry](../../GLOSSARY.md#recipient-address-registry), [action delay](../../GLOSSARY.md#action-delay), [result delay](../../GLOSSARY.md#result-delay), [default --private channels](../../GLOSSARY.md#default---private-channels), [privacy gateway](../../GLOSSARY.md#privacy-gateway), [audit log](../../GLOSSARY.md#audit-log), [JIT-liquidity](../../GLOSSARY.md#jit-liquidity)

---

## 1. Scope

**In scope:** a `manage_lightning` capability that (a) probes **basic availability** - "is node X
reachable?", "does a path between X and Y work?" - and (b) acts on the result by **autonomously
closing** a channel to a failed node / path and **opening a fresh one**, all within the operator's
existing LN setup. The adversary is the AI client (it may probe to map the network) plus any observer
of the resulting traffic. Measurement references are signet / Mutinynet / test-mint; no mainnet.

**Out of scope** (owned elsewhere, cross-referenced not restated): the per-call leak map and
timing-layer mechanics (doc 01 §3-§5); the cost ledger (doc 11); the internal-only posture and banding
rule (doc 12); the world-facing threat model in full (archived node-privacy doc); the mint-facing legs
(doc 07); wire formats / `petcli` / `lnd.py` structure (implementation).

**Authority.** This doc owns the **probing + self-healing capability and its privacy bounds**. It does
not redefine the leak map (doc 01), the cost ledger (doc 11), the value-boundary posture (doc 12), or
the world-facing model (archived doc) - it reconciles to them.

## 2. The capability

Two operations under `manage_lightning`, both internal-management-only (doc 12):

- **Probe availability.** "Is node X up / reachable?" and "does a path between X and Y work?" - a
  liveness check, not a metric read.
- **Self-heal.** When a node or path a channel depends on fails availability past a threshold,
  **close that channel and open a fresh one** to a healthy counterparty, to keep liquidity working
  without hand-operation.

The value is autonomous liquidity-health maintenance. The constraint is that every part of it stays
inside doc 01's defenses.

## 3. The line: availability, not position

The single distinction the design turns on:

- **In scope:** *liveness*. "Is this node / path up right now?" - a boolean, or a coarse degraded tier.
- **Out of scope:** *position*. Anything that reconstructs the node's place in the network graph -
  topology / peer maps, per-hop latency, route taken, channel balances, pathfinding scores.

Two directions must **both** be bounded, or the capability becomes a deanonymization oracle:

- **Inward** - what the **AI** learns from probing: no topology map (doc 01 §3.3), no binary-search
  balance discovery (doc 01 OQ4), no per-path / per-hop detail (doc 01 §4.1). Bounded in §§4-5.
- **Outward** - what the **probing traffic itself** leaks to the world: timing / path-selection /
  pathfinding-score fingerprints to routing nodes and gossip observers (archived doc §2.2 / §2.6;
  doc 01 §3.6 / OQ5). Bounded in §7.

## 4. Inward bound: arbiter-side probe, coarse verdict, registry-gated targets

- **The probe runs arbiter-side; the AI sees only a verdict.** Like mint monitoring (doc 10 §4), the
  probe executes inside the arbiter and records the raw signal - latency, hop count, route, fee,
  pathfinding score, balance - into **arbiter-local state, never AI-readable**. The AI receives only a
  **coarse verdict**: per node `{reachable | degraded | down}`, per path `{works | degraded | down}` -
  never the underlying metric. This closes the graph-distance estimate (doc 01 §4.1), the
  route-discovery channel (§4.7), the per-peer / channel detail (§3.3), and the pathfinding-score
  fingerprint (§3.6 / OQ5) in one move: the AI cannot read what it is not given.
- **Targets are registry-gated.** The AI may probe only nodes / pairs already in the operator-approved
  [recipient address registry](../../GLOSSARY.md#recipient-address-registry) (our peers, our intended
  counterparties) - the same gate that governs `connect` (doc 01 §3.1) and `openchannel` counterparties
  (§3.5). (The registry's entry *shape* for LN peers is an open reconciliation with the doc 12
  recast - §9.7.) A probe naming a node outside the registry is **uniformly refused** (the refusal shape of the
  mode gate, doc 01 §1, and the missing-allowance default, doc 10 §5). So the AI learns up / down only
  of nodes the operator already chose - it cannot **discover** or **map** new ones. Availability of an
  operator's known peer is not network position.

## 5. Cadence and disclosure: decouple the AI's request from the wire

A probe the AI can trigger on demand, at a cadence it controls, re-creates the polling-cadence
(doc 01 §4.2) and latency (§4.1) channels even with a coarse verdict. So the request is **decoupled
from execution**:

- **Arbiter-controlled, randomized, idle-aware cadence** (doc 10 §4): the arbiter probes on its own
  jittered schedule, piggybacking on organic LN traffic when active; an AI request is **served from a
  recent cached verdict** where possible, not turned 1:1 into a fresh on-wire probe.
- **Disclosure rides the [result delay](../../GLOSSARY.md#result-delay)** (doc 01 §5): the verdict's
  response latency is decoupled from the probe's actual RTT, so the AI cannot time the answer to infer
  hop count (doc 01 §4.1). Any AI-initiated trigger rides the
  [action delay](../../GLOSSARY.md#action-delay).
- **Rate-limit + noise** (doc 01 OQ4): availability queries are bounded per session and the verdict is
  coarsened / noised near thresholds, so a sequence of "is X reachable at capacity N?" queries cannot
  binary-search balances or liveness boundaries.

## 6. Autonomous self-healing, within the autonomy line

The arbiter runs an autonomous **detect -> heal** loop, bounded exactly like doc 10's "act up to the
fail-closed line, never choose the counterparty":

- **It may** close a channel whose node / path has failed availability past a threshold and open a
  fresh one - autonomously, because that only maintains the operator's own liquidity.
- **It may not** choose a *new* counterparty freely: the replacement comes from the operator-approved
  [registry](../../GLOSSARY.md#recipient-address-registry), never AI-named, never a fresh AI-supplied
  node (doc 01 §3.5 "resolve counterparty via the registry"; doc 10 §5 "never chooses the mint").
  Among eligible registry peers the arbiter prefers a **representative / average** one - selection
  criterion = availability **and** representativeness - so the heal carries no distinctive
  counterparty-selection signature and the ambient fee / health signal it yields is representative
  (feeding the anonymity-set-aware fee feedback, §9). **Closing is a policy decision, not an AI choice**
  (doc 01 §3.5); a **force-close needs elevated authorization** (§3.5). New channels default
  [--private](../../GLOSSARY.md#default---private-channels), banded size (§3.5).
- **The AI sees only aggregate health** - e.g. "liquidity healthy: yes", or a banded / relative
  indicator (doc 12 G2) - **never** the per-channel open / close events or their timing. This closes
  the [JIT-liquidity](../../GLOSSARY.md#jit-liquidity) sequence leak (doc 01 §4.6) and the private-close
  balance inference (OQ3): the AI never sees the per-channel state those inferences need. Heal events
  surface to the **operator** (the two-column operator console, doc 13), tagged petitioner-never-known.
- **Anti-flap.** A heal that churns channels rapidly is itself a signal (cf. doc 10 §7
  churn-as-signal); the loop rate-limits heals and treats sustained churn as an operator alert, not an
  automatic re-heal.

## 7. Outward bound: the probing traffic's world-facing fingerprint

The arbiter <-> local-LND link is trusted (out of scope per the internal-link rule); but the **probe
payments and connections LND then makes to the world are world-facing** and must not fingerprint or
deanonymize the node. The archived
[node-privacy-from-the-world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) doc is the
threat model (gossip publication of channel pubkey-pairs / SCID §2.2; routing-node HTLC-settlement
timing §2.6; on-chain channel funding / close §3.3; esplora polling §2.3) and supplies the mitigation
menu this capability adopts as **constraints**:

- **Tor** for the node's transport (archived §5.1); **private channels by default** so probe-driven
  opens do not enter the public routing graph (§5.3); **multi-peer broadcast** for the on-chain funding
  / close a heal produces (§5.2); **local esplora** for confirmation polling (§5.4).
- **No pathfinding-score export** (doc 01 §3.6 blocks `export_pathfinding_scores`); probe path-selection
  must not create a distinctive, repeatable probe-path signature for routing nodes.

These stay world-facing concerns: the archived doc is cited, not un-archived (world-facing remains out
of active design scope) - its mitigations are pulled in only as bounds on how probing runs.

## 8. Seams: cost, internal-only, eCash

- **Cost (doc 11).** Every probe, rebalance, and channel open / close incurs a fee - LN routing fees on
  probe payments, on-chain mining fees on channel open / close (doc 11 §3) - and the probe **cadence
  has a recurring cost**. Each op books an exact `fee_components` record in the arbiter cost ledger
  (doc 11 §4); the petitioner sees it banded / often 0 (doc 11 §2; doc 12 G2). doc 14 owns the
  capability; **doc 11 owns the cost** - this doc does not redefine the ledger.
- **Internal-only (doc 12).** `manage_lightning` manages the operator's **own** LN plumbing between
  operator-controlled endpoints (doc 12 §2 / §6) - liquidity-health maintenance, not external value
  movement. The AI directs it but never holds value and never sees absolute amounts (doc 12 G2).
- **eCash legs (doc 07).** The eCash rail's fund / defund are LN payments on this surface (doc 01 §7);
  availability-healing of LN channels can affect mint defund paths. The mint-facing leak map and timing
  for those legs stay doc 07 §5-§6's; doc 14 only notes the dependency.

## 9. Open questions

1. **Verdict granularity.** Binary `up / down` vs a `degraded` tier - how much a `degraded` verdict
   leaks beyond `down`, and whether the tier earns its marginal disclosure. Gated on live test
   (sp-2hwco4.4 env).
2. **Rate-limit + noise policy.** The concrete per-session query bound and near-threshold noise that
   defeats binary-search probing - shared with doc 01 OQ4; design once, apply to both.
3. **Irreducible path-probe signature.** Whether a path-works probe can avoid a routing-node-observable
   multi-hop signature (archived §2.6) at all, or whether - like doc 01 §4.1 - it can only be absorbed
   (delay layer), not eliminated.
4. **Heal thresholds + cooldown.** How many failed probes trigger a close, and the cooldown that
   prevents heal churn (and the churn-as-signal it would create).
5. **Probe vs passive inference.** Whether availability can be read from organic traffic the rail
   already produces (cheaper, no new footprint) before an active probe is ever sent - the passive-first
   preference of doc 10 §4.
6. **Anonymity-set-aware fee feedback.** Whether representative-peer probing (§6) can yield useful
   **AI-facing fee feedback** - LN feedback banded (doc 01 / doc 12), on-chain ambient from public data
   (doc 03) - without leaking specifics. This is the doc 11 §7.3 tail that replaces an operator
   fee-alarm; the cross-doc design is tracked separately.
7. **Registry entry class for LN peers.** The doc 12 recast defines registry entries as
   operator-owned output descriptors - endpoints the operator *controls*. This doc's probe targets and
   channel counterparties (§4, §6) are operator-*approved* but not operator-*owned*: a routing peer is
   external infrastructure, even though the funds in a 2-of-2 channel with it stay the operator's.
   Reconcile the entry shape: either the registry gains a second, explicitly-tagged entry class
   (approved-peer: node pubkey, no descriptor, no fresh-address machinery), or peer approval becomes
   its own small allowlist beside the registry. Either way the doc 12 posture is untouched - no
   external value payment: a channel open parks operator funds with an approved peer; it does not pay
   them away.

## 10. What is NOT in this doc

- The per-call leak map and the action / result-delay timing layer (doc 01 §3-§5).
- The cost ledger and fee taxonomy (doc 11).
- The internal-only value boundary and the banding / scale-cloaking rule (doc 12).
- The world-facing threat model in full (archived node-privacy doc) - cited for the outward bound, not
  restated.
- The mint-facing fund / defund legs (doc 07 §5-§6).
- Wire formats, `petcli` / `lnd.py` structure, exact probe payloads - implementation.
- Mainnet - signet / Mutinynet / test only.
