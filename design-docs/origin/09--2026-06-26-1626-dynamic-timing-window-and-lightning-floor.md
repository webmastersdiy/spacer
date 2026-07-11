# Dynamic Timing Window and Per-Rail Delay Floors

**Date:** 2026-06-26
**Status:** DRAFT (design-first; no implementation implied)
**Context:** Two halves of the timing layer are open. The **principle** half - per-rail
delay scaling and the per-rail floor table - was codified in
[`07--2026-06-12-0916-ecash-extension.md` §7](07--2026-06-12-0916-ecash-extension.md#7-the-delay-scaling-principle-standing-rule-codified)
("The delay-scaling principle"). The **algorithm** half - how the arbiter turns observed
activity into a concrete window - was left open in
[`05--2026-05-05-0948-architecture-overview.md` §7](05--2026-05-05-0948-architecture-overview.md#7-open-design-questions)
("Dynamic window calculation"). This doc resolves the algorithm half and supplies the
per-rail timing-channel reasoning that the floor table rests on. It does **not** re-derive
the principle; doc 07 §7 is the authority for that.
**Related:**
- [`07--2026-06-12-0916-ecash-extension.md` §7](07--2026-06-12-0916-ecash-extension.md#7-the-delay-scaling-principle-standing-rule-codified) - **origin of the delay-scaling principle and the per-rail floor table** (onchain ~12h / lightning ~1h / ecash); also §6 (mint-correlation channels) and §10.1-§10.2 (open floor/activity-source items)
- [`05--2026-05-05-0948-architecture-overview.md`](05--2026-05-05-0948-architecture-overview.md) §4.6 timing layer, §5.2 estimate display, §7 the open "dynamic window calculation"
- [`01--2026-05-02-1601-privacy-and-timing-leaks.md`](01--2026-05-02-1601-privacy-and-timing-leaks.md) §4 timing as a leak channel; §6 the KS-test detectability target
- [`03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`](03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md) on-chain companion
- GLOSSARY: [Action delay](../../GLOSSARY.md#action-delay), [Result delay](../../GLOSSARY.md#result-delay)

---

## 1. Purpose and scope

The timing layer enforces two anonymity-set delays - [Action delay](../../GLOSSARY.md#action-delay)
(submit -> execute) and [Result delay](../../GLOSSARY.md#result-delay) (execute -> petitioner
learns result). Doc 07 §7 already split the single ~12h floor into a per-rail table and made the
glossary's ~12h the *onchain rail's* floor rather than a universal constant. What remains open, and
what this doc supplies:

1. **The dynamic window calculation** (doc 05 §7): the algorithm that turns "observed activity for
   similar actions" into a concrete `[floor_rail, high]` window and samples each action's delay from
   it. The non-obvious part - and the reason this is an algorithm, not just a random draw - is that
   randomizing any *single* delay hides nothing on its own. The leak is statistical: an observer who
   collects the delays of *many* similar actions sees their **distribution**, and a distribution no
   organic process would produce announces "a delay-injecting proxy is here" (and can sometimes be
   subtracted back off to recover the true timing). So the window must be **shaped** to look organic,
   not merely bounded (§4.4). Doc 07 §7 said this "becomes per-rail: same mechanism, per-rail activity
   sources and floors" and pointed here.
2. **The per-rail timing-channel reasoning** the floor table rests on: *why* the floors differ is a
   difference in the timing *channel* per rail, not merely rail speed (§3). This is what justifies
   a lightning floor far below the onchain one.

**In scope:** the AI-facing timing layer (petitioner <-> privacy gateway <-> arbiter). Adversary
per doc 01 §2: the petitioner/AI itself, plus a network observer of the AI<->gateway channel.
**Out of scope:** the arbiter <-> local bitcoind / LND link (inside the trust boundary; no AI-facing
timing surface, and project policy adds no mitigations there - note the arbiter <-> *mint* link is
**not** covered by that exemption, doc 07 §6); world-facing observers (LN gossip, routing nodes,
explorer operators), which live in the world-facing privacy doc. All measurement references are
signet / Mutinynet / test-mint; no mainnet.

---

## 2. The principle (reference, not restated)

This doc builds directly on the delay-scaling principle codified in
[doc 07 §7](07--2026-06-12-0916-ecash-extension.md#7-the-delay-scaling-principle-standing-rule-codified):

> Delays must be adequate for the anonymity-set size and the nuances of the particular privacy
> concern. Privacy adequacy is the floor; UX never overrides it. The UX bet: delay tolerance tracks
> rail speed, and the bet pays because the adequate floor is naturally lower on faster rails - the
> anonymity set turns over faster.

Doc 07 §7 owns the principle and the per-rail floor **table** (the "what"). This doc owns the
**algorithm** that realizes it (§4) and the **channel reasoning** behind it (§3). Where a number
appears in both (the lightning floor), doc 07 §7 / §10.2 is the source of truth and this doc tracks
it (§5). Everything below is the genuinely-new material; the principle is not repeated.

---

## 3. Why the floors differ: the timing channel, per rail

Doc 07 §7 frames the difference as rail *speed* and *turnover*. The sharper reason - and the one
that lets the lightning floor sit ~12x below onchain - is that the **observable timing channel is a
different shape per rail**. The floor values fall out of this.

| Rail | Public global ledger? | Primary timing channel the *action* delay must break | Anonymity-set source |
|---|---|---|---|
| **On-chain (bitcoin)** | **Yes** - every tx is globally visible forever | A global chain observer lines up "petitioner reasoned/submitted at T" with "a tx matching our node appeared at T+e". | Other same-shape on-chain txs in mempool + recent blocks. Public, countable, **strong**. |
| **Lightning** | **No** - onion-routed, privately settled; no public per-payment ledger | The petitioner correlates *its own submission* with *any consequence it can observe*: a colluding recipient's receipt, a later balance/channel read, the result-delivery time. No public event exists for a third party to line up. | Other same-shape LN payments - **not publicly countable**; estimable only from the arbiter's own narrow node view (§4.3). **Weak.** |
| **eCash (Cashu)** | No public ledger; the **mint** sees all | Mint-side correlation of token ops (doc 07 §6, T1-T6); secondarily the petitioner's submit->observe channel. | Same-keyset-epoch mint traffic (doc 07 §6 T6). Estimable only at the mint (doc 07 §10.1). |

The load-bearing consequence for the **lightning floor**: Lightning's dominant channel -
petitioner-submit -> petitioner-observable-consequence - is **already broken by
[Result delay](../../GLOSSARY.md#result-delay)** (the same point doc 07 §6 T2 makes for the
issuance->first-swap gap). So the Lightning *action* delay is not carrying on-chain-scale
anonymity-set load; its remaining jobs are the floor's non-anonymity properties (§5) plus
de-coupling submit from execute against a colluding recipient. That is why a ~1h floor, not a ~12h
one, is adequate on Lightning - and why the inverse (using the safe-because-large onchain floor
everywhere) is the laziness doc 07 §7 forbids.

That premise requires the read path to be gated too: an ungated live `query_balance` /
`query_channels` is precisely such an observable consequence, open at poll resolution until
[Read snapshot](../../GLOSSARY.md#read-snapshot-snapshot-served-reads) serving (doc 15, which owns
the closure). The floor reasoning here assumes it.

---

## 4. The dynamic window calculation

For a given action the arbiter produces a window `[floor_rail, high]` and samples the actual delay
from a distribution over it. Per doc 07 §7 the mechanism is one mechanism, parameterized per rail.

### 4.1 What counts as "similar" (the bucket)

Similarity is over the **banded, not exact**, action shape:

`bucket = (rail, operation-class, amount-band, direction)`

- `rail` ∈ {onchain, lightning, ecash}; `operation-class` = the observable *kind* (payment,
  channel-open/close, sendcoins, fund/defund), not the petitioner's intent
- `amount-band` = the existing [banding](../../GLOSSARY.md#banding-numeric-value-banding) buckets,
  never the exact amount; `direction` where it changes the observable shape

Bucketing on bands means the anonymity set is computed over the same coarse classes the gateway
already exposes, so the window cannot triangulate a finer value than banding already permits.

### 4.2 Target anonymity set -> window width

The operator configures a per-rail **target set size** `k` (never surfaced). The arbiter estimates
the arrival rate `lambda_bucket` of similar actions (§4.3) and sizes the window so the expected
count of indistinguishable peers in it reaches `k`:

- High activity -> window **compresses** toward `floor_rail`.
- Low activity -> window **stretches** toward a per-rail cap.
- Even at the cap, `k` unreachable -> **starvation** (§6): never silently ship a weak set.

The realized delay is **never below `floor_rail`** (the floor is a hard ceiling on compression) and
never above the cap (bounds UX wait and the staleness risk Result delay flags).

### 4.3 Where the activity estimate comes from (per rail)

Gathered **without signaling the arbiter's own interest**, from inside the trust boundary where
possible:

- **On-chain:** count same-shape txs in the local mempool + recent blocks via the arbiter's own
  bitcoind / esplora. Public data, read locally, no outbound footprint. **Strong.**
- **Lightning:** no global feed. Approximate from the arbiter's own node view (gossip-derived
  capacity/fee churn, own forwarding volume, out-of-band public aggregates). **Weak, biased** - on
  low-confidence estimates, **fail safe to a *wider* window, never narrower.** Open problem (§7).
- **eCash:** estimate at the mint boundary; the mint's swap volume is not publicly observable
  (doc 07 §10.1). Detail and fallbacks belong to doc 07.

### 4.4 Keeping the window from becoming a fingerprint

This is the failure mode flagged by doc 05 §7 and both delay glossary entries ("the distribution
itself becomes a fingerprint"), and it is the one most easily misread. **Sampling each action's
delay at random is necessary but not sufficient.** A single delay reveals little; the leak shows up
only in aggregate, once an observer has collected the delays of a few hundred similar actions and
looks at their *distribution*. Two distinct properties of that distribution can betray the proxy,
and both must be defended.

1. **Shape (primary): random does not mean organic.** The natural choice - draw the delay uniformly
   from `[floor, high]` - is the trap. Over many actions a uniform draw produces a **flat histogram**:
   every value across the window equally likely. No organic process produces that. Real action timing
   is bursty and **heavy-tailed** - the same families (log-normal, Weibull with shape < 1, Pareto)
   that model organic network inter-arrival times - clustered near the low end with a long thin tail.
   A flat band is therefore *instantly* recognizable: an observer fits our few-hundred delays against
   the organic distribution, a Kolmogorov-Smirnov (or similar goodness-of-fit) test rejects "organic"
   at high confidence, and the proxy is outed - worse, a known padding shape can be partially
   subtracted to recover the true timing underneath.

   *Concrete before/after.* **Before:** uniform `[12h, 36h]`. Plot 500 of our delays and you get a
   flat slab from 12h to 36h - a shape no natural sender emits; the KS test separates it from organic
   timing within a few hundred samples. **After:** sample from a distribution **fitted to the bucket's
   own observed organic timing** (heavy-tailed, peaked just above the floor, thinning toward the cap).
   Plot 500 of our delays and the histogram sits *inside* the organic crowd's; the KS test fails to
   separate them (the p < 0.05 target of doc 01 §6). The defense is not "a random delay" - it is a
   delay drawn from the *right curve*.

2. **Predictability.** A correctly-shaped distribution still leaks if the *specific* window for a
   given action is a deterministic function of inputs the observer also holds. For the onchain rail
   the activity estimate (§4.3) is mempool + blocks - **public** data the observer sees too. If the
   arbiter computes `window = f(public_activity)` with no secret, an observer recomputes the same `f`,
   predicts our window, and narrows or removes the randomization it was meant to buy. Fold a
   **per-arbiter secret seed** into the sampling so `window = f(public_activity, secret)`: two arbiters
   on identical public inputs draw different windows, and no outside observer can reproduce the
   mapping. Rotate the seed on a schedule so a long observation cannot regress it.

3. **Bounded, audited parameters.** `floor_rail`, cap, `k`, the distribution family, and the seed
   policy are policy, audit-logged, and changed deliberately - never auto-tuned into a spike (a
   degenerate distribution is just a constant delay in a costume). The calculation is part of the
   **security surface**, not a tuning knob.

Until this lands, production timing stays `NotImplementedError`-gated and test mode uses the fixed
5-15 s windows (doc 07 §7) - the safe failure mode is per-rail.

---

## 5. Per-rail floors (tracking doc 07 §7)

`floor_rail` is the smallest delay a rail ever emits, independent of activity. The **floor values
are owned by [doc 07 §7](07--2026-06-12-0916-ecash-extension.md#7-the-delay-scaling-principle-standing-rule-codified)**;
reproduced here only to attach the cap (new) and the floor's non-anonymity jobs:

| Rail | Floor (per doc 07 §7) | Cap (new, this doc) | Status |
|---|---|---|---|
| On-chain (bitcoin) | **~12h** | ~36h target | floor settled (docs 01/03/05) |
| **Lightning** | **~1h target** | ~a few hours target | floor **proposed, tuning open** (doc 07 §10.2) |
| eCash boundary (fund/defund) | **the LN floor governs** (slowest surface touched) + mint-leg jitter (doc 07 §6 T1) | per doc 07 | per doc 07 §7 |
| AI-direct token ops | **none** (not arbiter-mediated) | n/a | per doc 07 §7 |

A floor exists even on fast rails because it carries jobs the window does not: **mistake/runaway
catch** (the operator's window to notice an accidental or injected action before it is
irreversible), **submit/execute de-coupling** (breaks the T->T+epsilon coupling even with a
colluding recipient), and a **compression backstop** (caps how far high activity shrinks the
window). These jobs - not anonymity-set size - are what keep the lightning floor at ~1h rather than
near zero; the §3 channel reasoning is why ~1h, not ~12h, is enough to discharge them.

The **lightning floor (~1h)** is explicitly proposed-on-reasoning, not measured (doc 07 §10.2); §7
carries it as an open tuning item, not a settled number. This doc adopts doc 07's ~1h verbatim so
the two docs do not diverge.

---

## 6. Threat model and residual leaks

- **Distribution-as-fingerprint (primary).** Addressed by §4.4, never fully closed: if our
  sampled-delay distribution is separable from organic same-shape timing, the proxy's presence and
  parameters leak. Validate continuously with the KS-style test (doc 01 §6).
- **The floor is a public lower bound - and that is intended.** Because `floor_rail` is hard, an
  observer learns "delay >= floor_rail" (">= 12h onchain, >= 1h lightning"). This is *by design* and
  is **not** what §4.4 defends. The defense was never about hiding the delay *numbers* - the floors
  are public knowledge and the rail is already known to the petitioner (rail-distinguishability,
  below). What must not leak is the distribution's **shape** looking machine-generated. A known lower
  bound on a delay drawn from an organic-looking curve reveals nothing an organic same-rail action
  would not.
- **Rail-distinguishability via delay.** Per-rail floors/caps mean delay magnitude correlates with
  rail. The petitioner already knows the rail it chose, so this is moot against the primary
  adversary; against the AI<->gateway network observer it is a secondary leak (it already sees
  request cadence/size) - noted, not solved here.
- **Lightning activity-estimation weakness.** §4.3's LN estimate is biased to the arbiter's own
  node; a too-high `lambda` would over-compress below a real set. Mitigation: fail safe *wider* on
  low confidence; treat the estimator as open research (§7), not a solved input.
- **Starvation on thin buckets.** A rare `(rail, op, band)` may never reach `k` even at the cap.
  Silently shipping a weak set is the dangerous failure. Policy options - widen the band, hold for
  HITL, refuse - are operator-configured, audit-logged, never silent.
- **eCash / mint channels** are enumerated in doc 07 §6 (T1-T6); this doc does not restate them.
  The dynamic window's ecash branch must satisfy the §7 adequacy test against observed mint traffic,
  which doc 07 §10.1 flags as not publicly observable.

---

## 7. Open questions

1. **LN global-activity estimator (the hardest piece).** §4.3's Lightning estimate - which signals,
   how combined, confidence scoring, and the fail-safe-wider rule. Parallels doc 07 §10.1's
   mint-activity-source problem (both rails lack a public global feed).
2. **Lightning floor value.** ~1h is proposed on turnover reasoning; needs signet/Mutinynet
   validation before any production window exists (doc 07 §10.2 owns this; listed here for the
   algorithm's dependence on it).
3. **Distribution family + per-arbiter seed scheme.** The shape family (§4.4.1) and seed-rotation
   derivation/cadence (§4.4.2), chosen so realized delays pass the KS test against organic timing.
4. **`k`, floors, caps - measured values.** §5's caps and `k` are targets; need same-shape
   arrival-rate measurement to set defensible numbers, especially the lightning floor's lower edge.
5. **Petitioner-side estimate, per rail.** The petitioner locally estimates total elapsed time
   (doc 05 §5.2); with per-rail floors it now estimates per rail. Confirm the petitioner estimator
   and the arbiter window stay loosely coupled (no shared secret, no arbiter-provided bound) while
   still giving the AI a usable upper bound.
6. **Starvation default.** Which of widen-band / HITL / refuse is the per-rail default for a thin
   bucket.

---

## 8. What is NOT in this doc

- The delay-scaling **principle** and the per-rail floor **table** - owned by doc 07 §7.
- The eCash mint-adversary timing model (doc 07 §6) and ecash activity-source open item (doc 07
  §10.1); here eCash only takes a window/floor slot in the shared algorithm.
- Wire formats, the result-delivery status enum (doc 05 §7), and `petcli` command shapes.
- World-facing timing (routing-node onion latency, gossip) - the world-facing privacy doc.
- Per-API field filtering (which fields band/tokenize/drop) - docs 01 and 03.
- Concrete code structure inside the arbiter timing layer beyond the auditability constraint.
