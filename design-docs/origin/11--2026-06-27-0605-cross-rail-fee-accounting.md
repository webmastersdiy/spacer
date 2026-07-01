# Cross-Rail Fee Accounting (Operator-Facing Cost Ledger)

**Date:** 2026-06-27
**Status:** DRAFT (design-first; no implementation implied)
**Context:** Generalizes the fee-accounting proposal in
[`07--2026-06-12-0916-ecash-extension.md` §10.4](07--2026-06-12-0916-ecash-extension.md#10-open-questions)
from the eCash rail to all three rails (onchain / Lightning / eCash). Doc 07 §10.4 established the
shape - the value ledger tracks *gross*, fees are *operator cost*, audit-logged per op - and noted
the per-op fee **audit surface the operator reads is still to be wired**. This doc defines that
surface and the unified model behind it, and **supersedes doc 07 §10.4** (now a pointer here; the two
must not drift).
**Related:**
- [`07--2026-06-12-0916-ecash-extension.md`](07--2026-06-12-0916-ecash-extension.md) §8 allowance (tracks gross value, not fees), §10.4 (this doc's charter), and its findings companion §2 (the measured eCash fee shape)
- [`01--2026-05-02-1601-privacy-and-timing-leaks.md`](01--2026-05-02-1601-privacy-and-timing-leaks.md) and [`03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`](03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md) - the **AI-facing** fee treatment (banding), which this doc does NOT touch
- [`05--2026-05-05-0948-architecture-overview.md`](05--2026-05-05-0948-architecture-overview.md) §6 (banding fires on fee fields), §4.5 audit log
- [`06--2026-05-24-0623-arb-auditability.md`](06--2026-05-24-0623-arb-auditability.md) - the audit log is the operator's read surface
- GLOSSARY: [Banding](../../GLOSSARY.md#banding-numeric-value-banding), [Audit log](../../GLOSSARY.md#audit-log)

---

## 1. Purpose and scope

Every write costs a fee, and the fee makes the books not balance: onchain a mining fee, on Lightning
a routing fee, on the eCash boundary a mint/LN/reserve trio (doc 07 §10.4). The operator needs to
*see* those costs - per op and in aggregate - to run the system (is the float bleeding? is a mint
overcharging? what did this week of autonomy cost?). What exists today is piecemeal: doc 07 §10.4
wired gross-value tracking and some eCash fee audit events, but no unified, operator-readable
fee surface, and nothing at all for the onchain and Lightning rails.

**In scope:** the **operator-facing cost ledger** - what fee data each rail produces, the per-op
audit schema, and the aggregate view - across onchain, Lightning, and eCash. **Out of scope:** the
**AI-facing** fee treatment (fees in petitioner responses are [banded](../../GLOSSARY.md#banding-numeric-value-banding)
for privacy - already designed in docs 01/03/05, and §2 explains why the two must never be
conflated); the [allowance](07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius)
itself (doc 07 §8 - it bounds gross value, not fees); fee *estimation/bidding* policy (how much to
pay); wire formats. Measurement references are signet / Mutinynet / test-mint; no mainnet.

---

## 2. Two fee surfaces, never conflated

This is the load-bearing distinction, and getting it wrong breaks privacy. The invariant is **never an
absolute fee amount to the petitioner**: the AI-facing side always sees a
[banded](../../GLOSSARY.md#banding-numeric-value-banding) value - often banded to 0 for the tiny LN
fees a `manage_lightning` op incurs - never a real sat figure; the operator-facing cost ledger sees the
**exact** number. A fee figure has **two audiences**, and they get opposite treatment:

| | AI-facing fee (the petitioner sees) | Operator-facing fee (the cost ledger) |
|---|---|---|
| **Audience** | the AI / petitioner | the human operator only |
| **Form** | [banded](../../GLOSSARY.md#banding-numeric-value-banding) - a coarse bucket, often 0 for small LN fees; **never an absolute sat figure** | **exact** - the real sat figure |
| **Where** | privacy-gateway response (a `manage_lightning` op returns `fee: banded`, doc 01) | arbiter-local [audit log](../../GLOSSARY.md#audit-log) + operator console |
| **Why** | exact fees leak (hop count, wallet size, broadcast timing) | the operator must run the books |
| **Status** | designed (docs 01/03/05) - **not this doc** | the gap - **this doc** |

Two AI-facing examples fix the invariant:

- An **eCash-boundary payout** (a defund / melt): the petitioner sees a **banded total**; the arbiter
  logs the exact §3 trio - mint input fee + LN-boundary routing + melt reserve.
- A **`manage_lightning` op** (a rebalance, a probe, or a payout leg): the per-op fee is **banded,
  often to 0**, and exact in the arbiter. With eCash disabled (doc 12), the banded total is surfaced as
  **relative proportions**, never an absolute figure (doc 12 G2).

The same underlying number is **exact in the cost ledger and banded in the AI's view**. The cost
ledger therefore lives entirely on the trusted side and is **never AI-readable** - same posture as
the audit log and the allowance ledger. Leaking it would (a) defeat the banding the AI-facing side
spent its design budget on, and (b) hand the AI a fee-timing channel: an exact `estimatesmartfee`
or routing-fee figure correlates to an impending broadcast (doc 03 §4.6). The cost ledger is an
*operator instrument*, not a protocol output.

---

## 3. Per-rail fee taxonomy

What makes "sent != received" on each rail, and where the number is observed. Grounded in the live
round-trip where measured (doc 07 findings §2).

| Rail | Fee components (operator cost) | Observed from | Knowable exactly? |
|---|---|---|---|
| **Onchain** | mining fee (`sat/vByte` x vsize) on a `manage_bitcoin` broadcast / channel funding / channel close (active fee-bumping is disallowed in v1 - bump accounting is future, §7.2) | the wallet's own tx record (`gettransaction.fee`); `estimatesmartfee` is the pre-estimate; banded to the AI, exact in the ledger (never absolute, §2) | **Yes** - we pay it; it is in our tx |
| **Lightning** | routing fee on a `manage_lightning` payment (sum of per-hop HTLC fees); channel open/close funding fees are *onchain* (above), not LN | the payment's per-attempt HTLC table `fee` (doc 01) - banded to the AI, exact in the ledger | **Yes** - we pay it |
| **eCash boundary** | (a) **mint input fee** on mint/melt; (b) **LN routing fee** paying the mint's funding quote; (c) the **melt fee reserve** - a conservative pre-estimate the defund subtracts (`max(2, ceil(2% * claimed))`), whose unspent remainder the arbiter **reclaims into its own eCash float** (§7.4) rather than leaving with the mint | executor `ecash_fund_executed` / `ecash_defund_executed` audit events: `ln_routing_fee_msat`, `credited_sats` (doc 07 §10.4) | **Partly** - (a)(b) yes; (c) the reserve is a *lump*; genuine mint fee vs reclaimable remainder is not separable at melt time - doc 10 M4 (a *real* input fee appearing) is the compensating signal |

Measured shape (5,000-sat eCash round-trip, doc 07 findings §2): funded 5,000 != credited ~4,900;
**~98% of the gap was the deliberate ~2% melt reserve**, ~1-2 sat genuine LN/mint fee, and this mint
charged no input fee. So on a healthy mint the dominant "fee" is our own conservative reserve, not a
mint charge - which is itself the signal worth surfacing (a *real* mint input fee appearing is a
[monitoring signal](10--2026-06-26-1930-ecash-mint-monitoring-and-rotation.md), doc 10 M4).

---

## 4. The cost-ledger model

One model across rails: **the value ledger tracks gross; fees are a parallel, operator-only cost
record** (doc 07 §10.4's rule, generalized). Two layers:

1. **Per-op cost record (audit event).** Every executed write audit-logs a fee breakdown against the
   op's opaque **handle** (an arbiter-local audit id, **not** a petitioner-visible token):

   `{ handle, rail, op, gross_sats, fee_components{...}, net_sats, ts }`

   - `gross_sats` - the value the op moved; **references** the allowance / value ledger (the single
     source), not a second copy.
   - `fee_components` - the rail's §3 fields, **exact**, named per rail (`mining_fee_sat`,
     `ln_routing_fee_msat`, `mint_input_fee_sat`, `melt_reserve_sat`...). Absent components are
     recorded as 0, not omitted, so a later-appearing fee (doc 10 M4) is visible as a change.
   - `net_sats` - what actually landed (`credited` on a defund, `received` on a payment).
   This generalizes doc 07 §10.4's existing eCash events to a per-rail schema; onchain and LN events
   gain the same shape - the **target**, since the onchain executor does not yet emit `mining_fee_sat`
   (§7.5).

2. **Aggregate view (operator console).** A rolling roll-up the operator reads: cost per rail, per op
   class, per period ("this week of autonomy cost ~N sats, M% of it eCash melt reserve"). Derived
   from layer-1 events and **materialized durably, independent of raw-event retention** (§7.1); holds
   no new secret. This is the surface doc 07 §10.4 called "still to be wired."

Both layers are arbiter-local (§2). The petitioner never sees either; its response still carries only
the banded fee.

---

## 5. What the ledger can and cannot attribute

Stating the limits honestly, in the spirit of doc 07 §8's "what the ledger can and cannot see":

- **Onchain / Lightning fees: exact.** We pay them; they are in our own records.
- **eCash reserve remainder: reclaimed, not a sunk cost (accounting flip, §7.4).** The melt reserve
  is paid as one lump, and the split between genuine mint fee and remainder is not observable at melt
  time (doc 07 findings §2). Component (c) therefore **stops being booked as a cost**: the ledger
  records the **actual** melt fee `F` exactly, and the **reclaimed unspent remainder as a recovery /
  credit** (the reclaim *mechanism* is doc 07 / PART B; doc 11 records only the accounting). A *real*
  mint input fee appearing is still noted separately (doc 10 M4).
- **AI-direct eCash spends: the AI's own domain (by design).** The AI-direct eCash bearer float is
  **the AI's to use**: once the AI holds it, its own mint swaps / sends incur mint fees the arbiter
  **never sees** (doc 07 §8). The **AI is responsible for its own usable-money-vs-fees split**; the
  arbiter has **no control over and no visibility into** it. The cost ledger bounds **operator-incurred**
  cost only - **never read its total as the AI's total** - the same honesty doc 07 §8 applies to the
  value side.
- **Estimate vs actual.** `estimatesmartfee` / the melt reserve are *pre-estimates*; the ledger
  records the **actual** paid fee where the rail reveals it (onchain confirmed fee, LN settled fee),
  and flags estimate-vs-actual drift as the §6 economic-degradation signal.

---

## 6. Threat model and residual leaks

- **Cost-ledger leakage to the AI (primary).** If any exact fee figure crosses to the petitioner,
  banding is defeated and a broadcast-timing channel opens (doc 03 §4.6: an exact fee estimate
  correlates to an impending tx). The ledger must stay arbiter-local; the petitioner's fee field
  stays banded. This is the one hard rule.
- **Aggregate as a slow leak (analysis-agnostic invariant).** Even banded per-op fees, summed by the
  AI across a session, could approximate totals. The invariant: **nothing revealed to the petitioner -
  the banded per-op fee stream - can be inverted to private info, regardless of forever-or-rolling
  analysis**. That is enforced on the **banding + rate-limit / noise** side (owner: docs 01/03; doc 01
  OQ4, the binary-search-the-balance problem), **not** in the cost ledger - noted so the two are not
  confused.
- **Fee drift as a mint signal (benefit, not leak).** Rising eCash input fees or estimate-vs-actual
  drift feed doc 10's M4; the cost ledger is the natural place that signal is computed.
- **Audit-log sensitivity.** The cost ledger is high-value operator data; it inherits the audit log's
  storage posture (doc 06) - outside AI read access, append-only. On the operator console its fees are
  classified **petitioner-never-known** (doc 13 two-column TUI).

---

## 7. Resolved decisions

The questions this doc opened are resolved; each is stated as a decision, and mechanisms that live in
other docs are referenced, not duplicated.

1. **Retention and granularity.** Store **all** events; retention is **operator-controlled, default
   forever**. The console shows all-time totals plus daily / monthly / yearly datapoints, and the
   roll-ups (§4) are **materialized durably, independent of raw-event retention**. This is an
   **arbiter-side** decision only - no petitioner exposure - so it is not a privacy question.
2. **RBF / bump.** **Active RBF fee-bumping is disallowed in v1.** Bumping draws from a small anonymity
   set and republishes the same UTXOs as a linked replacement, exposing inputs, timing, and mempool
   position - a fingerprint. Doc 11 therefore **reflects** onchain fees only; there is no bump
   component. Reintroduce only if (1) there is real demand **and** (2) it fits the anonymity set without
   exposing UTXOs / txs / mempool. **CPFP is not a privacy-free substitute.** (The op-surface deny lives
   in docs 03 / 05 -> PART B.)
3. **Fee-budget alarm.** **No arbiter-side fee-budget alarm.** A worried operator would use the AI to
   fix fees, turning the operator into a **side-channel** that leaks exact cost state. The need is met
   instead by **anonymity-set-aware AI-facing feedback** - an AI-facing mechanism, so out of doc 11
   (-> PART B). Doc 11 closes this with the reasoning, nothing more.
4. **Reserve-remainder reclaim.** The unspent melt reserve is **reclaimed into the arbiter's own eCash
   float** - **not** returned to the mint, **not** paid to the petitioner (returning it would leak the
   actual fee `F`, since the reserve `R` is publicly computable). It is recycled as fungible eCash to
   fund later petitioner withdrawals. Doc 11 records the **accounting flip** (§5, §3 component (c)); the
   **reclaim mechanism** lives in doc 07 / the impl companion (-> PART B).
5. **Executor symmetry.** The LN and eCash executors already emit their fee fields; the **onchain**
   executor (`send_bitcoin_executed`) does **not** yet emit `mining_fee_sat` - a wiring dependency,
   which is why §4's cross-rail shape is a **target** until it lands (build task -> PART B, coordinated
   with the `manage_bitcoin` rename).

---

## 8. What is NOT in this doc

- The **AI-facing** fee treatment - banding of fee fields in petitioner responses (docs 01/03/05).
  This doc is operator-facing only; §2 is the firewall between them.
- The allowance / blast-radius bound (doc 07 §8) - it tracks gross value; fees are this doc's parallel
  record.
- Fee *bidding / estimation* policy (how much to pay, fee-bumping strategy) - an execution concern.
  The **fee-budget alarm** is likewise out as a mechanism (§7.3): the operator-alarm form is a
  side-channel, and the anonymity-set-aware feedback that replaces it is **AI-facing**, not doc 11.
  This resolves the old fee-alarm-vs-fee-estimation-scope tension.
- The timing window (doc 09) and mint monitoring (doc 10), except where a fee change is a monitoring
  signal (§3, §6).
- Wire formats, console UI, and executor code structure beyond the per-op event schema.
