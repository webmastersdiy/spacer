# Cross-Rail Fee Accounting (Operator-Facing Cost Ledger)

**Date:** 2026-06-27
**Status:** DRAFT (design-first; no implementation implied)
**Context:** Generalizes the fee-accounting proposal in
[`07--2026-06-12-0916-ecash-extension.md` §10.4](07--2026-06-12-0916-ecash-extension.md#10-open-questions)
from the eCash rail to all three rails (onchain / Lightning / eCash). Doc 07 §10.4 established the
shape - the value ledger tracks *gross*, fees are *operator cost*, audit-logged per op - and noted
the per-op fee **audit surface the operator reads is still to be wired**. This doc defines that
surface and the unified model behind it.
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

This is the load-bearing distinction, and getting it wrong breaks privacy. A fee figure has **two
audiences**, and they get opposite treatment:

| | AI-facing fee (the petitioner sees) | Operator-facing fee (the cost ledger) |
|---|---|---|
| **Audience** | the AI / petitioner | the human operator only |
| **Form** | [banded](../../GLOSSARY.md#banding-numeric-value-banding) - a coarse bucket | **exact** - the real sat figure |
| **Where** | privacy-gateway response (`payinvoice` returns `fee: banded`, doc 01) | arbiter-local [audit log](../../GLOSSARY.md#audit-log) + operator console |
| **Why** | exact fees leak (hop count, wallet size, broadcast timing) | the operator must run the books |
| **Status** | designed (docs 01/03/05) - **not this doc** | the gap - **this doc** |

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
| **Onchain** | mining fee (`sat/vByte` x vsize) on `sendcoins` / channel funding / channel close; RBF top-up on `bumpfee` | the wallet's own tx record (`gettransaction.fee`); `estimatesmartfee` is the pre-estimate | **Yes** - we pay it; it is in our tx |
| **Lightning** | routing fee on `payinvoice` (sum of per-hop HTLC fees); channel open/close funding fees are *onchain* (above), not LN | `payinvoice` per-attempt HTLC table `fee` (doc 01) - banded to the AI, exact in the ledger | **Yes** - we pay it |
| **eCash boundary** | (a) **mint input fee** on mint/melt; (b) **LN routing fee** paying the mint's funding quote; (c) the **melt fee reserve** - a conservative pre-estimate the defund subtracts (`max(2, ceil(2% * claimed))`), whose unspent remainder stays with the mint, not refunded | executor `ecash_fund_executed` / `ecash_defund_executed` audit events: `ln_routing_fee_msat`, `credited_sats` (doc 07 §10.4) | **Partly** - (a)(b) yes; (c) the reserve is paid as a *lump*, and how much was genuine mint fee vs mint-kept remainder is not separately observable |

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
   op's opaque handle:

   `{ handle, rail, op, gross_sats, fee_components{...}, net_sats, ts }`

   - `gross_sats` - the value the op moved (what the allowance / value ledger already tracks).
   - `fee_components` - the rail's §3 fields, **exact**, named per rail (`mining_fee_sat`,
     `ln_routing_fee_msat`, `mint_input_fee_sat`, `melt_reserve_sat`...). Absent components are
     recorded as 0, not omitted, so a later-appearing fee (doc 10 M4) is visible as a change.
   - `net_sats` - what actually landed (`credited` on a defund, `received` on a payment).
   This generalizes doc 07 §10.4's existing eCash events to a per-rail schema; onchain and LN events
   gain the same shape.

2. **Aggregate view (operator console).** A rolling roll-up the operator reads: cost per rail, per op
   class, per period ("this week of autonomy cost ~N sats, M% of it eCash melt reserve"). Derived
   purely from layer-1 events; holds no new secret. This is the surface doc 07 §10.4 called "still to
   be wired."

Both layers are arbiter-local (§2). The petitioner never sees either; its response still carries only
the banded fee.

---

## 5. What the ledger can and cannot attribute

Stating the limits honestly, in the spirit of doc 07 §8's "what the ledger can and cannot see":

- **Onchain / Lightning fees: exact.** We pay them; they are in our own records.
- **eCash reserve remainder: not separable.** The melt reserve is paid as one number; the split
  between genuine mint fee and mint-kept remainder is not observable in this flow (doc 07 findings
  §2). The ledger records the reserve as the cost and notes a *real* input fee separately when the
  mint charges one.
- **AI-direct eCash spends: invisible (by design).** Once the AI holds its float, its own mint
  swaps/sends incur mint fees the arbiter never sees (doc 07 §8: AI-direct spends are invisible). The
  cost ledger bounds **operator-incurred** cost, not the AI's total fee burn - the same honesty doc 07
  §8 applies to the value side.
- **Estimate vs actual.** `estimatesmartfee` / the melt reserve are *pre-estimates*; the ledger
  records the **actual** paid fee where the rail reveals it (onchain confirmed fee, LN settled fee),
  and flags estimate-vs-actual drift as the §6 economic-degradation signal.

---

## 6. Threat model and residual leaks

- **Cost-ledger leakage to the AI (primary).** If any exact fee figure crosses to the petitioner,
  banding is defeated and a broadcast-timing channel opens (doc 03 §4.6: an exact fee estimate
  correlates to an impending tx). The ledger must stay arbiter-local; the petitioner's fee field
  stays banded. This is the one hard rule.
- **Aggregate as a slow leak.** Even banded per-op fees, summed by the AI across a session, could
  approximate totals. That is an AI-facing banding concern (docs 01/03's binary-search-the-balance
  problem), not a cost-ledger concern - noted so the two are not confused.
- **Fee drift as a mint signal (benefit, not leak).** Rising eCash input fees or estimate-vs-actual
  drift feed doc 10's M4; the cost ledger is the natural place that signal is computed.
- **Audit-log sensitivity.** The cost ledger is high-value operator data; it inherits the audit log's
  storage posture (doc 06) - outside AI read access, append-only.

---

## 7. Open questions

1. **Aggregate granularity and retention.** Per-op forever vs rolling windows; how much history the
   console keeps; whether aggregates are precomputed or derived on read.
2. **RBF / bump attribution.** A `bumpfee` adds cost to an *already-recorded* onchain op; whether it
   appends a delta event against the original handle or stands alone.
3. **A fee-budget alarm.** Whether the operator wants a soft cost cap (alert when period cost exceeds
   a threshold), paralleling the allowance's hard cap - and whether that is in scope or operator-tooling.
4. **Reserve-remainder reclaim.** Whether a future flow could reclaim the unspent melt reserve (it is
   the mint's today, doc 07 findings §2), which would change component (c)'s accounting.
5. **Wiring from existing events.** doc 07 §10.4 already emits `ln_routing_fee_msat` / `credited_sats`;
   confirm the onchain/LN executors emit the symmetric fields so layer-1 is uniform across rails.

---

## 8. What is NOT in this doc

- The **AI-facing** fee treatment - banding of fee fields in petitioner responses (docs 01/03/05).
  This doc is operator-facing only; §2 is the firewall between them.
- The allowance / blast-radius bound (doc 07 §8) - it tracks gross value; fees are this doc's parallel
  record.
- Fee *bidding/estimation* policy (how much to pay, fee-bumping strategy) - an execution concern.
- The timing window (doc 09) and mint monitoring (doc 10), except where a fee change is a monitoring
  signal (§3, §6).
- Wire formats, console UI, and executor code structure beyond the per-op event schema.
