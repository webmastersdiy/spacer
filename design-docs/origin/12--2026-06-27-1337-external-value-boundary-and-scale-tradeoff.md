# Foundational Privacy Posture: Internal-Only BTC/LN, eCash-Only External Value, and the Amount-Scale Tradeoff

**Date:** 2026-06-27
**Status:** states a foundational posture **and a reframe of the payment model**. The posture (the
two guarantees + the eCash exception) is the human's call, confirmed. The §8 decisions are now
**made** (mail bl-wisp-x3a67, 2026-06-28) and the cross-doc edits to docs 01 / 05 / 07 + the
GLOSSARY registry are **applied in PR #6** (companion to this PR). §8 records the resolutions.
**Context:** A foundational privacy principle the human gave by voice (mail thread bl-wisp-gvi3s,
corrected by bl-wisp-nmwb0). It is not just additive: it changes what the BTC/LN write ops *are*.
**Related:**
- [`01--2026-05-02-1601-privacy-and-timing-leaks.md`](01--2026-05-02-1601-privacy-and-timing-leaks.md) / [`03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`](03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md) - the AI-facing mitigations that *enforce* endpoint privacy
- [`05--2026-05-05-0948-architecture-overview.md`](05--2026-05-05-0948-architecture-overview.md) §4.1 modes / write flow, §4.7 recipient registry, §6 scale-cloaking
- [`07--2026-06-12-0916-ecash-extension.md`](07--2026-06-12-0916-ecash-extension.md) §5.2 (the float is precisely countable), §7 (per-rail delay; the LN floor), §8 (allowance), §9 (mode gating)
- [`09`](09--2026-06-26-1626-dynamic-timing-window-and-lightning-floor.md) (the lightning floor), GLOSSARY: [Scale cloaking](../../GLOSSARY.md#scale-cloaking), [Recipient address registry](../../GLOSSARY.md#recipient-address-registry)

PET = petitioner / the AI, the adversary (docs 01 §2).

---

## 1. Two guarantees and one exception

The AI-facing design provides two system-level privacy guarantees, and eCash is the single
deliberate exception to the second:

- **G1 - Endpoint privacy.** The PET never learns the operator's fund **endpoints** - source UTXOs,
  change outputs, channel topology/balances, funding txids. So it cannot reconstruct the operator's
  UTXO set, payment graph, or channel topology.
- **G2 - Amount-scale privacy.** The PET sees only **cloaked proportions** of operator funds (banding
  / [scale-cloaking](../../GLOSSARY.md#scale-cloaking), landed as `scale.py`), never an absolute sat
  figure - it cannot tell whether the operator holds a little or a lot.

Both hold whenever eCash is off. Enabling eCash deliberately loosens **G2 only**, and only to the
extent of the float (§4). G1 is never loosened.

---

## 2. The root rule: no external BTC/LN payments

**At the BTC/LN level the arbiter makes no external payments at all.** This is the rule from which
both guarantees follow.

*Why.* In the threat model, **any external payee that can see a UTXO is counted as the PET seeing
it** - the payee is inside the adversary's observability set. An on-chain payment inherently reveals
the spending UTXOs and change to its payee, so an external on-chain payment breaks G1 *by
construction*, regardless of what the proxy hides from the PET directly. Lightning is **not yet**
relied on as a private external rail either. Therefore:

- **BTC and LN are restricted to internal fund-storage management** - operator-controlled endpoints
  only (consolidation, channel management, moving value among the operator's own wallets/nodes).
- **All external value movement happens only via eCash** (when enabled): the operator funds a bearer
  [float](../../GLOSSARY.md#ecash-allowance) the PET spends directly at the mint, so no external
  party ever sees an operator UTXO.

This is exactly why eCash is where G2 loosens (§4): it is the *only* path by which real value leaves
operator control toward the outside world.

*Deferred (not current).* LND off-chain payments **may** later be adopted as a private external rail
(onion-routed, no public per-payment ledger). That is an explicit future option, **not** in force
now. Until then, external = eCash-only.

---

## 3. G1 - endpoint privacy, and its one honest tension

With no external BTC/LN payments, G1 reduces to: the PET never learns the operator's *internal*
endpoints. The existing AI-facing mitigations already enforce this and need only be re-read as
serving G1: `listunspent` never surfaced; coin selection + change kept inside bitcoind/LND (PSBTs
never leave); balances banded/scale-cloaked; channels aggregated; `payinvoice` route / `chan_out` /
preimage hidden; funding txids held internally (docs 01/03/05). This doc *names* the guarantee these
mitigations jointly provide; it adds no new mechanism.

*Tension, stated not papered over.* The root rule (§2) is what makes G1 robust: because there is no
external on-chain payment, there is no public tx exposing operator inputs+change to a colluding
recipient, and the on-chain colluding-recipient correlation vector (docs 01/09) is **eliminated for
BTC/LN**. It re-concentrates on the eCash boundary - the melt names our LND node to the *mint*
(doc 07 §5.1, §6), which is mint-facing, handled by docs 07/10, not a PET-facing G1 break. The only
residual G1 exposure is therefore the deferred external-LN option (§2), which must clear this bar
before adoption.

---

## 4. G2 - amount-scale privacy, and the eCash exception

**eCash disabled.** The arbiter does only fund-storage management; the PET directs operations but
never holds real value. Every value it reads is scale-cloaked into a fixed presentation window
(doc 05 §6), so it sees cloaked **proportions**, never an absolute figure. G2 holds in full.

**eCash enabled - G2 loosens, by necessity.** Funding hands the PET a bearer instrument (the float).
A bearer instrument in hand is *precisely countable* - [scale-cloaking does not apply to the float]
(07--2026-06-12-0916-ecash-extension.md#5-per-op-leak-surface) (doc 07 §5.2). So the PET now handles
a real amount of **known absolute scale** - the first absolute sat figure it ever sees. This is
inherent to handling real payments rather than managed storage; there is no way around it.

*Bounded - the precise reconciliation with doc 07 §5.2/§8.* The loosening is the **float's** scale
only: petty cash, the PET's own chosen amount, hard-capped by the [allowance](../../GLOSSARY.md#ecash-allowance)
(doc 07 §8). The operator's **total** wallet magnitude stays cloaked - "nothing about [it] crosses
with a funding event" (doc 07 §5.2), and a total-holdings bound is unobtainable from a bearer
instrument anyway (doc 07 §8). So the PET learns the float's scale, **not** whether the operator is
rich or poor. The trade is deliberate: the float's amount-scale privacy for AI payment autonomy.

---

## 5. Net posture

| | G1 endpoint privacy | G2 amount-scale privacy |
|---|---|---|
| **eCash disabled** | preserved (BTC/LN internal-only; §2-§3) | preserved - cloaked proportions only |
| **eCash enabled** | preserved (external value is bearer eCash, not an operator endpoint) | **loosened to the float's scale** - bounded; operator total stays cloaked (§4) |

Without eCash the system preserves both. eCash is the one deliberate exception, trading the float's
amount-scale privacy for the PET's ability to make real external payments.

---

## 6. Implications - the reframe this forces (mapped; applied in PR #6)

Before the reframe the docs exposed `send_bitcoin` / `send_lightning` as AI-requestable **external**
write ops gated by the recipient registry (doc 05 §4.1/§4.7, doc 07 §9, the exit-loop). The root
rule (§2) means they no longer make external-recipient payments. Each consequence below was mapped
here first and then **applied in PR #6** (per the §8 decisions); none was silently edited.

- **Write-op set splits internal vs external.** `send_bitcoin`, `send_lightning` (and
  `payinvoice` / `openchannel`) become **internal-management-only** - destinations are
  operator-controlled. `fund_ecash` / `defund_ecash` become the **only** external value path. The
  ops keep their names but change meaning.
- **Recipient registry's role collapses (biggest reconciliation).** Today the registry is the
  destination gate for external `send_*` (doc 05 §4.7); eCash already skips it (pinned mint). With no
  external BTC/LN payments, the registry has no external destinations to resolve. It must either be
  **recast** as an allowlist of operator-owned internal endpoints, or **deferred** (vestigial) until
  external-LN (§2) is adopted. This touches a core mitigation in docs 01/05 and the GLOSSARY. → §8.
- **Modes gain a sharper meaning.** `onchain` and `lightning` become **internal-management** modes;
  `ecash` is the **sole external-value** mode. This *coheres* with doc 07 §9's existing stance that
  eCash is the extension that "moves bearer value out of gateway control" and must be explicitly
  opted in - the reframe makes that the defining line between the modes, not just an eCash caveat.
- **Exit-loop / regression (sp-2hwco4.5).** The BTC/LN legs are no longer external *exits* - they are
  internal round-trips; the only true external exit is the eCash leg. The regression's "full exit-loop
  across onchain+lightning+ecash" needs its **semantics** restated (internal-management vs external
  exit), even if the manifests stay byte-identical.
- **Lightning floor (doc 07 §7 / doc 09).** Its live role becomes the **eCash funding leg** (the LN
  payment to the mint quote; doc 07 §7 already says "the LN floor governs" the ecash boundary) plus
  the deferred external-LN. `send_lightning`-as-external is not a current consumer of it. This is a
  clarification of doc 09, not a contradiction - doc 09 already argued the LN action delay carries
  little anonymity-set load.

---

## 7. Why the corrected rule makes the principle cohere

The correction (no external BTC/LN, not merely "hide the endpoints") is what makes G1 and G2 share a
single root. Because external value moves **only** as bearer eCash: (a) no operator UTXO is ever
shown to an external party → G1 holds without relying on chain-analysis-resistance; and (b) the PET
only ever handles real, absolutely-scaled value on the eCash rail → G2's loosening is *isolated* to
eCash by construction, not by a mitigation that could slip. The two guarantees and the one exception
are now one design, not three.

---

## 8. Decisions (RESOLVED 2026-06-28, mail bl-wisp-x3a67; applied in PR #6)

**Resolved:** (1) recipient registry **recast** as the operator-owned-internal-endpoint allowlist
(not shelved); (2) `send_bitcoin` / `send_lightning` **stay AI-requestable, internal-only** (operator
endpoints only); (3) the recast registry **is** the internal gate - the AI may send only to
allowlisted operator-owned endpoints; (4) **keep the names**, document internal-only (no `manage_*`
rename). Applied to docs 01/05/07 + the GLOSSARY registry in PR #6.

The original questions, kept as the record of what was decided:

1. **Recipient registry.** Recast as the operator-owned-internal-endpoint allowlist, or shelve as
   deferred-until-external-LN? (If recast: does an internal-management `send_*` still resolve a token,
   or is the operator-endpoint set a static config the AI cannot name into?)
2. **`send_bitcoin` / `send_lightning` requestability.** Do they stay **AI-requestable** but only to
   operator-controlled endpoints, or become **operator-only** management ops the PET cannot invoke at
   all? (This decides whether they keep a gateway gate or leave the AI surface.)
3. **Internal-management destination gate.** If internal `send_*` stay AI-requestable, what gates
   "operator-controlled" (an allowlist == the recast registry of #1)? If operator-only, the gate is
   moot.
4. **Naming.** Whether to rename the ops to signal internal-only (e.g. a `manage_*` family) or keep
   `send_bitcoin`/`send_lightning` and document the internal-only semantics.

---

## 9. What is NOT in this doc

- The enforcement mechanisms themselves (the doc 01/03/05 mitigations, `scale.py`) - referenced.
- The actual edits to docs 01 / 05 / 07, the registry, and the exit-loop - **deferred to §8's
  resolution**, then separate PRs.
- The eCash threat model, mint timing, allowance internals (doc 07), and mint monitoring (doc 10).
- World-facing on-chain privacy (the world-facing doc) and wire formats.
