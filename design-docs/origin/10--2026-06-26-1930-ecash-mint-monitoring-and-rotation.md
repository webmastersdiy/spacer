# eCash Mint Monitoring and Rotation

**Date:** 2026-06-26
**Status:** DRAFT (design-first; no implementation implied)
**Context:** Resolves the open question in
[`07--2026-06-12-0916-ecash-extension.md` §10.5](07--2026-06-12-0916-ecash-extension.md#10-open-questions)
("Mint monitoring and rotation"): what solvency or behavior signals should trigger
defund-and-rotate to a new mint, and whether rotation re-raises the multi-mint question that
doc 07 §2 deliberately rejected. Builds on the single-pinned-mint posture, the mint threat model,
and the allowance blast-radius bound already established in doc 07.
**Related:**
- [`07--2026-06-12-0916-ecash-extension.md`](07--2026-06-12-0916-ecash-extension.md) - §2 single-mint choice (the rule rotation must not break), §4 threat model (the mint as adversary), §6 mint-correlation timing channels, §8 allowance / blast radius (the bound that makes a bad mint survivable), §10.5 (this doc's charter)
- [`08--2026-06-18-0629-ecash-live-test-mint.md`](08--2026-06-18-0629-ecash-live-test-mint.md) and its findings companion - the live round-trip that grounds the observable signals (pending-vs-settled melt, DLEQ-bearing proofs, fee shape, version/pubkey/keyset capture)
- GLOSSARY: [Action delay](../../GLOSSARY.md#action-delay), [Result delay](../../GLOSSARY.md#result-delay), [Audit log](../../GLOSSARY.md#audit-log)

---

## 1. Purpose and scope

The eCash rail pins exactly one mint per deployment (doc 07 §2), operator-chosen, never
AI-suppliable, and prices total mint failure into the [allowance](07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius)
(§8: blast radius = outstanding float). What it lacks is the **operational safety net**: a way to
*notice* a mint going bad and a defined *procedure* to move off it. This doc supplies both.

**In scope:** the arbiter-side signals that indicate mint failure / compromise / degradation, the
signal -> action ladder, and the operator-driven rotation procedure. **Out of scope:** steady-state
multi-mint (rejected in doc 07 §2 - this doc keeps it rejected and shows rotation does not
reintroduce it, §8); the single-mint rationale, threat model, and allowance themselves (doc 07);
world-facing observers. Adversary is the mint (doc 07 §4), plus the AI insofar as it might try to
*induce* rotation churn (§9). Measurement references are signet / Mutinynet / test-mint; no mainnet.

---

## 2. What a bad mint does (the failure modes to detect)

The mint is modeled as an external adversary (doc 07 §4); the allowance bounds the *loss*, but only
if we *react*. The failure modes, worst first:

| Mode | What the mint does | Why it matters | Bounded by |
|---|---|---|---|
| **Rug / insolvency** | stops honoring melts - proofs no longer redeem to LN | the float cannot be drained; outstanding becomes a realized loss | allowance (§8); detection speed limits how much new float is added first |
| **Equivocation** | issues proofs that fail DLEQ; double-issues against a keyset | the float is counterfeit / unprovable; value is illusory | DLEQ verification at receive (doc 07 §2); detection halts further funding |
| **Censorship / freeze** | selectively refuses *our* quotes/melts while serving others | targeted denial; may precede a rug | allowance + rotation |
| **Economic degradation** | introduces or raises input/melt fees | the float bleeds on every cycle; funded != credited widens | allowance; operator cost visibility (doc 07 §10.4) |
| **Instability** | erratic keyset rotation, version churn, intermittent downtime | shrinks the anonymity set toward 1 (doc 07 §6 T6); breaks ops | mint choice (§2); rotation |

Detection turns each into "halt funding + drain what we can + alert the operator to rotate" before
the allowance is fully spent.

---

## 3. Monitoring signals

Grounded in the live round-trip (doc 08 findings): the mint is exercised on every fund/defund, so
most signals come **free, in-band**, with no new mint-facing footprint.

| # | Signal | Indicates | Source | Severity |
|---|---|---|---|---|
| M1 | **Melt fails to settle** (the "pending exit-0" trap: `cashu pay` returns 0 while the LN payment is only pending; real settlement needs the "Invoice paid"/preimage line) | rug / insolvency / freeze | passive - every defund already checks this (findings §1.2) | **CRITICAL** |
| M2 | **DLEQ verification failure** on received proofs | equivocation / counterfeit float | passive - verification is on by default for DLEQ-bearing tokens (findings §1; doc 07 §2) | **CRITICAL** |
| M3 | **Quote / mint-leg failure or timeout** (quote refused, blinded-output submission errors, mint unreachable) | freeze / downtime / liveness | passive (during fund) + optional active probe (§4) | HIGH |
| M4 | **Fee drift** - input fee appears where there was none, or the melt-reserve overrun grows beyond the conservative pre-estimate | economic degradation | passive - executor already records `ln_routing_fee_msat` / `credited_sats` (findings §2) | MED |
| M5 | **Keyset / pubkey rotation cadence anomaly** (rotation faster than a configured expectation; pubkey change) | instability; anonymity-set collapse (doc 07 §6 T6) | active - `cashu info` / `/v1/info`, already captured per run (findings §6) | MED |
| M6 | **Version churn** | informational; pairs with M5 to read mint operational health | active - `/v1/info` | LOW |

What we **cannot** directly observe: mint solvency/reserves. `/v1/info` exposes no balance or
traffic data (doc 07 §10.1). Solvency is inferred only *indirectly* from M1 (a solvent mint honors
melts; repeated melt failure is the solvency proxy). This doc does not pretend to a direct solvency
oracle a bearer-ecash mint does not provide.

---

## 4. Where monitoring runs (and the probe-as-fingerprint tension)

- **Passive (in-band) is primary.** M1/M2/M4 ride the fund/defund ops the rail already performs;
  the arbiter records outcomes (settled vs pending, DLEQ pass/fail, fees, latency) into arbiter-local
  state and the [audit log](../../GLOSSARY.md#audit-log). No new mint-facing traffic, so no new
  correlation surface.
- **Active probes (M3/M5/M6) are the tension.** A periodic `/v1/info` poll or a tiny melt "canary"
  gives liveness/keyset signal when the rail is idle - but a *fixed* probe cadence is itself a
  mint-observable fingerprint (doc 07 §6 T5: metronomic calls mark automation) and, for a canary, a
  recurring micro-transaction pattern. Constraints if active probing is used: **jittered** (not
  metronomic), **minimal** (info-only by default; a value-moving canary only if M1 cannot be trusted
  from organic traffic), and **indistinguishable** from an organic op where possible. Default lean:
  **passive-only**, with `/v1/info` checks piggybacked on the times the rail is already talking to
  the mint, and active canaries left as an operator-enabled option for idle deployments.

Monitoring state (counts, thresholds, last-good keyset) is **arbiter-local and never AI-readable**,
same posture as the audit log - otherwise the AI learns the mint's health and the detection
thresholds, and can shape behavior to stay just under them.

---

## 5. The signal -> action ladder

The arbiter acts **autonomously up to the fail-closed line**; it never chooses a mint.

| Tier | Triggers | Automatic arbiter action | Operator action |
|---|---|---|---|
| **Notice** | M4 fee drift, M6 version bump, mild M3 latency | audit-log + console surface; no behavior change | review; no action required |
| **Suspect** | repeated M3, M5 cadence anomaly, isolated M1/M2 | **raise alert severity**; optionally throttle the effective funding rate (slow the bleed) | decide whether to rotate |
| **Halt** | confirmed M1 (melt non-settlement) or any M2 (DLEQ failure) past threshold | **fail closed: refuse new `fund_ecash`** (uniform refusal, audit-logged - same shape as the missing-allowance default in doc 07 §8); **attempt to drain** existing float while the mint still melts | rotate (§6) |

Key invariants:
- The arbiter may **halt funding** and **attempt drain** on its own (fail-closed is safe - it only
  *stops* adding exposure and tries to *reduce* it). It may **not auto-rotate**: choosing the next
  mint is an operator-only act (doc 07 §2 - an automatically- or AI-chosen mint is a colluding
  counterparty / exfiltration channel).
- "Attempt to drain" reuses the normal defund pipeline and its standard
  [action/result delay](../../GLOSSARY.md#action-delay) windows; a rugging mint simply fails the
  melts (M1), which the operator already sees - no special fast-path that would itself be a signal.

---

## 6. The rotation procedure (operator-driven, sequential single-pin)

Rotation is a **drain-then-repin handover**, never a concurrent two-mint state:

1. **Choose** a new mint off-band by the doc 07 §2 criteria (busy, public, unaffiliated). Never the
   AI; never a default.
2. **Drain** the float from the old mint: defund outstanding back to LN to the extent the old mint
   still honors melts. The [allowance ledger](07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius)
   tracks `outstanding` down toward 0.
3. **Repin**: change `CASHU_MINT_URL` to the new mint - a console config edit, the same operator
   gesture as editing the allowance or the recipient registry. Funding resumes against the new mint
   only after the repin.

**Stranded float** (old mint rugged, cannot be drained): abandoned, an allowance-bounded loss (no
clawback - doc 07 §8: bearer means bearer). Repin proceeds; the stranded value was already written
off by the petty-cash allowance framing. The arbiter does not block rotation waiting on a mint that
will never pay.

---

## 7. Does rotation re-raise the multi-mint question? (doc 07 §10.5)

**No.** Doc 07 §2 rejected *steady-state* multi-mint: N mints running simultaneously means N
correlating adversaries, every timing mitigation must hold at all N, and the arbiter grows code for
all N. Rotation creates none of that:

- It is **sequential**: drain the old pin toward 0 (or write it off), *then* repin and fund the new
  one. At most one mint is ever the funded pin.
- The timing mitigations (doc 07 §6, doc 09) only ever face **one** mint at a time - the winding-down
  old one is the same single-mint posture, just shrinking.
- There is no steady state with two live floats by design; the handover is momentary and
  operator-gated.

So rotation is compatible with the single-mint invariant. Caveat worth stating: if drains routinely
strand float and force rapid re-pins, that *churn rate is itself a signal* that the mint-choice
criteria (§2) or the allowance sizing (§8) need revisiting - it is not an argument to relax §2 into
running multiple mints.

---

## 8. Threat model and residual leaks

- **Probe-as-fingerprint** (§4): active monitoring is a mint-observable cadence. Mitigated by
  passive-first + jitter; never fully closed if active canaries run. Prefer passive.
- **AI-induced rotation churn (DoS):** the AI could try to provoke alerts (e.g. patterns that look
  like M-signals) to force costly rotations. Bounded three ways: the AI's float ops are
  allowance-capped; it cannot itself rotate (operator-gated); and the costly signals (M1/M2) are
  *mint* behaviors the AI cannot forge through the gateway. AI-side noise reaches at most the
  "Suspect" tier, which requires an operator to act.
- **DLEQ-detection dependency:** M2 relies on the wallet (nutshell) verifying DLEQ at receive. If
  that verification regresses, equivocation goes undetected. The dependency is load-bearing and
  should be asserted in the rail's own checks, not assumed.
- **Threshold leakage:** if monitoring state or thresholds become AI-readable, the AI (or a
  colluding mint) tunes behavior to stay just under them. Keep monitoring state arbiter-local (§4).
- **Detection latency vs allowance:** the loss on a rug is (new float funded between the mint going
  bad and Halt firing). Faster M1 detection shrinks it; the allowance caps the absolute worst case
  regardless. The two compose - neither alone is the whole defense.

---

## 9. Open questions

1. **Concrete thresholds.** How many M1 non-settlements, what M2 count, what M3 rate, what M5 cadence
   delta move a mint Notice -> Suspect -> Halt. Needs live-mint data; gated on sp-2hwco4.4 (live test
   env, operator-assisted).
2. **Active-probe design vs passive-only.** Whether idle deployments run a canary at all, and if so
   its size, cadence distribution, and jitter - the §4 fingerprint tension. Default proposal:
   passive-only + piggybacked `/v1/info`.
3. **Throttle-before-halt.** Whether the "Suspect" tier should auto-lower the *effective* allowance
   (slow the bleed) before a full funding halt, and how that interacts with the §8 hard cap.
4. **Operator alerting channel.** How alerts surface (audit-log severity, console banner, out-of-band
   notify) so the operator actually sees a Halt promptly - detection is worthless if unread.
5. **Drain-time policy under a partial rug.** If the old mint honors *some* melts slowly, how long to
   keep draining before declaring the remainder stranded and repinning.

---

## 10. What is NOT in this doc

- The single-mint choice and its rationale (doc 07 §2), the mint threat model (doc 07 §4), and the
  allowance / blast-radius bound (doc 07 §8) - referenced, not restated.
- The mint-correlation timing channels (doc 07 §6) and the per-rail timing windows (doc 09).
- Concrete fee-accounting surface (doc 07 §10.4) and checkstate-cadence jitter (doc 07 §10.7),
  except where a fee change is a monitoring signal (M4).
- Wire formats, `petcli` / executor code structure, and the exact `/v1/info` schema.
- World-facing observers of the mint (chain/LN correlation of the mint's own activity).
