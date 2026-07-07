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

**Authority and cross-references (read first).** This doc is authoritative **only over eCash mint
monitoring and rotation**. Everything it touches outside those two areas it **cross-references, never
overrides**:

- the [allowance ledger](07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius) and the
  blast-radius bound -> **doc 07 §8** (the authority; this doc records *what* monitoring / rotation
  cost against it, not how the ledger works);
- the action / result-delay machinery and the per-rail timing windows -> **doc 07 §6 / doc 09**;
- world-facing timing of the mint's own activity (the mint is part of "the world") -> the archived
  [node privacy from the world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes
  (this doc owns only the *probe cadence* it originates, §4, and defers the rationale);
- the single-mint choice, the mint threat model, and the allowance itself -> **doc 07** (§2 / §4 / §8).

The operator-alerting **TUI is a general arbiter-visibility surface, not eCash-specific**, so its
authoritative design lives in its own doc, not here (§9, "Operator alerting"); this doc only states
that monitoring and rotation alerts surface there. Implementation nuances (parsing contracts, probe
mechanics, rotation / self-test wiring) live in the companion implementation doc, which reconciles to
this one within monitoring + rotation only (§10).

---

## 2. What a bad mint does (the failure modes to detect)

The mint is modeled as an external adversary (doc 07 §4); the allowance bounds the *loss*, but only
if we *react*. The failure modes, worst first:

| Mode | What the mint does | Why it matters | Bounded by |
|---|---|---|---|
| **Rug / insolvency** | stops honoring melts - proofs no longer redeem to LN | the float cannot be drained; outstanding becomes a realized loss | allowance (§8); detection speed limits how much new float is added first |
| **Equivocation / per-client tagging** | issues proofs that fail DLEQ, or signs *per client* to tag tokens (the one cryptographic way to defeat blinding) | the float is counterfeit / unprovable, or our tokens become linkable to us | **DLEQ verification (NUT-12) at receive (doc 07 §2) - signal M2**; detection halts further funding (DLEQ proves each proof is well-formed against the keyset) |
| **Over-issuance / insolvency** | signs *more* tokens than its reserves back (each individually DLEQ-valid), or double-issues against a keyset | the float is unbacked; melts fail once the unbacked float is presented - a **solvency** failure DLEQ cannot see | **M1 (melt non-settlement), not DLEQ-bounded**; allowance caps the loss (§8). Surfaces like a rug (row 1), since a solvent mint honors melts and an over-issued one cannot |
| **Censorship / freeze** (metadata-only) | selectively refuses *our* melts/quotes - targeted **only via metadata**, chiefly the defund/melt bolt11 that names our LND node (doc 07 §5.1) + caller IP/timing; **not** via the tokens (BDHKE blinding makes them unlinkable - see the note below) | targeted denial; may precede a rug | allowance + rotation; defund hygiene (doc 07 §6 T4) |
| **Economic degradation** | introduces or raises input/melt fees | the float bleeds on every cycle; funded != credited widens | allowance; operator cost visibility (doc 07 §10.4) |
| **Instability** | erratic keyset rotation, version churn, intermittent downtime | shrinks the anonymity set toward 1 (doc 07 §6 T6); breaks ops | mint choice (§2); rotation |

Detection turns each into "halt funding + drain what we can + alert the operator to rotate" before
the allowance is fully spent.

**No token-level censorship; rug and censorship collapse to one response.** Two clarifications the
rows above rest on (verified against the NUT specs and doc 07):

- *Censorship is metadata-only, never token-level.* In Chaumian eCash the mint **cannot** censor a
  specific holder through the tokens: BDHKE blinding makes issuance and redemption cryptographically
  unlinkable (doc 07 §2), so the mint cannot tell whose proofs it is seeing. This holds **because
  DLEQ verification (NUT-12) is mandatory** (doc 07 §2; signal M2) - without it a malicious mint
  could sign per-client and tag tokens, the one way to defeat blinding, which is exactly what M2
  catches. Our tokens are plain bearer - no NUT-11 P2PK lock (rejected in doc 07 §10.3) - so there
  is no pubkey for the mint to single out either; and a mint can refuse a whole *keyset*, but that
  hits every holder, not us. The only targeted vector left is **metadata**: the melt bolt11 names
  our LND node (doc 07 §5.1 - "defund is the only op that names our node to the mint") plus caller
  IP / timing, already blunted by keeping defunds infrequent, amount- and window-randomized
  (doc 07 §6 T4).
- *Rug and targeted censorship are indistinguishable to us, and share one response.* They are
  distinct **causes**, but from our vantage they collapse: both surface as **M1** (our melts fail to
  settle), we **cannot** observe whether the mint still serves others (mint traffic is not
  observable, doc 07 §10.1), and both trigger the **same** action (halt + drain + rotate, §5). So
  the rows stay separate (the cause differs) while the operational treatment is unified. We cannot
  confirm targeting - we observe only that *our* melts fail.

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

**Parsing contract (build-time, not runtime).** M1 depends on parsing the cashu CLI's stdout - the
"Invoice paid" / preimage line that distinguishes a settled melt from the pending-exit-0 trap - and
M2 depends on DLEQ verification being **on** in the wallet. Both are silent-failure surfaces: a CLI
output-format change breaks M1's parse, and a DLEQ-verification regression blinds M2, with no runtime
error in either case. This doc therefore **requires a build-time contract test**: the arbiter build
compiles the pinned cashu CLI and asserts (a) it still emits the exact strings M1 parses and (b) DLEQ
verification is enabled (the §8 keystone). Drift or a DLEQ regression then fails the **build**, not
M1 / M2 silently at runtime. The test *mechanics* live in the implementation doc (§10); the
*requirement* is load-bearing design and lives here.

---

## 4. Where monitoring runs (passive in-band + randomized active probing)

- **Passive (in-band) is primary.** M1/M2/M4 ride the fund/defund ops the rail already performs;
  the arbiter records outcomes (settled vs pending, DLEQ pass/fail, fees, latency) into arbiter-local
  state and the [audit log](../../GLOSSARY.md#audit-log). No new mint-facing traffic, so no new
  correlation surface.
- **Active probes (M3/M5/M6): periodic, with randomized timing.** A periodic `/v1/info` poll (or, only
  where M1 cannot be trusted from organic traffic, a tiny melt "canary") gives liveness / keyset signal
  when the rail is idle. A *fixed* cadence would itself be a mint-observable fingerprint (doc 07 §6 T5:
  metronomic calls mark automation), so probing is **periodic but randomized**: **jittered** (not
  metronomic), **minimal** (info-only by default; a value-moving canary only if M1 cannot be trusted
  from organic traffic), and piggybacked on organic mint traffic whenever the rail is already active.
  **This doc owns the probe cadence** (monitoring originates it); the broader rationale and mechanics of
  randomized *world-facing* timing - the mint is part of "the world" - live in the archived
  [node privacy from the world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes,
  cross-referenced here, not restated. This resolves the earlier passive-vs-active question (§9) in favor of **active
  periodic monitoring**.

Monitoring state (counts, thresholds, last-good keyset) is **arbiter-local and never AI-readable**,
same posture as the audit log - otherwise the AI learns the mint's health and the detection
thresholds, and can shape behavior to stay just under them.

---

## 5. The signal -> action ladder

The arbiter acts **autonomously up to the fail-closed line**; it never chooses a mint.

| Tier | Triggers | Automatic arbiter action | Operator action |
|---|---|---|---|
| **Notice** | M4 fee drift, M6 version bump, mild M3 latency | audit-log + console surface; no behavior change | review; no action required |
| **Suspect** | repeated M3, M5 cadence anomaly | **raise alert severity**; *optionally* throttle the effective funding rate (slow the bleed - the throttle-before-halt policy is still open, §9) | decide whether to rotate |
| **Halt** | confirmed M1 (melt non-settlement, after the pending-vs-settled check + one bounded retry) or **any** M2 (DLEQ failure) - CRITICAL, no tunable threshold (§9) | **fail closed: refuse new `fund_ecash`** (uniform refusal, audit-logged - same shape as the missing-allowance default in doc 07 §8); **attempt to drain** existing float on a fast path (skip the action-delay; see invariants) while the mint still melts | rotate (§6) |

Key invariants:
- The arbiter may **halt funding** and **attempt drain** on its own (fail-closed is safe - it only
  *stops* adding exposure and tries to *reduce* it). It may **not auto-rotate**: choosing the next
  mint is an operator-only act (doc 07 §2 - an automatically- or AI-chosen mint is a colluding
  counterparty / exfiltration channel).
- **Emergency drain runs on a fast path.** On a confirmed rug (Halt), the drain **skips the standard
  [action delay](../../GLOSSARY.md#action-delay)** and moves the float as fast as the defund pipeline
  allows - the goal is to recover value *before the mint completes the rug*. This does **not** weaken
  AI-facing privacy: privacy is preserved at the **disclosure** layer, not by throttling execution.
  What the petitioner learns about the drain (that it happened, its result) is **deferred and released
  only when safe**, on the normal [result delay](../../GLOSSARY.md#result-delay) schedule (doc 07 §6 /
  doc 09 own that machinery; this doc defers to it). **Mint-facing** cadence privacy is moot mid-rug -
  the mint is the adversary already rugging, so hiding our drain cadence from it buys nothing. (Normal,
  non-emergency defunds keep the standard action / result-delay windows; the fast path is the
  rug-response exception only.)

---

## 6. The rotation procedure (operator-driven, sequential single-pin)

Rotation is a **drain-then-repin handover**, never a concurrent two-mint state:

1. **Choose** a new mint off-band by the doc 07 §2 criteria (busy, public, unaffiliated). Never the
   AI; never a default.
2. **Drain** the float from the old mint - **a single binary pass**: defund outstanding back to LN to
   the extent the old mint honors melts *in that pass*; whatever it does not honor is declared
   **stranded** then and there (run / no-run, no graduated or time-tiered drain policy - see §9). If
   the drain is rug-triggered it runs on the §5 fast path. The
   [allowance ledger](07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius) (doc 07 §8,
   the authority) tracks `outstanding` down toward 0.
3. **Repin**: change `CASHU_MINT_URL` to the new mint - a console config edit, the same operator
   gesture as editing the allowance or the recipient registry.
4. **Self-test before resume.** Before the rail serves the petitioner against the new pin, run a
   **mint -> melt round-trip self-test**: a small canary fund + defund that must settle (M1 clean) and
   verify DLEQ (M2 clean). **Pass -> resume** funding and serving; **fail -> do not resume** - Halt on
   the new pin and alert the operator, because the rotation landed on another bad mint. This closes the
   rotate-into-another-bad-mint gap: funding resumes only after a passing self-test, never on the bare
   repin.

**Stranded float** (old mint rugged, cannot be drained): abandoned, an allowance-bounded loss (no
clawback - doc 07 §8: bearer means bearer). Repin proceeds; the stranded value was already written
off by the petty-cash allowance framing. The arbiter does not block rotation waiting on a mint that
will never pay.

**Accounting across monitoring and rotation.** Monitoring and rotation must keep value **accounted
across their own stages** - the drain outcome (settled vs stranded), the stranded-float write-off, the
repin, and any melt / routing fees - so the
[allowance ledger](07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius) reflects
reality after a rotation. The **ledger itself is doc 07 §8's authority**; this doc records only *what*
monitoring / rotation post to it, not how it works. Changes are communicated to the petitioner as
**only the privacy-safe subset**, and **only when safe to disclose** - the disclosure-timing mechanics
are doc 07 §6 / doc 09's (result delay), cross-referenced here, not redefined.

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

- **Probe-as-fingerprint** (§4): active periodic probing is a mint-observable cadence. Mitigated by
  **randomized (jittered) timing**, keeping probes minimal (info-only by default), and piggybacking on
  organic traffic; never fully closed while active canaries run. The residual is accepted as the cost
  of monitoring an otherwise-idle mint (the world-facing-timing rationale lives in the archived
  [node privacy from the world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes).
- **AI-induced rotation churn (DoS):** the AI could try to provoke alerts (e.g. patterns that look
  like M-signals) to force costly rotations. Bounded three ways: the AI's float ops are
  allowance-capped; it cannot itself rotate (operator-gated); and the costly signals (M1/M2) are
  *mint* behaviors the AI cannot forge through the gateway. AI-side noise reaches at most the
  "Suspect" tier, which requires an operator to act.
- **DLEQ-detection dependency:** M2 relies on the wallet (nutshell) verifying DLEQ at receive. If
  that verification regresses, equivocation goes undetected. This dependency is load-bearing, so it is
  **asserted at build time, not assumed** - the build-time contract test (§3) fails the build if DLEQ
  verification is off, the same gate that pins M1's stdout-parsing contract. (Mechanics: impl doc, §10.)
- **Threshold leakage:** if monitoring state or thresholds become AI-readable, the AI (or a
  colluding mint) tunes behavior to stay just under them. Keep monitoring state arbiter-local (§4).
- **Detection latency vs allowance:** the loss on a rug is (new float funded between the mint going
  bad and Halt firing). Faster M1 detection shrinks it; the allowance caps the absolute worst case
  regardless. The two compose - neither alone is the whole defense.

---

## 9. Decisions and open questions

Most questions this doc opened are now resolved; provisional defaults are set where live data is still
owed, and one item stays genuinely open.

**Resolved.**

- **Monitoring mode (was the active-vs-passive question): active.** Periodic, randomized probing is the
  default (§4), not passive-only. Removed from the open list.
- **Operator alerting: the two-column TUI.** Alerts surface in an operator TUI with two side-by-side,
  **color-coded columns** - column 1, events the petitioner **already knows**; column 2, things the
  petitioner **must never learn**. The split keeps the operator's at-a-glance view from ever leaking a
  column-2 item into anything petitioner-facing. **Scope:** this TUI is a **general arbiter-visibility
  surface, not eCash-specific**, so its authoritative design does **not** belong here - it belongs in
  **its own dedicated doc** (a follow-up). This doc states only that monitoring / rotation alerts
  surface there, tagged petitioner-known vs petitioner-never-known; the concrete cross-ref lands once
  that doc does.
- **Partial-rug drain: binary.** If the old mint honors only some melts, the policy is a simple
  **run / no-run**: drain in one pass (§6 step 2), then declare the remainder **stranded**. No
  graduated, time-tiered draining for now.

**Provisional (defaults set now; empirically-TBD, confirmed at sp-2hwco4.4 live test).**

Favor a **small number of shared defaults**; keep the configurable-parameter count minimal
(configurable only where genuinely needed):

- **CRITICAL signals halt immediately, no tunable.** A confirmed M1 (melt non-settlement, *after* the
  mandatory pending-vs-settled check plus one bounded retry) or **any** M2 (DLEQ failure) -> **Halt**.
  The cost of a false Halt is low (fail-closed only *stops* funding; the operator can clear or rotate),
  so these need no threshold knob.
- **Non-critical signals share one count and one window.** M3 (quote / mint-leg failure) and M5 (keyset
  cadence anomaly) -> **Suspect** after a shared default of **K = 3** occurrences within a shared window
  **W = 24 h** (plus: any pubkey change -> at least Notice). One `K`, one `W`, reused across signals
  rather than a per-signal matrix.
- **Active-probe cadence (§4).** One knob: a randomized interval with a **~30 min mean, full jitter**,
  only while the rail is idle. Exact distribution deferred to the live mint.

All numbers above are provisional and marked empirically-TBD; they are confirmed / tuned against live
data at sp-2hwco4.4.

**Open.**

- **Throttle-before-halt.** Whether the **Suspect** tier should auto-lower the *effective* allowance
  (slow the bleed) before a full funding Halt, and how that composes with the §8 hard cap.
  **Deferred - TBD after more testing and live experience.**

---

## 10. Scope boundaries and the implementation companion

This doc is **design**, authoritative only over monitoring and rotation. The **mechanics** that
implement it live in the companion implementation doc
(`design-docs/implementation/00--2026-06-28-0944-ecash-mint-monitoring-rotation-impl.md`), which
reconciles to this doc **within monitoring + rotation only** - the build-time contract test (§3), the
active-probe jitter / canary mechanics (§4), the signal -> action wiring and where monitoring state
lives (§4 / §5), and the rotation + self-test round-trip wiring (§6).

Owned by other docs, referenced and not restated here:

- The single-mint choice and its rationale (doc 07 §2), the mint threat model (doc 07 §4), and the
  **allowance ledger / blast-radius bound (doc 07 §8, the authority)** - this doc records *what*
  monitoring / rotation post to the ledger (§6 accounting), not how the ledger works.
- The mint-correlation timing channels (doc 07 §6) and the per-rail timing windows (doc 09), including
  the result-delay schedule this doc defers disclosure to (§5 / §6).
- The **world-facing-timing rationale** - the mint is part of "the world"; it lives in the archived
  [node privacy from the world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes,
  cross-referenced from §4. This doc owns only the *probe cadence* it originates (§4), rather than
  scoping world-facing timing fully out.
- The **operator-visibility TUI** (the two-column surface, §9) - a general arbiter feature, its own
  dedicated doc (a follow-up), not this one.
- Concrete fee-accounting surface (doc 07 §10.4) and checkstate-cadence jitter (doc 07 §10.7), except
  where a fee change is a monitoring signal (M4).
- Wire formats, `petcli` / executor code structure, and the exact `/v1/info` schema - all in the
  implementation doc.
