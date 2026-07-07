# eCash Mint Monitoring and Rotation - Implementation

**Date:** 2026-06-28
**Status:** partially landed - §2 is collapsed to pointers (the build gate landed, sp-xha); §§3-6 are the live pre-build spec and collapse per the [README lifecycle](README.md) as they land
**Context:** The build-time and runtime mechanics for the monitoring and rotation design in
`../origin/10--2026-06-26-1930-ecash-mint-monitoring-and-rotation.md`. Doc 10 is the **design
authority** over eCash mint monitoring and rotation; this spec says *how* to build and run it, and is
authoritative only within those same two areas. Where doc 10 defers, so does this spec: the allowance
ledger -> doc 07 §8; the action / result-delay machinery -> doc 07 §6 / doc 09; world-facing timing ->
the archived node-privacy-from-the-world doc; the operator-visibility TUI -> its own dedicated doc.
**Related:**
- `../origin/10--2026-06-26-1930-ecash-mint-monitoring-and-rotation.md` - the design this reconciles to (signals M1-M6, the Notice/Suspect/Halt ladder §5, the rotation procedure §6). On `main`.
- [`08--2026-06-18-0629-ecash-live-test-mint.md`](../origin/08--2026-06-18-0629-ecash-live-test-mint.md) and its findings companion - the live round-trip that grounds the cashu-CLI behavior this spec pins (the pending-exit-0 melt trap, DLEQ-bearing proofs, fee shape).
- [`06--2026-05-24-0623-arb-auditability.md`](../origin/06--2026-05-24-0623-arb-auditability.md) §3 - the arbiter tree layout (`src/` / `config/` / `ops/` / `state/` / `ecash/`) this spec writes into.
- [`07--2026-06-12-0916-ecash-extension.md`](../origin/07--2026-06-12-0916-ecash-extension.md) - §8 allowance ledger (the authority this spec only posts to), §6 mint-correlation timing channels.
- GLOSSARY: [Action delay](../../GLOSSARY.md#action-delay), [Result delay](../../GLOSSARY.md#result-delay), [Audit log](../../GLOSSARY.md#audit-log)

---

## 1. Scope

This spec covers the build-time and runtime mechanics for doc 10's monitoring signals (§3 / §4), the
signal -> action ladder (§5), and the rotation + self-test procedure (§6). It is authoritative only
over *how* those are implemented. It does **not** restate or extend doc 10's design, and it inherits
every one of doc 10's cross-reference boundaries: the
[allowance ledger](../origin/07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius) is
doc 07 §8's (this spec only names the hooks that post to it), the delay machinery is doc 07 §6 /
doc 09's, world-facing timing is owned by the archived
[node privacy from the world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes, and
the operator-visibility TUI belongs in its own dedicated doc.
Measurement references are signet / Mutinynet / test-mint; no mainnet.

## 2. Build-time contract test (doc 10 §3, §8) - landed

Landed as `arbiter/ops/mint_contract_test.py` (sp-xha), pinned via
`config/cashu-pin.yaml`; **the module docstring is the spec**. Three
layers: parser fixtures (always run), a version pin (`cashu info` must
equal the pinned version, so an unreviewed CLI bump fails the build),
and a live ephemeral FakeWallet nutshell mint driven through the
arbiter's own `ecash.py` - covering the pending-exit-0 melt trap and
DLEQ (presence asserted on send; bit-flipped proofs rejected, the
intact original accepted as the control). Runs on every arbiter build.

## 3. Monitoring runtime (doc 10 §3, §4)

- **State.** A monitoring store under `arbiter/state/` (doc 06 §3 - gitignored, runtime): per-signal
  counters, the shared-window timestamps, last-good keyset / pubkey, and the current tier. It is
  **arbiter-local and never reachable through the gateway** - the AI cannot read mint health or the
  detection thresholds (doc 10 §4, the threshold-leakage leak in §8).
- **Passive capture (M1 / M2 / M4).** Hook the existing fund / defund path: record settled-vs-pending
  melt outcome (M1), DLEQ pass / fail at receive (M2), and the `ln_routing_fee_msat` / `credited_sats`
  deltas (M4) the executor already emits (doc 08 findings §2). No new mint-facing traffic, no new
  correlation surface.
- **Active probing (M3 / M5 / M6).** A scheduler draws the next probe time from a randomized
  distribution - **~30 min mean, full jitter** (doc 10 §9), e.g. an exponential inter-probe interval so
  the cadence carries no metronomic signature (doc 07 §6 T5) - and only while the rail is idle; when the
  rail is already talking to the mint, `/v1/info` is piggybacked on that organic call instead. A
  value-moving canary is built but **disabled by default**, enabled only where M1 cannot be trusted from
  organic traffic (doc 10 §4). The scheduler runs **in the arbiter process** (a jittered timer
  thread), not an external cron: idle-awareness and organic-traffic piggybacking need in-process
  visibility of rail activity and monitoring state, and the whole probe surface then sits in the one
  tree the manual-audit pass reads (doc 05 §2.1). The jitter distribution is the one tunable here; the world-facing
  rationale for why a randomized cadence defeats observation lives in the archived
  node-privacy-from-the-world doc, not restated.

## 4. Signal -> action wiring (doc 10 §5, §9)

- **Thresholds (shared defaults, doc 10 §9).** One shared count `K` (default 3) and one shared window
  `W` (default 24 h) drive M3 / M5 -> Suspect; any pubkey change -> at least Notice. CRITICAL signals
  are **not** thresholded: a confirmed M1 (after the pending-vs-settled check + one bounded retry) or
  **any** M2 -> Halt immediately. `K`, `W`, the probe mean, and the canary-enable flag are the *only*
  monitoring config knobs (doc 10 §9: minimize parameter count); all live in `config/`, default to the
  values above, and are marked empirically-TBD until sp-2hwco4.4.
- **Halt = fail-closed flag.** Halt sets an arbiter-local flag that makes `fund_ecash` refuse uniformly,
  reusing the **same refusal path as the missing-allowance default** (doc 07 §8) so the AI sees one
  indistinguishable "unavailable", never a mint-health oracle.
- **Fast-path drain (doc 10 §5).** The rug-response drain calls the normal defund pipeline with the
  [action delay](../../GLOSSARY.md#action-delay) **bypassed**, to move float before the rug completes.
  What it operates on, stated plainly: the outstanding float is **petitioner-held bearer value**, so
  the arbiter cannot pull it back unilaterally - the fast path covers (a) defunds the petitioner
  submits, and (b) the arbiter's own remnant float (transient custody plus reclaimed melt-reserve
  remainders, doc 11 §7.4). And because mint health is never petitioner-readable (§3), the petitioner
  will not know to defund on its own - prompting it is an **operator act**.
  Petitioner-facing disclosure of the drain still flows through the normal
  [result delay](../../GLOSSARY.md#result-delay) (doc 07 §6 / doc 09): the fast path changes *execution*
  timing, not *disclosure* timing. Only the rug-response path takes the bypass; ordinary defunds keep
  both windows.

## 5. Rotation + self-test (doc 10 §6)

- **Repin.** The operator edits `CASHU_MINT_URL` in `config/` (doc 06 §3 tracks config edits); the
  arbiter picks up the new pin on reload. Never AI-settable.
- **Binary drain.** A single defund pass against the old pin; whatever does not settle in that pass is
  written to the ledger as **stranded** (doc 10 §6, §9) - no retry loop, no time-tiered policy.
- **Self-test before resume.** After repin, run a canary **fund -> melt round-trip** against the new pin
  and require M1-clean settlement *and* M2-clean DLEQ before clearing the fail-closed flag. Pass ->
  serve the petitioner; fail -> stay Halted on the new pin and alert the operator (the rotation landed
  on another bad mint). Funding never resumes on the bare repin (doc 10 §6 step 4). The self-test is
  **arbiter/operator-initiated and never petitioner-triggerable**, and it runs while Halt is still
  set - the flag gates the *petitioner-facing* `fund_ecash`, not this internal path (otherwise the
  test that clears the flag could never run). Its canary fund/defund post to the allowance ledger
  like any other executed ops.
- **Accounting hooks.** Drain outcome (settled vs stranded), the stranded write-off, and melt / routing
  fees post to the
  [allowance ledger](../origin/07--2026-06-12-0916-ecash-extension.md#8-allowance-and-blast-radius);
  **the ledger schema and semantics are doc 07 §8's** - this spec only names the post points.
  Petitioner disclosure of any balance change is the privacy-safe subset, released on the result-delay
  schedule (doc 07 §6 / doc 09).

## 6. Test surface

- **Build-time:** the two contract assertions of §2, run on every build.
- **Exit-loop / integration** (signet / Mutinynet / test-mint, per doc 08; no mainnet): a forced M1
  (melt left pending) trips Halt + a uniformly-refusing `fund_ecash`; a corrupted-DLEQ proof trips M2;
  a repin + passing self-test clears Halt; a repin + failing self-test stays Halted. These variants
  need an arbiter-side mint that misbehaves on demand - which collides with the recorded
  no-arbiter-side-cashu-fake stance (doc 05 §10 / doc 07 §9), whose rationale ("no variant can reach
  the wrapper") is obsolete now that the executor runs. Resolution: reuse the §2 ephemeral FakeWallet
  mint harness (pending-forever backend, corrupted-DLEQ tokens) as the misbehaving mint, and amend the
  stance sentence in docs 05 / 07 when these variants land.
- **Privacy:** assert monitoring state is unreachable through the gateway - no response field exposes
  tier, counts, or keyset health to the AI.

## 7. Reconciliation boundary

This spec stops where doc 10 stops. It does **not** define: the allowance-ledger schema (doc 07 §8),
the action / result-delay windows (doc 07 §6 / doc 09), the world-facing-timing rationale (the archived
node-privacy-from-the-world doc), or the operator-visibility TUI (its own dedicated doc). If any of those needs a change to support monitoring /
rotation, that change is filed against the owning doc, not added here.
