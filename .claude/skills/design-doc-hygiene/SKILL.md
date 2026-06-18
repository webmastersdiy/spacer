---
name: design-doc-hygiene
description: Keep spacer design docs free of anything a fresh, capable model could derive on its own from the rest of the docs plus the codebase. Trigger whenever writing, editing, or RECONCILING a design doc under design-docs/ (or a doc-like README such as exit-loop/README.md). Docs hold only the non-derivable essence - decisions and their rationale (especially roads-not-taken), constraints, invariants, threat models, and choices that bind future work. Strip or compress restated code, obvious mechanics, standard-pattern explanations, and anything a fresh reader would already conclude. The test, applied per section, asks whether a fresh model given the rest of the docs and the code could derive a passage; if it could, cut the passage or compress it to the non-obvious remainder. Inconclusive findings go under design-docs/findings/, not the numbered set.
---

# Design-doc hygiene (spacer)

Spacer's design docs (`design-docs/`, and doc-like READMEs such as
`exit-loop/README.md`) are written for a capable model with **no prior
context**. But that reader already has the rest of the docs and the entire
codebase in front of it. So a doc must carry only what that reader **cannot**
reconstruct on its own. Everything else is noise that ages, drifts from the
code, and buries the few sentences that actually matter.

## The rule

Keep a design doc free of anything a fresh, capable model could derive from the
other docs plus the code. A doc holds only the **non-derivable essence**:

- **Decisions and their rationale** - above all **roads not taken**. The code
  shows the road taken; only the doc can record why Cashu over Fedimint, why a
  single pinned mint, why P2PK handoff tokens were rejected. A rejected
  alternative leaves no trace in the source, so the doc is its only home.
- **Constraints and invariants that bind future work** - "a HITL approval can
  never widen the blast radius", "`full` must never silently arm ecash". These
  are commitments, not mechanics; a reader cannot infer that they are *promised*
  just by seeing them currently hold.
- **Threat models** - the adversary, what they observe, and *why* a mitigation
  exists. The mitigation is in the code; the threat that justifies it is not.
- **Cross-cutting intent** no single file makes obvious - the AI-facing vs
  world-facing privacy split, the delay-scaling principle.

Strip or compress everything else: code restated as prose, obvious mechanics,
standard-pattern explanations (what a subprocess wrapper, a lazy import, or an
env var "does"), and anything a fresh reader would simply conclude.

## The test

Apply it per section and per paragraph - when writing fresh **and when
reconciling a doc against a build**:

> **"Could a fresh, capable model, given the rest of the docs and the code,
> derive this?"**

- **Yes** -> cut it, or compress to the non-obvious remainder.
- **No** -> it belongs; keep it sharp.

Reconciliation is the high-risk moment. The reflex is to append as-built
mechanics ("landed as a `_run` helper, argv list, no shell, schema registered on
first import..."). Resist it. Fold in only the **delta that surprised you** - a
decision that changed, a property now proven, a gotcha discovered - and compress
the rest. A reconciled doc should get *shorter per fact*, not longer; doc 07 §11
is the model (it records what building *taught*, not what building *did*).

## Keep vs cut, concretely

| Keep (non-derivable) | Cut or compress (derivable) |
|---|---|
| *why* a choice was made; what was rejected and why | *what* the code does, restated in prose |
| constraints, invariants, ordering properties | the step-by-step mechanics that implement them |
| threat model: adversary, observation, motive | re-listing variants / fields / flags already in code or a manifest |
| a fact stated **once**, in its canonical home | the same fact restated in a second doc |

## Examples (real, from this repo)

**1. `exit-loop/README.md` re-derives the op-routing model.** A ~20-line
paragraph restates the whole `SPACER_MODE` op ladder - `query_balance`,
`send_bitcoin`, `poll`, the Lightning ops under `lightning|full`, the eCash
writes under `ecash`, refuse-at-mode-gate, lazy import - every bit of which doc
07 §9 already owns and `gateway.py` implements.

> Before: "The gateway routes inbound requests on a small fixed set of
> recognized ops [...] query_balance (known read [...]), send_bitcoin ([...] the
> standing approvals gate decides default-pause vs dispatch), poll [...] under
> `SPACER_MODE=ecash` the full ladder plus the eCash writes [...]. When an
> extension is disabled its ops refuse uniformly at the mode gate [...]
> `arbiter/src/lnd.py` is never imported in onchain mode [...] the runner
> asserts all of it via the no-lnd-import and no-ecash-import gates."

A fresh reader has doc 07 §9 and the gateway code, so the routing is fully
derivable. The one thing this README *adds* is that the runner **proves** the
import discipline structurally - that is the only sentence worth keeping here.

> After: "The runner replays the doc 07 §9 mode/op routing end-to-end. Two
> structural gates beyond artifact content - no-lnd-import, no-ecash-import -
> assert `lnd.py` / `ecash.py` stay unimported outside their modes, the one
> routing invariant the artifacts cannot show by content alone. Routing model:
> doc 07 §9."

**2. The same coverage facts are stated three times.** The exit-loop variant
inventory lives in the runner manifest (the source of truth), is narrated in
`exit-loop/README.md`, and is narrated *again* in doc 07 §9 ("42 manifest
variants [...] mode-gate refusals for `fund_ecash`/`defund_ecash` against
onchain AND lightning [...] both standing-approvals branches [...]
ladder-regression variants [...]"). Duplication across docs is itself a hygiene
smell: a fact with no single home has three copies that will drift out of sync.
Pick the canonical home (the manifest owns the list; the README narrates it) and
let the design doc assert only what a reader cannot get from the manifest.

> After (doc 07 §9): "Exit loop green at sp-2hwco4.2: both custody halves
> covered, and the §8 allowance-before-approvals *ordering* is proven (not just
> the refusal). Deliberately no fake for the arbiter-side wrapper - no variant
> can reach it, and leaving `CASHU_BIN` / `CASHU_MINT_URL` unset makes a stray
> mint call error loudly instead of being absorbed. Variant inventory: the
> runner manifest + `exit-loop/README`."

The kept sentences are a proven property and a deliberate decision with its
reasons - neither is in the manifest. The cut sentences were a third copy of it.

## Placement and companion rules

- **Inconclusive work goes in `design-docs/findings/`, never in a numbered
  doc.** The numbered `design-docs/` set is for decisions that bind; dead ends,
  unresolved investigations, and open measurements live under `findings/` so the
  binding docs stay free of tentative material. A named *open question* inside a
  decided doc is fine (doc 07 §10) - what does not belong is a whole exploratory
  write-up.
- **Commit docs immediately, with a reason** stating *why* the change was made
  (the `commit-docs-with-reasons` rule is authoritative).
- **Filenames keep their date prefix forever**: `NN--YYYY-MM-DD-HHMM-<slug>.md`
  for design docs (see `design-docs/README.md`), date-prefixed for findings.
  Never rename to drop or change the date (the `notes-conventions` rule).

## Do not over-apply

The test cuts *derivable* text, not *dense* text. Do not strip a rationale just
because it sits beside mechanics - separate them: keep the why, compress the
what. When you genuinely cannot tell whether a reader could derive something,
keep the decision and cut only the restated mechanics around it. The target is a
doc where every sentence earns its place, not a terse doc that lost its
reasoning.
