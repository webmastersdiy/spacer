# Design docs - implementation specs

Implementation specifications that reconcile a design doc in
[`origin/`](../origin/README.md) to concrete build-time and runtime
mechanics. Each spec is authoritative only over **how** to implement its
parent design doc, and only **within that doc's authoritative scope** - it
never extends or overrides the design, and it inherits every one of the
parent's cross-reference boundaries.

This mirrors the [`findings/`](../findings) split: `origin/` holds the
design, `findings/` holds empirical results, and `implementation/` holds
the mechanics that realize the design. Keeping them apart lets `origin/`
stay design-first while the "how" lives somewhere a reviewer can read it
without wading through design rationale.

Same [filename convention](../README.md) as the rest of `design-docs/`:
`NN--YYYY-MM-DD-HHMM-<name>.md`, the index chronological within this
directory.

## Lifecycle: specs collapse when the code lands

An implementation spec is a **pre-build artifact**: it exists so the
mechanics can be designed and reviewed before they are code. Once the
mechanics land, the code is the authority (inline-documented per the
arbiter discipline, architecture overview §2.1), and the spec
**collapses**: the implemented sections are replaced by a summary of at
most ~100 words plus pointers to the code that now carries the
mechanics. Leave no residue - no "alternatives considered", no
superseded mechanics; anything still load-bearing belongs in the owning
design doc, not here. Partial landings collapse section by section; a
spec whose every section has landed shrinks to its title, the ~100-word
summary, and the pointers.
