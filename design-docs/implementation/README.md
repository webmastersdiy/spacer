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
