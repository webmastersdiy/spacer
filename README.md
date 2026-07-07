# Spacer

Spacer lets an AI client drive a Bitcoin node without learning more
about the operator's wallet, balances, or identifiers than the task
requires. It is two processes joined by a protocol, and the protocol
is the trust boundary:

- the **petitioner** - client-side, runs in the AI's own environment,
  holds no secrets; exposes one CLI (`petcli`) the AI drives.
- the **arbiter** - server-side, out of the AI's reach; bundles the
  privacy gateway, the bitcoind/LND/mint client access, local state,
  the append-only audit log, and the timing layer.

The value model in one line: **BTC and Lightning are internal fund
management only; all external value movement is eCash** - a
mint-backed bearer float the AI spends directly, hard-capped by an
operator allowance. (The foundational-posture doc, doc 12, states why.)

## The rail ladder

`SPACER_MODE` selects the op surface; each rail is an explicit opt-in
on top of the one below it:

| Mode | Surface | Role |
|---|---|---|
| `onchain` (default) | bitcoind only | internal management |
| `lightning` | + LND | internal management |
| `ecash` | + Cashu mint | the sole external-value rail |

**No mainnet yet.** Spacer is developed and live-tested entirely on
signet / Mutinynet / test-mint, and the registry refuses mainnet
addresses at add time - a development-phase gate, lifted only by a
deliberate future decision.

## Repository map

```
arbiter/          server side. src/ config/ bin/ ops/ are tracked;
                  state/ bitcoin/ lnd/ ecash/ data/ are gitignored
                  runtime (the doc 06 snapshot-audit split)
petitioner/       client side: petcli, the protocol shim
test-harness/     testbed wrappers, the exit-loop runner
exit-loop/        preserved end-to-end artifacts, one dir per variant
design-docs/      origin/ (design) · findings/ (empirical residue)
                  · implementation/ (build mechanics)
archive/          world-facing privacy notes and other retired docs
GLOSSARY.md       project vocabulary; naming disputes resolve here
```

## Reading order (for a human reviewer)

1. `GLOSSARY.md` - the project axes (AI-facing vs world-facing,
   arbiter vs petitioner) and the mitigation vocabulary.
2. Doc 05 - architecture overview: components, data flow, modes.
3. Doc 12 - the foundational privacy posture (G1 endpoint privacy,
   G2 amount-scale privacy, the eCash exception).
4. Docs 01 / 03 - the per-call leak maps (LND / bitcoind).
5. Docs 07 / 08 - the eCash extension and its live-mint validation.
6. Docs 09 / 10 / 11 / 13 / 14 - timing windows, mint monitoring,
   fee accounting, the operator TUI, LN availability probing.

The per-doc index with one-line summaries and the authority map is
`design-docs/origin/README.md`.

## Status

Design-first, with the skeleton landed and exercised: privacy gateway,
recipient registry (YAML), standing approvals, eCash allowance, timing
layer (test mode), and the write executor are wired; the exit loop (42
variants + 2 import gates) is green, and a live eCash fund/defund
round-trip ran against `cashu.mutinynet.com`. Production timing
windows and scale-cloak production mode are deliberately
`NotImplementedError`-gated until the dynamic-window design (doc 09)
lands - the safe failure mode is "does not run."
