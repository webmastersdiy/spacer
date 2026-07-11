# Design docs - origin set

The founding spacer design docs: the set that established the
architecture, the threat model, and the implementation closed loop
(§10). Still actively edited - this folder is not frozen. New design
work that fits the founding set continues here under the same naming
convention; new work for a separate initiative goes in a sibling
directory under `design-docs/`.

See the top-level [`design-docs/README.md`](../README.md) for the
filename convention.

## Index

One line per doc; the parenthetical names what the doc is the
**authority** over, where that matters (other docs cross-reference,
never override).

| Doc | What it is |
|---|---|
| 00 | LND Mutinynet end-to-end test flow - the founding bring-up record |
| 01 | LND per-call leak map + timing channels (authority: the AI-facing LN surface) |
| 02 | Local bitcoind bring-up record (the onchain-default backend) |
| 03 | bitcoind per-RPC leak map (authority: the AI-facing bitcoind surface) |
| 04 | - (the world-facing node-privacy doc; archived, see `../../archive/`) |
| 05 | Architecture overview: components, trust boundary, data flow, modes, exit criteria (authority: the logical architecture) |
| 06 | Arb-auditability: continuous git snapshot + operator audit scripts |
| 07 | eCash extension: custody split, mint threat model (authority: delay-scaling principle + per-rail floor table §7, allowance §8) |
| 08 | eCash live test mint: selection + round-trip flow (results in `../findings/00--...`) |
| 09 | Dynamic timing window (authority: the window algorithm; floors stay doc 07 §7's) |
| 10 | eCash mint monitoring + rotation (authority: monitoring + rotation only; mechanics in `../implementation/00--...`) |
| 11 | Cross-rail fee accounting - the operator-only cost ledger (authority: operator-facing fees; AI-facing fee banding stays docs 01/03) |
| 12 | Foundational privacy posture: internal-only BTC/LN, eCash-only external value - the two guardrails (G1/G2) and the eCash exception |
| 13 | Operator-visibility TUI: the two-column console - petitioner-known vs never-known, fed by the disclosure record |
| 14 | LN availability probing + autonomous channel management under `manage_lightning` |
| 15 | Petitioner read freshness: snapshot-served balance/capacity reads (authority: the read-path freshness mitigation) |

## Rule: AI-facing vs world-facing privacy

Spacer's primary goal is to keep the AI client from learning anything about
the node it does not need to know. World-facing privacy (what the public
Bitcoin and Lightning networks, peer nodes, block explorers, and hosting
operators can observe about us) is a separate, secondary concern.

These two go in **separate documents**:

- **AI-facing privacy** docs cover the AI client as the adversary. Threat
  model: a potentially malicious or compromised AI exfiltrating via API
  responses. Mitigations: proxy filtering rules - tokenize identifiers,
  band numeric values, withhold proofs, gate outbound destinations
  through the recipient address registry, aggregate by default, audit
  log.

- **World-facing privacy** docs cover everyone except the AI: the public
  Bitcoin/LN networks, peers we connect to, block explorers we query,
  hosts we run on. Mitigations: Tor, multi-peer broadcast, private
  channels, self-hosting, avoiding identity-binding services.

Why split: if the AI client knows nothing it does not need to know, public
chain leaks alone should not enable it to derive new private info about us.
The two threat surfaces have different mitigations and different priority
(AI-facing first), so mixing them obscures both.

When writing or editing a privacy doc, place each concern in the right
file. If a concern is genuinely both (e.g. timing of a payment is visible
to both the AI through the proxy AND to chain observers), call that out
explicitly and explain how each side perceives it.
