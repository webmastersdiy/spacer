# Design docs - origin set

The founding spacer design docs: the set that established the
architecture, the threat model, and the implementation closed loop
(§10). Still actively edited - this folder is not frozen. New design
work that fits the founding set continues here under the same naming
convention; new work for a separate initiative goes in a sibling
directory under `design-docs/`.

See the top-level [`design-docs/README.md`](../README.md) for the
filename convention.

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
