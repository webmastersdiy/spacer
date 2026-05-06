# Design docs

## Naming

Every design doc filename is prefixed with the date and time it was created, then the doc name:

```
YYYY-MM-DD-HHMM-<name>.md
```

- `YYYY-MM-DD` - creation date (UTC or local, pick one and stay consistent)
- `HHMM` - creation time, 24-hour, no separator
- `<name>` - short kebab-case slug describing the doc

Files sort chronologically by `ls`.

## Examples

```
2026-05-02-1410-privacy-proxy-architecture.md
2026-05-03-0915-channel-management-policy.md
2026-05-10-1700-bitcoind-rpc-allowlist.md
```

## Rule: AI-facing vs world-facing privacy

Spacer's primary goal is to keep the AI client from learning anything about
the node it does not need to know. World-facing privacy (what the public
Bitcoin and Lightning networks, peer nodes, block explorers, and hosting
operators can observe about us) is a separate, secondary concern.

These two go in **separate documents**:

- **AI-facing privacy** docs cover the AI client as the adversary. Threat
  model: a potentially malicious or compromised AI exfiltrating via API
  responses. Mitigations: proxy filtering rules - tokenize identifiers,
  band numeric values, withhold proofs, allowlist outbound, aggregate by
  default, audit log.

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
