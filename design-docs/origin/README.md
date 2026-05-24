# Design docs - origin set

The original spacer design docs, frozen here for historical reference.
These are the docs that defined the architecture and threat model up
to and including the implementation closed loop (§10). New design work
goes elsewhere under `design-docs/` (one directory per initiative);
this `origin/` folder is the founding set.

## Naming

Every doc here uses a two-part filename:

```
NN-YYYY-MM-DD-HHMM-<name>.md
```

- `NN` - two-digit chronological index across the origin set (`00`,
  `01`, ...). Indices are assigned once at archive time and never
  rewritten, so a reader can cite "doc 05" without retyping the full
  date. The `NN-` prefix is the load-bearing sort key (`ls` orders by
  it directly); the embedded date is kept for provenance.
- `YYYY-MM-DD-HHMM` - creation date and 24-hour time the doc was
  originally authored (no separator inside the time). Kept verbatim
  from the pre-prefix filenames so the historical record is preserved.
- `<name>` - short kebab-case slug describing the doc.

## Examples

```
00-2026-05-02-1600-lnd-mutinynet-test-flow.md
05-2026-05-05-0948-architecture-overview.md
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
