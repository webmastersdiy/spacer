# Design docs

The founding set of spacer design docs lives under
[`origin/`](origin/README.md). New design work for a separate
initiative goes in a sibling directory under `design-docs/`, one per
initiative, each with its own `README.md`.

## Naming

Every doc uses a two-part filename:

```
NN--YYYY-MM-DD-HHMM-<name>.md
```

- `NN` - two-digit chronological index within the containing
  directory (`00`, `01`, ...). Indices are assigned at the time the
  doc lands and never rewritten, so a reader can cite "doc 05"
  without retyping the full date. The `NN--` prefix (with two
  dashes) is the load-bearing sort key (`ls` orders by it directly);
  the embedded date is kept for provenance.
- `YYYY-MM-DD-HHMM` - creation date and 24-hour time the doc was
  originally authored (no separator inside the time).
- `<name>` - short kebab-case slug describing the doc.

The double-dash between the index and the date is intentional: it
keeps the index visually separable from the date even on terminals
where single dashes blur into each other.

## Examples

```
00--2026-05-02-1600-lnd-mutinynet-test-flow.md
05--2026-05-05-0948-architecture-overview.md
```
