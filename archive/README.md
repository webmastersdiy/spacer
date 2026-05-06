# Archive

Long-term storage for files that have served their purpose in an
active project but are still worth keeping for reference. Each file
is renamed at the time of archiving so its place in history is
visible from the filename alone.

## Naming

Every archived file is prefixed with the date and time the file was
originally created (or last meaningfully modified, if creation date
is unknown), then the original name in kebab-case:

```
YYYY-MM-DD-HHMM-<name>.<ext>
```

- `YYYY-MM-DD` - original creation date
- `HHMM` - original creation time, 24-hour, no separator
- `<name>` - short kebab-case slug; usually the original filename
  with the extension stripped, separators normalized to `-`
- `<ext>` - original file extension

Files sort chronologically by `ls`.

## Examples

```
2026-05-02-1428-privacy-notes.md
2026-05-10-0915-onboarding-doodles.md
2026-06-01-1700-old-config-backup.toml
```

## Provenance

When archiving, leave a one-line note in the source project
pointing at the archived file's new path, so future readers of the
project can follow the trail.
