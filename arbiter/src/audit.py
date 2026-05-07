"""
Arbiter audit log: append-only JSONL.

Every AI request and every arbiter decision (allow, deny, redact, band,
defer-to-human) is appended here as one JSON object per line, with a
UTC timestamp. The file is opened with O_APPEND and fsynced after every
write. There is no code path in this module that edits or deletes
existing records; immutability rests on that absence and on the fact
that the petitioner cannot reach the arbiter's filesystem at all.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.5.
"""
import json
import os
import time
from pathlib import Path
from threading import Lock

DEFAULT_PATH = Path.home() / "spacer" / "arbiter" / "data" / "audit.log"

_lock = Lock()
_fd = None
_path = None


def configure(path=None):
    """Open the audit log at the given path. Closes any previously-open
    log. If path is None, falls back to AUDIT_LOG_PATH env var, then
    DEFAULT_PATH."""
    global _fd, _path
    target = Path(path or os.environ.get("AUDIT_LOG_PATH", DEFAULT_PATH))
    target.parent.mkdir(parents=True, exist_ok=True)
    with _lock:
        if _fd is not None:
            os.close(_fd)
        _fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        _path = target


def record(event, payload=None):
    """Append one record. event is a short string (e.g., "request_received",
    "decision_allow", "decision_deny"); payload must be JSON-serializable.
    Returns only after fsync, so a successful return means the record is
    on disk."""
    line = json.dumps(
        {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "payload": payload or {},
        },
        separators=(",", ":"),
        sort_keys=True,
    ) + "\n"
    data = line.encode("utf-8")
    with _lock:
        global _fd, _path
        if _fd is None:
            DEFAULT_PATH.parent.mkdir(parents=True, exist_ok=True)
            _fd = os.open(
                DEFAULT_PATH, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600
            )
            _path = DEFAULT_PATH
        # write() with O_APPEND is atomic for buffers <= PIPE_BUF
        # (typically 4096 bytes on POSIX). The Lock above serializes
        # writers in this process, so longer records are also safe; the
        # arbiter is single-process by design (§4.1).
        os.write(_fd, data)
        os.fsync(_fd)


def path():
    """Return the currently-configured log path, or None if the log has
    not been opened yet."""
    return _path


if __name__ == "__main__":
    # Smoke test: write 2 records to a temp file, read them back, verify.
    import sys
    import tempfile

    tmp = Path(tempfile.gettempdir()) / "arbiter-audit-smoke.log"
    if tmp.exists():
        tmp.unlink()
    configure(tmp)
    record("smoke_test", {"hello": "world"})
    record("smoke_test", {"sequence": 2})
    with open(tmp) as f:
        lines = f.readlines()
    assert len(lines) == 2, f"expected 2 lines, got {len(lines)}: {lines!r}"
    rec0 = json.loads(lines[0])
    assert rec0["event"] == "smoke_test"
    assert rec0["payload"] == {"hello": "world"}
    assert "ts" in rec0 and rec0["ts"].endswith("Z")
    rec1 = json.loads(lines[1])
    assert rec1["payload"] == {"sequence": 2}
    print(f"OK: 2 records at {tmp}")
    sys.exit(0)
