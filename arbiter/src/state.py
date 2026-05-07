"""
Arbiter local state: a single SQLite database.

Holds everything that lives on the arbiter and never crosses the privacy
gateway: the token-to-real mapping that backs Pseudonymize (recipient
destinations are the recipient address registry per §4.7), the policy
tables that back the outbound allowlist, the pending HITL approval
queue, and pending action+result deferrals.

This module is the framework only. Each subsystem (recipient registry,
allowlist, HITL, timing layer) declares its own table schema by
calling register_schema() at import time; migrate() applies all
registered fragments idempotently. Subsystems reach the database via
the connect() context manager.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.4.
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from threading import Lock

DEFAULT_PATH = Path.home() / "spacer" / "arbiter" / "data" / "state.db"

_lock = Lock()
_path = None
_schemas = []


def configure(path=None):
    """Set the database path. If path is None, falls back to STATE_DB_PATH
    env var, then DEFAULT_PATH. Idempotent."""
    global _path
    _path = Path(path or os.environ.get("STATE_DB_PATH", DEFAULT_PATH))
    _path.parent.mkdir(parents=True, exist_ok=True)


def register_schema(sql):
    """Register a SQL schema fragment to apply on the next migrate().
    Subsystems call this at module-import time. Fragments must be
    idempotent (use CREATE TABLE IF NOT EXISTS, CREATE INDEX IF NOT
    EXISTS, etc.)."""
    _schemas.append(sql)


def migrate():
    """Apply every registered schema fragment. Safe to call repeatedly:
    idempotent fragments produce no change on re-application."""
    if _path is None:
        configure()
    conn = sqlite3.connect(_path, isolation_level=None)  # autocommit
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        for sql in _schemas:
            conn.executescript(sql)
    finally:
        conn.close()


@contextmanager
def connect():
    """Yield a sqlite3 connection. Commits on successful exit, rolls
    back on exception, closes either way. SQLite (WAL mode) serializes
    writes itself; in-process callers do not need an extra lock."""
    if _path is None:
        configure()
    conn = sqlite3.connect(_path)
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def path():
    """Return the currently-configured database path, or None if not
    configured yet."""
    return _path


if __name__ == "__main__":
    # Smoke test: register a tiny schema, migrate, insert/query, verify.
    import sys
    import tempfile

    tmp = Path(tempfile.gettempdir()) / "arbiter-state-smoke.db"
    if tmp.exists():
        tmp.unlink()
    configure(tmp)
    register_schema(
        """
        CREATE TABLE IF NOT EXISTS smoke (
            id    INTEGER PRIMARY KEY,
            label TEXT NOT NULL
        );
        """
    )
    migrate()
    # Re-running migrate must be a no-op.
    migrate()
    with connect() as c:
        c.execute("INSERT INTO smoke (label) VALUES (?)", ("alpha",))
        c.execute("INSERT INTO smoke (label) VALUES (?)", ("beta",))
    with connect() as c:
        rows = c.execute("SELECT id, label FROM smoke ORDER BY id").fetchall()
    assert rows == [(1, "alpha"), (2, "beta")], f"unexpected rows: {rows!r}"
    # Roll-back path: an exception inside the context must not commit.
    try:
        with connect() as c:
            c.execute("INSERT INTO smoke (label) VALUES (?)", ("gamma",))
            raise RuntimeError("simulated failure")
    except RuntimeError:
        pass
    with connect() as c:
        n = c.execute("SELECT COUNT(*) FROM smoke").fetchone()[0]
    assert n == 2, f"rollback failed: row count is {n}, expected 2"
    print(f"OK: state framework round-trips at {tmp}")
    sys.exit(0)
