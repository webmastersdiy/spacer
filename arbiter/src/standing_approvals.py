"""
Standing approvals: the WHAT gate.

The privacy gateway calls `matches()` on every state-changing op
AFTER the recipient address registry (§4.7) has resolved the
destination. If no rule matches, the gateway HITL-parks the call
and refuses uniformly per §6.

The file ships empty: every state-changing call HITLs until the
operator writes a rule. That default is the design - the friction
is the pedagogy (GLOSSARY 'Standing approvals' / Default-pause).

The on-disk format is YAML, hand-edited by the operator at the
directly-attached arbiter console (§2.1: minimal-and-manual). The
arbiter is stdlib-only by discipline; this module ships a minimal
YAML parser covering exactly the schema below.

Schema (closes the §7 'Standing approvals YAML schema' open
question):

  approvals:
    - op: manage_bitcoin           # required: manage_bitcoin, manage_lightning,
                                   #           fund_ecash, or defund_ecash
      destination: ABCDE4          # required: a registry token, or 'any';
                                   #           for the eCash ops write 'mint'
                                   #           (their destination is
                                   #           structurally the pinned mint;
                                   #           doc 07 §3)
      max_amount_sats: 50000       # optional: inclusive upper bound (sats);
                                   #           omit it on defund_ecash rules
                                   #           (defund carries no gate-time
                                   #           amount, and an unknown amount
                                   #           fails any bounded rule)
      rationale: Daily coffee...   # optional: operator free-text

Precedence: first matching rule wins (top-down file order). The
operator keeps the file short by hand (GLOSSARY caveat: "long
config means a small surface of real human oversight"), so a linear
scan is fast and obvious.

Per design-docs/origin/05--2026-05-05-0948-architecture-overview.md
§4.1, §6, §7 and GLOSSARY 'Standing approvals'.
"""
import os
from pathlib import Path

import audit


# Path resolved on every call so tests can swap files without
# restarting the module. Production sets the env var once at boot;
# the per-call read is negligible against the multi-hour Action
# delay window the gateway is gating.
DEFAULT_PATH = (
    Path.home() / "spacer" / "arbiter" / "config" / "standing_approvals.yaml"
)


def _config_path():
    raw = os.environ.get("SPACER_STANDING_APPROVALS_PATH")
    return Path(raw) if raw else DEFAULT_PATH


def matches(op, destination, amount_sats):
    """Return True iff some rule in the config matches.

    `op` is the wire op string (e.g., "manage_bitcoin").
    `destination` is the resolved recipient token (post-registry),
    or the structural constant "mint" for the eCash ops (their
    destination is the operator-pinned mint, not a registry entry;
    gateway._ECASH_DESTINATION).
    `amount_sats` is the amount in satoshis, or None when the
    request did not carry one. Caller is responsible for any
    msat -> sat conversion (round UP, so a max_amount_sats bound
    rejects the request rather than slipping through on a
    sub-sat fraction).

    Missing or unreadable config = no rule matches = False. The
    safe default is to HITL.
    """
    rules = _load_rules()
    for rule in rules:
        if _rule_matches(rule, op, destination, amount_sats):
            audit.record(
                "standing_approval_match",
                {"op": op, "rationale": rule.get("rationale")},
            )
            return True
    return False


def _rule_matches(rule, op, destination, amount_sats):
    if rule.get("op") != op:
        return False
    rule_dest = rule.get("destination")
    if rule_dest != "any" and rule_dest != destination:
        return False
    max_amt = rule.get("max_amount_sats")
    if max_amt is not None:
        # Unknown amount fails any rule with a bound: better to
        # HITL than to wave through a request whose magnitude
        # the gateway could not check.
        if amount_sats is None or amount_sats > max_amt:
            return False
    return True


def _load_rules():
    """Read the YAML file and return the list of rules. Any failure
    (missing file, OSError, parse error, wrong shape) returns []
    so the gateway HITL-parks every write. The error is audit-
    logged for operator triage."""
    path = _config_path()
    if not path.exists():
        return []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        audit.record(
            "standing_approvals_read_error", {"reason": str(e)}
        )
        return []
    try:
        doc = _parse_yaml(text)
    except ValueError as e:
        audit.record(
            "standing_approvals_parse_error", {"reason": str(e)}
        )
        return []
    if not isinstance(doc, dict):
        audit.record(
            "standing_approvals_parse_error",
            {"reason": "top-level not a mapping"},
        )
        return []
    approvals = doc.get("approvals", [])
    if not isinstance(approvals, list):
        audit.record(
            "standing_approvals_parse_error",
            {"reason": "approvals key not a list"},
        )
        return []
    return [r for r in approvals if isinstance(r, dict)]


# === Minimal YAML parser ============================================
#
# Subset supported (matches the operator-facing schema above):
#   - top-level mapping keys: `key: value` or `key:` + nested block
#   - block sequences: `  - key: value` items
#   - sequence-item continuation: indented `  key: value` aligned
#     under the first key of the previous list item
#   - scalar values: unquoted; parsed as int if all-digits, else
#     the empty-list literal `[]`, else a string (whitespace
#     stripped at both ends)
#   - line comments: `#` to end of line (the schema does not use
#     quoted strings so a blanket strip is safe)
#
# Deliberately NOT supported: anchors, references, flow style,
# multi-document streams, quoted strings, multi-line scalars,
# arbitrary nesting. The operator writes the config by hand; the
# schema is small enough that the subset is sufficient and the
# parser is auditable in one screen.

def _parse_yaml(text):
    lines = []
    for raw in text.splitlines():
        idx = raw.find("#")
        if idx >= 0:
            raw = raw[:idx]
        raw = raw.rstrip()
        if not raw.strip():
            continue
        lines.append(raw)
    if not lines:
        return {}
    return _parse_block(lines, _indent_of(lines[0]))


def _indent_of(line):
    return len(line) - len(line.lstrip(" "))


def _parse_block(lines, indent):
    """Parse a block at the given indent level. Returns dict or list
    depending on the first content line's shape."""
    if not lines:
        return {}
    if lines[0].lstrip().startswith("- "):
        return _parse_list(lines, indent)
    return _parse_mapping(lines, indent)


def _parse_mapping(lines, indent):
    out = {}
    i = 0
    while i < len(lines):
        line = lines[i]
        if _indent_of(line) != indent:
            break
        stripped = line.strip()
        if ":" not in stripped:
            raise ValueError(f"expected 'key: value', got {line!r}")
        key, _, rest = stripped.partition(":")
        key = key.strip()
        rest = rest.strip()
        if rest:
            out[key] = _parse_scalar(rest)
            i += 1
        else:
            child_lines = []
            i += 1
            while i < len(lines) and _indent_of(lines[i]) > indent:
                child_lines.append(lines[i])
                i += 1
            if child_lines:
                child_indent = _indent_of(child_lines[0])
                out[key] = _parse_block(child_lines, child_indent)
            else:
                out[key] = {}
    return out


def _parse_list(lines, indent):
    items = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if _indent_of(line) != indent:
            break
        stripped = line.lstrip()
        if not stripped.startswith("- "):
            break
        # Each item is a mapping; its first key starts on the same
        # line as the dash. Rewrite the leading "- " as spaces so
        # the item's keys all share one inner indent level.
        first_key_line = " " * (indent + 2) + stripped[2:]
        item_lines = [first_key_line]
        i += 1
        while i < len(lines) and _indent_of(lines[i]) > indent:
            item_lines.append(lines[i])
            i += 1
        items.append(_parse_mapping(item_lines, indent + 2))
    return items


def _parse_scalar(s):
    s = s.strip()
    if s == "[]":
        return []
    try:
        return int(s)
    except ValueError:
        return s


# === Rendering ======================================================
#
# Used by tests to write a YAML file the parser will round-trip,
# and available to any operator-side tooling that needs to emit a
# fragment programmatically (none today; the operator hand-edits).

def render_yaml(rules):
    """Render a list of rule dicts as YAML matching the parser's
    subset. Always emits `approvals: []` for an empty rule set so
    the file shape stays consistent and the parser does not have
    to special-case a key with no value."""
    if not rules:
        return "approvals: []\n"
    out = ["approvals:"]
    for rule in rules:
        first = True
        for key, value in rule.items():
            prefix = "  - " if first else "    "
            out.append(f"{prefix}{key}: {value}")
            first = False
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    # Smoke test: round-trip the schema, exercise the matcher,
    # confirm a missing file is treated as empty.
    import sys
    import tempfile

    tmp = Path(tempfile.gettempdir()) / "arbiter-standing-approvals-smoke.yaml"
    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-standing-approvals-audit.log"
    for p in (tmp, tmp_audit):
        if p.exists():
            p.unlink()
    audit.configure(tmp_audit)
    os.environ["SPACER_STANDING_APPROVALS_PATH"] = str(tmp)

    # Missing file = no rule matches; nothing crashes.
    assert matches("manage_bitcoin", "ABCDE4", 1000) is False, "missing file should match nothing"

    # Empty file = no rule matches.
    tmp.write_text(render_yaml([]))
    assert matches("manage_bitcoin", "ABCDE4", 1000) is False, "empty rules should match nothing"

    # One exact-token rule.
    rules = [
        {"op": "manage_bitcoin", "destination": "ABCDE4",
         "max_amount_sats": 5000, "rationale": "test"},
    ]
    tmp.write_text(render_yaml(rules))
    assert matches("manage_bitcoin", "ABCDE4", 1000) is True, "in-bounds amount should match"
    assert matches("manage_bitcoin", "ABCDE4", 5000) is True, "at-bound amount should match (inclusive)"
    assert matches("manage_bitcoin", "ABCDE4", 5001) is False, "over-bound amount should NOT match"
    assert matches("manage_bitcoin", "OTHER1", 1000) is False, "wrong token should NOT match"
    assert matches("manage_lightning", "ABCDE4", 1000) is False, "wrong op should NOT match"
    assert matches("manage_bitcoin", "ABCDE4", None) is False, "unknown amount fails a bounded rule"

    # 'any' destination matches every token.
    rules = [
        {"op": "manage_lightning", "destination": "any",
         "max_amount_sats": 1000, "rationale": "tiny LN any-dest"},
    ]
    tmp.write_text(render_yaml(rules))
    assert matches("manage_lightning", "WHATEV", 1000) is True
    assert matches("manage_lightning", "WHATEV", 1001) is False

    # No max_amount_sats = any amount passes.
    rules = [{"op": "manage_bitcoin", "destination": "ABCDE4", "rationale": "no bound"}]
    tmp.write_text(render_yaml(rules))
    assert matches("manage_bitcoin", "ABCDE4", 10**12) is True, "unbounded rule matches any amount"
    assert matches("manage_bitcoin", "ABCDE4", None) is True, "unbounded rule matches unknown amount"

    # First match wins: put a narrow rule above a broad one; broad
    # one shouldn't be consulted when narrow matches.
    rules = [
        {"op": "manage_bitcoin", "destination": "ABCDE4", "max_amount_sats": 100, "rationale": "narrow"},
        {"op": "manage_bitcoin", "destination": "any", "max_amount_sats": 10**9, "rationale": "broad"},
    ]
    tmp.write_text(render_yaml(rules))
    assert matches("manage_bitcoin", "ABCDE4", 50) is True   # narrow rule
    assert matches("manage_bitcoin", "ABCDE4", 500) is True  # falls through to broad
    assert matches("manage_bitcoin", "OTHER1", 500) is True  # broad rule

    # Parse-error / wrong-shape inputs return [] without crashing.
    tmp.write_text("not yaml at all: : :\n")
    # Either parses to a degenerate dict or raises; either way no rules.
    assert matches("manage_bitcoin", "ABCDE4", 1) is False

    tmp.write_text("approvals: 42\n")  # wrong shape: not a list
    assert matches("manage_bitcoin", "ABCDE4", 1) is False

    print(f"OK: standing-approvals matcher round-trips at {tmp}")
    sys.exit(0)
