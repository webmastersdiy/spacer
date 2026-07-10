"""
Recipient address registry (§4.7).

Manages the pseudonymized handles ("tokens") the petitioner uses to
refer to Bitcoin and Lightning destinations the operator has approved
as send targets. The arbiter never reveals the real address to the
petitioner; the registry is the only place that maps token to real.

Three responsibilities:

1. Add (operator-side). The operator types a real address at the
   directly-attached arbiter console. The registry validates the
   address's built-in checksum, generates a fresh token (with
   bounded retry on collision), and appends the entry. The operator
   reads the issued (id, token) from the console and hand-transcribes
   the token to the AI side.

2. Lookup (gateway-side). The privacy gateway calls the registry on
   every petitioner request that references a recipient token. The
   lookup returns the real address only when the token is well-formed
   (Damm32 checksum), present, unexpired, and unused. Every other
   case collapses to a single uniform "destination unavailable"
   outcome on the petitioner side; the audit log differentiates the
   cause for operator triage.

3. Consume (dispatch-side). After a successful send, the dispatch
   layer marks the entry consumed so the same token cannot be reused.
   The consume call is idempotent on a per-process basis: a second
   consume against the same token returns False without rewriting.

Token format (sp-77lxs.5): 5 random Crockford-base32 characters + 1
Damm32 check character. Crockford-base32 is 0-9 + A-Z minus I, L,
O, U (no visually ambiguous glyphs); input normalization maps I/L
to 1 and O to 0 so an obvious-glyph confusion at the operator
console resolves to the same canonical token before the checksum
runs.

Address ingestion (sp-77lxs.6): bech32 (P2WPKH, P2WSH segwit),
bech32m (P2TR taproot), and base58check (P2PKH, P2SH legacy).
Format detection runs in fixed order (bech32m, bech32, base58check);
first match wins. Mainnet HRPs and version bytes are refused at
add-time per the project's no-mainnet hard rule.

Storage substrate (bl-2lbqu4): a YAML file at arbiter/config/
destinations.yaml. The operator owns the file and can hand-edit it
at the directly-attached console with any text editor; saved changes
take effect on the next lookup (mtime-based reload, no arbiter
restart needed). The arbiter is deliberately minimal and manually
managed (architecture overview §2.1): adding a destination,
retiring one, or auditing what is in the universe should be one
open-file / edit / save round-trip with no tool, no schema
migration, and no query language between the operator and the data.

Stdlib only.
"""
import hashlib
import os
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import audit


# === Token alphabet, namespace, and Damm32 checksum ===================

# Crockford base32: 0-9 + A-Z minus I, L, O, U (no visually
# ambiguous glyphs). Each glyph's integer value is its index.
ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_ALPHABET_VAL = {c: i for i, c in enumerate(ALPHABET)}

# Crockford "loose decode": I/L look like 1, O looks like 0. Applied
# on input normalization so an obvious glyph confusion still resolves
# to the canonical sequence. (U is excluded entirely from the
# alphabet, so a typed U fails alphabet validation rather than
# silently mapping to V.)
_NORMALIZE_MAP = {"I": "1", "L": "1", "O": "0"}

# Token shape: 5 random chars (5*5 = 25 bits of namespace) plus 1
# Damm32 check char.
TOKEN_RANDOM_LEN = 5
TOKEN_TOTAL_LEN = TOKEN_RANDOM_LEN + 1
NAMESPACE_SIZE = 32 ** TOKEN_RANDOM_LEN  # 33,554,432

# §4.7's 1% utilization threshold. The arbiter audit-logs a warning
# whenever an add pushes the count to/over this fraction so the
# operator can clean up old entries.
WARN_UTILIZATION = 0.01

# §4.7's 7-day default expiry. Operator can override at creation.
DEFAULT_EXPIRY_DAYS = 7

# Bound on token-collision retry. 10 consecutive collisions means the
# namespace is unhealthy enough to require operator action; the call
# raises rather than looping forever.
MAX_COLLISION_RETRY = 10

# Damm32 quasigroup construction (sp-77lxs.5):
#
# We use op(a, b) = α*a + b in GF(2^5) with α = x and reduction
# polynomial x^5 + x^2 + 1. This is a totally anti-symmetric
# quasigroup over the 32-element alphabet, which gives the Damm
# property:
#
#   - Every single-character substitution is detected: a change in
#     position i shifts the running state by α^(n-i)*δ for δ != 0;
#     since α and δ are non-zero in a field with no zero divisors,
#     the shift is non-zero and propagates to the final state.
#
#   - Every adjacent transposition of distinct characters is
#     detected: swapping positions i and i+1 shifts the running
#     state at position i+1 by (α-1)*(d_i - d_{i+1}); since α != 1
#     in GF(2^5) and d_i != d_{i+1} by hypothesis, the shift is
#     non-zero and propagates through.
#
# Multiplication by α=x in GF(2^5) is a 5-bit left shift with
# reduction by x^5 + x^2 + 1: when the shift sets the x^5 bit
# (0x20), we replace it with x^2 + 1 (0b00101 = 5). That's the
# entire field operation we need; no full GF(2^5) multiplication
# table is built.
_GF32_REDUCTION = 0b00101  # the value x^5 reduces to in GF(2^5)


def _mul_alpha(a):
    """Multiply a by α=x in GF(2^5) modulo x^5 + x^2 + 1."""
    high = a & 0x10  # the x^4 bit; if set, the shift will overflow
    a = (a << 1) & 0x1F
    if high:
        a ^= _GF32_REDUCTION
    return a


def _damm32_state(values):
    """Iterate the Damm32 quasigroup over a sequence of integers in
    [0, 31]. The final state is 0 iff the sequence (random portion +
    check digit) is well-formed."""
    s = 0
    for v in values:
        s = _mul_alpha(s) ^ v
    return s


def damm32_check_digit(random_values):
    """Compute the check digit for a random-portion sequence.
    Appending this digit produces a sequence whose _damm32_state is 0."""
    return _mul_alpha(_damm32_state(random_values))


def normalize_token(s):
    """Apply Crockford input normalization. Strips outer whitespace,
    uppercases, then maps the visually ambiguous I/L to 1 and O to 0.
    Does not strip non-alphabet characters; those fall through and
    fail validate_token_format()."""
    out = []
    for c in s.strip().upper():
        out.append(_NORMALIZE_MAP.get(c, c))
    return "".join(out)


def _decode_token(s):
    """Map a Crockford-base32 string to the integer value list. Returns
    None if any character is not in the alphabet."""
    out = []
    for c in s:
        v = _ALPHABET_VAL.get(c)
        if v is None:
            return None
        out.append(v)
    return out


def validate_token_format(s):
    """True iff s has the right length, is in the alphabet, and has
    a valid Damm32 checksum. Caller normalizes first."""
    if len(s) != TOKEN_TOTAL_LEN:
        return False
    values = _decode_token(s)
    if values is None:
        return False
    return _damm32_state(values) == 0


def generate_token():
    """Generate a fresh token (5 random + 1 check). 25 bits of
    randomness from os.urandom; check digit computed deterministically."""
    raw = int.from_bytes(os.urandom(4), "big") & 0x1FFFFFF  # 25 bits
    values = [(raw >> (5 * i)) & 0x1F for i in range(TOKEN_RANDOM_LEN)]
    values.append(damm32_check_digit(values))
    return "".join(ALPHABET[v] for v in values)


# === Address validation ==============================================
#
# Four accepted formats (sp-77lxs.6; bolt11 wired at the captain live
# loop closing the doc-vs-code gap the schema reserved), tried in
# fixed order:
#   bech32m (P2TR taproot, BIP-350)
#   bech32  (P2WPKH, P2WSH segwit, BIP-173)
#   base58check (P2PKH, P2SH legacy, BIP-13)
#   bolt11  (Lightning invoice, BOLT-11; the manage_lightning target)
#
# All four are checksum-self-validating, so a typo at the operator
# console is rejected before storage. The bech32 polymod and HRP-
# expand helpers follow the BIP-173 reference implementation; the
# only numeric difference between bech32 and bech32m is the constant
# the polymod must yield (BIP-350). bolt11 reuses the classic bech32
# checksum with no 90-char cap (invoices run hundreds of chars) and
# an HRP of "ln" + network + optional amount. bolt12 offers and
# lightning addresses remain schema-reserved, not yet accepted.
#
# Network policy (no-mainnet hard rule): only test networks accepted.
# bech32 HRP must be "tb" (testnet/signet) or "bcrt" (regtest); base58
# version byte must be 0x6F (testnet/signet P2PKH) or 0xC4 (testnet/
# signet P2SH); bolt11 network must be tb (testnet), tbs (signet), or
# bcrt (regtest). Mainnet bech32 HRP "bc", base58 versions 0x00 / 0x05,
# and bolt11 network "bc" (lnbc...) are refused.

_BECH32_ALPHABET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
_BECH32_CONST = 1
_BECH32M_CONST = 0x2BC830A3
_TESTNET_HRPS = ("tb", "bcrt")
_TESTNET_BASE58_VERSIONS = (0x6F, 0xC4)
_BASE58_ALPHABET = (
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
)


def _bech32_polymod(values):
    """BIP-173 polynomial."""
    gen = (0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3)
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            if (b >> i) & 1:
                chk ^= gen[i]
    return chk


def _bech32_hrp_expand(hrp):
    """BIP-173 HRP expansion."""
    return [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]


def _try_bech32(s, constant):
    """Validate s as a bech32 / bech32m address with the given
    polymod constant. Returns the HRP on success, None on any
    failure (mixed case, missing separator, bad alphabet, bad
    checksum, mainnet HRP)."""
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return None
    if s.lower() != s and s.upper() != s:
        return None  # mixed case forbidden by BIP-173
    s = s.lower()
    pos = s.rfind("1")
    if pos < 1 or pos + 7 > len(s) or len(s) > 90:
        return None
    hrp = s[:pos]
    if hrp not in _TESTNET_HRPS:
        return None
    data = []
    for c in s[pos + 1:]:
        v = _BECH32_ALPHABET.find(c)
        if v == -1:
            return None
        data.append(v)
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != constant:
        return None
    return hrp


def _try_base58check(s):
    """Validate s as a base58check address. Returns the version byte
    on success, None on any failure (non-alphabet, bad checksum,
    wrong payload length, mainnet version)."""
    if not s or any(c not in _BASE58_ALPHABET for c in s):
        return None
    n = 0
    for c in s:
        n = n * 58 + _BASE58_ALPHABET.index(c)
    body = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    # Leading "1" characters in base58 represent leading zero bytes.
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    raw = b"\x00" * pad + body
    if len(raw) != 25:  # 1 version + 20 hash + 4 checksum
        return None
    payload, csum = raw[:-4], raw[-4:]
    h = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    if h != csum:
        return None
    version = payload[0]
    if version not in _TESTNET_BASE58_VERSIONS:
        return None
    return version


def _bolt11_network(rest):
    """Return the network code from a bolt11 HRP with the leading
    "ln" stripped (<network><amount?>), or None if the shape is not
    a known network followed by a well-formed optional amount.

    The prefixes are unambiguous because a bolt11 amount always
    starts with a digit: "lnbcrt..." can never parse as bc + amount
    "rt...", and "lntbs..." can never parse as tb + amount "s...".
    The amount grammar (digits + one optional m/u/n/p multiplier) is
    checked just enough to refuse an unknown network from
    masquerading as a known prefix; full integrity comes from the
    bech32 checksum over the whole string."""
    for net in ("bcrt", "tbs", "tb", "bc"):
        if not rest.startswith(net):
            continue
        tail = rest[len(net):]
        if not tail:
            return net
        digits = tail[:-1] if tail[-1] in "munp" else tail
        if digits and digits.isdigit():
            return net
        return None
    return None


def _try_bolt11(s):
    """Validate s as a BOLT-11 Lightning invoice on a test network.
    Returns the HRP on success, None on any failure (non-string,
    mixed case, bad charset, bad bech32 checksum, unknown network,
    mainnet network).

    bolt11 is bech32-coded (BIP-173 charset and polymod, classic
    constant) with two deviations that matter here: the 90-character
    cap does not apply, and the HRP is "ln" + network + optional
    amount. Field and signature semantics stay inside LND
    (lnd.payinvoice validates what it pays); this gate validates
    string integrity and the no-mainnet network rule only."""
    if not isinstance(s, str) or len(s) < 20:
        return None
    if any(ord(c) < 33 or ord(c) > 126 for c in s):
        return None
    if s.lower() != s and s.upper() != s:
        return None  # mixed case forbidden, as for on-chain bech32
    s = s.lower()
    if not s.startswith("ln"):
        return None
    pos = s.rfind("1")
    if pos < 3:
        return None
    hrp = s[:pos]
    net = _bolt11_network(hrp[2:])
    if net is None or net == "bc":
        return None  # unknown network, or the no-mainnet hard rule
    data = []
    for c in s[pos + 1:]:
        v = _BECH32_ALPHABET.find(c)
        if v == -1:
            return None
        data.append(v)
    if _bech32_polymod(_bech32_hrp_expand(hrp) + data) != _BECH32_CONST:
        return None
    return hrp


def detect_format(addr):
    """Detect the format of a candidate address. Returns one of
    "bech32m", "bech32", "base58check", "bolt11" on success, None on
    failure. Tries formats in fixed order; first match wins. The
    polymods / checksums are non-overlapping so at most one matches
    in practice (a bolt11's HRP starts with "ln", never a bare
    on-chain HRP, and on-chain bech32 caps at 90 chars)."""
    if not isinstance(addr, str):
        return None
    if _try_bech32(addr, _BECH32M_CONST) is not None:
        return "bech32m"
    if _try_bech32(addr, _BECH32_CONST) is not None:
        return "bech32"
    if _try_base58check(addr) is not None:
        return "base58check"
    if _try_bolt11(addr) is not None:
        return "bolt11"
    return None


def canonicalize(addr, fmt):
    """Return the canonical encoding for storage. bech32 / bech32m /
    bolt11 are canonically lowercased (BIP-173 forbids mixed case at
    decode and we normalize to the lowercase form on storage; bolt11
    inherits the rule from its bech32 coding). base58check is
    case-significant and stored verbatim."""
    if fmt in ("bech32", "bech32m", "bolt11"):
        return addr.lower()
    return addr


# === YAML storage ====================================================
#
# The on-disk substrate is a flat YAML list of entry mappings at
# arbiter/config/destinations.yaml. The operator owns the file and
# may hand-edit it; the arbiter reads on lookup (mtime-based reload)
# and rewrites on add() / consume(). The header comment block in the
# file documents the schema for the operator and is re-emitted on
# every rewrite.
#
# Schema (per bead bl-2lbqu4):
#   id:          int       monotonic local sequence (1, 2, 3, ...)
#   token:       str       6-char Crockford-base32 (5 random + 1 Damm32)
#   real:        str       real address (bech32* lowercased on storage)
#   format:      str       bech32 | bech32m | base58check
#                          | bolt11 | bolt12 | lightning_address (LN reserved)
#   created_at:  str       ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')
#   expires_at:  str       ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')
#   used:        bool      true once consumed
#   consumed_by: str|~     txid (Bitcoin) or payment hash (Lightning);
#                          ~ if not used
#
# We hand-write a minimal YAML emitter and parser rather than depend
# on PyYAML so this module stays stdlib-only. The schema is small and
# closed (no anchors, refs, multi-line strings, nested lists), so the
# subset we accept is tractable. Operator-friendly: bare alphanumeric
# values and single-quoted strings both work; comments anywhere are
# discarded.

DEFAULT_PATH = (
    Path(__file__).resolve().parent.parent / "config" / "destinations.yaml"
)

_FIELDS = (
    "id",
    "token",
    "real",
    "format",
    "created_at",
    "expires_at",
    "used",
    "consumed_by",
)

# Header block re-emitted on every rewrite. The schema doc here is
# the operator's reference; keep it accurate as the schema evolves.
_HEADER = """\
# arbiter/config/destinations.yaml
#
# Recipient address registry (§4.7 of design-docs/origin/05--).
# The arbiter never reveals the real address to the petitioner; this
# file is the only place that maps the public token to the real
# destination. See GLOSSARY.md "Recipient address registry" for
# the threat model.
#
# Edit this file directly with any text editor. Saved changes take
# effect on the next registry lookup (mtime-based reload, no arbiter
# restart needed). The arbiter rewrites this file on registry_add
# and registry_consume; any operator comments above individual
# entries are NOT preserved across rewrites.
#
# Schema (per-entry mapping):
#   id:          int       monotonic local sequence (1, 2, 3, ...)
#   token:       str       6-char Crockford-base32 (5 random + 1 Damm32)
#   real:        str       real address (bech32* stored lowercased)
#   format:      str       bech32 | bech32m | base58check |
#                          bolt11 | bolt12 | lightning_address
#   created_at:  str       ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')
#   expires_at:  str       ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')
#   used:        bool      true once consumed
#   consumed_by: str|~     txid (Bitcoin) or payment hash (Lightning);
#                          ~ if not used
#
# To add an entry from the directly-attached arbiter console, run:
#   arbiter/bin/registry add <real-address>
# which validates the checksum, generates a token, and appends here.
# Direct YAML edits are equally supported.
#
"""

_lock = Lock()
_path = None
_entries = []         # in-memory parsed view: list of dicts (see _FIELDS)
_mtime_ns = None      # last seen file mtime in ns; None if file absent


def configure(path=None):
    """Set the YAML file path and reset the in-memory cache. Falls back
    to DESTINATIONS_PATH env var, then DEFAULT_PATH. Idempotent. Does
    not require the file to exist; a missing file is treated as an
    empty registry until the first write creates it."""
    global _path, _entries, _mtime_ns
    with _lock:
        _path = Path(
            path or os.environ.get("DESTINATIONS_PATH", DEFAULT_PATH)
        )
        # Reset the in-memory cache so a re-configure (e.g., between
        # tests) does not serve stale entries from the previous path.
        _entries = []
        _mtime_ns = None


def path():
    """Return the currently-configured YAML path, or None if not
    configured yet."""
    return _path


def _iso_from_epoch(t):
    """Format an epoch float as ISO 8601 UTC ('YYYY-MM-DDTHH:MM:SSZ')."""
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


def _epoch_from_iso(s):
    """Parse an ISO 8601 UTC string into an epoch float. Accepts the
    canonical 'YYYY-MM-DDTHH:MM:SSZ' shape we emit, plus the
    '+00:00' suffix variant fromisoformat accepts natively. Raises
    ValueError on any other shape."""
    s = s.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    dt = datetime.fromisoformat(s)
    if dt.tzinfo is None:
        # YAML doesn't carry tz; treat naive as UTC for safety. The
        # only writer is _persist() and it always emits 'Z', so this
        # branch only fires on operator hand-edits that dropped the
        # suffix.
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _emit_str(s):
    """Emit a string as a single-quoted YAML scalar. Single quotes
    are the simplest YAML string quoting: the only escape needed is
    doubling an embedded single quote. None of our stored fields
    (Crockford tokens, bech32/base58 addresses, ISO timestamps,
    format keywords, txids, payment hashes) contain single quotes
    in practice, but the escape keeps us safe against
    consumed_by values an operator might paste in by hand."""
    return "'" + s.replace("'", "''") + "'"


def _emit(entries):
    """Serialize the entries list to YAML text. Always re-emits the
    schema header so the file remains self-documenting after every
    arbiter rewrite. Entry order matches the input list (which is
    insertion order, also id order since ids are monotonic)."""
    out = [_HEADER]
    if not entries:
        out.append("[]\n")
        return "".join(out)
    for e in entries:
        out.append(f"- id: {int(e['id'])}\n")
        out.append(f"  token: {_emit_str(e['token'])}\n")
        out.append(f"  real: {_emit_str(e['real'])}\n")
        out.append(f"  format: {_emit_str(e['format'])}\n")
        out.append(f"  created_at: {_emit_str(_iso_from_epoch(e['created_at']))}\n")
        out.append(f"  expires_at: {_emit_str(_iso_from_epoch(e['expires_at']))}\n")
        out.append(f"  used: {'true' if e['used'] else 'false'}\n")
        cb = e.get("consumed_by")
        if cb is None:
            out.append("  consumed_by: ~\n")
        else:
            out.append(f"  consumed_by: {_emit_str(cb)}\n")
        out.append("\n")
    return "".join(out)


def _parse_scalar(raw):
    """Parse one YAML scalar from the right-hand side of a 'key: value'
    line. Accepts: single-quoted strings ('foo' or 'it''s'), double-
    quoted strings ("foo" with backslash escapes), bare integers
    ('123' or '-1'), bare booleans ('true' / 'false'), nulls ('~' or
    empty), and bare alphanumeric/punctuation strings. Trailing
    '# comment' is stripped from BARE scalars only (quoted strings
    pass through verbatim). Raises ValueError on unparseable input."""
    s = raw.strip()
    if not s or s == "~":
        return None
    if s.startswith("'"):
        end = s.rfind("'")
        if end <= 0:
            raise ValueError(f"unterminated single-quoted string: {raw!r}")
        body = s[1:end].replace("''", "'")
        return body
    if s.startswith('"'):
        # Minimal double-quoted: backslash-escape, no flow indicators.
        end = -1
        i = 1
        while i < len(s):
            c = s[i]
            if c == "\\":
                i += 2
                continue
            if c == '"':
                end = i
                break
            i += 1
        if end < 0:
            raise ValueError(f"unterminated double-quoted string: {raw!r}")
        body = s[1:end]
        out = []
        i = 0
        while i < len(body):
            c = body[i]
            if c == "\\" and i + 1 < len(body):
                nxt = body[i + 1]
                out.append({"n": "\n", "t": "\t", "\\": "\\", '"': '"'}.get(
                    nxt, nxt))
                i += 2
            else:
                out.append(c)
                i += 1
        return "".join(out)
    # Bare scalar. Strip a trailing comment for tolerance with operator
    # additions like "used: false  # consumed last week".
    comment = s.find("#")
    if comment >= 0:
        s = s[:comment].rstrip()
    if not s or s == "~":
        return None
    if s == "true":
        return True
    if s == "false":
        return False
    if s.lstrip("-").isdigit():
        return int(s)
    return s


def _parse(text):
    """Parse YAML text into a list of entry dicts. Handles the closed
    schema we control: a top-level list of mappings, comments, blank
    lines, and the value shapes _parse_scalar understands.

    Recognized item start lines:
      '[]'           -> the canonical empty marker emitted by _emit()
      '- key: value' -> start a new entry; the line carries the first key
      '  key: value' -> continuation key on the current entry

    Raises ValueError on structural or schema errors with a line
    number, so operator edits that drift from the schema land an
    error the operator can correct."""
    entries = []
    current = None
    for lineno, line in enumerate(text.splitlines(), start=1):
        # Strip comments and trailing whitespace on bare lines. Quoted
        # scalars are handled inside _parse_scalar so a '#' inside a
        # quoted value is not treated as a comment.
        stripped = line.rstrip()
        if not stripped.strip() or stripped.lstrip().startswith("#"):
            continue
        # Top-level empty marker. Emitted by _emit() when entries is
        # empty so the file is still well-formed YAML.
        if stripped.strip() == "[]":
            continue
        if stripped.startswith("- "):
            if current is not None:
                entries.append(_finalize_entry(current, lineno))
            current = {}
            kv_line = stripped[2:]
            _ingest_kv(current, kv_line, lineno)
        elif stripped.startswith("  ") and current is not None:
            _ingest_kv(current, stripped.strip(), lineno)
        else:
            raise ValueError(
                f"line {lineno}: expected '- key: value' or '  key: value', "
                f"got {line!r}"
            )
    if current is not None:
        entries.append(_finalize_entry(current, lineno))
    return entries


def _ingest_kv(target, kv_line, lineno):
    """Split 'key: value' (or 'key:' for an empty value) and stuff the
    parsed result into target. Raises ValueError on missing colon."""
    colon = kv_line.find(":")
    if colon < 0:
        raise ValueError(
            f"line {lineno}: missing ':' in {kv_line!r}"
        )
    key = kv_line[:colon].strip()
    val_raw = kv_line[colon + 1:]
    target[key] = _parse_scalar(val_raw)


def _finalize_entry(raw, lineno):
    """Validate a parsed entry has every required field, normalize the
    timestamp strings to epoch floats, and return the canonical dict
    used by the in-memory cache."""
    missing = [k for k in _FIELDS if k not in raw]
    if missing:
        raise ValueError(
            f"line {lineno}: entry missing fields {missing!r}"
        )
    out = {}
    out["id"] = int(raw["id"])
    out["token"] = str(raw["token"])
    out["real"] = str(raw["real"])
    out["format"] = str(raw["format"])
    # Timestamps: stored as ISO strings in YAML, kept as epoch floats
    # in memory so the audit log payloads and the list_entries() tuple
    # shape match the pre-migration SQLite contract.
    out["created_at"] = _epoch_from_iso(str(raw["created_at"]))
    out["expires_at"] = _epoch_from_iso(str(raw["expires_at"]))
    out["used"] = bool(raw["used"])
    cb = raw["consumed_by"]
    out["consumed_by"] = None if cb is None else str(cb)
    return out


def _maybe_reload():
    """Re-read the YAML file if its mtime has changed since the last
    successful read. Called from every read path (lookup, list,
    utilization). A missing file is treated as an empty list with
    mtime=None so the first operator add() can create it.

    Caller must NOT hold _lock; this function acquires it."""
    global _entries, _mtime_ns
    with _lock:
        if _path is None:
            configure()
        try:
            st = _path.stat()
        except FileNotFoundError:
            # File doesn't exist yet (fresh deployment, before the
            # first add). Treat as empty; do not create the file
            # here - that would be a write from a read path.
            _entries = []
            _mtime_ns = None
            return
        if _mtime_ns is not None and st.st_mtime_ns == _mtime_ns:
            return
        text = _path.read_text()
        _entries = _parse(text)
        _mtime_ns = st.st_mtime_ns


def _persist(entries):
    """Atomically write entries to the YAML path. Tempfile + rename
    on the same filesystem is atomic on POSIX, so a reader concurrent
    with the rewrite sees either the old or the new file in full,
    never a torn half-written file.

    Caller must hold _lock (so _entries and _mtime_ns updates are
    coherent with this write)."""
    global _entries, _mtime_ns
    if _path is None:
        configure()
    _path.parent.mkdir(parents=True, exist_ok=True)
    text = _emit(entries)
    # Same-directory tempfile so os.replace() is a rename within one
    # filesystem (cross-fs rename would not be atomic).
    fd, tmp_path = tempfile.mkstemp(
        prefix=".destinations.", suffix=".yaml.tmp", dir=str(_path.parent)
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, _path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
    # Refresh the cached mtime after the rename so the next read does
    # not trigger a redundant reload of our own write.
    st = _path.stat()
    _entries = list(entries)
    _mtime_ns = st.st_mtime_ns


# === Errors and public API ===========================================

class RegistryError(Exception):
    """Raised for operator-facing failures: address-validation failure
    at the console, namespace exhaustion on token generation. The
    petitioner-facing path collapses every failure to "destination
    unavailable" via the gateway; this exception is for the
    operator-side console flow only."""


def add(real, expires_in_days=DEFAULT_EXPIRY_DAYS):
    """Console-side add. Validates the operator-typed address,
    generates a fresh token (with bounded collision retry), appends
    a new entry to the YAML file, audit-logs the success. Returns
    (id, token).

    Raises RegistryError on any validation failure or on collision
    exhaustion. The operator sees the exception at the console; the
    petitioner is unaware of either case.
    """
    fmt = detect_format(real)
    if fmt is None:
        # Per sp-77lxs.6 audit policy: input redacted to length +
        # format-class. The typed string itself is NOT logged: an
        # operator who fat-fingered a private key into the field by
        # mistake should not have it land in the audit log.
        audit.record(
            "registry_add_invalid",
            {"reason": "unrecognized_format", "input_len": len(real)},
        )
        raise RegistryError("address did not match any accepted format")
    canon = canonicalize(real, fmt)
    now = time.time()
    expires = now + float(expires_in_days) * 86400.0
    _maybe_reload()
    with _lock:
        # Snapshot the existing token set so collision detection is
        # cheap and consistent with the persisted state.
        existing_tokens = {e["token"] for e in _entries}
        next_id = (max((e["id"] for e in _entries), default=0)) + 1
        token = None
        for _ in range(MAX_COLLISION_RETRY):
            cand = generate_token()
            if cand not in existing_tokens:
                token = cand
                break
        if token is None:
            audit.record(
                "registry_collision_exhausted",
                {"attempts": MAX_COLLISION_RETRY},
            )
            raise RegistryError(
                f"namespace unhealthy: {MAX_COLLISION_RETRY} consecutive "
                f"token collisions; manual cleanup needed"
            )
        new_entry = {
            "id": next_id,
            "token": token,
            "real": canon,
            "format": fmt,
            "created_at": now,
            "expires_at": expires,
            "used": False,
            "consumed_by": None,
        }
        new_entries = list(_entries) + [new_entry]
        _persist(new_entries)
    audit.record(
        "registry_add",
        {
            "id": next_id,
            "token": token,
            "format": fmt,
            "real": canon,
            "expires_at": expires,
        },
    )
    _maybe_warn_utilization()
    return (next_id, token)


def lookup(token):
    """Petitioner-side lookup, called from the privacy gateway's
    inbound pseudonymize step.

    Returns one of:
      ("ok", real, format)         - token is live and unused
      ("bad_checksum", None, None) - typo, alphabet error, length
                                     mismatch, or non-string input
      ("unknown", None, None)      - passes checksum but no entry
      ("expired", None, None)      - past expires_at
      ("used", None, None)         - already consumed
      ("anomalous", None, None)    - re-validation of stored address
                                     failed (defense in depth; should
                                     never fire in normal operation)

    The caller collapses every non-"ok" outcome to the same uniform
    "destination unavailable" response per §4.7's refusal behavior.
    The audit log here differentiates the cause for operator triage.
    """
    if not isinstance(token, str):
        audit.record(
            "registry_lookup_refuse",
            {"reason": "bad_checksum", "type": type(token).__name__},
        )
        return ("bad_checksum", None, None)
    norm = normalize_token(token)
    if not validate_token_format(norm):
        audit.record(
            "registry_lookup_refuse",
            {"reason": "bad_checksum", "token_len": len(token)},
        )
        return ("bad_checksum", None, None)
    _maybe_reload()
    match = None
    for e in _entries:
        if e["token"] == norm:
            match = e
            break
    if match is None:
        audit.record(
            "registry_lookup_refuse",
            {"reason": "unknown", "token": norm},
        )
        return ("unknown", None, None)
    rid = match["id"]
    real = match["real"]
    fmt = match["format"]
    if match["expires_at"] <= time.time():
        audit.record(
            "registry_lookup_refuse",
            {"reason": "expired", "id": rid, "token": norm},
        )
        return ("expired", None, None)
    if match["used"]:
        audit.record(
            "registry_lookup_refuse",
            {"reason": "used", "id": rid, "token": norm},
        )
        return ("used", None, None)
    # Defense-in-depth re-validation per sp-77lxs.6: re-detect the
    # stored address's format. If the result differs from the stored
    # format, storage is corrupt or the validator changed since
    # add-time. Audit-log full detail so the operator can investigate.
    # Applies to every format detect_format validates (on-chain plus
    # bolt11); the still-unwired LN formats (bolt12, lightning_address)
    # are skipped.
    if fmt in ("bech32", "bech32m", "base58check", "bolt11") and detect_format(real) != fmt:
        audit.record(
            "registry_lookup_anomalous",
            {"id": rid, "token": norm, "stored_format": fmt, "real": real},
        )
        return ("anomalous", None, None)
    audit.record("registry_lookup_ok", {"id": rid, "token": norm})
    return ("ok", real, fmt)


def consume(token, consumed_by):
    """Mark the entry consumed after a successful send. Called by the
    dispatch layer when bitcoind/LND returns a txid (Bitcoin) or
    payment hash (Lightning).

    Returns True on the first successful consume, False otherwise
    (already used, unknown, or bad checksum). The lock + rewrite
    makes consume race-safe against a concurrent in-process
    consume, but not against an operator hand-editing the YAML at
    the same instant; that race is accepted (operator edits are
    human-slow and the arbiter is single-process by design).

    Note: consume does NOT re-check expires_at. The lookup-time gate
    is the precondition; once the action was authorized at lookup,
    the post-action record-keeping must record use even if the entry
    crossed its expiry between lookup and consume (the action delay
    window can span hours).
    """
    if not isinstance(token, str):
        audit.record(
            "registry_consume_anomalous",
            {"reason": "bad_checksum", "type": type(token).__name__},
        )
        return False
    norm = normalize_token(token)
    if not validate_token_format(norm):
        audit.record(
            "registry_consume_anomalous",
            {"reason": "bad_checksum", "token_len": len(token)},
        )
        return False
    _maybe_reload()
    with _lock:
        new_entries = []
        flipped = False
        for e in _entries:
            if e["token"] == norm and not e["used"]:
                new_entries.append({**e, "used": True, "consumed_by": consumed_by})
                flipped = True
            else:
                new_entries.append(e)
        if not flipped:
            audit.record(
                "registry_consume_refuse",
                {"token": norm, "consumed_by": consumed_by},
            )
            return False
        _persist(new_entries)
    audit.record(
        "registry_consume",
        {"token": norm, "consumed_by": consumed_by},
    )
    return True


def utilization():
    """Return (total_entries, namespace_size, fraction). Operator-
    facing only; never crosses the privacy gateway. Used by the
    console list command and the post-add warning."""
    _maybe_reload()
    total = len(_entries)
    return (total, NAMESPACE_SIZE, total / NAMESPACE_SIZE)


def _maybe_warn_utilization():
    """Emit a warning audit-log entry whenever utilization is at or
    above the §4.7 1% threshold. Fired from add() so an upward
    crossing is surfaced to the operator on the first add that
    pushed it over."""
    total, _ns, frac = utilization()
    if frac >= WARN_UTILIZATION:
        audit.record(
            "registry_utilization_warn",
            {"total": total, "fraction": frac, "threshold": WARN_UTILIZATION},
        )


def list_entries():
    """Return all entries in id order as raw tuples for the operator
    console list command. Tuple shape:
    (id, token, format, real, created_at, expires_at, used, consumed_by).

    Real addresses ARE returned here; this function is operator-only
    and never crosses the privacy gateway."""
    _maybe_reload()
    return [
        (
            e["id"],
            e["token"],
            e["format"],
            e["real"],
            e["created_at"],
            e["expires_at"],
            int(bool(e["used"])),
            e["consumed_by"],
        )
        for e in sorted(_entries, key=lambda x: x["id"])
    ]


# === Smoke test ======================================================

if __name__ == "__main__":
    import json
    import sys

    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-registry-smoke.log"
    tmp_yaml = Path(tempfile.gettempdir()) / "arbiter-registry-smoke.yaml"
    for p in (tmp_audit, tmp_yaml):
        if p.exists():
            p.unlink()
    audit.configure(tmp_audit)
    configure(tmp_yaml)

    # --- Damm32 invariants -------------------------------------------
    # Every single-character substitution in a generated token must
    # be detected by validate_token_format. Sample 100 fresh tokens
    # and mutate every position with every other character.
    for _ in range(100):
        t = generate_token()
        assert validate_token_format(t), f"fresh token must validate: {t}"
        for i in range(TOKEN_TOTAL_LEN):
            for c in ALPHABET:
                if c == t[i]:
                    continue
                mutated = t[:i] + c + t[i + 1:]
                assert not validate_token_format(mutated), (
                    f"single-char mutation must fail: {t} -> {mutated}"
                )

    # Every adjacent transposition of distinct characters must be
    # detected. Sample 100 fresh tokens, swap each adjacent pair.
    for _ in range(100):
        t = generate_token()
        for i in range(TOKEN_TOTAL_LEN - 1):
            if t[i] == t[i + 1]:
                continue
            swapped = t[:i] + t[i + 1] + t[i] + t[i + 2:]
            assert not validate_token_format(swapped), (
                f"adjacent transposition must fail: {t} -> {swapped}"
            )

    # --- Crockford normalization -------------------------------------
    assert normalize_token("o0iIlL") == "001111"
    assert normalize_token("  abcde  ") == "ABCDE"
    # Tokens generated in canonical form remain unchanged after normalize.
    for _ in range(20):
        t = generate_token()
        assert normalize_token(t) == t

    # --- Address validation ------------------------------------------
    # bech32 testnet P2WPKH (witness v0, 20 zero bytes), self-encoded
    # so the vector is verifiable from first principles rather than
    # depending on a copied external vector.
    assert detect_format(
        "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"
    ) == "bech32"
    # bech32m testnet P2TR (witness v1, 32 zero bytes), self-encoded.
    assert detect_format(
        "tb1pqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkgkkf5"
    ) == "bech32m"
    # bech32 regtest P2WPKH, exercises the second testnet HRP.
    assert detect_format(
        "bcrt1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqdku202"
    ) == "bech32"
    # bech32m testnet P2TR (BIP-350 vector).
    assert detect_format(
        "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c"
    ) == "bech32m"
    # base58check testnet P2PKH and P2SH.
    assert detect_format("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn") == "base58check"
    assert detect_format("2N2JD6wb56AfK4tfmM6PwdVmoYk2dCKf4Br") == "base58check"

    # Mainnet must be refused.
    assert detect_format(
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"
    ) is None
    assert detect_format("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2") is None
    assert detect_format("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy") is None

    # Garbage must be refused.
    assert detect_format("") is None
    assert detect_format("not an address") is None
    assert detect_format("tb1qinvalidcharacterszzz") is None
    # Mutated bech32 (last char wrong) must fail checksum.
    assert detect_format(
        "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cz"
    ) is None
    # Mixed case bech32 forbidden (BIP-173).
    assert detect_format(
        "tb1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ0l98cr"
    ) is None
    # Non-string input.
    assert detect_format(None) is None
    assert detect_format(b"tb1qabc") is None

    # --- bolt11 validation -------------------------------------------
    # Self-encoded invoice-shaped vectors (arbitrary zero payload +
    # correct bech32 checksum), verifiable from first principles with
    # the module's own polymod - the same discipline as the on-chain
    # vectors above. Real signet invoices are exercised live.
    def _mk_bolt11(hrp, payload_len=40):
        data = [0] * payload_len
        poly = _bech32_polymod(
            _bech32_hrp_expand(hrp) + data + [0] * 6
        ) ^ _BECH32_CONST
        checksum = [(poly >> 5 * (5 - i)) & 31 for i in range(6)]
        return hrp + "1" + "".join(
            _BECH32_ALPHABET[d] for d in data + checksum
        )

    # Test networks accepted: signet (tbs), testnet (tb), regtest
    # (bcrt), with and without an HRP amount.
    assert detect_format(_mk_bolt11("lntbs")) == "bolt11"
    assert detect_format(_mk_bolt11("lntbs4310n")) == "bolt11"
    assert detect_format(_mk_bolt11("lntb500u")) == "bolt11"
    assert detect_format(_mk_bolt11("lnbcrt1m")) == "bolt11"
    # Uppercase form accepted (bech32 all-upper variant)...
    assert detect_format(_mk_bolt11("lntbs256n").upper()) == "bolt11"
    # ...and canonicalized to lowercase for storage.
    up = _mk_bolt11("lntbs256n").upper()
    assert canonicalize(up, "bolt11") == up.lower()
    # Mainnet refused (no-mainnet hard rule): lnbc + amount / bare.
    assert detect_format(_mk_bolt11("lnbc10n")) is None
    assert detect_format(_mk_bolt11("lnbc")) is None
    # Unknown network refused (lntbx is not tb + amount "x...").
    assert detect_format(_mk_bolt11("lntbx5n")) is None
    # Corrupted checksum refused: flip one data char.
    good = _mk_bolt11("lntbs")
    bad = good[:-8] + ("q" if good[-8] != "q" else "p") + good[-7:]
    assert detect_format(bad) is None
    # Mixed case refused, mirroring the on-chain bech32 rule.
    mixed = good[: len("lntbs") + 3].upper() + good[len("lntbs") + 3:]
    assert detect_format(mixed) is None

    # --- add / lookup happy path -------------------------------------
    addr = "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"
    rid, token = add(addr)
    assert rid >= 1, rid
    assert validate_token_format(token), token
    status, real, fmt = lookup(token)
    assert status == "ok" and real == addr.lower() and fmt == "bech32"

    # The file exists on disk after the first add and parses back
    # round-trip-clean. This is the load-bearing check the YAML
    # substrate replaces: a fresh process can re-read the file and
    # see the same entry.
    assert tmp_yaml.exists(), f"YAML file should exist after add: {tmp_yaml}"
    raw_text = tmp_yaml.read_text()
    reparsed = _parse(raw_text)
    assert len(reparsed) == 1, reparsed
    assert reparsed[0]["token"] == token
    assert reparsed[0]["real"] == addr.lower()
    assert reparsed[0]["format"] == "bech32"

    # Crockford-normalized lookup. Lowercase the canonical token, swap
    # any "1" for "I" and any "0" for "O"; lookup must still resolve.
    perturbed = token.lower().replace("1", "i").replace("0", "o")
    status, real, _ = lookup(perturbed)
    assert status == "ok" and real == addr.lower(), (status, real)

    # Bad-checksum: mutate the last char to one that breaks the Damm
    # invariant. Pick any other alphabet char.
    mutated = token[:-1] + ("Z" if token[-1] != "Z" else "Y")
    status, _, _ = lookup(mutated)
    assert status == "bad_checksum", status

    # Wrong type.
    status, _, _ = lookup(None)
    assert status == "bad_checksum", status
    status, _, _ = lookup(b"abc123")
    assert status == "bad_checksum", status

    # Unknown but well-formed: generate a fresh token unlikely to
    # collide with the one we added.
    while True:
        spare = generate_token()
        if spare != token:
            break
    status, _, _ = lookup(spare)
    assert status == "unknown", status

    # --- Consume idempotency -----------------------------------------
    assert consume(token, "txid_smoke") is True
    assert consume(token, "txid_smoke_again") is False
    status, _, _ = lookup(token)
    assert status == "used", status
    # Bad-checksum consume returns False without touching state.
    assert consume("nope", "x") is False
    assert consume(None, "x") is False

    # Re-parse: the consume() rewrote the YAML and the flipped state
    # is now persistent. Confirms the rewrite path round-trips.
    reparsed = _parse(tmp_yaml.read_text())
    consumed = [e for e in reparsed if e["token"] == token]
    assert len(consumed) == 1 and consumed[0]["used"] is True
    assert consumed[0]["consumed_by"] == "txid_smoke"

    # --- Mtime-based reload ------------------------------------------
    # The operator's hand-edit path: replace the file directly, lookup
    # must see the new contents on the very next call. Construct a
    # minimal valid entry by hand to simulate an operator edit; reuse
    # the existing tokens and add a brand-new entry inline.
    edited_token = None
    for _ in range(20):
        cand = generate_token()
        if cand != token:
            edited_token = cand
            break
    assert edited_token is not None
    edited_addr = "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"  # same valid addr
    hand_edited = _HEADER + (
        f"- id: 99\n"
        f"  token: '{edited_token}'\n"
        f"  real: '{edited_addr}'\n"
        f"  format: 'bech32'\n"
        f"  created_at: '2026-05-24T00:00:00Z'\n"
        f"  expires_at: '2099-01-01T00:00:00Z'\n"
        f"  used: false\n"
        f"  consumed_by: ~\n"
    )
    # Sleep briefly to ensure st_mtime_ns advances on filesystems with
    # coarse mtime; modern macOS/Linux are nanosecond, but a single
    # ns is enough to differ.
    time.sleep(0.01)
    tmp_yaml.write_text(hand_edited)
    status, real, _ = lookup(edited_token)
    assert status == "ok" and real == edited_addr, (status, real)

    # The reload also drops the prior in-memory entries (token now
    # unknown because the hand-edit replaced the whole file).
    status, _, _ = lookup(token)
    assert status == "unknown", status

    # --- Expiry path -------------------------------------------------
    rid2, token2 = add(addr, expires_in_days=0)
    status, _, _ = lookup(token2)
    assert status == "expired", status

    # --- Anomalous: corrupt a stored address -------------------------
    rid3, token3 = add(addr)
    # Hand-edit the file to mangle the stored address for token3.
    current = _parse(tmp_yaml.read_text())
    for e in current:
        if e["token"] == token3:
            e["real"] = "not_an_address"
    # Manually re-emit (bypassing _persist so we exercise the parser /
    # emitter directly here, plus a fresh mtime).
    time.sleep(0.01)
    tmp_yaml.write_text(_emit(current))
    status, _, _ = lookup(token3)
    assert status == "anomalous", status

    # --- Add invalid address -----------------------------------------
    raised = False
    try:
        add("definitely not a btc address")
    except RegistryError:
        raised = True
    assert raised, "invalid address must raise RegistryError"

    # --- Mainnet add must be refused ---------------------------------
    raised = False
    try:
        add("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")
    except RegistryError:
        raised = True
    assert raised, "mainnet bech32 must be refused"
    raised = False
    try:
        add("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2")
    except RegistryError:
        raised = True
    assert raised, "mainnet base58 must be refused"

    # --- Utilization warning -----------------------------------------
    # We can't realistically generate 1% (~335k) entries. Lower the
    # threshold via the module global and verify the warning event
    # appears in the audit log.
    saved_threshold = WARN_UTILIZATION
    globals()["WARN_UTILIZATION"] = 0.0
    try:
        add(addr)
    finally:
        globals()["WARN_UTILIZATION"] = saved_threshold
    with open(tmp_audit) as f:
        events = [json.loads(line)["event"] for line in f if line.strip()]
    assert "registry_utilization_warn" in events, events

    # --- Audit-log differentiation -----------------------------------
    # The audit log must differentiate the cause for each refusal
    # path. We've exercised bad_checksum, unknown, expired, and used
    # above; check that all four reasons appear in the log payloads.
    with open(tmp_audit) as f:
        reasons = [
            json.loads(line).get("payload", {}).get("reason")
            for line in f
            if line.strip()
        ]
    for r in ("bad_checksum", "unknown", "expired", "used"):
        assert r in reasons, f"audit log must record reason {r!r}: {reasons!r}"

    # --- Collision exhaustion ----------------------------------------
    # Force every generate_token() call to return the same value.
    # First add: succeeds (assuming the value isn't already in the
    # YAML, which we ensure explicitly). Second add: every retry
    # collides on the in-memory token set, loop hits
    # MAX_COLLISION_RETRY, raises.
    fixed = generate_token()
    existing = {e["token"] for e in _entries}
    while fixed in existing:
        fixed = generate_token()
    saved_gen = globals()["generate_token"]
    globals()["generate_token"] = lambda: fixed
    try:
        add(addr)  # first add succeeds
        raised = False
        try:
            add(addr)  # second add: every retry collides
        except RegistryError as e:
            raised = "namespace unhealthy" in str(e)
        assert raised, "collision exhaustion must raise"
    finally:
        globals()["generate_token"] = saved_gen

    # --- list_entries shape preservation -----------------------------
    # The CLI consumer (registry_cli.py cmd_list) iterates the tuple
    # by position; the YAML migration must preserve that shape and
    # the float-epoch type for the two timestamps (so the CLI's
    # time.strftime(..., time.gmtime(t)) call still works).
    rows = list_entries()
    assert rows, "list_entries should not be empty after the adds above"
    for row in rows:
        assert len(row) == 8, row
        rid, tok, fmt_, real_, ca, ea, used_, cb = row
        assert isinstance(rid, int)
        assert isinstance(tok, str) and len(tok) == TOKEN_TOTAL_LEN
        assert isinstance(fmt_, str)
        assert isinstance(real_, str)
        assert isinstance(ca, float)
        assert isinstance(ea, float)
        assert used_ in (0, 1)
        assert cb is None or isinstance(cb, str)

    # --- bolt11 add / lookup / consume round-trip --------------------
    # Runs last so the count-sensitive assertions above stay stable.
    # Stored lowercased, returned by lookup, one-time-use flips like
    # any other entry, and anomaly re-validation accepts the stored
    # form (bolt11 is in the re-detect set).
    inv = _mk_bolt11("lntbs4310n").upper()
    rid_ln, token_ln = add(inv)
    status, real_ln, fmt_ln = lookup(token_ln)
    assert status == "ok" and fmt_ln == "bolt11", (status, fmt_ln)
    assert real_ln == inv.lower(), real_ln
    assert consume(token_ln, "smoke_payment_hash") is True
    status, _, _ = lookup(token_ln)
    assert status == "used", status

    print(f"OK: registry round-trips at audit={tmp_audit}, yaml={tmp_yaml}")
    sys.exit(0)
