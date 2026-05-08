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
   bounded retry on collision), and inserts the row. The operator
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
   The consume call is idempotent and race-safe via a single atomic
   UPDATE.

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

Stdlib only.
"""
import hashlib
import os
import sqlite3
import time

import audit
import state


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
# Three accepted formats (sp-77lxs.6), tried in fixed order:
#   bech32m (P2TR taproot, BIP-350)
#   bech32  (P2WPKH, P2WSH segwit, BIP-173)
#   base58check (P2PKH, P2SH legacy, BIP-13)
#
# All three are checksum-self-validating, so a typo at the operator
# console is rejected before storage. The bech32 polymod and HRP-
# expand helpers follow the BIP-173 reference implementation; the
# only numeric difference between bech32 and bech32m is the constant
# the polymod must yield (BIP-350).
#
# Network policy (no-mainnet hard rule): only test networks accepted.
# bech32 HRP must be "tb" (testnet/signet) or "bcrt" (regtest); base58
# version byte must be 0x6F (testnet/signet P2PKH) or 0xC4 (testnet/
# signet P2SH). Mainnet bech32 HRP "bc" and base58 versions 0x00 / 0x05
# are refused.

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


def detect_format(addr):
    """Detect the format of a candidate address. Returns one of
    "bech32m", "bech32", "base58check" on success, None on failure.
    Tries formats in fixed order; first match wins. The three
    polymods / checksums are non-overlapping so at most one matches
    in practice."""
    if not isinstance(addr, str):
        return None
    if _try_bech32(addr, _BECH32M_CONST) is not None:
        return "bech32m"
    if _try_bech32(addr, _BECH32_CONST) is not None:
        return "bech32"
    if _try_base58check(addr) is not None:
        return "base58check"
    return None


def canonicalize(addr, fmt):
    """Return the canonical encoding for storage. bech32 / bech32m
    are canonically lowercased (BIP-173 forbids mixed case at decode
    and we normalize to the lowercase form on storage). base58check
    is case-significant and stored verbatim."""
    if fmt in ("bech32", "bech32m"):
        return addr.lower()
    return addr


# === Storage schema ==================================================
#
# One table. PRIMARY KEY AUTOINCREMENT gives the monotonic local
# sequence id (§4.7: "id ... assigned at creation. Local-only.").
# UNIQUE on token enforces collision-free allocation; the integrity
# error on insert drives the bounded retry in add().
_SCHEMA = """
CREATE TABLE IF NOT EXISTS recipient_addresses (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    token       TEXT    NOT NULL UNIQUE,
    real        TEXT    NOT NULL,
    format      TEXT    NOT NULL,
    created_at  REAL    NOT NULL,
    expires_at  REAL    NOT NULL,
    used        INTEGER NOT NULL DEFAULT 0,
    consumed_by TEXT
);
CREATE INDEX IF NOT EXISTS idx_recipient_addresses_token
    ON recipient_addresses(token);
"""
state.register_schema(_SCHEMA)


# === Errors and public API ===========================================

class RegistryError(Exception):
    """Raised for operator-facing failures: address-validation failure
    at the console, namespace exhaustion on token generation. The
    petitioner-facing path collapses every failure to "destination
    unavailable" via the gateway; this exception is for the
    operator-side console flow only."""


def add(real, expires_in_days=DEFAULT_EXPIRY_DAYS):
    """Console-side add. Validates the operator-typed address,
    generates a fresh token (with bounded collision retry), inserts
    a new row, audit-logs the success. Returns (id, token).

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
    last_err = None
    for _ in range(MAX_COLLISION_RETRY):
        token = generate_token()
        try:
            with state.connect() as conn:
                cur = conn.execute(
                    "INSERT INTO recipient_addresses "
                    "(token, real, format, created_at, expires_at) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (token, canon, fmt, now, expires),
                )
                rid = cur.lastrowid
        except sqlite3.IntegrityError as e:
            last_err = e
            continue
        audit.record(
            "registry_add",
            {
                "id": rid,
                "token": token,
                "format": fmt,
                "real": canon,
                "expires_at": expires,
            },
        )
        _maybe_warn_utilization()
        return (rid, token)
    audit.record(
        "registry_collision_exhausted",
        {"attempts": MAX_COLLISION_RETRY},
    )
    raise RegistryError(
        f"namespace unhealthy: {MAX_COLLISION_RETRY} consecutive token "
        f"collisions; manual cleanup needed (last sqlite error: {last_err})"
    )


def lookup(token):
    """Petitioner-side lookup, called from the privacy gateway's
    inbound pseudonymize step.

    Returns one of:
      ("ok", real, format)         - token is live and unused
      ("bad_checksum", None, None) - typo, alphabet error, length
                                     mismatch, or non-string input
      ("unknown", None, None)      - passes checksum but no row
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
    with state.connect() as conn:
        row = conn.execute(
            "SELECT id, real, format, expires_at, used FROM "
            "recipient_addresses WHERE token = ?",
            (norm,),
        ).fetchone()
    if row is None:
        audit.record(
            "registry_lookup_refuse",
            {"reason": "unknown", "token": norm},
        )
        return ("unknown", None, None)
    rid, real, fmt, expires_at, used = row
    if expires_at <= time.time():
        audit.record(
            "registry_lookup_refuse",
            {"reason": "expired", "id": rid, "token": norm},
        )
        return ("expired", None, None)
    if used:
        audit.record(
            "registry_lookup_refuse",
            {"reason": "used", "id": rid, "token": norm},
        )
        return ("used", None, None)
    # Defense-in-depth re-validation per sp-77lxs.6: re-detect the
    # stored address's format. If the result differs from the stored
    # format, storage is corrupt or the validator changed since
    # add-time. Audit-log full detail so the operator can investigate.
    if detect_format(real) != fmt:
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
    (already used, unknown, or bad checksum). The single atomic
    UPDATE makes consume idempotent and race-safe against a
    concurrent lookup.

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
    with state.connect() as conn:
        cur = conn.execute(
            "UPDATE recipient_addresses SET used = 1, consumed_by = ? "
            "WHERE token = ? AND used = 0",
            (consumed_by, norm),
        )
        affected = cur.rowcount
    if affected == 1:
        audit.record(
            "registry_consume",
            {"token": norm, "consumed_by": consumed_by},
        )
        return True
    audit.record(
        "registry_consume_refuse",
        {"token": norm, "consumed_by": consumed_by},
    )
    return False


def utilization():
    """Return (total_entries, namespace_size, fraction). Operator-
    facing only; never crosses the privacy gateway. Used by the
    console list command and the post-add warning."""
    with state.connect() as conn:
        total = conn.execute(
            "SELECT COUNT(*) FROM recipient_addresses"
        ).fetchone()[0]
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
    """Return all entries in id order as raw rows for the operator
    console list command. Tuple shape:
    (id, token, format, real, created_at, expires_at, used, consumed_by).

    Real addresses ARE returned here; this function is operator-only
    and never crosses the privacy gateway."""
    with state.connect() as conn:
        return conn.execute(
            "SELECT id, token, format, real, created_at, expires_at, "
            "used, consumed_by FROM recipient_addresses ORDER BY id"
        ).fetchall()


# === Smoke test ======================================================

if __name__ == "__main__":
    import json
    import sys
    import tempfile
    from pathlib import Path

    tmp_audit = Path(tempfile.gettempdir()) / "arbiter-registry-smoke.log"
    tmp_state = Path(tempfile.gettempdir()) / "arbiter-registry-smoke.db"
    for p in (tmp_audit, tmp_state):
        if p.exists():
            p.unlink()
    audit.configure(tmp_audit)
    state.configure(tmp_state)
    state.migrate()

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

    # --- add / lookup happy path -------------------------------------
    addr = "tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq0l98cr"
    rid, token = add(addr)
    assert rid >= 1, rid
    assert validate_token_format(token), token
    status, real, fmt = lookup(token)
    assert status == "ok" and real == addr.lower() and fmt == "bech32"

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

    # --- Expiry path -------------------------------------------------
    rid2, token2 = add(addr, expires_in_days=0)
    status, _, _ = lookup(token2)
    assert status == "expired", status

    # --- Anomalous: corrupt a stored address -------------------------
    rid3, token3 = add(addr)
    with state.connect() as c:
        c.execute(
            "UPDATE recipient_addresses SET real = ? WHERE id = ?",
            ("not_an_address", rid3),
        )
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
    # First add: succeeds (assuming the value isn't already in the DB,
    # which we ensure explicitly). Second add: every retry collides
    # on the UNIQUE token, loop hits MAX_COLLISION_RETRY, raises.
    fixed = generate_token()
    with state.connect() as c:
        while c.execute(
            "SELECT 1 FROM recipient_addresses WHERE token = ?", (fixed,)
        ).fetchone():
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

    print(f"OK: registry round-trips at audit={tmp_audit}, state={tmp_state}")
    sys.exit(0)
