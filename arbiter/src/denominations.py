"""
Petitioner amount quantization: the submission-side amount gate.

The petitioner may only submit a state-changing amount drawn from a
fixed ladder of standard denominations. Any other amount is refused at
the gateway before anything reaches the network. This closes the
amount-correlation channel (design doc 12 G2, GLOSSARY 'Banding' /
'Mint correlation'): a value the AI hands over is executed exactly on
the public LN/BTC/mint surface, so a distinctive AI-chosen amount would
be a fingerprint linking the AI's request to the arbiter's node / UTXOs
/ float. Restricting submissions to a small ladder of round numbers -
the amounts a large population of other users also transacts - keeps
every executed amount inside a big anonymity set, so the amount alone
carries no correlation signal.

Why a ladder of round numbers (not powers of 2, not arbitrary): the
anonymity set is "everyone else moving the same amount around the same
time," and human-chosen amounts cluster hard on round figures. The 1-2-5
series (1k, 2k, 5k, 10k, ... - the banknote-denomination pattern)
maximizes that overlap while staying usable. Powers of 2 (1024, 2048,
...) are eCash-native but would stand OUT against human traffic, so they
are the wrong choice for the network-facing amount. The eCash wallet
still decomposes a funded ladder amount into power-of-2 proofs
internally; that is invisible on the LN leg, which sees only the ladder
total.

Scope. The gate binds every op where the petitioner chooses the amount
that hits the network: manage_bitcoin (the on-chain send amount),
manage_lightning (the AI-declared amount; the operator's registered
invoice must itself be a ladder amount for full effect - the gate bounds
the AI, the registry bounds the operator), and fund_ecash (the minted /
LN-paid amount). defund_ecash is exempt: it carries no gate-time amount
(the token's value is whatever was funded, already ladder-quantized),
and defund only shrinks exposure.

Configuration. The allowed set resolves, in order: SPACER_DENOMINATIONS
(a comma-separated list of sat integers, for the test harness and quick
overrides) -> config/denominations.yaml (operator-editable, like the
allowance and standing approvals) -> the built-in DEFAULT_LADDER. Unlike
the allowance (missing = 0 = refuse all), a missing denominations config
falls back to the built-in ladder: quantization is a privacy ENABLER, so
the fail-safe is "privacy on with sane defaults," not "refuse
everything." A malformed config also degrades to DEFAULT_LADDER (audited)
rather than opening the gate.

Stdlib only.
"""
import os
import re
from pathlib import Path

import audit

# The 1-2-5 round-number ladder, 1k sat to 1M sat. Round figures that
# blend with human-chosen amounts; the 1k floor stays clear of the
# on-chain dust limit. Operator-overridable per the module docstring.
DEFAULT_LADDER = (
    1000, 2000, 5000,
    10000, 20000, 50000,
    100000, 200000, 500000,
    1000000,
)

DEFAULT_PATH = (
    Path.home() / "spacer" / "arbiter" / "config" / "denominations.yaml"
)

_KEY = "denominations"


def _config_path():
    raw = os.environ.get("SPACER_DENOMINATIONS_PATH")
    return Path(raw) if raw else DEFAULT_PATH


def _from_env():
    """Parse SPACER_DENOMINATIONS (comma-separated sat integers), or
    None if unset. A malformed entry drops that value; an all-bad list
    returns None so resolution falls through to the file / default."""
    raw = os.environ.get("SPACER_DENOMINATIONS")
    if raw is None:
        return None
    out = []
    for tok in raw.split(","):
        tok = tok.strip()
        if not tok:
            continue
        try:
            v = int(tok)
        except ValueError:
            continue
        if v > 0:
            out.append(v)
    return out or None


def _from_file():
    """Parse config/denominations.yaml, or None if absent. The file's
    only content is the denomination list, so every positive integer in
    it (after stripping comments) is a denomination - this reads both an
    inline `denominations: [1000, 2000]` and a block `- 1000` list
    without a full YAML parser. A read/parse failure audits and returns
    None so the caller falls back to DEFAULT_LADDER."""
    path = _config_path()
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        audit.record("denominations_read_error", {"reason": str(e)})
        return None
    stripped = []
    for raw in text.splitlines():
        idx = raw.find("#")
        stripped.append(raw[:idx] if idx >= 0 else raw)
    body = "\n".join(stripped)
    m = re.search(r"\bdenominations\b\s*:", body)
    if not m:
        audit.record("denominations_parse_error", {"reason": "no denominations key"})
        return None
    values = [int(n) for n in re.findall(r"\d+", body[m.end():])]
    values = [v for v in values if v > 0]
    if not values:
        audit.record("denominations_parse_error", {"reason": "no positive values"})
        return None
    return values


def allowed():
    """Return the allowed denomination set (frozenset of sat ints) for
    the active configuration. Resolution: env -> file -> DEFAULT_LADDER."""
    values = _from_env()
    if values is None:
        values = _from_file()
    if values is None:
        values = list(DEFAULT_LADDER)
    return frozenset(values)


def is_allowed(amount_sats):
    """True iff amount_sats is a positive integer in the allowed set.
    A missing (None) or non-integer amount is not allowed - an amount
    the gate cannot pin is refused, mirroring the allowance and
    standing-approval posture on unknown amounts."""
    if not isinstance(amount_sats, int) or amount_sats <= 0:
        return False
    return amount_sats in allowed()


if __name__ == "__main__":
    # Smoke test: default ladder, env override, file override (inline and
    # block forms), malformed-config fallback, and is_allowed membership.
    import sys
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="arbiter-denoms-smoke-"))
    audit.configure(work / "audit.log")

    # Clean env for the default-path checks.
    for k in ("SPACER_DENOMINATIONS", "SPACER_DENOMINATIONS_PATH"):
        os.environ.pop(k, None)
    os.environ["SPACER_DENOMINATIONS_PATH"] = str(work / "denominations.yaml")

    # --- default ladder when neither env nor file is set --------------
    assert allowed() == frozenset(DEFAULT_LADDER), allowed()
    assert is_allowed(1000) and is_allowed(50000) and is_allowed(1000000)
    assert not is_allowed(1500), "1500 is off-ladder"
    assert not is_allowed(256) and not is_allowed(512)
    assert not is_allowed(0) and not is_allowed(-1000)
    assert not is_allowed(None) and not is_allowed("1000") and not is_allowed(1000.0)

    # --- env override wins, drops malformed tokens --------------------
    os.environ["SPACER_DENOMINATIONS"] = "100, 300 ,900,oops,-5"
    assert allowed() == frozenset({100, 300, 900}), allowed()
    assert is_allowed(300) and not is_allowed(1000)
    del os.environ["SPACER_DENOMINATIONS"]

    # --- file override: inline list ----------------------------------
    (work / "denominations.yaml").write_text(
        "# test set\ndenominations: [1000, 4000, 16000]\n"
    )
    assert allowed() == frozenset({1000, 4000, 16000}), allowed()

    # --- file override: block list -----------------------------------
    (work / "denominations.yaml").write_text(
        "denominations:\n  - 2000  # two k\n  - 8000\n  - 32000\n"
    )
    assert allowed() == frozenset({2000, 8000, 32000}), allowed()

    # --- malformed file degrades to DEFAULT_LADDER (audited) ----------
    (work / "denominations.yaml").write_text("unrelated_key: 9\n")
    assert allowed() == frozenset(DEFAULT_LADDER), "malformed -> default"

    # --- env beats file ----------------------------------------------
    (work / "denominations.yaml").write_text("denominations: [7]\n")
    os.environ["SPACER_DENOMINATIONS"] = "1000,2000"
    assert allowed() == frozenset({1000, 2000}), allowed()
    del os.environ["SPACER_DENOMINATIONS"]

    import json
    events = [
        json.loads(line)["event"]
        for line in (work / "audit.log").read_text().splitlines()
        if line.strip()
    ]
    assert "denominations_parse_error" in events, events

    import shutil
    shutil.rmtree(work, ignore_errors=True)
    print("OK: denomination gate resolves env/file/default and gates membership")
    sys.exit(0)
