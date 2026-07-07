#!/usr/bin/env python3
"""
Build-time mint contract test: pins the cashu (nutshell) CLI surface
the arbiter's eCash rail depends on (design doc 10 §3; implementation
companion §2).

Two silent-failure surfaces motivate this gate:

- M1, melt settlement. The defund handler decides "really defunded"
  by parsing `cashu pay` stdout for the "Invoice paid"/preimage line
  (executor._melt_settled), because a merely-pending melt EXITS 0
  (the pending-exit-0 trap, doc 08 findings §1.2). If a CLI upgrade
  rewords that line, nothing errors at runtime: settled melts start
  reading as not-settled, or - worse - pending output starts
  matching and a stuck melt reports a false "defunded".
- M2, DLEQ verification at receive. The wallet must reject a proof
  whose NUT-12 DLEQ is present but wrong (doc 07 §2). A regression
  that silently disables verification produces no error anywhere:
  the counterfeit proof is simply accepted.

Both therefore fail THE BUILD here, loudly, instead of M1/M2 failing
silently at runtime.

What runs:

1. Parser fixtures (always; stdlib + arbiter modules only): the
   arbiter's own executor._melt_settled is asserted against recorded
   nutshell-0.18.1 `cashu pay` shapes - the live mint's settled form
   (preimage revealed, doc 08 findings), the FakeWallet backend's
   settled form, and the pending form. This layer gates parser edits
   even on checkouts without the CLI installed.
2. Version pin (when the CLI is present): `cashu info` must report
   exactly the version pinned in config/cashu-pin.yaml, so an
   unreviewed CLI upgrade cannot land green; a bump is forced
   through a reviewed pin change, which re-runs this test against
   the new CLI. `info` prints wallet-local state without contacting
   any mint (verified against 0.18.1), so the gate needs no mint.
3. Live CLI contract (when the CLI is present): an ephemeral local
   nutshell mint (FakeWallet backend, loopback only, all state under
   a temp dir) is driven through the arbiter's own ecash.py wrapper,
   so the exact argv/env construction the arbiter uses is what gets
   exercised:
     - fund leg: the mint-quote stdout parses
       (executor._parse_mint_quote) and issuance completes;
     - settled melt: with the backend settling instantly, pay output
       must read settled (executor._melt_settled is True);
     - pending melt: the mint restarts in a pending-forever backend
       config; `cashu pay` exits 0 and its output must NOT read
       settled - the trap, asserted against the real CLI;
     - DLEQ: `cashu send -y -d` must embed DLEQ on every proof (the
       wallet SKIPS verification for proofs without DLEQ, NUT-12
       optionality, so a token that silently lost its DLEQ fields
       would make this whole check vacuous); a copy with every DLEQ
       challenge scalar bit-flipped must be REJECTED at receive with
       a DLEQ-naming error and no balance credit, and the intact
       original must then be accepted, proving the rejection was the
       DLEQ check and not general breakage;
     - decode: the executor's offline mint-pin + value parse
       (executor._decode_and_pin) holds against real decode output.

The ephemeral mint is TEST SCAFFOLDING, not part of the contract:
the wallet CLI under test talks to it over loopback HTTP exactly as
it talks to the real pinned mint. Nothing here contacts any external
host - CASHU_MINT_URL is always overridden to the ephemeral mint,
and the version gate runs against a dead loopback URL.

Environment:

- CASHU_BIN: the pinned CLI to test. Default: the arbiter's deployed
  binary, via ecash.py's own resolution, so the gate tests what the
  arbiter would actually run.
- Missing CLI: layers 2-3 SKIP (exit 0) so hermetic checkouts stay
  green on layer 1 alone. An eCash deployment build sets
  MINT_CONTRACT_REQUIRE_CLI=1 to make absence a build failure.
- MINT_CONTRACT_PYTHON: interpreter of the python env nutshell is
  installed in (needed for the ephemeral mint and token surgery).
  Default: derived from the CLI entry script's shebang - a pip
  console script carries its venv's absolute interpreter there - and
  the script re-execs itself under it.

Wired into the arbiter build as a gate in
test-harness/scripts/exit_loop_runner.py (the suite every change
must keep green). Standalone:

    python3 arbiter/ops/mint_contract_test.py            # full gate
    python3 arbiter/ops/mint_contract_test.py --smoke    # hermetic self-test

This file itself is stdlib-only; the nutshell python env supplies
the cashu and bolt11 packages used by the mint scaffolding and the
token corruption. On failure the temp workdir is kept and its path
printed, mirroring the exit-loop convention of leaving failure
artifacts for a non-AI reviewer.
"""
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ARBITER_SRC = REPO_ROOT / "arbiter" / "src"
PIN_PATH = REPO_ROOT / "arbiter" / "config" / "cashu-pin.yaml"
_PIN_KEY = "cashu_pin_version"
_REEXEC_MARKER = "MINT_CONTRACT_REEXECED"

sys.path.insert(0, str(ARBITER_SRC))
import ecash  # noqa: E402
import executor  # noqa: E402


class ContractFailure(Exception):
    """A step that leaves the contract unverifiable (mint would not
    boot, corruption helper cannot run, CLI output unparseable).
    Distinct from a failed check: a check failing means the contract
    is BROKEN; this means it could not be tested - both fail the
    build, with different messages."""


# Recorded nutshell 0.18.1 `cashu pay` stdout shapes. The settled
# forms are the live pinned mint's (a preimage is revealed only on
# settlement; doc 08 findings §1.2, sp-uwa0v0) and the FakeWallet
# backend's (no preimage to reveal, still "Invoice paid"; recorded
# against this test's own ephemeral mint at sp-xha). The pending form
# is the exit-0 trap's output. These are the M1 contract frozen at
# the pin; the live layer re-derives them from the actual CLI.
_SETTLED_SHAPES = [
    "Paying Lightning invoice ... Invoice paid. (Preimage:"
    " 8d7f3b1a9c2e4d6f) (fee 3 sat).\n",
    "Balance: 5000 sat\nPaying Lightning invoice ... Invoice paid."
    " Mint did not provide a preimage.\nBalance: 3999 sat\n",
]
_PENDING_SHAPES = [
    "Balance: 3999 sat\nPaying Lightning invoice ... Invoice pending."
    "\nBalance: 2989 sat\n",
]

# Deterministic mint identity across the settled -> pending restart:
# same private key + same mint database = same keysets, so proofs
# issued under the settled config stay spendable under the pending
# one. Test-only key material for a loopback FakeWallet mint; nothing
# real is derived from it.
_MINT_KEY = "spacer-mint-contract-test-fixed-key"

# The ephemeral mint launcher. The strategy alias is scaffolding for
# a nutshell-0.18.1 / newer-`limits` incompatibility: 0.18.1 requests
# the "fixed-window-elastic-expiry" rate-limit strategy, which recent
# `limits` releases removed, so the mint app cannot even start
# without the alias. Rate limiting is irrelevant to the contract
# (loopback, one wallet); the wallet CLI under test is untouched. The
# setdefault is a no-op on environments where the strategy exists.
_MINT_LAUNCHER = """\
import sys

from limits.strategies import STRATEGIES

STRATEGIES.setdefault(
    "fixed-window-elastic-expiry", STRATEGIES["fixed-window"]
)

import uvicorn
from cashu.mint.app import app

uvicorn.run(
    app, host="127.0.0.1", port=int(sys.argv[1]), log_level="warning"
)
"""


class Checks:
    """PASS/FAIL line accounting, same shape as the exit-loop
    runner's output so the gate reads uniformly in suite logs."""

    def __init__(self):
        self.total = 0
        self.failed = []

    def check(self, name, ok, detail=""):
        self.total += 1
        print(("PASS  " if ok else "FAIL  ") + name)
        if not ok:
            self.failed.append((name, detail))
            if detail:
                print("      -> " + detail)
        return ok

    def summary(self, label):
        print()
        print("--- %s summary ---" % label)
        print("passed: %d/%d" % (self.total - len(self.failed), self.total))
        if self.failed:
            print("failed: %d" % len(self.failed))
            for name, detail in self.failed:
                print("  - %s: %s" % (name, detail))
        return 0 if not self.failed else 1


def _tail(text, lines=6):
    """Last few lines of a captured stream, flattened for a one-line
    failure detail."""
    parts = [ln for ln in (text or "").strip().splitlines() if ln.strip()]
    return " | ".join(parts[-lines:])


def read_pin(path):
    """Return the pinned version string from config/cashu-pin.yaml,
    or None when absent/unparseable. Same hand-parse idiom as
    ecash.allowance_sats: hash comments stripped, first matching
    key wins, stdlib only."""
    if not path.exists():
        return None
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return None
    for raw in text.splitlines():
        idx = raw.find("#")
        if idx >= 0:
            raw = raw[:idx]
        if ":" not in raw:
            continue
        key, _, value = raw.partition(":")
        if key.strip() != _PIN_KEY:
            continue
        value = value.strip().strip("'").strip('"')
        return value or None
    return None


def resolve_cli():
    """The CLI under test: ecash.py's own resolution (CASHU_BIN env
    override, else the deployed default), None when the binary is
    absent. Reusing ecash._bin_path keeps this gate pointed at
    exactly what the arbiter would exec."""
    path = ecash._bin_path()
    return path if path.exists() else None


def cli_version(cashu_bin, workdir):
    """Version string from `cashu info`, run offline: fresh temp
    CASHU_DIR and a dead loopback --host. info prints wallet-local
    state without contacting the mint (verified against 0.18.1), so
    the version gate works with no mint anywhere. Raises
    ContractFailure when the CLI fails or prints no Version line."""
    wallet_dir = workdir / "version-gate-wallet"
    wallet_dir.mkdir(parents=True, exist_ok=True)
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(workdir),
        "CASHU_DIR": str(wallet_dir),
    }
    cmd = [str(cashu_bin), "--host=http://127.0.0.1:9", "info"]
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30, env=env,
        )
    except subprocess.TimeoutExpired:
        raise ContractFailure(
            "`cashu info` timed out; the version gate expects it to "
            "run offline"
        )
    except OSError as e:
        raise ContractFailure("could not exec %s: %s" % (cashu_bin, e))
    if proc.returncode != 0:
        raise ContractFailure(
            "`cashu info` exited %d: %s"
            % (proc.returncode, _tail(proc.stderr))
        )
    m = re.search(r"^Version:\s*(\S+)", proc.stdout, re.MULTILINE)
    if not m:
        raise ContractFailure(
            "no 'Version:' line in `cashu info` output: %s"
            % _tail(proc.stdout)
        )
    return m.group(1)


def _cashu_importable():
    try:
        import cashu  # noqa: F401
        return True
    except Exception:
        return False


def _nutshell_python(cashu_bin):
    """Interpreter of the python env nutshell is installed in:
    MINT_CONTRACT_PYTHON override, else the CLI entry script's
    shebang (a pip console script's first line is its venv's
    absolute interpreter; an env-style shebang resolves via PATH).
    None when underivable - e.g. a non-script binary."""
    override = os.environ.get("MINT_CONTRACT_PYTHON")
    if override:
        p = Path(override)
        return p if p.exists() else None
    try:
        with open(cashu_bin, "rb") as fh:
            first = fh.readline(256).decode("utf-8", "replace").strip()
    except OSError:
        return None
    if not first.startswith("#!"):
        return None
    tokens = first[2:].split()
    if not tokens:
        return None
    if tokens[0].endswith("/env") and len(tokens) > 1:
        found = shutil.which(tokens[1])
        p = Path(found) if found else None
    else:
        p = Path(tokens[0])
    # Only a python counts: a wrapper script with some other
    # interpreter line (or a native binary) must fall through to the
    # loud "env unavailable" failure instead of re-exec'ing this
    # python file under, say, /bin/sh.
    if p is None or not p.name.startswith("python"):
        return None
    return p if p.exists() else None


class EphemeralMint:
    """One ephemeral nutshell mint on loopback: FakeWallet backend,
    all state under the test workdir (including HOME, so the default
    data dir cannot escape it). FAKEWALLET_BRR auto-marks mint quotes
    paid, so the fund leg needs no LN payer; the *_STATE knobs make
    melt payments settle immediately (SETTLED) or hang forever
    (PENDING), which is how the exit-0 trap is reproduced against
    the real CLI. Runs under the nutshell env's interpreter (this
    script re-execs into it before constructing one)."""

    def __init__(self, workdir, port, fakewallet_state):
        self.workdir = Path(workdir)
        self.port = port
        self.state = fakewallet_state
        self.log_path = self.workdir / (
            "mint-%s.log" % fakewallet_state.lower()
        )
        self.proc = None
        self._log = None

    def start(self, timeout_s=60):
        launcher = self.workdir / "mint_launcher.py"
        launcher.write_text(_MINT_LAUNCHER, encoding="utf-8")
        env = {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": str(self.workdir),
            "MINT_LISTEN_HOST": "127.0.0.1",
            "MINT_PRIVATE_KEY": _MINT_KEY,
            "MINT_DATABASE": str(self.workdir / "mint-db"),
            "CASHU_DIR": str(self.workdir / "mint-cashu-dir"),
            "MINT_BACKEND_BOLT11_SAT": "FakeWallet",
            "FAKEWALLET_BRR": "TRUE",
            "FAKEWALLET_DELAY_INCOMING_PAYMENT": "0",
            "FAKEWALLET_DELAY_OUTGOING_PAYMENT": "0",
            "FAKEWALLET_PAY_INVOICE_STATE": self.state,
            "FAKEWALLET_PAYMENT_STATE": self.state,
        }
        self._log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(
            [sys.executable, str(launcher), str(self.port)],
            stdout=self._log,
            stderr=subprocess.STDOUT,
            env=env,
        )
        deadline = time.time() + timeout_s
        url = "http://127.0.0.1:%d/v1/info" % self.port
        while time.time() < deadline:
            if self.proc.poll() is not None:
                rc = self.proc.returncode
                self.stop()
                raise ContractFailure(
                    "ephemeral mint (%s) exited rc=%d before ready; "
                    "log: %s" % (self.state, rc,
                                 _tail(self._log_text(), 8))
                )
            try:
                with urllib.request.urlopen(url, timeout=2):
                    return
            except OSError:
                time.sleep(0.25)
        self.stop()
        raise ContractFailure(
            "ephemeral mint (%s) not ready within %ds; log: %s"
            % (self.state, timeout_s, _tail(self._log_text(), 8))
        )

    def _log_text(self):
        try:
            return self.log_path.read_text(
                encoding="utf-8", errors="replace"
            )
        except OSError:
            return ""

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(5)
                except subprocess.TimeoutExpired:
                    pass
        if self._log is not None:
            self._log.close()
            self._log = None


def _free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _make_bolt11(amount_sat, label):
    """A syntactically valid, freshly signed bolt11 for the melt
    legs, built with the nutshell env's own bolt11 package under a
    throwaway key. The FakeWallet backend "pays" any well-formed
    invoice; nothing routes anywhere. Generated per run rather than
    shipped as a fixture so invoice-expiry decode paths never age
    into the test."""
    import secrets

    from bolt11 import (
        Bolt11, MilliSatoshi, Tag, TagChar, Tags, encode,
    )

    tags = Tags([
        Tag(TagChar.payment_hash, secrets.token_hex(32)),
        Tag(TagChar.payment_secret, secrets.token_hex(32)),
        Tag(TagChar.description, "spacer-mint-contract-" + label),
        Tag(TagChar.expire_time, 86400),
    ])
    invoice = Bolt11(
        currency="bc",
        amount_msat=MilliSatoshi(int(amount_sat) * 1000),
        date=int(time.time()),
        tags=tags,
    )
    return encode(invoice, secrets.token_hex(32))


def _corrupt_dleq(token):
    """Return (corrupted_token, proof_count): a copy of the
    serialized token with every proof's DLEQ challenge scalar
    bit-flipped, via the pinned nutshell's own V4 codec. Refuses to
    produce a vacuous corruption: every proof must carry DLEQ before
    AND after re-serialization, because the wallet skips verification
    for proofs without DLEQ (NUT-12 optionality) and 0.18.1's
    serializer drops DLEQ unless asked to keep it - a stripped token
    would be accepted and read as a false M2 pass."""
    from cashu.core.base import TokenV4

    try:
        tok = TokenV4.deserialize(token)
    except Exception as e:
        raise ContractFailure(
            "send output is not a V4 (cashuB) token this corruption "
            "helper understands - update the helper alongside the "
            "pin: %s" % e
        )
    proofs = [p for t in tok.t for p in t.p]
    missing = [p for p in proofs if p.d is None]
    if missing:
        raise ContractFailure(
            "`cashu send -y -d` produced %d/%d proofs WITHOUT DLEQ; "
            "the -d contract is broken (doc 07 §2)"
            % (len(missing), len(proofs))
        )
    for p in proofs:
        p.d.e = bytes([p.d.e[0] ^ 0x01]) + p.d.e[1:]
    corrupted = tok.serialize(include_dleq=True)
    back = [
        p for t in TokenV4.deserialize(corrupted).t for p in t.p
    ]
    if any(p.d is None for p in back):
        raise ContractFailure(
            "corrupted token lost its DLEQ fields on re-serialization"
        )
    return corrupted, len(proofs)


def _raw_receive(cashu_bin, mint_url, token):
    """One receive call outside ecash._run, argv-identical to it
    (connection flag first, argv list, CASHU_DIR pinned via env), so
    the FULL stderr is available: EcashError truncates stderr to 200
    chars and the DLEQ-naming assert needs the error's final line."""
    cmd = [str(cashu_bin), "--host=" + mint_url, "receive", token]
    env = dict(os.environ)
    proc = subprocess.run(
        cmd, capture_output=True, text=True, timeout=60, env=env,
    )
    return proc.returncode, proc.stdout, proc.stderr


def run_parser_fixtures(checks):
    """Layer 1: the arbiter's melt-settlement classifier against the
    recorded 0.18.1 shapes. Runs everywhere, no CLI needed."""
    for i, shape in enumerate(_SETTLED_SHAPES):
        checks.check(
            "M1 fixture: recorded settled shape %d reads settled" % i,
            executor._melt_settled(shape),
            repr(shape[:80]),
        )
    for i, shape in enumerate(_PENDING_SHAPES):
        checks.check(
            "M1 fixture: recorded pending shape %d does NOT read settled" % i,
            not executor._melt_settled(shape),
            repr(shape[:80]),
        )
    checks.check(
        "M1 fixture: empty/None melt output does NOT read settled",
        not executor._melt_settled("") and not executor._melt_settled(None),
    )


def run_live_contract(checks, cashu_bin, workdir):
    """Layers 2b-3: drive the real pinned CLI against the ephemeral
    mint THROUGH the arbiter's own ecash.py wrapper. Wallet env is
    set process-wide because ecash._run snapshots os.environ per
    call; everything points into the temp workdir and the mint URL
    is always the loopback mint."""
    port = _free_port()
    mint_url = "http://127.0.0.1:%d" % port
    os.environ["CASHU_BIN"] = str(cashu_bin)
    os.environ["CASHU_MINT_URL"] = mint_url
    os.environ["CASHU_DIR"] = str(workdir / "wallet")
    os.environ.setdefault("CASHU_TIMEOUT_S", "60")

    mint = EphemeralMint(workdir, port, "SETTLED")
    mint.start()
    try:
        # Fund leg: quote parse contract, then issuance (BRR has
        # already marked the quote paid; no payer needed).
        quote_out = ecash.mint_quote(5000)
        try:
            _, quote_id = executor._parse_mint_quote(quote_out)
            checks.check(
                "fund leg: mint-quote stdout parses "
                "(executor._parse_mint_quote)", True,
            )
        except executor.EcashParseError:
            checks.check(
                "fund leg: mint-quote stdout parses "
                "(executor._parse_mint_quote)",
                False, _tail(quote_out),
            )
            raise ContractFailure(
                "cannot fund the test wallet without a quote id"
            )
        ecash.mint(5000, quote_id)

        # M1, settled: the backend settles instantly, so pay output
        # must read settled through the arbiter's own classifier.
        settled_out = ecash.pay(_make_bolt11(1000, "settled"))
        checks.check(
            "M1 live: settled melt reads settled "
            "(executor._melt_settled)",
            executor._melt_settled(settled_out),
            _tail(settled_out),
        )

        # M2: a DLEQ-bearing handoff token, its corrupted twin, and
        # the executor's offline decode parse.
        send_out = ecash.send(1500)
        try:
            token = executor._parse_token(send_out)
            checks.check(
                "handoff leg: send stdout parses "
                "(executor._parse_token)", True,
            )
        except executor.EcashParseError:
            checks.check(
                "handoff leg: send stdout parses "
                "(executor._parse_token)",
                False, _tail(send_out),
            )
            raise ContractFailure(
                "cannot run the DLEQ contract without a token"
            )
        claimed = executor._decode_and_pin(ecash, token)
        checks.check(
            "decode leg: mint pin + value parse "
            "(executor._decode_and_pin)",
            claimed == 1500,
            "claimed %r, sent 1500" % claimed,
        )
        corrupted, proof_count = _corrupt_dleq(token)
        checks.check(
            "M2 live: send -y -d embeds DLEQ on every proof (%d)"
            % proof_count,
            proof_count > 0,
        )
        rc, r_out, r_err = _raw_receive(cashu_bin, mint_url, corrupted)
        checks.check(
            "M2 live: corrupted-DLEQ token REJECTED at receive",
            rc != 0,
            "receive exited 0 and accepted the counterfeit: %s"
            % _tail(r_out),
        )
        checks.check(
            "M2 live: rejection names DLEQ (not some other failure)",
            "dleq" in (r_out + r_err).lower(),
            _tail(r_err),
        )
        try:
            ecash.receive(token)
            intact_ok, intact_note = True, ""
        except ecash.EcashError as e:
            intact_ok, intact_note = False, str(e)
        checks.check(
            "M2 live: intact token accepted (rejection was "
            "DLEQ-specific, wallet still functional)",
            intact_ok, intact_note,
        )
    finally:
        mint.stop()

    # M1, pending: same mint identity (key, database, port) so the
    # wallet's remaining proofs stay spendable, but the backend now
    # leaves outgoing payments pending forever - the live exit-0
    # trap. ecash.pay returning (exit 0) with un-settled output is
    # the recorded 0.18.1 behavior; a future CLI that instead exits
    # nonzero fails SAFE (the defund handler already treats a raise
    # as failure), so that shape change is noted loudly, not failed.
    mint = EphemeralMint(workdir, port, "PENDING")
    mint.start()
    try:
        try:
            pending_out = ecash.pay(_make_bolt11(1000, "pending"))
        except ecash.EcashError as e:
            print(
                "NOTE  pending melt now exits nonzero (0.18.1 exited "
                "0); safe direction, but re-verify the trap on the "
                "next pin bump: %s" % str(e)[:160]
            )
            pending_out = ""
        checks.check(
            "M1 live: pending melt does NOT read settled "
            "(the exit-0 trap)",
            not executor._melt_settled(pending_out),
            _tail(pending_out),
        )
    finally:
        mint.stop()


def run_smoke(checks, workdir):
    """Hermetic self-test of the gate's own plumbing: pin parsing,
    version extraction against a fake CLI, mismatch detection, and
    CLI resolution. No nutshell, no mint, no network."""
    pin_file = workdir / "pin.yaml"
    pin_file.write_text(
        "# comment\ncashu_pin_version: 1.2.3  # trailing\n",
        encoding="utf-8",
    )
    checks.check(
        "smoke: pin file parses (comments stripped)",
        read_pin(pin_file) == "1.2.3",
        repr(read_pin(pin_file)),
    )
    checks.check(
        "smoke: missing pin file reads as None",
        read_pin(workdir / "nope.yaml") is None,
    )
    pin_file.write_text("cashu_pin_version:\n", encoding="utf-8")
    checks.check(
        "smoke: empty pin value reads as None",
        read_pin(pin_file) is None,
    )
    pin_file.write_text("unrelated_key: 9\n", encoding="utf-8")
    checks.check(
        "smoke: unrelated keys read as None",
        read_pin(pin_file) is None,
    )

    fake = workdir / "cashu"
    fake.write_text(
        "#!/bin/sh\n"
        "# fake cashu for the mint-contract smoke test: canned info\n"
        "echo 'Generated a new mnemonic. To view it, run"
        " \"cashu info --mnemonic\".'\n"
        "echo 'Version: 9.9.9'\n"
        "echo 'Wallet: wallet'\n",
        encoding="utf-8",
    )
    fake.chmod(0o755)
    ver = cli_version(fake, workdir)
    checks.check(
        "smoke: version parsed from `cashu info` amid preamble noise",
        ver == "9.9.9",
        repr(ver),
    )
    checks.check(
        "smoke: version-gate comparison detects drift",
        ver != "0.18.1",
    )

    failing = workdir / "cashu-broken"
    failing.write_text(
        "#!/bin/sh\necho 'boom' >&2\nexit 3\n", encoding="utf-8"
    )
    failing.chmod(0o755)
    try:
        cli_version(failing, workdir)
        raised = False
    except ContractFailure:
        raised = True
    checks.check(
        "smoke: failing CLI surfaces as ContractFailure",
        raised,
    )

    prior = os.environ.get("CASHU_BIN")
    os.environ["CASHU_BIN"] = str(workdir / "does-not-exist")
    missing_is_none = resolve_cli() is None
    if prior is None:
        os.environ.pop("CASHU_BIN", None)
    else:
        os.environ["CASHU_BIN"] = prior
    checks.check(
        "smoke: absent CLI resolves to None (skip path)",
        missing_is_none,
    )


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    smoke = argv == ["--smoke"]
    if argv and not smoke:
        print("unknown arguments: %s" % argv, file=sys.stderr)
        return 2

    # Land in the nutshell python env before any checks print, so
    # the live layer can import cashu/bolt11 and host the ephemeral
    # mint. Guarded against loops; smoke mode never re-execs.
    if not smoke and not _cashu_importable():
        cli = resolve_cli()
        if cli is not None and os.environ.get(_REEXEC_MARKER) != "1":
            py = _nutshell_python(cli)
            if py is not None:
                env = dict(os.environ)
                env[_REEXEC_MARKER] = "1"
                os.execve(
                    str(py),
                    [str(py), str(Path(__file__).resolve())] + argv,
                    env,
                )

    checks = Checks()
    label = "mint-contract smoke" if smoke else "mint-contract"
    workdir = Path(tempfile.mkdtemp(prefix="mint-contract-"))
    try:
        run_parser_fixtures(checks)

        if smoke:
            run_smoke(checks, workdir)
            return checks.summary(label)

        cli = resolve_cli()
        if cli is None:
            if os.environ.get("MINT_CONTRACT_REQUIRE_CLI") == "1":
                checks.check(
                    "pinned cashu CLI installed "
                    "(MINT_CONTRACT_REQUIRE_CLI=1)",
                    False,
                    "no CLI at CASHU_BIN or the deployed default; an "
                    "eCash build must install the pinned nutshell",
                )
            else:
                print(
                    "SKIP  version pin + live CLI contract: no cashu "
                    "CLI at CASHU_BIN or the deployed default "
                    "(hermetic checkout; parser fixtures above still "
                    "gate; eCash builds set MINT_CONTRACT_REQUIRE_CLI=1)"
                )
            return checks.summary(label)

        pin = read_pin(PIN_PATH)
        if not checks.check(
            "version pin present in config/cashu-pin.yaml",
            pin is not None,
            str(PIN_PATH),
        ):
            return checks.summary(label)
        try:
            installed = cli_version(cli, workdir)
        except ContractFailure as e:
            checks.check(
                "`cashu info` reports a parseable version",
                False, str(e),
            )
            return checks.summary(label)
        if not checks.check(
            "installed CLI version matches the pin (%s)" % pin,
            installed == pin,
            "installed %s, pinned %s; a CLI upgrade must be a "
            "reviewed pin bump (impl companion §2)" % (installed, pin),
        ):
            # A drifted CLI already fails the build; the live layer
            # against the wrong version would only stack confusing
            # secondary failures on top.
            return checks.summary(label)

        if not _cashu_importable():
            checks.check(
                "nutshell python env available for the ephemeral mint",
                False,
                "cashu CLI exists but `import cashu` fails under %s "
                "and no interpreter was derivable from the CLI "
                "shebang; set MINT_CONTRACT_PYTHON" % sys.executable,
            )
            return checks.summary(label)

        try:
            run_live_contract(checks, cli, workdir)
        except (ecash.EcashError, executor.EcashParseError,
                ContractFailure) as e:
            checks.check(
                "live mint contract run completed",
                False,
                "%s: %s" % (type(e).__name__, e),
            )
        return checks.summary(label)
    finally:
        if checks.failed:
            print("failure artifacts kept at %s" % workdir)
        else:
            shutil.rmtree(workdir, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
