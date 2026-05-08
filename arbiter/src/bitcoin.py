"""
Bitcoin client access: subprocess wrapper for the locally self-hosted
bitcoind under arbiter/bitcoin/.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.2.

Wrapper choice: this module shells out to the bitcoin-cli binary
directly via subprocess (argv list, no shell). It deliberately does
NOT depend on the test-harness/scripts/btccli convenience wrapper.
That shell wrapper is for human use at the arbiter console; it
prepends -datadir and execs bitcoin-cli, but it adds a layer of
shell-quoting and PATH resolution between the audited Python code
and the binary call. The production arbiter must control the binary
path, datadir, and argv list explicitly so a non-AI reviewer can
audit exactly what executes (§2.1). A reviewer can read this module
and the bitcoin-cli man page in one sitting; with the shell wrapper
they would need to read the wrapper too and convince themselves the
two layers compose without surprises.

Hide-secrets discipline (§4.2 + Hide secrets glossary entry): coin
selection and signing happen inside bitcoind itself. The send path
here is sendtoaddress, which runs build / sign / broadcast as one
RPC and returns only the resulting txid. Descriptors, change
addresses, the selected UTXO set, and any PSBT bitcoind constructs
during signing never reach this module's caller, so they cannot
leak through the privacy gateway downstream.

Read-only return values (chain info, balance) DO surface here as
plain dicts and Decimals; the privacy gateway is responsible for
banding and aggregating those before they cross the AI-facing
boundary (§4.1: filtering lives in the gateway, not here).

The arbiter <-> bitcoind link is on the trusted side of the privacy
boundary, so this module applies no additional anti-cadence or
anti-timing mitigation between itself and bitcoind. Petitioner-
facing mitigations (action delay, result delay, the privacy
gateway's latency normalization) cover that link in aggregate.

Stdlib only.
"""
import json
import os
import subprocess
from decimal import Decimal
from pathlib import Path

# Deployment defaults match §9 (repository layout) and the
# test-harness/scripts/btccli wrapper. Both are env-overridable so
# the test harness can point at an alternative install layout
# without editing source. The defaults are absolute paths under the
# user's home so the arbiter does not depend on the caller's CWD.
DEFAULT_BIN = Path.home() / "spacer" / "arbiter" / "bin" / "bitcoin-cli"
DEFAULT_DATADIR = Path.home() / "spacer" / "arbiter" / "bitcoin"

# Hard cap on bitcoin-cli wall time. The binary is local IPC against
# a long-running bitcoind; routine RPCs return in milliseconds. A
# stall longer than this means bitcoind is wedged, in initial block
# download, or the binary is mis-pointed; in any of those cases the
# caller (gateway dispatch) treats the timeout as a refusal and
# audit-logs the cause. Override via BITCOIN_CLI_TIMEOUT_S for slow
# IBD scenarios.
DEFAULT_TIMEOUT_S = 30.0


class BitcoinError(Exception):
    """Raised on any bitcoin-cli failure: non-zero exit, timeout,
    binary missing, JSON parse failure, or unexpected output shape.
    The dispatch layer catches this at the arbiter-internals
    boundary, audit-logs the cause, and returns the uniform refusal
    to the petitioner. The exception message stays inside the
    arbiter; it never crosses the privacy gateway."""


def _bin_path():
    """Resolve the bitcoin-cli binary. Env override BITCOIN_CLI_BIN
    takes precedence, else DEFAULT_BIN."""
    return Path(os.environ.get("BITCOIN_CLI_BIN", DEFAULT_BIN))


def _datadir():
    """Resolve the bitcoind datadir. Env override BITCOIN_DATADIR
    takes precedence, else DEFAULT_DATADIR."""
    return Path(os.environ.get("BITCOIN_DATADIR", DEFAULT_DATADIR))


def _timeout_s():
    """Resolve the per-call wall-time cap. Env override
    BITCOIN_CLI_TIMEOUT_S takes precedence."""
    return float(os.environ.get("BITCOIN_CLI_TIMEOUT_S", DEFAULT_TIMEOUT_S))


def _run(*args):
    """Invoke bitcoin-cli with -datadir prepended; return stdout as
    a string. Raises BitcoinError on any failure.

    Argv-list form (no shell): each argument is passed as a separate
    process argv entry, so AI-reachable string fields (after the
    privacy gateway has resolved them through the recipient address
    registry) flow through without shell-metacharacter expansion.
    Every argv element is stringified explicitly so a numeric amount
    or boolean flag becomes the same exact bytes bitcoin-cli would
    receive on the command line.
    """
    cmd = [str(_bin_path()), f"-datadir={_datadir()}"] + [str(a) for a in args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_timeout_s(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise BitcoinError(f"bitcoin-cli timed out after {_timeout_s()}s")
    except FileNotFoundError:
        raise BitcoinError(f"bitcoin-cli not found at {cmd[0]}")
    if result.returncode != 0:
        # bitcoin-cli's stderr can mention amounts, txids, or
        # descriptor fragments. We retain it inside the exception
        # so the dispatch layer can audit-log the cause; the
        # petitioner only ever sees the uniform refusal so the
        # string never crosses the privacy gateway. Truncate at
        # 200 chars to discourage any caller from surfacing it
        # verbatim.
        raise BitcoinError(
            f"bitcoin-cli exited {result.returncode}: "
            f"{result.stderr.strip()[:200]}"
        )
    return result.stdout


def _run_json(*args):
    """Invoke bitcoin-cli and parse stdout as JSON. Most non-trivial
    RPCs return JSON objects; this is the standard path."""
    out = _run(*args)
    try:
        return json.loads(out)
    except ValueError:
        raise BitcoinError("bitcoin-cli output was not valid JSON")


# Read-only RPCs. These return precise values; the gateway bands and
# aggregates them on the way out.

def getblockchaininfo():
    """Return bitcoind chain status as a dict: chain (network name),
    blocks (best block height), initialblockdownload, and the rest
    of bitcoind's standard fields. The gateway redacts and bands
    fields before sending to the petitioner; this function returns
    the raw dict for arbiter-internal use."""
    return _run_json("getblockchaininfo")


def getbalance(minconf=1):
    """Return the wallet's confirmed balance as a Decimal in BTC.

    bitcoin-cli's getbalance prints a JSON-encoded number ("0.001").
    We parse via Decimal rather than float to preserve satoshi
    precision; 1 sat = 1e-8 BTC, which is at the edge of float64
    representable values, and float -> str round-trip can shift the
    value by a sat in adversarial cases.

    The gateway bands this value before exposing it to the
    petitioner; this function returns the precise balance for
    arbiter-internal use (e.g., the timing layer's pre-flight
    check that the wallet can fund a pending action before it
    becomes due).
    """
    out = _run("getbalance", "*", str(minconf)).strip()
    try:
        return Decimal(out)
    except Exception:
        raise BitcoinError(f"could not parse getbalance output: {out!r}")


# State-changing RPCs. These are gated by the outbound allowlist
# upstream in the gateway; this module trusts its caller to have
# passed the allowlist + token-resolution path.

def sendtoaddress(address, amount_btc):
    """Send amount_btc to address. Returns the txid (64-char hex).

    bitcoind performs the entire transaction lifecycle internally:
    coin selection from the wallet's UTXO set, change-address
    derivation, signing with the wallet's keys, and broadcast to
    the P2P network. The only return value is a single txid.

    Per §4.2 and the Hide secrets glossary entry, this matches the
    arbiter's discipline at the bitcoind boundary: the PSBT, the
    descriptor, the change address, and the selected UTXO set that
    bitcoind constructs during signing never reach this module's
    caller, so they cannot leak through the privacy gateway. A
    reviewer can confirm by reading bitcoin-cli's man page that
    sendtoaddress's return shape is just a txid string.

    Caller responsibility:
    - address is the **real** Bitcoin address, already resolved
      from the petitioner's token by the recipient address
      registry (sp-77lxs.13). The AI never reaches this function
      directly: an inbound state-changing call goes through the
      gateway's allowlist, the registry's token-to-real
      resolution, and the timing layer's action-delay queue
      before the executor calls into here.
    - amount_btc is a string in BTC decimal form ("0.001"), or a
      Decimal. Never pass a Python float: float -> str loses
      satoshi precision (1 sat = 1e-8 BTC is at the edge of
      float64) so a 1-sat dust attack could be triggered by an
      otherwise-correct caller.

    On any failure (RPC error, wallet locked, insufficient funds,
    malformed address, network not synced) bitcoin-cli exits
    non-zero and this function raises BitcoinError. The caller
    treats the raise as the action having failed; whatever audit
    log entry the caller wrote on submit is paired with a
    decision_action_failed entry at the dispatch layer.
    """
    txid = _run("sendtoaddress", str(address), str(amount_btc)).strip()
    # Defense-in-depth shape check: bitcoin-cli should print exactly
    # the txid (64 lowercase hex chars). Any deviation means we got
    # a different output and a downstream caller would mis-audit.
    if len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
        raise BitcoinError(f"unexpected sendtoaddress output: {txid!r}")
    return txid


def gettransaction(txid):
    """Return the wallet's view of a transaction (confirmations,
    blockhash, time, amount). Used by the dispatch layer after the
    timing layer's action-delay window elapses, to confirm the
    broadcast landed before queueing the result for delivery via
    the result registry.

    Returns the raw bitcoind dict; the gateway redacts fields
    before exposing to the petitioner."""
    if len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
        raise BitcoinError(f"invalid txid: {txid!r}")
    return _run_json("gettransaction", txid)


if __name__ == "__main__":
    # Smoke test: a fake bitcoin-cli script lets us exercise argv
    # construction, JSON parsing, and error paths without a live
    # bitcoind. The fake is invoked through the same subprocess.run
    # / argv path as the real binary, so we cover the full stack
    # except bitcoind itself. Live bitcoind coverage lands in the
    # end-to-end validation (sp-77lxs.15).
    import shutil
    import sys
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="arbiter-bitcoin-smoke-"))
    fake = work / "bitcoin-cli"
    argv_log = work / "argv.log"
    # The fake echoes its full argv (including -datadir=) to a side
    # file so the test can assert exact arg propagation, then
    # dispatches a canned reply per the first non-flag arg.
    fake.write_text(
        f"""#!/bin/sh
# Fake bitcoin-cli for arbiter/src/bitcoin.py smoke test.
echo "$@" >> {argv_log}
# Drop the -datadir= flag (always first per _run).
case "$1" in -datadir=*) shift;; esac
case "$1" in
  getblockchaininfo)
    printf '{{"chain":"signet","blocks":42,"initialblockdownload":false}}'
    ;;
  getbalance)
    printf '0.00100000'
    ;;
  sendtoaddress)
    printf '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
    ;;
  gettransaction)
    printf '{{"confirmations":3,"txid":"%s"}}' "$2"
    ;;
  failboom)
    echo "wallet is locked" >&2
    exit 1
    ;;
  notjson)
    printf '<<<not json>>>'
    ;;
  badtxid)
    printf 'not_a_real_txid'
    ;;
  slow)
    sleep 5
    ;;
  *)
    echo "unknown rpc: $1" >&2
    exit 64
    ;;
esac
"""
    )
    fake.chmod(0o755)
    os.environ["BITCOIN_CLI_BIN"] = str(fake)
    os.environ["BITCOIN_DATADIR"] = str(work)
    os.environ["BITCOIN_CLI_TIMEOUT_S"] = "1.0"

    try:
        # Read-only round-trip.
        info = getblockchaininfo()
        assert info == {
            "chain": "signet",
            "blocks": 42,
            "initialblockdownload": False,
        }, info

        # Balance returns Decimal at full precision.
        bal = getbalance()
        assert bal == Decimal("0.00100000"), bal
        assert isinstance(bal, Decimal)

        # Send returns the txid; argv had address and amount in order.
        good_addr = "tb1qexampleaddressexampleaddressexample0"
        good_amt = "0.0005"
        txid = sendtoaddress(good_addr, good_amt)
        assert txid == "0123456789abcdef" * 4, txid

        # Inspect a known-good txid round-trip.
        tx = gettransaction(txid)
        assert tx["confirmations"] == 3, tx
        assert tx["txid"] == txid, tx

        # gettransaction shape-checks its arg before invoking the
        # binary: a malformed txid is rejected without an exec.
        raised = False
        try:
            gettransaction("zzzz")
        except BitcoinError:
            raised = True
        assert raised, "gettransaction must reject malformed txid"

        # Non-zero exit becomes BitcoinError. The stderr fragment is
        # captured for audit but truncated to discourage echoing.
        raised = False
        try:
            _run("failboom")
        except BitcoinError as e:
            raised = "exited 1" in str(e)
        assert raised, "non-zero exit must raise"

        # Malformed JSON becomes BitcoinError.
        raised = False
        try:
            _run_json("notjson")
        except BitcoinError:
            raised = True
        assert raised, "bad JSON must raise"

        # sendtoaddress shape-checks the returned txid; build a
        # second fake that returns a bogus txid so we exercise the
        # shape check rather than the happy path.
        fake2 = work / "bitcoin-cli-bogus"
        fake2.write_text(
            "#!/bin/sh\n"
            "case \"$1\" in -datadir=*) shift;; esac\n"
            "case \"$1\" in\n"
            "  sendtoaddress) printf 'not_a_real_txid';;\n"
            "  *) exit 64;;\n"
            "esac\n"
        )
        fake2.chmod(0o755)
        os.environ["BITCOIN_CLI_BIN"] = str(fake2)
        raised = False
        try:
            sendtoaddress(good_addr, good_amt)
        except BitcoinError as e:
            raised = "unexpected sendtoaddress output" in str(e)
        assert raised, "malformed txid output must raise"
        os.environ["BITCOIN_CLI_BIN"] = str(fake)

        # Timeout: the fake sleeps 5s; the cap is 1s.
        raised = False
        try:
            _run("slow")
        except BitcoinError as e:
            raised = "timed out" in str(e)
        assert raised, "timeout must raise"

        # Missing binary: a clean error rather than an OSError leak.
        os.environ["BITCOIN_CLI_BIN"] = "/nonexistent/path/bitcoin-cli"
        raised = False
        try:
            _run("getblockchaininfo")
        except BitcoinError as e:
            raised = "not found" in str(e)
        assert raised, "missing binary must raise"
        os.environ["BITCOIN_CLI_BIN"] = str(fake)

        # Argv assertion: -datadir was passed exactly once per call,
        # and downstream args (rpc name, address, amount) propagated
        # in the right order without shell expansion.
        argv = argv_log.read_text()
        assert "-datadir=" in argv, argv
        assert "getblockchaininfo" in argv, argv
        # sendtoaddress argv line: "-datadir=<dir> sendtoaddress <addr> <amt>"
        assert f"sendtoaddress {good_addr} {good_amt}" in argv, argv

        print(f"OK: bitcoin-cli wrapper round-trips at {work}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    sys.exit(0)
