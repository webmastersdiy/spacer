"""
LND client access: subprocess wrapper for the deployment's LND
instance via lncli.

Per design-docs/2026-05-05-0948-architecture-overview.md §4.3.

Wrapper choice: this module shells out to lncli directly via
subprocess (argv list, no shell). It deliberately does NOT depend
on the test-harness/scripts/lncliA convenience wrapper. That shell
wrapper is testbed-specific (Voltage-hosted Node A on Mutinynet)
and prepends connection flags before exec'ing lncli; the production
arbiter must control the binary path, TLS cert path, macaroon path,
RPC server, and network explicitly so a non-AI reviewer can audit
exactly what executes (§2.1). A reviewer can read this module and
the lncli man page in one sitting; with the shell wrapper they
would need to read the wrapper too and convince themselves the
two layers compose without surprises.

lncli speaks gRPC to lnd under the hood, so "wrapped access over
lncli plus gRPC/REST" reduces here to lncli; the gRPC channel is
already what lncli uses. A future bead can swap to a direct gRPC
client if the binary footprint becomes a constraint, but the
auditability tradeoff currently favors the CLI: lncli's flag
surface is documented and stable, and the argv list this module
constructs is something a reviewer can reproduce by hand.

Hide-secrets discipline (§4.3 + Hide secrets glossary entry):
HTLC-level secrets (preimages, full route, per-hop fee detail) and
channel-state internals stay inside lnd and surface here only as
JSON fields. The privacy gateway is responsible for redacting and
banding those before they cross the AI-facing boundary (§4.1).
This module returns the raw JSON dicts for arbiter-internal use.

Default --private channels (Mitigation map §6, "default --private
channels"): openchannel here passes --private by default. AI-facing
this hides the channel from the petitioner's listchannels view;
world-facing it suppresses the gossip entry so the LN graph does
not learn the new edge. A caller can override to a public channel
by passing private=False, but the default biases toward less
leakage.

The arbiter <-> LND link is on the trusted side of the privacy
boundary, so this module applies no additional anti-cadence or
anti-timing mitigation between itself and lnd. Petitioner-facing
mitigations (action delay, result delay, the privacy gateway's
latency normalization) cover that link in aggregate.

Stdlib only.
"""
import json
import os
import subprocess
from pathlib import Path

# Deployment defaults match §9 (repository layout) and the
# test-harness/scripts/lncliA wrapper. All env-overridable so the
# test harness or a redeployment can point at an alternative install
# layout without editing source. Defaults are absolute paths under
# the user's home so the arbiter does not depend on the caller's CWD.
DEFAULT_BIN = Path.home() / "spacer" / "arbiter" / "bin" / "lncli"
DEFAULT_TLS_CERT = Path.home() / "spacer" / "arbiter" / "lnd" / "tls.cert"
DEFAULT_MACAROON = Path.home() / "spacer" / "arbiter" / "lnd" / "admin.macaroon"
DEFAULT_RPCSERVER = "localhost:10009"
DEFAULT_NETWORK = "signet"

# Hard cap on lncli wall time. lncli is local IPC against a
# long-running lnd; routine RPCs return in milliseconds, but
# payinvoice can take seconds while routes are explored and HTLCs
# settle through the network. 60s covers payinvoice; tighter caps
# (e.g., for read-only RPCs) come from the caller via env override.
# A stall longer than this means lnd is wedged, the network is
# unreachable, or the binary is mis-pointed; in any of those cases
# the caller treats the timeout as a refusal and audit-logs the
# cause. Override via LNCLI_TIMEOUT_S.
DEFAULT_TIMEOUT_S = 60.0


class LndError(Exception):
    """Raised on any lncli failure: non-zero exit, timeout, binary
    missing, JSON parse failure, or unexpected output shape. The
    dispatch layer catches this at the arbiter-internals boundary,
    audit-logs the cause, and returns the uniform refusal to the
    petitioner. The exception message stays inside the arbiter; it
    never crosses the privacy gateway."""


def _bin_path():
    """Resolve the lncli binary. Env override LNCLI_BIN takes
    precedence, else DEFAULT_BIN."""
    return Path(os.environ.get("LNCLI_BIN", DEFAULT_BIN))


def _tls_cert():
    """Resolve the lnd TLS cert path. Env override LNCLI_TLSCERT
    takes precedence, else DEFAULT_TLS_CERT."""
    return Path(os.environ.get("LNCLI_TLSCERT", DEFAULT_TLS_CERT))


def _macaroon():
    """Resolve the lnd admin macaroon path. Env override LNCLI_MACAROON
    takes precedence, else DEFAULT_MACAROON."""
    return Path(os.environ.get("LNCLI_MACAROON", DEFAULT_MACAROON))


def _rpcserver():
    """Resolve the lnd gRPC endpoint. Env override LNCLI_RPCSERVER
    takes precedence, else DEFAULT_RPCSERVER."""
    return os.environ.get("LNCLI_RPCSERVER", DEFAULT_RPCSERVER)


def _network():
    """Resolve the lnd network. Env override LNCLI_NETWORK takes
    precedence, else DEFAULT_NETWORK."""
    return os.environ.get("LNCLI_NETWORK", DEFAULT_NETWORK)


def _timeout_s():
    """Resolve the per-call wall-time cap. Env override
    LNCLI_TIMEOUT_S takes precedence."""
    return float(os.environ.get("LNCLI_TIMEOUT_S", DEFAULT_TIMEOUT_S))


def _run(*args):
    """Invoke lncli with connection flags prepended; return stdout
    as a string. Raises LndError on any failure.

    Argv-list form (no shell): each argument is passed as a separate
    process argv entry, so AI-reachable string fields (after the
    privacy gateway has resolved them through the recipient address
    registry) flow through without shell-metacharacter expansion.
    Every argv element is stringified explicitly so a numeric amount
    or boolean flag becomes the same exact bytes lncli would receive
    on the command line.

    The four connection flags (--rpcserver, --tlscertpath,
    --macaroonpath, --network) are always prepended in the same
    order. The smoke-test fake script and any human reviewer can
    read this single _run helper and know the entire connection
    surface.
    """
    cmd = [
        str(_bin_path()),
        f"--rpcserver={_rpcserver()}",
        f"--tlscertpath={_tls_cert()}",
        f"--macaroonpath={_macaroon()}",
        f"--network={_network()}",
    ] + [str(a) for a in args]
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_timeout_s(),
            check=False,
        )
    except subprocess.TimeoutExpired:
        raise LndError(f"lncli timed out after {_timeout_s()}s")
    except FileNotFoundError:
        raise LndError(f"lncli not found at {cmd[0]}")
    if result.returncode != 0:
        # lncli's stderr can mention amounts, pubkeys, payment
        # hashes, or route fragments. We retain it inside the
        # exception so the dispatch layer can audit-log the cause;
        # the petitioner only ever sees the uniform refusal so the
        # string never crosses the privacy gateway. Truncate at
        # 200 chars to discourage any caller from surfacing it
        # verbatim.
        raise LndError(
            f"lncli exited {result.returncode}: "
            f"{result.stderr.strip()[:200]}"
        )
    return result.stdout


def _run_json(*args):
    """Invoke lncli and parse stdout as JSON. lncli emits JSON for
    its standard RPC outputs; this is the normal path."""
    out = _run(*args)
    try:
        return json.loads(out)
    except ValueError:
        raise LndError("lncli output was not valid JSON")


# Read-only RPCs. These return precise values; the gateway bands
# and aggregates them on the way out (§4.1).

def getinfo():
    """Return lnd node status as a dict: identity_pubkey, alias,
    block_height, synced_to_chain, synced_to_graph,
    num_active_channels, and the rest of lnd's standard fields. The
    gateway redacts and bands fields before sending to the
    petitioner; this function returns the raw dict for
    arbiter-internal use (e.g., the timing layer's pre-flight check
    that the node is synced before a queued action becomes due)."""
    return _run_json("getinfo")


def walletbalance():
    """Return lnd's on-chain wallet balance dict: total_balance,
    confirmed_balance, unconfirmed_balance, and per-account
    breakdowns. lncli emits the satoshi values as decimal strings
    of integers ('100000'); we return them unchanged so the
    gateway's banding sees integer-precision input and the arbiter
    never round-trips through float."""
    return _run_json("walletbalance")


def channelbalance():
    """Return lnd's Lightning channel balance dict: local_balance,
    remote_balance, unsettled_local_balance, pending_open_balance,
    and bucketed sub-totals. As with walletbalance, satoshi values
    are decimal-string integers and are returned unchanged. The
    gateway bands these on outbound; this function returns the raw
    dict for arbiter-internal balance checks."""
    return _run_json("channelbalance")


# State-changing RPCs. These are gated by the outbound allowlist
# upstream in the gateway; this module trusts its caller to have
# passed the allowlist + token-resolution path.

def sendcoins(address, amount_sat):
    """Send amount_sat satoshis on-chain to address. Returns the
    txid (64-char lowercase hex) extracted from lncli's JSON
    response.

    lnd performs the entire on-chain transaction lifecycle
    internally: coin selection from the wallet's UTXOs,
    change-address derivation, signing, and broadcast. The only
    return value is a single txid.

    Per §4.3 and the Hide secrets glossary entry, this matches the
    arbiter's discipline at the lnd boundary: the change address,
    the selected UTXO set, and the signed tx body never reach this
    module's caller, so they cannot leak through the privacy
    gateway.

    Caller responsibility:
    - address is the **real** Bitcoin address, already resolved
      from the petitioner's token by the recipient address registry
      (sp-77lxs.13). The AI never reaches this function directly:
      an inbound state-changing call goes through the gateway's
      allowlist, the registry's token-to-real resolution, and the
      timing layer's action-delay queue before the executor calls
      into here.
    - amount_sat is an integer number of satoshis. Pass an int (or
      a string of digits); never a Python float. lncli's --amt
      takes integer satoshis, so float values would either be
      rejected or silently truncated.
    """
    out = _run_json(
        "sendcoins", f"--addr={address}", f"--amt={amount_sat}"
    )
    txid = (out.get("txid") or "").strip()
    if len(txid) != 64 or any(c not in "0123456789abcdef" for c in txid):
        raise LndError(f"unexpected sendcoins output: {out!r}")
    return txid


def payinvoice(payment_request):
    """Pay a BOLT-11 invoice. Returns the lncli payinvoice JSON dict
    (status, payment_preimage, payment_hash, value_msat, fee_msat,
    failure_reason, htlcs, ...). The gateway redacts fields and
    bands the success/fail signal + fee band before the petitioner
    sees it.

    -f (force) suppresses lncli's interactive y/N confirmation
    prompt. Without it lncli would block on stdin for a
    confirmation; the arbiter has no operator at the lncli stdin
    (the operator-facing channel is the directly-attached console,
    not lncli), so we always pass -f.

    Caller responsibility:
    - payment_request is the BOLT-11 invoice string the petitioner
      supplied. Per §4.7's recipient address registry, BOLT-11
      invoices that are too long to retype reliably enter via a
      registry pseudonym; the gateway resolves the token to the
      real invoice before this function is called.
    """
    return _run_json(
        "payinvoice", "-f", f"--pay_req={payment_request}"
    )


def openchannel(node_pubkey, local_amount_sat, private=True):
    """Open a Lightning channel to node_pubkey, funding
    local_amount_sat satoshis from this node's on-chain wallet.
    Returns the lncli openchannel JSON dict (funding_txid,
    output_index).

    private defaults to True per Mitigation map §6 ("default
    --private channels"). This passes lncli's --private flag,
    which sets the channel's announce_channel=False at funding
    time. AI-facing this hides the channel from the petitioner's
    listchannels view; world-facing it suppresses the gossip entry
    so the LN graph does not learn the new edge. A caller can
    override to a public channel by passing private=False, but the
    default biases toward less leakage and a reviewer reading this
    module sees that bias in one place.

    Caller responsibility:
    - node_pubkey is the **real** counterparty pubkey, already
      resolved from any petitioner-facing token by the registry /
      gateway. lncli requires the peer to already be connected
      (`lncli connect`); peer connection is not handled here and
      is part of operator-side setup before the channel-open call
      reaches the arbiter.
    - local_amount_sat is an integer number of satoshis.
    """
    args = [
        "openchannel",
        f"--node_key={node_pubkey}",
        f"--local_amt={local_amount_sat}",
    ]
    if private:
        args.append("--private")
    return _run_json(*args)


if __name__ == "__main__":
    # Smoke test: a fake lncli script lets us exercise argv
    # construction, JSON parsing, --private default behavior, and
    # error paths without a live lnd. The fake is invoked through
    # the same subprocess.run / argv path as the real binary, so we
    # cover the full stack except lnd itself. Live lnd coverage
    # lands in the end-to-end validation (sp-77lxs.15).
    import shutil
    import sys
    import tempfile

    work = Path(tempfile.mkdtemp(prefix="arbiter-lnd-smoke-"))
    fake = work / "lncli"
    argv_log = work / "argv.log"
    # The fake echoes its full argv (including connection flags) to
    # a side file so the test can assert exact arg propagation,
    # then dispatches a canned reply per the first non-flag arg.
    # The connection-flag-stripping loop mirrors what _run prepends:
    # all four flags are dropped before the dispatch case picks the
    # RPC name.
    fake.write_text(
        f"""#!/bin/sh
# Fake lncli for arbiter/src/lnd.py smoke test.
echo "$@" >> {argv_log}
while [ $# -gt 0 ]; do
  case "$1" in
    --rpcserver=*|--tlscertpath=*|--macaroonpath=*|--network=*) shift;;
    *) break;;
  esac
done
case "$1" in
  getinfo)
    printf '{{"identity_pubkey":"02abc","alias":"node-A","synced_to_chain":true,"block_height":42}}'
    ;;
  walletbalance)
    printf '{{"total_balance":"100000","confirmed_balance":"100000","unconfirmed_balance":"0"}}'
    ;;
  channelbalance)
    printf '{{"local_balance":{{"sat":"50000","msat":"50000000"}},"remote_balance":{{"sat":"30000","msat":"30000000"}}}}'
    ;;
  sendcoins)
    printf '{{"txid":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}'
    ;;
  payinvoice)
    printf '{{"status":"SUCCEEDED","payment_preimage":"deadbeef","fee_msat":"1000"}}'
    ;;
  openchannel)
    printf '{{"funding_txid":"abc","output_index":0}}'
    ;;
  failboom)
    echo "node not synced" >&2
    exit 1
    ;;
  notjson)
    printf '<<<not json>>>'
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
    os.environ["LNCLI_BIN"] = str(fake)
    os.environ["LNCLI_TLSCERT"] = str(work / "tls.cert")
    os.environ["LNCLI_MACAROON"] = str(work / "admin.macaroon")
    os.environ["LNCLI_RPCSERVER"] = "fake:10009"
    os.environ["LNCLI_NETWORK"] = "signet"
    os.environ["LNCLI_TIMEOUT_S"] = "1.0"

    try:
        # Read-only round-trips.
        info = getinfo()
        assert info["identity_pubkey"] == "02abc", info
        assert info["synced_to_chain"] is True, info

        wbal = walletbalance()
        assert wbal["confirmed_balance"] == "100000", wbal

        cbal = channelbalance()
        assert cbal["local_balance"]["sat"] == "50000", cbal

        # Send returns the txid; argv had --addr= and --amt= flags.
        good_addr = "tb1qexampleaddressexampleaddressexample0"
        good_amt = 50000
        txid = sendcoins(good_addr, good_amt)
        assert txid == "0123456789abcdef" * 4, txid

        # Pay invoice surfaces the JSON dict; status is preserved.
        pay = payinvoice("lntb1pexampleinvoice")
        assert pay["status"] == "SUCCEEDED", pay
        assert pay["payment_preimage"] == "deadbeef", pay

        # Open channel: --private must be passed by default.
        chan = openchannel("02deadbeef", 100000)
        assert chan["funding_txid"] == "abc", chan
        argv = argv_log.read_text()
        last_open = [
            ln for ln in argv.splitlines() if "openchannel" in ln
        ][-1]
        assert "--private" in last_open, last_open

        # Open channel with private=False omits --private. Verifies
        # the override path; the default-private behavior above is
        # what the mitigation map relies on.
        chan_pub = openchannel("02deadbeef", 100000, private=False)
        assert chan_pub["funding_txid"] == "abc", chan_pub
        last_open_pub = [
            ln for ln in argv_log.read_text().splitlines()
            if "openchannel" in ln
        ][-1]
        assert "--private" not in last_open_pub, last_open_pub

        # Non-zero exit becomes LndError. The stderr fragment is
        # captured for audit but truncated to discourage echoing.
        raised = False
        try:
            _run("failboom")
        except LndError as e:
            raised = "exited 1" in str(e)
        assert raised, "non-zero exit must raise"

        # Malformed JSON becomes LndError.
        raised = False
        try:
            _run_json("notjson")
        except LndError:
            raised = True
        assert raised, "bad JSON must raise"

        # sendcoins shape-checks the returned txid; build a second
        # fake that returns a bogus txid so we exercise the shape
        # check rather than the happy path.
        fake2 = work / "lncli-bogus"
        fake2.write_text(
            "#!/bin/sh\n"
            "while [ $# -gt 0 ]; do\n"
            "  case \"$1\" in\n"
            "    --rpcserver=*|--tlscertpath=*|--macaroonpath=*|--network=*) shift;;\n"
            "    *) break;;\n"
            "  esac\n"
            "done\n"
            "case \"$1\" in\n"
            "  sendcoins) printf '{\"txid\":\"not_a_real_txid\"}';;\n"
            "  *) exit 64;;\n"
            "esac\n"
        )
        fake2.chmod(0o755)
        os.environ["LNCLI_BIN"] = str(fake2)
        raised = False
        try:
            sendcoins(good_addr, good_amt)
        except LndError as e:
            raised = "unexpected sendcoins output" in str(e)
        assert raised, "malformed txid output must raise"
        os.environ["LNCLI_BIN"] = str(fake)

        # Timeout: the fake sleeps 5s; the cap is 1s.
        raised = False
        try:
            _run("slow")
        except LndError as e:
            raised = "timed out" in str(e)
        assert raised, "timeout must raise"

        # Missing binary: a clean error rather than an OSError leak.
        os.environ["LNCLI_BIN"] = "/nonexistent/path/lncli"
        raised = False
        try:
            _run("getinfo")
        except LndError as e:
            raised = "not found" in str(e)
        assert raised, "missing binary must raise"
        os.environ["LNCLI_BIN"] = str(fake)

        # Argv assertion: connection flags are present and downstream
        # args propagate without shell expansion.
        argv = argv_log.read_text()
        assert "--rpcserver=fake:10009" in argv, argv
        assert "--tlscertpath=" in argv, argv
        assert "--macaroonpath=" in argv, argv
        assert "--network=signet" in argv, argv
        assert "getinfo" in argv, argv
        assert f"--addr={good_addr}" in argv, argv
        assert f"--amt={good_amt}" in argv, argv

        print(f"OK: lncli wrapper round-trips at {work}")
    finally:
        shutil.rmtree(work, ignore_errors=True)

    sys.exit(0)
