#!/usr/bin/env python3
"""
live_sequence_b_runner.py - sequence B: a linear value journey.

Unlike sequence A (a recoverable loop of self-sends and round-trips),
sequence B walks value in ONE direction across all three layers, the way
an operator brings funds up onto Lightning and hands the AI eCash:

  B0  reads: starting on-chain + channel balances, node synced
  B1  move on-chain: manage_bitcoin (petitioner) sends a ladder amount
      on signet to a registry-resolved operator address           [chain]
  B2  open a channel with them: the OPERATOR funds a fresh LN channel
      from the on-chain wallet to the faucet peer, and waits for it to
      confirm active                                          [chain->ln]
  B3  move on LN: manage_lightning (petitioner) pays a ladder amount over
      Lightning to an arbiter-owned mint quote                     [ln]
  B4  get eCash out: fund_ecash (petitioner) converts a ladder amount of
      Lightning liquidity into the AI's eCash float          [ln->ecash]
  B5  recover the floats: defund the AI's eCash and melt the arbiter's
      B3 residue back to Lightning, so no bearer float is left
      outstanding. The channel is LEFT OPEN - that is where the value now
      lives (the point of "opening a channel with them").

B1/B3/B4 are petitioner ops through the gateway, so the denomination gate
(doc 12 G2) binds them: every amount is a ladder rung. B2 is operator
provisioning (lncli openchannel) - there is no gateway op for channel
management yet (doc 14 is design-only), so it runs operator-side and this
runner posts an `operator_channel_*` audit event so the open still shows
on the two-column console as never-petitioner-known (a funding txid /
channel point is exactly the on-chain footprint the AI must never learn).

Reuses live_sequence_runner's helpers, env, and per-step TUI capture.
Run after any sequence-A cycle finishes (shared node / wallet / arbiter).

Stdlib only.
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_sequence_runner as R  # noqa: E402  (also puts arbiter/src on path)
import audit  # noqa: E402  (arbiter/src/audit.py, via R's path insert)

# Ladder amounts for the gateway-gated ops (all on DEFAULT_LADDER).
B1_ONCHAIN = 10000   # on-chain move (manage_bitcoin self-send)
B3_LN = 5000         # LN move (manage_lightning -> arbiter mint quote)
B4_ECASH = 5000      # eCash out (fund_ecash -> AI float)
# Operator-side channel funding (not a gateway op, not denomination-gated).
# The faucet peer enforces a 25,000-sat minimum channel size; stay at or
# above it. Within our ~30k spendable on-chain (40k total minus the ~10k
# LND anchor reserve).
CHANNEL_LOCAL = 25000
ALLOWANCE_B = 6000   # >= B4 fund
# Mutinynet targets ~30s blocks but stalls for many minutes then bursts;
# a fresh channel took ~16 min (32 confs) to go active once. Wait
# generously so a slow-block patch does not abort a genuine open.
CHAN_ACTIVE_TIMEOUT = 1500  # s (25 min)

B_DIR = R.SESSION / "sequence-b"

APPROVALS_B = """approvals:
  - op: manage_bitcoin
    destination: any
    max_amount_sats: 10000
    rationale: sequence B on-chain move (2026-07-10)
  - op: manage_lightning
    destination: any
    max_amount_sats: 5000
    rationale: sequence B LN move (2026-07-10)
  - op: fund_ecash
    destination: mint
    max_amount_sats: 5000
    rationale: sequence B eCash-out; allowance caps total
  - op: defund_ecash
    destination: mint
    rationale: sequence B recovery
"""


def setup_b():
    """Write B-specific allowance + standing approvals (higher bounds
    than sequence A's) and ensure the output dir + audit handle exist.
    Shares A's config paths, so a later A run resets them via its own
    setup - fine, A is not running concurrently."""
    p = R.paths()
    B_DIR.mkdir(parents=True, exist_ok=True)
    p["allowance"].write_text(
        f"# sequence B petty-cash bound\necash_allowance_sats: {ALLOWANCE_B}\n")
    p["approvals"].write_text(APPROVALS_B)
    audit.configure(p["audit"])  # append operator_channel_* to the same log


def wait_confirmed(txid, timeout=300):
    """Best-effort wait for a wallet tx to reach 1 confirmation, via
    LND's `listchaintxns` ({"transactions":[{"tx_hash",
    "num_confirmations"}]}). Returns True once seen confirmed, False on
    timeout - the journey continues either way, since the channel open
    below spends from the confirmed UTXO pool."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            txns = R.lncli("listchaintxns").get("transactions", [])
        except Exception:
            txns = []
        for tx in txns:
            if tx.get("tx_hash") == txid and int(tx.get("num_confirmations", 0)) >= 1:
                return True
        time.sleep(10)
    return False


def open_channel(peer_pubkey, local_amt):
    """Operator-side channel open to peer_pubkey, funded local_amt from
    the on-chain wallet, --private (the doc-06/mitigation default).
    Returns the funding txid. Posts an operator_channel_open audit event
    (never-petitioner-known: a channel point is on-chain footprint)."""
    out = R.lncli("openchannel", f"--node_key={peer_pubkey}",
                  f"--local_amt={local_amt}", "--private")
    txid = (out.get("funding_txid") or "").strip()
    if not txid:
        raise R.StepError(f"openchannel returned no funding_txid: {out}")
    audit.record("operator_channel_open",
                 {"funding_txid": txid, "local_amt_sat": local_amt,
                  "peer": peer_pubkey})
    return txid


def wait_channel_active(funding_txid, timeout=CHAN_ACTIVE_TIMEOUT):
    """Poll listchannels until the new channel (matched by funding txid
    in its channel_point) is active. Posts operator_channel_active on
    success. Raises on timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for ch in R.lncli("listchannels").get("channels", []):
            if ch.get("channel_point", "").startswith(funding_txid) and ch.get("active"):
                audit.record("operator_channel_active",
                             {"channel_point": ch["channel_point"],
                              "local_balance": ch.get("local_balance")})
                return ch
        R.log("  channel pending; waiting for confirmations...")
        time.sleep(15)
    raise R.StepError(f"channel {funding_txid[:16]} did not become active in {timeout}s")


def run():
    p = R.paths()
    if not R.gateway_up():
        raise R.StepError("gateway not up; run sequence-A setup first")
    if not R.tui_acknowledged():
        raise R.StepError("TUI not acknowledged - clear the console safety gate first")
    setup_b()
    watch = R.AuditWatch(p["audit"])
    t0 = time.time()

    # --- B0 reads ----------------------------------------------------
    wb0, cb0 = R.node_balances()
    arb0 = R.arb_wallet_balance()
    pet0 = R.pet_wallet_balance()
    info = R.lncli("getinfo")
    if not info.get("synced_to_chain"):
        raise R.StepError("node not synced to chain")
    R.log(f"B start: onchain={wb0} ln_local={cb0} arb_ecash={arb0} pet_ecash={pet0} "
          f"channels={info.get('num_active_channels')}")
    watch.mark()
    qb = R.petcli("query", "balance")
    qc = R.petcli("advanced", "channels")
    if qb.get("status") != "ok" or qc.get("status") != "ok":
        raise R.StepError(f"reads failed: {qb} {qc}")
    R.tui_capture(B_DIR, "b0-reads", ["balance_sats=", "capacity_sats=", "real_sats="])

    # --- B1 move on-chain (manage_bitcoin self-send) ------------------
    watch.mark()
    addr = R.lncli("newaddress", "p2wkh")["address"]
    tok_btc = R.registry_add(addr)
    R.log(f"B1 on-chain move: {B1_ONCHAIN} sat -> tok_btc={tok_btc}")
    h1, res1 = R.submit_and_result(
        watch, ["submit", "manage-bitcoin", "--to-token", tok_btc,
                "--amount-sats", str(B1_ONCHAIN)], "manage_bitcoin")
    if res1 != {"status": "sent", "amount_sats": B1_ONCHAIN}:
        raise R.StepError(f"B1 result unexpected: {res1}")
    exec1 = watch.find(R.ev("manage_bitcoin_executed", handle=h1))
    b1_txid = (exec1 or {}).get("payload", {}).get("txid", "")
    R.tui_capture(B_DIR, "b1-onchain-move",
                  ["manage_bitcoin_executed", "registry_consume",
                   f"real: handle={h1[:12]}"])
    R.log(f"  B1 txid={b1_txid[:16]}; waiting for 1 conf...")
    wait_confirmed(b1_txid, timeout=180)

    # --- B2 open a LN channel with them (operator-side) --------------
    watch.mark()
    chans = R.lncli("listchannels").get("channels", [])
    if not chans:
        raise R.StepError("no existing channel to derive the faucet peer")
    peer = chans[0]["remote_pubkey"]
    R.log(f"B2 open channel: {CHANNEL_LOCAL} sat local -> peer {peer[:20]} (faucet)")
    funding_txid = open_channel(peer, CHANNEL_LOCAL)
    R.log(f"  funding txid={funding_txid[:16]}; waiting for active...")
    ch = wait_channel_active(funding_txid)
    R.log(f"  channel ACTIVE: {ch['channel_point']} local={ch.get('local_balance')}")
    R.tui_capture(B_DIR, "b2-open-channel",
                  ["operator_channel_open", "operator_channel_active"])

    return _finish(watch, (wb0, cb0, arb0, pet0), ch["channel_point"])


def _finish(watch, start, channel_point):
    """B3-B5 + summary. Shared by run() (full journey) and resume()
    (when the channel was already opened by an earlier run). `start` is
    the (onchain, ln, arb, pet) baseline for the conservation report;
    channel_point names the channel the value now lives in."""
    wb0, cb0, arb0, pet0 = start
    t0 = time.time()

    # --- B3 move on LN (manage_lightning -> arbiter mint quote) ------
    watch.mark()
    quote_out = R.arb_cashu("invoice", B3_LN, "--no-check")
    bolt11, quote_id = R._parse_mint_quote(quote_out)
    tok_ln = R.registry_add(bolt11)
    R.log(f"B3 LN move: {B3_LN} sat -> tok_ln={tok_ln} (arbiter mint quote)")
    h3, res3 = R.submit_and_result(
        watch, ["advanced", "manage-lightning", "--to-token", tok_ln,
                "--amount-msats", str(B3_LN * 1000)], "manage_lightning")
    if res3.get("status") != "sent":
        raise R.StepError(f"B3 result unexpected: {res3}")
    R.arb_cashu("invoice", B3_LN, "--id", quote_id)  # arbiter claims the eCash
    R.tui_capture(B_DIR, "b3-ln-move",
                  ["manage_lightning_executed", "registry_consume"])

    # --- B4 get eCash out (fund_ecash -> AI float) -------------------
    watch.mark()
    R.log(f"B4 eCash out: fund {B4_ECASH} sat -> AI float")
    h4, res4 = R.submit_and_result(
        watch, ["advanced", "ecash", "fund", "--amount-sats", str(B4_ECASH)],
        "fund_ecash")
    if res4.get("status") != "funded" or res4.get("amount_sats") != B4_ECASH:
        raise R.StepError(f"B4 result unexpected: {res4}")
    ai_token = res4.get("token", "")
    if not ai_token.startswith("cashu"):
        raise R.StepError(f"B4 token unexpected: {ai_token[:40]}")
    R.tui_capture(B_DIR, "b4-ecash-out",
                  ["ecash_fund_executed", "ecash_ledger_fund", "[ecash]"])
    R.log(f"  AI now holds {B4_ECASH} sat of eCash (token {ai_token[:16]}...)")

    # --- B5 recover the floats (channel stays open) ------------------
    watch.mark()
    # Recover the AI's B4 eCash: custody hop (pet receive -> send) then defund.
    R.petcli("advanced", "ecash", "receive", "--token", ai_token)
    snd = R.petcli("advanced", "ecash", "send", "--amount-sats", str(B4_ECASH))
    t2 = R._parse_token(snd.get("stdout", ""))
    h5, res5 = R.submit_and_result(
        watch, ["advanced", "ecash", "defund", "--token", t2], "defund_ecash")
    if res5.get("status") != "defunded":
        raise R.StepError(f"B5 defund unexpected: {res5}")
    # Melt the arbiter's B3 mint-quote residue back to LN.
    arb_res = R.arb_wallet_balance()
    swept = 0
    if arb_res >= R.SWEEP_MIN:
        inv_amt = arb_res - R._melt_fee_reserve(arb_res)
        inv = R.lncli("addinvoice", f"--amt={inv_amt}", "--memo=seqB-recover")["payment_request"]
        if not R._melt_settled(R.arb_cashu("pay", "-y", inv)):
            raise R.StepError("B5 arbiter melt did not settle")
        swept = inv_amt
    R.tui_capture(B_DIR, "b5-recover",
                  ["ecash_defund_executed", "ecash_ledger_defund"])

    # --- summary + conservation -------------------------------------
    wb1, cb1 = R.node_balances()
    arb1 = R.arb_wallet_balance()
    pet1 = R.pet_wallet_balance()
    total0 = wb0 + cb0 + arb0 + pet0
    total1 = wb1 + cb1 + arb1 + pet1
    R.log("=" * 60)
    R.log(f"B DONE ({round(time.time() - t0, 1)}s). value journey:")
    R.log(f"  on-chain {wb0} -> {wb1}")
    R.log(f"  ln_local {cb0} -> {cb1}   ({B3_LN}+{B4_ECASH} moved on LN)")
    R.log(f"  eCash recovered (AI defunded, arbiter swept {swept}); float outstanding now 0")
    R.log(f"  conservation: total {total0} -> {total1} (loss {total0 - total1} sat = fees + melt reserves)")
    R.log(f"  channel LEFT OPEN: {channel_point} - the funds now live on LN")
    (B_DIR / "summary.txt").write_text(
        f"seqB {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}\n"
        f"start onchain/ln/arb/pet = {wb0}/{cb0}/{arb0}/{pet0}\n"
        f"end   onchain/ln/arb/pet = {wb1}/{cb1}/{arb1}/{pet1}\n"
        f"loss = {total0 - total1}\nchannel = {channel_point}\n"
        f"handles = {[h3, h4, h5]}\n")
    return 0


def resume():
    """Continue the journey from B3 when B1/B2 already ran (the channel
    is open) - so a slow-Mutinynet abort mid-open does not re-open a
    second channel. Verifies at least two active channels (the original
    + the new one), then runs B3-B5 over the existing liquidity."""
    if not R.gateway_up():
        raise R.StepError("gateway not up")
    if not R.tui_acknowledged():
        raise R.StepError("TUI not acknowledged - clear the console safety gate first")
    setup_b()
    chans = R.lncli("listchannels").get("channels", [])
    active = [c for c in chans if c.get("active")]
    if len(active) < 2:
        raise R.StepError(
            f"resume expects the new channel already open; only {len(active)} "
            f"active channel(s) found")
    # The new channel is the higher-local-balance one (freshly funded,
    # ~CHANNEL_LOCAL) vs the older, partly-spent channel.
    newest = max(active, key=lambda c: int(c.get("local_balance", 0)))
    R.log(f"resume: {len(active)} channels active; continuing over "
          f"{newest['channel_point']} (local {newest.get('local_balance')})")
    watch = R.AuditWatch(R.paths()["audit"])
    start = (*R.node_balances(), R.arb_wallet_balance(), R.pet_wallet_balance())
    return _finish(watch, start, newest["channel_point"])


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "run"
    try:
        sys.exit(resume() if mode == "resume" else run())
    except R.StepError as e:
        R.log(f"FAIL: {e}")
        try:
            w = R.AuditWatch(R.paths()["audit"]); w.pos = max(0, w.pos - 6000)
            for rec in w.tail(20):
                import json as _j
                R.log(f"  audit: {_j.dumps(rec)[:200]}")
        except Exception:
            pass
        sys.exit(1)
