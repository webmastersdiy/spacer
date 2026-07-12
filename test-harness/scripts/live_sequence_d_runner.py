"""
live_sequence_d_runner.py - sequence D: the demo showcase.

A narrated, pure happy-path tour of what spacer gives an AI petitioner:
constrained, auditable, privacy-preserving agency over the operator's
Bitcoin treasury. No failure testing - every step exercises a capability
working as designed (the exit-loop suite owns the refusal paths).

  D0  reads: query_balance + query_channels through the gateway. The
      console's left column is what the AI may see; the right column is
      the operator-only truth (presented vs real).
  D1  on-chain: a fresh operator address becomes an opaque registry
      token and manage_bitcoin sends a ladder amount to it - the AI
      moves real on-chain value without ever learning an address or
      txid. The result rides a handle, polled once after its audit
      deposit (action delay + result poll floor in play).
  D2  Lightning: manage_lightning pays a tokenized bolt11 (an arbiter
      mint quote) - the fast rail, same tokenization + handle flow. The
      arbiter claims the quote's eCash (recovered in D4).
  D3  eCash custody: fund_ecash hands the AI true bearer money (an
      allowance-capped cashu float). The petitioner wallet receives it
      and mints a fresh send from it (proof of custody), then defund
      melts it back - the full float lifecycle with the ledger's
      outstanding accounting returning to zero.
  D4  recovery + conservation: melt the arbiter-wallet residue back to
      LN, final reads, value-conservation summary. The demo ends with
      zero bearer float outstanding.

Artifacts (per-beat TUI captures + summary) land in
~/spacer/captain-loop/sequence-d/. Rerunnable: needs an active channel
with local LN liquidity >= D2+D3 amounts and on-chain >= D1 + mining
fee; no channel opens, so a run costs roughly one mining fee plus the
defund haircut. Stdlib only.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import live_sequence_runner as R  # noqa: E402  (also puts arbiter/src on path)

# Ladder amounts for the gateway-gated ops (all on DEFAULT_LADDER).
# D1 sits on the smallest rung: the wallet must stay above LND's 10k-sat
# anchor-channel reserve through the send under the strict reading
# (balance - amount - fee >= reserve), and the demo pool runs lean
# between faucet fills (the on-chain faucet drip needs browser OAuth).
D1_ONCHAIN = 1000    # on-chain move (manage_bitcoin self-send via token)
D2_LN = 5000         # LN move (manage_lightning -> arbiter mint quote)
D3_ECASH = 5000      # eCash float (fund_ecash -> AI custody -> defund)
ALLOWANCE_D = 6000   # >= D3 fund

D_DIR = R.SESSION / "sequence-d"

APPROVALS_D = """approvals:
  - op: manage_bitcoin
    destination: any
    max_amount_sats: 10000
    rationale: sequence D demo on-chain move (2026-07-10)
  - op: manage_lightning
    destination: any
    max_amount_sats: 5000
    rationale: sequence D demo LN move (2026-07-10)
  - op: fund_ecash
    destination: mint
    max_amount_sats: 5000
    rationale: sequence D demo eCash float; allowance caps total
  - op: defund_ecash
    destination: mint
    rationale: sequence D demo float recovery
"""


def setup_d():
    """Write D-specific allowance + standing approvals and ensure the
    artifact dir exists. Shares the session config paths, so a later
    sequence-A/B run resets them via its own setup - fine, sequences do
    not run concurrently."""
    p = R.paths()
    D_DIR.mkdir(parents=True, exist_ok=True)
    p["allowance"].write_text(
        f"# sequence D demo petty-cash bound\necash_allowance_sats: {ALLOWANCE_D}\n")
    p["approvals"].write_text(APPROVALS_D)


def show(caption):
    """Demo narration: one 'what this beat just showed' line per step."""
    R.log(f"  SHOWCASE: {caption}")


def run():
    p = R.paths()
    if not R.gateway_up():
        raise R.StepError("gateway not up; run sequence-A setup first")
    if not R.tui_acknowledged():
        raise R.StepError("TUI not acknowledged - clear the console safety gate first")
    setup_d()
    watch = R.AuditWatch(p["audit"])
    t0 = time.time()

    # --- D0 reads ----------------------------------------------------
    wb0, cb0 = R.node_balances()
    arb0 = R.arb_wallet_balance()
    pet0 = R.pet_wallet_balance()
    info = R.lncli("getinfo")
    if not info.get("synced_to_chain"):
        raise R.StepError("node not synced to chain")
    R.log(f"D start: onchain={wb0} ln_local={cb0} arb_ecash={arb0} pet_ecash={pet0} "
          f"channels={info.get('num_active_channels')}")
    watch.mark()
    qb = R.petcli("query", "balance")
    qc = R.petcli("advanced", "channels")
    if qb.get("status") != "ok" or qc.get("status") != "ok":
        raise R.StepError(f"reads failed: {qb} {qc}")
    show("gateway reads - the AI gets presented figures (left column); the "
         "real treasury stays on the operator-only right column")
    R.tui_capture(D_DIR, "d0-reads",
                  ["balance_sats=", "capacity_sats=", "real_sats="])

    # --- D1 on-chain move via registry token -------------------------
    watch.mark()
    addr = R.lncli("newaddress", "p2wkh")["address"]
    tok_btc = R.registry_add(addr)
    R.log(f"D1 on-chain: {D1_ONCHAIN} sat -> tok_btc={tok_btc}")
    show("the destination is an opaque token - the AI commands an on-chain "
         "send without ever seeing an address or a txid")
    h1, res1 = R.submit_and_result(
        watch, ["submit", "manage-bitcoin", "--to-token", tok_btc,
                "--amount-sats", str(D1_ONCHAIN)], "manage_bitcoin")
    if res1 != {"status": "sent", "amount_sats": D1_ONCHAIN}:
        raise R.StepError(f"D1 result unexpected: {res1}")
    show("the result itself is minimal - status and amount; txid, address, "
         "and change stay operator-only, visible on the right column")
    R.tui_capture(D_DIR, "d1-onchain",
                  ["manage_bitcoin_executed", "registry_consume",
                   f"real: handle={h1[:12]}"])

    # --- D2 Lightning move via tokenized bolt11 ----------------------
    watch.mark()
    quote_out = R.arb_cashu("invoice", D2_LN, "--no-check")
    bolt11, quote_id = R._parse_mint_quote(quote_out)
    tok_ln = R.registry_add(bolt11)
    R.log(f"D2 Lightning: {D2_LN} sat -> tok_ln={tok_ln} (arbiter mint quote)")
    show("same tokenization on the fast rail - a bolt11 becomes a token, "
         "the payment settles in seconds, the result rides a handle")
    h2, res2 = R.submit_and_result(
        watch, ["advanced", "manage-lightning", "--to-token", tok_ln,
                "--amount-msats", str(D2_LN * 1000)], "manage_lightning")
    if res2.get("status") != "sent":
        raise R.StepError(f"D2 result unexpected: {res2}")
    R.arb_cashu("invoice", D2_LN, "--id", quote_id)  # arbiter claims the eCash
    R.tui_capture(D_DIR, "d2-lightning",
                  ["manage_lightning_executed", "registry_consume"])

    # --- D3 eCash custody lifecycle ----------------------------------
    watch.mark()
    R.log(f"D3 eCash custody: fund {D3_ECASH} sat -> AI float")
    show("fund_ecash hands the AI true bearer money - an allowance-capped "
         "cashu float it holds in its own wallet")
    h3, res3 = R.submit_and_result(
        watch, ["advanced", "ecash", "fund", "--amount-sats", str(D3_ECASH)],
        "fund_ecash")
    if res3.get("status") != "funded" or res3.get("amount_sats") != D3_ECASH:
        raise R.StepError(f"D3 result unexpected: {res3}")
    ai_token = res3.get("token", "")
    if not ai_token.startswith("cashu"):
        raise R.StepError(f"D3 token unexpected: {ai_token[:40]}")
    R.log(f"  AI holds {D3_ECASH} sat of eCash (token {ai_token[:16]}...)")
    R.tui_capture(D_DIR, "d3-ecash-fund",
                  ["ecash_fund_executed", "ecash_ledger_fund", "[ecash]"])

    # Custody proof: the petitioner wallet receives the float and mints a
    # fresh send from it - the tokens the arbiter sees at defund are not
    # the tokens it issued.
    R.petcli("advanced", "ecash", "receive", "--token", ai_token)
    snd = R.petcli("advanced", "ecash", "send", "--amount-sats", str(D3_ECASH))
    t2 = R._parse_token(snd.get("stdout", ""))
    show("custody proof - the AI's wallet received the float and re-minted "
         "it; the defunded token is not the issued token")
    h4, res4 = R.submit_and_result(
        watch, ["advanced", "ecash", "defund", "--token", t2], "defund_ecash")
    if res4.get("status") != "defunded":
        raise R.StepError(f"D3 defund unexpected: {res4}")
    show("defund melts the float back to Lightning - the ledger's "
         "outstanding count returns to zero")
    R.tui_capture(D_DIR, "d3-ecash-defund",
                  ["ecash_defund_executed", "ecash_ledger_defund"])

    # --- D4 recovery + conservation ----------------------------------
    arb_res = R.arb_wallet_balance()
    swept = 0
    if arb_res >= R.SWEEP_MIN:
        inv_amt = arb_res - R._melt_fee_reserve(arb_res)
        inv = R.lncli("addinvoice", f"--amt={inv_amt}",
                      "--memo=seqD-recover")["payment_request"]
        if not R._melt_settled(R.arb_cashu("pay", "-y", inv)):
            raise R.StepError("D4 arbiter melt did not settle")
        swept = inv_amt

    wb1, cb1 = R.node_balances()
    arb1 = R.arb_wallet_balance()
    pet1 = R.pet_wallet_balance()
    total0 = wb0 + cb0 + arb0 + pet0
    total1 = wb1 + cb1 + arb1 + pet1
    dur = round(time.time() - t0, 1)
    R.log("=" * 60)
    R.log(f"D DONE ({dur}s). capabilities shown: gateway reads, registry "
          f"tokenization, on-chain send, Lightning send, eCash custody "
          f"lifecycle, float recovery - all under standing approvals, the "
          f"denomination gate, handles + the poll floor, and a full audit trail")
    R.log(f"  on-chain {wb0} -> {wb1}")
    R.log(f"  ln_local {cb0} -> {cb1}")
    R.log(f"  arb eCash {arb0} -> {arb1}; pet eCash {pet0} -> {pet1} "
          f"(arbiter swept {swept})")
    R.log(f"  conservation: total {total0} -> {total1} "
          f"(loss {total0 - total1} sat = fees + melt reserves)")
    (D_DIR / "summary.txt").write_text(
        f"seqD demo {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())} ({dur}s)\n"
        f"start onchain/ln/arb/pet = {wb0}/{cb0}/{arb0}/{pet0}\n"
        f"end   onchain/ln/arb/pet = {wb1}/{cb1}/{arb1}/{pet1}\n"
        f"loss = {total0 - total1}\n"
        f"handles = {[h1, h2, h3, h4]}\n")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(run())
    except R.StepError as e:
        R.log(f"FAIL: {e}")
        try:
            w = R.AuditWatch(R.paths()["audit"])
            w.pos = max(0, w.pos - 6000)
            for rec in w.tail(20):
                R.log(f"  audit: {json.dumps(rec)[:200]}")
        except Exception:
            pass
        sys.exit(1)
