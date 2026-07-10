#!/usr/bin/env python3
"""
live_sequence_runner.py - the captain's live end-to-end loop driver.

Runs the full spacer stack LIVE (real gateway process, real timing
windows in test mode, real executor drainer) against the live testbed:
LND Node A on Voltage (Mutinynet signet) and cashu.mutinynet.com.
One invocation = one cycle of the designed sequence (see the session
feature map): every sat-moving op on all three layers, negatives, a
sweep, and conservation accounting - with a tmux-hosted operator TUI
(arbiter/src/tui.py) captured and asserted after every step.

Subcommands:
  setup [--fresh]   create session dirs/configs, launch tmux windows
                    (arbiter + tui), wait for the gateway
  cycle             run one full sequence cycle (S0..S9)
  status            print balances + session state
  preflight         run module smokes + exit-loop fake suite + mint gate

Unlike test-harness/scripts/exit_loop_runner.py (in-process arbiter,
forced drains, fakes by default), this runner submits through petcli
over HTTP to a real arbiter process and waits out the real test-mode
action/result windows. The 10-minute result poll floor is respected by
polling each handle exactly ONCE, after the operator-side audit log
shows its result_deposit - the operator may watch arbiter state; the
petitioner still only ever polls.

Amount sizing keeps 100+ cycles per faucet fill: the only per-cycle
losses are the on-chain mining fee (self-send), 2-3 LN routing fees,
and the mint melt reserves; every principal amount round-trips back
to the operator's wallets.

Stdlib only.
"""
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent.parent
RUNTIME = Path.home() / "spacer" / "arbiter"      # bins + lnd creds
SESSION = Path.home() / "spacer" / "captain-loop"  # this loop's state
MINT = "https://cashu.mutinynet.com"
TMUX = "spacer"
PY = sys.executable or "python3"
GATE_HOST, GATE_PORT = "127.0.0.1", 8420

AMOUNT_ONCHAIN = 1500   # manage_bitcoin self-send
AMOUNT_ML = 256         # manage_lightning -> arbiter-owned mint quote
AMOUNT_FUND = 512       # fund/defund float round-trip
ALLOWANCE = 2000        # config/ecash.yaml cap
SWEEP_MIN = 64          # melt arbiter-wallet residue at/above this
LOSS_BOUND = 800        # sats; per-cycle conservation alarm threshold

# Reuse the executor's verified stdout parsers (pure regex helpers).
sys.path.insert(0, str(REPO / "arbiter" / "src"))
from executor import (  # noqa: E402
    _melt_fee_reserve,
    _melt_settled,
    _parse_mint_quote,
    _parse_token,
)

_BALANCE_RE = re.compile(r"Balance:\s*(\d+)\s*sat", re.IGNORECASE)


class StepError(Exception):
    pass


def log(msg):
    sys.stdout.write(time.strftime("%H:%M:%S ") + msg + "\n")
    sys.stdout.flush()


# === paths / env =====================================================

def paths():
    return {
        "audit": SESSION / "state" / "audit.log",
        "state_db": SESSION / "state" / "state.db",
        "destinations": SESSION / "config" / "destinations.yaml",
        "approvals": SESSION / "config" / "standing_approvals.yaml",
        "allowance": SESSION / "config" / "ecash.yaml",
        "arb_wallet": SESSION / "ecash" / "arbiter",
        "pet_wallet": SESSION / "ecash" / "petitioner",
        "pet_cashu": SESSION / "bin" / "cashu-pet",
        "envsh": SESSION / "env.sh",
        "runner_state": SESSION / "state" / "runner-state.json",
        "cycles": SESSION / "cycles",
    }


def arbiter_env():
    p = paths()
    return {
        "SPACER_MODE": "ecash",
        "SPACER_TIMING_MODE": "test",
        "SPACER_SCALE_MODE": "test",
        "AUDIT_LOG_PATH": str(p["audit"]),
        "STATE_DB_PATH": str(p["state_db"]),
        "DESTINATIONS_PATH": str(p["destinations"]),
        "SPACER_STANDING_APPROVALS_PATH": str(p["approvals"]),
        "SPACER_ECASH_ALLOWANCE_PATH": str(p["allowance"]),
        "CASHU_BIN": str(RUNTIME / "bin" / "cashu"),
        "CASHU_MINT_URL": MINT,
        "CASHU_DIR": str(p["arb_wallet"]),
        "CASHU_TIMEOUT_S": "120",
        "LNCLI_BIN": str(RUNTIME / "bin" / "lncli"),
        "LNCLI_RPCSERVER": "first-test.u.voltageapp.io:10009",
        "LNCLI_TLSCERT": str(RUNTIME / "lnd" / "tls.cert"),
        "LNCLI_MACAROON": str(RUNTIME / "lnd" / "admin.macaroon"),
        "LNCLI_NETWORK": "signet",
        "LNCLI_TIMEOUT_S": "120",
    }


# === subprocess helpers ==============================================

def _run(cmd, env_extra=None, timeout=180, input_text=None):
    env = dict(os.environ)
    if env_extra:
        env.update(env_extra)
    return subprocess.run(
        [str(c) for c in cmd],
        capture_output=True, text=True, timeout=timeout, env=env,
        input=input_text,
    )


def petcli(*args):
    """Invoke petcli as the AI would; return its parsed JSON line."""
    env = {
        "PETCLI_TEST_TIMING": "1",
        "PETCLI_TIMEOUT_S": "30",
        "PETCLI_CASHU_BIN": str(paths()["pet_cashu"]),
        "CASHU_DIR": str(paths()["pet_wallet"]),
    }
    p = _run([PY, REPO / "petitioner" / "src" / "petcli.py", *args],
             env_extra=env)
    if p.returncode != 0:
        raise StepError(f"petcli {args} rc={p.returncode}: {p.stderr[-400:]}")
    line = p.stdout.strip().splitlines()[-1]
    return json.loads(line)


def lncli(*args):
    """Operator-side lncli against Node A (same creds the arbiter uses)."""
    e = arbiter_env()
    p = _run([e["LNCLI_BIN"], f"--rpcserver={e['LNCLI_RPCSERVER']}",
              f"--tlscertpath={e['LNCLI_TLSCERT']}",
              f"--macaroonpath={e['LNCLI_MACAROON']}",
              "--network=signet", *args])
    if p.returncode != 0:
        raise StepError(f"lncli {args[:1]} rc={p.returncode}: {p.stderr[-300:]}")
    return json.loads(p.stdout)


def arb_cashu(*args):
    """Operator-side cashu against the ARBITER wallet dir."""
    e = arbiter_env()
    p = _run([e["CASHU_BIN"], f"--host={MINT}", *args],
             env_extra={"CASHU_DIR": e["CASHU_DIR"]}, timeout=180)
    if p.returncode != 0:
        raise StepError(f"cashu {args[:2]} rc={p.returncode}: {p.stderr[-300:]}")
    return p.stdout


def registry_add(real):
    """Operator console add; returns the issued token."""
    e = arbiter_env()
    p = _run([REPO / "arbiter" / "bin" / "registry", "add", real],
             env_extra={"DESTINATIONS_PATH": e["DESTINATIONS_PATH"],
                        "AUDIT_LOG_PATH": e["AUDIT_LOG_PATH"]})
    if p.returncode != 0:
        raise StepError(f"registry add failed: {p.stderr[-300:]}")
    m = re.search(r"token=(\S+)", p.stdout)
    if not m:
        raise StepError(f"registry add output unparsed: {p.stdout!r}")
    return m.group(1)


def raw_post(data, timeout=30):
    req = urllib.request.Request(
        f"http://{GATE_HOST}:{GATE_PORT}/", data=data,
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def wallet_balance_sats(stdout):
    m = _BALANCE_RE.search(stdout)
    return int(m.group(1)) if m else 0


def arb_wallet_balance():
    return wallet_balance_sats(arb_cashu("balance"))


def pet_wallet_balance():
    r = petcli("advanced", "ecash", "balance")
    if r.get("exit_code") != 0:
        raise StepError(f"pet wallet balance failed: {r}")
    return wallet_balance_sats(r.get("stdout", ""))


def node_balances():
    wb = lncli("walletbalance")
    cb = lncli("channelbalance")
    return int(wb["total_balance"]), int(cb["local_balance"]["sat"])


# === audit log watching =============================================

class AuditWatch:
    """Incremental reader over the arbiter's append-only audit JSONL."""

    def __init__(self, path):
        self.path = Path(path)
        self.pos = self.path.stat().st_size if self.path.exists() else 0

    def mark(self):
        if self.path.exists():
            self.pos = self.path.stat().st_size

    def _scan(self):
        if not self.path.exists():
            return []
        out = []
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(self.pos)
            for line in f.read().splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except ValueError:
                    continue
        return out

    def find(self, pred):
        for rec in self._scan():
            if pred(rec):
                return rec
        return None

    def wait_for(self, pred, timeout, desc):
        deadline = time.time() + timeout
        while time.time() < deadline:
            rec = self.find(pred)
            if rec is not None:
                return rec
            time.sleep(0.5)
        raise StepError(f"timeout ({timeout}s) waiting for {desc}")

    def tail(self, n=40):
        recs = self._scan()
        return recs[-n:]


def ev(name, **payload_match):
    def pred(rec):
        if rec.get("event") != name:
            return False
        pl = rec.get("payload") or {}
        return all(pl.get(k) == v for k, v in payload_match.items())
    return pred


# === tmux ============================================================

def tmux(*args, check=True):
    p = subprocess.run(["tmux", *[str(a) for a in args]],
                       capture_output=True, text=True)
    if check and p.returncode != 0:
        raise StepError(f"tmux {args[:2]} failed: {p.stderr.strip()}")
    return p


def tui_capture(cycle_dir, step, markers):
    """Capture the TUI pane, save it, and require every marker."""
    cap = ""
    for _ in range(16):  # renderer polls at 250ms; allow 4s
        cap = tmux("capture-pane", "-p", "-S", "-200", "-t",
                   f"{TMUX}:tui").stdout
        if all(m in cap for m in markers):
            break
        time.sleep(0.25)
    (cycle_dir / f"{step}-tui.txt").write_text(cap)
    missing = [m for m in markers if m not in cap]
    if missing:
        raise StepError(f"TUI capture after {step} missing {missing}")
    log(f"  tui ok: {step}" + (f" ({len(markers)} markers)" if markers else ""))


def gateway_up(timeout=1.5):
    try:
        with socket.create_connection((GATE_HOST, GATE_PORT), timeout=timeout):
            return True
    except OSError:
        return False


# === setup ===========================================================

APPROVALS_YAML = """approvals:
  - op: manage_bitcoin
    destination: any
    max_amount_sats: {mb}
    rationale: captain live loop self-sends (2026-07-10)
  - op: manage_lightning
    destination: any
    max_amount_sats: 1000
    rationale: captain live loop mint-quote pays (2026-07-10)
  - op: fund_ecash
    destination: mint
    max_amount_sats: 1024
    rationale: captain live loop float top-ups; allowance caps total
  - op: defund_ecash
    destination: mint
    rationale: always willing to take float back
"""


def cmd_setup(fresh=False):
    p = paths()
    if fresh:
        tmux("kill-session", "-t", TMUX, check=False)
    for d in ("state", "config", "cycles", "bin",
              "ecash/arbiter", "ecash/petitioner"):
        (SESSION / d).mkdir(parents=True, exist_ok=True)
    p["allowance"].write_text(
        "# captain live loop petty-cash bound\n"
        f"ecash_allowance_sats: {ALLOWANCE}\n")
    p["approvals"].write_text(APPROVALS_YAML.format(mb=AMOUNT_ONCHAIN + 500))
    p["pet_cashu"].write_text(
        "#!/bin/sh\n"
        f'exec "{RUNTIME / "bin" / "cashu"}" --host="{MINT}" "$@"\n')
    p["pet_cashu"].chmod(0o755)
    env_lines = "".join(
        f"export {k}={v}\n" for k, v in arbiter_env().items())
    p["envsh"].write_text(env_lines)
    if not p["runner_state"].exists():
        p["runner_state"].write_text(json.dumps(
            {"cycle": 0, "handles": [], "history": []}))

    have = tmux("has-session", "-t", TMUX, check=False).returncode == 0
    if not have:
        tmux("new-session", "-d", "-s", TMUX, "-x", "230", "-y", "50",
             "-n", "arbiter")
        tmux("send-keys", "-t", f"{TMUX}:arbiter",
             f"cd {REPO} && . {p['envsh']} && exec {PY} arbiter/src/arbiter.py",
             "Enter")
        tmux("new-window", "-a", "-t", f"{TMUX}:arbiter", "-n", "tui")
        tmux("send-keys", "-t", f"{TMUX}:tui",
             f"cd {REPO} && AUDIT_LOG_PATH={p['audit']} exec {PY} arbiter/src/tui.py",
             "Enter")
        log("tmux session 'spacer' launched (windows: arbiter, tui)")
    for _ in range(40):
        if gateway_up():
            break
        time.sleep(0.5)
    if not gateway_up():
        pane = tmux("capture-pane", "-p", "-t", f"{TMUX}:arbiter",
                    check=False).stdout
        raise StepError(f"gateway did not come up on :{GATE_PORT}\n{pane[-800:]}")
    # Initialize both wallets so first-run mnemonic noise lands here,
    # not mid-cycle.
    arb_cashu("balance")
    petcli("advanced", "ecash", "balance")
    log(f"setup ok: gateway :{GATE_PORT} live, wallets initialized")


# === the cycle =======================================================

def load_state():
    return json.loads(paths()["runner_state"].read_text())


def save_state(st):
    paths()["runner_state"].write_text(json.dumps(st, indent=1))


def submit_and_result(watch, args, desc):
    """Submit a write, wait (operator-side) for its result deposit,
    then poll exactly once. Returns (handle, result payload)."""
    resp = petcli(*args)
    handle = resp.get("handle")
    if resp.get("status") != "received" or not handle:
        raise StepError(f"{desc}: submit not acknowledged: {resp}")
    log(f"  {desc}: handle={handle} (estimate {resp.get('_petcli_estimate_window_s')}s)")
    watch.wait_for(ev("result_deposit", handle=handle), 150,
                   f"result_deposit for {desc}")
    poll = petcli("result", "poll", "--handle", handle)
    if poll.get("status") != "result":
        raise StepError(f"{desc}: poll after deposit not result: {poll}")
    return handle, poll["result"]


def expect_refused(resp, desc):
    # Leading-underscore keys are petitioner-side annotations (petcli
    # stamps _petcli_estimate_window_s on every submit, refusals
    # included); only the arbiter-sent body must be the uniform shape.
    core = {k: v for k, v in resp.items() if not k.startswith("_")}
    if core != {"status": "refused"}:
        raise StepError(f"{desc}: expected uniform refusal, got {resp}")


def cmd_cycle():
    p = paths()
    if not gateway_up():
        raise StepError("gateway not up; run setup first")
    st = load_state()
    n = st["cycle"] + 1
    cdir = p["cycles"] / f"{n:03d}"
    cdir.mkdir(parents=True, exist_ok=True)
    watch = AuditWatch(p["audit"])
    t_start = time.time()

    wb0, cb0 = node_balances()
    arb0 = arb_wallet_balance()
    pet0 = pet_wallet_balance()
    log(f"cycle {n} start: onchain={wb0} ln_local={cb0} "
        f"arb_ecash={arb0} pet_ecash={pet0}")

    # --- S0 reads ----------------------------------------------------
    watch.mark()
    est = petcli("estimate", "window")
    if est.get("estimate_window_seconds") != 30.0:
        raise StepError(f"estimate window unexpected: {est}")
    qb = petcli("query", "balance")
    if qb.get("status") != "ok" or not isinstance(qb.get("balance_sats"), int):
        raise StepError(f"query balance unexpected: {qb}")
    qc = petcli("advanced", "channels")
    if qc.get("status") != "ok" or not isinstance(qc.get("capacity_sats"), int):
        raise StepError(f"query channels unexpected: {qc}")
    tui_capture(cdir, "s0-reads",
                ["op=query_balance", "op=query_channels", "balance_sats=",
                 "balance_read", "capacity_read", "[chain]", "[ ln  ]"])

    # --- S1 operator provisioning ------------------------------------
    watch.mark()
    addr = lncli("newaddress", "p2wkh")["address"]
    tok_btc = registry_add(addr)
    quote_out = arb_cashu("invoice", AMOUNT_ML, "--no-check")
    bolt11_ml, quote_ml = _parse_mint_quote(quote_out)
    tok_ln = registry_add(bolt11_ml)
    log(f"  registered tok_btc={tok_btc} (self-send) tok_ln={tok_ln} (mint quote)")
    tui_capture(cdir, "s1-provision", ["registry_add"])

    # --- S2 manage_bitcoin: on-chain self-send ------------------------
    watch.mark()
    h1, res1 = submit_and_result(
        watch,
        ["submit", "manage-bitcoin", "--to-token", tok_btc,
         "--amount-sats", str(AMOUNT_ONCHAIN)],
        "manage_bitcoin")
    if res1 != {"status": "sent", "amount_sats": AMOUNT_ONCHAIN}:
        raise StepError(f"manage_bitcoin result unexpected: {res1}")
    if not watch.find(ev("registry_consume", token=tok_btc)):
        raise StepError("tok_btc was not consumed on success")
    exec1 = watch.find(ev("manage_bitcoin_executed", handle=h1))
    txid = (exec1 or {}).get("payload", {}).get("txid", "")
    tui_capture(cdir, "s2-manage-bitcoin",
                ["manage_bitcoin_executed", "registry_consume",
                 "result.status=sent", f"real: handle={h1[:12]}"])

    # --- S3 manage_lightning: pay arbiter-owned mint quote ------------
    watch.mark()
    h2, res2 = submit_and_result(
        watch,
        ["advanced", "manage-lightning", "--to-token", tok_ln,
         "--amount-msats", str(AMOUNT_ML * 1000)],
        "manage_lightning")
    if res2.get("status") != "sent":
        raise StepError(f"manage_lightning result unexpected: {res2}")
    if not watch.find(ev("registry_consume", token=tok_ln)):
        raise StepError("tok_ln was not consumed on success")
    arb_cashu("invoice", AMOUNT_ML, "--id", quote_ml)  # claim proofs
    arb_after_claim = arb_wallet_balance()
    if arb_after_claim < arb0 + AMOUNT_ML:
        raise StepError(
            f"quote claim did not credit arbiter wallet: {arb0} -> {arb_after_claim}")
    tui_capture(cdir, "s3-manage-lightning",
                ["manage_lightning_executed", "registry_consume"])

    # --- S4 fund_ecash -------------------------------------------------
    watch.mark()
    h3, res3 = submit_and_result(
        watch,
        ["advanced", "ecash", "fund", "--amount-sats", str(AMOUNT_FUND)],
        "fund_ecash")
    if res3.get("status") != "funded" or res3.get("amount_sats") != AMOUNT_FUND:
        raise StepError(f"fund result unexpected: {res3}")
    fund_token = res3.get("token", "")
    if not fund_token.startswith("cashu"):
        raise StepError(f"fund token unexpected: {fund_token[:40]}")
    tui_capture(cdir, "s4-fund",
                ["ecash_fund_executed", "ecash_ledger_fund", "token=cashu",
                 "[ecash]"])

    # --- S5 AI custody hop (local wallet ops, no arbiter) --------------
    rcv = petcli("advanced", "ecash", "receive", "--token", fund_token)
    if rcv.get("exit_code") != 0:
        raise StepError(f"pet receive failed: {rcv}")
    pet_mid = pet_wallet_balance()
    if pet_mid != pet0 + AMOUNT_FUND:
        raise StepError(f"pet wallet after receive: {pet0} -> {pet_mid}")
    snd = petcli("advanced", "ecash", "send",
                 "--amount-sats", str(AMOUNT_FUND))
    if snd.get("exit_code") != 0:
        raise StepError(f"pet send failed: {snd}")
    t2 = _parse_token(snd.get("stdout", ""))
    tui_capture(cdir, "s5-ai-custody", [])  # local ops: no arbiter events

    # --- S6 defund_ecash ------------------------------------------------
    watch.mark()
    h4, res4 = submit_and_result(
        watch,
        ["advanced", "ecash", "defund", "--token", t2],
        "defund_ecash")
    if res4 != {"status": "defunded", "amount_sats": AMOUNT_FUND}:
        raise StepError(f"defund result unexpected: {res4}")
    ledger = watch.find(ev("ecash_ledger_defund"))
    outstanding = (ledger or {}).get("payload", {}).get(
        "outstanding_after_sats")
    if outstanding != 0:
        raise StepError(f"outstanding after defund != 0: {outstanding}")
    pet_end = pet_wallet_balance()
    if pet_end != pet0:
        raise StepError(f"pet wallet not drained: {pet0} -> {pet_end}")
    tui_capture(cdir, "s6-defund",
                ["ecash_defund_executed", "ecash_ledger_defund",
                 "result.status=defunded"])

    # --- S7 negatives (no value moves) ---------------------------------
    watch.mark()
    expect_refused(petcli("submit", "manage-bitcoin", "--to-token", tok_btc,
                          "--amount-sats", "10"), "reused token")
    watch.wait_for(ev("decision_refuse_registry"), 10, "used-token refusal")
    expect_refused(petcli("submit", "manage-bitcoin", "--to-token", "ZZZZZ0",
                          "--amount-sats", "10"), "bad checksum")
    expect_refused(petcli("advanced", "ecash", "fund", "--amount-sats",
                          str(ALLOWANCE + 500)), "over allowance")
    watch.wait_for(ev("decision_refuse_allowance"), 10, "allowance refusal")
    expect_refused(petcli("advanced", "ecash", "fund", "--amount-sats",
                          "1600"), "fund past standing bound")
    quote2_out = arb_cashu("invoice", 2000, "--no-check")
    bolt11_hitl, _q2 = _parse_mint_quote(quote2_out)
    tok_hitl = registry_add(bolt11_hitl)
    expect_refused(petcli("advanced", "manage-lightning", "--to-token",
                          tok_hitl, "--amount-msats", "2000000"),
                   "manage_lightning past standing bound")
    watch.wait_for(ev("decision_defer_hitl", op="manage_lightning"), 10,
                   "HITL park")
    expect_refused(raw_post(json.dumps({"op": "frobnicate_x"}).encode()),
                   "unknown op")
    watch.wait_for(ev("decision_defer_hitl", op="frobnicate_x"), 10,
                   "unknown-op HITL park")
    expect_refused(raw_post(b"this is not json"), "malformed body")
    expect_refused(raw_post(b"x" * 70000), "oversized body")
    # Unique per cycle: the poll floor is keyed per handle, so a
    # reused fake handle reads as throttled (same wire response, but
    # the audit cause this asserts would never fire again).
    ghost = f"neverexisted-{n}-{int(t_start)}"
    nz = petcli("result", "poll", "--handle", ghost)
    if nz != {"status": "not_yet"}:
        raise StepError(f"unknown-handle poll: {nz}")
    watch.wait_for(ev("result_poll_unknown", handle=ghost), 10,
                   "unknown-handle audit")
    th = petcli("result", "poll", "--handle", h1)
    if th != {"status": "not_yet"}:
        raise StepError(f"floor-throttled poll: {th}")
    watch.wait_for(ev("result_poll_throttled", handle=h1), 10,
                   "throttled audit")
    aged = [h for h in st["handles"] if t_start - h["ts"] > 660]
    if aged:
        ac = petcli("result", "poll", "--handle", aged[-1]["h"])
        if ac != {"status": "not_yet"}:
            raise StepError(f"aged consumed poll: {ac}")
        watch.wait_for(ev("result_poll_already_consumed",
                          handle=aged[-1]["h"]), 10, "already-consumed audit")
        log("  aged-handle already_consumed path exercised")
    tui_capture(cdir, "s7-negatives",
                ["decision_refuse_registry", "decision_refuse_allowance",
                 "decision_defer_hitl", "result_poll_unknown",
                 "result_poll_throttled", "status=refused"])

    # --- S8 sweep: melt arbiter-wallet residue back to LND -------------
    watch.mark()
    arb_res = arb_wallet_balance()
    swept = 0
    if arb_res >= SWEEP_MIN:
        inv_amt = arb_res - _melt_fee_reserve(arb_res)
        inv = lncli("addinvoice", f"--amt={inv_amt}",
                    "--memo=captain-sweep")["payment_request"]
        pay_out = arb_cashu("pay", "-y", inv)
        if not _melt_settled(pay_out):
            raise StepError("sweep melt did not settle")
        swept = inv_amt
        log(f"  swept {inv_amt} of {arb_res} arbiter-wallet residue to LN")
    arb_end = arb_wallet_balance()

    # --- S9 conservation + fee accounting -------------------------------
    wb1, cb1 = node_balances()
    total0 = wb0 + cb0 + arb0 + pet0
    total1 = wb1 + cb1 + arb_end + pet_end
    loss = total0 - total1
    fee_events = {}
    for rec in watch.tail(400):
        e = rec.get("event", "")
        pl = rec.get("payload") or {}
        if e in ("manage_bitcoin_executed", "manage_lightning_executed",
                 "ecash_fund_executed", "ecash_defund_executed"):
            fee_events.setdefault(e, []).append(pl)
    if loss < 0:
        raise StepError(f"conservation anomaly: negative loss {loss}")
    if loss > LOSS_BOUND:
        raise StepError(
            f"per-cycle loss {loss} sats exceeds bound {LOSS_BOUND}")
    summary = {
        "cycle": n, "started": t_start, "duration_s": round(time.time() - t_start, 1),
        "balances": {"start": [wb0, cb0, arb0, pet0],
                     "end": [wb1, cb1, arb_end, pet_end]},
        "loss_sats": loss, "swept_sats": swept, "txid": txid,
        "handles": [h1, h2, h3, h4],
        "fee_events": fee_events,
    }
    (cdir / "summary.json").write_text(json.dumps(summary, indent=1))
    now = time.time()
    st["cycle"] = n
    st["handles"] = (st["handles"] + [
        {"h": h, "ts": now} for h in (h1, h2, h3, h4)])[-40:]
    st["history"] = (st.get("history") or []) + [
        {"cycle": n, "loss": loss, "duration_s": summary["duration_s"]}]
    save_state(st)
    log(f"cycle {n} PASS: loss={loss} sats, duration={summary['duration_s']}s, "
        f"onchain={wb1} ln_local={cb1}")
    return 0


# === status / preflight =============================================

def cmd_status():
    st = load_state() if paths()["runner_state"].exists() else {}
    log(f"gateway up: {gateway_up()}")
    try:
        wb, cb = node_balances()
        log(f"onchain={wb} ln_local={cb} arb_ecash={arb_wallet_balance()} "
            f"pet_ecash={pet_wallet_balance()}")
    except Exception as e:
        log(f"balance read failed: {e}")
    log(f"runner state: {json.dumps(st)[:400]}")
    return 0


def cmd_preflight():
    checks = [
        [PY, REPO / "arbiter" / "src" / "audit.py"],
        [PY, REPO / "arbiter" / "src" / "state.py"],
        [PY, REPO / "arbiter" / "src" / "timing.py"],
        [PY, REPO / "arbiter" / "src" / "results.py"],
        [PY, REPO / "arbiter" / "src" / "scale.py"],
        [PY, REPO / "arbiter" / "src" / "registry.py"],
        [PY, REPO / "arbiter" / "src" / "registry_cli.py"],
        [PY, REPO / "arbiter" / "src" / "standing_approvals.py"],
        [PY, REPO / "arbiter" / "src" / "lnd.py"],
        [PY, REPO / "arbiter" / "src" / "ecash.py"],
        [PY, REPO / "arbiter" / "src" / "gateway.py"],
        [PY, REPO / "arbiter" / "src" / "executor.py"],
        [PY, REPO / "petitioner" / "src" / "protocol.py"],
        [PY, REPO / "petitioner" / "src" / "estimate.py"],
        [PY, REPO / "petitioner" / "src" / "petcli_smoke.py"],
        [PY, REPO / "test-harness" / "scripts" / "exit_loop_runner.py"],
    ]
    fails = 0
    for cmd in checks:
        name = Path(cmd[1]).name
        env_extra = None
        if name == "tui.py":
            env_extra = {"TUI_SMOKE": "1"}
        if name == "registry_cli.py":
            env_extra = {"REGISTRY_CLI_SMOKE": "1"}
        p = _run(cmd, env_extra=env_extra, timeout=600)
        ok = p.returncode == 0
        fails += 0 if ok else 1
        log(f"  {'PASS' if ok else 'FAIL'} {name}")
        if not ok:
            log(p.stdout[-400:] + p.stderr[-400:])
    p = _run([PY, REPO / "arbiter" / "src" / "tui.py"],
             env_extra={"TUI_SMOKE": "1"})
    ok = p.returncode == 0
    fails += 0 if ok else 1
    log(f"  {'PASS' if ok else 'FAIL'} tui.py")
    log(f"preflight: {'PASS' if fails == 0 else f'{fails} FAILURES'}")
    return 0 if fails == 0 else 1


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "cycle"
    try:
        if cmd == "setup":
            cmd_setup(fresh="--fresh" in sys.argv)
            return 0
        if cmd == "cycle":
            return cmd_cycle()
        if cmd == "status":
            return cmd_status()
        if cmd == "preflight":
            return cmd_preflight()
        log(f"unknown subcommand {cmd}")
        return 2
    except StepError as e:
        log(f"FAIL: {e}")
        try:
            watch = AuditWatch(paths()["audit"])
            watch.pos = max(0, watch.pos - 8000)
            for rec in watch.tail(30):
                log(f"  audit: {json.dumps(rec)[:220]}")
        except Exception:
            pass
        return 1


if __name__ == "__main__":
    sys.exit(main())
