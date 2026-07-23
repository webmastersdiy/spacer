#!/usr/bin/env python3
"""Annotated Spacer deployment-mode demo figures (D1 onchain, D2 +lightning,
D3 +ecash). Self-contained Pillow generator, same visual language as
generate_01_privacy_gateway.py: Menlo, dark terminal, two panes split by a
dashed PRIVACY GATEWAY BOUNDARY rail, numbered callouts, amber = amounts /
rounding, cyan = snapshot / timing, red = refusal, a MUTINYNET SIGNET badge.

Every value shown is a real captured figure from the live captain-loop audit
log (see ~/spacer/demo/captures/<name>/ and its notes.md). Nothing is invented;
the arbiter-private figures (real balances, txid, routing fee, melt haircut)
sit in the right (operator-only) column. Renders one PNG per demo next to this
file. Reproduce: `python3 generate_mode_demos.py`.
"""
import os
from PIL import Image, ImageDraw, ImageFont

S = 2  # supersample: design in 1x coords, render at 2x
W = 1500

BG = "#141414"
PANE = "#171717"
GREY = "#6f6f6f"
GREEN = "#4fc47c"
DIM_GREEN = "#3d8f5d"
SALMON = "#d9868c"
RED = "#e5636e"
RAIL = "#7a7a7a"
HEAD = "#ececec"
BODY = "#a8a8a8"
DIM = "#8a8a8a"
CYAN = "#56b6e8"
CYAN_H = "#7cc4ea"
AMBER = "#e0b45c"
AMBER_H = "#e6c078"

MENLO = "/System/Library/Fonts/Menlo.ttc"


def font(sz, bold=False):
    want = "Bold" if bold else "Regular"
    for i in range(4):
        f = ImageFont.truetype(MENLO, int(sz * S), index=i)
        if f.getname()[1] == want:
            return f
    return ImageFont.truetype(MENLO, int(sz * S), index=0)


f_title = font(24, True)
f_sub = font(13.5)
f_badge = font(11, True)
f_hdr = font(16.5, True)
f_body = font(12.5)
f_log = font(14.5)
f_call_h = font(13, True)
f_call = font(12.5)
f_num = font(11.5, True)
f_foot = font(11)
f_chip = font(10.5, True)

# Geometry.
FIG_T = 118
PANE_L0, PANE_L1 = 24, 732
PANE_R0, PANE_R1 = 768, 1476
RAIL_A, RAIL_B = 746, 758
LX, RX = 52, 790          # log-text left edge, each column
LH = 30                   # log line height
CALL_XL, CALL_XR = 64, 790  # callout left edge, per side (pane-confined)
CALL_W = 656               # callout width - stays within one pane, boundary rail stays clean
BADGE_X_L = LX - 24


def tlen(s, f):
    return f.getlength(s) / S


def wrap(s, f, maxw):
    words, lines, cur = s.split(), [], ""
    for w_ in words:
        t = (cur + " " + w_).strip()
        if tlen(t, f) <= maxw:
            cur = t
        else:
            lines.append(cur)
            cur = w_
    if cur:
        lines.append(cur)
    return lines


def _beat_height(beat):
    log_h = max(len(beat["left"]), len(beat["right"])) * LH
    body_lines = len(wrap(beat["body"], f_call, CALL_W - 16))
    callout_h = 24 + body_lines * 18 + 12
    return 14 + log_h + 10 + callout_h + 22


class Fig:
    def __init__(self, height):
        self.H = height
        self.img = Image.new("RGB", (W * S, height * S), BG)
        self.d = ImageDraw.Draw(self.img)

    def text(self, xy, s, f, fill, anchor="la"):
        self.d.text((xy[0] * S, xy[1] * S), s, font=f, fill=fill, anchor=anchor)

    def para(self, xy, s, f, fill, maxw, lh):
        x, y = xy
        for ln in wrap(s, f, maxw):
            self.text((x, y), ln, f, fill)
            y += lh
        return y

    def vdash(self, x, y0, y1, color, dash=5, gap=5, w=1):
        y = y0
        while y < y1:
            self.d.line([(x * S, y * S), (x * S, min(y + dash, y1) * S)],
                        fill=color, width=w * S)
            y += dash + gap

    def rrect(self, box, r, outline=None, fill=None, w=1):
        self.d.rounded_rectangle([c * S for c in box], radius=r * S,
                                 outline=outline, fill=fill, width=w * S)

    def num_badge(self, cx, cy, n, color):
        r = 10
        self.d.ellipse([(cx - r) * S, (cy - r) * S, (cx + r) * S, (cy + r) * S],
                       outline=color, width=2 * S, fill=BG)
        self.text((cx, cy + 0.5), str(n), f_num, color, anchor="mm")

    def hl(self, x, y, prefix, token, color):
        x0 = x + tlen(prefix, f_log)
        tw = tlen(token, f_log)
        self.rrect((x0 - 4, y - 3, x0 + tw + 4, y + 21), 4, outline=color, w=1)


def _check_fit(spec):
    """Warn if any log line overflows its pane (content must not spill past the
    boundary rail or the figure edge)."""
    left_w = PANE_L1 - LX - 8
    right_w = PANE_R1 - RX - 8
    for beat in spec["beats"]:
        for ln in beat["left"]:
            if tlen(ln, f_log) > left_w:
                print(f"  WARN overflow (left): {ln!r}")
        for ln in beat["right"]:
            if tlen(ln, f_log) > right_w:
                print(f"  WARN overflow (right): {ln!r}")


def render(spec):
    _check_fit(spec)
    beats = spec["beats"]
    body_top = 232
    total = body_top + sum(_beat_height(b) for b in beats) + 44
    fig = Fig(total)
    fig_b = total - 30

    # header
    fig.text((40, 26), spec["title"], f_title, HEAD)
    y = 60
    for line in spec["subtitle"]:
        fig.text((40, y), line, f_sub, "#9a9a9a")
        y += 20

    badge_txt = "MUTINYNET SIGNET - TEST SATS ONLY"
    bw = tlen(badge_txt, f_badge)
    fig.rrect((1460 - bw - 24, 26, 1460, 52), 6, outline=AMBER, w=1)
    fig.text((1460 - bw / 2 - 12, 39), badge_txt, f_badge, AMBER, anchor="mm")

    # panes + boundary
    fig.d.rectangle([PANE_L0 * S, FIG_T * S, PANE_L1 * S, fig_b * S], fill=PANE)
    fig.d.rectangle([PANE_R0 * S, FIG_T * S, PANE_R1 * S, fig_b * S], fill=PANE)
    fig.vdash(RAIL_A, FIG_T + 2, fig_b, RAIL)
    fig.vdash(RAIL_B, FIG_T + 2, fig_b, RAIL)
    chip = "PRIVACY GATEWAY BOUNDARY"
    cw = tlen(chip, f_chip)
    fig.rrect((752 - cw / 2 - 12, 107, 752 + cw / 2 + 12, 129), 5, fill=BG,
              outline="#666666", w=1)
    fig.text((752, 118), chip, f_chip, "#d8d8d8", anchor="mm")

    # column headers
    fig.text((44, 136), 'PETITIONER ("Pet")', f_hdr, HEAD)
    fig.para((44, 164), "The sandboxed AI agent. This pane is its entire view of the "
             "world - the requests it sends and the replies it gets. The operator "
             "watches the same left column live in the Spacer TUI.",
             f_body, BODY, 640, 18)
    fig.text((790, 136), "ARBITER", f_hdr, HEAD)
    fig.para((790, 164), "The operator's gatekeeper in front of the real wallet and "
             "node. Everything here is private - Pet can never see it.",
             f_body, BODY, 640, 18)

    # beats
    y = body_top
    for beat in beats:
        n = beat["n"]
        accent = beat["accent"]
        # log lines
        for i, ln in enumerate(beat["left"]):
            style = DIM_GREEN if ln.startswith("->") else GREEN
            fig.text((LX, y + i * LH), ln, f_log, style)
        for i, ln in enumerate(beat["right"]):
            fig.text((RX, y + i * LH), ln, f_log, SALMON)
        # number badge next to the first left line
        fig.num_badge(BADGE_X_L, y + 9, n, accent)
        # token highlights: (side, line_index, prefix, token, color)
        for side, idx, prefix, token, color in beat.get("hl", []):
            x = LX if side == "L" else RX
            fig.hl(x, y + idx * LH, prefix, token, color)
        log_h = max(len(beat["left"]), len(beat["right"])) * LH
        # callout, confined to one pane so the boundary rail stays clean
        call_x = CALL_XL if beat.get("side", "L") == "L" else CALL_XR
        cy = y + log_h + 10
        fig.text((call_x + 12, cy), beat["heading"], f_call_h, accent)
        by = fig.para((call_x + 12, cy + 24), beat["body"], f_call, BODY,
                      CALL_W - 16, 18)
        fig.d.rectangle([call_x * S, cy * S, (call_x + 3) * S, (by - 4) * S],
                        fill=accent)
        y += _beat_height(beat)

    # footer
    fig.para((40, fig_b + 8), spec["footer"], f_foot, "#6f6f6f", 1420, 16)

    out = os.path.join(os.path.dirname(os.path.abspath(__file__)), spec["out"])
    fig.img.save(out)
    print("wrote", out, fig.img.size)


# === demo specs (real captured values only) ================================

FOOTER = ("Spacer lets an AI client drive a Bitcoin node without learning the "
          "operator's wallet, exact balances, addresses, or tx identifiers.")

D1 = {
    "out": "D1-onchain.png",
    "title": "Spacer onchain mode",
    "subtitle": [
        "SPACER_MODE=onchain exposes only the on-chain rail. The sandboxed AI "
        '("Pet") reads a cloaked balance and commands a send it can',
        "never trace - and the advanced rails simply refuse. Real values are "
        "captured live on Mutinynet signet; test sats only.",
    ],
    "footer": FOOTER,
    "beats": [
        {
            "n": 1, "accent": AMBER,
            "left": ["-> op=query_balance", "<- balance_sats=12000 status=ok"],
            "right": ["real: presented_sats=12103 real_sats=12103 snapshot_age_s=2.6"],
            "hl": [("L", 1, "<- ", "balance_sats=12000", AMBER),
                   ("R", 0, "real: presented_sats=12103 ", "real_sats=12103", AMBER),
                   ("R", 0, "real: presented_sats=12103 real_sats=12103 ", "snapshot_age_s=2.6", CYAN)],
            "side": "R",
            "heading": "1 - query_balance: cloaked and snapshot-served",
            "body": "The real 12,103 sats is floored to a 1,000-sat grid, so Pet sees "
                    "12,000 - sat-precision deltas (fees, change) can't fingerprint real "
                    "activity. The reply is a cached snapshot 2.6 s old, refreshed on a "
                    "randomized 5-15 s timer, never a live lookup, so rapid polling leaks "
                    "no timing.",
        },
        {
            "n": 2, "accent": GREEN,
            "left": ["-> op=manage_bitcoin amount_sats=1000 recipient_token=9BJY3W",
                     "<- handle=DpJV2vl2XdIkyxphMt9Zlw status=received",
                     "<- result.amount_sats=1000 result.status=sent"],
            "right": ["registry_lookup_ok token=9BJY3W",
                      "standing_approval_match  ->  decision_allow",
                      "manage_bitcoin_executed amount_sats=1000 txid=60f7673f...487167c"],
            "hl": [("L", 0, "-> op=manage_bitcoin amount_sats=1000 ", "recipient_token=9BJY3W", CYAN),
                   ("R", 2, "manage_bitcoin_executed amount_sats=1000 ", "txid=60f7673f...487167c", AMBER)],
            "heading": "2 - manage_bitcoin: tokenized send, no address or txid exposed",
            "body": "The destination is an opaque registry token; a standing approval "
                    "clears it to decision_allow. Pet gets back only a handle, and one "
                    "poll later (past the 10-minute result-poll floor) status=sent. The "
                    "address, the real txid and the change never cross the boundary.",
        },
        {
            "n": 3, "accent": RED,
            "left": ["-> op=manage_lightning amount_msats=5000000",
                     "<- handle=IJ_fZIzGiyNh0hc-Pobp6Q status=received",
                     "<- result.status=failed"],
            "right": ["decision_refuse_mode op=manage_lightning reason=advanced_extension_disabled",
                      "decision_defer_rejection hold_s=4.1  (rejection window)"],
            "hl": [("L", 1, "<- handle=IJ_fZIzGiyNh0hc-Pobp6Q ", "status=received", GREEN),
                   ("L", 2, "<- ", "result.status=failed", RED),
                   ("R", 0, "", "decision_refuse_mode", RED)],
            "side": "R",
            "heading": "3 - the mode gate: the Lightning rail does not exist",
            "body": "An onchain Pet reaching for Lightning is refused at the mode gate "
                    "(decision_refuse_mode) - but the wire still acks received plus a "
                    "handle, identical to a passing write, and the uniform failed "
                    "surfaces only on a later poll, after the rejection window. No "
                    "HITL prompt and no reason leaked: the operator already decided "
                    "by choosing SPACER_MODE=onchain, so there is nothing to escalate.",
        },
    ],
}

D2 = {
    "out": "D2-onchain-lightning.png",
    "title": "Spacer onchain + lightning mode",
    "subtitle": [
        "SPACER_MODE=lightning adds the Lightning rail on top of onchain (D1). Pet "
        "reads cloaked channel capacity and pays a tokenized",
        "invoice on the same handle + approval flow - but eCash custody still does "
        "not exist. Real values, Mutinynet signet, test sats only.",
    ],
    "footer": FOOTER,
    "beats": [
        {
            "n": 1, "accent": AMBER,
            "left": ["-> op=query_channels", "<- capacity_sats=72000 status=ok"],
            "right": ["real: presented_sats=72833 real_sats=72833 snapshot_age_s=6.2"],
            "hl": [("L", 1, "<- ", "capacity_sats=72000", AMBER),
                   ("R", 0, "real: presented_sats=72833 ", "real_sats=72833", AMBER),
                   ("R", 0, "real: presented_sats=72833 real_sats=72833 ", "snapshot_age_s=6.2", CYAN)],
            "side": "R",
            "heading": "1 - query_channels: cloaked capacity, snapshot-served",
            "body": "Same read protection as the balance: real channel capacity 72,833 "
                    "sats floored to 72,000, from a snapshot 6.2 s old. Everything D1 "
                    "shows still holds - a cloaked query_balance and tokenized on-chain "
                    "sends are unchanged in this mode.",
        },
        {
            "n": 2, "accent": GREEN,
            "left": ["-> op=manage_lightning amount_msats=5000000 recipient_token=ZHQB0H",
                     "<- handle=qzerADydD6rmySfoB51LSA status=received",
                     "<- result.amount_sats=5000 result.status=sent"],
            "right": ["registry_lookup_ok token=ZHQB0H",
                      "standing_approval_match  ->  decision_allow",
                      "manage_lightning_executed amount_sats=5000 ln_routing_fee_msat=1005"],
            "hl": [("L", 0, "-> op=manage_lightning amount_msats=5000000 ", "recipient_token=ZHQB0H", CYAN),
                   ("R", 2, "manage_lightning_executed amount_sats=5000 ", "ln_routing_fee_msat=1005", AMBER)],
            "heading": "2 - manage_lightning: tokenized invoice payment",
            "body": "A bolt11 becomes an opaque token; a standing approval allows it and "
                    "5,000 sats settle in seconds on the same handle + poll pattern as the "
                    "on-chain send. The real routing fee stays on the operator-only side.",
        },
        {
            "n": 3, "accent": RED,
            "left": ["-> op=fund_ecash amount_sats=5000",
                     "<- handle=O4PacnZtCuu1m74PBgPNAg status=received",
                     "<- result.status=failed"],
            "right": ["decision_refuse_mode op=fund_ecash reason=advanced_extension_disabled",
                      "decision_defer_rejection hold_s=3.5  (rejection window)"],
            "hl": [("L", 1, "<- handle=O4PacnZtCuu1m74PBgPNAg ", "status=received", GREEN),
                   ("L", 2, "<- ", "result.status=failed", RED),
                   ("R", 0, "", "decision_refuse_mode", RED)],
            "side": "R",
            "heading": "3 - the mode gate again: eCash custody is not enabled",
            "body": "A Lightning-mode Pet asking for bearer eCash is refused at the mode "
                    "gate, exactly as Lightning was refused in onchain mode - same "
                    "deferred shape: received plus a handle at submit, the uniform "
                    "failed on a later poll. Each rail switches on only when the "
                    "operator names the mode that enables it.",
        },
    ],
}

D3 = {
    "out": "D3-onchain-lightning-ecash.png",
    "title": "Spacer onchain + lightning + ecash mode",
    "subtitle": [
        "SPACER_MODE=ecash adds bearer-money custody on top of onchain + Lightning "
        "(D1, D2). Pet can hold and return a real cashu float -",
        "inside a hard allowance cap checked before any approval. Real values, "
        "Mutinynet signet, test sats only.",
    ],
    "footer": FOOTER,
    "beats": [
        {
            "n": 1, "accent": GREEN,
            "left": ["-> op=fund_ecash amount_sats=5000",
                     "<- handle=2dWpvujp-byVeyRoHpTVaQ status=received",
                     "<- result.amount_sats=5000 result.status=funded token=cashuBo2F0aC..."],
            "right": ["standing_approval_match  ->  decision_allow",
                      "ecash_fund_executed amount_sats=5000 ln_routing_fee_msat=1005",
                      "ecash_ledger_fund outstanding_after_sats=5000"],
            "hl": [("L", 2, "<- result.amount_sats=5000 result.status=funded ", "token=cashuBo2F0aC...", AMBER),
                   ("R", 2, "ecash_ledger_fund ", "outstanding_after_sats=5000", CYAN)],
            "heading": "1 - fund_ecash: the AI receives real bearer money",
            "body": "A standing approval clears a 5,000-sat float; the arbiter mints it "
                    "and Pet receives a real cashu token it holds in its own wallet. The "
                    "ledger records 5,000 sats outstanding against the allowance.",
        },
        {
            "n": 2, "accent": GREEN,
            "left": ["-> op=defund_ecash token=cashuBo2F0gA...",
                     "<- handle=FXhx6WJekDXLsAkFlj8ucQ status=received",
                     "<- result.amount_sats=5000 result.status=defunded"],
            "right": ["ecash_defund_executed claimed_sats=5000 credited_sats=4900",
                      "ecash_ledger_defund outstanding_after_sats=0"],
            "hl": [("R", 0, "ecash_defund_executed claimed_sats=5000 ", "credited_sats=4900", AMBER),
                   ("R", 1, "ecash_ledger_defund ", "outstanding_after_sats=0", CYAN)],
            "side": "R",
            "heading": "2 - defund via the AI custody hop: the float returns",
            "body": "Pet hands bearer money back through the custody hop - the token it "
                    "returns is one it re-minted, not the one issued. 5,000 claimed, 4,900 "
                    "credited after the 100-sat melt haircut; the outstanding ledger "
                    "returns to 0. Full lifecycle, no float left behind.",
        },
        {
            "n": 3, "accent": RED,
            "left": ["-> op=fund_ecash amount_sats=100000",
                     "<- handle=u28B_2oD5bOYUHshwxqlgw status=received",
                     "<- result.status=failed"],
            "right": ["decision_refuse_allowance allowance_sats=6000 requested_sats=100000",
                      "decision_defer_rejection hold_s=3.3  (rejection window)"],
            "hl": [("R", 0, "decision_refuse_allowance ", "allowance_sats=6000", RED),
                   ("R", 0, "decision_refuse_allowance allowance_sats=6000 ", "requested_sats=100000", AMBER),
                   ("L", 2, "<- ", "result.status=failed", RED)],
            "side": "R",
            "heading": "3 - the allowance cap: a hard ceiling, checked first",
            "body": "A fund over the configured cap (here 6,000 sats) is refused with "
                    "decision_refuse_allowance BEFORE standing approvals are even "
                    "consulted, so no approval - however broad - can widen the AI's "
                    "maximum bearer exposure. The refusal defers like every write "
                    "refusal: received plus a handle at submit, the uniform failed on "
                    "a later poll.",
        },
    ],
}


if __name__ == "__main__":
    for spec in (D1, D2, D3):
        render(spec)
