#!/usr/bin/env python3
"""Annotated Spacer privacy-gateway demo figure (single query_balance cycle)."""
from PIL import Image, ImageDraw, ImageFont

S = 2  # supersample scale: design in 1x coords, render at 2x
W, H = 1500, 790

BG = "#141414"
PANE = "#171717"
GREY = "#6f6f6f"
GREEN = "#4fc47c"
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
    # Menlo.ttc: probe indices for Regular / Bold
    want = "Bold" if bold else "Regular"
    for i in range(4):
        f = ImageFont.truetype(MENLO, int(sz * S), index=i)
        if f.getname()[1] == want:
            return f
    return ImageFont.truetype(MENLO, int(sz * S), index=0)

img = Image.new("RGB", (W * S, H * S), BG)
d = ImageDraw.Draw(img)

def text(xy, s, f, fill, anchor="la"):
    d.text((xy[0] * S, xy[1] * S), s, font=f, fill=fill, anchor=anchor)

def tlen(s, f):
    return f.getlength(s) / S

def wrap(s, f, maxw):
    words, lines, cur = s.split(), [], ""
    for w_ in words:
        t = (cur + " " + w_).strip()
        if tlen(t, f) <= maxw:
            cur = t
        else:
            lines.append(cur); cur = w_
    if cur:
        lines.append(cur)
    return lines

def para(xy, s, f, fill, maxw, lh):
    x, y = xy
    for ln in wrap(s, f, maxw):
        text((x, y), ln, f, fill); y += lh
    return y

def vdash(x, y0, y1, color, dash=5, gap=5, w=1):
    y = y0
    while y < y1:
        d.line([(x * S, y * S), (x * S, min(y + dash, y1) * S)], fill=color, width=w * S)
        y += dash + gap

def rrect(box, r, outline=None, fill=None, w=1):
    d.rounded_rectangle([c * S for c in box], radius=r * S, outline=outline, fill=fill, width=w * S)

def bezier(p0, p1, p2, p3, n=240):
    pts = []
    for i in range(n + 1):
        t = i / n; u = 1 - t
        x = u**3 * p0[0] + 3 * u**2 * t * p1[0] + 3 * u * t**2 * p2[0] + t**3 * p3[0]
        y = u**3 * p0[1] + 3 * u**2 * t * p1[1] + 3 * u * t**2 * p2[1] + t**3 * p3[1]
        pts.append((x, y))
    return pts

def dashed_path(pts, color, dash=7, gap=5, w=2):
    import math
    acc, on = 0.0, True
    seg = []
    for i in range(1, len(pts)):
        x0, y0 = pts[i - 1]; x1, y1 = pts[i]
        acc += math.hypot(x1 - x0, y1 - y0)
        seg.append((x0, y0))
        lim = dash if on else gap
        if acc >= lim:
            seg.append((x1, y1))
            if on:
                d.line([(px * S, py * S) for px, py in seg], fill=color, width=w * S)
            seg, acc, on = [], 0.0, not on
    if on and seg:
        d.line([(px * S, py * S) for px, py in seg], fill=color, width=w * S)

# fonts
f_title = font(25, True)
f_sub = font(13.5)
f_badge = font(11, True)
f_hdr = font(16.5, True)
f_body = font(12.5)
f_log = font(15)
f_call_h = font(13, True)
f_call = font(12.5)
f_note = font(12)
f_chip = font(10.5, True)
f_num = font(11.5, True)
f_foot = font(11)
f_lab = font(12, True)

# ---------- header ----------
text((40, 26), "Spacer privacy gateway - one balance query, two views", f_title, HEAD)
text((40, 62), "A sandboxed AI agent asks the operator's wallet for its balance. The gateway answers honestly -", f_sub, "#9a9a9a")
text((40, 82), "but never precisely, and never in real time.", f_sub, "#9a9a9a")

badge_txt = "MUTINYNET SIGNET - TEST SATS ONLY"
bw = tlen(badge_txt, f_badge)
rrect((1460 - bw - 24, 26, 1460, 52), 6, outline=AMBER, w=1)
text((1460 - bw / 2 - 12, 39), badge_txt, f_badge, AMBER, anchor="mm")

# ---------- pane tints ----------
FIG_T, FIG_B = 118, 700
d.rectangle([24 * S, FIG_T * S, 732 * S, FIG_B * S], fill=PANE)
d.rectangle([768 * S, FIG_T * S, 1476 * S, FIG_B * S], fill=PANE)

# ---------- boundary rail ----------
vdash(746, FIG_T + 2, FIG_B, RAIL)
vdash(758, FIG_T + 2, FIG_B, RAIL)
chip = "PRIVACY GATEWAY BOUNDARY"
cw = tlen(chip, f_chip)
rrect((752 - cw / 2 - 12, 107, 752 + cw / 2 + 12, 129), 5, fill=BG, outline="#666666", w=1)
text((752, 118), chip, f_chip, "#d8d8d8", anchor="mm")

# ---------- pane headers ----------
text((44, 136), 'PETITIONER ("Pet")', f_hdr, HEAD)
para((44, 164), "The sandboxed AI agent, with narrow, delegated spending authority. This pane is "
                "its entire view of the world - the RPC requests it sends and the responses it "
                "gets back, the same petitioner-facing view the operator can watch live in the "
                "Spacer TUI. Nothing else crosses the boundary.",
     f_body, BODY, 640, 18)

text((790, 136), "ARBITER", f_hdr, HEAD)
para((790, 164), "The operator's gatekeeper in front of the real wallet and node. Everything on "
                 "this side is private - Pet can never see it.",
     f_body, BODY, 640, 18)

# ---------- time arrow (far left) ----------
d.line([(31 * S, 292 * S), (31 * S, 546 * S)], fill="#4a4a4a", width=S)
d.polygon([(31 * S, 556 * S), (27 * S, 546 * S), (35 * S, 546 * S)], fill="#4a4a4a")
text((31, 285), "time", f_foot, "#5f5f5f", anchor="ms")

# ---------- log lines ----------
L1_Y, L2_Y, L3_Y, L4_Y = 292, 336, 392, 540
LX, RX = 52, 790
l1 = "23:00:37 [chain] -> op=query_balance"
l2 = "[chain] real: presented_sats=12103 real_sats=12103 snapshot_age_s=3.17"
l3 = "23:00:37 [chain] decision_allow op=query_balance"
l4 = "23:00:37 [chain] <- balance_sats=12000 status=ok"

text((LX, L1_Y), l1, f_log, GREY)
text((RX, L2_Y), l2, f_log, SALMON)
text((RX, L3_Y), l3, f_log, RED)
text((LX, L4_Y), l4, f_log, GREEN)

def badge(cx, cy, n, color):
    r = 10
    d.ellipse([(cx - r) * S, (cy - r) * S, (cx + r) * S, (cy + r) * S], outline=color, width=2 * S, fill=BG)
    text((cx, cy + 0.5), str(n), f_num, color, anchor="mm")

badge(LX - 24, L1_Y + 9, 1, GREY)
badge(RX - 20, L2_Y + 9, 2, SALMON)
badge(RX - 20, L3_Y + 9, 3, RED)
badge(LX - 24, L4_Y + 9, 4, GREEN)

# ---------- token highlights ----------
def hl(line_x, line_y, full, prefix, token, color):
    x0 = line_x + tlen(prefix, f_log)
    tw = tlen(token, f_log)
    rrect((x0 - 4, line_y - 4, x0 + tw + 4, line_y + 22), 4, outline=color, w=1)
    return x0, tw

hl(RX, L2_Y, l2, "[chain] real: presented_sats=12103 ", "real_sats=12103", AMBER)
sx, swid = hl(RX, L2_Y, l2, "[chain] real: presented_sats=12103 real_sats=12103 ", "snapshot_age_s=3.17", CYAN)
tx, twid = hl(LX, L4_Y, l4, "23:00:37 [chain] <- ", "balance_sats=12000", AMBER)

# ---------- callouts ----------
def callout(x, y, wmax, heading, body, accent, body_col=BODY):
    y0 = y
    text((x + 12, y), heading, f_call_h, accent)
    y = para((x + 12, y + 24), body, f_call, body_col, wmax, 18)
    d.rectangle([x * S, y0 * S, (x + 3) * S, (y - 4) * S], fill=accent)
    return y

callout(64, 326, 470, "1 - Pet asks for its balance",
        "It can poll as often as it likes - rapid polling reveals nothing extra (see 2).",
        "#9b9b9b")

text((810, 420), "3 - Policy check: reads are allowed. Spends would need explicit operator approval.",
     f_note, "#b98b90")

callout(810, 480, 620, '2 - Snapshot serving: Pet never sees "now"',
        "The reply is served from a cached snapshot - here 3.17 s old - refreshed on a "
        "randomized 5-15 s timer, never a live lookup. Pet cannot observe the instantaneous "
        "balance, so rapid polling recovers no timing information: when funds actually moved, "
        "or when the arbiter talks to its own node. (presented_sats is the snapshot's raw "
        "value, before rounding.)",
        CYAN, )

callout(64, 584, 600, "4 - Balance rounding at the boundary",
        "The real balance of 12,103 sats is floored to a 1,000-sat grid before it crosses: "
        "Pet sees 12,000. Sat-precision deltas - fees paid, deposit amounts, change from a "
        "settle - can never fingerprint real wallet activity.",
        AMBER)

# ---------- amber arrow: real_sats=12103 -> balance_sats=12000 ----------
rs_x = RX + tlen("[chain] real: presented_sats=12103 ", f_log)
rs_w = tlen("real_sats=12103", f_log)
# Route through the empty central corridor: glide left (below line 2, above line 3),
# then dive down into the top of the balance box. Avoids crossing any log text.
p0 = (rs_x - 2, L2_Y + 25)
p1 = (560, L2_Y + 24)
p2 = (300, 482)
p3 = (tx + twid * 0.45, L4_Y - 6)
pts = bezier(p0, p1, p2, p3)
dashed_path(pts, AMBER, w=1)
# arrowhead at p3, pointing along final tangent
import math
dx, dy = p3[0] - pts[-6][0], p3[1] - pts[-6][1]
ang = math.atan2(dy, dx)
ah = 9
left = (p3[0] - ah * math.cos(ang - 0.42), p3[1] - ah * math.sin(ang - 0.42))
rgt = (p3[0] - ah * math.cos(ang + 0.42), p3[1] - ah * math.sin(ang + 0.42))
d.polygon([(p3[0] * S, p3[1] * S), (left[0] * S, left[1] * S), (rgt[0] * S, rgt[1] * S)], fill=AMBER)
text((645, 430), "floored to 1,000-sat grid", f_lab, AMBER_H, anchor="mm")

# ---------- footer ----------
para((40, 714), "Spacer lets an AI client drive a Bitcoin node without learning about the "
                "operator's wallet, exact balances, or tx identifiers.",
     f_foot, "#6f6f6f", 1420, 16)

import os
out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "01-privacy-gateway-balance-query.png")
img.save(out)
print("wrote", out, img.size)
