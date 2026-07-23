#!/usr/bin/env python3
"""Annotated Spacer timing-mitigation demo figures (T1 amount gate + deferred
refusal, T2 timing shield). Shares the visual framework of
generate_mode_demos.py (imported from the same directory): Menlo, dark
terminal, two panes split by the dashed PRIVACY GATEWAY BOUNDARY rail,
numbered callouts, amber = amounts, cyan = timing, red = refusal, the
MUTINYNET SIGNET badge.

Every value shown is a real captured figure from ONE live sequence-T run
(2026-07-23, test-harness/scripts/live_sequence_t_runner.py) against the
captain-loop arbiter on Mutinynet signet - one wall clock, real chronology.
Raw evidence: ~/spacer/demo/captures/T1-amount-gate/ and T2-timing-shield/
(audit.jsonl + tui.txt + notes.md). Nothing is invented. Renders one PNG per
demo next to this file. Reproduce: `python3 generate_timing_demos.py`.
"""
from generate_mode_demos import (
    render, AMBER, CYAN, GREEN, RED,
)

FOOTER = ("Spacer lets an AI client drive a Bitcoin node without learning the "
          "operator's wallet, exact balances, addresses, or tx identifiers.")

T1 = {
    "out": "T1-amount-gate.png",
    "title": "Spacer: the amount gate and the deferred refusal",
    "subtitle": [
        "Every state-changing amount must sit on a fixed denomination ladder - "
        "and a refused call is indistinguishable from a passing",
        "one at submit. Two live sends, same recipient token, one wall clock. "
        "Real values, Mutinynet signet, test sats only.",
    ],
    "footer": FOOTER,
    "beats": [
        {
            "n": 1, "accent": RED,
            "left": ["-> op=manage_bitcoin amount_sats=1234 recipient_token=TQ9NNW",
                     "<- handle=OCNTngxToj60k38foeGAFw status=received"],
            "right": ["decision_refuse_denomination requested_sats=1234",
                      "decision_defer_rejection hold_s=2.3  (rejection window)"],
            "hl": [("L", 0, "-> op=manage_bitcoin ", "amount_sats=1234", AMBER),
                   ("L", 1, "<- handle=OCNTngxToj60k38foeGAFw ", "status=received", GREEN),
                   ("R", 0, "", "decision_refuse_denomination", RED)],
            "side": "R",
            "heading": "1 - 1,234 sats is not a denomination: refused, silently",
            "body": "Submitted amounts must come from a fixed 1-2-5 ladder (1k, 2k, "
                    "5k ... 1M sats) - round figures a large population also moves - so "
                    "an executed amount never fingerprints the operator's node on the "
                    "public chain. 1,234 fails the gate before the recipient registry "
                    "even runs. And the wire still says received.",
        },
        {
            "n": 2, "accent": GREEN,
            "left": ["-> op=manage_bitcoin amount_sats=1000 recipient_token=TQ9NNW",
                     "<- handle=MDKwXf-EWtB85EmOXldtNQ status=received"],
            "right": ["registry_lookup_ok token=TQ9NNW",
                      "standing_approval_match  ->  decision_allow",
                      "action_enqueued hold_s=12.2  (execution scheduled)"],
            "hl": [("L", 0, "-> op=manage_bitcoin ", "amount_sats=1000", AMBER),
                   ("L", 1, "<- handle=MDKwXf-EWtB85EmOXldtNQ ", "status=received", GREEN),
                   ("R", 2, "", "action_enqueued", CYAN)],
            "heading": "2 - 1,000 sats is on the ladder: same wire, different fate",
            "body": "The same recipient token with a ladder amount: the registry "
                    "resolves it, a standing approval clears it, and execution is "
                    "scheduled. The ack is byte-shape-identical to the refusal's - "
                    "status=received plus an opaque handle, latency-normalized to the "
                    "same floor - so submit carries no signal, by content or by "
                    "timing, of which gates fired or whether any did.",
        },
        {
            "n": 3, "accent": RED,
            "left": ["-> op=poll handle=OCNTngxToj60k38foeGAFw",
                     "<- result.status=failed",
                     "-> op=poll handle=MDKwXf-EWtB85EmOXldtNQ",
                     "<- result.status=sent result.amount_sats=1000"],
            "right": ["result_deposit kind=rejection  (window elapsed)",
                      "manage_bitcoin_executed txid=6708e01d...417265b8",
                      "result_deposit kind=result"],
            "hl": [("L", 1, "<- ", "result.status=failed", RED),
                   ("L", 3, "<- ", "result.status=sent", GREEN),
                   ("R", 1, "manage_bitcoin_executed ", "txid=6708e01d...417265b8", AMBER)],
            "side": "R",
            "heading": "3 - the refusal surfaces late, and looks like any failure",
            "body": "The refused call's outcome arrives only after a randomized "
                    "rejection window, as the same uniform failed a genuinely broken "
                    "send would produce - which gate fired (denomination, registry, "
                    "approval) stays operator-side. The passing call really moved "
                    "coin; its txid stays operator-side too. Probing the policy costs "
                    "a delivery-window wait per guess and returns one uniform bit.",
        },
    ],
}

T2 = {
    "out": "T2-timing-shield.png",
    "title": "Spacer: the timing shield",
    "subtitle": [
        "Four timing mitigations on one live send: a fixed latency floor at "
        "submit, a randomized action window, a randomized result",
        "window, and a 10-minute poll floor. One wall clock, real chronology. "
        "Real values, Mutinynet signet, test sats only.",
    ],
    "footer": FOOTER,
    "beats": [
        {
            "n": 1, "accent": CYAN,
            "left": ["-> op=query_balance             <- ok        261 ms",
                     "-> (malformed frame)            <- refused   256 ms",
                     "-> op=manage_bitcoin (refused)  <- received  256 ms",
                     "-> op=manage_bitcoin (passed)   <- received  255 ms"],
            "right": ["latency_normalized work_s=0.0012 held_s=0.2488",
                      "latency_normalized work_s=0.0004 held_s=0.2496",
                      "latency_normalized work_s=0.0044 held_s=0.2456",
                      "latency_normalized work_s=0.0059 held_s=0.2441"],
            "hl": [("R", 0, "latency_normalized work_s=0.0012 ", "held_s=0.2488", CYAN),
                   ("R", 3, "latency_normalized ", "work_s=0.0059", AMBER)],
            "side": "R",
            "heading": "1 - every answer takes 250 ms, whatever happened inside",
            "body": "Client-measured round-trips: four different pipeline branches - "
                    "a snapshot read, a malformed frame, a gate-refused write, a "
                    "gate-passed write - land on one wire latency. Operator-side, "
                    "latency_normalized records the truth: real work varies 0.4-5.9 ms "
                    "and the hold pads every response to the same 250 ms floor, so "
                    "response timing carries no information about which branch ran.",
        },
        {
            "n": 2, "accent": AMBER,
            "left": ["16:03:56  -> op=manage_bitcoin amount_sats=1000",
                     "16:03:56  <- handle=MDKwXf-EWtB85EmOXldtNQ status=received"],
            "right": ["16:03:56  action_enqueued hold_s=12.2  (5-15 s test window)",
                      "16:04:09  manage_bitcoin_executed txid=6708e01d...417265b8"],
            "hl": [("R", 0, "16:03:56  action_enqueued ", "hold_s=12.2", CYAN),
                   ("R", 1, "", "16:04:09", AMBER)],
            "side": "R",
            "heading": "2 - submit is not execute: the action-delay window",
            "body": "At submit the timing layer commits to a randomized hold - here "
                    "12.2 s inside the test-mode 5-15 s window; production windows "
                    "carry a ~12 h floor - and the executor fires only once it "
                    "elapses. Request timing and chain timing decorrelate: an "
                    "observer of the public chain cannot tie the broadcast back to "
                    "the AI's submission moment.",
        },
        {
            "n": 3, "accent": CYAN,
            "left": ["16:03:58  -> op=poll   <- not_yet",
                     "16:14:03  -> op=poll   <- result.status=sent"],
            "right": ["16:03:58  result_poll_unknown  (poll floor anchored: 10 min)",
                      "16:04:25  result_deposit kind=result  (result window)",
                      "16:14:03  result_poll_ok"],
            "hl": [("L", 0, "16:03:58  -> op=poll   <- ", "not_yet", CYAN),
                   ("L", 1, "16:14:03  -> op=poll   <- ", "result.status=sent", GREEN)],
            "side": "R",
            "heading": "3 - the answer is rationed: binary state behind a poll floor",
            "body": "An early poll gets only the binary not_yet - no progress, no "
                    "ETA - and anchors a 10-minute per-handle floor; polling faster "
                    "returns the same not_yet without touching state. The result was "
                    "sitting ready from 16:04:25, but the AI could not learn it "
                    "before the floor elapsed. One successful poll consumes it; "
                    "afterwards the handle is indistinguishable from one that never "
                    "existed.",
        },
    ],
}


if __name__ == "__main__":
    for spec in (T1, T2):
        render(spec)
