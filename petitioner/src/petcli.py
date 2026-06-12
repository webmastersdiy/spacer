#!/usr/bin/env python3
"""
petcli - the spacer petitioner CLI.

Single CLI tool exposed to the AI, organized as a nested tree of
commands and subcommands with informative --help at every node. The AI
discovers available operations by walking the help output rather than
relying on external documentation. petcli is a thin protocol shim: it
translates AI requests into spacer-protocol messages, presents the
arbiter's responses back, and computes a local upper-bound estimate
for the action+result delay window (§5.2).

Per design-docs/origin/05--2026-05-05-0948-architecture-overview.md §5.1, §5.2.

Constraints:
- Holds no secrets, no policy, no state the AI cannot already reach.
- The protocol shim is the only first-class function. The local
  estimate is a placeholder upper bound (§5.2 leaves the exact
  method open; sp-77lxs.9 explicitly accepts a placeholder).
- petcli does not interpret arbiter responses. Decision logic lives
  on the AI side; petcli's job is to render whatever JSON the
  arbiter returned.

Command tree:

    petcli
    |-- submit                     state-changing actions (§3, §4.6)
    |   `-- send-bitcoin           Bitcoin send by recipient token
    |-- query                      read-only inspection (§3 last paragraph)
    |   `-- balance                node balance (banded)
    |-- result                     poll the result registry (§4.8)
    |   `-- poll                   check for a result against a handle
    |-- estimate                   local-only estimate display (§5.2)
    |   `-- window                 upper-bound seconds, no arbiter call
    `-- advanced                   opt-in extensions (arbiter SPACER_MODE gates)
        |-- send-lightning         Lightning send by recipient token
        |-- channels               LN channels (aggregate-by-default)
        `-- ecash                  eCash extension (SPACER_MODE=ecash; doc 07)
            |-- fund               arbiter-mediated: operator wallet -> float
            |-- defund             arbiter-mediated: float -> operator wallet
            |-- balance            local wallet: count the float
            |-- send               local wallet: serialize a token to hand off
            |-- receive            local wallet: swap-claim a token
            `-- info               local wallet / mint info

Bitcoin on-chain is the primary surface: send-bitcoin and balance live
at the top of the tree. The Lightning commands move under `advanced`
because they belong to the opt-in advanced extension - the arbiter only
honors them when it runs SPACER_MODE=lightning|full; an onchain-mode
arbiter refuses them uniformly. petcli holds no policy, so it always
exposes the `advanced` namespace for discovery; the mode gate lives on
the arbiter side.

The eCash commands (design doc 07) split along the custody boundary:
`fund` and `defund` are arbiter-mediated writes (ops fund_ecash /
defund_ecash; honored only under SPACER_MODE=ecash, refused uniformly
elsewhere), while `balance`, `send`, `receive`, and `info` are local
operations on the AI's own bearer wallet - they shell out to the
petitioner-side cashu CLI and never touch the arbiter. That is the
extension's point: value inside the float moves without the gateway
mediating each action.

Specific command shape (which commands exist, what flags) is an
implementation decision per §5.1; the doc deliberately does not
enumerate it.
"""
import argparse
import json
import os
import subprocess
import sys

import estimate
import protocol

# The petitioner-side cashu CLI for the local eCash wallet commands.
# PATH resolution is acceptable here - the petitioner runs inside the
# AI's environment and holds no operator secrets, so the arbiter-side
# pin-everything discipline does not apply; the env overrides exist so
# the AI's environment (and the exit-loop harness) can point at a
# specific binary. The wallet's own configuration (mint URL, wallet
# dir) is the AI environment's concern: petcli passes the subcommand
# argv through unmodified and adds no flags, holding no policy here
# either.
DEFAULT_CASHU_BIN = "cashu"
DEFAULT_CASHU_TIMEOUT_S = 60.0


def _emit(response):
    """Write a response on stdout as compact, key-sorted JSON.

    Compact keeps lines stable across runs; key-sorted means a given
    response prints byte-identically every time so exit-loop/
    artifacts (§10) compare cleanly without diff noise. petcli does
    not interpret responses, only format them.
    """
    json.dump(response, sys.stdout, separators=(",", ":"), sort_keys=True)
    sys.stdout.write("\n")


def _add_endpoint_flags(parser):
    """Attach --host / --port / --timeout-s. Connection settings are
    not secrets; the AI may already know them (the arbiter is in the
    petitioner's environment from the AI's perspective). Defaults
    fall back to PETCLI_* env vars and finally to the gateway's
    documented defaults (127.0.0.1:8420)."""
    parser.add_argument(
        "--host",
        default=None,
        help="arbiter host (env PETCLI_HOST, default 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        default=None,
        type=int,
        help="arbiter port (env PETCLI_PORT, default 8420)",
    )
    parser.add_argument(
        "--timeout-s",
        default=None,
        type=float,
        help="HTTP request timeout in seconds (env PETCLI_TIMEOUT_S, default 60)",
    )


def _do_submit_send_bitcoin(args):
    response = protocol.submit(
        op="send_bitcoin",
        # Wire field is `recipient_token`: the arbiter's privacy gateway
        # resolves it through the recipient address registry (§4.7). The
        # CLI flag stays `--to-token` for operator brevity; the rename
        # happens here, on the wire boundary.
        params={
            "recipient_token": args.to_token,
            "amount_sats": args.amount_sats,
        },
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    # Stamp the local upper-bound estimate alongside the arbiter
    # response. Doing this on every state-changing submit gives the
    # AI a single point at which it sees both the handle and the
    # window in which the result might appear (§5.2). The leading
    # underscore marks it as a petitioner-side annotation rather
    # than something the arbiter said.
    response["_petcli_estimate_window_s"] = (
        estimate.action_plus_result_window_s()
    )
    _emit(response)


def _do_advanced_send_lightning(args):
    # Lightning send: an advanced-extension command. The wire op is the
    # same send_lightning the gateway has always routed; only the petcli
    # command path moved under `advanced`. An onchain-mode arbiter
    # refuses this uniformly (the mode gate), so the AI sees the standard
    # refusal body when the extension is not enabled.
    response = protocol.submit(
        op="send_lightning",
        # Same wire-field convention as send-bitcoin above: the CLI
        # exposes `--to-token` for brevity, the wire body carries
        # `recipient_token` because that is what the gateway's
        # pseudonymize-inbound step looks for.
        params={
            "recipient_token": args.to_token,
            "amount_msats": args.amount_msats,
        },
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    response["_petcli_estimate_window_s"] = (
        estimate.action_plus_result_window_s()
    )
    _emit(response)


def _do_advanced_ecash_fund(args):
    # eCash fund: an arbiter-mediated write (op fund_ecash, doc 07 §3).
    # No recipient token - the destination is structurally the
    # arbiter's operator-pinned mint - so the body carries only the
    # amount. The arbiter honors this under SPACER_MODE=ecash only and
    # gates it on the allowance cap and standing approvals; any other
    # mode refuses uniformly.
    response = protocol.submit(
        op="fund_ecash",
        params={"amount_sats": args.amount_sats},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    response["_petcli_estimate_window_s"] = (
        estimate.action_plus_result_window_s()
    )
    _emit(response)


def _do_advanced_ecash_defund(args):
    # eCash defund: the float -> operator-wallet crossing (op
    # defund_ecash). The request body carries the serialized cashuB
    # token being returned; the arbiter swap-claims and melts it at
    # execution time. Like fund, ecash-mode only.
    response = protocol.submit(
        op="defund_ecash",
        params={"token": args.token},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    response["_petcli_estimate_window_s"] = (
        estimate.action_plus_result_window_s()
    )
    _emit(response)


def _run_local_cashu(cashu_args):
    """Run the petitioner-side cashu CLI and emit its outcome as a
    JSON object, keeping petcli JSON-shaped end-to-end.

    petcli does not interpret the wallet's output any more than it
    interprets arbiter responses: stdout/stderr are presented
    verbatim under a structured envelope, and the leading-underscore
    `_petcli_local` marker distinguishes a local wallet outcome from
    anything the arbiter said (mirroring `_petcli_transport_error`).
    Binary-missing and timeout failures surface as structured errors
    rather than tracebacks for the same reason.
    """
    bin_path = os.environ.get("PETCLI_CASHU_BIN", DEFAULT_CASHU_BIN)
    timeout_s = float(
        os.environ.get("PETCLI_CASHU_TIMEOUT_S", DEFAULT_CASHU_TIMEOUT_S)
    )
    # Argv list, no shell: token strings and amounts pass through
    # without shell-metacharacter expansion.
    cmd = [bin_path] + [str(a) for a in cashu_args]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
    except FileNotFoundError:
        _emit({
            "_petcli_local": True,
            "error": f"cashu binary not found: {bin_path}",
        })
        return
    except subprocess.TimeoutExpired:
        _emit({
            "_petcli_local": True,
            "error": f"cashu timed out after {timeout_s}s",
        })
        return
    _emit({
        "_petcli_local": True,
        "exit_code": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    })


def _do_advanced_ecash_balance(args):
    _run_local_cashu(["balance"])


def _do_advanced_ecash_send(args):
    _run_local_cashu(["send", args.amount_sats])


def _do_advanced_ecash_receive(args):
    _run_local_cashu(["receive", args.token])


def _do_advanced_ecash_info(args):
    _run_local_cashu(["info"])


def _do_query_balance(args):
    response = protocol.submit(
        op="query_balance",
        params={},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    _emit(response)


def _do_advanced_channels(args):
    # LN channels query: an advanced-extension command. The wire op is
    # the same query_channels; only the petcli command path moved under
    # `advanced`. An onchain-mode arbiter refuses this uniformly.
    response = protocol.submit(
        op="query_channels",
        params={},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    _emit(response)


def _do_result_poll(args):
    # Wire op is "poll" because the gateway's read-only fast-path
    # (gateway.py: process_request) routes on op == "poll" rather
    # than the longer petcli command path "result poll". The petcli
    # function name and the command path stay descriptive; the wire
    # op stays terse to match the gateway's single-token routing.
    response = protocol.submit(
        op="poll",
        params={"handle": args.handle},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    _emit(response)


def _do_estimate_window(args):
    """§5.2 estimate display. Local-only: never asks the arbiter."""
    _emit({
        "estimate_window_seconds": estimate.action_plus_result_window_s(),
        "method": "placeholder_upper_bound",
        "note": "§5.2 estimate is local; petcli never asks the arbiter for it",
    })


def _build_parser():
    """Build the argparse tree.

    Every node carries its own description so `petcli --help`,
    `petcli submit --help`, `petcli submit send-bitcoin --help`, etc.,
    each stand alone as a discoverable surface. Subparser containers
    are required so a partial command (`petcli submit` with no op)
    fails with a usage line rather than silently succeeding.
    """
    p = argparse.ArgumentParser(
        prog="petcli",
        description=(
            "Spacer petitioner CLI. Translates AI requests into spacer-"
            "protocol messages and presents arbiter responses. Holds no "
            "secrets, no policy, no state."
        ),
    )
    sub = p.add_subparsers(dest="cmd", metavar="<command>")
    sub.required = True

    # --- submit: state-changing actions ----------------------------
    submit_p = sub.add_parser(
        "submit",
        help="state-changing actions (subject to action+result delay windows)",
        description=(
            "Submit a state-changing action to the arbiter. The "
            "submission returns an opaque handle synchronously. Every "
            "AI-observable consequence (on-chain visibility, result "
            "knowledge) is deferred by the timing layer (§3, §4.6); "
            "use `petcli result poll <handle>` to check for the "
            "eventual outcome."
        ),
    )
    submit_sub = submit_p.add_subparsers(dest="submit_op", metavar="<op>")
    submit_sub.required = True

    sb = submit_sub.add_parser(
        "send-bitcoin",
        help="send Bitcoin to a recipient address registry token",
        description=(
            "Send Bitcoin to a recipient token from the arbiter's "
            "recipient address registry (§4.7). The token is a "
            "pseudonym; the real address never appears AI-side. "
            "Tokens are one-time-use and have an expiry."
        ),
    )
    sb.add_argument(
        "--to-token", required=True, help="recipient address registry token"
    )
    sb.add_argument(
        "--amount-sats", required=True, type=int, help="amount in satoshis"
    )
    _add_endpoint_flags(sb)
    sb.set_defaults(func=_do_submit_send_bitcoin)

    # --- query: read-only inspection -------------------------------
    query_p = sub.add_parser(
        "query",
        help="read-only inspection (no timing layer; outbound filters apply)",
        description=(
            "Read-only queries to the arbiter. These skip the action+"
            "result timing layer (§3 last paragraph) but still pass "
            "through the outbound filter pipeline of the privacy "
            "gateway: pseudonymize, banding, aggregate-by-default, "
            "hide-secrets, and latency-normalization (§4.1, §6)."
        ),
    )
    query_sub = query_p.add_subparsers(dest="query_op", metavar="<op>")
    query_sub.required = True

    qb = query_sub.add_parser(
        "balance",
        help="show banded node balance",
        description=(
            "Return the node's balance summary. Numeric values are "
            "banded by the privacy gateway before they leave the "
            "arbiter (§6, banding)."
        ),
    )
    _add_endpoint_flags(qb)
    qb.set_defaults(func=_do_query_balance)

    # --- result: poll the result registry --------------------------
    result_p = sub.add_parser(
        "result",
        help="poll the result registry (§4.8)",
        description=(
            "Pull-only access to the result registry (§4.8). A poll "
            "returns either the result for the given handle or "
            "'not yet'. There is no in-progress state. The privacy "
            "gateway throttles polls for the same handle to a "
            "10-minute floor; faster cadences reveal nothing the "
            "10-minute cadence would not."
        ),
    )
    result_sub = result_p.add_subparsers(dest="result_op", metavar="<op>")
    result_sub.required = True

    rp = result_sub.add_parser(
        "poll",
        help="check for a result against a handle",
        description=(
            "Poll the result registry for a given handle. Returns "
            "the final filtered result (success or rejection) or "
            "'not yet'. Subject to the 10-minute poll floor (§4.8)."
        ),
    )
    rp.add_argument(
        "--handle", required=True, help="opaque handle returned by `submit`"
    )
    _add_endpoint_flags(rp)
    rp.set_defaults(func=_do_result_poll)

    # --- estimate: local-only display (§5.2) -----------------------
    estimate_p = sub.add_parser(
        "estimate",
        help="local-only estimate display (§5.2; never calls the arbiter)",
        description=(
            "Display the petitioner's local upper-bound estimate of "
            "the action delay + result delay window. Per §5.2 this "
            "estimate is computed locally from the petitioner's own "
            "view of similar global activity, with no input from the "
            "arbiter and no arbiter guarantee on the bound. The "
            "current implementation is a placeholder upper bound, "
            "explicitly accepted for early scaffolding (sp-77lxs.9)."
        ),
    )
    estimate_sub = estimate_p.add_subparsers(
        dest="estimate_op", metavar="<op>"
    )
    estimate_sub.required = True

    ew = estimate_sub.add_parser(
        "window",
        help="show upper-bound seconds for action+result delay",
        description=(
            "Print the petitioner's local upper-bound estimate (in "
            "seconds) of how long until a submitted state-changing "
            "action's result becomes pollable. Local-only by design "
            "(§5.2)."
        ),
    )
    ew.set_defaults(func=_do_estimate_window)

    # --- advanced: opt-in extensions --------------------------------
    # Bitcoin on-chain is primary; the Lightning and eCash commands
    # live here under `advanced` because the arbiter only honors them
    # when it runs the corresponding extension (Lightning:
    # SPACER_MODE=lightning|full; eCash: SPACER_MODE=ecash). petcli
    # holds no policy and cannot see the arbiter's mode, so it always
    # exposes these for discovery; an arbiter without the extension
    # refuses them uniformly (the wire response is the standard
    # refusal body).
    advanced_p = sub.add_parser(
        "advanced",
        help=(
            "opt-in extension commands: Lightning "
            "(SPACER_MODE=lightning|full) and eCash (SPACER_MODE=ecash)"
        ),
        description=(
            "Advanced extensions, grouped here to signal they are "
            "opt-in. The Lightning commands speak the same Lightning "
            "ops the gateway has always routed (send_lightning, "
            "query_channels); the arbiter honors them only when "
            "deployed with the Lightning extension "
            "(SPACER_MODE=lightning|full). The ecash group layers the "
            "eCash extension on top (SPACER_MODE=ecash; design doc "
            "07). An arbiter without the corresponding extension - "
            "onchain is the default - refuses these uniformly. "
            "Bitcoin on-chain commands (submit send-bitcoin, query "
            "balance) are the primary surface."
        ),
    )
    advanced_sub = advanced_p.add_subparsers(dest="advanced_op", metavar="<op>")
    advanced_sub.required = True

    asl = advanced_sub.add_parser(
        "send-lightning",
        help="send a Lightning payment to a recipient token",
        description=(
            "Send a Lightning payment to a recipient token from the "
            "arbiter's recipient address registry (§4.7). The token is a "
            "pseudonym; the real invoice/offer/pubkey never appears "
            "AI-side. Advanced extension: refused uniformly unless the "
            "arbiter runs SPACER_MODE=lightning|full."
        ),
    )
    asl.add_argument(
        "--to-token", required=True, help="recipient address registry token"
    )
    asl.add_argument(
        "--amount-msats",
        required=True,
        type=int,
        help="amount in millisatoshis",
    )
    _add_endpoint_flags(asl)
    asl.set_defaults(func=_do_advanced_send_lightning)

    ach = advanced_sub.add_parser(
        "channels",
        help="list Lightning channels (aggregate-by-default)",
        description=(
            "List Lightning channels. Aggregate-by-default applies "
            "(§4.1, §6): the response is summary-shaped unless the "
            "arbiter has been asked, with audit-logged justification, "
            "for per-item detail. Advanced extension: refused uniformly "
            "unless the arbiter runs SPACER_MODE=lightning|full."
        ),
    )
    _add_endpoint_flags(ach)
    ach.set_defaults(func=_do_advanced_channels)

    # --- advanced ecash: the eCash extension (design doc 07) --------
    # Custody split per doc 07 §3: fund/defund are arbiter-mediated
    # writes (every custody crossing is gateway-mediated); balance/
    # send/receive/info operate the AI's own local bearer wallet
    # (movement within the float is not mediated - the autonomy the
    # extension buys). As with the rest of `advanced`, the namespace
    # is always visible for discovery and the mode gate lives on the
    # arbiter side (SPACER_MODE=ecash).
    ecash_p = advanced_sub.add_parser(
        "ecash",
        help="eCash extension commands (arbiter SPACER_MODE=ecash; doc 07)",
        description=(
            "Chaumian eCash (Cashu) extension, layered on top of the "
            "Lightning extension. fund/defund cross the custody "
            "boundary and are arbiter-mediated (ops fund_ecash / "
            "defund_ecash; honored only when the arbiter runs "
            "SPACER_MODE=ecash, refused uniformly elsewhere; fund is "
            "additionally bounded by the operator's eCash allowance). "
            "balance/send/receive/info operate the local bearer "
            "wallet directly - they shell out to the petitioner-side "
            "cashu CLI (env PETCLI_CASHU_BIN) and never touch the "
            "arbiter."
        ),
    )
    ecash_sub = ecash_p.add_subparsers(dest="ecash_op", metavar="<op>")
    ecash_sub.required = True

    ef = ecash_sub.add_parser(
        "fund",
        help="fund the eCash float from the operator wallet (arbiter-mediated)",
        description=(
            "Submit a fund_ecash write: move amount-sats from the "
            "operator's Lightning liquidity into the AI's eCash "
            "float, via the arbiter's full write pipeline (allowance "
            "cap, standing approvals / HITL, action+result delays). "
            "The serialized token arrives later via `petcli result "
            "poll`. eCash extension: refused uniformly unless the "
            "arbiter runs SPACER_MODE=ecash."
        ),
    )
    ef.add_argument(
        "--amount-sats", required=True, type=int, help="amount in satoshis"
    )
    _add_endpoint_flags(ef)
    ef.set_defaults(func=_do_advanced_ecash_fund)

    ed = ecash_sub.add_parser(
        "defund",
        help="return float value to the operator wallet (arbiter-mediated)",
        description=(
            "Submit a defund_ecash write: hand a serialized cashuB "
            "token back across the custody boundary. The arbiter "
            "swap-claims and melts it to its own Lightning node at "
            "execution time. Subject to standing approvals / HITL "
            "and the action+result delays; no allowance check "
            "(defund only shrinks the float). eCash extension: "
            "refused uniformly unless the arbiter runs "
            "SPACER_MODE=ecash."
        ),
    )
    ed.add_argument(
        "--token", required=True, help="serialized cashuB token to return"
    )
    _add_endpoint_flags(ed)
    ed.set_defaults(func=_do_advanced_ecash_defund)

    eb = ecash_sub.add_parser(
        "balance",
        help="count the local eCash float (local wallet; no arbiter)",
        description=(
            "Show the local bearer wallet's balance. Local-only: "
            "runs the petitioner-side cashu CLI. The float is "
            "precisely countable by design (doc 07 §5.2: scale "
            "cloaking does not apply to a bearer instrument in "
            "hand)."
        ),
    )
    eb.set_defaults(func=_do_advanced_ecash_balance)

    es = ecash_sub.add_parser(
        "send",
        help="serialize float value into a token to hand off (local wallet)",
        description=(
            "Serialize amount-sats of the local float into a cashuB "
            "token string for handoff to a third party. Local-only: "
            "runs the petitioner-side cashu CLI; no arbiter "
            "mediation (the autonomy the extension buys)."
        ),
    )
    es.add_argument(
        "--amount-sats", required=True, type=int, help="amount in satoshis"
    )
    es.set_defaults(func=_do_advanced_ecash_send)

    er = ecash_sub.add_parser(
        "receive",
        help="swap-claim a received token into the float (local wallet)",
        description=(
            "Claim a serialized cashuB token into the local wallet "
            "by swapping it at the mint (which invalidates the "
            "handed-off proofs). Local-only: runs the petitioner-"
            "side cashu CLI."
        ),
    )
    er.add_argument(
        "--token", required=True, help="serialized cashuB token to claim"
    )
    er.set_defaults(func=_do_advanced_ecash_receive)

    ei = ecash_sub.add_parser(
        "info",
        help="show local wallet / mint info (local wallet)",
        description=(
            "Show the local wallet's view of itself and its mint. "
            "Local-only: runs the petitioner-side cashu CLI."
        ),
    )
    ei.set_defaults(func=_do_advanced_ecash_info)

    return p


def main(argv=None):
    """Parse argv and dispatch to the leaf handler. Each leaf parser
    sets a `func` default; intermediate nodes do not, so a partial
    invocation falls into the `not hasattr` belt-and-suspenders path
    even on Python versions where required-subparsers does not error
    cleanly on its own."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help(sys.stderr)
        sys.exit(2)
    args.func(args)


if __name__ == "__main__":
    main()
