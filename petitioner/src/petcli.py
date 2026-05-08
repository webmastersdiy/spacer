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

Per design-docs/2026-05-05-0948-architecture-overview.md §5.1, §5.2.

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
    |   |-- send-bitcoin           Bitcoin send by recipient token
    |   `-- send-lightning         Lightning send by recipient token
    |-- query                      read-only inspection (§3 last paragraph)
    |   |-- balance                node balance (banded)
    |   `-- channels               LN channels (aggregate-by-default)
    |-- result                     poll the result registry (§4.8)
    |   `-- poll                   check for a result against a handle
    `-- estimate                   local-only estimate display (§5.2)
        `-- window                 upper-bound seconds, no arbiter call

Specific command shape (which commands exist, what flags) is an
implementation decision per §5.1; the doc deliberately does not
enumerate it.
"""
import argparse
import json
import sys

import estimate
import protocol


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
        params={"to_token": args.to_token, "amount_sats": args.amount_sats},
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


def _do_submit_send_lightning(args):
    response = protocol.submit(
        op="send_lightning",
        params={
            "to_token": args.to_token,
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


def _do_query_balance(args):
    response = protocol.submit(
        op="query_balance",
        params={},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    _emit(response)


def _do_query_channels(args):
    response = protocol.submit(
        op="query_channels",
        params={},
        host=args.host,
        port=args.port,
        timeout_s=args.timeout_s,
    )
    _emit(response)


def _do_result_poll(args):
    response = protocol.submit(
        op="result_poll",
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

    sl = submit_sub.add_parser(
        "send-lightning",
        help="send a Lightning payment to a recipient token",
        description=(
            "Send a Lightning payment to a recipient token from the "
            "arbiter's recipient address registry (§4.7). The token "
            "is a pseudonym; the real invoice/offer/pubkey never "
            "appears AI-side."
        ),
    )
    sl.add_argument(
        "--to-token", required=True, help="recipient address registry token"
    )
    sl.add_argument(
        "--amount-msats",
        required=True,
        type=int,
        help="amount in millisatoshis",
    )
    _add_endpoint_flags(sl)
    sl.set_defaults(func=_do_submit_send_lightning)

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

    qc = query_sub.add_parser(
        "channels",
        help="list Lightning channels (aggregate-by-default)",
        description=(
            "List Lightning channels. Aggregate-by-default applies "
            "(§4.1, §6): the response is summary-shaped unless the "
            "arbiter has been asked, with audit-logged justification, "
            "for per-item detail."
        ),
    )
    _add_endpoint_flags(qc)
    qc.set_defaults(func=_do_query_channels)

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
