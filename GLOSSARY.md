# Glossary

Authoritative vocabulary for talking about the `~/spacer` project: the
gateway we are designing, the testbed we run it against, and the
Bitcoin/Lightning concepts that show up often enough that imprecise
use is expensive. Use these terms in prose, in commit
messages, in design docs, and in conversation. The whole point is to
be less verbose and more precise: say "AI-facing privacy" instead of
"the privacy concern where the AI client itself is the adversary."
Say "banding" instead of "returning the balance as a bucket like
`>=50k` instead of an exact integer."

When this glossary disagrees with code or another doc, code wins for
fact, this glossary wins for naming. Update the loser.

## How to read this doc

Terms are grouped by their role: project axes (the load-bearing
distinctions), the testbed we exercise the design against, the Bitcoin
and Lightning primitives we lean on, the mitigations we have
designed, the side channels we worry about, and a small set of
project-internal artifacts (wrappers, wallets) worth naming.

## Project axes

These are the load-bearing distinctions. Every design decision in
spacer routes through one of them.

### Spacer

The umbrella name for this project. Currently a research workspace
at `~/spacer/` (testbed, session state, design docs, an installed
Mutinynet node stack); will graduate to a GitHub repository of the
same name that encompasses both **design** (the docs already in
`design-docs/`) and **implementation** of a two-component system:

- the **arbiter** (server-side node), running alongside bitcoind
  and LND on a host the AI cannot reach; bundles the privacy
  gateway, the bitcoin/LN client access, the local state, and the
  audit log; and
- the **petitioner** (client-side process), running in the AI's
  own environment; holds no secrets; speaks the spacer protocol
  to the arbiter on the AI's behalf.

The trust boundary is the protocol itself. All sensitive
filtering, gating, and state lives on the arbiter; the petitioner
is a thin protocol shim.

Goal: let an AI client drive a Bitcoin and Lightning node without
learning more about the operator's wallet, balances, or identifiers
than the task requires.

### Arbiter

The server-side node in the spacer system. The host the AI cannot
reach (no shell, no filesystem, no inbound network except the
spacer protocol). Bundles together everything that must stay out
of the AI's reach:

- the **privacy gateway** (the request-path process that filters
  and gates each call; see entry below);
- access to the bitcoin clients (`bitcoin-cli` against the local
  bitcoind);
- access to the LND clients (`lncli`, plus gRPC/REST against LND);
- local state (audit log, policy tables, token-to-real-value
  mappings, HITL approval queue);
- the ability to write the immutable audit log.

The arbiter decides what the petitioner is allowed to learn or
do. Naming rationale: an arbiter judges and decides; the role is
broader than "gateway" because the arbiter also owns the state and
the client-tool access. The privacy gateway is one process running
on the arbiter; the arbiter is the whole environment.

Arbiter implementation discipline (manual auditability,
`spacer/arbiter/src/` layout, minimal-and-inline-documented-only
constraints) is documented in the architecture doc.

See also: [Architecture overview, §2.1](design-docs/2026-05-05-0948-architecture-overview.md#21-arbiter-implementation-discipline).

### Petitioner

The client-side process in the spacer system. Runs in the AI's
own environment. Holds no secrets - anything it knows or caches
is reachable by the AI. Translates AI requests into spacer-
protocol messages addressed to the arbiter, and presents the
arbiter's responses back to the AI. That is all it does;
everything else lives on the arbiter.

Naming rationale: a petitioner asks. The petitioner requests; the
arbiter decides. The asymmetric register is intentional and
reflects the trust direction.

### Privacy gateway

One of the processes running on the **arbiter**. Specifically,
the process that sits in the request path between the petitioner
and the local bitcoind/LND clients, applying the AI-facing
filters and gating policy on every call. The privacy gateway is
*not* the entire arbiter - the arbiter also owns the client-tool
access, the local state, and the immutable audit log (see
Arbiter entry above). The privacy gateway must run on the arbiter
and nowhere else: putting any of its logic on the petitioner
side places it in reach of the AI and defeats the point.

The privacy gateway is the primary AI-facing defense; world-facing
mitigations like Tor are defense-in-depth on top of it. Not yet
implemented; the design docs in `design-docs/` are the current
artifact. Position in the data flow, the limited-and-airtight
constraints, and the per-request mechanism list are documented in
the architecture doc.

See also: [Architecture overview, §3](design-docs/2026-05-05-0948-architecture-overview.md#3-end-to-end-data-flow) and [§4.1](design-docs/2026-05-05-0948-architecture-overview.md#41-privacy-gateway).

### AI-facing privacy

Privacy where the AI client is the adversary, on two distinct
threat axes:

1. **Surveillance**: the AI reads more than the task requires
   (balances, UTXO sets, identifiers, history). Cause may be
   malice, compromise, prompt injection, or simply a disposition
   to gather context greedily. Mitigation: the arbiter returns
   only what the task requires - filter responses, pseudonymize
   identifiers, band numeric values, hide secrets, aggregate
   by default.

2. **Unexpected actions**: the AI initiates an operation the
   operator did not intend - new destination, unusual amount,
   strange tx shape. Mitigation: the arbiter gates state-changing
   calls against policy and pauses anything anomalous for
   out-of-band human approval (see **Human-in-the-loop approval**
   below). Logging alone does not prevent unexpected actions; it
   only records them.

Both axes are backed by an immutable audit log on the arbiter:
the petitioner cannot reach it, so the AI cannot tamper with the
record even if it fully owns its environment. AI-facing privacy is the
**primary** scope of spacer; world-facing privacy is a separate,
secondary concern, kept in different documents because the
adversaries, mitigations, and priorities differ.

### World-facing privacy

Privacy from everyone except the AI: public Bitcoin and Lightning
networks, the peer nodes we connect to, block explorers we query,
faucets that fund us, hosting providers we run on. Mitigations are
infrastructure-layer: Tor for transport anonymity, multi-peer
broadcast, private channels, self-hosted esplora, avoiding
identity-binding funding sources. World-facing privacy alone does not
defend against the AI; AI-facing privacy alone makes world-facing
leaks survivable (the AI cannot connect public observations to our
node if it does not know our node's identity).

## Testbed

The concrete pieces we run against to produce real txids, balances,
and timing data. Everything here is throwaway and Mutinynet-only;
nothing in spacer touches mainnet.

### Mutinynet

A custom signet variant maintained by the Mutiny wallet team. Targets
~30-second blocks (vs. signet default 10 minutes), uses a custom
`signetchallenge`, and has a single team-operated peer at
`45.79.52.207`. Funded via the public faucet at
`https://faucet.mutinynet.com`. Block explorer at
`https://mutinynet.com`. Mutinynet is not a production network; it
exists for testing Lightning-on-signet workflows that need faster
confirmations than vanilla signet.

### Voltage

A managed Lightning node hosting service (`https://voltage.cloud`).
Free Essentials tier allows one Mutinynet node per account. We use it
to host Node A, the LND instance the test flow drives. Voltage
operators have unconditional visibility into the LND process,
datadir, wallet, macaroons, and TLS - they are out of scope for the
arbiter's defenses and a known-trust dependency. Self-hosting LND
removes Voltage from the threat list at the cost of hardware and
uptime maintenance.

### Faucet (Mutinynet faucet)

`https://faucet.mutinynet.com`. Issues sats to a supplied address
(on-chain) or pays a supplied bolt11 invoice (Lightning). On-chain
funding requires GitHub OAuth; bolt11 issuance via `POST /api/bolt11`
does not. The faucet operator's records link our GitHub identity to
the receiving address and to the payout txid, which is a world-facing
identity-binding leak. The faucet's LN node serves as our test
counterparty for channel open, payinvoice, and cooperative close.

### Esplora

A block explorer HTTP API, originally from Blockstream. We use the
public esplora at `https://mutinynet.com/api` to poll transaction
confirmation status during test flows. Each `/api/tx/<txid>/status`
request links our IP to that txid in the operator's logs. Polling
frequency reveals urgency. World-facing mitigation: run a local
esplora indexed on top of our pruned bitcoind, point all polling at
`http://localhost:PORT`, eliminate the third-party log entry.

### Node A

The single Voltage-hosted LND node (`first-test.u.voltageapp.io`)
that drives the LND test flow. Its pubkey is
`029ec3af8da98bb3f5825b74bf0e5b0c4cb401a602cca7afd25fc84a4279f62617`.
Identified by name in design docs to disambiguate from the faucet's
LN node ("counterparty") and from any future second node.

### Local bitcoind

The locally self-hosted Bitcoin Core instance under `~/spacer/arbiter/bitcoin/`.
Built from the `mutinynet-covtools` tag of `benthecarman/bitcoin`
(v25.99.0-gf036909dbe28). Runs as a pruned signet node
(`prune=2200`, `txindex=0`) with a single addnode peer at
`45.79.52.207:38333`. Locally self-hosted - not remote - because the
arbiter must sit on the same host or LAN as the daemon; a remote
bitcoind would move the trust boundary to a third party.

### lncliA

A throwaway shell wrapper at `~/spacer/test-harness/scripts/lncliA` that calls
`lncli` with the rpcserver, tlscertpath, macaroonpath, and network
flags pre-filled for Node A. Every Lightning command in the test
flow goes through it. The wrapper exists so each command is one
line in the doc; a long invocation with five flags would obscure
which command is actually being run.

### btccli

The bitcoind-side equivalent of lncliA: a wrapper at
`~/spacer/test-harness/scripts/btccli` that calls `bitcoin-cli` with `-datadir`
prefilled. Wallet-scoped calls add `-rpcwallet=spacer-smoke`. Same
purpose as lncliA: keep individual command lines short and readable.

### spacer-smoke

The throwaway descriptor wallet created on the local bitcoind for
smoke tests. Created during the bitcoind setup flow; not seeded with
mainnet funds; cannot be reused. The naming convention is "smoke"
to make it obvious to future readers that this wallet is exploratory.

### ldk-node

The Lightning Dev Kit node implementation. Considered as an alternative
local LN backend in the test flow but blocked because the Python
bindings are not on PyPI and require a Rust toolchain to build (see
`state/INSTALL_BLOCKER.md`). Its API surface is documented in
`state/ldk_notes.md`; the gateway design treats ldk-node and LND as
equivalent backends for filter-rule purposes since their privacy
surfaces overlap heavily.

## Bitcoin and Lightning primitives we lean on

The terms below are not invented by this project; they are standard
Bitcoin/Lightning vocabulary. They show up in nearly every design
doc and merit explicit definitions because slight imprecision is
expensive.

### UTXO

Unspent Transaction Output. The unit of Bitcoin ownership. Spacer
treats raw UTXO data as the highest-leak object in the bitcoind
surface: `listunspent` dumps the full set, `listdescriptors` dumps the
keys that derive their addresses, and `getaddressinfo` ties an address
to its derivation path. Proxy answers UTXO-related questions in
aggregate ("is there a confirmed UTXO of at least X sats: yes/no")
without ever returning per-UTXO records to the AI.

### xpub / descriptor

Account-level extended public key. One xpub deterministically derives
every receive address and every change address for an account, past
and future. `listdescriptors` returns one xpub per descriptor (8 on a
fresh wallet: BIP44/49/84/86 across receive and change). One leaked
xpub deanonymizes the entire chain forever - this is the highest-
severity single-call leak in the bitcoind surface. Proxy denies
`listdescriptors` and `getaddressinfo` absolutely.

### bolt11

The original Lightning invoice format. A bolt11 string encodes the
destination pubkey, amount, payment_hash, payment_addr, and route
hints by spec - there is no opt-out. Anyone with the invoice has the
destination's identity. Implication: when an AI hands the gateway an
invoice to pay, the gateway must decode internally and surface only
policy-relevant facts ("destination matches allowlist: yes", "amount
within ceiling: yes"); the raw bolt11 stays inside the arbiter.

### bolt12

The newer Lightning invoice format that supports reusable offers.
Long-lived offers reuse the same node pubkey across all payers, so
repeated payments to the same offer are linkable. Offers are also
trivially fingerprintable through the node pubkey. The gateway
never surfaces the offer string; it stays in the arbiter.

### HTLC

Hash Time-Locked Contract. The atomic unit of a Lightning payment in
flight. Each hop along a payment path receives an HTLC, holds it
briefly, and forwards it (minus its fee) to the next hop. The HTLC
table returned by `payinvoice` carries per-attempt state, latency,
fees, and the channel each attempt routed through - all of which
the gateway must filter before responding to the AI.

### Payment hash and preimage

In a Lightning payment, the payer commits to a payment hash; the
payee reveals the preimage to claim the funds; the preimage is
proof-of-payment. Both are sensitive: preimages prove a specific
payment was settled (useful only inside the arbiter, never returned
to the AI), payment hashes plus amounts plus timestamps reconstruct
payment history. Proxy holds preimages internally; surfaces only
`{succeeded: bool, paid_amount: banded, fee: banded}` to the AI.

### SCID

Short Channel ID. A compact identifier for a Lightning channel,
derived from the funding transaction's block height, transaction
index within that block, and output index. Once gossiped, an SCID
permanently links the gossip entry to a specific on-chain UTXO. Any
node with the LN gossip graph can resolve our SCID to our funding
tx and from there to the inputs we used to fund the channel.

### Channel point

The tuple `<funding_txid>:<output_index>` that uniquely identifies a
Lightning channel by its on-chain funding output. Equivalent
information to an SCID but expressed pre-confirmation. Listed by
`listchannels`; surfaced by `openchannel`. High-leak: discloses our
on-chain footprint to whoever has the channel point.

### Funding tx and closing tx

The on-chain transactions that open and close a Lightning channel.
The funding tx creates a 2-of-2 multisig output that backs the
channel; the closing tx (cooperative or force) publishes the final
balance split between the parties. Both are public, permanent on-
chain records, even for `--private` (un-announced) channels. Private
channels suppress gossip-layer publication of the pubkey-pair and
SCID, but the on-chain footprint is identical.

### Cooperative close vs. force close

Two ways to close a Lightning channel. Cooperative: both parties
sign a closing tx that pays out their current balances immediately.
Force: one party broadcasts the latest commitment tx unilaterally,
balances are time-locked, and recovery requires an on-chain wait.
Force-close is an irreversible signal of distrust; the gateway treats
force-close requests as a higher policy tier than cooperative close.

### PSBT

Partially Signed Bitcoin Transaction (BIP 174). A serialization
format that lets a transaction be constructed in one place, signed
in another, and broadcast in a third. The arbiter uses PSBTs
internally so coin selection and signing stay inside the arbiter;
the petitioner never receives a PSBT directly because PSBTs leak
input descriptors and change addresses.

### Signet

Bitcoin's test chain that requires a signature from designated keys
to add blocks (vs. testnet's open mining). Mutinynet is a custom
signet variant. RPC port `38332`, distinct from testnet `18332`
and mainnet `8332`. `chain=signet` at the top level of `bitcoin.conf`
locks the daemon to signet only; signet-specific knobs go inside the
`[signet]` section.

### Mutinynet-covtools

The `mutinynet-covtools` tag of the `benthecarman/bitcoin` repo, the
Mutinynet-patched Bitcoin Core build we use locally
(v25.99.0-gf036909dbe28). Distinct from `mutinynet-inq-29`, which
ships GUI-only on macOS arm64. Patches add `signetchallenge` and
`signetblocktime` config parsing; the binary works with the standard
Bitcoin Core CLI surface otherwise. Source URL:
`https://github.com/benthecarman/bitcoin/releases/tag/mutinynet-covtools`.

## Mitigations

Each entry below is a specific filtering or policy mechanism the
arbiter applies. The names are short for the same reason "wisp" or
"sling" are short in Gas City: a one-word handle costs less than a
phrase every time the concept comes up.

### Pseudonymize (Identifier pseudonymization)

Replace addresses, pubkeys, channel_ids, and payment_hashes with
opaque arbiter-scoped tokens before responding to the AI. The arbiter
maintains the token-to-real-value mapping internally. The AI can use
tokens in subsequent requests; the gateway resolves them. Caveat: the
size of the token vocabulary is itself a leak (number of unique
tokens is roughly the number of channels or addresses we have), so
heavy pseudonymization needs aggregation alongside it.

### Banding (Numeric value banding)

Surface balances, fees, amounts as buckets like `<10k / 10k-100k /
100k-1M / >1M sats` instead of exact integers. The AI usually needs
capability ("can fund a channel of size X?") not precision. Caveat:
bands themselves are a fingerprint, and an AI that can probe
"can fund X?" across many X values can binary-search the exact
balance unless paired with rate limits and noise.

### Outbound allowlist

> **Status: open.** See [Architecture overview, §7](design-docs/2026-05-05-0948-architecture-overview.md#7-open-design-questions) (policy table format).

Every state-changing or network-touching call (`connect`, `sendcoins`,
`openchannel`, `payinvoice`, `sendrawtransaction`) is gated against a
policy table of allowed destinations and amounts. The AI cannot
direct funds or connections to arbitrary targets. Caveat: a static
allowlist that never changes is its own fingerprint ("this operator
only ever pays 3 destinations").

See also: [Architecture overview, §7](design-docs/2026-05-05-0948-architecture-overview.md#7-open-design-questions).

### Human-in-the-loop (HITL) approval

When a proposed state-changing call falls outside the allowlist
fast path - new destination, unusual amount, tx shape the operator
has not seen before - the arbiter pauses the call and sends the
operator (a human) a structured approval request out of band. The
call only proceeds on explicit human assent. The allowlist handles
the routine cases without ceremony; HITL catches the ambiguous
ones. Out-of-band means: the request and response travel on a
channel the AI does not see (push notification, hardware button,
dedicated terminal), not the same RPC channel the AI is already on.
Caveat: a human who clicks "approve" on every prompt provides no
defense; the surface must be scoped tightly enough that approvals
are rare and meaningful.

### Aggregate-by-default

List-style calls (`listchannels`, `listpayments`, `listpeers`,
`listunspent`) return counts and aggregate summaries by default;
per-item detail requires explicit per-call justification that gets
audit-logged. Counts are themselves [banded](#banding-numeric-value-banding)
into anonymity-set buckets rather than reported exactly (e.g.
1 channel, 2-10 channels, more than 15 channels); bucket edges are
chosen so each bucket covers a plausible-set of nodes, and exact
counts are not exposed even with per-call justification. Defeats
history-dump exfiltration. Caveat: bucket membership still leaks
some information ("more than 15 channels" rules out small nodes);
the choice of bucket edges is part of the security surface, not
just a display preference.

### Hide secrets

Anything sensitive the arbiter holds stays on the arbiter and is
never returned to the AI: preimages, signatures, macaroons,
descriptors, xpubs, PSBTs, plus the raw values behind any
pseudonymized identifier. The arbiter uses these internally to
prove, sign, or look up things; the AI sees only the outcome.

**Withholding proofs** is a subcategory of this: the
cryptographic-proof material specifically (preimages, signatures,
PSBTs) where exposure would let any holder reproduce or authorize
a transaction. The broader rule extends the same treatment to
identifiers, credentials, and anything else that could deanonymize
or impersonate us.

Caveat: the arbiter becomes a single point of failure for secret
custody, so its storage hygiene matters.

### Default --private channels

Open channels with `--private` (LND) or `open_channel` (ldk-node, vs.
`open_announced_channel`) by default. Suppresses the gossip-layer
publication of pubkey-pair plus SCID plus capacity. Funding and
closing txs are still on-chain, but the routing graph entry is not
gossiped. Defends both AI-facing (AI sees nothing on `listchannels`)
and world-facing (gossip network sees no entry) at once.

### Action delay

Mandatory wait between the petitioner submitting a state-changing
action and the arbiter actually executing it against bitcoind / LND
/ the network. The petitioner receives an immediate synchronous
acknowledgment ("received: <opaque-handle>"); the on-chain or LN
effect is deferred until the wait elapses. Applies to every state-
changing call (`sendcoins`, `openchannel`, `payinvoice`,
`sendrawtransaction`, etc.); read-only queries are out of scope -
this is per-action timing across hours and days.

The clock applies to the **final action** - the actual broadcast
or LN call against bitcoind / LND / the network. A
human-in-the-loop reviewer on the arbiter side can review (and
approve or reject) a petitioner's request well before the 12 hour
floor has elapsed; the human's decision is an internal arbiter
event with no observable outside-world signal. What the floor
constrains is the moment the action becomes visible on the
network. Even if the human approves immediately, the on-chain or
LN execution still waits for the delay window to elapse. This is
because the petitioner can observe public chain and gossip data
and would be able to derive the operator's intent (and from there,
secrets) if the anonymity set around the executed action is too
small. The floor preserves the anonymity set; the human reviewer
preserves correctness.

The wait is randomized within a window the arbiter computes
dynamically from observed global activity for similar actions, with
the goal of reaching a target anonymity set: high activity
compresses the window toward its lower bound, low activity stretches
it. Hard floor: ~12 hours minimum, regardless of activity. Initial
tuning target: roughly 12-36 hours, randomized; refine as we
measure. The floor is intentional - cheap mistakes get caught,
accidental actions get noticed, and the floor itself is part of the
privacy budget. A global observer cannot correlate "the petitioner
asked at T" with "the chain saw a tx at T+epsilon" because other
actions of the same type happen in the interval, growing the
anonymity set the action could plausibly belong to. Composes with
**Aggregate-by-default** and **Banding** as another anonymity-set
mechanism.

Caveat: the delay distribution is itself a fingerprint if its
parameters are constant or naively chosen. The randomization window
must be at least similar in shape to the natural distribution of
similar actions for the anonymity set to actually hold.

### Result delay

> **Status: open.** See [Architecture overview, §7](design-docs/2026-05-05-0948-architecture-overview.md#7-open-design-questions) (action+result delay estimate API, result delivery mechanism, result-delivery status enum).

Mandatory wait between the arbiter completing an action and the
petitioner learning the result. After the action goes out, the
petitioner does NOT get a synchronous "ok, here is the txid / here
is the payment_hash / success/failure" - it gets nothing for at
least the secondary wait window. Result delivery is therefore
asynchronous: the petitioner polls or receives a callback after the
window elapses, not in response to the original action. Sibling to
**Action delay**: same window construction, same ~12 hour hard
floor; randomized within bounds driven by observed network activity
for similar result-shapes.

Purpose: a second layer of de-correlation. Even if a global observer
eventually links the on-chain action back to our node, the AI's
*knowledge* of the action's outcome trails by another anonymity-
set-scaled gap, breaking the timing channel that links petitioner-
side reasoning to chain-side events. Composes with
**Aggregate-by-default** and **Banding**.

Subsumes per-poll cadence concerns. The arbiter polls local bitcoind
/ LND on its own schedule to drive its internal state machine, but
the petitioner only learns anything through the result-delivery path
gated by this delay. By the time a result surfaces, hours have
elapsed and the original poll/RPC pattern is decorrelated from the
petitioner's view; an earlier "anti-cadence" mitigation that
randomized the arbiter's poll interval is no longer needed as a
distinct term. The arbiter <-> bitcoind / LND link is inside the
trust boundary (loopback / unix socket on the trusted host) and
external observers see only what the daemons themselves emit, which
is governed by their own protocols rather than by RPC-layer jitter.

UX implication: the petitioner (and the AI it serves) need an
estimate of total elapsed time (action delay + result delay) so the
AI can reason about the decision tree - still within window -> wait;
past the upper bound and no result -> assume lost, decide whether to
re-initiate; result arrived -> success / failure / explicit
lost-or-expired status. The arbiter should expose this estimate at
acknowledgment time and update it as conditions change.

Caveat: a long secondary wait increases the risk that real-world
conditions change (fees, channel state, counterparty behavior)
between action and result-knowledge, so the floor is a tradeoff
with operational reliability, not just a knob to turn up.

See also: [Architecture overview, §4.6](design-docs/2026-05-05-0948-architecture-overview.md#46-timing-layer) and [§7](design-docs/2026-05-05-0948-architecture-overview.md#7-open-design-questions).

### Audit log

Every AI request and every arbiter decision (allow, deny, redact,
band, defer-to-human) is appended to an immutable, append-only log
on the arbiter. The petitioner cannot reach the log, so the AI
cannot tamper with the record even if it fully owns its
environment. Forensics trail for prompt injection, surveillance
attempts, and unexpected-action attempts. Caveat: logging records
events; it does not prevent them. Logging is the floor, not the
ceiling - prevention work belongs to the allowlist and HITL.

## Side channels

The leaks that do not appear in any single API response but emerge
from patterns of calls, timing, and correlation. Easy to overlook
because no individual call shows them.

### Latency fingerprinting

> **TODO (review needed):** reconsider whether this term is still
> necessary now that **Action delay** and **Result delay** exist
> with ~12 hour floors. Per-response timing leaks may be dominated
> by the per-action delay. Decide: keep, drop, or fold into the
> action/result delay framing.

Response time correlates with hop count (LN), with index
configuration (bitcoind), with mempool vs. confirmed-block lookup,
and with IBD state. An AI issuing many calls and observing latency
distributions can derive properties the gateway intended to hide.
Mitigation: state-changing calls are decoupled from their effects
by **Action delay** + **Result delay** (the AI sees only an
acknowledgment, not a synchronous outcome); pure read paths can
batch responses into windows or fold into the same result-delivery
path so per-call latency does not reach the petitioner directly.

### Polling cadence

A fixed-interval polling pattern broadcast to anyone watching the
host's network or process activity. A 30-second heartbeat is a
fingerprint of the specific software running on top of the node.
Metronomic polling signals automation; irregular intervals signal a
human. The arbiter <-> bitcoind / LND poll path is inside the trust
boundary, so this side-channel does not reach the petitioner; it is
covered by **Result delay** (which decorrelates any internal poll
timing from anything the petitioner can observe). Daemon-level
protocol cadence (block fetch, gossip, ping) is governed by
bitcoind / LND themselves and is out of scope at the RPC layer.

### First-hop attribution

In LN, the first hop on a payment path always knows our node ID. In
Bitcoin P2P with a single addnode peer, that peer has guaranteed
first-seen status for any tx we originate. Both are inherent to the
respective protocols; mitigations are infrastructure choices (Tor,
multi-peer broadcast) rather than gateway filters.

### JIT liquidity

> **Status: open.** See [Architecture overview, §7](design-docs/2026-05-05-0948-architecture-overview.md#7-open-design-questions) (channel-open timing threat model).

Just-in-time liquidity. Opening a channel immediately before a
payment and observing that the channel did not exist in the
previous `listchannels` result. Recognizable to the AI through the
sequence of API states it observes; recognizable to chain observers
through the funding tx's timing relative to payment activity.

See also: [Architecture overview, §7](design-docs/2026-05-05-0948-architecture-overview.md#7-open-design-questions).

### Inter-event timing

> **TODO (review needed):** reconsider whether this term is still
> necessary now that **Action delay** and **Result delay** exist
> with ~12 hour floors. The request-to-broadcast gap is now
> dictated by the per-action delay rather than by the AI's
> behavior. Decide: keep, drop, or fold into the action/result
> delay framing.

The gap between a request arriving and the resulting on-chain
broadcast. Sub-second gap = bot. Multi-second variance = human.
Visible to the AI through gateway response latency. Conversely, the
gateway can deliberately spoof human-like timing as a mitigation, at
the cost of throughput.

## Inherent leaks

The constraints that no arbiter or infrastructure choice can remove.
Naming them prevents mitigation cycles that try to hide them.

### Public on broadcast

Broadcasting a Bitcoin transaction publishes it globally and
permanently. There is no mechanism to broadcast to a trusted subset.
Implication: the gateway can decide *whether* to broadcast, but cannot
limit *who* sees the broadcast.

### BOLT11 encodes destination

By spec, every bolt11 invoice encodes destination pubkey, amount,
and payment_hash. There is no opt-out. Anyone with an invoice has
those facts. Mitigation: hold the raw invoice in the arbiter; surface
only policy-relevant facts.

### Public gossip is permanent

Once an LN channel announcement propagates the gossip graph, it
cannot be recalled. Nodes retain it indefinitely. Mitigation:
default to `--private` so no announcement happens.

### First hop knows our node ID

In LN onion routing, the first hop receives an HTLC from us and
therefore knows our node identity. Inherent to the routing
protocol. Tor anonymizes the underlying TCP, but the LN-protocol
identity is still visible.

### Inputs and change reveal wallet structure

Every on-chain transaction we sign publishes our input UTXOs, our
change address, and (typically) the linkage between them. Coin
selection inside the arbiter can choose *which* UTXOs to publish, but
publishing happens unconditionally on every send.

## Project structure

### Design doc naming

Every file in `design-docs/` is named
`YYYY-MM-DD-HHMM-<slug>.md`: creation date, then 24-hour HHMM time
with no separator, then a kebab-case slug. Files sort
chronologically by `ls`. Any new design doc must follow this
convention so the directory remains scannable.

### Layout

The current physical layout of `~/spacer/` (the
arbiter/petitioner/test-harness directory tree, with notes on the
non-conforming `go/`, `go-cache/`, and `first-game/` directories)
is documented in the architecture doc. The naming convention -
parent folders live under `arbiter/`, `petitioner/`, or
`test-harness/`, with project-level artifacts at the root - is
itself part of the vocabulary.

See also: [Architecture overview, §9](design-docs/2026-05-05-0948-architecture-overview.md#9-current-physical-layout).

## See also

- `~/spacer/design-docs/` - all design docs use the terms above.
  See particularly `2026-05-05-0948-architecture-overview.md` for the
  logical architecture, data flow, and mitigation map; and
  `2026-05-02-1601-privacy-and-timing-leaks.md` and
  `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` for the
  per-API leak maps that the mitigation terms target.
- `~/spacer/archive/2026-05-02-1428-privacy-notes.md` - the
  original session ledger that seeded the AI-facing design.
  Archived from `~/spacer/test-harness/state/privacy_notes.md`.
- `~/spacer/test-harness/state/INSTALL_BLOCKER.md` - context on why
  ldk-node is not in active use despite being in the design surface.
