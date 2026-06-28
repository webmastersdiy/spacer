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

See also: [Architecture overview, §2.1](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#21-arbiter-implementation-discipline).

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
mitigations like Tor are defense-in-depth on top of it. Implemented
as a skeleton at `arbiter/src/gateway.py`: HTTP server with a uniform
refusal body, per-response [latency normalization](#latency-normalization),
audit logging at every decision point, recipient-token resolution on
known write ops (via the [recipient address registry](#recipient-address-registry)),
[HITL](#human-in-the-loop-hitl-approval) park on unknown ops, and a
binary-state result-poll endpoint (see [result delay](#result-delay)).
Outbound filters ([hide secrets](#hide-secrets),
[banding](#banding-numeric-value-banding),
[aggregate-by-default](#aggregate-by-default)) are wired in structure
but currently pass-through pending their own beads. Position in the
data flow, the limited-and-airtight constraints, and the per-request
mechanism list are documented in the architecture doc.

See also: [Architecture overview, §3](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#3-end-to-end-data-flow) and [§4.1](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#41-privacy-gateway).

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
the log lives in the arbiter's environment, which the petitioner
does not own and cannot reach, so tampering from the AI side is
structurally impossible. AI-facing privacy is the
**primary** scope of spacer; world-facing privacy is a separate,
secondary concern, and we move world-facing docs to `archive/` to
keep them out of the active design surface. The adversaries,
mitigations, and priorities differ, so mixing them obscures both.

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

Out of active design scope for spacer right now. Existing
world-facing material lives in `archive/`; new design work in this
area does not land in `design-docs/` unless and until world-facing
becomes part of the active scope. The split is deliberate, not a
backlog: world-facing is a different problem with different
priority, and bundling it with AI-facing obscures both.

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
policy-relevant facts ("destination resolves through the registry: yes",
"amount within ceiling: yes"); the raw bolt11 stays inside the arbiter.

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

### Chaumian eCash (Cashu)

Blind-signature bearer money over Lightning, per the Cashu NUT
specs. A [mint](#mint) issues *proofs* (bearer tokens) against
Lightning funds: the wallet sends blinded messages, the mint signs
them (BDHKE blind Diffie-Hellman key exchange), the wallet unblinds.
Because the mint signs blind, it cannot link a proof it later sees
spent back to the issuance event - the unlinkability the whole
extension leans on. Core ops: **mint** (pay a bolt11 quote, receive
new proofs), **melt** (surrender proofs, the mint pays a bolt11
invoice), **swap** (surrender proofs, receive fresh ones - how
tokens are claimed after a transfer). Amounts are NOT blinded:
denominations (powers of 2), totals, and keyset epochs are visible
to the mint, so unlinkability in practice rests on timing and
amount mitigations, not cryptography alone. Wallets must verify
DLEQ proofs (NUT-12) or a malicious mint can tag clients with
per-client keys. Serialized tokens (V4 `cashuB`, CBOR; embeds the
mint URL) are self-contained bearer strings - holding the string is
holding the money. Reference implementation: nutshell (Python mint
and CLI wallet). See the eCash extension design doc
(`design-docs/origin/07--2026-06-12-0916-ecash-extension.md`).

### Melt

The [Cashu](#chaumian-ecash-cashu) operation that redeems eCash
proofs back to Lightning sats - the reverse of [Mint](#mint). The
wallet presents its proofs to the mint; the mint burns them and pays
out a [bolt11](#bolt11-encodes-destination) Lightning invoice. In
spacer, melt is the execution leg of `defund_ecash` (eCash float ->
the operator's own LND node). It is the **only** op whose bolt11
names our LND node to the mint (design doc 07 §5.1) - the metadata
leak and the one targeted-censorship vector (the proofs themselves
are unlinkable by blinding, so the mint cannot censor a holder
through the tokens) - so defunds are kept infrequent, amount- and
window-randomized (doc 07 §6 T4). A melt that does not truly settle
(`cashu pay` can exit 0 on a still-*pending* payment) is monitoring
signal **M1** in the mint-monitoring design (doc 10): the shared
rug / insolvency / targeted-censorship indicator. Counterpart:
[Mint](#mint).

### Mint

The external party that backs [Cashu eCash](#chaumian-ecash-cashu):
it holds the Lightning funds behind every outstanding proof
(custodial), issues and redeems proofs, and serves the token API.
In spacer the mint is **not** arbiter infrastructure - it is a
third-party adversary in its own right, alongside the AI client and
the network observer (design doc 07 §4). It sees amounts, keyset
epochs, caller IPs, call timing, and the LN legs of mint/melt; it
cannot link proofs to issuance (blinding), and it cannot tell whose
proofs are whose. The arbiter <-> mint link is therefore OUTSIDE
the no-internal-mitigations rule that covers arbiter <-> local
bitcoind / LND: mint-facing timing mitigations are in scope.
Deployment guidance: one mint per deployment, operator-chosen,
pinned in arbiter config (never AI-suppliable), busy and public and
operator-unaffiliated so its other users form our anonymity set.

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

### Scale cloaking

Stronger sibling of [banding](#banding-numeric-value-banding) that
covers not just the precise satoshi figure but the **order of
magnitude** of the wallet. Instead of letting a balance grow from
"in the 100k band" to "in the 10M band" (which leaks that the wallet
is now an order of magnitude larger than it used to be), the privacy
gateway projects the real total into a fixed presentation window,
nominally `0 - 100,000` sats. Every petitioner read of balance or
channel capacity is rescaled before egress; the AI sees a number in
that window regardless of whether the wallet holds 50k, 5M, or 500M
sats.

The mechanism has three pieces:

- **Cloak tier.** The arbiter assigns the wallet to a tier based on
  its real total: T0 = `[0, 100k)` (no scaling), T1 = `[100k, 1M)`
  (scale roughly `0.1`), T2 = `[1M, 10M)` (scale roughly `0.01`), and
  so on by powers of 10. The scale within a tier is randomized within
  a band rather than fixed at the exact power, so two wallets in the
  same tier do not present identical numbers for identical
  underlying balances.
- **Tier shift.** When the real total crosses a tier boundary, the
  arbiter does **not** change the active scale immediately. It
  schedules a *tier shift* with a multi-day randomized delay (test
  mode collapses this to seconds). During the delay the wallet keeps
  presenting under the old tier's scale, so the petitioner-visible
  drift is gradual and decoupled from the moment of the underlying
  send/receive. When the shift fires, the active scale flips and the
  petitioner sees a discrete change in presented balance - which by
  construction looks identical to a normal payment in or out of the
  wallet.
- **Drift > range.** Privacy beats range-fidelity: during a pending
  tier shift the presented value can briefly fall outside the
  `0 - 100k` window (e.g., real grew to 150k but the active tier is
  still T0, so presented = 150k). That is acceptable. Forcing the
  range immediately would re-couple the tier shift to the underlying
  fund movement, which is exactly the leak the delay is there to
  break.

Audit log records every tier shift, the real before/after, the new
scale, and the randomized delay; the operator can see at the
arbiter console that a given drop in presented balance was a tier
shift rather than a real send. The petitioner cannot tell the two
apart - that is the property the cloak is buying.

Caveat: a petitioner that polls fast enough to observe the *exact*
moment of a tier shift can flag it as suspicious if the magnitude
of the change is implausibly large for a single transaction.
Mitigation lives in the band of randomized scale factors plus the
random delay: the shift is deferred so it does not align with the
known fund movement, and the band makes the magnitude variable
across wallets and across shifts.

### Recipient address registry

The allowlist of **operator-owned internal endpoints** for
state-changing BTC/LN calls. The arbiter holds a hand-curated list of
**operator-owned output descriptors / extended public keys** (xpub +
script type + derivation path) - **never raw addresses**, so the
arbiter derives a *fresh unused address per send* and never reuses one
(see *Fresh-address derivation* below) - all **operator-controlled**
(the operator's own wallets / nodes) that a `send_bitcoin` /
`send_lightning` call may target. **External recipients are not a possibility:** BTC/LN make no
external payments (any external payee that can see a UTXO is inside
the adversary's observability set, which would break UTXO privacy), so
all external value movement is eCash-only (the external-value reframe;
see the foundational-posture doc and the eCash extension doc). The
registry's role is therefore *internal fund management* - it bounds
the AI to moving value only among the operator's own endpoints - not
gating external sends. The petitioner never sees a descriptor or any
derived address - only an opaque single-use token naming the receiver
identity, which resolves inside the arbiter. (History: this list
previously modeled approved *external*
send targets; the 2026-06-27 external-value reframe recast it as the
operator-owned-internal allowlist.)

**Storage substrate.** A YAML file at a known path on the arbiter,
hand-edited by the operator at the directly-attached console. The
arbiter is deliberately minimal and manually managed (architecture
overview §2.1); adding a destination, retiring one, or auditing
what is in the universe should be one open-file / edit / save
round-trip, not a tool invocation against a SQL schema. The
registry module reads the YAML; the operator owns the file.
(Migration note: as of this writing the registry is backed by a
SQLite table in arbiter local state; the YAML migration is the
next milestone in this chain.)

**Entry shape.** Each entry has a local-only numeric id (for
operator notes), a public-facing token the petitioner sees, the
operator-owned **output descriptor** (xpub + script type +
derivation path), a per-descriptor **next-derivation index** and
gap-limit (the no-reuse / no-gaps bookkeeping), a created_at /
expires_at pair (default 7-day expiry), and a used / consumed_by
pair tracking one-time-use.

**Fresh-address derivation (no reuse).** The registry holds
*descriptors, not addresses*, so address reuse - which would erode
on-chain and UTXO privacy - is structurally avoided. On each internal
`send_bitcoin` the arbiter derives the **next unused address** from
the registered descriptor by standard BIP32 HD derivation (advancing
the entry's next-index; the gap-limit guards against derivation racing
ahead of the operator's watching wallet). Three properties follow:
(1) **no-redirect** - every derived address provably belongs to the
operator's descriptor (only the operator holds the matching private
keys), so the AI cannot point a send at itself or a third party;
(2) **operator-verifiability** - the operator can deterministically
check that any derived address belongs to their descriptor, so the
derivation is auditable from the console; (3) **AI-free and
address-blind** - registering the descriptor and deriving each address
both happen without the AI, which never supplies, generates, or sees a
raw address, reinforcing endpoint privacy (the PET never observes a
UTXO or address). *Lightning analog (the lighter case):* LN invoices
are already single-use and fresh, so an internal LN target is the
operator's own node issuing a fresh invoice per transfer; no
descriptor derivation is needed.

**Token format.** 5 random Crockford-base32 characters plus 1
Damm32 check character. Crockford-base32 omits visually ambiguous
glyphs (no I, L, O, U); operator-typed I or L normalize to 1 and O
to 0 before validation. Damm32 catches every single-character
mutation and every adjacent transposition of distinct characters.

**Internal-endpoint gate (who).** The registry gates that a BTC/LN
send targets *only an operator-owned internal endpoint*. A
state-changing call carries a `recipient_token`; the privacy gateway
calls `registry.lookup()` during pseudonymize-inbound; any outcome
other than `ok` (bad checksum, unknown, expired, already used,
anomalous) collapses to the uniform "destination unavailable"
refusal. Because every valid token resolves to an operator-owned
endpoint, a non-`ok` result means the AI tried to send off the
operator's allowlist - which, post-reframe, is the only way it could
attempt an external recipient, and is refused like any other miss.
The audit log differentiates the cause for operator triage. *Which*
actions to a resolved endpoint flow through without a HITL pause is a
separate gate - see [standing approvals](#standing-approvals).

**Probing infeasibility.** An AI cannot map the destination
universe by submitting candidate tokens in a tight loop. Four
mechanisms compose to make the probing strategy prohibitively
expensive in any realistic threat model:

- [Action delay](#action-delay) imposes a ~12h floor on every
  state-changing call. 100 probes is ~50 days.
- [HITL approval](#human-in-the-loop-hitl-approval) fires on every
  inbound call that is not a recognized op, so the operator sees
  unusual submission patterns on the directly-attached console.
- [One-time-use](#recipient-address-registry) enforcement means a
  token that *does* resolve is consumed on first use; the
  petitioner cannot re-test a successful hit to confirm it.
- The [audit log](#audit-log) records every attempt for non-AI
  human review, and [latency normalization](#latency-normalization)
  collapses the per-response timing channel that would otherwise
  let a probe distinguish "registry miss" from "registry hit but
  pending consume" by response time.

**Refusal behavior.** Every refusal path collapses to one bit on
the petitioner side: ok (the call proceeds) or refused. The
production deployment defers refusals through the result registry
(see [Result delay](#result-delay)) on a 1-hour ± 30-minute
randomized delay so the petitioner cannot correlate submission time
with response time. (Test mode collapses this delay; see the
test-mode timing rules in the architecture overview's exit
criteria.) The current `arbiter/src/gateway.py` skeleton refuses
synchronously; the deferred-rejection path lands with the result-
registry bead.

### Standing approvals

The operator's pre-approved-actions config. By default, every
state-changing call - even one that resolves a valid recipient
token through the [registry](#recipient-address-registry) - pauses
at the arbiter console for [HITL](#human-in-the-loop-hitl-approval)
approval. A standing approval is a rule the operator has written
down ahead of time that lets a specific (op, destination,
amount-band) tuple dispatch without pausing. The privacy gateway
checks the resolved call against the standing approvals after the
registry resolves the destination; first match wins and dispatch
proceeds; no match parks in HITL.

**Default-pause is the design.** The standing approvals file ships
empty. Two reasons:

1. **Pedagogy.** The operator builds working knowledge of what the
   AI is actually trying to do by reviewing each call in person
   before ratifying it. After approving the same shape of call a
   few times via HITL, the operator can convert it to a standing
   approval. The friction is the teacher.
2. **Asymmetric risk.** The cost of accidentally letting a
   malicious or buggy AI call through is financial loss; the cost
   of a pause is the operator's time. The first dominates. Default
   to pause; loosen as trust develops.

**Storage substrate.** A YAML file at a known path on the arbiter,
hand-edited by the operator at the directly-attached console (same
KVM and same edit workflow as the recipient address registry, per
§2.1's minimal-and-manual discipline). The arbiter does not learn
what to approve from the AI's behavior; the operator decides what
gets exempted, writes it down, and the change is captured by the
[arb-auditability](../design-docs/origin/06--2026-05-24-0623-arb-auditability.md)
snapshot.

**Entry shape (sketch).** Each rule names an op, a destination
token (or "any" for broader rules the operator chose to write),
optional amount band ("up to N sats", "exactly N sats"), and a
free-text rationale the operator wrote for their own future self.
Schema details land with the implementation.

**Scope.** Standing approvals apply to state-changing ops
(`send_bitcoin`, `send_lightning`). Read-only ops (`query_balance`,
`query_channels`) dispatch unconditionally - they are protected by
other mechanisms ([banding](#banding-numeric-value-banding),
[scale cloaking](#scale-cloaking),
[aggregate-by-default](#aggregate-by-default)) and HITL on every
balance check would be unworkable friction.

**Caveat.** Every line of standing approval is a decision the
operator made that some future call would not get reviewed. A long
config means a small surface of real human oversight. The
discipline is to keep the config short and concrete, not to grow
it indefinitely.

### Human-in-the-loop (HITL) approval

When the privacy gateway receives a state-changing call that does
not match any [standing approval](#standing-approvals) on the
arbiter, the gateway pauses the call and surfaces it to the
operator (a human) on a fully out-of-band channel. The call only
proceeds on explicit human assent. Unknown ops - anything outside
the recognized read set (`query_balance`, `query_channels`) and
write set (`send_bitcoin`, `send_lightning`) - also trip HITL by
default, regardless of standing approvals.

Out-of-band means: the request and response never travel on the
petitioner's RPC channel and the AI never sees the request. The
recommended setup is a keyboard and monitor (KVM) physically
attached to the arbiter, the same console used to add entries to
the **recipient address registry**. Anything that needs to cross
back to the AI side after a HITL decision (e.g., a newly-issued
recipient token the operator wants the AI to use) is hand-retyped
by the operator on the AI / petitioner side - there is no
clipboard between the arbiter console and the AI's environment, so
only handles the operator deliberately retypes can ever leave the
arbiter.

**Default-pause is deliberate.** Early in a deployment HITL fires
often because the [standing approvals](#standing-approvals) config
starts empty. That is intentional: the operator builds working
knowledge of the AI's behavior by reviewing each call in person,
then ratifies trusted patterns as standing approvals. The pause is
both a safety mechanism and a pedagogy mechanism.

Caveat: a human who clicks "approve" on every prompt provides no
defense; the surface must be scoped tightly enough that approvals
are rare and meaningful, and the standing-approvals config short
enough that the operator remembers what is in it.

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

### eCash allowance

The hard cap on the AI's [eCash](#chaumian-ecash-cashu) float - the
bound that replaces per-action control for AI-held bearer value.
`ecash_allowance_sats` (arbiter config, console-edited like the
registry and standing approvals) caps **outstanding float**:
total funded minus total successfully defunded, maintained entirely
from gateway-visible events. `fund_ecash` refuses past the cap
(audit `decision_refuse_allowance`, uniform refusal on the wire),
and the check precedes [standing
approvals](#standing-approvals): a [HITL](#human-in-the-loop-hitl-approval)
approval cannot exceed the allowance - raising it is a config edit,
never an approval click, so operator fatigue cannot widen the blast
radius. Blast radius = allowance: worst-case AI behavior (burn,
exfiltrate) and worst-case [mint](#mint) behavior (rug, freeze)
both cost at most the outstanding float. Size it like petty cash.
An optional rate cap (max funded per rolling window) bounds
slow-bleed patterns over time. Caveats: the ledger bounds
*operator loss*, not AI wealth (AI-direct spends are invisible by
design; third-party-received tokens are invisible and unbounded),
and there is no clawback - bearer means the operator can stop
funding the float but cannot revoke it. See design doc 07 §8.

### Default --private channels

Open channels with `--private` (LND) or `open_channel` (ldk-node, vs.
`open_announced_channel`) by default. Suppresses the gossip-layer
publication of pubkey-pair plus SCID plus capacity. Funding and
closing txs are still on-chain, but the routing graph entry is not
gossiped. Defends both AI-facing (AI sees nothing on `listchannels`)
and world-facing (gossip network sees no entry) at once.

### Delay-scaling principle

The standing rule that sizes every timing mitigation: **delays must
be adequate for the anonymity-set size and the nuances of the
particular privacy concern; privacy adequacy is the floor, and UX
never overrides it.** The UX bet is that delay tolerance tracks
rail speed - bitcoin is inherently slow so large delays from us are
tolerable, lightning is fast so smaller, eCash is fast so smaller -
and the bet pays because the adequate floor is naturally lower on
faster rails: the observable surface turns over faster, so the
anonymity set refills in less time. Operationally: each op's
[action delay](#action-delay) / [result delay](#result-delay)
window is sized to the anonymity set of the surfaces the op
touches, and the floor binds to the slowest-turnover surface among
them (an eCash fund op touches both the mint and Lightning, so the
Lightning floor governs). Per-rail floors: onchain ~12 h
(unchanged), lightning ~1 h (proposed target, tuning open), eCash
boundary ops governed by the Lightning leg, AI-direct token ops
not arbiter-mediated at all. The principle forbids both shrinking
a window below adequacy because users are impatient and lazily
applying the onchain floor everywhere because it is safely large.
Defined in design doc 07 §7, which is the authority for the
per-rail split.

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
it. Hard floor: ~12 hours minimum, regardless of activity - the
**onchain rail's** floor; floors are per-rail under the
[delay-scaling principle](#delay-scaling-principle). Initial
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

> **Status: open.** See [Architecture overview, §7](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#7-open-design-questions) (result-delivery status enum).

Mandatory wait between the arbiter completing an action and the
petitioner learning the result. After the action goes out, the
petitioner does NOT get a synchronous "ok, here is the txid / here
is the payment_hash / success/failure" - it gets nothing for at
least the secondary wait window. Result delivery is therefore
asynchronous via a pull-only result registry on the arbiter: the
petitioner polls a privacy-gateway endpoint for a given handle and
gets either "result" or "not yet," nothing in between. The privacy
gateway enforces a 10-minute minimum interval between polls for a
given handle. Sibling to **Action delay**: same window construction,
same ~12 hour hard floor on the onchain rail (per-rail under the
[delay-scaling principle](#delay-scaling-principle)); randomized
within bounds driven by observed network activity for similar
result-shapes. See
[Architecture overview, §4.8](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#48-result-registry).

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
re-initiate; result arrived -> success / failure. The petitioner
computes this estimate locally from its own view of similar global
activity; no estimate information comes from the arbiter, and the
arbiter offers no guarantee on the bound. See [Architecture overview, §5.2](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#52-estimate-display).

Caveat: a long secondary wait increases the risk that real-world
conditions change (fees, channel state, counterparty behavior)
between action and result-knowledge, so the floor is a tradeoff
with operational reliability, not just a knob to turn up.

See also: [Architecture overview, §4.6](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#46-timing-layer) and [§7](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#7-open-design-questions).

### Latency normalization

Mandatory minimum wall-clock floor on every petitioner-visible
response, held inside the privacy gateway from request receipt
until response send. Defeats the per-response timing channel: a
request that completes early is delayed to the floor before the
wire send, so the response itself carries no signal about which
pipeline branch ran (successful dispatch, registry miss, HITL park
on unknown op, protocol-error refusal, etc.) or how far the
pipeline progressed. Implemented in `arbiter/src/gateway.py`
(`_wait_until`); the skeleton ships with a 250ms default, and the
deployment is expected to set the floor at or above observed
worst-case backend latency.

Distinct from [Action delay](#action-delay) and
[Result delay](#result-delay), which absorb the much larger hop-
count / IBD / mempool-lookup variation by deferring the actual
execution and result delivery. Latency normalization handles the
synchronous response shape (the sub-second signal); the timing
layer handles the execution shape (the hours-scale signal). Both
coexist in spacer.

Caveat: a floor only normalizes responses that COULD have been
faster. If the backend genuinely takes longer than the floor, the
actual elapsed time leaks through. The floor must therefore be set
above the slowest legitimate synchronous path the gateway can
dispatch, or the mitigation collapses on the slow side.

### Audit log

Every AI request and every arbiter decision (allow, deny, redact,
band, defer-to-human) is appended to an immutable, append-only log
on the arbiter. The log lives in the arbiter's environment, which
the petitioner does not own and cannot reach, so tampering from
the AI side is structurally impossible. Forensics trail for prompt
injection, surveillance
attempts, and unexpected-action attempts. Caveat: logging records
events; it does not prevent them. Logging is the floor, not the
ceiling - prevention work belongs to the recipient address registry
and HITL.

## Side channels

The leaks that do not appear in any single API response but emerge
from patterns of calls, timing, and correlation. Easy to overlook
because no individual call shows them.

### Latency fingerprinting

Response time correlates with hop count (LN), with index
configuration (bitcoind), with mempool vs. confirmed-block lookup,
and with IBD state. An AI issuing many calls and observing latency
distributions could in principle derive properties the gateway
intended to hide.

Spacer closes this leak at two layers:

- [Latency normalization](#latency-normalization) inside the
  privacy gateway holds every synchronous response back to a
  uniform floor, so individual responses carry no per-call timing
  signal regardless of which pipeline branch ran.
- [Action delay](#action-delay) and [Result delay](#result-delay)
  in the timing layer absorb the much larger hop-count / indexing /
  mempool-lookup / IBD variation by completing state-changing work
  before the delay window expires and surfacing only the result.
  The petitioner sees an acknowledgment immediately, then a single
  result event after the delay.

If bitcoind / LND are down or a request legitimately cannot
complete within the delay window, the petitioner receives a
generic "failed temporary (try again)" after the delay elapses.
This deliberately exposes that *something* in the arbiter is not
operational, but does not reveal which component or why. Documented
tradeoff: the operator should ensure the arbiter is healthy before
engaging the petitioner; intermittent unavailability is observable
in aggregate but does not narrow the leak below the
arbiter-as-a-whole granularity.

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

Just-in-time liquidity. Opening a channel immediately before a
payment and observing that the channel did not exist in the
previous `listchannels` result. Recognizable to the AI through the
sequence of API states it observes; recognizable to chain observers
through the funding tx's timing relative to payment activity.

In Spacer the AI-facing side of this leak is closed by the
combination of **Aggregate-by-default** (channel counts come back
banded into anonymity-set buckets, not exact integers) and the
multi-hour **Action delay** / **Result delay** windows. The AI
never observes a precise channel count, and any change in observed
state trails the underlying event by hours, so the
"channel did not exist before, exists now, payment followed"
sequence is no longer directly recoverable.

To prevent the petitioner from triangulating band boundaries (e.g.
inferring that a band crossing must correspond to exactly one new
channel), the band edges are themselves randomized within the
arbiter's local state. Adding a channel sometimes pushes the
reported band up; sometimes the same operation leaves the reported
band unchanged. Over many observations the petitioner cannot fit a
deterministic boundary to the underlying count, so band transitions
do not function as event signals.

The world-facing side of this leak (chain observers correlating a
funding tx with downstream payment activity) is a separate threat
model, addressed in
`~/spacer/archive/2026-05-02-1700-node-privacy-from-the-world.md`.

### Mint correlation

The [mint](#mint)'s ability to stitch its two views together: the
arbiter-side events (LN payment of a mint quote, melt to our node)
and the AI-side events (swaps, checkstate queries). Blinding breaks
the cryptographic link between issuance and redemption, but the
mint still sees amounts, keyset epochs, caller IPs, and timing for
every call - so a 47,300-sat issuance followed shortly by 47,300
sats of swaps from a new IP links the AI client to the funding node
without breaking any cryptography. Channels and mitigations are
mapped in design doc 07 §6: randomized intra-execution gaps,
[result-delay](#result-delay)-randomized issuance-to-first-swap
timing, amount randomization, infrequent randomized defunds (melt
is the profile-richest op: the bolt11 it pays names our node), and
busy-public-unaffiliated mint choice so the anonymity set (other
traffic in the same keyset epoch) stays large. The anonymity-set
turnover at the mint is not publicly observable, which is an open
question for the dynamic window (doc 07 §10.1).

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

See also: [Architecture overview, §9](design-docs/origin/05--2026-05-05-0948-architecture-overview.md#9-current-physical-layout).

## Implementation learnings

- 2026-05-24: [Privacy gateway](#privacy-gateway) - dropped the
  "not yet implemented" claim; the skeleton now exists in
  `arbiter/src/gateway.py` (HTTP server, uniform refusal,
  latency normalization, audit at every decision point, registry-
  gated write ops, HITL park on unknown ops, result-poll endpoint).
- 2026-05-24: Added [Latency normalization](#latency-normalization)
  as its own mitigation entry. Spacer uses it (gateway.py's 250ms
  default floor) for the synchronous response shape in addition to
  the timing layer for execution shape. Rewrote
  [Latency fingerprinting](#latency-fingerprinting) to reference
  both mitigations rather than denying per-response normalization.
- 2026-05-24: Fixed broken intra-doc anchors in
  [Recipient address registry](#recipient-address-registry):
  `#action-delay-and-result-delay` -> `#action-delay`,
  `#result-registry` -> `#result-delay`, and added the missing
  [Latency normalization](#latency-normalization) target.
- 2026-05-24: Reviewed [Scale cloaking](#scale-cloaking) against
  `arbiter/src/scale.py`; tier function, scheduled-then-applied
  transition flow, drift-over-range exception, and audit events
  (`scale_tier_init`, `scale_tier_shift_scheduled`,
  `scale_tier_shift_applied`) all match. Test mode is
  deterministic (`0.1^tier`); production randomization and multi-
  day delays remain stubbed with `NotImplementedError` per the
  GLOSSARY description. No body change.
- 2026-05-24: Noted [Standing approvals](#standing-approvals)
  describes a gateway-side hook (between registry resolution and
  dispatch) that is NOT yet wired in `gateway.py`; that lands with
  bl-wisp-a78. Entry left intact as design intent.
- 2026-06-12: Added the eCash extension vocabulary with design doc
  07: [Chaumian eCash (Cashu)](#chaumian-ecash-cashu) and
  [Mint](#mint) under primitives, [eCash
  allowance](#ecash-allowance) and the [delay-scaling
  principle](#delay-scaling-principle) under mitigations,
  [Mint correlation](#mint-correlation) under side channels; the
  [action delay](#action-delay) / [result delay](#result-delay)
  ~12h floors are now marked as the onchain rail's floors (per-rail
  under the delay-scaling principle).
- 2026-06-12: Verified the eCash entries against the sp-2hwco4.2
  build: the [eCash allowance](#ecash-allowance) landed as written
  (`config/ecash.yaml`, audit `decision_refuse_allowance`, checked
  before standing approvals; the rate cap is deferred to the
  executor), the [Mint](#mint) pin landed as `CASHU_MINT_URL` with
  no default, and the [mint correlation](#mint-correlation) T1
  micro-gaps landed as `timing.mint_gap_s()` (test mode only,
  production `NotImplementedError`-gated). No body changes - the
  entries described the build accurately; doc 07 §11 is the full
  reconcile.

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
