# Node Privacy from the World: bitcoind and LND

**Date:** 2026-05-02
**Context:** World-facing privacy threat model for the full node stack (bitcoind + LND) on Mutinynet/signet.
**Related:**
- `2026-05-02-1601-privacy-and-timing-leaks.md` (LND AI-facing privacy)
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` (bitcoind AI-facing privacy)
- `2026-05-02-1600-lnd-mutinynet-test-flow.md` (LND test runbook)
- `2026-05-02-1602-bitcoind-mutinynet-test-flow.md` (bitcoind test runbook)

---

## 1. Purpose and Scope

This document covers world-facing privacy leaks only: what external parties outside
the AI ↔ proxy ↔ node stack can observe about our node, wallet, and activity.

**In scope:** the public Bitcoin P2P layer, the Lightning gossip network, our peer
connections, DNS and IP traffic, block explorers we query (mempool.space, mutinynet.com),
faucet operators who fund us, and the hosting providers we run on.

**Out of scope (covered in sibling docs):** the AI client as adversary. That is the
primary threat surface. See `2026-05-02-1601-privacy-and-timing-leaks.md` (LND) and
`2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` (bitcoind) for AI-facing concerns.

bitcoind and LND are covered together in this document because their world-facing
exposure overlaps heavily: both broadcast our public IP, both participate in the same
Mutinynet P2P environment, and their on-chain footprints are deeply interlinked
(LND channel funding and closing are bitcoind transactions).

---

## 2. Threat Actors

### 2.1 Single Mutinynet P2P peer (45.79.52.207)

Our bitcoind runs with `dnsseed=0` and a single `addnode` peer at
`45.79.52.207:38333`. That single operator:

- Receives every transaction we originate before it propagates to any other peer.
  With a one-peer setup, there is no ambiguity: if a tx first appears from our TCP
  connection, that operator knows we originated it with 100% certainty.
- Learns our public IP from the TCP handshake and from the `addrlocal` field our node
  broadcasts (`73.93.99.82` confirmed in every `getpeerinfo` row).
- Knows our protocol version string (`/Satoshi:25.99.0/`), local services bitmap,
  and connection uptime.
- Sees every block header request and inventory message, which reveals the
  IBD progression rate and the exact moment IBD completes.

At full sync, additional gossip-discovered peers appeared (7 total, including
`35.225.223.74:19444` - an inquisition node), so the one-peer guarantee is not
permanent. But during our run, the single addnode peer had privileged first-observer
status for all originating transactions.

### 2.2 LN gossip network

Every public Lightning channel announcement is broadcast globally and permanently.
Once gossiped, it cannot be un-gossiped. A public channel announcement reveals:

- Both node pubkeys in the channel
- Channel capacity (satoshis)
- Short channel ID (SCID), which encodes the funding transaction's block height,
  transaction index, and output index - permanently linking the gossip entry to
  an on-chain UTXO
- Fee policy

In our run, the channel opened to the Mutinynet faucet node (`02465ed5...@45.79.52.207:9735`)
was gossiped publicly. Every LN node that maintains a gossip graph now knows our node
participated in that channel.

### 2.3 Block explorers we query

During this run we used `https://mutinynet.com/api` (a public esplora) to poll
transaction confirmation status. Each HTTP request of the form `/api/tx/<txid>/status`
makes a connection from our IP to the esplora operator, linking our IP address to
our interest in that specific txid. The frequency of polling reveals urgency: a
request every 10 seconds for 20 minutes signals "I am actively waiting for this
transaction." The esplora operator can cross-reference the txid with on-chain data
and correlate it with other requests from the same IP in the same session.

Three txids were polled: the on-chain send (`35023eb9...`), the channel funding
(`9dd27afb...`), and the channel close (`ec936e9d...`). All three link our IP to
our full on-chain activity for this session.

### 2.4 Faucet operator (identity-binding funding source)

The Mutinynet faucet at `https://faucet.mutinynet.com` requires GitHub OAuth. The
faucet `POST /api/onchain` call supplies our receiving address and amount. The
faucet operator therefore holds a record linking:

- Our GitHub identity
- The address we provided (a bech32 address derived from our LND wallet)
- The payout txid, which is publicly visible on-chain

Anyone who later observes our on-chain activity can trace the faucet payout txid
as the funding source, and anyone with access to the faucet's records can resolve
"GitHub user X funded address Y at time T."

### 2.5 Hosting provider (Voltage)

Our LND node runs on Voltage's infrastructure (`first-test.u.voltageapp.io`,
LND v0.20.0-beta, Mutinynet). Voltage has full visibility into:

- All LND RPC calls and their responses (they control the host OS and disk)
- The LND datadir, wallet file, macaroons, and TLS certificates
- Network traffic in and out of the LND process
- Any credentials or identifiers stored by the node

This is an unconditional trust boundary. The privacy proxy between AI and LND
provides zero protection against Voltage. If Voltage is a threat, self-hosting
is the only mitigation.

### 2.6 Routing nodes on LN payment paths

LN uses onion routing, which hides the full path from individual hops, but
each intermediate hop observes:

- The HTLC it forwards (amount minus its fee, CLTV delta, next-hop onion blob)
- The timing between receiving the incoming HTLC and receiving the settlement
  (or failure)

The first hop from our node - the hop to the faucet node in our case, since
it was a direct 1-hop payment - always knows our node ID. The last hop
always knows the destination. In the direct-payment case, the first and last
hops are the same node (the faucet), giving it full sender and receiver
information.

Timing available to routing nodes enables path-length inference: a hop that
sees an HTLC settle in 0.22 s (our measured 1-hop time on Mutinynet clearnet)
can distinguish that from a 2-hop or 3-hop Tor path. This is a passive
observation; no special behavior is required from the routing node.

---

## 3. Concrete Leaks Observed in Our Run

All values are from Mutinynet/signet. No mainnet data appears anywhere in this
document.

### 3.1 Public IP (bitcoind)

Every row of `getpeerinfo` output contained `addrlocal: "73.93.99.82:<port>"`.
The public IP was not in a single field - it appeared in every peer entry,
once per peer connection. The LAN address `192.168.50.12` appeared in every
`addrbind` field.

Source: `bitcoind_notes.md` (section "Observed facts from live runs") and the
bitcoind AI-facing doc §2 threat model.

### 3.2 LND node identity (clearnet URI and Tor URI)

LND `getinfo` returned a `uris` array containing:
- Clearnet URI: `<pubkey>@54.244.234.100:19898` (Voltage's public IP)
- A `.onion` URI for the same node

Both were gossiped to the LN network when our public channel was announced.
Any node receiving the gossip now knows our pubkey and our clearnet IP.

Source: `privacy_notes.md` (setup snapshot) and LND AI-facing doc §2.

### 3.3 On-chain transaction permanent record

The following txids are permanently on the Mutinynet signet chain and visible
to any block explorer operator, chain observer, or anyone with a copy of the
block data:

- On-chain send: `35023eb9521d859ef2a9d5e7a9a8e86d7d6f639e4da01dd710fa060c4760775b`
  (our UTXOs as inputs, recipient address as output, change address as output)
- Channel funding: `9dd27afbd7df9a65e9341ad74f411e69bd10c9ba39f534fd4cde9586f367493d`
  (2-of-2 multisig output funding the channel, permanently on-chain)
- Channel close: `ec936e9d32ee38c0004641bb974639ae8c86b8d440c87e7ccb496d5c52ef6b7a`
  (publishes final balance split: our amount and the faucet's amount)

Source: `privacy_notes.md` session ledger.

### 3.4 Public channel gossip

The channel to the faucet node was announced publicly (not opened with
`--private`). The gossip entry includes our pubkey, the faucet's pubkey
(`02465ed5...`), channel capacity, and the SCID derived from the funding
txid. Every LN node that has received this gossip can look up the funding
tx on-chain and confirm the pairing.

Source: `privacy_notes.md` (openchannel section); LND AI-facing doc §3.6.

### 3.5 mempool.space / esplora IP linkage

Every confirmation poll during the session was directed at
`https://mutinynet.com/api`. The esplora operator's access logs contain
our source IP paired with each txid query. Three txids were queried:
on-chain send, channel funding, channel close.

Source: `privacy_notes.md` (side-channels section).

### 3.6 Faucet GitHub OAuth identity binding

The faucet required GitHub login before issuing funds. The faucet's records
link our GitHub identity to the receiving address and to the payout txid.
The payout txid is visible on-chain; tracing from txid to GitHub identity
requires the faucet's records, but those records exist.

Source: `privacy_notes.md` (`POST faucet/api/onchain` section).

### 3.7 Tor absent in bitcoind

`getnetworkinfo` confirmed `onion: reachable=false, proxy=""`. All bitcoind
P2P traffic - including our single peer connection to `45.79.52.207` - is
clearnet. Our IP is visible to the peer and to any network observer on the
path.

Source: `bitcoind_notes.md` (observed facts) and bitcoind AI-facing doc §2.

### 3.8 Dandelion absent in Mutinynet fork

`bitcoind -help-debug` for the Mutinynet/covtools build (v25.99.0) has no
`dandelion` option. Transaction broadcast goes directly to all connected
peers without a stem phase. The first peer to receive a transaction has
strong evidence we originated it, especially with a single-peer setup.

Source: `bitcoind_notes.md` (observed facts) and bitcoind AI-facing doc §4.1.

---

## 4. Inherent vs. Avoidable Leaks

### Inherent leaks (cannot be hidden by design)

- **Transaction broadcast IS publication.** Broadcasting a Bitcoin transaction
  to the P2P network makes it globally and permanently visible. There is no
  mechanism to send a tx to only trusted observers; the P2P protocol propagates
  it to every node. The funding, close, and on-chain send txids from our run
  are permanent Mutinynet chain records.

- **BOLT11 invoices encode the destination.** A bolt11 invoice encodes the
  destination pubkey, amount, and payment hash by protocol specification. Anyone
  who receives an invoice issued by our node learns our node ID. There is no
  opt-out from this encoding in the BOLT11 spec.

- **BOLT12 offers share the node pubkey.** A BOLT12 offer is long-lived and
  reuse of the same offer by different payers is linkable, since the offer
  contains the node's pubkey.

- **Channel funding and closing are on-chain transactions.** Even private
  (un-announced) channels require an on-chain funding tx and an on-chain
  closing tx. Those transactions are publicly visible. The balance split at
  cooperative close is visible in the closing tx outputs.

- **Public gossip is permanent.** Once a channel announcement propagates
  through the LN gossip layer it cannot be recalled. Nodes that have received
  it may retain it indefinitely.

- **First hop always knows our node ID.** In LN onion routing, the first hop
  receives an HTLC from us and therefore knows our node identity. This is
  unavoidable; it is the peer we are directly channeled with.

- **IP in TCP connections.** Any peer we connect to on clearnet observes our
  source IP from the TCP connection. This is inherent to clearnet networking.
  Tor hides it at the cost of latency.

### Avoidable leaks (can be mitigated with infrastructure choices)

- **Our IP in getpeerinfo addrlocal.** This is only a problem because we
  are on clearnet. Routing through Tor would hide the IP from peers and
  from the `addrlocal` field.

- **Single-peer first-hop attribution.** Using a single addnode peer makes
  origination attribution certain. Multiple peers reduce this to probabilistic.
  Broadcasting via Tor further obscures origination.

- **Public esplora confirmation polling.** Replacing
  `https://mutinynet.com/api` with local bitcoind RPC queries or a
  self-hosted esplora removes the IP-to-txid linkage from third-party logs.

- **Public (announced) channels.** Opening channels with `--private` (or the
  ldk-node `open_channel` instead of `open_announced_channel`) prevents the
  gossip layer from learning our pubkey-pair and channel capacity. The
  funding and close txs are still on-chain, but the routing graph entry is
  not gossiped.

- **Faucet GitHub OAuth binding.** Using a faucet that does not require OAuth,
  or receiving funding via a swap service that does not know our identity,
  would break the GitHub-to-address link.

- **Voltage operator trust.** Self-hosting LND on our own hardware eliminates
  Voltage's unconditional visibility. This does not affect the Bitcoin P2P or
  LN gossip leaks, but it removes the hosting provider from the threat list.

- **Dandelion absence.** If a future Mutinynet build includes Dandelion
  (BIP 156) or equivalent stem-phase broadcast, the first-hop attribution
  becomes probabilistic rather than certain. This is a build-level choice,
  not a configuration option in the current v25.99.0 fork.

---

## 5. Mitigation Menu

### 5.1 Tor for everything

- **bitcoind:** `proxy=127.0.0.1:9050`, `onlynet=onion` (requires the Mutinynet
  peer at 45.79.52.207 to have a `.onion` address - to be verified; see §7).
  Without `onlynet=onion`, clearnet connections will coexist with Tor connections.
- **LND:** `tor.active=true`, `tor.v3=true` in `lnd.conf`. Voltage exposes a
  `.onion` URI for Mutinynet nodes - confirm it is used for P2P connections.
- **All HTTP (esplora, faucet):** route through `torsocks` or a SOCKS5 proxy
  pointed at the local Tor daemon.

Tor eliminates the IP-in-TCP observation and makes `addrlocal` less useful
to peers. It does not hide which transactions we broadcast; Tor protects
transport-layer identity, not application-layer content.

Caveat: Tor adds latency. Our measured 1-hop clearnet payment time was 0.22 s;
a Tor path may add 1-3 s. Quantifying this against Mutinynet is an open item
(§7.1).

### 5.2 Multi-peer broadcast

Connect bitcoind to multiple peers (the default Bitcoin Core target is 8 outbound).
When a transaction reaches multiple peers simultaneously, no single peer has
certain first-seen attribution. An adversary among the peers gets a probabilistic
fingerprint rather than a guaranteed one.

Note: the Mutinynet peer set is small. With `dnsseed=0`, we may not have enough
peers to achieve meaningful ambiguity without manual `addnode` entries.

### 5.3 Private (un-announced) LN channels by default

Pass `--private` when calling `openchannel` with `lncli`, or use
`open_channel` (not `open_announced_channel`) with ldk-node. The channel
funding tx and close tx remain on-chain and publicly visible, but the
gossip-layer entry (pubkey-pair + capacity + SCID) is never broadcast.

Routing through private channels is possible if the recipient includes
route hints in their invoice. Private channels work well for the payer role;
they are less suitable if our node is intended to be a routing node.

The AI-facing proxy doc already recommends `--private` as a default for the
proxy policy (LND AI-facing doc §3.6). That recommendation serves both
AI-facing and world-facing goals simultaneously.

### 5.4 Self-hosted block explorer

Run a local esplora instance (e.g., `esplora` or `electrs`) indexing our
pruned bitcoind, and point all confirmation polling at `http://localhost:PORT`
instead of `https://mutinynet.com/api`. This removes the IP-to-txid linkage
from third-party access logs entirely.

Limitation: a local esplora still logs queries internally. Log hygiene on the
local host is still required. Also, our current bitcoind runs with `prune=2200`
and `txindex=0`; a full esplora index may conflict with these settings.
Testing is needed (§7.4).

### 5.5 Self-hosted everything vs. Voltage

Running LND on our own hardware removes Voltage from the threat model entirely.
Voltage currently has unconditional visibility into the LND process, datadir,
and all network traffic. Self-hosting eliminates this at the cost of hardware,
uptime maintenance, and physical security requirements.

Self-hosting does not change the Bitcoin P2P or LN gossip exposure - those
leaks are network-level and exist regardless of where LND runs.

### 5.6 CoinJoin or mixing before funding from low-privacy sources

The Mutinynet faucet funding links our GitHub identity to an on-chain address.
If we run a CoinJoin or mixing step before using those funds in a channel open
or an on-chain send, the direct UTXO chain from faucet payout to our channel
funding tx is broken. The faucet record still exists, but tracing from faucet
to our active wallet requires following the CoinJoin graph.

On Mutinynet (signet), there are limited CoinJoin participants; this is more
a design pattern to carry to mainnet than a practical Mutinynet mitigation.

### 5.7 Avoid identity-binding funding sources

Use faucets that do not require OAuth, or fund via a swap service (e.g., a
Lightning-to-on-chain swap where the incoming payment comes from a source that
does not know our identity). This avoids creating the GitHub-to-address record
at the faucet operator.

On Mutinynet, the main public faucet requires GitHub OAuth. An alternative is
to receive a faucet payment to a throw-away address and then route funds through
an intermediate step before funding the node wallet we care about.

### 5.8 Dandelion equivalent via Tor broadcast

Since Dandelion is absent in the Mutinynet v25.99.0 fork, broadcasting
transactions through a Tor exit to the P2P network serves a similar purpose:
the receiving node on the other side of the Tor circuit does not see our IP,
and is unlikely to be our regular peer. This does not implement the stem-phase
graph-propagation semantics of BIP 156, but it achieves the first-hop IP
anonymity goal.

If `onlynet=onion` is used (§5.1), all P2P connections are through Tor and
the Dandelion absence becomes less critical - the first-hop IP leak is already
addressed.

---

## 6. Coupling with AI-Facing Concerns

The world-facing leaks documented here are real and worth mitigating, but they
are secondary to AI-facing privacy. Here is why.

World-facing leaks reveal things to parties who observe the Bitcoin P2P network,
the LN gossip layer, esplora logs, or our peer connections. What those parties
learn - our IP, our txids, our channel pairings - enables correlation only if
they can link those observations to our identity within the AI ↔ proxy ↔ node
system.

The AI-facing proxy is the linchpin: if the proxy successfully withholds our
node's pubkey, IP addresses, channel_points, payment hashes, and funding txids
from the AI client, then the AI has no anchor to cross-reference against
publicly observable data. An adversarial AI that learns "some node broadcast
txid X to the P2P network" cannot connect that to our node unless it also
knows our node's identity.

This is why AI-facing privacy is the primary scope of this project. A world
where the AI knows nothing sensitive about our node is a world where world-facing
leaks are survivable - they leak to other parties, but those parties cannot
share what they know with the AI in a way that creates additional harm.

Conversely, if the AI-facing proxy fails - if the AI learns our node pubkey,
our IP, or our channel funding txids - then every world-facing observation
becomes potentially available to the AI for cross-reference. The gossip record
linking our pubkey to a channel, combined with the AI knowing our pubkey, enables
the AI to reconstruct our full channel history from public data.

**Practical implication:** world-facing mitigations (Tor, private channels,
self-hosting) are worth doing, but they should not be prioritized over getting
the proxy filtering rules correct. The proxy filter is the primary defense; the
world-facing mitigations are defense-in-depth.

---

## 7. Open Questions and Things to Test

1. **Tor latency on Mutinynet clearnet vs. onion path.** Our measured 1-hop
   direct payment time was 0.22 s on Mutinynet clearnet. Run the same payment
   through LND's `.onion` endpoint and measure the latency delta. Determine
   whether Tor latency makes Mutinynet unusable for iterative testing or just
   adds a fixed overhead.

2. **Does 45.79.52.207 have a .onion address?** Before enabling `onlynet=onion`
   for bitcoind, verify that the Mutinynet team's sync peer has a reachable
   `.onion` address. If it does not, `onlynet=onion` will leave bitcoind with
   zero peers and no way to sync. If it does not, the fallback is to use Tor
   SOCKS5 proxy without `onlynet=onion` - this lets clearnet connections
   continue while enabling Tor for outbound broadcast.

3. **PSBT-style flows over Tor between offline signer and Tor-only watch node.**
   If bitcoind runs `onlynet=onion` and LND uses `tor.active=true`, test
   whether a watch-only wallet plus offline signer workflow (PSBT constructed
   on the watching node, signed offline) is compatible with the Tor-only
   network mode. Specifically: can the signed tx be broadcast through the
   Tor-connected node without the offline signer needing its own Tor circuit?

4. **Self-hosted esplora vs. direct bitcoind RPC for confirmation polling.**
   Determine whether running a local `electrs` or `esplora` instance on top
   of our pruned bitcoind (`prune=2200`) is feasible. The key question is
   whether esplora's index requirements conflict with our pruning settings.
   If it works, measure whether it eliminates the IP-to-txid leak vs. public
   esplora, or whether the local esplora's own logs create an equivalent
   record on the local host.

5. **Dandelion in Mutinynet v29 or Bitcoin Core mainline.** Check whether
   the Mutinynet `mutinynet-inq-29` build or Bitcoin Core mainline v27+
   exposes a Dandelion option. If Dandelion is available and we are already
   using `onlynet=onion`, quantify whether Dandelion provides additional
   protection beyond what Tor already gives.

6. **Quantify single-peer vs. multi-peer origination attribution risk.**
   After sync, connect to 4-8 Mutinynet peers (using manual `addnode` entries
   if DNS seeding is disabled). Broadcast a test transaction and measure whether
   any single peer can distinguish origination from relay by timing alone.
   This sets the minimum peer count needed before Dandelion or Tor becomes
   strictly necessary for first-hop anonymity.
