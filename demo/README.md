# Spacer demos

Visual walkthroughs of Spacer's privacy features.

Spacer lets an AI client drive a Bitcoin node without learning about the operator's wallet, exact balances, or tx identifiers.

> All demos run on Mutinynet signet. Every sat shown is a valueless test sat.

## Privacy mitigations

### Balance query - two views across the gateway boundary

A single `query_balance` round-trip, split across the gateway boundary: the left pane is everything the sandboxed AI agent ("Pet") sees; the right pane is the operator-side Arbiter's private view. It shows two boundary mitigations at once:

- **Balance rounding** - the real `12103` sats is floored to a 1,000-sat grid, so Pet sees `12000`. Sat-precision deltas (fees, deposits, change) can't fingerprint real activity.
- **Snapshot serving** - the reply comes from a cached snapshot refreshed on a randomized 5-15s timer, never a live lookup, so Pet can't observe the instantaneous balance or leak timing.

![Balance query, two views](01-privacy-gateway-balance-query.png)

## Deployment-mode walkthroughs (sequence D)

`SPACER_MODE` selects the op surface; the rails are cumulative. Three demos, one per mode, each showing its own rail working and the higher rails refused by the mode gate:

1. **D1-onchain** - bitcoind only.
2. **D2-onchain-lightning** - onchain + Lightning.
3. **D3-onchain-lightning-ecash** - onchain + Lightning + eCash.

_These are being produced against live Mutinynet infra; each doc + image links here once it is verified against its captured audit log._

---

Each PNG is rendered by a small self-contained Pillow script (`generate_*.py`) using only real captured values. To reproduce demo 1: `python3 generate_01_privacy_gateway.py`.
