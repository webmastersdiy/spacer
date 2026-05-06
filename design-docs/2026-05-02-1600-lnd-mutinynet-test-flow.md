# LND Mutinynet end-to-end test flow

**Date:** 2026-05-02  
**Status:** completed  
**Companion doc:** `2026-05-02-1601-privacy-and-timing-leaks.md` (per-API leak map)

---

## 1. Purpose

Validate that a Voltage-hosted LND node on Mutinynet (signet) can execute the
full on-chain and Lightning lifecycle - fund from faucet, on-chain send, open
channel, pay invoice, cooperative close - using only local tooling (`lncli`)
and the public faucet API. The run produces concrete txids, balances, and
timing data that feed the AI ↔ bitcoind/LND privacy proxy design.

---

## 2. Test topology

Single-node: **Node A** (Voltage-hosted LND, Mutinynet) ↔ **Mutinynet faucet LN node** (counterparty).

We originally wanted two self-controlled nodes so both sides were observable.
Two constraints blocked that:

- **Voltage free-tier cap:** one Mutinynet node per account. A second Voltage
  account would work but adds friction with no technical upside for this run.
- **ldk-node was the planned local alternative** (run a second node locally in
  Python without a full daemon). It was abandoned: the Python bindings are not
  on PyPI, building them requires a Rust toolchain the environment doesn't
  have, and a cold Mutinynet sync from genesis would be prohibitively slow.
  See `~/spacer/test-harness/state/INSTALL_BLOCKER.md` for the full investigation.

The faucet's LN node serves as a functional counterparty: it accepts
connections, opens channels, and issues payable bolt11 invoices.

---

## 3. Prerequisites

**Accounts**

- Voltage account (free Essentials tier) - `https://voltage.cloud`
- GitHub account - required for faucet OAuth at `https://faucet.mutinynet.com`

**Platform**

- macOS + Apple Silicon (arm64). Linux x86-64 would work with different tarball
  URLs; adjust accordingly.

**Local installs (all under `~/spacer/`)**

| Tool | Version | Path |
|------|---------|------|
| `uv` | latest | `~/spacer/test-harness/bin/uv` |
| Python 3.12 | uv-managed | `~/spacer/test-harness/venv/` |
| `lncli` | v0.20.1-beta | `~/spacer/arbiter/bin/lncli` |

`lncli` is extracted from the prebuilt LND release tarball (see step 5.2).
Do **not** use `go install github.com/lightningnetwork/lnd/cmd/lncli@latest` -
it resolves to the ancient v0.0.2 stub, not the real binary.

---

## 4. Layout under `~/spacer/`

```
~/spacer/
├── arbiter/
│   ├── bin/
│   │   └── lncli                       # extracted from prebuilt LND tarball
│   └── lnd/
│       ├── first-test.admin.macaroon   # downloaded from Voltage dashboard
│       └── first-test.tls.cert         # dumped via openssl s_client (see §5.4)
└── test-harness/
    ├── bin/
    │   ├── uv
    │   └── uvx
    ├── scripts/
    │   ├── lncliA          # wrapper script (bakes in rpcserver, creds, network)
    │   └── ldk_smoke.py    # ldk-node smoke test (blocked; see INSTALL_BLOCKER.md)
    └── state/
        ├── nodeA.env
        ├── faucet.env
        ├── nodeA_address.json
        ├── onchain_send.json
        ├── channel_open.json
        ├── channel_close.json
        ├── invoice.json
        ├── payment_result.txt
        ├── privacy_notes.md
        ├── INSTALL_BLOCKER.md
        └── mutinynet_cli_main.rs   # reference: mutinynet-cli source
```

---

## 5. Setup steps

### 5.1 Download uv

```bash
mkdir -p ~/spacer/test-harness/bin
curl -fsSL https://astral.sh/uv/install.sh | INSTALL_DIR=~/spacer/test-harness/bin sh
```

### 5.2 Download lncli (prebuilt tarball)

Go to `https://github.com/lightningnetwork/lnd/releases` and grab the
`lnd-linux-arm64-vX.Y.Z-beta.tar.gz` (or `darwin-arm64`) asset for the latest
release (v0.20.1-beta at time of run).

```bash
# adjust URL to current release and platform
LND_VERSION=v0.20.1-beta
TARBALL=lnd-darwin-arm64-${LND_VERSION}.tar.gz
curl -fSL "https://github.com/lightningnetwork/lnd/releases/download/${LND_VERSION}/${TARBALL}" \
  -o /tmp/${TARBALL}
tar -xzf /tmp/${TARBALL} --strip-components=1 \
  "lnd-darwin-arm64-${LND_VERSION}/lncli" \
  -C ~/spacer/arbiter/bin/
chmod +x ~/spacer/arbiter/bin/lncli
```

### 5.3 Provision node A on Voltage

1. Sign up at `https://voltage.cloud` (free Essentials tier).
2. Create a new node → choose **Lightning** → **Mutinynet** (signet).
3. Name it (e.g. `first-test`), set an unlock password, wait for provisioning
   (~1-2 min).
4. In the node dashboard → **Manage Access** → download `admin.macaroon`.
5. Save it to `~/spacer/arbiter/lnd/first-test.admin.macaroon`.

Note: Voltage nodes use a Let's Encrypt TLS certificate (publicly trusted), so
the dashboard does not offer a cert download. `lncli` still requires
`--tlscertpath`, so the cert must be extracted manually (§5.4).

### 5.4 Dump the TLS certificate

```bash
openssl s_client -connect first-test.u.voltageapp.io:10009 \
  -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM \
  > ~/spacer/arbiter/lnd/first-test.tls.cert
```

Verify: `openssl x509 -in ~/spacer/arbiter/lnd/first-test.tls.cert -noout -subject`

### 5.5 Write the lncliA wrapper

```bash
cat > ~/spacer/test-harness/scripts/lncliA <<'EOF'
#!/usr/bin/env bash
# Throwaway wrapper: lncli pointed at Voltage node A (first-test).
exec "$HOME/spacer/arbiter/bin/lncli" \
  --rpcserver=first-test.u.voltageapp.io:10009 \
  --tlscertpath="$HOME/spacer/arbiter/lnd/first-test.tls.cert" \
  --macaroonpath="$HOME/spacer/arbiter/lnd/first-test.admin.macaroon" \
  --network=signet \
  "$@"
EOF
chmod +x ~/spacer/test-harness/scripts/lncliA
```

Smoke-test: `~/spacer/test-harness/scripts/lncliA getinfo | jq .alias`

---

## 6. End-to-end flow

Node A identity:

```
pubkey : 029ec3af8da98bb3f5825b74bf0e5b0c4cb401a602cca7afd25fc84a4279f62617
host   : first-test.u.voltageapp.io  (clearnet 54.244.234.100:19898)
```

Faucet LN node identity (from `state/faucet.env`):

```
pubkey : 02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b
host   : 45.79.52.207:9735
```

### Step 1 - Get a funding address

```bash
~/spacer/test-harness/scripts/lncliA newaddress p2wkh
```

Result: `tb1qf3ctcarh5ndfp30t78yjqmdex0a2duxg2sk0u9`

### Step 2 - Request faucet funding (manual)

1. Go to `https://faucet.mutinynet.com`, authenticate with GitHub OAuth.
2. Paste the address, request **100,000 sats**.
3. Faucet broadcasts the funding tx. Note the txid from the UI or from
   `walletbalance` once it appears.

### Step 3 - Poll for confirmation

```bash
# LND side (unconfirmed → confirmed)
~/spacer/test-harness/scripts/lncliA walletbalance

# Chain side
curl -s https://mutinynet.com/api/tx/<FUNDING_TXID>/status | jq .confirmed
```

Wait until `confirmed: true` (Mutinynet produces blocks ~30s apart; typically
1-2 min).

### Step 4 - On-chain send back to faucet return address

```bash
~/spacer/test-harness/scripts/lncliA sendcoins \
  --addr=tb1qmt3ue2senlg6ddgmr76hwsk0rdvdk4rgeaen7l \
  --amt=5000
```

Result txid: `35023eb9521d859ef2a9d5e7a9a8e86d7d6f639e4da01dd710fa060c4760775b`

### Step 5 - Peer the faucet LN node

```bash
~/spacer/test-harness/scripts/lncliA connect \
  02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b@45.79.52.207:9735
```

### Step 6 - Open a channel

```bash
~/spacer/test-harness/scripts/lncliA openchannel \
  --node_key=02465ed5be53d04fde66c9418ff14a5f2267723810176c9212b722e542dc1afb1b \
  --local_amt=50000
```

Funding txid: `9dd27afbd7df9a65e9341ad74f411e69bd10c9ba39f534fd4cde9586f367493d`

### Step 7 - Poll until channel is active

```bash
# Chain: wait for 3 confirmations
curl -s https://mutinynet.com/api/tx/9dd27afbd7df9a65e9341ad74f411e69bd10c9ba39f534fd4cde9586f367493d/status

# LND: watch channel state flip from pending → active
~/spacer/test-harness/scripts/lncliA listchannels | jq '.[].active'
```

This took ~168 s (≈ 5 blocks: 3 confirmations required + channel handshake).

### Step 8 - Fetch a bolt11 invoice from the faucet

The `/api/bolt11` endpoint requires no auth (unlike `/api/onchain`,
`/api/lightning`, `/api/channel` which all require GitHub session cookies).

```bash
curl -s -X POST https://faucet.mutinynet.com/api/bolt11 \
  -H 'Content-Type: application/json' \
  -d '{"amount_sats": 1000}' \
  | tee ~/spacer/test-harness/state/invoice.json
```

Result bolt11 (truncated): `lntbs10u1p5lv67w...qqj5dpwe`

### Step 9 - Decode the invoice (sanity check)

```bash
~/spacer/test-harness/scripts/lncliA decodepayreq \
  lntbs10u1p5lv67wpp5gu0t7pflc42yk38vlma6tg64jvwandtg9kk9mlhlapkrze82qcwqdqqcqzzsxqyz5vqsp5v34g4urkwnqkpnrj4lzr9xt523qnt4x83wqjy5ustv48wmluzg4q9qxpqysgqezfnnvec2smu78jd24j3336geg25lh6gfvcg6cgpdsmsxewxztwyt3x5vvc82t3ajaz4zfzpvvq262n7mg0kvsnjnnlcnfrt53t2z0qqj5dpwe
```

Confirms: 1,000 sat, destination = faucet pubkey.

### Step 10 - Pay the invoice

```bash
~/spacer/test-harness/scripts/lncliA payinvoice --force \
  lntbs10u1p5lv67wpp5gu0t7pflc42yk38vlma6tg64jvwandtg9kk9mlhlapkrze82qcwqdqqcqzzsxqyz5vqsp5v34g4urkwnqkpnrj4lzr9xt523qnt4x83wqjy5ustv48wmluzg4q9qxpqysgqezfnnvec2smu78jd24j3336geg25lh6gfvcg6cgpdsmsxewxztwyt3x5vvc82t3ajaz4zfzpvvq262n7mg0kvsnjnnlcnfrt53t2z0qqj5dpwe \
  | tee ~/spacer/test-harness/state/payment_result.txt
```

Settled in **0.223 s** (attempt_time=0.017, resolve_time=0.223), 1 hop, 0 fee.

### Step 11 - Close the channel (cooperative)

Get the channel point first:

```bash
~/spacer/test-harness/scripts/lncliA listchannels \
  | jq '.[] | {channel_point, remote_pubkey}'
```

Close:

```bash
~/spacer/test-harness/scripts/lncliA closechannel \
  --funding_txid=9dd27afbd7df9a65e9341ad74f411e69bd10c9ba39f534fd4cde9586f367493d \
  --output_index=0
```

Closing txid: `ec936e9d32ee38c0004641bb974639ae8c86b8d440c87e7ccb496d5c52ef6b7a`

### Step 12 - Poll closing tx confirmation

```bash
curl -s https://mutinynet.com/api/tx/ec936e9d32ee38c0004641bb974639ae8c86b8d440c87e7ccb496d5c52ef6b7a/status \
  | jq .confirmed
```

---

## 7. Actual outputs

### Transaction ledger

| Event | Txid |
|-------|------|
| Faucet on-chain funding | (noted from faucet UI / walletbalance) |
| On-chain send to faucet return | `35023eb9521d859ef2a9d5e7a9a8e86d7d6f639e4da01dd710fa060c4760775b` |
| Channel open (funding tx) | `9dd27afbd7df9a65e9341ad74f411e69bd10c9ba39f534fd4cde9586f367493d` |
| Channel close | `ec936e9d32ee38c0004641bb974639ae8c86b8d440c87e7ccb496d5c52ef6b7a` |

### Lightning payment

| Field | Value |
|-------|-------|
| payment_hash | `471ebf053fc5544b44ecfefba5a355931dd9b5682dac5dfeffe86c3164ea061c` |
| preimage | `d35257b5030f31fe136d6f7f2c0b2735f06bdfb9c54405f304019bcd8819ef74` |
| amount | 1,000 sat |
| fee | 0 sat |
| hops | 1 (Faucet LND direct) |
| resolve_time | 0.223 s |

### Sat accounting

| Event | Sats |
|-------|------|
| Faucet funding received | +100,000 |
| On-chain send (step 4) | −5,000 |
| LN payment (step 10) | −1,000 |
| On-chain + channel fees (3 txs) | ~−526 |
| **Remaining after close** | **93,474** |

---

## 8. Auxiliary tooling discovered

- **mutinynet-cli** - a standalone Rust CLI for interacting with the Mutinynet
  faucet programmatically (`~/spacer/test-harness/state/mutinynet_cli_main.rs` has the
  source for reference). Useful if you want scripted on-chain faucet funding
  without a browser. Requires building from source.

- **Faucet HTTP endpoints** (base: `https://faucet.mutinynet.com/api`):

  | Endpoint | Auth required |
  |----------|--------------|
  | `POST /onchain` | Yes (GitHub OAuth session) |
  | `POST /lightning` | Yes |
  | `POST /channel` | Yes |
  | `POST /bolt11` | **No** |
  | `GET /l402` | No - but returned HTTP 500 during our run |

  `/api/bolt11` being open is useful: it lets you generate invoices for payment
  tests without a browser session.

---

## 9. Limitations and gotchas

- **Voltage 1-node free cap.** The Essentials tier allows one Mutinynet node.
  Two-node testing on Voltage requires a paid plan or two separate accounts.

- **Faucet requires GitHub OAuth** for on-chain funding. The funding address
  ends up linked to a GitHub identity in the faucet's logs. Not a concern on
  Mutinynet, but note the pattern for any faucet design.

- **`go install lncli@latest` installs v0.0.2,** a stub that predates the real
  lncli. Always use the prebuilt tarball from the LND GitHub releases page.

- **TLS cert dance.** Voltage uses Let's Encrypt (publicly trusted) so the
  dashboard offers no cert download. You must dump the leaf cert via
  `openssl s_client` as shown in §5.4. The `--tlscertpath` flag to `lncli`
  is mandatory regardless.

- **Channel confirmation time is variable.** Mutinynet targets ~30 s blocks,
  but LND requires 3 confirmations by default. Budget 2-5 min from
  `openchannel` to `active: true`.

- **ldk-node is a dead end without Rust.** See
  `~/spacer/test-harness/state/INSTALL_BLOCKER.md`. If a second local node is needed,
  a second Voltage node (paid tier) or a local LND binary is more practical.

---

## 10. What's reproducible vs not

| Item | Reproducible? |
|------|--------------|
| `lncli` download + wrapper script | Yes - fully scriptable |
| Voltage node provisioning | Requires a personal Voltage account (per-user) |
| Faucet funding | Requires a GitHub account; rate-limited |
| All lncli commands (steps 4-11) | Yes, given a funded node and lncliA wrapper |
| Txids / addresses | No - new run produces new values |
| Channel timing (~168 s) | Approximate; Mutinynet block times vary |

The sequence in §6 is fully scriptable given credentials in `nodeA.env` and
`faucet.env`. The only manual steps are the Voltage signup and the faucet
browser funding in step 2.

---

## 11. Pointers

- **Privacy/leak analysis** for every API call above:
  `~/spacer/design-docs/2026-05-02-1601-privacy-and-timing-leaks.md`
- **ldk-node install investigation:** `~/spacer/test-harness/state/INSTALL_BLOCKER.md`
- **Node credentials:** `~/spacer/test-harness/state/nodeA.env`, `~/spacer/test-harness/state/faucet.env`
- **Voltage dashboard:** `https://voltage.cloud`
- **Mutinynet esplora:** `https://mutinynet.com`
- **Faucet:** `https://faucet.mutinynet.com`
- **LND releases:** `https://github.com/lightningnetwork/lnd/releases`
