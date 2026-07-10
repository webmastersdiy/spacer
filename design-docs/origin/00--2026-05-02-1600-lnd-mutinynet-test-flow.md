# LND Mutinynet end-to-end test flow

**Date:** 2026-05-02
**Status:** completed
**Context:** Validates the full on-chain + Lightning lifecycle (fund, on-chain send, open channel, pay, cooperative close) on a Voltage-hosted LND node against [Mutinynet](../../GLOSSARY.md#mutinynet) using only `lncli` and the public faucet. Produces the txids, timings, and balances that feed the AI-facing leak map.
**Companion:** `01--2026-05-02-1601-privacy-and-timing-leaks.md` (per-call leak map).

---

## 1. Topology

Single node: [Node A](../../GLOSSARY.md#node-a) (Voltage-hosted LND, Mutinynet) talking to the [faucet](../../GLOSSARY.md#faucet-mutinynet-faucet)'s LN node as counterparty. Two self-controlled nodes were the original plan, but the [Voltage](../../GLOSSARY.md#voltage) free tier caps at one Mutinynet node, and the local-second-node alternative ([ldk-node](../../GLOSSARY.md#ldk-node)) was blocked (no PyPI bindings, needs a Rust toolchain). The faucet node accepts connections, opens channels, and issues payable bolt11 invoices.

## 2. Setup, and the two non-obvious steps

Tools live under `~/spacer/`: `uv`, Python 3.12, and `lncli` v0.20.1-beta. Commands run through the [lncliA](../../GLOSSARY.md#lnclia) wrapper; the admin macaroon comes from the Voltage dashboard (Manage Access). Two setup steps are not obvious:

- **Get `lncli` from the prebuilt LND release tarball, not `go install`.** `go install github.com/lightningnetwork/lnd/cmd/lncli@latest` resolves to an ancient v0.0.2 stub. Download `lnd-darwin-arm64-v0.20.1-beta.tar.gz` from the LND releases page and extract `lncli` from it.
- **Dump the TLS cert manually.** Voltage uses a publicly-trusted Let's Encrypt cert, so the dashboard offers no cert download - but `lncli --tlscertpath` is still mandatory. Extract the leaf cert:
  ```bash
  openssl s_client -connect first-test.u.voltageapp.io:10009 -showcerts </dev/null 2>/dev/null \
    | openssl x509 -outform PEM > ~/spacer/arbiter/lnd/first-test.tls.cert
  ```

Node A identity: pubkey `029ec3af...62617`, host `first-test.u.voltageapp.io` (`54.244.234.100:19898`). Faucet node: pubkey `02465ed5...fb1b` at `45.79.52.207:9735`.

## 3. End-to-end flow

1. **Fund.** `newaddress p2wkh` -> `tb1qf3ctc...sk0u9`; request 100,000 sats from the faucet (GitHub OAuth), wait for confirmation (~1-2 min at Mutinynet's ~30 s blocks).
2. **On-chain send.** `sendcoins --addr=tb1qmt3ue2...4rgeaen7l --amt=5000` -> txid `35023eb9...0775b`.
3. **Open a channel.** `connect` the faucet node, then `openchannel --node_key=02465ed5... --local_amt=50000` -> funding txid `9dd27afb...493d`. Channel goes active after ~168 s (about 5 blocks: 3 confirmations + handshake).
4. **Pay.** Fetch a 1,000-sat invoice from the faucet (`POST /api/bolt11`, no auth), `decodepayreq` to sanity-check the destination/amount, then `payinvoice --force`. Settled in **0.223 s**, 1 hop, 0 fee.
5. **Close.** `closechannel --funding_txid=9dd27afb...493d --output_index=0` -> closing txid `ec936e9d...6b7a`; poll its confirmation.

## 4. Results

**Transaction ledger**

| Event | Txid |
|-------|------|
| On-chain send to faucet | `35023eb9521d859ef2a9d5e7a9a8e86d7d6f639e4da01dd710fa060c4760775b` |
| Channel funding | `9dd27afbd7df9a65e9341ad74f411e69bd10c9ba39f534fd4cde9586f367493d` |
| Channel close | `ec936e9d32ee38c0004641bb974639ae8c86b8d440c87e7ccb496d5c52ef6b7a` |

**Lightning payment:** payment_hash `471ebf05...061c`, preimage `d35257b5...ef74`; 1,000 sat, 0 fee, 1 hop (faucet direct), resolve_time 0.223 s.

**Sat accounting:** +100,000 (faucet) - 5,000 (on-chain send) - 1,000 (LN) - ~526 (fees across 3 txs) = **93,474 remaining** after close.

## 5. Faucet endpoints

Base `https://faucet.mutinynet.com/api`. `POST /bolt11` needs **no auth** (handy for generating invoices in tests); `POST /onchain`, `/lightning`, and `/channel` all require a GitHub OAuth session. A standalone Rust `mutinynet-cli` exists for scripted on-chain faucet funding without a browser.

## 6. Limitations and gotchas

- **Voltage free tier = one Mutinynet node**; two-node testing needs a paid plan or a second account.
- **Faucet on-chain funding requires GitHub OAuth**, linking the funding address to a GitHub identity in the faucet's logs (a world-facing leak).
- **`go install lncli@latest` installs the v0.0.2 stub** - always use the prebuilt tarball.
- **The TLS cert dance** (§2) is mandatory because Voltage uses Let's Encrypt.
- **Channel confirmation time varies** - Mutinynet targets ~30 s blocks but LND needs 3 confirmations; budget 2-5 min from `openchannel` to active.
- **ldk-node is a dead end without Rust**; a second Voltage node or a local LND binary is more practical.

## 7. Reproducible vs not

The §3 sequence is fully scriptable given credentials; the only manual steps are the Voltage signup and the browser faucet funding (step 1). Txids and addresses differ every run; the ~168 s channel timing is approximate (Mutinynet block times vary).

**Pointers:** leak map `01--2026-05-02-1601-privacy-and-timing-leaks.md`; Voltage `voltage.cloud`; esplora `mutinynet.com`; faucet `faucet.mutinynet.com`; LND releases `github.com/lightningnetwork/lnd/releases`.

## 8. Implementation learnings

- **2026-05-24:** reconciled against `test-harness/scripts/lncliA` - the §2 wrapper contract holds verbatim (`--rpcserver=first-test.u.voltageapp.io:10009`, `--tlscertpath`, `--macaroonpath`, `--network=signet` baked in, no extra flags or env indirection). This doc is a one-time bring-up record: the txids, addresses, and pubkeys in §3-§4 are the literal 2026-05-02 run values, left as-is since §7 disclaims their reproducibility. Note the repo now lives at `~/spacer-github/`; the `~/spacer/...` paths here (binaries, creds, state) refer to the testbed runtime tree.
