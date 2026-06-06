# bitcoind Mutinynet setup and smoke-test flow

**Date:** 2026-05-02 (reconciled 2026-05-24)
**Status:** partial - syncing; on-chain send/receive pending full sync
**Context:** Brings up a locally self-hosted, Mutinynet-patched Bitcoin Core node on macOS arm64 with no package manager or source build, and exercises its RPC surface for the AI ↔ bitcoind proxy design. Produces the [local bitcoind](../../GLOSSARY.md#local-bitcoind) datadir the arbiter targets.
**Companion docs:**
- `00--2026-05-02-1600-lnd-mutinynet-test-flow.md` (LND side); `03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` (RPC leak map).
- `05--2026-05-05-0948-architecture-overview.md` §4.2 (arbiter's bitcoind client) and §9 (layout).

---

## 1. Topology

A single local [Mutinynet-covtools](../../GLOSSARY.md#mutinynet-covtools) Bitcoin Core node (v25.99.0-gf036909dbe28), pruned [signet](../../GLOSSARY.md#signet), on macOS arm64. Sync source is the single Mutinynet peer `45.79.52.207:38333` with `dnsseed=0` (no DNS seeders). Locally self-hosted rather than remote because the arbiter must sit on the same host as the daemon (see [local bitcoind](../../GLOSSARY.md#local-bitcoind)). Prereqs: ~3 GB free disk (2.2 GB prune cap + overhead), no Homebrew / go / rust (the tarball is statically linked against macOS built-ins).

## 2. Setup, and the three non-obvious steps

- **Use the `mutinynet-covtools` release, not `mutinynet-inq-29`.** The v29 tag ships GUI-only on macOS arm64 (no `bitcoind` / `bitcoin-cli`); its CLI tarball is listed in SHA256SUMS but 404s. `mutinynet-covtools` ships the four CLI binaries with the same patches. Asset `bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz`, SHA256 `8b112e67...ee8b`; verify with `shasum -a 256 -c`.
- **Clear Gatekeeper or `bitcoind` is SIGKILLed silently.** The binaries are ad-hoc / linker-signed only; macOS 15.x `spctl` kills them at launch (exit 137, no output). Fix before the first run, per binary:
  ```bash
  for b in bitcoind bitcoin-cli bitcoin-tx bitcoin-wallet; do
    xattr -cr ~/spacer/arbiter/bin/$b && codesign --force --sign - ~/spacer/arbiter/bin/$b
  done
  ```
- **`signetblocktime=30` requires the benthecarman fork.** Stock Bitcoin Core rejects the knob; the covtools binary includes the patch.

All console `bitcoin-cli` calls go through the [btccli](../../GLOSSARY.md#btccli) wrapper; wallet-scoped calls add `-rpcwallet=spacer-smoke` (the throwaway [spacer-smoke](../../GLOSSARY.md#spacer-smoke) descriptor wallet).

## 3. bitcoin.conf

`~/spacer/arbiter/bitcoin/bitcoin.conf`, `chmod 600`. The rpcpassword below is a throwaway already in version control - regenerate for any real use.

```ini
chain=signet
daemon=1
server=1
prune=2200
txindex=0
debug=net
debug=mempool

[signet]
signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae
addnode=45.79.52.207:38333
dnsseed=0
signetblocktime=30
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=38332
rpcuser=spacer
rpcpassword=c_FCI8alPRy2MvGVnIw3T5MD3OjPeI3E8tdkltFKDaA
```

Config gotcha: the global knobs (`chain`, `prune`, `daemon`, `server`, `txindex`) must stay *above* `[signet]`, while the signet-specific knobs (`rpcbind`, `rpcport`, `addnode`, `signetchallenge`, `signetblocktime`, `dnsseed`) must stay *inside* it, or Bitcoin Core ignores them with a "only applied on signet network when in [signet] section" warning. `chain=signet` at top level locks out mainnet; RPC port `38332` is the signet default. Start with `bitcoind -datadir="$HOME/spacer/arbiter/bitcoin"` (daemonizes) and confirm with `getblockchaininfo` (`chain=signet`, `initialblockdownload=true`).

## 4. Layout

The install lives under the `arbiter/` (out of AI reach) and `test-harness/` (testbed) homes; the path each artifact lives under encodes which side of the trust boundary it belongs to (architecture overview §2, §9). The bitcoind-relevant paths:

```
arbiter/bin/              bitcoind, bitcoin-cli, bitcoin-tx, bitcoin-wallet
arbiter/bitcoin/          datadir: bitcoin.conf (600), signet/ chain data, wallets/spacer-smoke/
arbiter/src/bitcoin.py    production arbiter wrapper (§6)
test-harness/scripts/btccli   operator-console bitcoin-cli wrapper (pre-fills -datadir)
```

## 5. RPC surface exercised

The full chain / mempool / network / UTXO / wallet RPC surface was exercised during bring-up via the `btccli` operator wrapper and confirmed working; per-RPC leak analysis is in `03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`. Run observations: `getpeerinfo` showed the single `45.79.52.207` peer; `getindexinfo` returned empty `{}`; `createwallet spacer-smoke` produced a descriptor wallet whose `listdescriptors` returned 8 account descriptors (BIP44/49/84/86 across receive + change). **This inventory is operator-console scope, not the AI-reachable surface** - the production arbiter exposes only four RPCs (§6). `bitcoin-tx` and `bitcoin-wallet` ship in the tarball and run offline (no daemon), useful for tx construction / wallet inspection without a live node.

## 6. Arbiter wrapper: `arbiter/src/bitcoin.py`

The production arbiter does not call `btccli` (that shell wrapper is for human console use). It reaches bitcoind through `arbiter/src/bitcoin.py`, a stdlib-only subprocess wrapper that:

- builds an explicit argv list and runs it via `subprocess.run` with **no shell**, so AI-reachable string arguments cannot trigger shell-metacharacter expansion;
- resolves binary + datadir from env (`BITCOIN_CLI_BIN`, `BITCOIN_DATADIR`, defaults matching §4) and caps every call at `BITCOIN_CLI_TIMEOUT_S` (default 30s), so a wedged daemon or IBD stall becomes a clean refusal rather than an indefinite block;
- exposes exactly four RPCs: `getblockchaininfo`, `getbalance` (returns `Decimal` for satoshi precision), `sendtoaddress` (returns the txid; coin selection / signing / change / PSBT all stay inside bitcoind per [hide secrets](../../GLOSSARY.md#hide-secrets)), and `gettransaction` (with a txid shape check before exec);
- raises a single `BitcoinError` on any failure (non-zero exit, timeout, missing binary, malformed JSON); the dispatch layer audit-logs the cause and returns the uniform refusal, so the error string never crosses the privacy gateway.

The arbiter <-> bitcoind link is on the trusted side of the boundary, so the wrapper applies no anti-timing mitigation - [action delay](../../GLOSSARY.md#action-delay) / [result delay](../../GLOSSARY.md#result-delay) and the gateway's latency normalization cover it from the petitioner side (arch §4.2). The module's `__main__` exercises the full stack against a fake `bitcoin-cli`; live bitcoind coverage is deferred to the end-to-end validation.

## 7. Pending: on-chain send/receive

Sync was still in progress at handoff (~8.6k of ~3.07M blocks; ~1500 blocks/s at IBD start on the ~330-byte Mutinynet blocks, ETA a few hours). The on-chain flow (analogous to LND steps 2-4) needs the node past the funding block before UTXOs are visible. Remaining: paste the `spacer-smoke` address into the faucet (GitHub OAuth), wait for sync past the funding height, `getbalances`, `sendtoaddress` 5000 sats back, then `gettransaction` to verify.

## 8. Limitations and gotchas

- **`mutinynet-inq-29` ships GUI-only on macOS arm64** - use `mutinynet-covtools` for CLI work.
- **Gatekeeper SIGKILLs unsigned binaries silently** (exit 137); the `xattr` + `codesign` fix (§2) must run before the first launch.
- **Initial sync takes hours even pruned** - `prune=2200` caps disk but not IBD time; any test needing UTXO state must wait for the chain tip.
- **Single peer is a SPOF** - one `addnode`, `dnsseed=0`, no fallback discovery; if `45.79.52.207` is down, IBD stalls.
- **`signetblocktime=30` requires the covtools fork** (§2).
- **Wallet not auto-loaded** - `listwallets` is `[]` until `loadwallet` / `createwallet`; useful as a deliberate boundary in the proxy design.

## 9. Reproducible vs not

Everything through §3 is scriptable with no interactive steps except the rpcpassword (regenerate). The pending on-chain flow's only manual step is the browser faucet funding. Addresses / txids differ every run; sync time depends on peer throughput and the tip height at run time.

**Pointers:** LND companion `00--2026-05-02-1600-lnd-mutinynet-test-flow.md`; leak map `03--2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`; arbiter client `arbiter/src/bitcoin.py` (§6); releases `github.com/benthecarman/bitcoin/releases`; faucet / esplora `faucet.mutinynet.com` / `mutinynet.com`; RPC reference `developer.bitcoin.org/reference/rpc/`.

## 10. Implementation learnings

- **2026-05-24:** §4 layout rewritten to match the `arbiter/` + `test-harness/` split the setup steps and architecture overview §9 already use (the old flat `~/spacer/{bin,bitcoin,scripts}/` tree had drifted while the procedural steps stayed correct).
- **2026-05-24:** §6 added documenting `arbiter/src/bitcoin.py` - it deliberately bypasses the shell wrapper so a non-AI reviewer can audit exactly what executes, and exposes only 4 of the ~30 RPCs the operator exercises during smoke-test (§5). Confirmed the `btccli` -> `bitcoin-cli -datadir=$HOME/spacer/arbiter/bitcoin` contract matches `bitcoin.py`'s `DEFAULT_BIN` / `DEFAULT_DATADIR`; no path drift.
