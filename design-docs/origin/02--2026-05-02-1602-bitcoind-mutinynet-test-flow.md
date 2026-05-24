# bitcoind Mutinynet setup and smoke-test flow

**Date:** 2026-05-02  
**Status:** partial - syncing; on-chain send/receive pending full sync  
**Companion docs:**  
- `2026-05-02-1600-lnd-mutinynet-test-flow.md` (LND side)  
- `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md` (RPC leak map)

---

## 1. Purpose

Validate that a locally self-hosted, Mutinynet-patched Bitcoin Core node can be
installed and operated on macOS Apple Silicon without any system package manager
or source build, and that its RPC surface can be exercised end-to-end for the
purpose of designing an AI ↔ bitcoind privacy proxy. The run produces a working
`bitcoind` daemon syncing the Mutinynet signet chain, a confirmed RPC inventory,
and the datadir layout the proxy will target.

---

## 2. Test topology

Single local node: **Mutinynet-patched Bitcoin Core v25.99.0-gf036909dbe28**
running as a `daemon=1` pruned signet node on macOS arm64. Sync source is the
single Mutinynet team peer at `45.79.52.207:38333`; DNS seeding is disabled
(`dnsseed=0`) because Mutinynet has no DNS seeders.

We deliberately chose a locally self-hosted node over a remote RPC endpoint
(e.g. a hosted Bitcoin node service). The privacy proxy's entire purpose is to
sit between an AI client and the daemon - that requires the proxy to run on the
same host (or LAN) as `bitcoind`. A remote `bitcoind` would move the trust
boundary to a third party and defeat the point.

---

## 3. Prerequisites

- macOS Apple Silicon (arm64). No Linux or x86-64 equivalent was tested in this
  run; adjust tarball URL for other platforms.
- ~3 GB free disk space (prune cap is 2.2 GB; overhead for signet metadata and
  wallets adds ~100 MB).
- No Homebrew, no system installs, no `go`, no `rust`, no package manager
  dependencies required. The shipped tarball is statically linked against only
  `libSystem` and `libc++` (both macOS built-ins).
- No per-user accounts needed (unlike the Voltage signup required in the LND
  flow).

---

## 4. Layout under `~/spacer/`

```
~/spacer/
├── bin/
│   ├── bitcoind          # Mutinynet-patched Bitcoin Core v25.99.0-gf036909dbe28
│   ├── bitcoin-cli       # RPC client
│   ├── bitcoin-tx        # offline tx construction (no daemon needed)
│   ├── bitcoin-wallet    # offline wallet ops (no daemon needed)
│   ├── lncli             # (LND flow - see companion doc)
│   ├── uv
│   └── uvx
├── bitcoin/              # bitcoind datadir
│   ├── bitcoin.conf      # chmod 600
│   ├── rpcauth.txt       # password copy, chmod 600
│   └── signet/           # all chain data lives here (signet-only tree)
│       ├── bitcoind.pid
│       ├── blocks/
│       ├── chainstate/
│       ├── debug.log
│       ├── peers.dat
│       └── wallets/
│           └── spacer-smoke/   # test wallet (created during smoke-test)
├── downloads/
│   └── mutinynet/
│       ├── bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz   # source tarball
│       ├── bitcoin-f036909dbe28/                            # extracted tree
│       ├── SHA256SUMS-covtools                              # checksum file
│       └── SHA256SUMS.asc                                   # GPG sig
└── scripts/
    ├── btccli            # bitcoin-cli wrapper (pre-fills --datadir)
    └── lncliA            # (LND flow - see companion doc)
```

---

## 5. Setup steps

### 5.1 Pick the right release

Go to `https://github.com/benthecarman/bitcoin/releases`.

The **latest** Mutinynet tag at time of setup was `mutinynet-inq-29`
("Mutinynet v29.0"). On macOS arm64 that release uploaded only
`arm64-apple-darwin-unsigned.zip`, which unpacks to a `Bitcoin-Qt.app` GUI
bundle only - no `bitcoind` or `bitcoin-cli` CLI binaries. The corresponding
`arm64-apple-darwin-unsigned.tar.gz` is listed in that release's `SHA256SUMS`
but returns 404 (never uploaded).

Use the **`mutinynet-covtools`** tag instead. It ships
`bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz` with full CLI binaries and
carries the same Mutinynet patches (`signetchallenge`, `signetblocktime` config
parsing):

```
Release : mutinynet-covtools
Version : Bitcoin Core v25.99.0-gf036909dbe288ee5b7f2c38564a3c5375255822f
Asset   : bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz
SHA256  : 8b112e676ed8e32d4a291a3c8b78d1a725be37e30bf048a637a17eb41820ee8b
```

### 5.2 Download and verify

```bash
mkdir -p ~/spacer/test-harness/downloads/mutinynet
cd ~/spacer/test-harness/downloads/mutinynet

TARBALL=bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz
curl -fSL \
  "https://github.com/benthecarman/bitcoin/releases/download/mutinynet-covtools/${TARBALL}" \
  -o "${TARBALL}"

# Download the SHA256SUMS file for this release and verify
curl -fSL \
  "https://github.com/benthecarman/bitcoin/releases/download/mutinynet-covtools/SHA256SUMS" \
  -o SHA256SUMS-covtools

grep "${TARBALL}" SHA256SUMS-covtools | shasum -a 256 -c -
# Expected: bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz: OK
```

### 5.3 Extract and copy binaries

```bash
cd ~/spacer/test-harness/downloads/mutinynet
tar -xzf bitcoin-f036909dbe28-arm64-apple-darwin.tar.gz

mkdir -p ~/spacer/arbiter/bin

# Copy the four CLI binaries (skip bitcoin-qt, bitcoin-util, test_bitcoin)
cp bitcoin-f036909dbe28/bin/bitcoind      ~/spacer/arbiter/bin/
cp bitcoin-f036909dbe28/bin/bitcoin-cli   ~/spacer/arbiter/bin/
cp bitcoin-f036909dbe28/bin/bitcoin-tx    ~/spacer/arbiter/bin/
cp bitcoin-f036909dbe28/bin/bitcoin-wallet ~/spacer/arbiter/bin/
```

### 5.4 Fix macOS Gatekeeper

The tarball ships binaries that are ad-hoc / linker-signed only. macOS 15.x
(Sequoia-era) `spctl` rejects them with "invalid signature (code or signature
have been modified)" and kills `bitcoind` at launch with SIGKILL (exit 137),
producing no output. Strip the quarantine attribute and apply a fresh ad-hoc
signature to each binary:

```bash
for bin in bitcoind bitcoin-cli bitcoin-tx bitcoin-wallet; do
  xattr -cr ~/spacer/arbiter/bin/${bin}
  codesign --force --sign - ~/spacer/arbiter/bin/${bin}
done
chmod +x ~/spacer/arbiter/bin/bitcoind ~/spacer/arbiter/bin/bitcoin-cli \
         ~/spacer/arbiter/bin/bitcoin-tx ~/spacer/arbiter/bin/bitcoin-wallet
```

Verify: `~/spacer/arbiter/bin/bitcoind --version` should print
`Bitcoin Core version v25.99.0-gf036909dbe28...` without error.

### 5.5 Create the datadir

```bash
mkdir -p ~/spacer/arbiter/bitcoin
```

### 5.6 Write bitcoin.conf

Save the following to `~/spacer/arbiter/bitcoin/bitcoin.conf` and restrict permissions:

```ini
# bitcoin.conf - Mutinynet (signet variant) - for the spacer privacy-proxy project.
# Datadir: ~/spacer/arbiter/bitcoin/
# Generated 2026-05-02. Do NOT enable mainnet from this config.

# --- chain selection: signet ONLY (Mutinynet is a custom signet) ---
chain=signet

# --- daemonize and run RPC server (these are global) ---
daemon=1
server=1

# --- pruning: keep on-disk size modest, no txindex ---
prune=2200
txindex=0

# --- diagnostics ---
debug=net
debug=mempool

[signet]
# Mutinynet's hardcoded signetchallenge from the Mutiny faucet docs.
signetchallenge=512102f7561d208dd9ae99bf497273e16f389bdbd6c4742ddb8e6b216e64fa2928ad8f51ae
# Mutinynet seed node (see https://faucet.mutinynet.com/)
addnode=45.79.52.207:38333
# Don't query DNS seeds - Mutinynet has no DNS seeders, only the addnode above.
dnsseed=0
# Mutinynet's custom 30-second block time (this flag requires benthecarman's fork).
signetblocktime=30

# RPC bind/auth (network-section-only knobs).
rpcbind=127.0.0.1
rpcallowip=127.0.0.1
rpcport=38332
rpcuser=spacer
rpcpassword=c_FCI8alPRy2MvGVnIw3T5MD3OjPeI3E8tdkltFKDaA
```

```bash
chmod 600 ~/spacer/arbiter/bitcoin/bitcoin.conf
# Also store the password separately for reference
echo "c_FCI8alPRy2MvGVnIw3T5MD3OjPeI3E8tdkltFKDaA" > ~/spacer/arbiter/bitcoin/rpcauth.txt
chmod 600 ~/spacer/arbiter/bitcoin/rpcauth.txt
```

Config notes:
- `chain=signet` is at the top level - no way to accidentally connect to
  mainnet from this config.
- `prune=2200`, `daemon=1`, `server=1`, and `txindex=0` are global (above
  `[signet]`); placing them inside `[signet]` causes an error.
- All signet-specific knobs (`rpcbind`, `rpcport`, `addnode`, `signetchallenge`,
  `signetblocktime`, `dnsseed`) must live inside the `[signet]` section, or
  Bitcoin Core logs "Config setting for X only applied on signet network when in
  [signet] section." and ignores them.
- RPC port `38332` is Bitcoin Core's signet default (distinct from testnet
  `18332` and mainnet `8332`).

### 5.7 Start bitcoind

```bash
~/spacer/arbiter/bin/bitcoind -datadir="$HOME/spacer/arbiter/bitcoin"
# daemonizes immediately; PID written to ~/spacer/arbiter/bitcoin/signet/bitcoind.pid
```

Confirm it is syncing:

```bash
~/spacer/arbiter/bin/bitcoin-cli -datadir="$HOME/spacer/arbiter/bitcoin" getblockchaininfo
```

Expected output includes `"chain": "signet"`, `"initialblockdownload": true`,
and `"headers"` rising toward ~3.07M.

To stop and restart:

```bash
~/spacer/test-harness/scripts/btccli stop                        # graceful shutdown
~/spacer/arbiter/bin/bitcoind -datadir="$HOME/spacer/arbiter/bitcoin"  # start again
```

### 5.8 Write the btccli wrapper

```bash
cat > ~/spacer/test-harness/scripts/btccli <<'EOF'
#!/bin/sh
# Convenience wrapper around bitcoin-cli that pre-fills -datadir.
# Usage: btccli getblockchaininfo, btccli -named sendtoaddress address=... amount=...
exec ~/spacer/arbiter/bin/bitcoin-cli -datadir="$HOME/spacer/arbiter/bitcoin" "$@"
EOF
chmod +x ~/spacer/test-harness/scripts/btccli
```

All subsequent examples use `btccli` for brevity. Wallet-scoped calls add
`-rpcwallet=spacer-smoke`.

---

## 6. RPCs exercised during smoke-test

The following were called against the live node during initial bring-up and
smoke-testing. Privacy implications are in the sibling doc
(`2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`); this section just
confirms each call worked and what it returned.

**Chain info**

| RPC | What it returned |
|-----|-----------------|
| `getblockchaininfo` | chain=signet, headers≈1.07M, blocks≈8.6k, IBD=true, pruned=false (prune active but not triggered yet), on-disk≈3.3 MB |
| `getbestblockhash` | hash of the current tip block |
| `getblockcount` | current tip height |
| `getdifficulty` | current signet difficulty |
| `getchaintips` | single active chain entry |
| `getchaintxstats` | aggregate tx counts over last N blocks |
| `getblockhash N` | block hash at height N |
| `getblock <hash>` | full block JSON |
| `getblockheader <hash>` | block header JSON |
| `getblockstats <hash>` | per-block fee/size stats |

**Mempool**

| RPC | What it returned |
|-----|-----------------|
| `getmempoolinfo` | size, bytes, fee floor - local view only |
| `getrawmempool` | txids in mempool |
| `getrawmempool true` | verbose mempool with fee/size per tx |

**Network**

| RPC | What it returned |
|-----|-----------------|
| `getnetworkinfo` | local services, reachability per transport, proxy settings, relayfee |
| `getpeerinfo` | one entry: the `45.79.52.207:38333` Mutinynet peer |
| `getconnectioncount` | 1 |
| `uptime` | seconds since start |
| `getnodeaddresses 5` | 5 gossip-discovered peer addresses |
| `getmininginfo` | chain, difficulty, networkHashPs |
| `getindexinfo` | empty (txindex=0) |

**UTXO / tx**

| RPC | What it returned |
|-----|-----------------|
| `gettxout <txid> <n>` | UTXO info for an in-chain output |
| `getrawtransaction <txid> 1` | decoded tx (mempool or wallet-seen) |
| `decoderawtransaction <hex>` | decode a raw tx hex without broadcast |
| `scantxoutset start '[{"desc":"..."}]'` | UTXO set scan for a descriptor |

**Wallet** (all with `-rpcwallet=spacer-smoke`)

| RPC | What it returned |
|-----|-----------------|
| `listwallets` | `[]` before createwallet; `["spacer-smoke"]` after |
| `createwallet spacer-smoke` | created descriptor wallet, no passphrase |
| `getwalletinfo` | walletname, balance=0, txcount=0, keypoolsize=4000 |
| `getbalances` | mine.trusted=0, untrusted_pending=0 |
| `getnewaddress` | a fresh bech32 receive address |
| `getaddressinfo <addr>` | full derivation path, pubkey, descriptor, xpub |
| `listdescriptors` | all active BIP44/49/84/86 receive + change descriptors |
| `listlabels` | `[""]` (default label only) |

---

## 7. Pending: on-chain send/receive flow

Full sync was still in progress at handoff (~8.6k of ~3.07M blocks). The
intended on-chain flow - analogous to steps 2-4 in the LND test doc - requires
the node to be past the funding block before UTXOs become visible.

Checklist for completing this flow once sync catches up:

- [x] `btccli -rpcwallet=spacer-smoke createwallet spacer-smoke` - done during smoke-test
- [x] `btccli -rpcwallet=spacer-smoke getnewaddress` - done; address noted
- [ ] Paste address into `https://faucet.mutinynet.com`, request sats (requires
      GitHub OAuth; use the same account as the LND run if already authenticated)
- [ ] Wait for sync to pass the funding block height; then check:
      `btccli -rpcwallet=spacer-smoke getbalances`
- [ ] Send 5000 sats back to the faucet return address:
      ```bash
      btccli -rpcwallet=spacer-smoke sendtoaddress \
        <faucet-return-address> 0.00005
      ```
- [ ] Verify:
      ```bash
      btccli -rpcwallet=spacer-smoke gettransaction <txid>
      ```

Sync ETA from setup time: a few hours (observed ~1500 blocks/s at IBD start on
the 330-byte Mutinynet blocks; Mutinynet chain tip is ~3.07M blocks).

---

## 8. Auxiliary tooling

The `mutinynet-covtools` tarball includes two binaries beyond `bitcoind` and
`bitcoin-cli` that are useful for the privacy proxy project:

- **`bitcoin-tx`** - offline transaction construction and signing. Can decode,
  modify, and sign raw transactions without a running daemon. Useful for testing
  the proxy's tx-handling paths without requiring a live node.

- **`bitcoin-wallet`** - offline wallet operations (create, dump, inspect wallet
  files). Can be used to inspect the `spacer-smoke` wallet file at
  `~/spacer/arbiter/bitcoin/signet/wallets/spacer-smoke/` without starting `bitcoind`.

Neither binary requires a running `bitcoind` or any RPC connection, which makes
them straightforward to allow through the privacy proxy without special handling.

---

## 9. Limitations and gotchas

- **`mutinynet-inq-29` ships GUI-only on macOS.** The v29.0 release omits the
  CLI tarball for arm64-apple-darwin. Always use `mutinynet-covtools` for CLI
  work until the upstream issue is resolved.

- **Gatekeeper SIGKILLs unsigned binaries silently.** `bitcoind` exits 137
  with no output. `xattr -cr` + `codesign --force --sign -` is the fix;
  this must be done before the first run, not after a failed launch.

- **Initial sync takes hours even with pruning.** `prune=2200` caps on-disk
  storage but does not speed up IBD. Any test that requires UTXO state (wallet
  balance, `scantxoutset`, `listunspent`) must wait for the chain tip or use a
  snapshot. Plan around this.

- **Single peer is a single point of failure.** Only one `addnode` entry
  (`45.79.52.207:38333`) is configured; `dnsseed=0` means no fallback peer
  discovery. If that peer is offline, IBD stalls.

- **`signetblocktime=30` requires the benthecarman fork.** Stock Bitcoin Core
  does not accept this config knob. The `mutinynet-covtools` binary includes the
  patch; a vanilla Core build will ignore it and may produce parse errors.

- **Wallet not auto-loaded on startup.** `listwallets` returns `[]` until you
  call `loadwallet spacer-smoke` or `createwallet`. This is consistent with
  Bitcoin Core's default behavior since v21 and is actually useful: wallet
  attachment can serve as a deliberate boundary in the proxy design.

---

## 10. What's reproducible vs not

| Item | Reproducible? |
|------|--------------|
| Binary download + Gatekeeper fix | Yes - fully scriptable |
| `bitcoin.conf` with Mutinynet params | Yes - no per-user values except rpcpassword (generate fresh) |
| `rpcpassword` in conf | Replace with a fresh random string; the one above is in version control |
| Starting `bitcoind` + `btccli` wrapper | Yes - no accounts needed |
| Wallet creation (`spacer-smoke`) | Yes - deterministic given the same seed phrase |
| Faucet funding | Requires GitHub OAuth; no API key needed for `POST /bolt11` but on-chain requires browser |
| Addresses / txids | No - new run produces new values |
| Sync time | Approximate; depends on peer throughput and Mutinynet tip height at run time |

Everything through step 5.8 is scriptable with no interactive steps. The only
manual step in the pending on-chain flow (§7) is the browser-based faucet
funding.

---

## 11. Pointers

- **LND test flow** (the companion run that completed the full Lightning
  lifecycle): `2026-05-02-1600-lnd-mutinynet-test-flow.md`
- **LND privacy + timing leaks** (per-API leak map for `lncli` calls):
  `2026-05-02-1601-privacy-and-timing-leaks.md`
- **bitcoind privacy + timing leaks** (RPC leak map for `bitcoin-cli` calls):
  `2026-05-02-1603-bitcoind-privacy-and-timing-leaks.md`
- **benthecarman/bitcoin releases:** `https://github.com/benthecarman/bitcoin/releases`
- **Mutinynet faucet + esplora:** `https://faucet.mutinynet.com` / `https://mutinynet.com`
- **Bitcoin Core RPC reference:** `https://developer.bitcoin.org/reference/rpc/`
