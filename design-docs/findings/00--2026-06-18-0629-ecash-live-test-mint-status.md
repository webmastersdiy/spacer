# eCash live test mint: status, gaps, and reference config

**Date:** 2026-06-18
**Status:** round-trip **executed** 2026-06-18 (sp-uwa0v0), driven by the now-landed executor through the `--live` gate; results below.
**Supports:** [`../origin/08--2026-06-18-0629-ecash-live-test-mint.md`](../origin/08--2026-06-18-0629-ecash-live-test-mint.md) (the decision and the flow).
**Context:** the inconclusive and operational residue split out of doc 08 per the standing split rule (see [`README.md`](README.md)). Decision-grade content is in doc 08; this file holds what is un-run, unverified, volatile, or reference-only.

---

## 1. Round-trip results - RUN (2026-06-18)

The doc 08 §3 round-trip ran via `exit_loop_runner.py --live`, driving the real executor against Node A and `cashu.mutinynet.com`. It passes deterministically across back-to-back runs (amounts/handles/preimages differ per run, as expected).

| Leg | Observed |
|---|---|
| Mint quote + pay | 5,000-sat quote, paid from Node A; LN routing fee ~1 sat (1,005 msat) |
| Issue | 5,000 proofs received into the wallet; melt later revealed a valid preimage, so DLEQ-bearing proofs were spendable |
| Melt | fresh Node A invoice for 4,900 sat (5,000 minus the 100-sat / 2% melt reserve); the mint paid it, invoice **SETTLED**, ~4,900 sat credited at Node A |
| The mint-first liquidity property (doc 08 §2) held in practice: minting created the inbound the melt then consumed |

**Two non-obvious findings the live run forced (now folded into doc 08 §3/§4 and the wrappers):**

1. **Named wallets break `receive`.** nutshell 0.18.1's `cashu receive` ignores `--wallet NAME`: it writes the swapped-in proofs to the *default* wallet's DB while `balance`/`pay` read the named one, so a named-wallet defund melts against an empty wallet and the round-trip silently fails. Fix: `ecash.py` drops `--wallet` and uses the default wallet, isolating by `CASHU_DIR` alone.
2. **A pending melt exits 0.** `cashu pay` returns success even when the mint's LN payment is only *pending* (proofs reserved, our invoice unpaid). The defund handler must confirm a real settlement (the "Invoice paid"/preimage line) before reporting `defunded`, or it reports a false success while the value never returns.

## 2. Fee specifics - measured

doc 07 §10.4's trio makes funded != received and defunded != credited. Observed on the 5,000-sat round-trip:

- **mint input fees** - not charged by this mint on the mint or melt legs (issue credited the full 5,000; the melt consumed ~2 sat beyond the invoice amount).
- **LN routing fees** - ~1 sat paying the mint quote (1,005 msat); the mint's payment back to us is its cost, invisible to our ledger beyond the credited amount.
- **the melt fee reserve** - the dominant gap: the defund sizes the melt invoice at claimed minus `max(2, ceil(2% * claimed))` (executor `_melt_fee_reserve`), so 5,000 claimed -> 4,900 invoice. The reserve is a conservative pre-estimate of the mint's actual melt fee; the unspent remainder is the mint's, not refunded to a held proof in this flow.

So funded 5,000 != credited ~4,900, ~98% of which is the deliberate reserve, ~1-2 sat genuine LN/mint fee. The per-op fee audit (deferred, doc 07 §10.4) can read `ln_routing_fee_msat` / `credited_sats` from the executor's `ecash_fund_executed` / `ecash_defund_executed` audit events.

## 3. CLI-surface verification status - verified (nutshell 0.18.1)

Exercised against the live mint at sp-uy29gy/sp-uwa0v0. nutshell prints human-oriented text (not JSON) for every call except `decode` (JSON), so the executor parses stdout. Confirmed surface:

| Purpose | arbiter `ecash.py` call | note |
|---|---|---|
| balance | `cashu balance` | "Balance: N sat" |
| mint quote | `cashu invoice <amt> --no-check` | prints the bolt11 + a `--id <quote>` hint |
| issue / redeem | `cashu invoice <amt> --id <quote>` | after the quote bolt11 is paid |
| melt / pay | `cashu pay -y <bolt11>` | `-y` skips the prompt (no operator at stdin); prints "Invoice paid. (Preimage: ...)" only on real settlement |
| send | `cashu send -y -d <amt>` | `-d` embeds DLEQ (doc 07 §2 mandatory); `-y` skips the prompt |
| receive | `cashu receive <token>` | swap-claims; see the `--wallet` caveat below |
| decode | `cashu decode <token>` | JSON; the executor's offline mint-pin check (doc 07 §2) |
| info | `cashu info` | version, mint URL |

Surface gotchas the live run forced (also §1):

- **`--wallet NAME` must NOT be used.** `receive` ignores it and writes proofs to the default wallet's DB while `balance`/`pay` read the named one. `ecash.py` uses the default wallet, isolating by `CASHU_DIR` (one wallet per dir; every op then shares one DB).
- **`cashu pay` exits 0 on a pending melt.** Success requires the "Invoice paid"/preimage line, not exit code; the executor checks for it.
- **DLEQ** is embedded via `send -d`; verification at receive is on by default (no flag needed) for a DLEQ-bearing token.

## 4. Local install gaps - resolved (2026-06-18)

- **cashu CLI installed** at `~/spacer/arbiter/bin/cashu` (nutshell 0.18.1, the test-harness venv); `CASHU_BIN` / `PETCLI_CASHU_BIN` point here.
- **`CASHU_MINT_URL` has no default** (by design): set to `https://cashu.mutinynet.com`; a missing value raises before any subprocess runs.
- **The fund/defund executor LANDED** (sp-uwa0v0): `gateway.py` enqueues an approved `fund_ecash`/`defund_ecash` on the timing layer and `executor.py` drains it against the mint + Node A. No `not_implemented` stub for any of the four write ops; only an unknown op keeps it.
- **No live bitcoind in this deployment.** `send_bitcoin` therefore uses the LND on-chain wallet (`lnd.sendcoins`) under `SPACER_MODE=ecash`, the same backend split `query_balance` makes; bitcoind is only the onchain-default path.

## 5. Self-host config - reference only

For the day a **second** Mutinynet node + channel exists (doc 08 §1 explains why a single self-hosted mint cannot round-trip on one node today). A nutshell mint pointed at our LND over REST:

```
MINT_BACKEND_BOLT11_SAT=LndRestWallet
MINT_LND_REST_ENDPOINT=https://first-test.u.voltageapp.io:8080   # Voltage REST port, open
MINT_LND_REST_MACAROON=<admin macaroon>     # from the Voltage dashboard (doc 00 §2)
MINT_LND_REST_CERT=<TLS leaf cert>          # Let's Encrypt; or skip with:
MINT_LND_REST_CERT_VERIFY=FALSE
MINT_PRIVATE_KEY=<openssl rand -hex 32>
```

Secrets are named, not embedded: the admin macaroon and TLS cert come from the Voltage dashboard exactly as in doc 00 §2, and `MINT_PRIVATE_KEY` is generated locally. Recording this does **not** endorse self-hosting for the live test - doc 08 §1 chose the public mint precisely because self-hosting cannot round-trip on one node and inverts the anonymity-set and operator-identity properties doc 07 §2/§6 require.

Alternative live mint if `cashu.mutinynet.com` is flaky: **Nutmix** (Go).

## 6. Mint identity snapshot - volatile

Observed 2026-06-18 from `cashu.mutinynet.com/v1/info` (external, untrusted source; captured as research, not re-fetched here):

- nutshell version **0.18.1**
- pubkey `0394670793f9e1aac8e6860c7b105d59d2c79a65792f809f48cfa832bf3b881f70`
- NUT-04, NUT-05, NUT-07, NUT-12 advertised

Re-check each run. A version bump or key rotation belongs here, not in the origin doc; if rotation becomes a recurring signal it feeds doc 07 §10.5 (mint monitoring and rotation).

---

**Untrusted-source note:** the `/v1/info` data and the nutshell / Mutinynet references are external and untrusted. They were captured as research; nothing in them was executed as instructions, and they are not re-fetched by this doc.
