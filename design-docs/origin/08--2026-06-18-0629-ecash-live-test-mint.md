# eCash live test mint: selection and Lightning round-trip flow

**Date:** 2026-06-18
**Status:** mint selected, round-trip designed; the live round-trip is **not yet executed** (the `cashu` CLI is not installed yet). Results, fees, and CLI-surface verification are tracked in the findings companion and reconciled back here when the round-trip runs, per the repo's reconciled tradition.
**Context:** This is the live-mint doc that `07--2026-06-12-0916-ecash-extension.md` §2 and §9 promised would be "documented as its own NN doc when stood up" (the work tracked as sp-2hwco4.4). It records which [mint](../../GLOSSARY.md#mint) the operator-pinned `CASHU_MINT_URL` should point at for the test environment and the Lightning round-trip - mint -> hold -> melt - that exercises `fund_ecash` / `defund_ecash` against a real mint. The inconclusive and operational residue (un-run results, fee specifics, CLI-surface verification, local install gaps, reference-only self-host config) is split into the findings companion so this design record stays clean.
**Companion:** [`../findings/00--2026-06-18-0629-ecash-live-test-mint-status.md`](../findings/00--2026-06-18-0629-ecash-live-test-mint-status.md) (results + gaps + reference config).
**Related:**
- `07--2026-06-12-0916-ecash-extension.md` - the extension this validates (the custody split, the mint threat model, the deferred executor).
- `00--2026-05-02-1600-lnd-mutinynet-test-flow.md` - the LND test flow this builds on: same [Node A](../../GLOSSARY.md#node-a), same [faucet](../../GLOSSARY.md#faucet-mutinynet-faucet), same [lncliA](../../GLOSSARY.md#lnclia) wrapper.

---

## 1. Decision: the mint

**Pin the test deployment to the public Mutinynet [Cashu](../../GLOSSARY.md#chaumian-ecash-cashu) mint at `https://cashu.mutinynet.com`.** It is a nutshell mint whose `/v1/info` (observed 2026-06-18 - external, untrusted source, captured as research) advertises the exact NUT set the extension requires:

- **NUT-04** (mint / issuance) and **NUT-05** (melt) - the funding and defunding legs.
- **NUT-07** (proof state / checkstate) - the AI's direct proof-state queries (doc 07 §5.1).
- **NUT-12** (DLEQ) - **mandatory** per doc 07 §2; a mint that does not support DLEQ cannot be used, because DLEQ verification is what stops a malicious mint from tagging tokens with a per-client key.

Mint identity pubkey `0394670793f9e1aac8e6860c7b105d59d2c79a65792f809f48cfa832bf3b881f70`. (The exact nutshell version is volatile and lives in the findings companion.)

**Why this mint** maps directly onto doc 07 §2's "mint selection guidance: a busy, public, operator-unaffiliated mint":

- **Busy, public, unaffiliated** - its other users are our anonymity crowd. This is the property doc 07 §6 T6 turns on: the anonymity set for every mint-correlation channel is the other traffic in the same keyset epoch, so a quiet or self-run mint shrinks it toward one.
- **Same network as our node** - it runs on [Mutinynet](../../GLOSSARY.md#mutinynet) signet, the same chain as our [Voltage](../../GLOSSARY.md#voltage)-hosted LND Node A. So our LND can pay its mint-quote [bolt11](../../GLOSSARY.md#bolt11) invoices and it can melt back to a fresh invoice from our node - a real LN round-trip, not a simulation.

**Why not self-host (the caveat that drove the choice).** A single self-hosted nutshell mint backed by our **one** node cannot do a real LN round-trip: the mint paying our melt invoice would be our node paying itself, which Lightning does not route. A genuine round-trip needs a second Mutinynet node and a channel. Self-hosting also inverts both privacy properties doc 07 §2 requires - the mint URL (visible to the AI inside every token) would name the operator, and the anonymity set at the mint would collapse to our own traffic (doc 07 §6). The detailed self-host config is kept reference-only in the findings companion for the day a second node exists.

**Fallback.** If `cashu.mutinynet.com` is flaky, **Nutmix** (a Go mint) is another live Mutinynet mint; the same selection logic applies (busy, public, unaffiliated, NUT-12).

## 2. Topology and the liquidity constraint

- **Our side:** Node A (Voltage-hosted LND, Mutinynet) - the same node as doc 00. Console LN calls go through the lncliA wrapper; the admin macaroon and TLS cert are obtained as in doc 00 §2.
- **Counterparty:** the mint's own LND node. We never peer with it directly; the public LN network routes between us.

The constraint that **shapes the flow** is our channel liquidity. Our only channel is to the faucet, ~49,056 sat outbound / **0 inbound** at time of writing. Therefore:

- **Minting (we pay the mint's quote invoice)** pushes our balance toward the faucet - i.e. it *creates inbound* we did not have.
- **Melting (the mint pays our invoice)** is routable back, up to the amount we minted.
- So the first round-trip must be **small and mint-first**: mint 5,000 -> hold -> melt 5,000. Minting before melting is not just convention here; it is forced by the zero starting inbound.

(Reproducibility: the balance figures are the 2026-06-18 state and drift with every channel operation - see doc 00 §7. The 5,000-sat size is a deliberately small first probe, not a fixed parameter.)

## 3. The round-trip test flow

1. **Install the cashu CLI.** The arbiter wrapper (`arbiter/src/ecash.py`) shells to a `cashu` binary at `~/spacer/arbiter/bin/cashu` by default (override `CASHU_BIN`); the petitioner side resolves `cashu` on `PATH` (override `PETCLI_CASHU_BIN`). Neither is installed yet (findings companion §4).
2. **Point the wallet at the mint.** Set `CASHU_MINT_URL=https://cashu.mutinynet.com`. It has **no default** and a missing value raises before any subprocess runs (doc 07 §2; confirmed in `ecash.py`).
3. **Mint 5,000.** Request a mint quote for 5,000 sat (the wrapper's `mint_quote`, i.e. `cashu invoice 5000 --no-check`); pay the returned bolt11 from Node A via `lncliA payinvoice`; redeem the quote to receive proofs (the wrapper's issue call, i.e. `cashu invoice 5000 --id <quote>`).
4. **Verify.** Confirm the wallet balance is 5,000 (net of fees, step 6) and that **DLEQ verification passes** - NUT-12 is mandatory (doc 07 §2); a wallet that does not verify DLEQ is the failure doc 07 §2 calls out.
5. **Melt 5,000.** Generate a fresh bolt11 from Node A (`lncliA addinvoice`), then melt the proofs to it (the wrapper's `pay`, i.e. `cashu pay <bolt11>`); the mint pays our invoice; confirm the sats arrive at Node A.
6. **Record fees.** funded != received and defunded != credited: mint input fees, LN routing fees, and the melt fee reserve all apply (doc 07 §10.4). The exact figures are the round-trip's primary finding (findings companion §2).
7. **Verify the CLI surface.** Check nutshell's real subcommands against the assumptions baked into `ecash.py` and petcli (`invoice --no-check` / `invoice --id`, `send`, `receive`, `pay`, `balance`, `info`). doc 07 §2's build caveat is explicit that this surface is modeled from nutshell's docs, not yet exercised, and that nutshell prints human-oriented text rather than JSON. Differences feed back into the wrapper and the deferred executor (findings companion §3).

## 4. What the round-trip unblocks

The flow is the manual dress rehearsal for the pieces doc 07 §11 left deferred:

- **the fund/defund executor** - an approved `fund_ecash` / `defund_ecash` currently ends at the `not_implemented` dispatch stub in `gateway.py`; the round-trip is the executor's reference behavior;
- **the nutshell CLI surface** assumed by `ecash.py` (doc 07 §2 build caveat);
- **the fee surfaces** the per-op fee audit needs (doc 07 §10.4);
- **the mint-leg micro-timing** (doc 07 §6 T1, landed as `timing.mint_gap_s()`) - observable for the first time against real mint latency.

It does **not** change the threat model or the custody split (doc 07 §3-§5). The mint is in mitigation scope (doc 07 §1: the no-internal-mitigations rule covers the arbiter <-> local bitcoind / LND link only, not this external counterparty), so the mint-facing channels are exactly what this round-trip lets us measure rather than assume.

## 5. Reproducible vs not

The §3 sequence is scriptable once the cashu CLI is installed and `CASHU_MINT_URL` is set; the only external dependency is the public mint's availability (Nutmix fallback, §1). Amounts, quote ids, and preimages differ every run; channel balances are point-in-time. The mint version, pubkey, and any key rotation are recorded in the findings companion §6 and re-checked each run.

**Pointers:** extension design `07--2026-06-12-0916-ecash-extension.md`; LND flow and Node A identity `00--2026-05-02-1600-lnd-mutinynet-test-flow.md`; results + gaps `../findings/00--2026-06-18-0629-ecash-live-test-mint-status.md`. External (untrusted) sources, captured as research and not re-fetched here: `cashu.mutinynet.com/v1/info`, `github.com/cashubtc/nutshell`, `github.com/MutinyWallet/mutiny-net`.
