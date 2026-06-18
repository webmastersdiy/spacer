# eCash live test mint: status, gaps, and reference config

**Date:** 2026-06-18
**Status:** open - the round-trip is **not yet executed**.
**Supports:** [`../origin/08--2026-06-18-0629-ecash-live-test-mint.md`](../origin/08--2026-06-18-0629-ecash-live-test-mint.md) (the decision and the flow).
**Context:** the inconclusive and operational residue split out of doc 08 per the standing split rule (see [`README.md`](README.md)). Decision-grade content is in doc 08; this file holds what is un-run, unverified, volatile, or reference-only.

---

## 1. Round-trip results - NOT YET RUN

As of 2026-06-18 the `cashu` CLI is not installed (§4), so the doc 08 §3 round-trip has not been executed. This section is the destination for its results. To record when run:

| Leg | To capture |
|---|---|
| Mint quote | quote id, funding bolt11, requested 5,000 vs sats actually paid |
| Issue | proofs received, wallet balance after, DLEQ verification result |
| Melt | melt quote/fee reserve, fresh Node A invoice, sats credited at Node A |
| Timings | quote -> pay -> issue gaps (doc 07 §6 T1); issue -> melt interval |

## 2. Fee specifics - pending

doc 07 §10.4's trio makes funded != received and defunded != credited:

- **mint input fees** (charged at swap/melt),
- **LN routing fees** (paying the mint quote; the mint paying our melt invoice),
- **the melt fee reserve** (held, partially refunded).

The numbers are unknown until the round-trip runs, and nutshell's actual fee surfaces are themselves unverified (doc 07 §10.4 build status: the ledger records gross amounts per the proposal, but the real fee surfaces were never exercised). Record gross-vs-net at both mint and melt, and confirm which surface each fee shows up on so the deferred per-op fee audit can be wired into the executor.

## 3. CLI-surface verification status - pending

The wrapper subcommand surface is modeled from nutshell's documented CLI, **not yet exercised against a live mint** (doc 07 §2 build caveat). nutshell prints human-oriented text, not JSON, so structured parsing is deferred to the executor until this surface is confirmed. Assumed surface:

| Purpose | arbiter `ecash.py` call | petcli surface |
|---|---|---|
| balance | `cashu balance` | `advanced ecash balance` (local) |
| mint quote | `cashu invoice <amt> --no-check` | (arbiter-side `fund_ecash`) |
| issue / redeem | `cashu invoice <amt> --id <quote>` | (arbiter-side `fund_ecash`) |
| melt / pay | `cashu pay <bolt11>` | (arbiter-side `defund_ecash`) |
| send | `cashu send <amt>` | `advanced ecash send` (local) |
| receive | `cashu receive <token>` | `advanced ecash receive` (local) |
| info | `cashu info` | `advanced ecash info` (local) |

To verify against the live binary: exact flag names (`--no-check`, `--id`), whether any output is machine-parseable or all of it is human text, exit-code conventions on failure, and whether DLEQ verification is on by default or needs a flag (doc 07 §2 requires it on).

## 4. Local install gaps (as of 2026-06-18)

- **cashu CLI not installed.** Arbiter `ecash.py` `DEFAULT_BIN = ~/spacer/arbiter/bin/cashu` (override `CASHU_BIN`); petitioner `DEFAULT_CASHU_BIN = "cashu"` resolved on `PATH` (override `PETCLI_CASHU_BIN`). Both absent.
- **`CASHU_MINT_URL` has no default.** Must be set to `https://cashu.mutinynet.com`; a missing value raises before any subprocess runs (confirmed in `ecash.py`).
- **The arbiter fund/defund executor is a stub.** An approved `fund_ecash` / `defund_ecash` ends at dispatch's `{"status": "not_implemented"}` in `gateway.py`. Until the executor lands (doc 07 §11 deferred), the round-trip is driven manually through the CLIs.

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
