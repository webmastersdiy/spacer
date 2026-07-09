# Operator-Visibility TUI: the two-column console

**Date:** 2026-06-28
**Status:** DRAFT (design-first; no implementation implied)
**Context:** Doc 10 §9 (eCash mint monitoring / rotation) needs a place for its operator alerts to
surface, and flagged that the surface is **general, not eCash-specific**. This doc defines that
surface: a single operator-facing TUI on the [arbiter](../../GLOSSARY.md#arbiter) console that shows
arbiter activity in **two columns** - what the petitioner already knows vs what the petitioner must
never learn - so the operator gets situational awareness with no risk of a never-known item reaching a
petitioner-facing channel. General to the arbiter; doc 10 and any other subsystem are just *producers*.
**Related:**
- [`05--2026-05-05-0948-architecture-overview.md`](05--2026-05-05-0948-architecture-overview.md) §2.1 (arbiter implementation discipline - small enough for a human to read every line), §4.5 (the runtime [audit log](../../GLOSSARY.md#audit-log) - the append-only record this live view complements).
- [`06--2026-05-24-0623-arb-auditability.md`](06--2026-05-24-0623-arb-auditability.md) - the other operator-console primitive (continuous git snapshot); same console (KVM), same operator-only posture.
- doc 10 §9 - the first producer (eCash monitoring / rotation alerts, tagged petitioner-known vs petitioner-never-known). On `main`.
- [`README.md`](README.md) "AI-facing vs world-facing" split - this doc is squarely **AI-facing** (the petitioner / AI is the adversary the column split defends against).
- GLOSSARY: [arbiter](../../GLOSSARY.md#arbiter), [audit log](../../GLOSSARY.md#audit-log), [HITL approval](../../GLOSSARY.md#human-in-the-loop-hitl-approval), [recipient address registry](../../GLOSSARY.md#recipient-address-registry)

---

## 1. Purpose and scope

The arbiter does a lot the operator should be able to watch live: funding / defunding, gateway
refusals, registry edits, HITL prompts, mint-monitoring tiers, rotations. Some of that the petitioner
(the AI client) **already knows** - it saw the result in an API response. Some of it the petitioner
**must never learn** - node identity, mint URL, internal health, detection thresholds, real amounts. A
single undifferentiated activity log forces the operator to mentally re-derive, line by line, "does the
AI know this?" - and the cost of getting it wrong is a leak.

This doc defines a **two-column operator-visibility TUI** that does that classification once, up front,
and shows it: **column 1** = events the petitioner already knows; **column 2** = things the petitioner
must never learn. It is a **general arbiter surface** - any subsystem posts to it; eCash monitoring /
rotation (doc 10) is the first producer, not the owner.

**In scope:** the two-column model, the classification contract producers follow, the never-leak
invariant, where the TUI runs, and its relationship to the audit log (doc 05 §4.5) and the git snapshot
(doc 06). **Out of scope:** each producer's own event semantics (theirs); the audit-log format
(doc 05); world-facing observers (this is an AI-facing surface - the archived
[node-privacy-from-the-world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes cover
world-facing). Adversary: the petitioner / AI, which must never receive a column-2 item.

## 2. The two-column model

| Column | Holds | Colour | The question it answers |
|---|---|---|---|
| **1 - Petitioner-known** | the **literal replies the petitioner received**, projected from the **disclosure record** (§3) - the timestamped log of petitioner<->arbiter traffic: a banded amount it was told, a refusal it received, a tokenized id it was given, an action's result once the [timing layer](05--2026-05-05-0948-architecture-overview.md#46-timing-layer) released it. Verbatim what crossed the gateway, stamped with the record's send time - not what it *could* derive. | calm (e.g. green / neutral) | "what does the AI's view of us currently include?" |
| **2 - Petitioner-never-known** | things the petitioner must never learn: node / LND identity, the mint URL and keyset health, real (unbanded) amounts, monitoring tiers and thresholds, drain cadence, rotation internals, registry contents | alert (e.g. red / amber) | "what are we keeping from the AI right now, and is any of it at risk of leaking?" |

Colour-coding is **load-bearing, not decoration**: the operator must tell the two apart at a glance,
because the whole point is to never act on a column-2 item as if it were shareable.

**Rows are shared, and a blank is a signal.** The columns sit **side by side on one row grid**,
append-only - nothing already printed ever moves. When an internal event and its disclosure land
together (the petitioner is told a banded X while the real X is withheld beside it), both print on
one row and nothing more is needed. But disclosure usually **lags** the internal event by the
timing-layer windows (action + result delay, ~12h+ each; [doc 05 §4.6](05--2026-05-05-0948-architecture-overview.md#46-timing-layer),
doc 09): the event prints now in column 2 with **nothing opposite in column 1**, and that blank is
first-class information - a filled column-2 cell beside an empty column-1 cell reads at a glance as
*"we did this; the AI does not know it yet."* When the timing layer later releases the result, it
prints on a **new** row that pairs the column-1 disclosure (the verbatim reply, stamped from the
disclosure record) with a **re-print** of the withheld secret beside it, so the two align on that
row without moving the original (a fresh column-1 row, §3, not a backfill). The re-print is only for this deferred case; the earlier column-2 line
stays put, and a run of still-blank column-1 opposites is a visible backlog of what the AI has not
yet been told.

## 3. What feeds each column

The two columns are fed differently, and that difference is what makes column 1 trustworthy.

- **Column 1 is projected from the disclosure record, not tagged.** The disclosure record is the
  arbiter's timestamped, append-only log of petitioner<->arbiter traffic - every request in and every
  reply out. Column 1 is a straight projection of it: a row appears only because a reply was actually
  sent, shown verbatim and stamped with the record's send time. So `pet-known` is never a producer's
  guess about what the AI learned - it is what the record says crossed the gateway. Replies are meant
  to be both machine- and human-readable (YAML the likely form), so one representation serves the wire,
  the record, and the operator's eye; the reply / wire format itself is a protocol concern (doc 05 §8).
  The disclosure record is arbiter architecture - a petitioner-facing relative of the
  [audit log](../../GLOSSARY.md#audit-log) (doc 05 §4.5) - so its format and home are pinned there;
  this doc only reads it.
- **Column 2 is producer-tagged.** Internal events the petitioner never receives (mint-health tiers,
  real amounts, rotation internals) have no traffic record to draw from, so each is emitted by its
  producer carrying the `pet-never` tag. Here the producer does own the call, under two rules:
  - **Default to `pet-never` on any doubt.** Mistagging a never-known item as known is a *leak*;
    over-hiding only costs the operator a glance. That asymmetry sets the fail-safe default - mirroring
    the gateway's deny-by-default and doc 07 §8's missing-allowance refusal posture.
  - **Tags are immutable once posted.** A column-2 event is never rewritten into column 1; when the
    petitioner is later told something, that is a *new* column-1 row from the disclosure record (§2),
    and the [audit log](../../GLOSSARY.md#audit-log) (doc 05 §4.5) keeps the full trail.

## 4. The never-leak invariant

The one invariant the surface exists to enforce: **no column-2 content ever reaches a petitioner-facing
channel.** The TUI is **one direction only** - subsystems -> operator. It reads from arbiter-local state
(the same arbiter-local, never-AI-readable posture as the audit log and the eCash monitoring state,
doc 10 §4); nothing it displays is reachable through the gateway. The TUI is a **display** - not a store,
not an input: there is no path from the screen back into a petitioner response, and the AI has no path
to read it.

## 5. Where it runs

On the **arbiter console** - the same operator-only KVM that already hosts
[HITL approval](../../GLOSSARY.md#human-in-the-loop-hitl-approval), the
[recipient address registry](../../GLOSSARY.md#recipient-address-registry), and the git-snapshot audit
queries (doc 06). **Not network-exposed**, no remote surface: a remote operator dashboard would be a new
egress / identity channel, out of scope exactly as doc 06 §6 holds off-host shipping out.

HITL shares the console but not the surface: the TUI *shows* that a write parked for approval (a
column-2 event), while the approve / deny input stays the separate
[HITL](../../GLOSSARY.md#human-in-the-loop-hitl-approval) channel (doc 05 §6) - the TUI itself takes
no input (§4).

It **complements, does not replace**:

- the **runtime audit log** (doc 05 §4.5) - append-only, per-request, the forensic record. The TUI is the
  live glance; the audit log is the history.
- the **git snapshot** (doc 06) - what was deployed / configured over time. Orthogonal: provenance vs
  live activity.

## 6. Threat model and residual leaks

- **Misclassification / omission.** Because column 1 is projected from the disclosure record (§3), a
  producer cannot place a never-known value into column 1 - that leak path is closed by construction.
  The residual is a producer *omitting* a column-2 event, or mis-describing one, which under-informs
  the operator rather than over-informing the AI; mitigated by the fail-safe `pet-never` default and
  small, reviewable producers (doc 05 §2.1), with the [audit log](../../GLOSSARY.md#audit-log)
  (doc 05 §4.5) as the after-the-fact backstop.
- **Operator error.** The TUI informs the operator but cannot stop them pasting a column-2 value
  elsewhere; it minimizes the chance by making the classification unmissable (colour + column), but the
  human remains the last line.
- **No new AI surface.** Because the TUI is display-only, arbiter-local, and console-bound, it adds **no**
  channel the AI can read or write - it removes operator-side ambiguity without widening the attack
  surface.

## 7. Open questions

- **Concrete colour / layout.** Exact palette (colour-blind-safe), column widths, grouping within
  column 1, scrollback depth. Deferred to implementation.
- **Producer enumeration.** The full set of producers and each one's per-event tags (executor, gateway
  decisions, registry edits, HITL, eCash monitoring / rotation). doc 10 §9 is the first; others are
  enumerated as they wire in.
- **Severity within columns.** Whether column 2 needs its own severity gradient (internal-vs-at-risk) or
  colour-by-column is enough.
- **Quiescent display.** What the TUI shows when nothing is happening (last-N events vs live-only)
  without becoming a second audit log.

## 8. What is NOT in this doc

- Each producer's event semantics and when they fire (theirs; e.g. doc 10 for eCash).
- The audit-log format and the git-snapshot mechanism (doc 05 §4.5, doc 06).
- World-facing observers - this is an AI-facing surface; the archived
  [node-privacy-from-the-world](../../archive/2026-05-02-1700-node-privacy-from-the-world.md) notes cover
  world-facing.
- Screen-implementation specifics (palette, widget toolkit, layout) - implementation.
