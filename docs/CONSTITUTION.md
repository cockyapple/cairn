# Cairn constitution, version 1

The hash of this file is recorded in GENESIS. Changing it means a new genesis
or a T4 amendment that every verifier can see.

## 1. Purpose

Cairn keeps AI agents accountable. Every change to an agent's behaviour, and
every consequential action, is written to a public append-only log that anyone
can verify and a community can review.

## 2. Honest limits

Cairn makes change **tamper-evident and governed**. It does not make an agent
"unalterable", and it does not make a model immune to manipulation. It makes
alteration visible, delayed, reviewed and attributable, and it bounds what a
manipulated agent can do.

## 3. Change tiers

| Tier | Examples | Minimum delay |
|------|----------|---------------|
| T0 | Tighten a limit, add a blocklist entry | none |
| T1 | Prompt wording, non-security config | 24 h |
| T2 | New tool, model swap, widened limits | 72 h |
| T3 | Permission changes, new agent role | 7 d |
| T4 | Gatekeeper code, validator set, this constitution | 14 d |

Each tier above T0 also needs approvals from distinct reviewers, and T2 and
above need at least one security reviewer. The exact counts and delays are fixed
by SPEC section 10.2 so every verifier applies the same ones.

## 4. Invariants

These hold regardless of any vote.

- **I1. No self-governance.** An agent key may write ACTION and PROPOSAL. It may
  never VOTE or ACTIVATE, on any change, and in particular not on changes to itself.
- **I2. One source of truth.** The ledger is the only source of agent
  configuration. A change that is not activated on the ledger does not exist.
- **I3. Freeze is narrow.** A FREEZE stops activations only. It never blocks
  reading, verification, ACTION logging or an emergency rollback.
- **I4. Loosening is slower than tightening.** Relaxing any limit requires a
  tier strictly above the tier that could have imposed it.
- **I5. The gatekeeper is not ledger-configurable.** The code that enforces
  capabilities changes only by audited code release at T4.
- **I6. Authority lives outside the model.** No prompt, message, document or
  tool output can grant a capability. Capabilities come from ledger-recorded
  grants enforced by the gatekeeper (see INJECTION-DEFENSE.md).
- **I7. Log before act.** The gatekeeper writes an ACTION entry before it
  executes. An action with no entry is a violation.
- **I8. Untrusted text is data.** Content from outside the trust boundary is
  never placed in an instruction channel and never treated as a command.
- **I9. Humans approve irreversible acts.** Acts that move value, publish,
  delete or change configuration require approval bound to the action hash.
- **I10. Verifiers owe nothing to the operator.** Verification needs only the
  log, the checkpoints and the vectors. No operator-held secret is required.

- **I11. Delegation only narrows.** An agent may delegate only a strict subset of
  its own grant. No agent can create authority it does not hold.
- **I12. Model-agnostic guarantees.** No security guarantee depends on which
  model is used or on the model behaving well. Changing the model is a T2 change,
  and a model with no recorded evaluation receives the minimum grant.

## 5. Enforcement status

The Phase 1 governance replay (SPEC section 10) enforces **I1** (no
self-governance, by role) and **I3** (a freeze stops activations only, and T0
rollbacks still pass). It enforces **I11** at the moment of delegation: a grant
handed to another agent must be a strict subset of the delegator's own (SPEC
10.3.2). Once an agent has held a grant, the replay also holds each of its actions
to that grant: tool, host, expiry and a budget that is totalled down the delegation
chain (SPEC 10.3.3). It records **I7** as an auditable trail: an intent
entry precedes its completion, but nothing yet proves a gatekeeper waited for
it. **I2** holds only to the extent that consumers read configuration from the
ledger, which no code here does yet.

Not enforced by any code today: **I4** (it needs the ledger to understand what a
change means; only tier minimums and reserved T4 targets are mechanical), **I5,
I6, I8, I9, I12** (gatekeeper and agent runtime, Phase 2 and later). **I11** and the grant
check are enforced on replay, with stated limits: an agent that has never held a
grant is not checked, `host` and `cost` are declared by the writer, and an action
taken without writing an intent is invisible to the log (SPEC 10.5). Until the rest are enforced, they are commitments, not
guarantees, and this repository must not claim otherwise.
