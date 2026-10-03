# Cairn ledger specification, version 1

Status: Phase 1 draft. Phase 1 made three deliberate format changes before freezing
(canonical checkpoints, the FREEZE lift scope, and the ACTION intent/completion
rule); after those, any change is a new version. Conformance is defined by
`testdata/vectors-v1.json`, not by this prose. Where they disagree, the vectors
win and this file has a bug.

Keywords MUST, SHOULD and MAY are as in RFC 2119.

## 1. Primitives

- Hash: SHA-256. Signatures: Ed25519 (RFC 8032, pure, no context).
- Integers are unsigned big-endian. `u8`, `u32`, `u64`.
- `bytes`: u32 length, then that many bytes. `string`: `bytes` that MUST be valid UTF-8.
- Fixed arrays are written raw with no length.
- A decoder MUST reject trailing bytes, short input, invalid UTF-8, and any
  length or count above its bound (`bytes` 16 MiB; key list 1024; vote list 256;
  checkpoint signatures 1024). Bounds are checked **before** allocating.
- Every signature, and every hash that is signed or chained (entry hash, Merkle
  nodes, checkpoint), uses a domain prefix (ends in `\x00`) so a signature made for
  one purpose can never be replayed for another. Blob addresses, and therefore an
  entry's `payload_hash`, are plain SHA-256 of the bytes, on purpose: `sha256sum`
  reproduces them. They are content addresses, never signed on their own; the entry
  hash that covers `payload_hash` is domain-separated.
- No public key may be of small order (order dividing 8): `ed25519.Verify` accepts
  such keys and anyone could then forge for them. An entry whose author is one
  fails `bad_signature`; a TrustConfig that admits one is `bad_trust_config`.

## 2. Entry (fixed 178 bytes)

| Offset | Size | Field | Notes |
|-------:|-----:|-------|-------|
| 0 | 1 | version | MUST be 1 |
| 1 | 8 | height | 0 for GENESIS, then +1 each entry |
| 9 | 32 | prev_hash | entry hash of height-1; all zero at height 0 |
| 41 | 1 | kind | see section 3 |
| 42 | 32 | payload_hash | SHA-256 of the payload blob |
| 74 | 32 | author | Ed25519 public key |
| 106 | 8 | time | unix seconds, **advisory only**, never used for ordering |
| 114 | 64 | signature | Ed25519 over `"cairn/entry/v1\x00" \|\| bytes[0:114]` |

Entry hash = SHA-256(`"cairn/entry-hash/v1\x00"` \|\| all 178 bytes, signature
included). Including the signature means the chain commits to it, so an
equivalent-but-different signature cannot be swapped in later.

Payload blobs are stored beside the log and addressed by `payload_hash`. A
verifier that lacks a blob can still verify the chain and checkpoints; it just
cannot interpret that entry.

Time is a u64 of unix seconds rather than a formatted timestamp, to remove
parsing ambiguity. It is advisory: order comes from height.

## 3. Entry kinds and payloads

| Kind | Name | Payload |
|-----:|------|---------|
| 0 | GENESIS | `u32 spec_version, [32] constitution_hash, TrustConfig` |
| 1 | PROPOSAL | `u8 tier, string target, [32] diff_hash, [32] rationale_hash, [32] eval_hash` |
| 2 | VOTE | `[32] proposal_entry_hash, u8 verdict, [32] comment_hash` (verdict 1 approve, 2 reject, 3 escalate) |
| 3 | ACTIVATE | `[32] proposal_entry_hash, u32 n, n x [32] vote_entry_hash, u64 effective_after` |
| 4 | ACTION | `string action_type, [32] args_hash, [32] result_hash, [32] prev_action_hash` |
| 5 | VALIDATORS | `TrustConfig` (a new epoch) |
| 6 | FREEZE | `u8 scope, [32] reason_hash` (scope 1 = freeze activations, scope 2 = lift the freeze) |
| 7 | REVOKE | `[32] public_key, [32] reason_hash` |

GENESIS `spec_version` MUST be 1 and its TrustConfig epoch MUST be 0 (`bad_payload`).
`TrustConfig` = `u64 epoch, u32 n, n x (u8 role, [32] public_key), u32 witness_threshold`.
Roles: 1 validator, 2 witness, 3 reviewer, 4 security reviewer, 5 proposer, 6 agent.
A key holds exactly one role. At least one validator. `witness_threshold` MUST NOT
exceed the witness count. Tiers 0 to 4 map to T0 to T4 (constitution section 3).
Unknown kinds, tiers, roles, verdicts and scopes are rejected, not ignored.
An ACTION is either an intent (zero `result_hash`) or a completion (non-zero);
section 10.4 gives the pairing and chaining rules.

## 4. Chain rules

A chain is valid iff: it is non-empty (an empty chain is `bad_genesis`); entry 0 is GENESIS with height 0 and zero
`prev_hash`; there is no other GENESIS; heights are consecutive; every
`prev_hash` equals the previous entry hash; every signature verifies under the
entry's own `author`.

## 5. Merkle tree

RFC 9162 section 2.1. Leaf hash = SHA-256(`0x00` \|\| entry bytes); node hash =
SHA-256(`0x01` \|\| left \|\| right); split at the largest power of two strictly
less than n; the empty tree hashes the empty string. Leaves are the 178-byte
encoded entries.

## 6. Checkpoint

Body (81 bytes): `u8 version, u64 epoch, u64 size, [32] root, [32] head`.
Signature input: `"cairn/checkpoint/v1\x00" || body`. Wire form: body, `u32 n`,
then n x (`[32] public_key, [64] signature`).

A checkpoint is valid for a chain and a TrustConfig iff: size equals the entry
count and is non-zero; root equals the Merkle root; head equals the last entry
hash; epoch equals the TrustConfig epoch; signatures are in strictly ascending order of public key (a repeat is `duplicate_signer`,
a misordering is `unsorted_signers`); every signer is **admitted** (a stranger is
`unknown_signer`); every signature verifies; validator signatures reach
`n - (n-1)/3`; witness signatures reach `witness_threshold`.

Consequence: a given *set* of signatures has exactly one valid encoding. Because
signatures are sorted and only admitted keys may sign, no byte string that is not
that encoding verifies (ADR-12). This is not the same as one checkpoint per tree
head: different subsets of validators and witnesses that each meet quorum are
different valid checkpoints for the same size, root and head. To identify a tree
head, use size and root (or the checkpoint body); hash the full encoding only to
identify that particular signed checkpoint. A coordinator must filter and sort
before publishing.

Quorum `n - (n-1)/3` means any two quorums share an honest validator when at
most `(n-1)/3` are faulty. For n = 1, 4, 7 the quorum is 1, 3, 5.

## 7. Error codes

Stable strings. The vectors assert every one except the last, which only the
Go tests cover so far. Governance adds more in section 10.6.

`bad_length`, `bad_version`,
`unknown_kind`, `bad_genesis`, `duplicate_genesis`, `bad_height`,
`bad_prev_hash`, `bad_signature`, `bad_payload`, `size_mismatch`,
`root_mismatch`, `head_mismatch`, `epoch_mismatch`, `below_quorum`,
`below_witness_threshold`, `duplicate_signer`, `bad_trust_config`,
`bad_checkpoint`, `unknown_signer`, `unsorted_signers`, `bad_proof`.

## 8. What each layer checks

The **ledger** package (this spec's sections 1 to 7) checks authenticity:
structure, hashes, signatures, chain linkage, Merkle roots and proofs,
checkpoint quorum. A chain that passes it is untampered. It says nothing about
whether the chain is *lawful*.

The **governance** package (section 10) replays a verified chain and checks
lawfulness: roles, approvals, delays, freeze, validator epochs and the ACTION
chain. It enforces invariants I1 and I3, and keeps I7 as an auditable intent
trail. It does **not** enforce I4, I5, I6, I8, I9, I11 or I12; section 10.5
says why. Do not claim more than that.

## 9. Test vectors

`testdata/vectors-v1.json` contains an 8-entry chain covering every kind, Merkle
roots for 0 to 9 leaves, payload encodings, and invalid chain and checkpoint
cases with exact expected error codes. Keys are derived from public seeds and
are for testing only. The vectors are language-neutral so an independent
verifier can be written without reading the Go.

## 10. Governance rules

`governance.Replay` runs `VerifyChain` and then applies these rules in order,
entry by entry, stopping at the first violation. Roles come from the
TrustConfig **in force before the entry** (the epoch is that of the last
applied VALIDATORS entry). Payload blobs are required for every entry.

### 10.1 Who may write what

| Kind | Author's role |
|------|---------------|
| GENESIS | validator in the GENESIS TrustConfig itself |
| PROPOSAL | proposer or agent |
| VOTE | reviewer or security reviewer |
| ACTIVATE | validator |
| ACTION | agent |
| VALIDATORS | validator |
| FREEZE (scope 1) | validator or security reviewer |
| FREEZE (scope 2, lift) | validator |
| REVOKE | validator or security reviewer |

A key holds exactly one role, so a proposer can never vote on its own proposal
and an agent can never vote or activate (I1) by construction, not by an extra
check.

### 10.2 Changes

- Entry `time` never decreases from one entry to the next (`time_regression`).
  Time stays advisory (ADR-5): the rule only bounds how far a proposal can be
  backdated to shorten its delay, to the time of the entry before it.
- Targets `cairn/validators`, `cairn/constitution` and `cairn/gatekeeper` can
  only be proposed at tier T4; any other target beginning `cairn/` is reserved
  (`reserved_target`).
- A proposal belongs to the epoch in which it was written. A VALIDATORS entry
  voids every earlier open proposal (`wrong_epoch`).
- A reviewer votes at most once per proposal (`duplicate_vote`). Any reject or
  escalate vote blocks activation for good (`blocked_by_vote`); to try again,
  propose again.
- ACTIVATE lists the approving VOTE entries. Each must approve this proposal,
  come from a distinct author who **still** holds a reviewer or security
  reviewer role (`bad_vote_reference`), and the counts must meet the tier
  (`insufficient_approvals`):

  | Tier | Approvals | of which security | Minimum delay |
  |-----:|----------:|------------------:|--------------:|
  | T0 | 0 | 0 | 0 |
  | T1 | 1 | 0 | 24 h |
  | T2 | 2 | 1 | 72 h |
  | T3 | 3 | 1 | 7 d |
  | T4 | 3 | 1 | 14 d |

- `effective_after` must be at least the proposal entry's time plus the delay
  (`delay_too_short`). A proposal activates once (`already_activated`).
- A VALIDATORS entry's TrustConfig may not contain a key that has been revoked
  (`revoked_key`): a revocation outlives every epoch, so a rotation cannot quietly
  re-admit a withdrawn key.
- A VALIDATORS entry must carry epoch current + 1 and a TrustConfig whose
  encoding hashes (plain SHA-256) to the `diff_hash` of an activated, unused
  `cairn/validators` proposal (`bad_validators_change`), and its own `time` must
  not precede that activation's `effective_after` (`delay_not_elapsed`).
- A checkpoint of size n is judged by the TrustConfig in force after entry n-1
  has been applied; a checkpoint that covers a VALIDATORS entry is therefore
  signed by the **new** set.

### 10.3 Freeze

While frozen, ACTIVATE is rejected except for T0 proposals, and VALIDATORS is
rejected (`frozen`). Reading, verifying, ACTION and VOTE continue (I3). T0 is
the only tier that can only tighten, so it is the emergency rollback path: to
roll back a loosening, propose its inverse as T0. Freezing a frozen log, or
lifting an unfrozen one, is `bad_freeze_state`.

### 10.3.1 REVOKE (ADR-20)

A REVOKE names one public key and ends its authority at once, from the next entry
on, without waiting for a new epoch. It is the answer to a stolen key, which
otherwise stays valid until a T4 change clears its 14-day delay.

- Written by a validator or a security reviewer. A freeze does not block it.
- The target must hold the **agent or proposer** role in the epoch in force and not
  be revoked already (`bad_revocation`). Keys that vote, validate or witness cannot
  be revoked by one signer: otherwise a single rogue security reviewer could stall
  every approval. Those keys leave through a T4 VALIDATORS change.
- A revoked key stays revoked for good, whatever later epochs say. Its entries are
  rejected (`revoked_key`), and so is the activation of any proposal it wrote that
  was not yet activated (`revoked_key`). Changes already activated stand.
- Open intents of a revoked agent stay open and are reported: its completions are
  refused, so the gap is visible.
- REVOKE only removes authority. It cannot grant a role.

### 10.4 ACTION: intent, then completion (ADR-13)

An ACTION whose `result_hash` is zero is an **intent**. One with a non-zero
`result_hash` is a **completion**: it must repeat the `action_type` and
`args_hash` of the author's *oldest* open intent and closes it
(`bad_action_completion` otherwise). Every ACTION's `prev_action_hash` must be
the entry hash of the same author's previous ACTION, or zero for its first
(`bad_action_chain`). The replay reports every intent still open; an old open
intent is a signal (crash, refusal or concealment), not itself a violation.

Convention, not a rule the replay checks: a gatekeeper writes the result blob so
that its first line is `ok`, `error` or `refused`, and a refusal is an intent
plus a completion whose blob is `refused`, a code and a detail (ADR-17).

### 10.5 What is not enforced, and why

- **I4 (loosening is slower than tightening).** Whether a change loosens a
  limit depends on what the target and diff *mean*, which the ledger does not
  parse. Tiers are chosen by the proposer and checked by reviewers. Tier
  minimums, the reserved T4 targets and the freeze-time T0 rule are the
  mechanical part; the semantic part is a reviewer duty.
- **I5, I6, I8, I9, I12** concern the gatekeeper and the agent runtime
  (Phase 2 and later), not the log.
- **I11 (delegation only narrows).** There is no wire format yet for capability
  grants or delegation, so there is nothing to check. Defining one is open work.
- **Time.** Delays are measured on entry `time` values, which are claims. They
  are bounded by monotonicity and, in Stage A, by the sequencer refusing
  entries far from its own clock; a consumer that loads a change must compare
  `effective_after` with a clock it trusts. A verifier that has such a clock can pass it as `Now` with a `MaxSkew`;
  an entry stamped later is rejected (`future_entry`), which stops a validator
  dating a VALIDATORS entry ahead to skip its delay. Without `Now` the delay
  rests on entry times alone.
- **Tier floors for other targets.** The log fixes floors only for the reserved
  `cairn/` targets. For anything else a proposer chooses the tier, and T0 needs
  no votes and no delay. A verifier can pass a `MinTier` policy; a proposal below
  its floor is rejected (`tier_too_low`). The policy is not recorded in the log,
  so every verifier has to be given the same one.
- **Revoking keys that vote, validate or witness.** REVOKE (10.3.1) covers agent and
  proposer keys only. A stolen reviewer, validator or witness key stays valid until a
  T4 VALIDATORS change clears its delay.
- **I7** is enforced only as a record: the log shows an intent before the
  completion. Whether a gatekeeper really waited for the log is Phase 2.

### 10.6 Error codes

Governance failures add these stable codes to section 7's. Malformed payloads
keep the ledger codes `bad_payload` and `bad_trust_config`. The guard test
`TestSpecGovernanceCodesMatchCode` keeps this list equal to the code.

`unauthorized_author`, `bad_blob`, `time_regression`, `constitution_mismatch`,
`reserved_target`, `unknown_proposal`, `wrong_epoch`, `duplicate_vote`,
`already_activated`, `bad_vote_reference`, `blocked_by_vote`,
`insufficient_approvals`, `delay_too_short`, `delay_not_elapsed`, `frozen`,
`bad_freeze_state`, `bad_validators_change`, `bad_action_chain`,
`bad_action_completion`, `tier_too_low`, `future_entry`, `bad_revocation`, `revoked_key`.
