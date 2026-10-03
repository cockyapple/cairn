# Cairn ledger specification, version 1

Status: draft. Version 1 is **not frozen**. Phase 1 made three format changes (canonical
checkpoints, the FREEZE lift scope, and the ACTION intent/completion rule), and a fourth
was added after the vectors were first published: entry kind 7, REVOKE (ADR-20), with the
vectors regenerated. Until there is a second implementation, or a release is tagged, the
format may still change; once either happens, any change is a new version. Conformance is defined by
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

Consequence: surplus, unsorted, repeated or stranger signatures cannot be added to a
checkpoint without it being rejected, so a checkpoint cannot be padded or reordered
into a second valid byte string (ADR-12). That is all it guarantees. It is **not**
one checkpoint per tree head, and it does not make the full encoding a unique
identifier: different subsets of validators and witnesses that each meet quorum are
different valid checkpoints for the same size, root and head, and one signer can
produce several valid Ed25519 signatures over the same body (a verifier cannot tell
a deterministic nonce from any other). To identify a tree head, use size and root,
or the 81-byte body; hash the full encoding only to identify one particular signed
checkpoint. A coordinator must filter and sort before publishing.

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
chain. It enforces invariants I1 and I3, I11 at delegation time, and keeps I7 as an auditable intent
trail. It does **not** enforce I4, I5, I6, I8, I9 or I12, and I11 only for delegation; section 10.5
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

A PROPOSAL whose target is `cairn/grant/<hex>` and an ACTION of type
`cairn/delegate` carry the capability rules of 10.3.2; they use the same authors
as any other PROPOSAL and ACTION.

A key holds exactly one role, so a proposer can never vote on its own proposal
and an agent can never vote or activate (I1) by construction, not by an extra
check.

### 10.2 Changes

- Entry `time` never decreases from one entry to the next (`time_regression`).
  Time stays advisory (ADR-5): the rule only bounds how far a proposal can be
  backdated to shorten its delay, to the time of the entry before it.
- Targets `cairn/validators`, `cairn/constitution`, `cairn/gatekeeper` and
  `cairn/policy/require-grants` (10.3.4) can only be proposed at tier T4; any other target beginning `cairn/` is reserved
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
  not precede that activation's `effective_after` (`delay_not_elapsed`). If several
  activated proposals carry that same diff, any one whose delay has elapsed will do.
  Applying the entry uses up every activated validators proposal, not only the one it
  matched: they belong to the epoch that just ended, so a further change needs a new
  proposal (`bad_validators_change`).
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

### 10.3.2 Capability grants and delegation (I11)

A **grant** says what one agent key may do. It is a canonical blob (all integers
big-endian, strings as in section 3):

```
u8 version (1) | u32 n | n strings: tools | u32 m | m strings: hosts | u64 budget | u64 not_after
```

Each list is strictly ascending by byte order, with no empty and no duplicate name,
at most 256 names of at most 256 bytes each. `budget` is an abstract unit count;
`not_after` is a time, exclusive. `2^64-1` means unlimited and, for `not_after`, no expiry: such a grant never
expires, whatever the entry time. A grant that
does not re-encode to the bytes given is `bad_grant`.

**Root grants.** A PROPOSAL with target `cairn/grant/<64 lowercase hex chars>`
(the agent's public key) whose `diff_hash` is the hash of a grant blob. It needs
tier T3 or T4 (`reserved_target`). The key must hold the agent role and not be
revoked (`bad_grant`, `revoked_key`), and the blob must be supplied and decode
(`bad_blob`, `bad_grant`). Activation goes through the ordinary vote, delay and
freeze rules, and fails with `revoked_key` if the agent was revoked in the meantime.
The grant takes effect at the activation's `effective_after`; until then the key's
earlier grant, if any, stays in force. A root grant that takes effect replaces the
grant the key held, and a grant activated later supersedes one activated earlier even
if the earlier one would have taken effect after it. A target that starts with
`cairn/grant/` but is not followed by exactly 64 lowercase hex digits is a reserved
target (`reserved_target`), like every other `cairn/` target. Names in a grant must be
valid UTF-8.

**Delegation.** An agent that holds a grant may pass a **strictly narrower** one to
another agent. It writes an ACTION intent of type `cairn/delegate` whose `args_hash`
is the hash of `child (32 bytes) | grant blob`. The replay rejects it as
`bad_delegation` when the author holds no grant, the grant is not yet effective at
the entry's time, the entry's time is at or past the grant's `not_after`, the child
is the author, the child is not an agent, or the child already holds a grant that has
not expired;
`revoked_key` when the child is revoked; and `delegation_not_narrower` unless the
child's tools and hosts are subsets of the author's, its budget and `not_after` are
no greater, and at least one of the four is strictly smaller. The child's grant takes
effect at the entry's time. Revoking a key withdraws its grant and, recursively,
every grant it delegated; a root grant that governance approved separately for one of
those keys is not derived from it and still takes effect at its time. A revoked key also
loses its own scheduled grants. `State.Grants` lists the grants in force at the time of the
last entry: scheduled and expired grants are not listed.

### 10.3.3 Enforcing a grant on replay (I2, I6)

An agent is **bound** once it has held a grant: a root grant that has taken effect,
or a delegation. Binding is never undone, not by expiry and not by withdrawal. An
agent that has never held a grant is unconstrained unless the log requires
grants (10.3.4; see 10.5).

An ACTION **intent** by a bound agent is checked against the agent's grant, unless
its type is `cairn/delegate` (10.3.2) or `cairn/event` (10.4). Completions are
never checked. The `args_hash` of a checked intent must be the hash of a **use**
blob:

```
u8 version (1) | string host | u64 cost | bytes args
```

`host` may be empty. `args` is the caller's own argument blob and is not parsed.
The checks run in this order and the first failure is reported:

1. `no_grant`: the agent holds no grant now (it was withdrawn, for example by a
   revocation of its parent).
2. `grant_expired`: the entry's time is at or past the grant's `not_after`.
3. `bad_blob`: the use blob is not supplied. `bad_use`: it does not decode, or
   has bytes left over.
4. `tool_not_granted`: `action_type` is not in the grant's tools.
5. `host_not_granted`: `host` is not empty and not in the grant's hosts.
6. `budget_exceeded`: `cost` is more than the budget still unspent on the
   agent's grant, or on any grant above it in the delegation chain.

**Budget.** The cost of an intent is charged when the intent is written, as a
reservation. A completion refunds nothing, and neither does a refusal the agent
wrote about itself. A cost is charged to the agent's grant and to every grant
above it through the parent chain, so a parent's budget bounds all of its
descendants together and siblings cannot multiply it. The whole chain is checked
before anything is charged, so a failed intent charges nothing. A grant with
unlimited budget is not counted. A root grant that takes effect starts a new
count. `State.Grants[].Spent` reports the count.

**Delegation loops.** A delegation to a key that is already above the author in
its own chain is `bad_delegation`. Without this rule an expired grant, which may be
overwritten, would let a chain close on itself.

### 10.3.4 Requiring every agent to hold a grant

A PROPOSAL with target `cairn/policy/require-grants` at tier T4 sets whether the
log requires every agent to hold a grant. Its diff blob is

```
u8 version (1) | u8 require (0 or 1)
```

any other bytes are `bad_policy`. The change takes effect like a root grant
(10.3.2): when the replay reaches an entry whose time is at or after the
activation's `effective_after`, and an activation made later supersedes any made
earlier, even one that takes effect later. The default is not to require.

While it is required, an intent by an agent that has never held a grant is
`no_grant`, as if its grant had been withdrawn. Delegation, `cairn/event` and
completions are not checked, so an ungranted agent can still be handed a grant,
log an event, and close an intent it opened before the switch. Bound agents are
held to their grants as in 10.3.3 whether or not the switch is on. Turning the
switch off lets ungranted agents act again; it does not unbind anyone.
`State.RequireGrants` reports the setting in force after the last entry.

### 10.4 ACTION: intent, then completion (ADR-13)

An ACTION whose `result_hash` is zero is an **intent**. One with a non-zero
`result_hash` is a **completion**: it must repeat the `action_type` and
`args_hash` of the author's *oldest* open intent and closes it
(`bad_action_completion` otherwise). Every ACTION's `prev_action_hash` must be
the entry hash of the same author's previous ACTION, or zero for its first
(`bad_action_chain`). The replay reports every intent still open; an old open
intent is a signal (crash, refusal or concealment), not itself a violation.

An ACTION of type `cairn/event` records something the agent's gatekeeper did
about the agent, such as a refusal or a rate limit, for a bound agent that
cannot put its own refusals through the grant check. Its args are
`string type | bytes args`, the type and arguments of the action the event is
about. The replay does not parse them and does not check the action against the
grant.

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
- **I11 (delegation only narrows)** is enforced at the moment of delegation
  (10.3.2). Replacing a root grant with a smaller one does not shrink grants already
  delegated from the old one; revoking the key does.
- **I2 and I6 (an agent stays inside its grant)** are enforced on replay for bound
  agents (10.3.3), with limits worth stating. The log can show that an intent was
  outside the grant and reject the entry, but it cannot stop an action taken without
  writing an intent. `host` and `cost` are declared by the writer, not measured.
  Budget is a reservation with no refund. An agent that has never held a grant is
  not checked unless the log has switched on `cairn/policy/require-grants`
  (10.3.4); a deployment that wants every agent held to a grant must do so, and
  must still give each agent a grant before it can act. The switch is recorded
  in the log, so every verifier reads the same setting.
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
`bad_action_completion`, `tier_too_low`, `future_entry`, `bad_revocation`, `revoked_key`,
`bad_grant`, `bad_delegation`, `delegation_not_narrower`, `no_grant`,
`grant_expired`, `bad_use`, `tool_not_granted`, `host_not_granted`,
`budget_exceeded`, `bad_policy`.
