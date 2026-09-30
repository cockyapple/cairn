# Cairn ledger specification, version 1

Status: Phase 0 draft. The wire format in this file is frozen once Phase 1
starts; any change after that is a new version. Conformance is defined by
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
- Every signature and hash uses a domain prefix (ends in `\x00`) so a signature
  made for one purpose can never be replayed for another.

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
| 6 | FREEZE | `u8 scope, [32] reason_hash` (scope 1 = activations) |

`TrustConfig` = `u64 epoch, u32 n, n x (u8 role, [32] public_key), u32 witness_threshold`.
Roles: 1 validator, 2 witness, 3 reviewer, 4 security reviewer, 5 proposer, 6 agent.
A key holds exactly one role. At least one validator. `witness_threshold` MUST NOT
exceed the witness count. Tiers 0 to 4 map to T0 to T4 (constitution section 3).
Unknown kinds, tiers, roles, verdicts and scopes are rejected, not ignored.

## 4. Chain rules

A chain is valid iff: it is non-empty; entry 0 is GENESIS with height 0 and zero
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
hash; epoch equals the TrustConfig epoch; no signer appears twice; every
signature by an **admitted** key verifies (signatures by keys outside the
config are ignored and never counted); validator signatures reach
`n - (n-1)/3`; witness signatures reach `witness_threshold`.

Quorum `n - (n-1)/3` means any two quorums share an honest validator when at
most `(n-1)/3` are faulty. For n = 1, 4, 7 the quorum is 1, 3, 5.

## 7. Error codes

Stable strings, asserted exactly by the vectors: `bad_length`, `bad_version`,
`unknown_kind`, `bad_genesis`, `duplicate_genesis`, `bad_height`,
`bad_prev_hash`, `bad_signature`, `bad_payload`, `size_mismatch`,
`root_mismatch`, `head_mismatch`, `epoch_mismatch`, `below_quorum`,
`below_witnesses`, `duplicate_signer`, `bad_trust_config`,
`bad_checkpoint_length`.

## 8. What Phase 0 does and does not check

Checked here: structure, hashes, signatures, chain linkage, Merkle roots,
checkpoint quorum. **Not yet checked** (Phase 1 state machine): that an author
holds a role permitted to write that kind (for example an agent key writing
VOTE), tier delays, vote counting, freeze semantics and the constitution
invariants. A chain that passes Phase 0 verification is authentic and
untampered; it is not yet known to be *lawful*. Do not claim more.

## 9. Test vectors

`testdata/vectors-v1.json` contains an 8-entry chain covering every kind, Merkle
roots for 0 to 9 leaves, payload encodings, and invalid chain and checkpoint
cases with exact expected error codes. Keys are derived from public seeds and
are for testing only. The vectors are language-neutral so an independent
verifier can be written without reading the Go.
