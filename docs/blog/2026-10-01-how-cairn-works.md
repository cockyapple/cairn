# How Cairn works: 178 bytes, a hash chain and a Merkle tree

*Part 2 of the Cairn series. The short version of the "how," with the real numbers.*

[Part 1](2026-09-30-why-cairn.md) said what Cairn is for. This post shows how the ledger
actually works, at the level where you could check it yourself. Everything here is
specified in `docs/SPEC.md`, and the test vectors in `testdata/vectors-v1.json` are the
final authority where the two ever disagree.

## One entry, 178 bytes

Every event in Cairn is one fixed-size entry:

- **version** (1 byte), always 1 for now
- **height** (8 bytes): 0 for the first entry, then one more each time
- **prev_hash** (32 bytes): the hash of the entry before it
- **kind** (1 byte): what sort of event this is
- **payload_hash** (32 bytes): the SHA-256 of the event's details, stored beside the log
- **author** (32 bytes): the Ed25519 public key of whoever wrote it
- **time** (8 bytes): unix seconds, and *advisory only*, never used for ordering
- **signature** (64 bytes): the author's signature over everything above

That is 178 bytes. The details (a prompt diff, a vote comment) live in a separate blob and
the entry only holds its hash, so the log stays small and a verifier that lacks a blob can
still check the chain.

There are seven kinds: GENESIS, PROPOSAL, VOTE, ACTIVATE, ACTION, VALIDATORS and FREEZE.
That is the whole vocabulary. A change to an agent is a PROPOSAL followed by VOTEs and an
ACTIVATE. Something an agent does is an ACTION. Anything the decoder doesn't recognise is
rejected, never ignored.

## Why a chain

Each entry's hash covers all 178 bytes *including the signature*, and the next entry stores
that hash as its `prev_hash`. Change any byte of entry 40 and its hash changes, so entry 41
no longer points at it, and every entry after that is broken too. Including the signature
in the hash also means nobody can swap in a different-but-valid signature later without the
chain noticing.

Signatures carry a domain prefix, such as `cairn/entry/v1` followed by a zero byte. A
signature made for an entry can never be replayed as a signature on a checkpoint, because
the signed bytes differ from the first byte.

## Why a tree as well

A chain tells you nothing is out of order. It doesn't let a stranger check one entry
without downloading all of them. That is what the Merkle tree adds. The entries are the
leaves of a tree built exactly as RFC 9162 describes (the standard behind Certificate
Transparency), with a `0x00` byte prefixed to leaves and `0x01` to inner nodes so the two
can never be confused. The single hash at the top, the **root**, commits to the whole log.

With that root you can prove one entry is in the log using about log2(n) hashes, and prove
a newer log is a pure extension of an older one. Phase 0 builds the tree and the roots;
serving those proofs is Phase 1.

## Checkpoints and the quorum

Periodically the validators sign a **checkpoint**: 81 bytes holding the epoch, the log size,
the Merkle root and the hash of the latest entry. A checkpoint is valid only if:

- its size, root and head match the chain you are holding,
- its epoch matches the current trust configuration,
- enough validators signed, and
- enough independent witnesses cosigned.

"Enough validators" is `n - (n-1)/3`. With 1, 4 or 7 validators that is 1, 3 or 5 signatures.
The arithmetic is chosen so any two quorums overlap in at least one honest validator as long
as no more than a third are faulty. Signatures from keys outside the configuration are
ignored and never counted, and one admitted key signing twice is an error.

**Witnesses** are the piece that stops a split view. If an operator wanted to show you one
history and someone else another, both histories would need witness cosignatures, and an
honest witness won't sign two different histories for the same point in the log.

## What the verifier says when something is wrong

Errors are stable strings that the test vectors assert exactly: `bad_signature`,
`bad_prev_hash`, `bad_height`, `root_mismatch`, `below_quorum`, `duplicate_signer` and so
on. That matters because a second implementation, in any language, can be tested against the
same file and has to fail the same way, not merely fail.

## Design choices worth knowing

- **Standard library only.** SHA-256 and Ed25519 come from Go's standard library, and the
  core has no third-party dependencies. Cairn writes the protocol, never the primitives.
- **Small on purpose.** The verifier has a budget of 1,500 lines and is about 900 today,
  small enough to read in an afternoon. CI fails if it grows past the budget.
- **Strict decoding.** Trailing bytes, short input, bad UTF-8 and oversized lengths are all
  rejected, and length limits are checked *before* anything is allocated, so hostile input
  can't make the verifier run out of memory.
- **Time is advisory.** Order comes from height, never from a clock an attacker could set.

## The rules on top of the chain

The chain proves *authenticity*: these entries are exactly what was signed, in this order.
It doesn't yet prove *lawfulness*: that the author was allowed to write that kind of entry.
Roles are in the trust configuration (validator, witness, reviewer, security reviewer,
proposer, agent), and the governance rules in the constitution say who may do what and how
long a change must wait:

| Tier | Examples | Minimum delay |
|------|----------|---------------|
| T0 | Tighten a limit | none |
| T1 | Prompt wording | 24 hours |
| T2 | New tool, model swap | 72 hours |
| T3 | Permission changes | 7 days |
| T4 | Gatekeeper code, the constitution | 14 days |

Enforcing those rules is the Phase 1 state machine, and it is **not built yet**. Phase 0
verifies authenticity only, and the docs say so in several places on purpose.

## Try it

```
git clone https://github.com/cockyapple/cairn.git && cd cairn
make test     # unit tests, vectors, and an independent re-derivation
make loc      # verifier size against the 1,500-line budget
```

Then open `testdata/vectors-v1.json` and try writing a verifier in your favourite language.
If your implementation and the Go one disagree on any vector, one of them has a bug, and
finding out which is exactly the point.
