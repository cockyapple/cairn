# Dev log 1: we tried to break our own log

*Part 4 of the Cairn series. The first sandbox experiment, with real numbers.*

Parts [1](2026-09-30-why-cairn.md) to [3](2026-10-02-cairn-in-the-real-world.md) explained
what Cairn is and why. They were claims. This post is the first time we test one of them
in public: **if someone changes a single bit of the log, will an outside checker notice?**

The claim in the design is that an outside party holding only the log bytes, the
checkpoint bytes and the public trust configuration can detect tampering. Let's find out
how true that is.

## The sandbox

Every experiment in this series runs in a throwaway container:

- `golang:1.24-alpine`, no network at all (`--network none`)
- 1 GB memory, 2 CPUs, a process limit
- the source mounted read-only, with the work copy on a RAM disk that disappears afterwards

The code under test never touches anything real, and nothing it does can leave the
box. It is the same discipline we want from the agents Cairn will eventually govern.

One honest limit: the Go race detector needs a C compiler, which the offline container
doesn't have. CI runs `-race` on GitHub's runners. Locally I ran `go vet`, `gofmt` and
the full test suite without it.

## The setup

We take the known-good 8-entry test chain and its signed checkpoint (4 validators,
3 needed, plus 2 witnesses), then damage the encoded bytes and run the real verifier
(`VerifyLog`). A mutation passes the test only if the verifier **rejects** it. Three
kinds of damage:

1. **Every single-bit flip**, exhaustively. Not a sample: every bit of every byte.
2. **1,000 seeded random mutations:** multi-bit flips, random overwrites, truncation,
   junk appended, zeroed runs. The seed is fixed so anyone can reproduce the run.
3. **94 structural attacks** on the list of entries: delete one, duplicate one, swap
   neighbours, replace one with a copy of another, drop the head, cut the tail.

## Results

**Exhaustive bit flips: 15,912 tried, 0 accepted.** That is 11,392 bits in the chain
(8 entries of 178 bytes) and 4,520 in the checkpoint (565 bytes). Nearly all are caught
by the signature check (11,278). The rest are caught earlier or by other checks, each
with its own stable error code: a flipped prev-hash bit gives `bad_prev_hash`, a flipped
height gives `bad_height`, a flipped Merkle root gives `root_mismatch`, and so on.

**Seeded random mutations: 1,000 drawn, 992 actually changed bytes, 0 accepted.** The
8 that didn't were no-ops (for example zeroing bytes that were already zero), so they
don't count. The 992 were rejected under 15 different error codes.

**Structural attacks: 94 tried, 0 accepted by the full check.** Every reordering,
duplication, substitution and head-drop dies on `bad_height` or `bad_genesis`.

## Finding 1: a chain on its own cannot see its tail cut off

This one is obvious in hindsight, and worth saying out loud. Among the 94 structural
attacks, 7 distinct ones pass the *chain* check by themselves: cutting the log short
after 1, 2, 3, 4, 5, 6 or 7 entries (deleting the last entry is the same attack as the
last of these). A shorter chain is still a perfectly valid chain. Only the checkpoint
catches it, because it commits to the size (`size_mismatch`).

We also checked the mirror image: adding one more correctly signed entry after the
checkpoint was cut gives a valid chain, and the old checkpoint correctly refuses to
vouch for it.

The lesson for real deployments: **a verifier that checks the chain but not a recent,
quorum-signed checkpoint is not checking for truncation.** The spec already says to use
`VerifyLog`, not `VerifyChain`. Now there's a test that says why.

## Finding 2: some changes are accepted, and that is by design, but it has a cost

The main checkpoint has exactly enough signatures, so any damage to a signature removes
a needed one and fails. What if the checkpoint carries *surplus* signatures? We built one
with all 4 validators and both witnesses, where only 3 validators are needed, and flipped
every bit again.

**5,288 flips tried; 1,024 were accepted.** All 1,024 are in the same place: the
32-byte public-key field of a validator's signature. If one signer's public key is
changed to a stranger's, the verifier treats that signature as coming from a key
outside the trust configuration and ignores it, by the spec's own rule. Quorum is still
met by the other three, so the checkpoint verifies.

Is that a security hole? No. Nobody forged anything, and the checkpoint proves exactly what
it proved before. But it does mean the checkpoint's **bytes are not canonical**: two
different byte strings are the same valid checkpoint. Flipped *signature* bits by a key
that is still admitted were never accepted (0 of 3,072 in that run).

Two consequences, both now written down:

- Anything that identifies a checkpoint must use its body (epoch, size, root, head),
  not a hash of its encoding, or an attacker can make the same checkpoint look like
  many. This is now stated in `docs/SPEC.md`.
- Whether Phase 1 should tighten this (require sorted, admitted-only signatures so the
  encoding is unique) is an open decision, recorded as ADR-12. We'd rather have the
  argument in the open than discover it in production.

## What this does and doesn't show

It shows the verifier is strict about every byte it is handed, across about 17,000
corruptions. It does not show the design is secure. All these mutations are *dumb*:
none is an attacker who holds a key. The attacks that matter most (a compromised
validator, a split view served to different readers, an agent that lies in its
payload) are not things a byte-flipper finds, and we are not claiming otherwise. The
next experiments go after them.

## Reproduce it

```sh
git clone https://github.com/cockyapple/cairn && cd cairn
go test ./internal/vectorgen -run Tamper -v
```

The suite is `internal/vectorgen/tamper_test.go`. It takes about 9 seconds and is part
of CI.

## Next

Phase 1 is the governance state machine: who may propose what, which votes count, and
how the tier delays are enforced. The next sandbox experiment writes that as a pure
function of the log and then attacks it with randomly generated *valid* histories,
where every entry is correctly signed and the question is whether the rules hold.
