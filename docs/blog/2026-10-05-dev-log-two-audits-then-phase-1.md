# Dev log 3: two code audits, then the rules get teeth

*Part 6 of the Cairn series. Phase 1 is partly built, and we say exactly which part.*

A 53-second explainer is at the top of this post, in case you are new to the project. The
rest is what happened since the last dev log.

## Two models audited the code

We gave the verifier source (`wire/` and `ledger/`, about 1,100 lines) and the SPEC to two
different models, Google's Gemini and DeepSeek's reasoner, and asked each for real defects
only. Then we checked every claim against the code before touching anything.

Gemini returned three findings, all rated low. DeepSeek returned eleven, one rated high.
They agreed on the most important one and disagreed on its severity.

**Real, and the worst: small-order Ed25519 keys.** Go's standard library accepts a handful
of public keys that have no real private key behind them, for which one fixed signature
verifies on any message. An entry claiming such an author passed signature checks.
Gemini called it low because a reviewed trust configuration would never admit such a key.
DeepSeek called it high. We side with DeepSeek: chain verification does not look at who the
author is, so anyone could forge entries under that identity. Both are partly right, and the
fix is the same: entries by such keys now fail with `bad_signature`, a trust configuration
that admits one is `bad_trust_config`, and the check uses only the standard library.

**Real, smaller:** an empty checkpoint returned `bad_version` instead of `bad_checkpoint`;
a nil argument made the checkpoint verifier panic; a GENESIS with the wrong spec version or a
non-zero epoch was accepted; the key count in a trust configuration had no bound outside the
decoder.

**Not a bug:** DeepSeek said blob hashes should have a domain prefix like every other hash.
They are deliberately plain SHA-256 so anyone can reproduce one with `sha256sum`. The SPEC
wording was the thing that was wrong, and it now says so.

**Not changed:** a few low items about encoders that would accept oversized input from a
buggy caller. They are not reachable from hostile bytes, and we did not touch them.

The audit also made us decide two things we had been avoiding. Checkpoints are now
canonical: signatures must be in key order and from admitted keys only, so one valid
checkpoint has exactly one encoding, and the surplus-signer bit flips that used to slip
through are all rejected (ADR-12). And an ACTION is now two entries, an intent written
before the action and a completion after it, because one entry cannot commit to a result
that does not exist yet (ADR-13).

## Phase 1 so far

- **Merkle proofs.** Inclusion and consistency proofs per RFC 9162, tested exhaustively over
  small tree sizes and against Certificate Transparency reference roots.
- **Governance replay.** A new package replays a verified chain and checks the rules:
  which role may write which kind of entry, approvals and delays per tier, validator
  rotation, freezes and lifts, and the ACTION intent trail. It has 19 stable error codes.
  Every one is exercised by a test, and a second test fails the build if the SPEC and the
  code ever list different codes.
- **A verifier CLI**, `cairn-verify`, which takes the files and prints either what it
  verified or the exact error code.
- **Fuzz targets** for every decoder and the proof verifiers: they must not panic, and
  anything they accept must re-encode to the same bytes.

## Three things we caught in ourselves

1. **Tests that passed without testing.** The replay reported no open action intents even
   when one was open, and the test expecting zero agreed with it. Two tests looked
   suspiciously empty, and the code was wrong. After the fix we broke the code on purpose
   in ten different ways; every one is now caught.
2. **A constitution claim that could not be true.** It said approval counts "are set in the
   trust configuration". That structure has no such field. The counts are now fixed in the
   SPEC (ADR-14), and the constitution says so.
3. **An overclaim in our own SPEC.** A draft said one invariant was enforced when no wire
   format for it exists yet. It now lists what is *not* enforced next to what is.

## What is still not built

Be exact about this. There is **no log server** and **no witness running on a separate
machine**, so nobody can append to a log over a network yet. The proofs and governance
rules have Go tests but no language-neutral test vectors, so a second implementation could
not check itself against them. Of the constitution's invariants, replay enforces two (no
self-approval, and a freeze never blocks rollback). Semantic rules about what a change
means, the gatekeeper, and delegation are not enforced by any code today. And the delays
rest on entry times that the author writes, which are checked only to be non-decreasing.

Everything is in the repository: <https://github.com/cockyapple/cairn>.
