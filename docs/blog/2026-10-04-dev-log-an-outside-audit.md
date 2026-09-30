# Dev log 2: we had another AI audit our blog

*Part 5 of the Cairn series. An outside review found two real problems and one wrong complaint.*

A project that says "don't trust, verify" shouldn't grade its own homework. So after
[posts 1 to 4](2026-09-30-why-cairn.md) were written, we gave all four to a different model
family (Google's Gemini) together with the real SPEC and the raw output of the
[tamper suite](2026-10-03-dev-log-breaking-our-own-log.md), and asked it to be adversarial:
find factual errors, overclaims and flawed security reasoning.

It scored the series 7.5 out of 10 and raised five points. We checked every one against the
repository instead of taking its word. Here is how they came out.

## Real: the SPEC named two error codes differently from the code

The SPEC said a checkpoint with too few witnesses fails with `below_witnesses`, and a
malformed checkpoint with `bad_checkpoint_length`. The code, and the committed test
vectors, use `below_witness_threshold` and `bad_checkpoint`. The vectors are the
ground truth, so the SPEC was wrong. A second implementation written from the SPEC would
have failed the vectors.

This is exactly the sort of thing the project exists to prevent, and our own CI missed it,
because nothing compared the SPEC text with the code. **Fix:** the SPEC now matches the
code, and a new test fails the build if the list of error codes in SPEC section 7 and the
codes in the `ledger` package ever differ.

## Real: "log before act" conflicts with the ACTION entry's result hash

Our constitution says the gatekeeper writes an ACTION entry *before* it executes. But the
ACTION entry carries a `result_hash`, a commitment to what the action produced, and that
cannot exist until the action has run. As specified, one entry cannot do both.

We hadn't noticed. The audit did, and it is right. Candidate fixes are in the decision log
(ADR-13, left open on purpose): write the entry first with an empty result and then a
second one with the real result, or add a separate RESULT kind. Either way intent is
committed first, and an intent with no result becomes a signal in its own right. Until that
is decided, the posts no longer claim more than "every action is recorded".

## Partly right: "a poisoned page can at worst produce a bad summary"

Post 1 said this about the reader agent, and the audit called it a false sense of
security: if an injection makes the reader output a clean-looking but malicious summary,
the actor will act on it. That is true, and our own injection-defense document already
says the reader and actor can both be fooled. Only the blog sentence overclaimed. The
design's actual guarantee is about *authority*, not correctness. A fooled reader cannot call
a tool, and a fooled actor is still held to a capability grant, spending caps and human
approval for anything irreversible. Post 3 said this correctly. Post 1 now does too.

## Unclear wording: the checkpoint in the tamper test

Post 4 described the test checkpoint as "4 validators, 3 needed, plus 2 witnesses" and
also as 565 bytes. Those sound inconsistent unless you know the checkpoint was signed by
exactly 3 validators and 2 witnesses (five signatures, 565 bytes). The 6-signature case
belongs to the later surplus-signers experiment. Reworded.

## Wrong: "structural attacks die on other codes"

The audit said our summary of how structural attacks fail was imprecise, because
swapping or substituting entries should break the hash link (`bad_prev_hash`). The test
output shows those attacks are caught earlier, on height or genesis (85 and 1 of the 94), and
the remaining 8 on checkpoint size. `bad_prev_hash` shows up in the bit-flip run
(1,792 times), not in the structural one. The post was correct, and we left it alone.

## What we take from it

- **Scoring a model's review is itself a measurement.** Two of five points were real
  defects, one was a fair wording complaint, one was clarity, one was wrong. We did not
  apply any of it blindly.
- **A different model found what we and our own tests missed.** The error-code drift and the
  result-hash conflict were both invisible to the author and to CI. That is an argument for
  independent review, and the reason to eventually test models against the same attack corpus.
- **The fixes became tests or decisions, not just edits.** One is now a CI check, the other
  an open ADR.

Both fixes are in the repository: <https://github.com/cockyapple/cairn>.
