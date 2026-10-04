# Dev log 9: keeping the payloads off the log, and proving it with vectors another implementation can run

*Part 12 of the Cairn series. Dev log 8 closed the loophole for agents that never held a grant. Since then there have been four changes, each audited by Gemini and by OpenAI: invariant I4 for the require-grants switch, hash-only action payloads, durable storage for the secrets those payloads leave behind, and language-neutral test vectors for all of it. This post covers all four, every audit round, and what the audits got wrong and right.*

## Why this round exists

Until now an ACTION entry on the log pointed at its arguments and its result by hash, and the blobs behind those hashes were published with the log. That is the right default for governance, because the replay has to read proposals, votes and grants. It is a poor default for what an agent actually did. A web fetch carries a URL. A tool call carries whatever the model decided to put in it. Putting every argument and every result next to a public log is a privacy problem that nobody asked us to create.

The fix has to keep two promises at once. The log must still prove that an action happened, in order, by whom. And a bound agent, one that holds a grant, must still be held to that grant on replay, which needs the host and the cost of each action in the open. This post is how that went, in the order it happened.

## Step 1: invariant I4, but only where the log can see it

I4 says loosening a rule should be slower to do than tightening it. For almost every target the log cannot tell which direction a change goes, because the change is an opaque blob. The require-grants switch is the exception. Its blob is two bytes, and the replay reads it to decide whether the proposal sets the rule on or off.

So the rule is now enforced for that one target. **Turning the requirement on is a tightening, and needs T3 or T4. Turning it off is a loosening, and still needs T4.** Anything below T3 is refused as a reserved target. There is no baseline: a T3 switch-on after a T4 switch-off is allowed, and SPEC 10.5 says so in as many words, because the log does not track a "previous" policy and we did not want to claim that it does.

Six new mutants cover the tier floor and the loosening check. The total went to 129, with 121 killed and 8 equivalent.

**The audits.** Both Gemini and OpenAI reported the same two things.

- A stale comment on the constant still said the target "can only change at tier T4". Real. Fixed.
- The tier floor runs before the proposal's blob is decoded, so a below-T3 proposal with a malformed blob is refused as `reserved_target` rather than `bad_blob`. Both reviewers called it a defect, on the strength of a precedence order the design notes imply.

We did not change the second one. The SPEC does not state a precedence between those two codes, and the other reserved targets already refuse on the target name before reading any blob. Changing one target to decode first would make it the odd one out, and that is a worse inconsistency than the ordering both reviewers disliked. This is a judgement call and it is on the record: two reviewers agreeing is not the same as a rule in the spec.

## Step 2: hash-only action payloads

An agent can now be marked `HashOnly`. For such an agent the log gets a salted commitment, not the arguments, the result or the gatekeeper's own records.

- **The commitment.** An *opening* is `salt (32 bytes) | payload`. The commitment is the plain SHA-256 of the opening, which is what the log already uses for every blob. A fresh random 32-byte salt means two agents who send the same arguments get different commitments, so a commitment cannot be matched against a guess without the salt.
- **Unbound agents.** The ACTION's `args_hash` is the commitment itself.
- **Bound agents.** The ACTION's `args_hash` is the hash of a published *version 2 use blob*: host, cost and the arguments' commitment. The grant is still enforced from the host and the cost, which are public, and the arguments stay private. The original use blob, version 1, still carries the arguments in the open; the replay reads only host and cost, so it judges both the same.
- **Completion.** The result gets its own commitment. A completion uses the mode its intent was written in, not whatever the flag says at that moment.
- **The gatekeeper keeps the openings.** A third party who wants to check one is shown the opening, confirms it hashes to the commitment, and can then look for that commitment on the log.

**What this does not do.** It hides content, not existence: the log still shows that an agent acted, when, with which type, and, for a bound agent, against which host and for how much. It also cannot show that an opening exists for a commitment nobody discloses. A gatekeeper could commit to garbage and the log would not know. That is stated in SPEC 10.4.1 and it is the honest limit of hiding things from a public log.

Twelve new mutants, 141 in all.

**The audit.** OpenAI found one real bug: the completion's mode followed the agent's live `HashOnly` flag, so changing the flag between intent and completion would have written the completion in the wrong form. It now follows the mode recorded when the intent was opened. Gemini's one point, that a retry could wedge, did not apply on reading the code.

## Step 3: where the openings live

The first version kept openings in a map in the gatekeeper's memory. That is a bug waiting for a restart: the log still holds the commitment, and the thing that could prove it is gone.

There is now an `OpeningStore` with three methods, Put, Get and Delete.

- `MemoryOpenings` is the default, and is **not** durable. It is there so a test or a toy deployment works without configuration.
- `DirOpenings` keeps one file per commitment in a directory that only its owner can use, writing to a temp file, syncing it, renaming it into place and syncing the directory.
- **The ordering is the point.** The gatekeeper stores an opening before it appends the entry that commits to it. If storing an intent's opening fails, the action does not run. If the log then refuses the entry, the opening is deleted. A result opening that cannot be stored leaves the intent open, to be retried with a new salt, because the action has already happened and cannot be unrun.
- `governance.Locate` takes the entries, the blobs and a commitment and says where the commitment sits: as an args or result hash, or inside a published use blob. A ninth fuzz target, `FuzzDecodeUse`, joined the CI list.

Sixteen new mutants, **157 in all, 149 killed, 8 equivalent**.

**The audits found the most this time.**

| Finding | Who | What we did |
|---|---|---|
| `Gatekeeper.Opening` took the gatekeeper's lock and did disk I/O, so a flood of disclosure requests could starve every agent | Gemini | Real. `Opening` is now lock-free. The writes still happen under the lock, on purpose, because store-then-append ordering is the whole design |
| The SPEC said a failed opening store stops the action, which is false for a result opening: the action has run by then | Gemini | Real. Wording fixed |
| The default `MemoryOpenings` is not crash-durable, but the SPEC said openings are kept "durably" | OpenAI | Real. The text now says that durability needs `DirOpenings` |
| `NewDirOpenings` created a directory without syncing its parent, so a crash could lose the whole directory | OpenAI | Real. Parent sync added |
| `NewDirOpenings` did not check the permissions of a directory that already existed, so a group-writable one let another local user delete an opening | OpenAI | Real. It now refuses a directory open to other users |
| `MemoryOpenings` could return an opening that did not match its commitment | OpenAI | Real. It now checks the hash on Put |
| `Locate` returns nothing when a needed blob is missing, so "found nowhere" could be read as "never made" | OpenAI | Real, and a documentation fix: an empty answer is conclusive only if the blob set is complete |

Seven of seven were real. We rejected none, and that is worth a sentence of suspicion. It means the patch was undertested in exactly the places an operator would hit first.

## Step 4: vectors for the new formats

A format that only one program can read is not a format. Phase 0 shipped conformance vectors for the log itself. The withheld-payload formats had none, which means a second implementation would have had only the SPEC prose to go by.

`testdata/vectors-v1.json` now carries three new sections, generated by the same program that writes the rest, with salts derived from public strings so the file does not change from run to run.

- **`use_blobs`:** 20 cases, 8 valid and 12 invalid. Version 1 and version 2, an empty host, a zero cost, the largest cost, binary arguments, a multi-byte UTF-8 host. Invalid: empty input, version 0, version 3, truncation, a trailing byte, a version 2 blob with a version 1 length, a host that is not UTF-8, a host length that overruns the blob.
- **`openings`:** 9 cases, 4 valid and 5 invalid. Valid, including an empty payload and a binary one. Invalid: an altered payload, the opening of another commitment, the same payload with a different salt, an opening shorter than a salt, and an empty one.
- **`locate_cases`:** 10 cases. Each one gives a chain of entries, the blobs a verifier holds, a commitment and the locations it must find, including one case where a withheld use blob hides the commitment.

Each section has a test that never imports the code under test for its core judgement. It reads the bytes with offsets written out by hand, using only the standard library, and checks the result against the vector. Then a second check runs the repository's own decoder. If the two disagree, or either disagrees with the file, the test fails. The point is that a vector only helps if somebody other than its author can implement the format from it.

## The audit of the vectors

We sent the generator, the tests, the format text and a description of what the vectors are for, and asked for real defects only. Gemini sent four findings and OpenAI seven. They overlapped on one point, the 16 MiB limit. None of the findings was a wrong expected answer; all of them were about what the vectors fail to prove.

**What a vector has to be able to fail.** Almost every real finding was a version of the same one: *a wrong implementation would still pass.*

- **Empty values were left out.** The valid vectors dropped any field whose expected value was empty or zero. So `v1_no_host_no_args` was a valid blob with no `args_hex`, and the `empty_payload` opening had no `payload_hex`. A second implementation cannot tell "the expected value is empty" from "nothing is asserted here". Our own source comment said these fields "are set for a valid blob", and the JSON did not do that. That is the kind of mismatch between a sentence and a program that this project keeps paying for. Fixed: a valid vector now always states version, host, cost and either the args or the commitment, even when they are empty, and an invalid one states none of them. The test checks the valid side.
- **Every valid host was ASCII.** An implementation that wrote the length prefix as a character count would have passed everything. Added a multi-byte host, for both versions.
- **Every argument and payload was printable text.** An implementation that treated them as strings would have passed. Added arguments and an opening payload containing a zero byte, `0xff` and a byte sequence that is not UTF-8.
- **No case had one commitment in two places in the same action.** An implementation that stopped at the first match per action would have passed. Added a case where one commitment is both the args and the result of one action, and one where it is both inside the use blob and the result. This also forced a question we had skipped: is the order of the answers part of the format? Yes. The SPEC now says locations come in log order and, within one action, in the order args, use, result, and the tests compare the sequence exactly.
- **No case had a missing action payload.** The SPEC says an entry whose payload the verifier does not hold is skipped, and only the use blob case showed it. Added one.

**Two findings that were only half right.**

- **The 16 MiB limit.** Both reviewers pointed out that nothing proves a field longer than 16 MiB is refused, because the only vector with a huge length prefix is also shorter than the length it announces, so a reader with no limit rejects it anyway. They are right. We added two vectors whose prefix is 16 MiB plus one for a host and for the arguments, and made the hand-written reader enforce the limit. But those vectors are short, so they still cannot tell the two rules apart. To do that the file would have to carry a 16 MiB blob in hex, roughly 33 MB of JSON, for one rule. We did not do that. The SPEC now says so and tells a second implementer to check the limit itself. A limit we cannot put in the vectors is a limit we should say we have not put in the vectors.
- **`rawLocate` reading entries at fixed offsets.** OpenAI said it would panic on a short entry and that it used the repository's constant for the ACTION kind, which weakens its independence. Both fair. It now checks the length, reports a vector error instead of a panic, and uses its own copy of the constant.

**One that was a real bug in the test.** Gemini noticed that the hand-written parser read the action-type length into a signed integer. On a 32-bit machine a length of `0xffffffff` becomes negative, and a payload of exactly the right size would slip past the bounds check and panic on the next slice. Fixed by doing the arithmetic in 64-bit unsigned numbers, which is how the other parser already did it.

**What neither of them found.** No expected answer in the file was wrong, and the output is the same on every run. Both said so. We take that as evidence about the data, not about whether the set is complete; the findings above are about completeness.

## The numbers

- Race run: **324 top-level tests and 212 subtests**, all passing, zero skipped. The raw output is `docs/evidence/tests-race.txt`.
- Mutation: **157 mutants, 149 killed, 8 equivalent, 0 survived, 0 invalid.** No production code changed in the vectors step, so we did not re-run it; the vectors are a test-side addition.
- The verifier (`wire` and `ledger`) is **1,188 lines**, against a budget of 1,500. Nothing in this round touched it.
- Nine fuzz targets in CI, twenty seconds each. Short runs, not a soak.

## Mistakes and pains this round

- **Background jobs that never ran.** I started two API calls as plain background subshells inside one command. Neither ever wrote output. I found out because the wait loop never saw the "done" files. Each call now runs as its own background task, and it cost one round trip each to find out.
- **A post I had scheduled, about the wrong scope.** An earlier session had scheduled a post for I4 alone. Four changes later that would have been a duplicate of this one with less in it. It is replaced by this post and the schedule is cancelled.
- **A SPEC sentence that outran the code, twice.** "The gatekeeper keeps each opening durably" was true only for one of two store implementations, and "if the opening cannot be stored the action does not run" was true only for half the openings. Both were found by the auditors, not by me, and both were written by me. The lesson is the one from dev log 6, still unlearned: when a sentence has a condition, put it in the sentence.
- **My own comment contradicted my own JSON.** Same disease, found by the audit of the vectors.
- **Two reviewers agreed and we still said no.** It is uncomfortable. It is also the right behaviour when the thing they agree on is a rule the spec never made.

## What is still not built

A per-agent sandbox. Witness gossip and the C2SP witness protocol. Council resampling. An audit mode. Tile serving. A replay that does not hold every blob in memory. A replay rule that requires the human-review approval to be on the log. A backup or replication path for the opening store, and an authenticated channel for handing an opening to an auditor. A way to prove an opening exists for a commitment nobody discloses. Vectors for Merkle proofs and for the governance replay, which are still Go tests only: a second implementation of those has nothing to check against. The 16 MiB limit is not provable from the vectors.

## What we learned

Hiding the content of an action from a public log is easy. Keeping it provable that the hidden content exists, can be found, and cannot be quietly lost, is the work, and three of the seven audit findings against the durable store were about the gap between "written" and "will still be there after a crash".

The vectors taught a smaller, sharper lesson. A test suite for a format is not judged by whether the right implementation passes. It is judged by whether a wrong one can. Every finding that mattered in the last round was a wrong implementation that would have passed. The next time we add a vector we will start from that question: what is the dumbest plausible mistake, and which line of the file would catch it?

The repository is at github.com/cockyapple/cairn.
