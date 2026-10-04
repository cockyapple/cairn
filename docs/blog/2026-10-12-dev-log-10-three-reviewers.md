# Dev log 10: three AI reviewers, one repository, and the findings that were wrong

*Part 13 of the Cairn series. Since Dev log 9 there have been three steps: language-neutral vectors for the Merkle proofs, an abuse catalogue with a warning in the verifier, and then the big one, a full review of everything by three different AI vendors. OpenAI read all the code. Gemini read all the documents. DeepSeek read both. This post lists what each of them found, what was real, what was wrong, and what went wrong on my side while I was doing it. These are AI reviews. They are not a professional security audit, and nothing here should be read as one.*

## Where Dev log 9 left off

Dev log 9 ended with hash-only payloads, durable opening storage, and vectors for those formats. It listed what was not built, and two items on that list were vectors for Merkle proofs and a catalogue of the ways someone could misuse the framework. Both are done now, so this post starts there.

## Step 1: vectors for inclusion and consistency proofs

The Merkle tree in Cairn follows RFC 9162. A proof format that only our own code can check is not much of a format, so `testdata/vectors-v1.json` now carries inclusion and consistency proof cases, valid and invalid, for trees of several sizes. The expected answers were re-derived by two separate implementations written with the standard library only, and the test fails if the file on disk is stale. The generator is `go run ./cmd/cairn-vectors`.

One of those checkpoint cases changed later in this post, and I will say which when we get there.

## Step 2: asking OpenAI how someone would abuse this

I asked OpenAI for an adversarial review of the documents, with one instruction: list the ways someone could abuse or misuse the framework, as examples, so we can look for them later or stop them without compromising the design. The result is `docs/ABUSE-CASES.md`. It started with 36 cases, each marked either acknowledged (the docs already said so) or a new gap, with what to watch for and a mitigation that leaves the core alone.

Only one change went into code. `cairn-verify` now ends every successful run with a single line saying that a pass is not proof of what any agent did, and not proof that any agent is safe. That sentence comes up again below, because it turned out to be too generous.

## Step 3: the three-vendor review

The request was to use OpenAI's top coding mode for all the code, Gemini's top model for every non-code document, and DeepSeek's top model for everything at once. I took that literally. Every model is the strongest that vendor exposes through its API: OpenAI `gpt-5.3-codex` at extra-high reasoning, Gemini `gemini-pro-latest`, DeepSeek `deepseek-v4-pro`.

**The rule for triage never changed:** each finding is checked against the repository before anything is done about it. A reviewer saying a thing is a bug is a claim, not a result. Where I could, I wrote a test that would fail if the claim were true.

### OpenAI, on the code: 17 findings in three passes

The code was split into three parts so each fit in one request. Seventeen findings, and this is how they sorted:

- **Fixed with a code change (13):**
  - `note.ParseVKey` split a verifier key on `+` without a limit, so a key whose name contained a plus parsed as something else.
  - `governance.Locate` found a commitment inside a blob without checking that the blob was the one the entry committed to.
  - Withdrawing a grant recursed once per delegated child and scanned the whole grant map each time. A flat tree of delegations made that quadratic, and a deep chain risked the stack. It is now iterative.
  - The log server kept references into a large buffer, so a small blob pinned a big allocation in memory.
  - Nothing stopped two log servers from opening the same directory. There is now a process lock.
  - A negative clock value, in the log server and again in the witness, disabled the future-entry check, because `Now == 0` means "no check". There is now one helper that clamps the time to at least 1.
  - `Server.Blob` handed back the server's own slice, so a caller could change stored data.
  - The provider adapter followed redirects, and a redirect to another host would have carried the API key with it. It now refuses to follow one.
  - A failed proposal left staged blobs behind.
  - The verifier's blob limit was checked against a count that could be bypassed with many small files.
  - A time-of-check, time-of-use gap when reading a bundle.
  - A very large diff could exhaust memory in the review view.
- **Wording fix (1):** a baseline comment was not accurate.
- **Documented, not changed (1):** `review.Log` is not safe for concurrent use. The honest fix would be a mutex, but the type is documented as single-writer and every caller in the repository follows that. I wrote the limit down instead of adding a lock nobody needs.
- **Rejected (2):** a claim that `Sign` and `Cosign` panic on a malformed key (they behave like `ed25519.Sign`, which also panics, and the comment now says so), and a claim that the witness accepts trailing data in its state file. I tested the second one. It does not.

That is 13 real defects out of 17 from one reviewer, and several of them were of the kind a person gets wrong on a first read: an integer that can go negative, a map that is scanned in a loop, a slice returned by reference.

### Gemini, on the documents: 15 ranked findings

Gemini was given every non-code file and asked to rank the worst problems. About ten became document changes:

- **Stranded intents.** If a gatekeeper dies between logging an intent and logging its completion, the intent stays open forever. SPEC 10.4 now has a section on it, and the abuse catalogue has a case (O-02).
- **Why one signer can revoke.** ADR-20 now explains why REVOKE is allowed with a single signature and what that costs.
- **The cosignature wording** in `SPEC-NOTE.md` was ambiguous. Rewritten.
- **`SECURITY.md`** still read like a project with a stable release. It now says plainly that this is pre-release.
- **Witness memory.** A witness replays the whole log, so its memory grows with it. Added as case W-05.
- **`args_hash`** is plain SHA-256 with no domain prefix. That was true but never stated. It is stated now.
- **`local_only`** on a grant was described as if it worked. It is marked planned.
- **ADR-18** now records why the verifier flag for a minimum tier is what it is.
- **Bulk blob sync** is listed as a known limitation.

Three of Gemini's findings were about old blog posts: contradictory test counts, "Merkle vectors not built", and require-grants still in the roadmap. Those posts are dated records of what was true that day. I left them as written. This post carries the current numbers.

**Where Gemini was wrong.** It said duplicate votes in an activation are undefined. They are not: the code rejects them with `bad_vote_reference`. The spec did not say so, though, so I added the sentence. It also said a model named `gpt-5.5` does not exist. That claim was false. My guess, and it is only a guess, is that a model reviewing a document that names newer things than it knows will tend to call them mistakes.

### DeepSeek, on everything: 28 findings and a different kind of review

DeepSeek got the whole repository, code and documents, in one request. The call took about twelve minutes. It sent back 20 findings on the code and 8 on the documents, plus a cross-check of what each earlier reviewer had said, and a section on what those reviews missed.

**Important caveat: DeepSeek read the snapshot from before I had applied the OpenAI and Gemini fixes.** So it re-reported several bugs that were already fixed. That was my sequencing choice, and I would make it again, because the request was for a complete independent audit and a reviewer who sees the fixed code is not independent. But it means its count has to be read with that in mind.

What was new and real, and is fixed:

- **Unauthenticated reads could cost O(n).** The log server computed Merkle roots by hashing the whole tree for a status or checkpoint request, and any client could ask. It now keeps a small cache of roots keyed by size. A test compares every cached value against a fresh computation for every size.
- **"Authentic" overclaimed.** The verifier and the README said a log that passed was "authentic". Without a genesis you pinned yourself, a pass shows the log is internally consistent and followed its own rules, not that it is the log you meant to check. The scope notice now has three forms and none of them says "authentic". This is the finding I take most seriously, because it was wording I wrote.
- **Checkpoint signers with the wrong role.** `VerifyCheckpoint` admitted any key in the trust configuration, so a reviewer's signature could ride along on a checkpoint and the result was a second valid byte string for the same quorum. That is the malleability ADR-12 says we do not allow. Any signer that is not a validator or a witness is now refused as `unknown_signer`. **This changed a published vector:** `reviewer_signature_does_not_count_as_validator` used to expect `below_quorum`. It now expects `unknown_signer`, and there is a second case for a reviewer's signature added to an otherwise complete quorum. I regenerated the vectors file. Changing an expected answer in a published conformance file is the kind of thing that should be hard to do quietly, and it is recorded here.
- **Limits the verifier cannot read.** The log server would accept configuration limits above what `cairn-verify` is willing to load, so a server could produce a log its own verifier refuses. `Open` now refuses limits above the verifier's ceilings.
- **`gatekeeper.Strict` accepted JSON `null`** as a string. Refused now.
- **`Propose` did not check that an eval result decodes.** A proposal could carry an eval result no council could read. `Propose` now round-trips it and refuses.
- **The loader returned its internal slice.** It returns a copy.
- **A quadratic insertion sort** in grant ordering. Replaced by a standard library sort, with a test that sorts 200,000 items inside a time bound.
- **Stale status headers** in two design documents still said grants and replay enforcement were not built. They are.
- **When the log is broken**, reads were described as stopping. They keep being served from memory; appends and checkpoint signatures are what fail. The document now says so.

**Rejected:** `loadState` accepting trailing data. DeepSeek said it confirmed OpenAI's claim. My test shows it is false, so two models agreed on something untrue. I say that without a moral. Agreement between reviewers is not evidence.

**Left alone:** two functions, `promote` and `promotePolicy`, are still quadratic in a corner case. They are bounded by the number of governance activations, which cost a quorum of signatures each. I judged that not worth the extra code, and I wrote it down.

### What the three reviews say together

- **Real findings came from all three, and the wrong ones came from all three.** A reviewer is a source of leads, not verdicts.
- **They found different things.** OpenAI found concurrency, clocks, limits and aliasing in the code. Gemini found places where the documents disagree with each other or with the code. DeepSeek found a mix, including the wording problem and the checkpoint signer, because it saw both sides at once.
- **None of them could run anything.** All three read text. The fixes I trusted most were the ones where I wrote a failing test first.
- **No professional has looked at this.** Three models is three models. The README now has a short paragraph that says exactly that.

## The numbers

- Full race run: **347 top-level tests and 212 subtests**, all passing, none skipped. Raw output is `docs/evidence/tests-race.txt`.
- Mutation: ****157 mutants, 149 killed, 8 equivalent, 0 survived, 0 invalid.** The first run after the fixes reported four invalid mutants, because the code each one pointed at had been rewritten. I rewrote those four entries and ran the whole list again.**
- The verifier (`wire` and `ledger`) is **1,193 lines**, against a budget of 1,500.
- Nine fuzz targets in CI, twenty seconds each. Short runs, not a soak.
- The abuse catalogue is at **38 cases**.

## Mistakes and pains

I want these in the post, because the finished list of fixes makes the process look cleaner than it was.

- **A CI failure from gofmt.** One file, `disclosure.go`, was not gofmt-clean and CI caught it before I did. CI now has a gofmt step, and I run `gofmt -l` before every test run.
- **Using the wrong tool name.** I tried to call a tool named `bash` that does not exist; it is `Bash`. A trivial error and a wasted round trip.
- **The blog publisher is not executable.** `blogger-post.sh` gave "Permission denied" until I called it through `bash`. The same script crashed `md2html.js` once because I left out its output argument.
- **Blocked sleeps and polling.** The environment refuses long sleeps, and a poll loop is not how background work should be watched. I started jobs as separate background tasks and waited for their notifications. Earlier I had started two API calls as plain subshells inside one command, and neither ever ran.
- **A harmless error that looked worse than it was.** A script reported a missing `ext.js` once. It did not matter.
- **Huge output.** A reviewer's reply was big enough that the tool stored it in a file and I had to read it in chunks. I stopped pasting them in.
- **Compile errors in my own fixes.** I declared `readCapped` twice. I assigned with `:=` where there was nothing new on the left side. I wrote `seen >= maxBlobs` when it should have been `seen > maxBlobs`, an off-by-one that the new test caught. I called a method on a value type that had a pointer receiver.
- **A spec edit that landed in the wrong place.** A perl edit left a stray ".," in `SPEC.md`, and a new abuse case was inserted into the wrong section. Both were my edits and both were found by reading the diff.
- **Four mutants went invalid.** The mutation list matches source text exactly, and my fixes rewrote the text under four of them. The run said "4 invalid" rather than passing, which is the right behaviour, and fixing them was the price of having changed the code under a hand-written list.
- **A test I wrote was flaky.** `TestBlobReturnsACopy` picked a blob from a random map key, and sometimes that blob was missing or empty. It failed one run in a while. I made it deterministic and ran it thirty times.
- **A test I could not prove would fail.** To show that the loader copy test catches the bug, I reverted the fix with `sed`. It also removed the only use of the `bytes` import, so the build broke before the test ran. I restored the fix. I did not get the "would fail without the fix" check for that one, and I am saying so.
- **A scope notice that broke its own test.** Rewording the verifier's closing line made `TestVerifiesALawfulLog` fail, because the test expected the old ending. The fix was to put the genesis caveat before the "that is not proof" sentence.
- **A reviewer's claim I believed too early.** I nearly changed `loadState` on the strength of two reviewers. The test took a minute to write and it showed they were wrong.
- **DeepSeek was slow.** About twelve minutes, with no progress indicator. I waited for a notification.
- **A secret rule I will keep stating.** Every call passed keys only in headers, nothing was echoed, and no script that reads the secrets file was ever traced with `-x`.

## What is still not built

A per-agent sandbox. Witness gossip and the C2SP witness protocol. Council resampling. An audit mode. Tile serving. A replay that does not hold every blob in memory. A replay rule that requires the human-review approval to be on the log. Backup for the opening store and an authenticated way to hand an opening to an auditor. Governance replay vectors, which are still Go tests only. A genesis pin and a maximum checkpoint age in the verifier. Locking `review.Log` is documented, not done. And what is still entirely missing: a human professional who reads this code.

## What we learned

The cheapest finding to fix was the one that mattered most: a sentence in the verifier that said "authentic" when the code only knew "consistent". Wording that outruns the code is the same disease that Dev log 6 and Dev log 9 both named, and it showed up again. It was found by a reviewer who had never seen the intent behind the sentence.

The second lesson is about method. Three vendors reading the same code produced largely different lists, and each list contained at least one confident claim that was false. The work that held up was the work I did myself: read the claim, find the line, write the test, see it fail, fix it, see it pass.

The repository is at github.com/cockyapple/cairn.
