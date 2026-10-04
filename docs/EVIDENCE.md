# Evidence for the testing claims

Cairn's documents say things like "all mutants are killed". This page says where those
numbers come from, how to reproduce them, and what they do not show. The raw outputs of the
runs described here are in `docs/evidence/`.

## What was run

| File | Command | Result |
|---|---|---|
| `evidence/tests-race.txt` | `go test -race -count=1 -v ./...` | 327 top-level tests passed, 0 failed, 0 skipped; 212 subtests passed. Every package with tests reports `ok`. |
| `evidence/mutation.txt` | `go run ./internal/mutate -j 3` (about four minutes) | 157 mutants: 149 killed, 8 equivalent, 0 survived, 0 invalid. |

Both ran in the pinned `golang:1.24-alpine` image (Go 1.24.13). The race run needs cgo, so it
installs `build-base` first. Each file records the commit it ran on. The runs were made on the
commit before the one that added them, plus the changes in that commit, so the commit hash in
the header is the base, not the exact tree.

## What a mutation run is

`internal/mutate` reads `testdata/mutants.json`. Each entry names a file, one exact piece of
source text, and a replacement. For each entry the tool copies the repository to a temporary
directory, makes that one substitution, and runs the tests of the mutated package, then, if
they pass, the tests of the whole repository (another package may be the one that notices).
The repository itself is never changed.

| Verdict | Meaning |
|---|---|
| killed | The tests fail, or hang past the timeout, with the change. This is the good outcome: the tests notice the behaviour. A kill by timeout or by another package is labelled as such. |
| survived | The tests still pass. Either a test is missing or the change does not alter behaviour. |
| equivalent | A survivor that the list declares, with a written reason, cannot be told apart by any test. |
| invalid | The text was not found exactly once, or the mutant does not compile. This is reported, never hidden, because a mutant that does not apply tests nothing. |

The tool first runs the unmutated tests, on a copy of the repository, and stops if they fail. It exits non-zero unless every
mutant is killed or declared equivalent, and CI runs it as the `mutation` job.

To reproduce:

    make mutate                        # in the pinned container
    go run ./internal/mutate -only witness:    # a subset, by name

## The eight equivalent mutants

They are listed in `testdata/mutants.json` with their reasons. They are the part of this page
most worth checking, because "equivalent" is a claim the author makes about their own gap.

- **witness: root check** and **witness: head check.** The witness compares the first N
  entries of the log against the root and head it stored when it last signed. Either check
  alone is enough: by the time the comparison runs, `fetch` has verified that each entry links
  to the one before, so a changed entry changes the head, and the root commits to the last
  entry. Removing one leaves the other doing the work. Removing both is a separate mutant
  (**whole seen-prefix comparison removed**), and the tests kill it.
- **witness: fetch empty page.** An empty page is also a short page, and the short-page check
  just below refuses it with the same error code. The branch exists to give a clearer message.

- **grant: self delegation.** A key that delegates to itself already holds a grant (it had to,
  to pass the parent check), so the "receiving key already holds a grant" rule just below
  refuses it with the same code. The self check gives a clearer message.

- **policy: applied entries stay scheduled** and **policy: an earlier policy is not dropped by a later one.**
  The require-grants rule (SPEC 10.3.4) keeps a list of activated changes and, as each comes
  into effect, drops the ones activated before it. The last entry in activation order that has
  come into effect always wins, so an entry left in the list is never the one chosen once a later
  one is, and one that is chosen again sets the value it already set. The dropping only bounds
  the list.
- **policy: not promoted after the last entry.** Every entry is promoted at its own time before
  it is applied, and a T3 or T4 activation is delayed at least 7 days, so no policy can come into effect
  between the last entry and the end of the replay. The call mirrors the root-grant promotion
  beside it.
- **gatekeeper: an action is retried as an event when grants are required.** Retrying an
  agent action in the bound form writes a Use blob, which the replay refuses with the same
  `no_grant`; the narrower test only says that the retry is meant for a gatekeeper record.

If you read these and think a test should exist anyway, you may be right: these are defence in
depth, and a test that pins the message would kill the third and fourth. They are marked equivalent
because they do not change what the witness accepts or refuses.

## What the numbers do not show

- **A hundred and fifty-seven mutants is a small sample.** They were written by hand, mostly against the witness
  (32 of 157) and the grant, delegation, use, policy and opening-store code (over 80), because that is where the earlier
  audits found gaps and where the newest code is. Packages with no entry in
  the list, such as `ledger` and `wire`, have not been mutation tested by this tool at all. A
  clean run says these 157 changes are noticed; it says nothing about changes nobody wrote.
- **The mutants are the author's own.** They were chosen by the same person who wrote the
  tests. A tool that generated mutants mechanically would be a stronger check. This is an
  honest start, not a mutation score.
- **A kill means a test failed, not that the right test failed.** The tool does not check which
  test caught the mutant.
- **The race run is one run on one machine.** It shows the suite passed once under the race
  detector. It is not a soak, and it does not cover the fuzz targets, which CI runs for 20
  seconds each.
- **The earlier "29 mutants" figure** in `docs/DECISIONS.md` (ADR-20 addendum) came from a
  throwaway script that was never committed, so it could not be reproduced. The witness
  entries here are a re-fitted version of that script, adapted to the witness as it is now. The
  first run of this tool found five survivors that the old figure did not predict; the section
  below says what became of them.

## What the first run of this tool found

The first run of the committed list left five survivors and two invalid entries. That is the
reason to publish the tool and not the claim.

- **Two real gaps, now tested.** No test gave the witness a chain whose entry has the right
  link but the wrong height (`TestRefusesAnEntryWithTheWrongHeight`), and no test gave
  `LoadBundle` a single blob over the per-blob cap (`TestBundleRefusesAnOversizedBlob`). Both
  mutants are killed now.
- **Three equivalent mutants,** described above.
- **Two invalid entries.** One no longer matched the source after earlier fixes; the other was
  a mistake in the new mutant (it did not compile). Both were re-fitted.

## Review of the tool itself

Gemini reviewed `internal/mutate` and the two new tests. Four findings were right and are fixed:
the baseline ran on the live tree instead of a copy (a copy that lost something would have been
blamed on every mutant); the context timeout equalled go test's own, so a hung mutant could
leave its test binary running; only the mutated package's tests ran, so a mutant caught only
elsewhere would have been called a survivor; and an interrupt left temporary directories behind.
Three findings were checked and rejected: that the two new tests pass vacuously (each is killed by its own mutant, which is the evidence that it does not), and a loop-variable
race that cannot occur under `go 1.24` in `go.mod`.
