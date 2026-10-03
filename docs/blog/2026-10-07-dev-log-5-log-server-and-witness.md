# Dev log 5: a log server you can append to, and a witness that doesn't believe it

*Part 8 of the Cairn series. Two pieces landed: a server that sequences the log, and a second program that checks the server and signs only what it can verify. This one is mostly about what the tests found.*

Dev log 4 ended with an admission: nobody could append to a Cairn log over a network,
because there was no log server. That is fixed. The second thing we said was missing, a
witness on a separate machine, is also built. Neither is production software, and the end
of this post lists what is still missing.

## The log server

`cairn-logd` is a sequencer. It is the one process that decides the order of entries. The
design rule is that nothing in it needs to be trusted, because everything it stores can be
re-checked by `cairn-verify`. The server holds **no signing keys**. Validators and witnesses
fetch the 81-byte checkpoint body, sign it themselves and post the signature back. The
server publishes a checkpoint only once the signatures it holds pass the same check a
verifier would run.

Before it accepts an entry it checks, in order: the request parses, one blob matches the
entry's payload hash, the author is in the current trust configuration, the signature is
valid, the author's rate limit, the height and previous hash, the entry's date against the
server clock, the size caps, and finally that **the whole log plus the new entry still
replays under the governance rules**. If the replay fails, nothing is written. So the log on
disk is always one that the verifier accepts.

Three decisions worth explaining:

- **The storage directory is the verifier's input.** `entries.bin` is the entries
  concatenated and `blobs/` is a directory of files named by hash. There is no second
  format to trust.
- **An empty log accepts only a genesis entry from a configured author.** Without that, the
  first writer to reach a fresh server would own the log.
- **Start-up replays everything and refuses to run on any inconsistency.** A torn final
  entry is cut off; a bad chain, a blob whose name is not its hash or a missing payload
  refuses to start.

The cost is real. Every append replays the whole log, which is O(n). It is bounded by a
configured maximum, and we have not built anything faster.

## The witness

A checkpoint signed only by the log's own validators proves little to an outsider: the
people who could rewrite history are the people signing. A witness is a signer who is not
one of them.

`cairn-witness` runs on a different machine. Each cycle it downloads the whole log and
replays it under the same governance rules the server enforces. Only if the replay passes
and its own key is an admitted witness at that log size does it sign the checkpoint and post
the signature. Refusals have stable names, and two of them are alarms:

- `log_shrank`: the server now has fewer entries than this witness has already signed.
- `history_diverged`: the first entries differ from what this witness signed before.

The rest are ordinary refusals: `unavailable` (the server could not be reached or did not
supply a blob), `invalid_log` (the log breaks the rules), `not_a_witness`, `wrong_genesis`
(a pinned first entry does not match), `stale_size`, `bad_request`, `state_error` and
`submit_failed`.

The part that matters most is the order of two writes. The witness keeps a small state file
(size, Merkle root, head hash). It writes and flushes that file **before** it posts the
signature. If it crashes in between, it remembers signing something it never delivered,
which is safe, because the next cycle signs the same thing again. The reverse, a signature
out in the world that the witness has no record of, cannot happen. A test makes the state
write fail and checks that no signature is sent.

It also treats the server as hostile. Every response is bounded: entries, blob size, blob
count, total blob bytes. Every blob is checked against the hash it was requested by. On
growth it re-reads only the last entry it holds plus the new ones, and compares that entry
byte for byte, so a cached prefix can't go stale without being noticed.

## What the tests found

The server has 40 tests and the witness 47, counting subtests. Counting tests is the easy
part, so here is what hunting for bugs turned up.

**Mutation testing on the witness.** We wrote 29 deliberate bugs, each removing or inverting
one check, and ran the tests against each. After the first round of tests, **seven survived**:
the tests passed with the bug in place. Those were real gaps:

- No test broke the `prev_hash` link while keeping the heights right, so the chain-link
  check could have been deleted.
- Nothing exercised the maximum-entries limit.
- Nothing asserted the exact refusal for a response that was not a whole number of entries.
- **Nothing ran above epoch 0.** The witness passes an epoch to the checkpoint it signs. A
  witness that always signed epoch 0 would have produced signatures the verifier rejects
  after the first validator-set change, and every test would still have been green. The new
  test performs a real validator rotation (a proposal, three approvals, the 14-day delay,
  the epoch entry) and checks the witness signs epoch 1 and that the result verifies.
- Two defensive lines turned out to be unreachable, so we deleted them instead of testing them.

All 29 are now caught. Three more mutants of the fixes below are also caught.

**Gemini audit of the log server.** Three findings, all valid. A blob length parsed with an
`int` would go negative on a 32-bit platform when the top bit was set, and the slice
would panic: fixed. A crash between writing blobs and writing the entry could leave unused
blobs counting against the storage cap: fixed with a staging step. A third said we checked
the signature before the cheap checks, against our own "cheapest first" comment. That one
was deliberate (a signed request is the unit of load, and a rate limit should be charged only
to a key that proved it holds the private key), so we corrected the comment.

**Gemini audit of the witness.** Three findings, all valid, none serious. If the server had
rolled back and the operator asked for a size larger than the rolled-back log, the witness
said `bad_request`, which is not an alarm, instead of `log_shrank`. A fetch loop made one
useless request after it had everything it needed. And the run loop did not log the moment a
checkpoint became complete when nothing else had changed. Fixed, each with a test that fails
without the fix. Gemini found no problem with the write ordering, the fork check, or the
cache rule, and we did not take that as proof: it is one reviewer reading code.

**What CI found that none of those did.** The first push failed. Under the race detector
everything runs slower, and stopping the run loop while a cycle was in flight logged
"not signed: context canceled" as if the server had refused. That is a real bug in a
program whose log lines are the alarm channel. Our local test runs did not use `-race`,
because the Go image we used has no C compiler. We fixed the loop and now run the race
detector locally in an image that has one.

## What is still not built

- **The witness has never run on a separate machine.** The tests start the real log server
  and the real witness code and connect them over HTTP on loopback. That checks the logic,
  not a network, a firewall, or a clock that disagrees. "Built" here means built and tested
  in one process tree.
- **No gossip between witnesses.** Two witnesses cannot yet compare notes. A server could
  show one witness one history and another witness a different one, and each would be
  satisfied. This is the largest remaining hole in the split-view story.
- **Not the C2SP witness protocol.** Our witness speaks a small Cairn-specific protocol, so
  it will not interoperate with other people's witnesses or tile-based clients.
- **O(n) replay**, on both the server (per append) and the witness (per cycle). Fine for a
  small log, not for a large one.
- **No TLS, no authentication on reads, one server, one key per witness.**
- **Replication.** One sequencer is one point of failure.
- Hash-only action payloads, review-approval rules in the replay, and language-neutral
  vectors for proofs and governance are still on the roadmap.

The verifier core is still 1,186 lines against a self-imposed budget of 1,500. The server and
witness live outside it; the only change to the core was one exported signature check.

## Next

Next we are handing the whole project, code and phase plan, to a different vendor's model for
a full audit, and we will publish what it finds, including anything that embarrasses us.

Everything is in the repository: <https://github.com/cockyapple/cairn>. The two designs are in
[docs/LOG-SERVER.md](https://github.com/cockyapple/cairn/blob/main/docs/LOG-SERVER.md) and
[docs/WITNESS.md](https://github.com/cockyapple/cairn/blob/main/docs/WITNESS.md).
