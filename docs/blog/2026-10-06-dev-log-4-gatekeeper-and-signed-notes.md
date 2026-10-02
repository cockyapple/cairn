# Dev log 4: a gatekeeper that can say no, and a checkpoint other tools can read

*Part 7 of the Cairn series. Phase 2 is partly built, a survey of similar projects changed the plan, and one external test vector is not a lot.*

The last dev log stopped at Phase 1: proofs, governance replay, a verifier CLI. This one
covers what came after, in the order it happened, and ends with the piece we built most
recently: a second way to publish a checkpoint so that other transparency-log tools can
read it.

## Phase 2: the layer that sits in front of the agent

Phase 2 added the parts that touch actual agents: a council that evaluates proposed rule
changes, provider adapters, a review page, and a **gatekeeper**. The gatekeeper sits
between an agent and its tools. For each call it checks the agent's allow list, writes an
intent entry to the log, runs or refuses the call, and writes a completion entry.

We keep saying what it is not, so once more: it is a policy layer in the process that
calls it. It is **not a sandbox**. An agent that finds another way to reach a tool is not
held by it (ADR-17). What it gives you is a log of every call that did go through, with
the refusals recorded too.

Gemini audited that slice. It reported four findings that held up, and we fixed those four.

## We went looking for projects like ours

Before building further we surveyed GitHub for similar work: agent audit logs, transparency
logs, policy engines. The result was ADR-20, a plan with specific items taken from what
other people had already learned. Four are built so far:

- **REVOKE.** A new entry kind that lets one validator or security reviewer cut off a
  compromised agent or proposer key at once, with no delay. It can only revoke, never
  grant, and it covers agent and proposer keys only, so a single stolen key cannot remove
  a reviewer or validator and stall the quorum.
- **A request budget per agent.** Over-budget calls are refused. The first refusal in a
  window is logged and later ones are only counted, so a runaway agent cannot fill the log
  by being refused a million times. It is off unless you turn it on.
- **A human-review pause.** Some action types can require a reviewer's signature before
  they run. The gatekeeper writes the intent and waits. The reviewer signs the intent's
  entry hash, which commits to the agent, the action, the arguments and the position in
  the chain, so an approval cannot be replayed onto a different action. No decision within
  24 hours counts as a rejection. The reviewer's key signs offline and the gatekeeper never
  holds it.
- **Session taint.** If an agent runs an action you marked as untrusted-input (reading a
  web page, say), it is marked tainted. A tainted agent's guarded actions are refused, or
  sent to the human-review pause, until an operator resets it. The same mark passes to any
  agent that reads a message from a tainted one.

Each of these has a limit, and the ADRs say so. The review pause and the taint rule are
enforced by the gatekeeper process and only *recorded* on the log. The governance replay
does not yet require an approval to exist, so an agent that bypasses the gatekeeper is not
held. Taint is kept in memory and a restart clears it. And taint says "this agent read
something untrusted", not "this value is poisoned"; we do not track data through the model.

## The checkpoint, in a format other tools speak

Cairn's checkpoint is a small binary object (81 bytes of body plus signatures) that only
Cairn tools can read. That is fine for governance, but it means an outside witness has to
learn our wire format before it can say anything about our log.

Transparency logs elsewhere (Go's checksum database, Sigstore) use a text format from the
C2SP project: a *signed note* holding three lines, an origin, a size and a root hash, plus
signature lines. We added that as a second rendering of the same tree head. The native
checkpoint is still the object Cairn signs and verifies; nothing in the wire format or the
test vectors changed.

What the note carries:

- **Three lines only.** Origin, size, base64 root. No extension lines, so a witness sees an
  ordinary checkpoint. The cost is that epoch and head hash are not in the note: a witness
  attests the Merkle root, and the verifier has to be told which trust configuration
  applies.
- **Validators sign as plain Ed25519 note signatures** under the log origin. **Witnesses
  cosign** with the C2SP timestamped cosignature, under a name each witness picks.
- **The same rules as the native checkpoint.** Validator quorum and witness threshold are
  enforced the same way. Unknown signers are ignored, as the format expects. A known key
  whose signature fails rejects the whole note, and so does a duplicate signer.
- **Strict parsing.** Canonical decimal size, canonical base64, no stray bytes, a size cap
  and a signature-count cap. Different bytes do not give you a second valid reading.

`cairn-verify -note` takes a note, the log's blobs, the origin and the witness names and
keys, and prints either `ok note: size N, V validator signatures and W witness cosignatures
meet quorum and threshold` or a named error.

One design point is worth explaining. A note is *not* canonical: because unknown signers
are ignored and signature order is free, two different byte strings can both be valid for
the same tree head. So we identify a tree head by its size and root, never by the bytes of
the note. The native checkpoint stays canonical, which is why it is still the one we sign
and store.

## What the tests found

We wrote the tests first and then tried to break the code.

- **The one external vector verifies.** The signed-note specification includes an example
  note with a known key. Our verifier accepts it, and our key-id calculation reproduces its
  `530d903a` key hash.
- **Mutation testing.** We changed the code in ten specific ways, each one a bug a careless
  implementation could have. Nine were caught by the first set of tests. **One survived**:
  a version of the base64 check that was too loose. Go's decoder quietly ignores carriage
  returns and newlines, so a signature line with a `\r` in the middle still decoded. Only
  re-encoding the result and comparing it to the input catches that. We added tests for it,
  and then all ten were caught.
- **Fuzzing.** The verifier takes arbitrary bytes, and a 20-second fuzz run found nothing.
  That is a short run and we are not claiming more than that.
- **One test of our own was wrong.** A "bad padding" case altered the root in the note
  text instead of the signature, so it tested the wrong thing and passed anyway. We found
  it when we rebuilt the case from the signature line.
- **A second audit.** We gave the package to Gemini as a plain code review. It reported one
  issue: a note could verify with no known signatures. We checked, and that cannot happen.
  A trust configuration with no validator is rejected before any note is looked at, so the
  case is unreachable. No code changed. We recorded the reasoning in the ADR instead.

The verifier core (`wire/` and `ledger/`) is 1,180 lines against a self-imposed budget of
1,500. The note package is separate and outside that budget; the only change to the core
was a three-line export.

## What is still not built

- **Only one external test vector.** There is no published vector for the witness
  cosignature type, so that path is checked against our reading of the spec and nothing else.
  It has **never been run against real witness software.** Until it is, "compatible" would
  be too strong a word. "Follows the specification as we read it" is accurate.
- **No tile serving and no witness protocol.** Those need a log server, and there still
  isn't one. Nobody can append to a Cairn log over a network yet.
- **No OS-level sandbox** around agents, and no separate-machine witness.
- **The replay does not require review approvals**, as above.
- **Not enforced by any code:** the constitution's invariants beyond the two that replay
  checks, plus semantic rules about what a change means.
- **Provider adapters** have not been tested against live services.
- Proofs and governance rules have Go tests but no language-neutral vectors.

## Next

The roadmap items that remain are a log server with sequencer-side limits, the replay
rule that requires a review approval, hash-only action payloads, and the witness protocol.
The log server comes first, because the other items either need it or are weaker without it.

Everything is in the repository: <https://github.com/cockyapple/cairn>. The design of the
note format is in [docs/SPEC-NOTE.md](https://github.com/cockyapple/cairn/blob/main/docs/SPEC-NOTE.md).
