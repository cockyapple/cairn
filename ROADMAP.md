# Roadmap

Thirty weeks, assuming one builder working part-time with AI coding help. Phases 0 to 3
end with something that works standing alone. Phases 4 and 5 are research-grade and can
slip without breaking what came before.

## Strategy

Cairn is a small, auditable core: a tamper-evident log, a governance state machine over it,
and a gatekeeper that treats the model as untrusted. It is not a general agent platform.
The plan follows from that, and was sharpened by a survey of related open-source work
(transparency-log infrastructure such as Tessera, Sigsum and the C2SP specs; agent receipt and
authorization tools such as VAOL, agent-custody, AgentLock and Openfirma; LLM councils).
The survey was read from those projects' READMEs and specs, not from running them, so
treat the comparisons as indicative.

1. **Own the governance layer, borrow the log conventions.** Nothing surveyed combines
   tiered, time-locked governance, an intent-then-completion action trail, and a council
   of reviewers that can be models, people or scripts. The log layer is a solved problem
   with shared formats. Interoperate there; do not reinvent it a second time.
2. **Close the gaps that attackers would use first.** The survey exposed three the threat
   model did not cover: no way to revoke a stolen key quickly, no defence against a
   permitted write built from poisoned reads, and no limit on log growth.
3. **Keep the trusted core small.** Every addition below is judged against the
   standard-library-only rule and the verifier line budget. Anything that cannot meet them
   lives outside the core as an optional adapter, or is not done.
4. **Say what is built.** Items under "Added after the survey" are plans. They are
   not described as built anywhere until they exist and are tested.

## Success measures (proposed, to be tuned after Phase 1)

| Measure | Target |
|---------|--------|
| Coverage | 100% of agent configuration changes carry an inclusion proof and a quorum |
| Tamper detection | 1,000 randomized corruption attempts on log, checkpoint and blob, all detected |
| Split-view detection | Caught within one checkpoint interval in fault-injection tests |
| Verifier size | Under 1,500 lines, no dependency beyond the standard library |
| Review quality | Red-team seed proposals caught at least 80% of the time |
| Bypass attempts | 0 activations without quorum across all adversarial runs |
| Injection containment | Attack success rate and containment rate reported per model (Phase 5) |

## Phases

### Phase 0 (weeks 1 to 2): Foundations. DONE
Spec, threat model, constitution, decision records, verifier core, conformance vectors,
injection-defense and model/fleet design.

### Phase 1 (weeks 3 to 6): The ledger. PARTLY BUILT
Append-only log server, inclusion and consistency proofs, verifier CLI, one witness on a
separate machine, and the governance state machine that enforces roles, tiers, timelocks
and freeze (invariants I1 and I3 are enforced; I4 and I11 are not: SPEC 10.5). Formats for
model identity, capability grants, delegation and agent suspension (not started). Fuzzing
of every decoder (written; run by hand, not in CI).
*Done when* the tamper suite passes, the verifier is under budget and a witness catches a
forced split view.

*Added after the survey (planned, not built):*
- **Checkpoint format (BUILT, ADR-20).** The native binary checkpoint stays the signed object.
  A C2SP signed-note rendering of the same tree head (package `note`, `docs/SPEC-NOTE.md`,
  `cairn-verify -note`) lets outside witnesses attest to it. Tested against the signed-note
  spec's own example; never run against real witness software.
- **`REVOKE` entry (BUILT, ADR-20).** An emergency, no-delay revocation signed by one validator
  or security reviewer. It covers agent and proposer keys only and is permanent; the replay
  rejects that key from the next entry on, and a freeze does not block it. Revoking a
  reviewer, validator or witness key still needs a T4 VALIDATORS change, by design, so one
  signer cannot stall governance.
- **Admission limits.** Built in the gatekeeper (opt-in `RateLimit` per agent): requests over
  budget are refused, the first refusal per window is logged, and the count of the rest is
  logged when the next window opens. A key that writes to the log directly does not pass
  the gatekeeper, so the log server now enforces its own per-author rate limit and blob,
  store and entry caps (BUILT). Still owed: a replay that does not hold every blob in memory.
- **Log server, slice 1 (BUILT, ADR-20, `docs/LOG-SERVER.md`).** Package `logserver` and command
  `cairn-logd`: one sequencer that admits an entry only if the whole log still replays with it,
  writes it to disk before acknowledging, serves entries, blobs and Merkle proofs, enforces
  per-author rate limits and blob, store and entry caps, and collects checkpoint signatures
  without holding any key. Its directory is what `cairn-verify` reads. Single process, no
  replication, replay is O(n) per append, no TLS or read authentication of its own.
- **Language-neutral vectors for proofs and governance**, which were already owed.

### Phase 2 (weeks 7 to 10): Review workflow and gatekeeper. MOSTLY BUILT
Proposals, votes, tiers, timelocks, freeze, a review web view showing diffs and eval
deltas, and an eval runner that records its result hash on the ledger. The gatekeeper
with provider adapters (OpenAI-compatible, Anthropic, Google, Ollama), per-agent sandbox
and typed message bus.
*Done when* a real change goes from proposal to activation with quorum and a rejected one
provably never loads.

*Added after the survey (planned, not built):*
- **`human_review` pause (BUILT in the gatekeeper, ADR-20).** An action an agent is marked `Review`
  for logs its intent and stays open until a reviewer or security reviewer signs a decision
  over that intent; it then runs, or is refused if rejected or if the wait times out. The
  signed decision is recorded in the completion blob. The governance replay does not check
  it: no new entry kind was added, so a verifier that wants to enforce review must read the
  blobs itself. Planned: a replay rule that requires the approval.
- **Council resampling.** If reviewer confidence is low or reviewers disagree narrowly, ask again
  before recording a vote, and log that it happened.
- **Hash-only mode for ACTION payloads.** The log records the digest and the blob stays
  private. Governance entries keep requiring their blobs, because replay reads them.
- **An eval runner service**, still owed from the original scope.

*State (Phase 2):* the review workflow, council, provider adapters (fakes only), gatekeeper
policy layer, message bus, review page and the end-to-end test are built. **Not built:**
the per-agent OS sandbox and live-service tests of the adapters. There is also no eval runner service: `eval` is a library, and the scores a
proposal carries are the proposer's claim, which the log does not recompute. I4 and I11 are not enforced (SPEC 10.5).
Phase 1 additions built since: the log server (`docs/LOG-SERVER.md`) and an independent
witness process (`docs/WITNESS.md`), neither yet run on a second real machine.

### Phase 3 (weeks 11 to 14): Governed agent and fleets
A first real agent that loads configuration only from the ledger, logs every action,
refuses unactivated changes. Fleet budgets, spawn-rate and concurrency caps, fleet-wide
anomaly freeze.
*Done when* the agent refuses a tampered config and a fleet stays inside its budget under
adversarial load.

*Added after the survey (planned, not built):*
- **Provenance tracking in the gatekeeper (BUILT at session granularity, ADR-20).** An agent is
  tainted once it runs an action marked `Untrusted`, or receives a message from a tainted
  sender. A tainted agent cannot run its `Guard` actions: they are refused (`tainted_input`),
  or with `GuardEscalate` held for the human-review pause. `ResetTaint` clears it and is
  logged. This is per session, not per value: the gatekeeper cannot see data flow inside a
  model, so it does not trace a single parameter back to its source. It does not stop a
  well-formed lie from a channel marked trusted, a `NoTaint` message type is the
  operator's claim that its bodies carry no free text, and taint does not survive a restart.
  Planned: a replay rule, and per-value tracking if a data-flow model proves workable.
- **Audit mode.** Classify actions as read, write or destructive and log what would have been
  refused before enforcing, so thresholds are set from data.
- **Blast-radius trace.** A verifier-side tool that, given one entry or memory write, lists the
  later entries that cite it. Memory writes should cite the intent that produced them.
- **Credential injection at the execution boundary.** The gatekeeper holds secrets and attaches
  them to a call; the model never sees them.
- **Independent witness (BUILT, slice 1).** `witness` / `cairn-witness` (docs/WITNESS.md) checks the
  whole log under the governance rules, keeps a durable record of the largest checkpoint it signed,
  and refuses a log that forks from or is shorter than that. It catches a server that lies to it;
  catching a server that shows two witnesses two histories still needs gossip between witnesses
  (not built).
- **Tile-served log and the C2SP witness protocol** (not built; the note format they carry
  is). Needs the log server, so existing witnesses and tooling can work with it without a
  custom service.

### Phase 4 (weeks 15 to 22): Decentralize (research)
Custom BFT with 3f+1 validators, specified in TLA+ and tested by deterministic simulation
with injected faults.

### Phase 5 (weeks 23 to 30): Attest and harden (research)
Hardware attestation, the prompt-injection corpus and benchmark, per-model scoring and
trust classes, multi-agent adversarial tests, third-party review.

*Added after the survey (planned, not built):* an optional external-policy adapter (Cedar or
OPA) behind the gatekeeper, outside the core, for operators who already use one.

## Not planned

A token, a general smart-contract VM, or claims that any model is injection-proof.

Also ruled out after the survey: embedding a BFT framework such as CometBFT or a policy
runtime in the core (it would break the dependency and size rules), and post-quantum
signatures in the verifier until the standard library supports them. Revisit that last one
when it does.
