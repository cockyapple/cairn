# Roadmap

Thirty weeks, assuming one builder working part-time with AI coding help. Phases 0 to 3
end with something that works standing alone. Phases 4 and 5 are research-grade and can
slip without breaking what came before.

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
and freeze (invariants I1, I3, I4, I11). Formats for model identity, capability grants,
delegation and agent suspension. Fuzzing of every decoder.
*Done when* the tamper suite passes, the verifier is under budget and a witness catches a
forced split view.

### Phase 2 (weeks 7 to 10): Review workflow and gatekeeper. MOSTLY BUILT
Proposals, votes, tiers, timelocks, freeze, a review web view showing diffs and eval
deltas, and an eval runner that records its result hash on the ledger. The gatekeeper
with provider adapters (OpenAI-compatible, Anthropic, Google, Ollama), per-agent sandbox
and typed message bus.
*Done when* a real change goes from proposal to activation with quorum and a rejected one
provably never loads.

*State (Phase 2):* the review workflow, council, provider adapters (fakes only), gatekeeper
policy layer, message bus, review page and the end-to-end test are built. **Not built:**
the per-agent OS sandbox, live-service tests of the adapters, and the log server that
Phase 1 still owes. I4 and I11 are not enforced (SPEC 10.5).

### Phase 3 (weeks 11 to 14): Governed agent and fleets
A first real agent that loads configuration only from the ledger, logs every action,
refuses unactivated changes. Fleet budgets, spawn-rate and concurrency caps, fleet-wide
anomaly freeze.
*Done when* the agent refuses a tampered config and a fleet stays inside its budget under
adversarial load.

### Phase 4 (weeks 15 to 22): Decentralize (research)
Custom BFT with 3f+1 validators, specified in TLA+ and tested by deterministic simulation
with injected faults.

### Phase 5 (weeks 23 to 30): Attest and harden (research)
Hardware attestation, the prompt-injection corpus and benchmark, per-model scoring and
trust classes, multi-agent adversarial tests, third-party review.

## Not planned

A token, a general smart-contract VM, or claims that any model is injection-proof.
