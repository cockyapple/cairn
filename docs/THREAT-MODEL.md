# Threat model

Scope: the Cairn ledger, its governance, and the agents it governs. Adversaries
are listed by capability, not name.

## Assets

1. Integrity and history of the log.
2. Integrity of agent configuration (prompts, tools, models, grants).
3. Secrets and funds reachable by agents.
4. The legitimacy of the review process.

## Adversaries

| ID | Adversary | Capability |
|----|-----------|------------|
| A1 | Outsider | Reads everything public; submits content to agents |
| A2 | Malicious content author | Plants instructions in pages, issues, code, contracts |
| A3 | Compromised agent | Model fully under attacker control within its grant |
| A4 | Rogue operator | Controls the sequencer and storage |
| A5 | Colluding minority | Up to f of 3f+1 validators, or a few reviewers |
| A6 | Sybil reviewer | Many fake identities seeking votes |
| A7 | Supply chain | Malicious dependency or build |

## Threats and mitigations

| Threat | Adversary | Mitigation | Status |
|--------|-----------|------------|--------|
| Rewrite or delete history | A4 | Hash chain, Merkle root, signed checkpoints, independent witnesses | Verified by Phase 0 code and vectors |
| Show different logs to different people (split view) | A4 | Witness cosignatures on checkpoints; verifiers compare | Checkpoint rule in Phase 0; gossip in Phase 3 |
| Forge an entry | A1 | Ed25519 signature over domain-separated bytes | Phase 0 |
| Replay a signature in another context | A1 | Domain prefixes per object type | Phase 0 |
| Malformed input exhausts memory or crashes a verifier | A1, A2 | Bounds checked before allocation, strict decoders, fuzzing | Bounds Phase 0; fuzz targets written Phase 1 (run by hand, not in CI) |
| Prompt injection turns an agent against its owner | A2, A3 | Structural containment, not model trust | See INJECTION-DEFENSE.md; Phase 2 and 5 |
| Agent approves its own change | A3 | Invariant I1 | Enforced in governance replay by role (Phase 1) |
| Governance capture by fake reviewers | A6 | Staked, identity-weighted votes, distinct-reviewer rule, security-reviewer requirement, timelocks | Phase 4 |
| Rushed malicious change | A5 | Tier delays and freeze | Enforced in replay (Phase 1), but delays rest on advisory entry times: see SPEC section 10.5 |
| Attacker freezes the system to block a fix | A5 | I3: freeze never blocks rollback | Enforced in replay (Phase 1) |
| Up to f validators equivocate | A5 | 3f+1 BFT, quorum n - (n-1)/3 | Quorum math Phase 0; protocol Phase 3 |
| Key theft | A1 | Role separation, rotation via VALIDATORS epochs, hardware keys advised | Phase 1 |
| Stolen key keeps writing until a tiered change clears its delay | A1, A3 | Emergency `REVOKE` entry, no delay (ADR-20) | Planned, not built; today only VALIDATORS rotation exists |
| Permitted write built from poisoned input (confused deputy) | A2, A3 | Provenance marks on inputs; refuse or escalate consequential writes that trace to untrusted reads (ADR-20) | Planned, not built (Phase 3). Does not stop a well-formed lie |
| Compromised agent floods the log, exhausting storage or verifier memory | A3 | Per-author rate and size caps at the sequencer; replay that does not hold every blob in memory (ADR-20) | Planned, not built (Phase 1). Per-entry bounds exist |
| Malicious dependency | A7 | Standard library only in the verifier; module and image pinned; reproducible build | Phase 0 (no deps); reproducible build Phase 1 |
| One compromised agent pivots through others | A3 | Per-agent keys, sandboxes, typed message bus, narrowing-only delegation (I11) | Phase 1-2 |
| Many agents stay under individual caps | A3 | Fleet budget, spawn-rate cap, fleet-wide anomaly freeze | Phase 3 |
| Weak local model is easily injected | A2 | Per-model eval score gates grants; unscored = minimum grant (I12) | Phase 5 |
| Test keys used in production | all | Test keys come from public seeds and are documented as such | Documented |

## Out of scope for v1

Side channels on validator hardware, censorship by the network layer, compromise
of a majority of validators (the BFT bound is explicit), and correctness of
model output (Cairn bounds authority, not truth).

## Assumptions

Ed25519 and SHA-256 are secure. At least one witness is honest and independent.
Fewer than one third of validators are faulty. A human reviewer population
exists that is not wholly captured.
