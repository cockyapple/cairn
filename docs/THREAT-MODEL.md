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
| Show different logs to different people (split view) | A4 | Witness cosignatures on checkpoints; verifiers compare | Checkpoint rule in Phase 0; C2SP note rendering built so outside witnesses can cosign (docs/SPEC-NOTE.md), and an independent witness process (`cairn-witness`) that refuses forks and shrinking logs it was shown; no C2SP witness protocol and no gossip between witnesses yet, so two witnesses can still be shown two histories |
| Forge an entry | A1 | Ed25519 signature over domain-separated bytes | Phase 0 |
| Replay a signature in another context | A1 | Domain prefixes per object type | Phase 0 |
| Malformed input exhausts memory or crashes a verifier | A1, A2 | Bounds checked before allocation, strict decoders, fuzzing | Bounds Phase 0; fuzz targets written Phase 1 (run by hand, not in CI) |
| Prompt injection turns an agent against its owner | A2, A3 | Structural containment, not model trust | See INJECTION-DEFENSE.md; Phase 2 and 5 |
| Agent approves its own change | A3 | Invariant I1 | Enforced in governance replay by role (Phase 1) |
| Governance capture by fake reviewers | A6 | Staked, identity-weighted votes, distinct-reviewer rule, security-reviewer requirement, timelocks | Phase 4 |
| Rushed malicious change | A5 | Tier delays and freeze | Enforced in replay (Phase 1), but delays rest on advisory entry times: see SPEC section 10.5 |
| Attacker freezes the system to block a fix | A5 | I3: freeze never blocks rollback | Enforced in replay (Phase 1) |
| Up to f validators equivocate | A5 | 3f+1 BFT, quorum n - (n-1)/3 | Quorum math Phase 0; protocol Phase 4 (research) |
| Key theft | A1 | Role separation, rotation via VALIDATORS epochs, hardware keys advised | Phase 1 |
| Stolen key keeps writing until a tiered change clears its delay | A1, A3 | Emergency `REVOKE` entry, no delay (ADR-20, SPEC 10.3.1) | Built for agent and proposer keys; reviewer, validator and witness keys still need a T4 VALIDATORS change |
| Permitted write built from poisoned input (confused deputy) | A2, A3 | Session taint: after untrusted input the agent cannot run guarded actions, or they wait for a human (ADR-20) | Partly built in the gatekeeper. Per session, not per value; lost on restart; does not stop a well-formed lie from a trusted channel |
| Compromised agent floods the log, exhausting storage or verifier memory | A3 | Per-author rate and size caps at the sequencer; replay that does not hold every blob in memory (ADR-20) | Partly built: the gatekeeper has a per-agent request budget (`RateLimit`) that logs one refusal per window plus a count, so refusals cannot flood the log, and the log server (docs/LOG-SERVER.md) limits every admitted key and caps blobs, store and entries. Not built: streaming replay, and protection of the server itself from unauthenticated floods (a proxy's job). Per-entry bounds exist |
| Malicious dependency | A7 | Standard library only in the verifier; module and image pinned; reproducible build | Phase 0 (no deps); reproducible build Phase 1 |
| One compromised agent pivots through others | A3 | Per-agent keys, sandboxes, typed message bus, narrowing-only delegation (I11) | Phase 1-2 |
| Many agents stay under individual caps | A3 | Fleet budget, spawn-rate cap, fleet-wide anomaly freeze | Phase 3 |
| Weak local model is easily injected | A2 | Per-model eval score gates grants; unscored = minimum grant (I12) | Phase 5 |
| An agent writes to the log directly and skips its gatekeeper | A3 | None in the log: the log checks keys and roles, not what a gatekeeper would have allowed. An agent holding its own signing key is outside the gatekeeper | Not mitigated; the gatekeeper is a policy layer, not a sandbox. Keep agent keys inside the gatekeeper process, and revoke a key that is used outside it |
| Reviewer or security-reviewer key compromised or captured | A5, A6 | Distinct-reviewer rule, security-reviewer requirement, tier delays, freeze | Only as strong as the quorum: three captured reviewers, one of them a security reviewer, can pass a T4 change after its delay. A single stolen reviewer key can only be removed by a T4 change (REVOKE does not cover it) |
| Validators lose a key and cannot rotate, or freeze the log and cannot lift it | A5 | VALIDATORS epochs need a quorum that includes the lost key's holder | Not mitigated: there is no key-recovery procedure, and a frozen log with a deadlocked quorum stays frozen |
| Validators collude to rewrite recent history | A5 | Witness cosignatures, outside verifiers comparing checkpoints | A validator quorum plus the operator can fork before any witness has seen the new tip; detection depends on witnesses and verifiers actually comparing |
| Clock manipulation shortens a timelock | A4, A5 | Monotonic entry times, sequencer clock check (`MaxSkew`), optional verifier clock | Time is advisory (ADR-5, SPEC 10.5); a verifier without a trusted clock cannot tell a backdated delay from a real one |
| Rollback or stale data served to a client | A4 | A checkpoint that meets quorum, a witness that refuses to sign a smaller log | A client that never sees a newer checkpoint cannot tell it is behind: freshness needs a clock or a gossip channel, neither built |
| Denial of service against the log server or a witness | A1 | Per-key rate limits, size caps, entry cap | The server has no authentication of its own for reads and no TLS; unauthenticated floods are a proxy's job. One process, no replication |
| Build or release tampering | A7 | Standard library only; CI gates the import graph | No reproducible-build evidence, signed releases or provenance exist yet |
| Partial signature state, gatekeeper state and taint lost on restart | A4 | The log and the witness's state file are durable | Partial checkpoint signatures, per-agent gatekeeper state and session taint are in memory; the server and gatekeeper read their configuration once at start |
| Test keys used in production | all | Test keys come from public seeds and are documented as such | Documented |

## Out of scope for v1

Side channels on validator hardware, censorship by the network layer, compromise
of a majority of validators (the BFT bound is explicit), and correctness of
model output (Cairn bounds authority, not truth).

## Assumptions

Ed25519 and SHA-256 are secure. At least one witness is honest and independent.
Fewer than one third of validators are faulty. A human reviewer population
exists that is not wholly captured.
