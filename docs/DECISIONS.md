# Architecture decisions

Short records. Format: decision, why, what it costs.

**ADR-1. Custom transparency log, no blockchain framework.**
Why: the owner asked for no framework unless written for this purpose; a
transparency log needs an append-only, verifiable history and a governance
process, not a general smart-contract platform. Cost: we own every bug, so the
verifier is kept tiny and is vector-tested.

**ADR-2. Stage A sequencer plus witnesses, Stage B custom BFT.**
Why: a single sequencer with independent witnesses already stops rewriting and
split views, and ships first. BFT removes the single operator later. Cost: Stage
A trusts the sequencer for liveness and ordering until Stage B.

**ADR-3. Go, standard library only in the core.**
Why: Ed25519, SHA-256 and strict binary handling are in the stdlib, which
removes supply-chain surface. Cost: no third-party conveniences.

**ADR-4. Fixed-size binary entry, not JSON.**
Why: one canonical encoding with no whitespace, key-order or float ambiguity;
cheap to bound and fuzz. Cost: human-unfriendly; tooling renders it.

**ADR-5. Time is advisory u64 unix seconds.**
Why: timestamps cannot be trusted, so ordering comes from height; an integer
avoids RFC 3339 parsing differences between languages. Cost: timelocks use the
validators' agreed checkpoint time, not the entry field, from Phase 1.

**ADR-6. Domain-separated signatures and hashes.**
Why: prevents cross-protocol replay. Cost: none meaningful.

**ADR-7. Conformance lives in language-neutral vectors.**
Why: lets a second implementation prove the spec is implementable and catches
Go-specific assumptions. The test suite re-derives the chain from raw stdlib
crypto with hand-written offsets. Cost: vectors must be regenerated on change,
and a stale-file test makes that loud.

**ADR-8. Prompt injection is contained, not "solved".**
Why: no model-level fix exists. Authority is enforced by a deterministic
gatekeeper outside the model, with a quarantined reader, typed tools, caps,
approvals and an injection corpus as a proposal gate. Cost: extra latency and
less agent autonomy by design. Details in INJECTION-DEFENSE.md.

**ADR-9. Governance rules are commitments until code enforces them.**
Why: honesty. Phase 0 verifies authenticity only; role and tier enforcement is
Phase 1. The spec and constitution say so explicitly.

**ADR-10. Model-agnostic through a minimal provider adapter.**
Why: the model is untrusted, so the security boundary must not care which model
it is. One `complete(request) -> response` contract covers cloud and local
(OpenAI-compatible, Anthropic, Google, Ollama). Credentials stay in the
gatekeeper. Authority for a model is earned by measured injection-corpus scores
(unscored models get the minimum grant). Cost: lowest-common-denominator
features, and scoring work for every model. See MODELS-AND-FLEETS.md.

**ADR-11. Multi-agent by per-agent identity, isolation, typed bus, and narrowing
delegation.**
Why: one compromised agent must yield only its own grant. Agents talk through
validated typed records (never spliced prompts), delegate only subsets of their
own grant, and are also bounded by fleet budgets, spawn limits and fleet-wide
anomaly freezes. Cost: more moving parts in the gatekeeper and a bus to operate.

**ADR-12. Checkpoint bytes are not canonical in Phase 0 (OPEN).**
Why: the tamper suite showed that with surplus signatures, 1,024 of 5,288
single-bit flips (every bit of every validator's public-key field) still verify,
because a key outside the trust config is ignored by design. That is not a
forgery (the quorum is still proven), but two different byte strings are the
same valid checkpoint. Rule until decided: identify a checkpoint by its body,
never by a hash of its encoding. Phase 1 should decide whether to require
sorted, admitted-only signatures so the encoding becomes unique.

**ADR-13. "Log before act" vs. ACTION's result_hash (OPEN).**
Why: found by an external audit of the blog series. Constitution I7 says the
gatekeeper writes the ACTION entry *before* it executes, but the ACTION payload
carries a `result_hash`, which cannot exist until the action has run. As
specified, a single entry cannot do both. Candidate fixes: (a) write the entry
before with a zero `result_hash`, then a second ACTION entry with the same
`args_hash` and the real `result_hash`; (b) a separate RESULT kind. Either keeps
I7 (intent is committed first) and adds a reconcile rule: an intent with no
result after a timeout is itself a signal. Until decided, docs must not claim
more than "every action is recorded".
