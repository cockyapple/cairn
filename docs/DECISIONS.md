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

**ADR-12. Checkpoints are canonical (DECIDED, Phase 1).**
Why: the Phase 0 tamper suite showed that with surplus signatures, 1,024 of
5,288 single-bit flips (every bit of every validator's public-key field) still
verified, because a key outside the trust config was ignored. That was not a
forgery, but two byte strings were the same valid checkpoint. Decision: a valid
checkpoint has signatures in strictly ascending public-key order and no
stranger keys (`unsorted_signers`, `unknown_signer`, `duplicate_signer`). Now
every single-bit flip of a surplus-signer checkpoint is rejected, and the
encoding may be hashed. Cost: a coordinator must filter and sort before
publishing, and a witness that is not yet admitted cannot cosign into the
published checkpoint.

**ADR-13. "Log before act" vs. ACTION's result_hash (DECIDED, Phase 1).**
Why: found by an external audit of the blog series. I7 says the gatekeeper
writes the ACTION entry *before* it executes, but a result cannot be hashed
before the action runs. Decision: two ACTION entries per action, no new kind.
An **intent** has an all-zero `result_hash` and is written first. A
**completion** has a non-zero `result_hash`, the same `action_type` and
`args_hash`, and closes the author's oldest open intent with those values.
Every ACTION by an agent also carries `prev_action_hash` = that agent's
previous ACTION entry hash (zero for its first), so an agent cannot silently
drop one of its own actions. The state machine reports open intents with their
age: an intent with no completion is itself a signal (crash, refusal or
concealment). Rejected alternative: a separate RESULT kind, which would add a
wire kind and vectors for no extra guarantee.

**ADR-14. Governance parameters are fixed in the spec, not in the TrustConfig
(DECIDED, Phase 1).**
Why: the constitution said approval counts "are set in the trust
configuration", but the TrustConfig carries only keys and a witness threshold,
and an outside verifier can only check rules it can read from the spec. Putting
counts in the TrustConfig would also mean changing the wire format a third time
before freezing. Decision: the per-tier approvals, security-reviewer minimums
and delays are constants in SPEC section 10.2. Raising them is a spec version
change, not a ledger entry. Related choices made together: any reject or
escalate vote vetoes a proposal for good; a VALIDATORS entry voids open
proposals; during a freeze only T0 activations pass, which doubles as the
emergency rollback path; validator-set changes must be authorised by an
activated T4 proposal whose `diff_hash` is the hash of the new TrustConfig.
Cost: one rogue reviewer can block a proposal (liveness over safety is the
wrong trade here), and small deployments need at least 3 reviewers including a
security reviewer before T2 and above can ever pass. Not decided here: I4,
whose enforcement needs the ledger to understand what a change means.
