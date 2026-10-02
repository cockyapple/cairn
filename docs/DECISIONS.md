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

**ADR-15. A proposal commits to the whole artifact, and reviewers see a diff
(DECIDED, Phase 2).**
Why: `diff_hash` was named for a patch, but a patch is meaningless without the
text it applies to, and the loader has to serve exactly what was approved.
Decision: `diff_hash` is the hash of the full proposed artifact. The review
page and the LLM reviewer compute a line diff against the artifact most
recently activated for the same target before this proposal. `eval_hash` points
to a canonical eval result (suite name, hash of baseline, hash of candidate,
per-case scores). The review layer checks that the result names this artifact
and the artifact now in force; if not, the scores are marked untrusted and an
LLM reviewer is told to ignore them (an external audit found a proposer could
otherwise attach a flattering result computed for something else). What the
ledger proves: which result reviewers saw. It does not prove the eval was run
honestly or that the cases were any good. Cost: every version is stored in full.

**ADR-16. Reviewers are keys; the council decides nothing (DECIDED, Phase 2).**
Why: the same log should work whether changes are approved by people, by models,
or by a mix, and a model that fails must not become a yes. Decision: a
`Reviewer` is anything that returns approve, reject or escalate for the material
it is shown; a `Council` runs members concurrently and appends one VOTE per
member that answered, signed by that member's own key. A member that errors,
times out, panics or returns something unparseable casts no vote, so silence
never counts as approval. The council never activates: governance does, at
ACTIVATE, by counting distinct reviewer keys against the tier. An LLM reviewer
sees untrusted text, so its prompt fences the content in random boundary
markers, asks for one strict JSON object, refuses to review what does not fit
in full (it will not approve what it could not read) and rejects trailing text.
None of that makes injection impossible. Limits worth stating: models from one
vendor fail in correlated ways, so quorum of three copies of one model is closer
to one opinion; a community of reviewers needs an identity story, because keys
are free; and the log proves who voted, not that the reasoning was sound.

**ADR-17. The gatekeeper is a policy layer, not a sandbox (DECIDED, Phase 2).**
Why: invariant I7 needs an intent on the log before an action runs, and the
threat model needs agents to run only activated configuration. Decision: for
each action the gatekeeper checks size, capability and config, writes the
intent, runs the handler under a timeout, then writes the completion. If the
intent cannot be written, the action does not run. A refusal is also an intent
plus a completion whose result starts `refused`. Result blobs start with a
status line (`ok`, `error`, `refused`). An agent that has declared a config
target runs only if the loader still serves its pinned artifact. Actions of one
agent are serialised, because the replay requires a completion to match the
oldest open intent and chains an author's own actions. The message bus is typed
(declared sender, receiver and a strict flat-JSON schema) and every send is an
action. Explicit non-claims: this runs inside one process, so a compromised
agent that shares that process can bypass it; there is no filesystem, network or
syscall isolation (OS-level sandboxing is future work); and a typed message
narrows what a reader can say but cannot stop a compromised reader sending a
well-formed lie.

**ADR-18. Verifier-supplied policy for what the log cannot enforce (DECIDED,
Phase 2).**
Why: an audit pointed out that a proposer chooses the tier, and T0 needs no
votes and no delay, and that delays rest on entry times which are claims.
Decision: `governance.Options` gains `MinTier` (a tier floor per target;
`tier_too_low`) and `Now` with `MaxSkew` (entries dated later than the
verifier's clock allows are rejected; `future_entry`). Both are inputs to the
verifier, not entries, so every verifier must be given the same policy; the CLI
exposes the clock as `-use-clock`. Cost: agreement on policy is out of band.

**ADR-19. Fixes from the Phase 2 audit (DECIDED, Phase 2).**
Why: a second Gemini audit of the whole phase found four real problems. (1) An
eval result for a target with nothing in force could name any baseline, and the
page and the model reviewer would present its scores as checked. Now the baseline
must be the hash of an empty artifact, otherwise the result is flagged as not
applying. (2) The blob loaders capped file count and file size but not the total,
so a hostile bundle could ask for terabytes; both now stop at 256 MiB in total
and one count limit. (3) A change too large to diff was refused outright by the
model reviewer, so it could never vote on a big file; it now gets the full
proposed content, as the review page does, and still declines when that is too
big to read in full. (4) If the log refused a completion after the handler had
run, the open intent was never closed and the replay then refused every later
action of that agent; the completion is now kept and retried before the agent
does anything else, and nothing runs until it is written. Explicit non-claim: the
log does not recompute eval scores, so they remain the proposer's claim, and
there is still no eval runner service, only the library.

**ADR-20. Plan after the prior-art survey (PROPOSED, nothing here is built).**
Why: a survey of related open-source projects (read from their READMEs and the C2SP
specs, not run) and a Gemini comparison, checked against this repo, found three
gaps the threat model did not cover and several worthwhile borrowings.
Decisions proposed:
(1) *Checkpoints.* Keep the native binary checkpoint as the signed object. Add a C2SP
signed-note rendering of the same tree head (origin, size, root) so existing witnesses and
tiles tooling can cosign and serve it. That note carries no epoch or head, so a witness
attests the Merkle root only, which still commits to every entry. Replacing the format
was rejected: it would rewrite SPEC section 6, the vectors and the quorum rules for no
gain in the governance layer. The mapping is decided and built (see the C2SP addendum below).
(2) *`REVOKE`* (BUILT). A new entry kind (7), no delay, signed by one validator or security
reviewer, naming one key. As built it covers agent and proposer keys only and is permanent:
a single signer must not be able to remove a reviewer or validator, which would let one
compromised key stall quorum. Those roles still change through T4 VALIDATORS. A revoked
proposer cannot get an unactivated proposal activated. Original wording: signed by a security reviewer or a validator
quorum, naming one key. The governance replay stops accepting that key from the next
entry. It must be limited to revoking, never granting, so it cannot be used to seize
roles. A freeze must not block it (I3 spirit).
(3) *Log growth* (partly built). The gatekeeper now enforces an opt-in per-agent request
budget; over-budget refusals are logged once per window and then counted, trading one
entry per refusal for bounded log growth. Still planned: rate and size caps per author at
the sequencer, and a replay that streams blobs. Admission limits are policy, not part of the wire format, so verifiers
are unaffected.
(4) *Provenance* (built at session granularity, see the addendum below). Taint marks carried
by the gatekeeper onto call parameters were the original idea; that needs a data-flow
model the gatekeeper does not have.
(5) *Smaller items:* council resampling, hash-only
ACTION payloads, audit mode, a blast-radius trace tool, credential injection, tile
serving and the C2SP witness protocol.
Not adopted: a BFT framework or policy runtime in the core, and post-quantum signatures
in the verifier. Cost of the plan: each item that touches the entry kinds changes SPEC
and the vectors, so they are batched into one version bump rather than trickled in.

### ADR-20 addendum: human-review pause (BUILT, gatekeeper only)

An agent can be configured with action types that need a human decision. The gatekeeper
logs the intent as usual and leaves it open. A reviewer or security reviewer in the epoch
in force signs a decision (domain `cairn/review-decision/v1`, the intent's entry hash, one
verdict byte); the entry hash commits to the agent, action, arguments and chain position,
so a decision cannot be moved to another action. The action then runs, or is refused on a
rejection or a timeout (default 24 hours), and the configuration is checked again after the
wait. The completion blob begins `review:<approve|reject> <reviewer> <signature>`.
Choices and limits: no wire change, so the pause is enforced by the gatekeeper process and
only recorded on the log; the replay does not require an approval, and an agent that does
not go through the gatekeeper is not held. Making the replay require one would need a new
entry kind or a payload field and is left for later. A reviewer key signs offline; the
gatekeeper never holds it.

### ADR-20 addendum: session taint (BUILT, gatekeeper only)

The gatekeeper cannot see how a model uses what it read, so provenance is tracked per
agent session. An agent is tainted when an action in its `Untrusted` list runs (success or
failure, since a partial result can still carry text), or when it calls `Receive` on a
message whose sender was tainted. Taint is applied at `Receive`, not on delivery, because
the data only enters the recipient's context when it reads. A tainted agent's `Guard`
actions are refused with `tainted_input`, naming the first source; with `GuardEscalate`
they wait for the human-review pause instead, so a clean agent runs unattended and a
tainted one needs a reviewer. `ResetTaint` is an operator call that logs the cleared
source and a reason as the action `taint.reset`.
Choices and limits: no wire change. A reader that passes only strictly validated enum
fields to an actor still taints it by default, because a validator limits form, not
truth; a message type can set `NoTaint` to declare otherwise, which is the operator's
claim and is not checked. Taint is held in memory and a restart clears it. Refused guarded
requests are logged, but a taint is not itself written when it happens, so the log shows
the refusal and the source it names rather than the moment the taint began. A lie that
arrives through a channel not marked untrusted is not caught. `Untrusted` and `Guard`
names must appear in `Allow`, so a typo cannot silently disable the protection.

### ADR-20 addendum: C2SP signed-note checkpoints (BUILT)

Decision (1) is settled and built. The native binary checkpoint stays the signed object
and verification path (ADR-12 is untouched). A C2SP signed note carrying a plain
three-line tlog-checkpoint (origin, size, root; no extension lines) is a second signature
over the same tree head by the same keys. Validators sign it as Ed25519 note signatures
under the log origin; witnesses cosign it as `0x04` cosignatures under names they choose.
Full format and verification rules are in `docs/SPEC-NOTE.md`.
Why a separate rendering and not a replacement: replacing the checkpoint would rewrite SPEC
section 6, the vectors and the quorum rules for no gain in governance. Why no extension
lines: epoch and head are derivable from the log, and C2SP discourages extensions, so a
witness sees an ordinary checkpoint.
Choices and limits: no wire change, so the vectors are unchanged and the new package
(`note`) sits outside the 1,500-line verifier budget (only a three-line `Validate` export
was added to `ledger`). A note is not canonical (unknown signers are ignored and order is
free), so a tree head is identified by size and root. A note carries no epoch, so a witness
attests the Merkle root and the verifier must be told the epoch's trust configuration. Only
the signed-note example is an external test vector; the cosignature path has none. Tile
serving and the witness protocol are not built and still need the log server.
Audit: Gemini reviewed the package against the specification rules and reported one
issue, that a note could verify with no known signature if a trust configuration had no
validators and a zero witness threshold. That configuration is rejected by
`TrustConfig.Validate`, which `Verify` runs first, so it is unreachable and no extra check
was added.
