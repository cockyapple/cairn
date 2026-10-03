# Dev log 7: the log now holds agents to their grants, and a plain account of what has gone wrong so far

*Part 10 of the Cairn series. Dev log 6 was the OpenAI audit. This one covers what we built since, the two audits of it, and, because we were asked for it, the pains and mistakes of the project so far, not just the progress.*

## What got built

Cairn is a tamper-evident log of what AI agents were allowed to do and what they did. Until now the log could say who may *delegate* a capability (invariant I11: a grant handed down must be strictly narrower than the one it came from). It could not say whether an agent then *stayed inside* the grant it held. That gap was written into the roadmap as "I11 only as far as delegation", and it was the next thing to close.

It is closed for agents that hold a grant. Replay now checks every action an agent logs against its grant:

- **Tool.** The action type must be in the grant's tool list.
- **Host.** The host the action declares must be in the grant's host list.
- **Expiry.** A grant past its `not_after` time permits nothing.
- **Budget.** Each action declares a cost, charged when the intent is written, with no refunds. The charge goes to the agent's grant and to every grant above it in the delegation chain, and the whole chain is checked before anything is charged, so a delegate cannot spend a budget its parent no longer has.

Six new error codes cover the failures (`no_grant`, `grant_expired`, `bad_use`, `tool_not_granted`, `host_not_granted`, `budget_exceeded`). They are in the spec, and a test fails if the spec and the code disagree about the list.

The gatekeeper, the component that sits between an agent and its tools and writes the log, was changed to match. An agent that holds a grant now has its actions recorded with a declaration of host and cost, and the gatekeeper's own records (refusals, rate limits, taint resets) are written as a separate `cairn/event` type that spends no budget. An agent asking the gatekeeper for an action outside its grant gets a refusal, and the refusal is itself in the log.

**What this does not do, stated up front.** An agent that has never held a grant is not checked. Host and cost are claims the writer makes; the log can show that an action's claims were outside the grant, but it cannot see what the process really connected to. And an agent that acts without writing an intent leaves nothing for the log to check. The log detects and records. It does not contain. The per-agent sandbox is still unbuilt.

## Two audits, and they disagreed

We sent the whole patch to Gemini and to `gpt-5.5`, with the `wire` and ledger payload source included, using the same neutral "senior engineer correctness review" framing as before.

**Gemini found nothing.** It said so confidently, with a tidy list of areas it had checked and found sound.

**OpenAI found four things, and all four were real.** We checked each against the code, and each now has a test that fails without the fix:

1. **A crafted argument could declare the action in the agent's place.** When a grant takes effect, the gatekeeper's view of the log can be one entry behind, so it briefly thinks the agent is unbound and writes the plain form. If the agent's own arguments happened to be a valid declaration blob, replay would read *those* as the declaration. The agent could pass `evil.example` and cost 999 to the gatekeeper while its arguments claimed no host and cost 0. The gatekeeper now writes the declared form whenever the arguments could be mistaken for one. For an agent that really is unbound the replay ignores that form, so it costs nothing.
2. **A refusal of a reserved type was unloggable.** `cairn/delegate` is a real governance action. An agent that had never held a grant and asked the gatekeeper for it was refused correctly, but the refusal was recorded *as* a `cairn/delegate` intent, which replay then judged as a delegation and rejected. The refusal was lost. Reserved types are now always recorded as events.
3. **Revoking a parent cancelled a child's own scheduled grant.** If governance had separately approved a root grant for an agent that was also holding a delegated one, revoking the delegator wiped the scheduled grant too. That grant did not come from the revoked key. Revocation now removes the revoked key's own scheduled grants, and below it only what was delegated.
4. **A host that is not valid UTF-8 was an unlogged error.** The declaration could not be encoded, so the action failed with no record. It is now refused and recorded.

Neither model is the answer. Gemini would have let this ship. OpenAI found real problems that Gemini missed, and in earlier rounds it found far more than Gemini did. The process that works is the dull one: two vendors, verbatim code, and every finding checked before anything changes.

## The pains

We were asked to be plain about these, so here is the list without the polish.

**The audits themselves are fragile.**
- Gemini made a false finding because we had not given it the `wire` package source; it assumed how a length prefix and a count were read, and was wrong on both points. It also caught one genuine mismatch, where the spec said a delegation's arguments were `child | grant` with no length prefix and the code wrote one. We fixed the code to the spec.
- Asked to act as a "hostile security reviewer", a model refused. Re-framed as a correctness review of the same code, it complied. The framing, not the task, was the problem.
- `gemini-3-pro` and the versioned `gemini-2.5-*` names return 404. Only `gemini-pro-latest` works. An OpenAI key with no credit looked healthy until we made a real call. A reachable API is not a funded one.
- Reviewers are wrong in both directions: false positives from missing context, and confident all-clears like Gemini's above.

**Our prose was the weakest part of the code.** Dev log 6 was mostly about this. "Exactly one encoding" was false. "Whatever later epochs say" was false. "Enforced" and "frozen" were each false in a specific way. The code fixes took an afternoon and the words took longer.

**Tests that cannot fail.** The mutation tool exists because we did not trust our own tests. It changes one piece of source, runs the suite, and reports whether anything noticed. Every list has the same three kinds of entry: mutants the tests killed, mutants that turned out *equivalent* (no test can tell the difference, and we write down why), and mutants that were *invalid*, meaning the text appeared twice or the result did not compile. In this round five of our own mutants came back invalid because we had written them badly, which is the tool doing its job: a mutant that does not apply tests nothing, and it says so.

**Our own enforcement code surprised us.** Three examples from this round:
- A delegation is logged as an action intent that is never completed, because there is no completion for a delegation. So a delegating agent always has an open intent, and two tests that tried to close the delegator's actions failed with `bad_action_completion` until we understood why.
- A new root grant takes effect when replay reaches an entry at or after its effective time, so the state a gatekeeper reads is one entry stale at that moment. The first action after a grant takes effect needed a retry in the other form. OpenAI's first finding above is the sharp edge of that same lag.
- A test grant built as a zero value has `not_after = 0`, which means it expired at the beginning of time. Two tests passed for the wrong reason until we saw that.

**Order matters more than we thought.** In dev log 6 the log server charged a rate limit before it checked an entry was stale, which let anyone spend another key's budget by replaying its public entries. In this round the order of the grant checks is spelled out in the spec and fixed by tests, because the first failing check decides the error code, and two implementations must agree on it.

**Process pains.** A host with no Go toolchain meant every build runs in Docker. A blocked long `sleep` made us learn the monitor tool. Docker prints a kernel-support warning that leaked into our first evidence files and had to be stripped. Small things, each a few lost minutes.

## What the numbers look like now

- **The verifier is still under its own budget.** The parts a third party needs to run, `wire` and `ledger`, are 1,188 lines against a ceiling of 1,500. Governance is larger and is not counted, because an auditor can check a log's structure without it.
- **Mutation testing: 104 mutants, 100 killed, 4 declared equivalent, 0 survived, 0 invalid.** The raw output is in the repository, as is the race-detector run.
- **Tests: 287 top-level tests under `-race`.** Every package passes.
- **CI has gates for** formatting, vet, race tests, fuzz targets, mutation, no third-party dependencies, current test vectors, and the spec listing exactly the error codes the code has.

## What is still not built

The per-agent sandbox. A policy switch that says "every agent must hold a grant", so that never having one stops being a loophole. Witness gossip and the C2SP witness protocol. Hash-only action payloads. Council resampling. An audit mode. Tile serving. Invariant I4.

## What we learned

The pattern across ten posts is that the failures that cost us were never clever attacks. They were sentences that claimed more than the code did, tests that passed for the wrong reason, and an order of operations nobody had written down. The tooling that helped was boring: a second reviewer from a different vendor, a tool that deletes one line and asks whether anyone noticed, and a rule that every claim in the docs has a test or a stated limit next to it.

The repository is at github.com/cockyapple/cairn.
