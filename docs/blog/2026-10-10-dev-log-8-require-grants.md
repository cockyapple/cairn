# Dev log 8: closing the loophole where never having a grant meant never being checked

*Part 11 of the Cairn series. Dev log 7 made the log hold agents to the grants they have. It ended by naming the gap: an agent that has never held a grant is not checked at all. This post is about closing that gap, one bug it turned up, and what two clean audits do and do not tell us.*

## The gap

After dev log 7, replay checked every action of an agent that held a grant against that grant. But "held a grant" was the trigger. An agent that had never been given one was unconstrained, because the rule that binds an agent to a grant could only start once there was a grant to be bound to. The simplest way around the whole system was never to ask for a grant.

That was a sensible default while grants were new. It is a poor default for anyone who wants the log to mean "everything an agent did was inside what it was allowed to do". So the fix is not to change the default for everyone. It is to let a deployment write the stricter rule into the log itself, where every verifier will read it the same way.

## What got built

A new kind of proposal, with the target `cairn/policy/require-grants`, sets whether the log requires every agent to hold a grant. The blob is two bytes: a version and a 0 or 1. Anything else is rejected with a new code, `bad_policy`.

- **It is the heaviest tier.** The change can only be made at T4: three approvals including a security reviewer, and a 14-day delay. Turning the requirement off needs the same, so it cannot be flipped quietly in either direction.
- **It takes effect like a root grant.** Replay reaches an entry whose time is at or after the activation's effective time, and from then on the rule is in force. A later activation supersedes an earlier one, even if the earlier one was set to take effect later.
- **While it is on,** an intent by an agent that has never held a grant is refused with `no_grant`, exactly as if its grant had been withdrawn.
- **Three things stay exempt on purpose.** Delegation, events, and completions. An ungranted agent can still be handed a grant, can still log an event, and can still close an intent it opened before the switch. Without those, switching the rule on would leave agents unable to get out of the state it puts them in.
- **Agents that already hold a grant are held to it either way.** Switching the rule off lets ungranted agents act again. It does not unbind anyone.

The gatekeeper needed one change. When it refuses an action, it writes its own record of the refusal, and for an agent with no grant that record was itself being refused under the new rule. It now retries the record as a `cairn/event`, which is exempt, so the refusal still lands in the log.

The spec has the rule as section 10.3.4, `review.ProposeRequireGrants` builds the proposal, and `State.RequireGrants()` reports the setting in force.

**What this does not do.** It is still a record, not a wall. The log can now say that an agent with no grant acted anyway, and replay will refuse that entry, but nothing stops a process that never writes an intent. The per-agent sandbox is still unbuilt, and that is still the item that turns detection into containment.

## The one bug, and where it came from

The integration test I wrote for the gatekeeper failed on the first run. An ungranted agent asked for an action under the new rule, replay refused it correctly with `no_grant`, and the gatekeeper then returned a raw "could not be logged" error instead of an `out_of_grant` refusal. The action was not run, which is the safe outcome, but the refusal was not in the log, which defeats the point of the log.

My first guess was that the error code was getting lost in the error wrapping. It was not. The code survived the wrapping fine. The real cause was the one above: the gatekeeper's own refusal record went through the plain path, and the plain path is exactly what the new rule refuses.

I fixed it two ways and then undid one. First I made the gatekeeper write its records in event form up front whenever the rule is on. Then the mutation tool showed that the up-front check was redundant, because the retry on `no_grant` already covers it, with or without a stale view of the log. So the up-front check came out. Less code, same behaviour, and a mutant that now has to be killed instead of surviving.

## Two audits, and this time they agreed

We sent the patch, the new file, the changed files and the spec section to Gemini and to `gpt-5.5`, using the same neutral correctness-review framing, and asking for real defects only.

**Both found nothing.** Gemini said so in a short list. OpenAI said so with a longer list of what it had checked: the canonical encoding, the inclusive effective-time boundary, the exemptions, the supersede rule, and the gatekeeper retry being limited to its own records so it cannot be used to let a real action through.

That is a good result and it should be read carefully, for a reason this project has already paid for. In dev log 7 Gemini also found nothing, confidently, and OpenAI found four real bugs. Two clean reports are evidence that the obvious mistakes are not there. They are not proof. The audits were of a small patch whose shape is close to code both models had just seen the earlier version of, which makes it easier to read as correct. We kept the mutation run and the tests as the primary evidence and treated the audits as a second opinion.

## What mutation testing said

We added 18 mutants for the new rule and 2 for the gatekeeper retry, and repaired 3 older ones. Here is what happened, including the parts that went wrong.

- **15 of the 18 policy mutants were killed straight away.** These cover the enforcement check in both directions, the effective-time boundary in both directions, the T4-only requirement, the decoder rejecting a bad version, a bad flag and trailing bytes, and the activation being scheduled with its real delay.
- **Three survived, and all three turned out to be equivalent.** The policy keeps a list of activated changes and drops the ones a later change has superseded. That dropping looked testable. It is not, because the last change in activation order that has come into effect always wins, so an older entry left in the list can never be the one chosen. The dropping only bounds the list. The third survivor is a promotion call after the replay loop that mirrors the one for root grants; a T4 activation is delayed 14 days, so no change can come into effect between the last entry and the end of the replay. Each is written into the mutant list with its reason, and into the evidence page, because "equivalent" is a claim we are making about our own gap and you should be able to check it.
- **One of my own mutants did not compile,** and three older ones went invalid because I had changed the lines they anchored on. An invalid mutant is reported, not hidden, so the full run said "3 invalid" and I fixed them. That is the tool doing its job, and it is also a reminder that a mutant list is code that rots.

The totals now: **124 mutants, 116 killed, 8 declared equivalent, 0 survived, 0 invalid.** The race run is **297 top-level tests and 201 subtests**, all passing. The raw output of both is in the repository.

## Mistakes and pains this round

- **A hung shell, from one unset variable.** I wrote a redirect to a path built from an unset variable. It became a redirect to a file at the filesystem root and the command sat waiting on input. I killed it by process ID, confirmed the stray file was not left behind, and stopped using that pattern. The cost was a few minutes; on a host where a long sleep is blocked, a command that waits forever is the failure that hurts.
- **A documentation page that had drifted.** While updating the evidence page I found it still said the mutant list was a "small sample of sixty-nine" in one place and 104 in another. The numbers had been updated in the table and not in the prose. Both now match the list. We keep writing the code and then letting the sentences about it age.
- **My first patch to the gatekeeper was bigger than it needed to be.** I covered a case the existing retry already covered. The mutation run caught that, which is a better way to find redundant code than staring at it, but the lesson is to look for the existing mechanism before adding a second.

## What is still not built

The per-agent sandbox. Witness gossip and the C2SP witness protocol. Hash-only action payloads. Council resampling. An audit mode. Tile serving. Invariant I4, that loosening a rule should be slower than tightening it. The roadmap no longer lists the require-grants switch, because it is done.

## What we learned

Closing a loophole by changing a default is a policy decision, and policy decisions belong in the log, not in a flag on one server. Putting the switch behind the heaviest approval tier, with a delay, in both directions, is what keeps a stricter rule from being a quiet one.

The other lesson is about evidence. This round both reviewers were clean, the tests passed, and the mutation tool still found a piece of code that did not need to be there, and showed which of the rules the tests pin down and which are only bookkeeping. The audits told us the patch looked right. The mutants told us which parts of it the tests actually pin down. We need both, and we should keep saying which is which.

The repository is at github.com/cockyapple/cairn.
