# Abuse and misuse cases

Status: draft. This is a catalogue of ways Cairn could be abused or misused, so they can be
watched for and, where possible, reduced without changing the core design. It is **not** a list
of controls. Where a mitigation is an operator practice or a plan, it says so; nothing here is
built unless it says **Built**.

Source: an adversarial review by OpenAI `gpt-5.5` over the public docs (README, SECURITY,
THREAT-MODEL, CONSTITUTION, SPEC, INJECTION-DEFENSE, MODELS-AND-FLEETS, LOG-SERVER, WITNESS),
curated by hand: duplicate scenarios merged, claims checked against the repository, mitigations
rewritten so none implies a feature that does not exist. The IDs are the reviewer's. The
reviewer read the docs, not the running system, so this is a map of where to look, not a
penetration test. O-02 and W-05 were added after a later Gemini review of the docs. See also [THREAT-MODEL.md](THREAT-MODEL.md), which lists adversaries and
mitigations at a coarser grain.

Every mitigation here is judged against the rules the core lives by: standard library only, the
verifier under 1,500 lines (`wire` and `ledger`), and the model untrusted. A mitigation that
would break one of them is moved out of the core (an adapter, an operator practice, a note in
the docs) or is not proposed.

**How to read an entry.** *Status* is **Acknowledged** (the docs already say it, with the
section) or **New gap** (the docs did not, or did not clearly, until this file). *Severity* is the
impact if Cairn guarded something consequential; *likelihood* is for a typical early,
self-run deployment. Both are judgements, not measurements.

## Contents

1. [Format, version and identity](#1-format-version-and-identity)
2. [Governance capture and abuse](#2-governance-capture-and-abuse)
3. [The log as a data store](#3-the-log-as-a-data-store)
4. [Withheld payloads](#4-withheld-payloads)
5. [The gatekeeper](#5-the-gatekeeper)
6. [Witnesses and freshness](#6-witnesses-and-freshness)
7. [False assurance and social misuse](#7-false-assurance-and-social-misuse)
8. [Supply chain and operations](#8-supply-chain-and-operations)
9. [Top ten to act on first](#9-top-ten-to-act-on-first)
10. [Not preventable: non-goals](#10-not-preventable-non-goals)
11. [Monitoring checklist](#11-monitoring-checklist)

## 1. Format, version and identity

### C-01 Verifier disagreement from spec or vector drift
- **Actor:** careless operator, malicious implementer, supply-chain attacker.
- **Example:** a log is built against an untagged draft; two implementations read an edge case
  differently; the operator points auditors at the one that says `ok governance`.
- **Severity / likelihood:** high / medium while v1 is a draft.
- **Status:** Acknowledged. SPEC header: version 1 "is **not frozen**"; where vectors and prose
  disagree the vectors win. README status: vectors exist for payload formats and Merkle
  proofs but **not** for the governance replay, so a second implementation cannot check that
  part.
- **Watch for:** audit reports that omit the verifier build, spec version and vector file hash;
  two verifier builds disagreeing on the same log.
- **Mitigation:** *Planned:* governance-replay vectors; tagged releases; a signed vector file.
  *Operator practice:* record verifier commit, spec version and vector hash in every audit.

### C-02 One key in several logs, or logs confused with each other
- **Actor:** governance-washing deployer; anyone building a dashboard.
- **Example:** one founder key signs a clean staging log and a risky production log. A dashboard
  indexes by key, and the operator shows the staging log's votes and checkpoints as the
  reputation of the production one.
- **Severity / likelihood:** medium / medium.
- **Status:** **New gap** (the identity point). Entries chain by hash, so a signed entry only fits
  the history it was signed for; I infer the risk is attribution and reputation confusion, not
  signature replay. `cairn-witness` can pin the first entry (`-genesis`, "recommended", not
  required, `wrong_genesis`). `cairn-verify -genesis HEX` now pins it too (`wrong_genesis`, exit 1); without it the only identity pin is
  `-constitution`, which two different logs can share, and the closing note says no genesis was pinned.
- **Watch for:** the same public key in the TrustConfig of unrelated GENESIS entries; reports that
  do not show the genesis entry hash.
- **Mitigation:** *Operator practice, built:* pin `-genesis` on every witness; one key per log.
  *Built:* the `-genesis` flag on `cairn-verify` (outside the line budget, in `cmd/`). It is optional, so a run that omits it is still unpinned.

### C-03 Guessing the content behind a plain hash
- **Actor:** anyone who reads the public log.
- **Example:** `diff_hash`, `rationale_hash`, `comment_hash`, `eval_hash` and blob addresses are
  plain SHA-256. A reader hashes likely prompts, short comments or small configs and compares.
- **Severity / likelihood:** medium / high for short or predictable content.
- **Status:** **New gap** as a privacy warning. SPEC states the hashes are plain "on purpose" (so
  `sha256sum` works) and says a withheld payload carries a salt because without one "anyone
  could confirm a guess", but nothing says the same of governance fields.
- **Watch for:** hashes of small, templated payloads (a stock comment such as "approved").
- **Mitigation:** *Operator practice:* do not rely on a plain hash for privacy; put a random nonce
  inside any blob whose content must stay secret, or keep it as a salted opening
  (SPEC 10.4.1). Governance blobs (proposals, votes, grants) are read by the replay, so they
  must be published whole.

## 2. Governance capture and abuse

### G-01 Reviewer capture: Sybils, one owner behind many keys, rubber stamps
- **Actor:** Sybil reviewer, captured organisation, colluding reviewers.
- **Example:** a TrustConfig lists many reviewer keys that one party controls; they pass a T3 or
  T4 change with its one security reviewer; replay sees distinct keys and enough approvals.
- **Severity / likelihood:** critical / medium in self-administered setups.
- **Status:** Acknowledged. THREAT-MODEL: "Governance capture by fake reviewers" is Phase 4;
  assumption: a human reviewer population exists that is not wholly captured.
- **Watch for:** reviewer keys with shared affiliation, correlated or very fast votes, one
  organisation holding both reviewer and validator keys.
- **Mitigation:** *Outside the core:* a public reviewer registry with affiliations; a conflict
  of interest process; rotation. Cryptography cannot show that two keys are two people.

### G-02 Choosing T0 for a target the log has no floor for
- **Actor:** malicious or compromised proposer; careless reviewer.
- **Example:** a proposal for an application target (not `cairn/`) is filed at T0, which needs no
  votes and no delay, but its diff loosens a limit; a validator activates it.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. SPEC 10.5, "Tier floors for other targets": the log fixes floors only
  for reserved `cairn/` targets; a verifier can pass a `MinTier` policy; the policy is not on the
  log. `MinTier` is a library option (`governance.Options`); `cairn-verify -min-tier N` applies one floor to every target (built after the DeepSeek review).
- **Watch for:** every T0 activation on a non-reserved target.
- **Mitigation:** *Operator practice:* keep a floor table for your targets and give every loader
  the same one. *Candidate, not built:* a per-target floor table on the command line; recording a policy hash on the log.

### G-03 Shortening a timelock with backdated entry times
- **Actor:** rogue operator, colluding validator, lax consumer.
- **Example:** a proposal is dated well in the past (still monotonic), so `effective_after`
  passes quickly; a consumer without a trusted clock accepts the delay as served.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. SPEC 10.5, "Time": entry times are claims; the sequencer refuses
  entries far from its clock (`MaxSkew`, **Built**); a verifier may pass `Now` and `MaxSkew`
  (`cairn-verify -use-clock`, **Built**, 5 minutes). Without them the delay rests on entry
  times alone.
- **Watch for:** entry times far from first-seen times recorded by witnesses or mirrors.
- **Mitigation:** *Built:* the sequencer clock check and `-use-clock`. *Operator practice:* loaders
  use a trusted clock and compare `effective_after` themselves; record first-seen times
  elsewhere.

### G-04 FREEZE as a denial of service, or mistaken for a kill switch
- **Actor:** compromised security reviewer or validator; a careless responder.
- **Example:** a freeze blocks activations and validator changes while a needed fix waits; or an
  operator believes "frozen" stops agents, when ACTION entries continue.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. CONSTITUTION I3 and SPEC: a freeze stops activations only; reading,
  verifying, ACTION and VOTE continue; a T0 rollback still passes.
- **Watch for:** every FREEZE; ACTION volume during a freeze; time to lift.
- **Mitigation:** *Wording:* call it a "governance freeze", never an "agent stop". *Operator
  practice:* a separate runbook to suspend an agent (revoke its key, or stop the gatekeeper).

### G-05 REVOKE used against a legitimate agent or proposer
- **Actor:** holder of a stolen security-reviewer or validator key.
- **Example:** one signature ends a proposer's or agent's authority from the next entry on; the
  revocation is permanent.
- **Severity / likelihood:** high / low to medium.
- **Status:** Acknowledged. SPEC 10.3.1: immediate, one signer, permanent.
- **Watch for:** any REVOKE; revocations by one author.
- **Mitigation:** keep the instant, one-signer form (it is the stolen-key control). *Operator
  practice:* review after the fact and publish the reason; issue the replacement key through
  normal governance.

### G-06 A stolen reviewer, validator or witness key stays valid for the delay
- **Actor:** key thief, insider, malware on a reviewer machine.
- **Example:** REVOKE does not cover these roles; the key keeps voting or signing until a T4
  VALIDATORS change clears its 14-day delay.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. SPEC 10.5, "Revoking keys that vote, validate or witness"; THREAT-MODEL.
- **Watch for:** votes or signatures from new places or hours.
- **Mitigation:** *Operator practice:* hardware keys, offline validator keys, scheduled rotation.
  A one-signer REVOKE for these roles would let one key stall governance, so it is not
  proposed.

### G-07 Weak decentralisation that still verifies
- **Actor:** a deployer using Cairn for legitimacy.
- **Example:** one validator, or several controlled by one party; `witness_threshold` of 0; witnesses
  run by the same operator. `cairn-verify` says ok, because the maths holds for that TrustConfig.
- **Severity / likelihood:** high / high for self-hosted setups.
- **Status:** Acknowledged in part. SPEC: `witness_threshold` only "MUST NOT exceed the witness
  count", so 0 is legal; n = 1 gives a quorum of 1. THREAT-MODEL assumes at least one honest,
  independent witness.
- **Watch for:** validator count, threshold and operator affiliations on any claim of
  "independent" or "community" governance.
- **Mitigation:** *Operator practice:* publish who runs each key. *Built:* `cairn-verify` prints a
  `warn:` line (never a failure) for threshold 0 or a single validator. It cannot tell one operator holding several keys from several operators.

## 3. The log as a data store

### L-01 Spam within limits, and O(n) replay cost
- **Actor:** compromised agent or proposer; a fleet of low-rate keys.
- **Example:** admitted keys submit valid entries with maximum-size blobs under their per-author
  limits; each append replays the whole log, and each witness replays it per cycle, until
  latency and witness lag grow past use.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. LOG-SERVER: "Every append replays the whole log, so cost grows with its
  length." THREAT-MODEL, flooding row: partly built; streaming replay not built.
- **Watch for:** append latency against log size; per-author growth; blob store growth; 413, 429
  and 507 rates; witness cycle time.
- **Mitigation:** *Built:* per-author rate limits and blob, store and entry caps in the log server;
  `RateLimit` in the gatekeeper. *Planned:* a replay that does not hold every blob in
  memory. Fees or tokens are ruled out ("Not planned" in ROADMAP).

### L-02 Floods and bulk scraping of the log server
- **Actor:** outsider, scraper, hostile auditor.
- **Example:** requests to entries, blob, proof or append endpoints exhaust CPU or bandwidth, or
  harvest every blob.
- **Severity / likelihood:** high / high if exposed directly.
- **Status:** Acknowledged. LOG-SERVER: serves everything to anyone who can reach it, no TLS or
  authentication of its own; unauthenticated floods are a proxy's job.
- **Watch for:** request volume, blob hot spots, egress bandwidth.
- **Mitigation:** *Operator practice:* bind to a private interface; put TLS, authentication, caching
  and rate limits in a reverse proxy; serve entries and checkpoints publicly and blobs
  separately.

### L-03 Illegal, abusive or doxxing content in an append-only log
- **Actor:** an admitted author, a compromised agent, a hostile proposer.
- **Example:** a valid entry carries a blob of harassment, personal data, secrets or illegal
  material. The server stores and serves it; witnesses, mirrors and auditors copy it; the log
  has no delete.
- **Severity / likelihood:** critical / medium for a log with public blobs.
- **Status:** **New gap.** The docs say the log serves blobs to anyone; they do not mention
  illegal content, takedown or right-to-erasure (I searched README, SPEC, LOG-SERVER and
  THREAT-MODEL for "erasure" and "GDPR": no match).
- **Watch for:** abuse reports; unusually large or private-looking blobs; blobs from newly
  admitted keys.
- **Mitigation:** *Design fact:* the entry commits only to a hash, so a blob **can** be removed from
  a server while the entry stays verifiable; what is lost is that the content can no longer be
  checked. *Operator practice:* keep sensitive content out (use withheld payloads for ACTION
  data); decide a takedown policy for the blob store before going public; do not put personal
  data in a blob. Governance blobs must stay readable for replay, so they cannot be withheld.
  Cairn does not scan content.

### L-04 Public metadata used for surveillance
- **Actor:** an employer, a data broker, a hostile third party.
- **Example:** even with arguments withheld, a public log shows each action's type, a bound
  agent's host and cost, the timing, the agent key and the chain, enough to infer behaviour,
  customers or spend.
- **Severity / likelihood:** high / high on a public log.
- **Status:** Acknowledged. SPEC 10.4.1 lists what stays public.
- **Watch for:** scrapers; published analytics built from the log.
- **Mitigation:** *Operator practice:* coarse host names; a private log with a public checkpoint
  only; do not run an employee-monitoring deployment on a public log. Rotating pseudonymous
  agent keys is possible but not a built feature.

### L-05 A single sequencer that censors or reorders
- **Actor:** a rogue log operator.
- **Example:** the operator never accepts a REVOKE or a vote, or accepts its own entries first. A
  refused entry leaves no trace on the log.
- **Severity / likelihood:** medium to high / medium for a single-sequencer deployment.
- **Status:** Acknowledged. LOG-SERVER: a rogue server "can refuse service or reorder what it has
  not yet accepted."
- **Watch for:** submitters whose own record of attempts exceeds what the log holds.
- **Mitigation:** *Operator practice:* submitters keep their own record of what they sent and when.
  *Planned:* more than one sequencer (Phase 4). Do not claim censorship resistance for this
  stage.

## 4. Withheld payloads

### H-01 Selective disclosure
- **Actor:** a dishonest operator or gatekeeper.
- **Example:** harmful arguments and results stay withheld; harmless openings are shown to an
  auditor, who finds everything shown verifies.
- **Severity / likelihood:** high / high where withheld payloads are used.
- **Status:** Acknowledged. SPEC 10.4.1: a verifier "cannot check that an opening exists for a
  commitment nobody discloses." README and ROADMAP list "a proof that an opening exists" as
  not built.
- **Watch for:** the share of commitments never opened; intents open for a long time; refusals to
  open high-risk actions.
- **Mitigation:** *Operator practice:* a retention and disclosure policy; an independent auditor
  holding encrypted copies of openings. Neither is built.

### H-02 Commitments that can never be opened
- **Actor:** a careless operator, or a compromised gatekeeper.
- **Example:** the default in-memory store loses openings on restart; or the store fails on a
  result after the action already ran.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. SPEC 10.4.1: the default store is in memory; the directory store syncs
  each file and its directory; the store is written before the entry that commits to it.
  Backup or replication of the store is not built (ROADMAP).
- **Watch for:** store errors; a commitment with no matching opening during a spot check.
- **Mitigation:** *Built:* the directory store (`DirOpenings`). *Operator practice:* never use the
  in-memory store in production; back the directory up and test a restore.

### H-03 Weak or reused salts
- **Actor:** a lazy implementer, or a malicious gatekeeper.
- **Example:** a custom gatekeeper uses a fixed or reused salt, so identical payloads give
  identical commitments and low-entropy payloads can be guessed.
- **Severity / likelihood:** medium / low to medium.
- **Status:** **New gap** as a warning. The shipped `governance.NewOpening` draws 32 bytes from
  `crypto/rand` (`governance/opening.go`) and each call is fresh. The format cannot check
  randomness: a commitment is only a hash of `salt | payload`.
- **Watch for:** two commitments that are equal; repeated salts in openings an auditor is given.
- **Mitigation:** *Operator practice:* use `NewOpening` and do not hand-roll openings; an auditor
  checks disclosed openings for repeats. A statistical check on salts is not proposed.

## 5. The gatekeeper

### K-01 Going around the gatekeeper
- **Actor:** a compromised or prompt-injected agent; a careless operator.
- **Example:** the agent process holds its own signing key or tool credentials and acts, or
  writes to the log, directly.
- **Severity / likelihood:** critical / medium.
- **Status:** Acknowledged. README: the gatekeeper is a policy layer, "not an OS sandbox".
  THREAT-MODEL: "An agent holding its own signing key is outside the gatekeeper." The
  per-agent sandbox is not built.
- **Watch for:** tool-provider activity with no earlier intent on the log; ACTION entries from
  unexpected hosts.
- **Mitigation:** *Operator practice:* keep agent keys and tool credentials inside the gatekeeper;
  run the agent in a container with default-deny egress; reconcile provider logs against
  intents. *Planned:* the sandbox.

### K-02 Declared host and cost
- **Actor:** a compromised gatekeeper, or a lazy tool adapter.
- **Example:** a use blob declares an allowed host and cost 0; the call goes elsewhere or costs
  more. Replay passes because it reads only the declared values.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. SPEC 10.5: `host` and `cost` are "declared by the writer, not
  measured."
- **Watch for:** differences between logged hosts and egress, DNS or billing records.
- **Mitigation:** *Operator practice:* derive host and cost from the validated request, never from
  model-supplied fields; check against an egress proxy.

### K-03 Agents with no grant, because require-grants is off
- **Actor:** a compromised unbound agent; an operator who never turned it on.
- **Example:** an agent that has never held a grant writes ACTIONs that replay does not check
  against any grant; a later T4 change turns the rule back off.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. SPEC 10.3.4: the default is not to require; SPEC 10.5: an unbound
  agent is not checked unless the log has switched `cairn/policy/require-grants` on.
- **Watch for:** ACTIONs by an agent that never held a grant; the switch being turned off.
- **Mitigation:** *Built:* the switch (on at T3 or T4, off at T4, recorded on the log). *Operator
  practice:* turn it on before an agent can act.

### K-04 Delegated grants outlive a tightened parent
- **Actor:** a compromised agent; a careless reviewer.
- **Example:** a parent delegates a narrow grant, reviewers later shrink the parent's, and the
  child keeps what it was given.
- **Severity / likelihood:** medium to high / medium.
- **Status:** Acknowledged. SPEC 10.5: replacing a root grant with a smaller one does not shrink
  grants already delegated; revoking the key does.
- **Watch for:** child grants wider than their parent's current grant.
- **Mitigation:** *Operator practice:* short expiries on delegated grants; revoke or re-issue the
  children when tightening a parent.

### K-05 Approval fatigue, and a human decision the replay does not require
- **Actor:** a social engineer; a tired reviewer.
- **Example:** a risky action is marked for human review; the reviewer approves a model-written
  summary. The signed decision is in the completion blob; the replay does not check that one
  exists.
- **Severity / likelihood:** high / high.
- **Status:** Acknowledged. README: "signed decision is logged in the completion blob, not enforced
  by the replay" (ROADMAP: a replay rule is planned). INJECTION-DEFENSE: a human approver can be
  socially engineered.
- **Watch for:** approval latency, approvals per reviewer per hour, approvals at odd hours.
- **Mitigation:** *Operator practice:* show the reviewer the exact structured action, not prose;
  two people for high risk; cap approvals per reviewer. *Planned:* a replay rule.

### K-06 Taint evaded by restart, reset or a trusted channel
- **Actor:** a prompt-injected agent; a content author.
- **Example:** taint is kept in memory and lost on restart; or the input arrives over a channel
  marked trusted.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. README and THREAT-MODEL: per session, not per value; in memory only; a
  lie from a trusted channel is not caught.
- **Watch for:** guarded actions soon after untrusted input; `ResetTaint` records; restarts before
  risky actions.
- **Mitigation:** *Operator practice:* few trusted channels; schemas on message bodies. *Planned:* a
  replay rule; per-value tracking "if workable".

### K-07 Leaking through an allowed host
- **Actor:** a prompt-injected agent; an author of malicious tool output.
- **Example:** secrets are encoded into a query string, a title or a filename sent to a host the
  grant allows.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. INJECTION-DEFENSE: side channels inside an allowed host are reduced by
  argument schemas, not eliminated.
- **Watch for:** canary hits; unusual entropy in arguments.
- **Mitigation:** *Operator practice:* narrow argument schemas; an egress proxy; never give one agent
  private data, untrusted input and egress together.

### K-08 Data sent to a provider the operator thought was local
- **Actor:** a careless operator; a compromised provider adapter.
- **Example:** sensitive task content is routed to a cloud provider; the log shows only hashes and
  a model id, so nothing on it proves where the content went.
- **Severity / likelihood:** medium to high / medium.
- **Status:** **New gap** in the docs as a misuse case. MODELS-AND-FLEETS describes a `local_only`
  grant that makes the gatekeeper refuse to route to a cloud provider; **I found no
  `local_only` in the code, so it is a design, not a control.** Provider adapters are tested
  against local fakes only.
- **Watch for:** calls to provider endpoints for tasks classed as private.
- **Mitigation:** *Operator practice:* enforce routing outside Cairn (network policy), and filter
  content before it reaches a provider. *Planned:* the `local_only` grant.

### K-09 One agent key shared across a fleet
- **Actor:** an operator who finds per-agent keys inconvenient; a compromised instance.
- **Example:** every container of a fleet signs with the same agent key. The log cannot say which
  host did what, a grant's budget is spent by all of them at once, and revoking the key stops
  the whole fleet, which discourages anyone from revoking after a compromise.
- **Severity / likelihood:** medium to high / medium.
- **Status:** **New gap** as a misuse case. MODELS-AND-FLEETS and README describe each agent as
  isolated with its own key and grant, but nothing in the replay can tell that two processes
  share a key.
- **Watch for:** one agent key whose ACTIONs come from several hosts or overlap in time; revocations
  that are delayed because of what they would stop.
- **Mitigation:** *Operator practice:* one key and one grant per instance, delegated from a
  fleet grant (delegation only narrows), rotated and revoked individually. The core cannot
  check this.

## 6. Witnesses and freshness

### W-01 Split view without gossip
- **Actor:** a compromised operator with witnesses it can keep apart.
- **Example:** witness A is shown one history, witness B another; each signs only extensions of
  what it saw; clients in different places hold different valid checkpoints.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. THREAT-MODEL and WITNESS: no gossip between witnesses, no C2SP witness
  protocol.
- **Watch for:** `(size, root, head)` that differs between witnesses or mirrors.
- **Mitigation:** *Operator practice:* publish checkpoints on more than one channel and compare.
  *Planned:* gossip.

### W-02 A stale checkpoint passed off as current
- **Actor:** a rogue server; a network attacker; a lax client.
- **Example:** an old, valid checkpoint and the entries it covers are served, hiding a later
  REVOKE or FREEZE.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. THREAT-MODEL: a client that never sees a newer checkpoint cannot tell it
  is behind. **`cairn-verify -max-age DURATION` now exists** (see below); the library still has none.
- **Watch for:** checkpoint age; a smaller latest size on one mirror than another.
- **Mitigation:** *Operator practice:* ask more than one source for the latest size. *Candidate, not
  built:* a maximum age flag in the CLI, which needs a trusted clock.

### W-03 Witness state lost or rolled back
- **Actor:** an attacker with host access; a careless operator.
- **Example:** `witness.state` is deleted or restored from an older backup, then a forked
  history is shown; the witness no longer remembers and signs it.
- **Severity / likelihood:** high / low to medium.
- **Status:** Acknowledged. WITNESS: the state file "is the witness's memory"; if lost or rolled
  back, the witness "can be shown a fork and will sign it."
- **Watch for:** the state's size going down; a witness restarted fresh.
- **Mitigation:** *Operator practice:* durable storage, append-only backups, alerts on regression.

### W-04 A hostile or flaky witness blocks checkpoints
- **Actor:** a malicious or unreliable witness operator.
- **Example:** the trust configuration needs N witness signatures; some refuse or go offline, so no
  checkpoint reaches the threshold and verifiers reject or find nothing fresh.
- **Severity / likelihood:** medium to high / medium.
- **Status:** **New gap** as a denial-of-service case. The rule is in SPEC ("meet quorum and witness
  threshold"); WITNESS lists the refusal codes.
- **Watch for:** time since the last checkpoint that met the threshold; refusal rates.
- **Mitigation:** *Operator practice:* more witnesses than the threshold, run by different parties.
  Changing the set is a T4 VALIDATORS change, so a dead witness costs the 14-day delay.

### W-05 A witness that replays the whole log in memory
- **Actor:** a log operator who grows the log; anyone who can append many entries and large blobs.
- **Example:** the witness checks the whole log under the governance rules on every checkpoint, so its
  time and memory grow with the log. A large enough log makes the witness slow or kill it, and it
  stops signing.
- **Severity / likelihood:** medium / medium.
- **Status:** **New gap** (found by an AI review of the docs). The log server's caps (`MaxEntries`,
  `MaxStoreBytes`) bound this only if the operator keeps them below what the witness can hold.
- **Watch for:** witness memory and replay time against log size; a witness that stops signing.
- **Mitigation:** *Operator practice:* size the witness for the caps, and keep the caps below it.
  *Candidate, not built:* an incremental witness replay.

## 7. False assurance and social misuse

### F-01 "Verify OK" sold as "the agent is safe"
- **Actor:** a vendor; an operator facing a regulator; a careless auditor.
- **Example:** the verifier prints ok and the result is shown as proof of safety, honesty or
  compliance. Off-log actions, false payloads and broad grants are not covered by it.
- **Severity / likelihood:** critical / high as use grows.
- **Status:** Acknowledged. README: a passing chain is authentic and untampered, not checked for
  what a gatekeeper or agent did. **Built with this file:** every successful `cairn-verify` run
  now ends with a one-line `note:` saying so (chain-only runs say governance was not checked).
- **Watch for:** marketing or audit text that cites the verifier as proof of safety or
  compliance.
- **Mitigation:** *Built:* the notice. *Operator practice:* audit reports separate authenticity,
  governance replay, runtime evidence and safety evidence.

### F-02 Eval and rationale hashes that prove nothing about the evaluation
- **Actor:** a malicious proposer; a captured reviewer.
- **Example:** an `eval_hash` points to a cherry-picked or invented result; reviewers approve on
  it.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged. README: the log records which result reviewers saw, "not that the eval
  ran honestly"; there is no eval runner service.
- **Watch for:** results that a re-run does not reproduce.
- **Mitigation:** *Operator practice:* reproducible runs in CI; reviewers read raw data for high-tier
  changes. Signed attestations from an eval runner would live outside the core; none exist.

### S-01 Governance as cover, and blame moved to the reviewers
- **Actor:** an organisation using Cairn for legitimacy.
- **Example:** reviewers are affiliated, hurried or never shown the openings; after harm the
  operator says the community approved it or that the log verified.
- **Severity / likelihood:** high / medium to high.
- **Status:** Acknowledged in part. CONSTITUTION section 2 ("Honest limits") and the
  captured-reviewer assumption. The social side cannot be prevented by software.
- **Watch for:** unusually fast votes, unopened evidence, claims of independence with no
  affiliation list.
- **Mitigation:** *Documentation:* the operator, not the framework or the reviewers, answers for the
  deployment; publish reviewer affiliations, witness operators, the threshold and the
  disclosure policy.

## 8. Supply chain and operations

### E-01 A look-alike verifier, repository or vector file
- **Actor:** a typosquatter; a compromised maintainer; a malicious pull request.
- **Example:** a fake `cairn-verify` says ok to anything; or a change to the vector generator
  blesses bad behaviour.
- **Severity / likelihood:** high / medium.
- **Status:** Acknowledged in part. THREAT-MODEL: no reproducible build, signed releases or
  provenance yet. The stale-file test makes vector changes visible in review.
- **Watch for:** look-alike names; diffs to `testdata/vectors-v1.json` and `internal/vectorgen`;
  new dependencies.
- **Mitigation:** *Planned:* signed releases, provenance, a published checksum page. *Operator
  practice:* build the verifier from source at a pinned commit.

### O-01 Key handling failures, test keys, and a deadlocked log
- **Actor:** a lazy operator; a compromised admin; bad luck.
- **Example:** vector keys (public seeds) are used in a real TrustConfig; all role keys sit on one
  machine; a validator key is lost and the quorum cannot rotate or lift a freeze.
- **Severity / likelihood:** critical / medium.
- **Status:** Acknowledged. README: test keys "must never be used for anything real".
  THREAT-MODEL: "there is no key-recovery procedure, and a frozen log with a deadlocked quorum
  stays frozen."
- **Watch for:** any key from `testdata/vectors-v1.json` in a TrustConfig; all keys signing from one
  host.
- **Mitigation:** *Operator practice:* hardware keys, role separation, encrypted backups, a drill for
  losing a quorum, and a written decision on starting a new log (which loses continuity).
  *Built:* `cairn-verify` warns if any trust key is one of the 16 published test keys (derived from `sha256("cairn-test-key-"+name)`, checked against `testdata/vectors-v1.json` by a test). Keys derived from other public strings are not recognised.

### O-02 A stranded intent that nothing can close
- **Actor:** bad luck; a crash at the wrong moment; an attacker who can kill the gatekeeper.
- **Example:** the gatekeeper writes an agent's intent, then dies before the completion. It keeps the open
  intent only in memory, so a restart cannot write the completion, and the replay requires the oldest
  open intent to be closed before the agent's next ACTION. The agent is stuck.
- **Severity / likelihood:** medium / medium.
- **Status:** **New gap** (found by an AI review of the docs, then checked against the gatekeeper code).
  SPEC 10.4 now names it. There is no recovery entry kind.
- **Watch for:** an intent open for much longer than the agent's usual action time; an agent whose
  later actions are all refused by the log with `bad_action_completion` or `bad_action_chain`.
- **Mitigation:** *Operator practice:* a completion signed by the agent's key with the same
  `action_type` and `args_hash`, or REVOKE the key and start a new agent. *Candidate, not built:* a
  gatekeeper that rereads its own open intents from the log at start.

## 9. Top ten to act on first

The reviewer's ranking, rechecked. **Built** marks what already exists.

1. **Say a pass is not a verdict on the agent.** Built: the `cairn-verify` notice (F-01).
2. **Give every non-reserved target a tier floor, and alert on T0.** Operator practice; no CLI flag yet (G-02).
3. **Keep agent keys and tool credentials inside the gatekeeper** (K-01).
4. **Use a trusted clock in production** and record first-seen times (G-03, W-02). `-use-clock` and `-max-age` are built.
5. **Publish who runs each key.** The CLI now warns on threshold 0, a single validator, or a published test key (G-07, S-01, O-01).
6. **Set an opening-retention policy; never the in-memory store in production** (H-01, H-02).
7. **Put the log server behind a proxy, and decide a takedown policy before going public** (L-02, L-03).
8. **Compare checkpoints across witnesses and mirrors** (W-01, W-02). Gossip is not built.
9. **Governance-replay vectors, signed releases, and a genesis pin in `cairn-verify`** (C-01, C-02, E-01). The genesis pin is built; vectors and signed releases are not.
10. **Turn on require-grants before agents act** (K-03). Built.

## 10. Not preventable: non-goals

These follow from what a transparency log is. Cairn cannot stop them, so the docs should not
imply that it can:

- A captured quorum or reviewer population, or a fake "community".
- Whether a model's output, a rationale, an eval or a comment is true.
- Reviewers rubber-stamping or being socially engineered.
- Anything done outside the gatekeeper, or by a process that holds its own credentials.
- The privacy of metadata on a public log (action types, hosts, costs, timing, keys).
- Erasure of data someone chose to put in a public, append-only blob.
- Freshness without a trusted clock, gossip or an outside source for the latest size.
- A cryptographic proof that witnesses or reviewers are independent.
- A proof that an opening exists for a commitment nobody discloses.
- Leaks through channels an agent is already allowed to use.
- Legal or regulatory legitimacy conferred by a passing verifier.
- Authenticity of a binary you did not build or check yourself.

## 11. Monitoring checklist

**Verifier and spec:** verifier build, spec version and vector hash in every report; the genesis
and constitution hashes shown; two builds disagreeing on one log.

**Governance:** T0 activations on non-reserved targets; proposals under your own floor; fast or
correlated approvals; FREEZE, REVOKE and epoch changes; require-grants off.

**Time and freshness:** entry times far from first-seen times; entries dated in the future;
checkpoint age; the latest size differing between mirrors or witnesses.

**Grants and gatekeeper:** ACTIONs by an agent that never held a grant; empty hosts or zero cost on
network or spend tools; long expiries and unlimited budgets; child grants wider than their
parent's; provider activity with no earlier intent; restarts or taint resets before guarded
actions.

**Withheld payloads:** the share of commitments never opened; repeated commitments or salts; old
open intents; opening-store backup and restore failures.

**Log server and storage:** append latency against log size; blob store growth; 413, 429, 503 and
507 rates; bulk reads; missing blobs for accepted entries; abuse reports.

**Witnesses:** refusal codes (`history_diverged`, `log_shrank`, `state_error`, `unavailable`);
signing lag; state size going down; checkpoints below the threshold; threshold 0 or one operator
for every witness.

**Ecosystem:** claims that the verifier proves safety or compliance; "community-reviewed" with no
affiliations; look-alike repositories or binaries; unsigned releases; test keys in any real
TrustConfig.
