<h1 align="center"><img alt="Cairn" src="docs/assets/cairn-logo.jpg" width="480"></h1>

<p align="center"><strong>A tamper-evident, community-reviewed ledger for AI agents.</strong><br>
Every change to an agent, and every consequential thing it does, goes into a public log anyone can verify.<br>
Changes take effect only after delayed, human-auditable review. No blockchain framework. Standard library only.</p>

<p align="center"><a href="https://cairnframework.blogspot.com">Blog</a> · <a href="docs/assets/cairn-logo-sting.mp4">5-second logo animation</a></p>

<p align="center">
<a href="https://github.com/cockyapple/cairn/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/cockyapple/cairn/actions/workflows/ci.yml/badge.svg"></a>
<img alt="Go 1.24" src="https://img.shields.io/badge/go-1.24-00ADD8">
<img alt="License Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-blue">
<img alt="Status: Phase 0" src="https://img.shields.io/badge/status-phase%200%20(spec%20%2B%20verifier%20core)-orange">
</p>

---

## Why this exists

AI agents now read untrusted text, call tools, hold credentials and move money. Two
problems follow, and neither is solved by a better model:

1. **Silent change.** A prompt, tool list, model or permission can be altered and
   nobody can prove what changed, when, or who approved it.
2. **Manipulation.** Anything an agent reads can contain instructions. Prompt
   injection cannot be made impossible at the model level, because a model reads
   instructions and data in the same channel.

Cairn takes the honest route on both. It does not claim an agent is "unalterable"
or that a model cannot be fooled. It claims:

> **Alteration is visible, delayed, reviewed and attributable, and a manipulated
> agent can do nothing its capability grant does not already allow.**

## What Cairn is

- A **transparency log** written from scratch: a hash-chained, Ed25519-signed,
  Merkle-tree-committed record of agent changes and actions, in the same family as
  Certificate Transparency and Go's checksum database, not a general smart-contract
  chain.
- A **governance process**: proposals, votes, risk tiers with timelocks, and a
  freeze, so a change to an agent takes effect only after independent review.
- A **gatekeeper design** that enforces permissions in plain deterministic code
  outside the model, so prompt injection is contained rather than merely discouraged.
- **Model-agnostic and multi-agent**: any LLM, cloud or local, and many agents at
  once, each isolated with its own key and grant.

## What Cairn is not

- Not a cryptocurrency, token or general blockchain platform.
- Not a guarantee that a model is correct or cannot be fooled.
- Not finished. See [Status](#status).

## How it fits together

```
 untrusted world                                   public, verifiable
┌────────────────┐   raw text    ┌─────────────┐
│ web, issues,   │ ────────────▶ │   READER    │  no tools, no secrets
│ code, logs     │               │   (any LLM) │
└────────────────┘               └──────┬──────┘
                                        │ schema-validated summary
                                        ▼
                                 ┌─────────────┐
                                 │    ACTOR    │  proposes tool calls
                                 │   (any LLM) │
                                 └──────┬──────┘
                                        │ structured call
                                        ▼
                                 ┌─────────────┐  1 validate  2 check grant
                                 │ GATEKEEPER  │  3 write ACTION  4 run or refuse
                                 │  (code)     │ ─────────────────────────────┐
                                 └──────┬──────┘                              ▼
                                        ▼                          ┌───────────────────┐
                                     tools                         │  CAIRN LEDGER     │
                                                                   │  hash chain       │
   proposals ─▶ reviewers vote ─▶ timelock ─▶ ACTIVATE ──────────▶ │  Merkle tree      │
                                                                   │  signed checkpoints│
                                          independent witnesses ─▶ │  witness cosigns  │
                                                                   └───────────────────┘
```

Every change follows one path: **PROPOSAL, VOTE, ACTIVATE**, with a delay set by risk
tier. Every action follows another: the gatekeeper writes an **ACTION** entry *before*
it executes.

| Tier | Examples | Minimum delay |
|------|----------|---------------|
| T0 | Tighten a limit, add a blocklist entry | none |
| T1 | Prompt wording, non-security config | 24 h |
| T2 | New tool, model swap, widened limits | 72 h |
| T3 | Permission changes, new agent role | 7 d |
| T4 | Gatekeeper code, validator set, the constitution | 14 d |

Tightening is always faster than loosening, and an agent can never vote on a change to
itself. The full list is in the [constitution](docs/CONSTITUTION.md).

## Design principles

1. **Write the protocol, never the primitives.** SHA-256 and Ed25519 from the Go
   standard library. No third-party dependencies in the core.
2. **Small trusted core.** The verifier must stay small enough to read in an afternoon
   (budget: 1,500 lines; currently about 918 lines including comments).
3. **Conformance lives in vectors, not prose.** `testdata/vectors-v1.json` is
   language-neutral, so a second implementation can prove the spec is implementable.
4. **The model is an untrusted component.** No guarantee depends on which model is
   used or on it behaving well.
5. **Be honest about what is enforced.** Commitments are labelled as commitments.
6. **Ship value before decentralization.** A single sequencer with independent
   witnesses is already useful; BFT consensus comes later.
7. **Publish the failures.** A public tamper-test log is worth more than a claim.

## Status

**Phase 0 is done: specification and verifier core.** What exists today, and what
does not, so nothing is oversold:

| | Status |
|---|---|
| Wire format, entry, chain, Merkle tree, checkpoints, quorum and witness checks | Built and tested |
| Language-neutral conformance vectors, with an independent stdlib re-derivation test | Built and tested |
| Spec, threat model, constitution, decision records | Written |
| Role, tier and freeze **enforcement** (for example, an agent key cannot VOTE) | **Not yet**: Phase 1 state machine |
| Gatekeeper, provider adapters, message bus, sandboxes | **Not yet**: designed in [docs](docs/INJECTION-DEFENSE.md), built in Phase 2 |
| Sequencer, witnesses, BFT consensus | **Not yet**: Phases 1 and 3 |
| Review web UI and eval runner | **Not yet**: Phase 2 |
| Injection benchmark, model scoring, attestation | **Not yet**: Phase 5 |

A chain that passes today's verifier is **authentic and untampered**. It is not yet known
to be **lawful** under the constitution. Do not treat it as more than that.

## Roadmap

| Phase | Weeks | Delivers | Standalone value |
|------:|------:|----------|:---:|
| 0 | 1 to 2 | Spec, threat model, constitution, verifier core, vectors | yes |
| 1 | 3 to 6 | Append-only log server, inclusion and consistency proofs, verifier CLI, witness, governance state machine | yes |
| 2 | 7 to 10 | Proposals, votes, tiers, timelocks, freeze, review UI, eval runner; **gatekeeper and provider adapters** | yes |
| 3 | 11 to 14 | First governed agent; fleet budgets, spawn limits, message bus | yes |
| 4 | 15 to 22 | Custom BFT (3f+1), specified in TLA+ and tested by deterministic simulation | research |
| 5 | 23 to 30 | Attestation, injection corpus and benchmark, per-model scoring, hardening | research |

Phases 0 to 3 are useful with a single operator. Phases 4 and 5 are research-grade and
can slip without breaking what came before. Details and the plan page are in
[docs/DECISIONS.md](docs/DECISIONS.md) and [ROADMAP.md](ROADMAP.md).

## Quick start

Go is not required on your machine; tooling runs in a pinned container. If you do have
Go 1.24, run the `go` commands directly.

```sh
git clone https://github.com/cockyapple/cairn.git && cd cairn
make test        # unit tests, vector tests, independent stdlib re-derivation
make vet
make vectors     # regenerate the golden file (a spec change: review the diff)
make loc         # verifier size against the 1,500-line budget
```

Verify a chain in code:

```go
entries, err := ledger.DecodeChain(encodedEntries) // strict decode + chain rules
sc, err := ledger.DecodeSignedCheckpoint(checkpointBytes)
err = ledger.VerifyLog(entries, &sc, &trust)       // chain + quorum + witnesses
if ledger.ErrCode(err) == ledger.CodeBelowQuorum { /* ... */ }
```

Errors carry stable string codes (`bad_signature`, `below_quorum`, ...) that the
vectors assert exactly, so another language can match them.

## Repository map

| Path | What |
|------|------|
| [`docs/SPEC.md`](docs/SPEC.md) | Wire format and verification rules, v1 |
| [`docs/THREAT-MODEL.md`](docs/THREAT-MODEL.md) | Assets, adversaries, mitigations and their status |
| [`docs/CONSTITUTION.md`](docs/CONSTITUTION.md) | Change tiers and the twelve invariants |
| [`docs/INJECTION-DEFENSE.md`](docs/INJECTION-DEFENSE.md) | How prompt injection is contained |
| [`docs/MODELS-AND-FLEETS.md`](docs/MODELS-AND-FLEETS.md) | Any LLM, and many agents at once |
| [`docs/DECISIONS.md`](docs/DECISIONS.md) | Architecture decision records |
| `wire/` | Strict canonical binary reader and writer |
| `ledger/` | Entries, chain, Merkle tree, trust config, checkpoints, verification |
| `internal/vectorgen`, `cmd/cairn-vectors` | Deterministic vector generator |
| `testdata/vectors-v1.json` | Conformance vectors |

## FAQ

**Is this a blockchain?** It is a cryptographic, append-only, publicly verifiable log
with a planned BFT validator set, but it has no token and is not built on a blockchain
framework. The word fits loosely; "transparency log" is more accurate.

**Can the AI really not be altered?** No. Nothing can promise that. Cairn makes any
alteration visible, delayed, reviewed and attributable.

**Can you stop prompt injection?** Not at the model level, and nobody can. Cairn makes
it structurally ineffective: authority is enforced by a deterministic gatekeeper outside
the model, untrusted text is treated as data, risky acts need human approval, and a
measured attack corpus gates every change. Read
[INJECTION-DEFENSE.md](docs/INJECTION-DEFENSE.md) for the full design and its limits.

**Which models work?** Any, cloud or local, through a small adapter (OpenAI-compatible
servers, Anthropic, Google, Ollama). A model with no measured injection score gets the
minimum grant.

**Why not use an existing chain or framework?** The goal is a small verifier that one
person can read, with no dependencies to audit. A general smart-contract platform is far
more surface than a transparency log needs.

## Safety notes

- Test keys are derived from public seeds and **must never be used for anything real**.
- Report vulnerabilities privately, see [SECURITY.md](SECURITY.md).

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md). The most valuable early contributions
are: a second-language verifier that passes the vectors, adversarial review of the spec,
and injection attack cases.

## License

Apache 2.0, see [LICENSE](LICENSE).
