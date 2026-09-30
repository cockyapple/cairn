# Cairn

A tamper-evident, community-reviewed ledger for AI agents. Every change to an
agent's behaviour and every consequential action is recorded in a public
append-only log that anyone can verify, and changes go through delayed, staked,
human-auditable review.

Cairn does not claim an agent is "unalterable" or that a model cannot be
fooled. It claims alteration is visible, governed and attributable, and that a
manipulated agent is bounded by capabilities enforced outside the model.

**Status: Phase 0.** Specification, threat model, constitution, and a Go
verifier core with conformance vectors. No network, no consensus, no agents yet.

## Layout

| Path | What |
|------|------|
| `docs/SPEC.md` | Wire format and verification rules (v1) |
| `docs/THREAT-MODEL.md` | Assets, adversaries, mitigations and their status |
| `docs/CONSTITUTION.md` | Change tiers and invariants |
| `docs/INJECTION-DEFENSE.md` | How prompt injection is contained |
| `docs/MODELS-AND-FLEETS.md` | Any LLM (cloud or local) and many agents at once |
| `docs/DECISIONS.md` | Architecture decision records |
| `wire/` | Strict canonical binary reader and writer |
| `ledger/` | Entries, chain, Merkle tree, trust config, checkpoints, verification |
| `internal/vectorgen`, `cmd/cairn-vectors` | Deterministic test-vector generator |
| `testdata/vectors-v1.json` | Language-neutral conformance vectors |

The core depends only on the Go standard library.

## Build and test

Go is not required on the host; tooling runs in a pinned container.

    make test      # go test ./...
    make vet
    make fmt
    make vectors   # regenerate testdata/vectors-v1.json (a spec change!)
    make loc       # the verifier must stay readable: budget 1,500 lines

## Safety notes

- Test keys are derived from public seeds and MUST NOT be used for anything real.
- Phase 0 proves a log is authentic and untampered. It does not yet prove the
  log is lawful under the constitution; that is the Phase 1 state machine.

License: Apache 2.0.
