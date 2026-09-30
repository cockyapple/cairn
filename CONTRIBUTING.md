# Contributing

Thanks for looking. Cairn is early, and careful critique is worth more than volume.

## Good first contributions

- Write a verifier in another language that passes `testdata/vectors-v1.json`. Any spec
  ambiguity you hit is a bug in `docs/SPEC.md`; please open an issue.
- Attack the spec and threat model. Break an invariant on paper.
- Add prompt-injection cases (direct, indirect, encoded, multi-turn, cross-agent).
- Fuzz the decoders.

## Ground rules

1. **Standard library only in `wire/` and `ledger/`.** A new dependency needs a written
   justification and maintainer approval.
2. **Keep the verifier small.** `make loc` has a 1,500-line budget.
3. **Spec first.** Behaviour changes start in `docs/SPEC.md` and the vectors, then code.
4. **Never change wire format without a version bump.** `make vectors` regenerates the
   golden file; a diff in `testdata/vectors-v1.json` is a spec change and must be called
   out in the pull request.
5. **No overclaiming.** Docs must say whether something is built, designed or planned.
6. **Tests are not optional.** Invalid inputs assert an exact error code.
7. **Comments explain why, not what.**

## Workflow

```sh
make fmt && make vet && make test
```

Open a pull request against `main` using the template. Keep changes focused. Security
issues go through [SECURITY.md](SECURITY.md), not public issues.

## Design changes

Anything touching the constitution invariants, risk tiers or trust model needs an entry in
`docs/DECISIONS.md` with the why and the cost.
