# Security policy

Cairn is a security project, so vulnerability reports are welcome and taken seriously.

## Status

Pre-release, Phase 0. There is no production deployment. The code has had an automated
review and is not yet independently audited. Do not rely on it to protect anything real.

## Reporting

Please **do not open a public issue** for a vulnerability. Use GitHub's private
vulnerability reporting on this repository (Security tab, "Report a vulnerability").

Include the affected file or document, what an attacker can do, and steps to reproduce.

We aim to acknowledge within 5 days and to agree a fix and disclosure timeline with you.

## In scope

- Anything that lets an invalid chain or checkpoint verify, or a valid one fail.
- Panics, hangs or unbounded allocation on hostile input to any decoder.
- Flaws in the spec, threat model or constitution that let a stated guarantee be defeated.
- Gaps in the prompt-injection containment design.

## Out of scope

- Test keys in the vectors. They come from public seeds by design.
- Attacks that require breaking SHA-256 or Ed25519.
- Claims the docs already label as not yet enforced (see README Status).

## Verifying downloads

The core has no third-party dependencies. `go.mod` contains only the module line, and
any change that adds a dependency must say why in its pull request.
