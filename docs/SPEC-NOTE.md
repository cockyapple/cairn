# Cairn checkpoint as a C2SP signed note

Status: built (package `note`, `cairn-verify -note`), ADR-20. This document is a
companion to SPEC section 6. It does not change the ledger wire format or the vectors.

## Why

Cairn's native checkpoint is a compact binary object that only Cairn tools read. The
transparency-log ecosystem (witnesses, monitors, tile servers) speaks the C2SP formats
instead: a *signed note* carrying a *tlog-checkpoint* body, cosigned by witnesses under the
*tlog-cosignature* rule. A note lets an outside witness attest to a Cairn log without
learning the Cairn wire format. The native checkpoint stays the object Cairn signs and
verifies; the note is a second, independent signature over the same tree head, made by the
same keys.

## The note

```
<origin>\n
<size>\n
<base64(root)>\n
\n
— <name> <base64(keyid || signature)>\n      one line per signature
```

The body is the plain three-line tlog-checkpoint with **no extension lines**. A verifier
rejects any extra line, so one tree head has exactly one text. `size` is a canonical
positive decimal (no sign, no leading zeros, fits in 64 bits). `root` is canonical
standard base64 of the 32-byte Merkle root (SPEC section 5, RFC 9162). `origin` names the
log; it must also be a valid note key name (non-empty, at most 255 bytes, no Unicode
spaces or control characters, no `+`), because validators sign under it.

Framing follows the signed-note rules: UTF-8 with no control characters other than the
line feed (this verifier also rejects Unicode control characters, which is stricter than
the minimum), the text ends at the last blank line, every signature line starts with an
em dash and a space, and base64 must be canonical (padding present, no stray characters).
A note is capped at 256 KiB and 1,024 signature lines.

## Who signs, and how

| Cairn role | Signature type | Key name | Signed message |
|---|---|---|---|
| validator | `0x01` Ed25519 note signature | the log origin | the note text |
| witness | `0x04` cosignature | a name the witness chooses | `"cosignature/v1\ntime <ts>\n"` + note text |

The 4-byte key id is `SHA-256(name || 0x0A || type || public_key)[:4]`, so it commits to
the role's signature type. A witness cosignature body is a big-endian `u64` timestamp
followed by the 64-byte signature. Other roles (reviewer, proposer, agent) do not sign
checkpoints; a signature from one is treated as an unknown signer.

C2SP's cosignature does not commit to the cosigner's name, so a witness operator running
several names should use a distinct key for each.

## Verification

`note.Verify(raw, Config{Origin, WitnessNames}, trust)` accepts a note iff:

1. the trust configuration is well-formed (`TrustConfig.Validate`, which also rejects
   small-order keys) and the origin matches the one configured (`origin_mismatch`);
2. every signature line parses, and a line from an unknown (name, key id) pair is
   **ignored**, as C2SP requires;
3. a line from a known key that does not verify rejects the whole note (`bad_signature`),
   and a key may appear once (`duplicate_signer`);
4. validator signatures reach `n - (n-1)/3` (`below_quorum`) and witness cosignatures
   reach the witness threshold (`below_witness_threshold`), with the same arithmetic and
   the same trust configuration as the native checkpoint.

`note.VerifyLog(entries, raw, cfg, trust)` additionally checks the hash chain and that the
note's size and root are the ones the entries produce (`size_mismatch`, `root_mismatch`).
`trust` must be the configuration in force after entry `size-1`, which is what
`cairn-verify -note` selects using the governance replay. `note.Peek` reads the size
before any signature is checked, only so the caller can choose that configuration.

Codes are the ledger's where one applies; the note adds `bad_note` (malformed note) and
`bad_origin`.

Differences from the native checkpoint, all forced by the C2SP rules:

- Signatures need not be sorted, and a signature by an unknown key is ignored rather than
  rejected. A note's bytes are therefore **not** canonical; identify a tree head by its
  size and root, not by hashing the note.
- The note carries no epoch and no head hash. The caller supplies the trust configuration
  for the epoch it means. A witness cosigning a note attests the Merkle root, which
  commits to every entry, and does not by itself attest which governance epoch applies.
- Cosignature timestamps are not judged. Freshness is the relying party's policy.

## Cross-protocol safety

The same keys sign the native checkpoint and the note. A native signature input begins with
`"cairn/checkpoint/v1\x00"`, and a note text cannot contain a NUL byte, so a native
signature can never verify as a note signature or the reverse. The cosignature message
begins `cosignature/v1`, which also differs from every Cairn domain string.

## Tested against

- The signed-note specification's own example (a published verifier key and note),
  including that the key id we derive equals the one the spec states. This is the only
  external vector: C2SP publishes no key or note for the `0x04` cosignature, so that path
  is tested against our own signer and the spec text only.
- Round trips, quorum and threshold edges, unknown and failing signers, duplicates,
  type confusion between roles, strict text and framing cases, a fuzz target, and ten
  mutation checks of the verifier.

## Not built

The log is not served as tiles and the witness protocol (a witness fetching consistency
proofs and returning a cosignature over HTTP) is not implemented; that needs the log
server. Nothing here has been run against real witness software, so interoperability is
established from the specifications, not from a live peer.
