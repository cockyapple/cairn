# Cairn witness

`witness` (package) and `cairn-witness` (command) are the independent cosigner. A
witness runs as its own process, ideally on a different machine under a different
operator, reads the **whole log** from a `cairn-logd` over HTTP, replays it under the
governance rules itself, and signs a checkpoint only when that checkpoint extends
everything the witness has signed before.

A validator vouches that it sequenced the log. A witness vouches that it checked the log
and has only ever been shown one history. A checkpoint that carries both (the trust
configuration's `witness_threshold`) cannot be produced by a compromised server alone:
it would need a witness to sign a history that forks from, or is shorter than, one that
witness already signed, and an honest witness refuses (SPEC section 6, THREAT-MODEL A4).

The witness trusts the server for nothing. It does not take the server's checkpoint,
status or word that a blob is current: it builds the checkpoint from the entries it
fetched and verified. The package is outside the 1,500-line verifier budget.

## What it checks, in order

Each cycle:

1. Re-read the last entry it holds; it must be byte-identical (else `history_diverged`).
   Then fetch only the new entries, checking height and `prev_hash` continuity. A page
   shorter than the page size that does not reach the log's end is refused (`unavailable`),
   so a server cannot drip-feed one entry per request.
2. Compare with its memory. A log shorter than the size it last signed is `log_shrank`
   (or `stale_size` when asked to sign a smaller prefix). A prefix root or head that
   differs from what it signed is `history_diverged`.
3. If a genesis hash is pinned, the first entry must match it (`wrong_genesis`).
4. Replay the whole log with `governance.Replay`, fetching every blob it needs, checking
   each against its hash, and bounding count and total size. Entries dated ahead of the
   witness's own clock are invalid. A governance failure is `invalid_log`; a blob the
   server would not or could not supply is `unavailable`, because that is the server's
   fault and not evidence about the log.
5. Check its own key is an admitted witness at that size (`not_a_witness`).
6. Build the checkpoint, **write the new size, root and head to the state file (fsync,
   rename, directory sync)**, and only then sign and post the 104-byte signature.

Because the state is written before the signature leaves, a crash can leave the witness
remembering a size it never delivered, never the reverse. The retry is idempotent.

## Refusal codes

Stable, matched by `witness.Code(err)`:

| Code | Meaning |
|---|---|
| `unavailable` | the server could not be read, sent something unusable, or withheld a blob |
| `log_shrank` | the log is shorter than what this witness has already signed (alarm) |
| `history_diverged` | the log does not extend what this witness signed (alarm) |
| `invalid_log` | the chain or the governance rules fail |
| `not_a_witness` | this key is not an admitted witness at that size |
| `wrong_genesis` | the first entry is not the pinned one |
| `stale_size` | asked to sign a size below one already signed |
| `bad_request` | the requested size is beyond the log |
| `state_error` | the state file is unreadable, malformed or cannot be written |
| `submit_failed` | the server refused or garbled the signature submission |

`log_shrank` and `history_diverged` are alarms: they mean the server showed this witness
two incompatible histories. `Run` logs them as `ALARM` and keeps trying, because a server
may be repaired; the witness never signs anything that fails a check.

## State file

JSON, `version` 1, mode 0600 (a file readable by group or others is refused with
`state_error`), written atomically. It holds the largest size signed and
that prefix's Merkle root and head hash. It is **the witness's memory**: if it is lost or
rolled back, the witness can be shown a fork and will sign it. Keep it on durable storage
and back it up. A state file that exists but cannot be parsed strictly (unknown field,
zero size, bad hex) stops the witness with `state_error` rather than starting from nothing.

## Running

    cairn-witness -genkey witness.key            # prints the public key only
    # add that key as a witness in the trust configuration, then:
    cairn-witness -server http://10.0.0.5:8480 -key witness.key -state witness.state \
        -genesis <hex hash of entry 0> -constitution <hex constitution hash>

`-key` must be mode 600; the seed is never printed. `-once [-size N]` signs one prefix and
exits. `-use-clock=false` disables the future-dated check. Exit status 2 on any error.

## Not built, honestly

- **No gossip or split-view detection between witnesses.** One witness catches a server
  that lies to *it*. Catching a server that shows witness A one history and witness B
  another needs the witnesses to compare notes; they do not yet.
- **Not the C2SP witness protocol.** It speaks cairn-logd's own endpoint, not
  `add-checkpoint` over signed notes, so off-the-shelf witnesses cannot cosign this log yet.
- **O(n) replay every cycle.** It re-fetches nothing it holds, but it replays every entry
  and keeps every blob in memory, bounded by `MaxEntries`, `MaxBlobs` and `MaxBlobSum`. A
  streaming replay is on the roadmap.
- **No TLS.** The transport is plain HTTP; redirects are refused. Safety does not depend on
  the transport (the witness verifies what it reads), but availability and privacy do.
- **One server, one key.** No rotation procedure beyond the trust configuration's own
  witness-key changes, and no hardware-key support.
