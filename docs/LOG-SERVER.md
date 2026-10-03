# Cairn log server

`logserver` (package) and `cairn-logd` (command) are the Stage A sequencer: the one
place that decides the order of entries. Nothing in it needs to be trusted, because
everything it stores can be re-checked with `cairn-verify`. A rogue server can refuse
service or reorder what it has not yet accepted; it cannot forge an entry, rewrite an
accepted one without the validators' checkpoint signatures disagreeing, or hide that it
did (SPEC section 6, THREAT-MODEL A4).

The server holds **no signing keys**. Validators and witnesses fetch the 81-byte
checkpoint body, sign it themselves and post the signature back. The package is outside
the 1,500-line verifier budget (only a `Checkpoint.VerifySig` export was added to `ledger`).

## What it checks, in order

1. The request parses: an entry, then 1 to 16 blobs, each at most `MaxBlobBytes`.
2. One blob hashes to the entry's `payload_hash`.
3. The author is in the current trust configuration (for the first entry: the configured
   genesis author, nobody else). With no genesis author set, an empty log refuses
   everything, so a stranger cannot claim it first.
4. `height` is the current length and `prev_hash` is the current head (409 otherwise).
5. The entry is not dated more than `MaxSkew` seconds (default 300) after the server clock
   (`future_entry`). This is the clock check the replay's `Now` option performs, applied at admission.
6. The entry cap (`MaxEntries`); blob and store caps apply as blobs are staged.
7. The signature verifies (small-order keys are rejected).
8. The author is charged one submission against its rate limit. The cheap position, clock
   and cap checks come first, so a client that lost a race for a height is told so without
   being charged; the charge comes after the signature check, so nobody can spend a key
   they cannot sign with, and it applies whether or not the entry then passes the replay,
   so a flood of validly signed junk from a real key is limited. Roles can have their own
   budget; 0 means unlimited. The first entry is exempt.
9. The whole log plus the candidate replays cleanly under `governance.Replay`. If it does
   not, nothing is written and the response carries the governance code (422).

## Storage

`-dir` holds `entries.bin` (concatenated 178-byte entries), `blobs/<lowercase hex sha256>`
and, once a checkpoint meets quorum, `checkpoint.bin`. `entries.bin` and `blobs/` are
exactly what `cairn-verify -entries ... -blobs ...` reads.

Order of writes for one append: stage new blobs in `staging/` with the entry's height,
append and fsync the entry (the commit point), move the blobs into `blobs/`. On start the
server cuts off a torn final entry, finishes or discards an interrupted append according
to whether its entry made it to disk, then **replays the entire log and refuses to start**
if anything is inconsistent: a bad chain, a blob whose name is not its hash, a missing
payload blob, a stored checkpoint that does not verify. If a disk write fails the server
stops accepting appends (`log_broken`) until it is restarted and has rechecked everything.

**Failure after the commit point.** Once the entry is fsynced it is part of the log. If a
later step fails (renaming a blob out of `staging/`, syncing a directory), the server
marks itself broken but still reports the append as accepted, because the entry is durable
and memory now matches disk; returning an error would tell the client to retry an entry
that is already committed. Every following request fails with `log_broken` until a restart
repairs the staging area. Files and their parent directories are fsynced, but this has been
reasoned about and reviewed, not tested by cutting power or killing the process at every
write.

## HTTP interface

Bodies are binary unless noted. Errors are JSON: `{"error": "<code>", "detail": "..."}`.

| Method and path | Purpose |
|-----------------|---------|
| `POST /v1/append` | Body: encoded entry, one byte blob count, then each blob as a 4-byte big-endian length and bytes. 201 `{"hash": ...}` |
| `GET /v1/entries?start=&limit=` | Concatenated entries (limit at most 1000); `X-Cairn-Size` carries the log length |
| `GET /v1/blob/{hex}` | A stored blob |
| `GET /v1/status` | JSON: entries, root, head, epoch, frozen, checkpoint size |
| `GET /v1/proof/inclusion?index=&size=` | Concatenated 32-byte hashes (RFC 9162) |
| `GET /v1/proof/consistency?first=&second=` | Concatenated 32-byte hashes |
| `GET /v1/checkpoint/body?size=` | The 81-byte body to sign; size 0 means the whole log |
| `POST /v1/checkpoint/signature` | Body: size (8 bytes, big endian), public key (32), signature (64). 202 `{"complete": bool}` |
| `GET /v1/checkpoint` | The newest signed checkpoint that met quorum and the witness threshold, 404 if none |

Signatures are accepted only from a validator or witness in the trust configuration in
force at that size. Partial signature sets are held in memory (at most 16 sizes) and a
signer whose set was lost to a restart signs again; a restart also forgets which sizes the
server was collecting for. A checkpoint for a smaller size never replaces a larger one. A
signature the server already holds is acknowledged without a rate-limit charge, so a
signer's retry loop cannot lock itself out.

## Status codes and stable error codes

| Status | Codes |
|-------:|-------|
| 400 | `malformed_request`, `too_many_blobs`, `out_of_range`, and the ledger codes `bad_length`, `bad_signature`, `bad_payload` |
| 403 | `not_genesis_author`, `unauthorized_author`, `unknown_signer` |
| 404 | `not_found` |
| 409 | `bad_height`, `bad_prev_hash` |
| 413 | `blob_too_large` |
| 422 | any governance rejection (`future_entry`, `frozen`, `revoked_key`, `time_regression`, ...) |
| 429 | `rate_limited` (with `Retry-After`) |
| 503 | `log_uninitialised`, `log_broken` |
| 507 | `log_full`, `store_full` |

Package-defined codes: `malformed_request`, `not_genesis_author`, `log_uninitialised`,
`rate_limited`, `blob_too_large`, `too_many_blobs`, `store_full`, `log_full`, `log_broken`,
`out_of_range`, `not_found`.

## Limits you should know about

- **Every append replays the whole log**, so cost grows with its length. `MaxEntries`
  (default 1,048,576) bounds it; a streaming or incremental replay is still owed.
- **Blobs are held in memory** up to `MaxStoreBytes` (default 256 MiB, the same ceiling
  `cairn-verify` accepts, so a log this server accepts is one an outside verifier can load).
- **One process, one mutex, one disk.** No replication, no high availability. A crash loses
  nothing that was acknowledged; a dead machine stops the log until it returns.
- **It serves everything to anyone who can reach it**, blobs included, and has no TLS or
  authentication of its own. Bind it to a private address or put a proxy in front. Rate
  limits apply to admitted keys only; an unauthenticated flood of garbage requests is
  the proxy's job.
- **The witness is a separate program** (`cairn-witness`, docs/WITNESS.md). The server only
  aggregates signatures; it does not speak the C2SP witness protocol or serve tiles.
- **Configuration is read at start.** Limits, the genesis author and the clock skew are
  enforced from the process's start-up flags; changing them means a restart, and the log
  does not record what they were.
- The rate-limit window and counters are in memory and reset on restart.
