# Argon2 upstream snapshot

- Upstream: https://github.com/P-H-C/phc-winner-argon2
- Commit: `f57e61e19229e23c4445b85494dbf7c07de721cb`
- Imported: 2026-08-28
- License: CC0 1.0 Universal or Apache License 2.0, at the user's option

Only the public header and reference implementation files required by
`argon2_hash` are included. The plugin builds the reference implementation
with `ARGON2_NO_THREADS`: the PPK parallelism value still defines Argon2 lanes
and therefore the derived key, while memory filling is performed sequentially.

No upstream source file in this directory is modified. Local integration,
parameter limits, Windows CNG AES/HMAC handling, and secure-buffer ownership
are implemented outside this directory.
