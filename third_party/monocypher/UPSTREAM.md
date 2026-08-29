# Monocypher upstream snapshot

- Upstream: https://github.com/LoupVaillant/Monocypher
- Release: `4.0.3`
- Archive: https://github.com/LoupVaillant/Monocypher/releases/download/4.0.3/monocypher-4.0.3.tar.gz
- Archive SHA-256: `8cc9bc341a66249016db9bd70e9142d8d0aef9945973744b1ac05dbc55d8ee66`
- Imported: 2026-08-28
- License: 2-clause BSD or CC0 1.0 Universal, at the user's option

Only `monocypher.c`, `monocypher.h`, `monocypher-ed25519.c`,
`monocypher-ed25519.h`, and `LICENCE.md` are included. These files are
unmodified from the release archive. Local secure-buffer ownership, PPK
validation, public-key comparison, and libssh2 callback integration are
implemented outside this directory.

Version 4.0.3 is intentionally required because its EdDSA implementation
includes the upstream timing-leak fix published with that release.
