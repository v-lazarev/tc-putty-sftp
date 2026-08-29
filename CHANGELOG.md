# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html)
while it remains in the 0.x development series.

## [Unreleased]

### Added

- In-memory authentication with unencrypted and AES-256-CBC-encrypted PPK v3
  Ed25519 keys, without Pageant, puttygen, or temporary converted key files.
- Runtime-generated Ed25519 PPK diagnostics on x86 and x64, plus RFC 8032 key
  derivation, signing, and verification vectors.

### Security

- Ed25519 PPK public/private key consistency is verified before use, and seed,
  expanded-secret, signature-working, decrypted-key, and passphrase buffers are
  cleared after use.
- Ed25519 operations use pinned Monocypher 4.0.3, including its upstream EdDSA
  timing-leak fix, with complete source provenance and license notices.

## [0.2.2] - 2026-08-28

### Changed

- Encrypted PPK authentication now allows up to three interactive passphrase
  attempts. A rejected stored passphrase falls back to the same bounded prompt.
- Retry prompts identify an incorrect PPK passphrase separately from the server
  account password.

### Fixed

- Cancelling or exhausting the PPK passphrase prompt no longer falls through to
  an unrelated server-password prompt.
- Passphrase resource loading now uses an array-only helper, so accidentally
  passing a pointer is rejected at compile time. WFX smoke tests also verify
  that the packaged caption and prompt resources are complete.

## [0.2.1] - 2026-08-28

### Fixed

- Passphrase-dialog captions and labels are no longer truncated to six or
  seven characters on x64. The PPK authentication helper now passes the real
  destination-buffer size when loading localized resource strings.

## [0.2.0] - 2026-08-28

### Added

- In-memory decryption of `aes256-cbc` PPK v3 RSA keys using the three PuTTY
  Argon2 flavours and the normal hidden Total Commander passphrase prompt.
- Strict KDF, salt, ciphertext, padding, and aggregate-work bounds before
  expensive key derivation begins.
- Pinned official Argon2 reference implementation with complete provenance and
  license notices.
- Runtime-generated encrypted PPK coverage on x86 and x64, including correct,
  wrong, absent, and empty passphrases, all three Argon2 flavours, malformed
  KDF parameters, and official Argon2/AES reference vectors.

### Security

- Passphrases, Argon2 output, AES key/IV material, decrypted private blobs, and
  in-memory PEM data are cleared after use and are never logged or written to
  temporary files.

## [0.1.1] - 2026-08-28

### Added

- Bounded, metadata-only PPK preflight before opening a network connection,
  with specific diagnostics for legacy versions, encryption, unsupported key
  algorithms, malformed headers, inaccessible files, and the 64 KiB limit.
- Runtime-generated TEST-ONLY RSA PPK coverage on x86 and x64 for valid,
  corrupted, truncated, embedded-NUL, empty, and oversized
  inputs without committing a reusable private key.

### Changed

- Connection-attempt logging now records only whether key files are configured
  instead of logging their filesystem paths.
- Local PPK parsing errors no longer trigger a second generic authentication
  error dialog.

## [0.1.0] - 2026-08-28

### Added

- Live, read-only PuTTY SSH sessions in the Total Commander plugin root.
- Default Settings fallback, Unicode session names, custom ports, usernames,
  private-key paths, and deterministic collision handling.
- Strict in-memory loader for unencrypted PPK v3 RSA keys from 2048 to 8192
  bits, including HMAC verification and Windows CNG validation.
- In-memory libssh2 public-key authentication without Pageant, puttygen, or
  temporary converted private-key files.
- SHA-256 host-key fingerprints and explicit blocking of unsupported PuTTY
  proxy configurations.
- Reproducible x86/x64 build, packaging, smoke, WFX, and integration harnesses.

[Unreleased]: https://github.com/v-lazarev/tc-putty-sftp/compare/v0.2.2...HEAD
[0.2.2]: https://github.com/v-lazarev/tc-putty-sftp/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/v-lazarev/tc-putty-sftp/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/v-lazarev/tc-putty-sftp/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/v-lazarev/tc-putty-sftp/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/v-lazarev/tc-putty-sftp/releases/tag/v0.1.0
