# Changelog

All notable changes are documented here, following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- P-256/P-384 private-key derivation uses compiler-resistant masked field reduction and returns only affine public coordinates; named temporary owners are erased, with compiler-created copy limits documented.

- Private PEM enforces its input cap before trimming and decodes Base64 with arithmetic classification instead of character-indexed tables.
- Native completion cleanup releases its mutation guard before allocator callbacks; request hashing also runs outside that guard.
- Freestanding cross checks compile the caller-service core root, while hosted test and measurement programs keep their OS I/O contract. The integer oracle uses a word-sized small addend on 32-bit targets.

- System CA bundles omit roots the strict parser cannot use, retaining usable roots without weakening explicit imports or resource limits.

- Cumulative name-constraint and policy work is bounded separately from discovery and policy-node storage, including failed candidate paths and native-selected verification.

### Added

- Structured shakedown benchmark rows and additional private-armor and native ownership regressions.

- Package build, preflight CI and production layer checks.
- Immutable indexed trust snapshots, retained private keys, identities and client authentication.
- Bounded portable paths, request-bound receipts, modern signatures, pins and offline CRL/OCSP evidence.
- Offline macOS/Windows native jobs with bounded admission, caller executors and late-completion ownership.
- Complete bounded RSA/EC/Ed key formats, encrypted PKCS8/legacy PEM, mathematical RSA validation and caller entropy.
- Safety-pilot local secret/guarded owners, optimized checks, vectors, parser fuzz targets and owned benchmark rows.
- Checked README usage and the private vulnerability reporting policy.

Private-primitive erasure/review gates remain open in the C1 draft; no TLS engine or production adoption is claimed.

[Unreleased]: https://github.com/pedronaugusto/cloak/commits/main
