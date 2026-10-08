# Changelog

All notable changes are documented here, following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- Cumulative name-constraint and policy work is bounded separately from discovery and policy-node storage, including failed candidate paths and native-selected verification.

### Added

- Package build, preflight CI and production layer checks.
- Immutable indexed trust snapshots, retained private keys, identities and client authentication.
- Bounded portable paths, request-bound receipts, modern signatures, pins and offline CRL/OCSP evidence.
- Offline macOS/Windows native jobs with bounded admission, caller executors and late-completion ownership.
- Complete bounded RSA/EC/Ed key formats, encrypted PKCS8/legacy PEM, mathematical RSA validation and caller entropy.
- Safety-pilot local secret/guarded owners, optimized checks, vectors, parser fuzz targets and owned benchmark rows.
- Checked README usage and the private vulnerability reporting policy.

Private-primitive erasure/review gates remain open in the C1 draft; no TLS engine or production adoption is claimed.

[Unreleased]: https://github.com/pedronaugusto/cloak/commits/main
