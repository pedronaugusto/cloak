# Changelog

All notable changes are documented here, following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.2.1] - 2026-10-12

### Changed

- Pins aegis 0.1.1, preflight 0.3.4 and shakedown 0.2.6.

## [0.2.0] - 2026-10-12

### Breaking

- cloak is developed with [bay](https://github.com/pedronaugusto/bay): preflight and shakedown are dev dependencies, and the tests, checks, examples and benchmarks are the development build's (`bay test`, `bay check`). cloak ships with aegis alone; what a project that depends on it builds is unchanged.
- `cloak` is one build module. `cloak.certificates` and `cloak.tls` are no longer modules to import; they are namespaces of `@import("cloak")`. TLS builds on the certificates, which link the native trust store, so every TLS user linked it already and a second module bought nothing. Code that wrote `@import("cloak").tls` is unchanged.
- Trust and policy generations, completion token fields, and identity and snapshot generations are distinct aegis ID types. Construct them with `.fromRaw(value)`; use `.raw()` only at encoding and native boundaries.
- `MixedTrustPolicies` is gone from `AddDerError`: a `Trust` may hold roots beside the system's policy.

### Added

- `tls.Connection`, a sans-I/O TLS 1.3 client and server:
  - X25519MLKEM768, X25519, P-256 and P-384 key exchange (the P-curves through HelloRetryRequest);
  - ALPN, SNI and an explicit reference identity;
  - client certificates, key updates and exporters;
  - an NSS key-log sink.

  A peer's certificate chain, CertificateVerify and Finished must all verify before any application byte is readable or writable.
- The TLS 1.3 server: `tls.Connection.server`, `tls.Session.accept` and `tls.quic.Handshake.server`. It has:
  - a hostile-input ClientHello parser, and one HelloRetryRequest checked against the first hello;
  - credential selection by server name (exact, or a one-label wildcard);
  - the server's order for suite, group and ALPN;
  - optional or required client certificates.

  A server connection allocates its handshake scratch when the first ClientHello arrives, so a connection nobody has spoken to costs 896 bytes. In QUIC the client's transport parameters are accepted before the server sends anything.
- `tls.Session`, the same client and server over `std.Io` readers and writers, with a strict truncation default.
  - `tls.Session.Diagnostics`, filled by `open` and `accept` when a handshake fails and by `Session.diagnostics` afterwards, says why a connection ended, which alerts crossed it, and whether a certificate was asked for.
  - `Session.rebind` gives a kept session the `Io` of the task that reads it next.
- `tls.quic.Handshake`, the record-free handshake for QUIC: per-level handshake data, traffic secrets, provisional transport parameters, and authentication as events.
- `PrivateKey.sign` and `Identity.sign`: ECDSA on P-256 and P-384, and Ed25519, from a parsed key.
  - ECDSA uses hedged nonces (32 or 48 bytes of noise, from the entropy request a handshake already makes), a masked secret multiplication and erased temporaries.
  - cloak signs a server's CertificateVerify and a client's response to a CertificateRequest itself. `tls.Session`'s `signer` is needed only for a key cloak does not hold, and `open` and `accept` return `SignerRequired` up front when one is missing.
  - `Identity.initExternal` and `ClientAuth.initExternal` carry a chain whose key is held elsewhere (a module, another process): a handshake raises a `sign` request, and the signature is checked against the leaf before it is sent.
  - RSA keys are parsed but not yet signed with.
- `Identity.initPem` and `ClientAuth.initPem`: a chain from the usual PEM file of a leaf and its intermediates. `Identity.Options.other_blocks` (`.skip`) reads a file that holds the key beside the chain.
- `Trust`: immutable indexed snapshots of the system's roots and of roots added by hand. On macOS and Windows, a chain the system refuses is still accepted when it reaches an added root under the portable verifier.
- Certificate verification:
  - bounded portable path building;
  - request-bound receipts;
  - modern signatures and pins;
  - offline CRL and OCSP evidence;
  - name-constraint and policy work bounded separately from discovery and storage.

  Native verification on macOS and Windows runs offline, with bounded admission, caller executors and late-completion ownership.
- Key formats: RSA, EC and Ed keys in their standard encodings, encrypted PKCS #8 and legacy PEM, mathematical RSA validation, and caller entropy.
- `certificates.ecdh`, ephemeral ECDH on P-256 and P-384 with masked private-scalar arithmetic; `certificates.certificate` and `certificates.signature` for strict certificate parsing and public-key signature checks.
- A scripted TLS peer with named misbehaviours for testing clients and servers, and RFC 8448 vectors.
- Benchmarks for client and server handshake CPU and private-scalar ECDH.

### Changed

- The fuzz tests are shakedown `check` properties.
- Secrets, byte capacities and spin guards are aegis's owners.
- System CA bundles leave out roots the strict parser cannot use, and keep the usable ones; explicit imports and resource limits are unchanged.
- Pins aegis 0.1.0.

### Fixed

- `tls.Session` checks a snapshot of the system's policy (`Trust.addSystem` on macOS and Windows) with the system's verifier, then with the portable one over the path the system chose. It used to hand such a snapshot, which holds no roots, to the portable verifier alone, so no public server verified there.
- A client given a fully qualified name with its trailing dot (`example.com.`) sends and checks the name without it, as RFC 6066 section 3 writes it. It used to refuse the name with `InvalidOptions`.
- PEM text before a block is skipped, as RFC 7468 section 5.2 permits: the attributes a PKCS #12 export writes, and the comments a CA bundle names each root with. Text after the last block is still refused. Reading several blocks no longer loses its place when the text ends in extra blank lines.
- The client's TLS state machine requires the response to a client certificate request before its own Finished, and accepts supplied credentials only after their possession is proved.
- P-256 and P-384 private-key derivation uses masked field reduction the compiler cannot shortcut, returns only affine public coordinates, and erases its named temporaries.
- PEM input is capped before it is trimmed, and Base64 is decoded by arithmetic, without character-indexed tables.
- Native completion cleanup releases its mutation guard before allocator callbacks; request hashing also runs outside it.
- On 32-bit targets the integer oracle uses a word-sized small addend.

[Unreleased]: https://github.com/pedronaugusto/cloak/commits/main
