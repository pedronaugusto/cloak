# Changelog

All notable changes are documented here, following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.6.0] - 2026-10-14

### Breaking

- RSA private-key parsing checks that the key's numbers agree (n = pq, e d = 1 modulo p - 1 and q - 1, dp, dq and qinv) and no longer tests p and q for primality, as Go, BoringSSL and ring do: a 4096-bit key took about 3 s to load. `PrivateKey.Entropy` and `ParseOptions.entropy` are gone, with `error.EntropyRequired`. A key whose factors are not prime releases no wrong signature: every RSA signature is checked against the public key before it leaves.

## [0.5.0] - 2026-10-14

### Breaking

- `tls.Session.failure` is a function, `failure()`, the first failure behind a `ReadFailed` or `WriteFailed`, which either task may read.
- `tls.Connection.output` takes the connection mutably: it writes what the read half owes first. `trim` keeps the output buffer once the handshake completes; `trimOutput` returns it.
- `tls.Session.info` returns `?Info`, null once the session failed: a failure erases what the handshake held, and the unwrap it did then crashed. `tls.Connection.info` reads what the handshake fixed as it completed, so either task may call it.

### Added

- A `tls.Session` may be read by one task while another writes (`reader` on one, `writer`, `keyUpdate` and `finish` on the other), with separate record states for the two halves; a KeyUpdate a peer asks for, a key update of the session's own, the refusal of renegotiation and a read failure's alert cross between them inside cloak. `tls.Connection` documents the same split for drivers of its own.
- `tls.Session.keyUpdate` and `tls.Session.exportKeyingMaterial`.
- The hardened tier: the parser properties under the fuzzer (`parser-fuzz`) and the concurrent tests under ThreadSanitizer (`concurrent`).

### Fixed

- `tls.Connection.keyUpdate` on a TLS 1.2 connection is refused with `NoKeyUpdate` instead of ending the connection.
- The test that a popped handshake output leaves no key bytes in its queue slot looks for the key's byte sequences, not for one byte value: a Debug build on the x86_64 backend fills the emptied slot with 0xaa, its pattern for undefined memory, which the test had used as its key.

## [0.4.0] - 2026-10-13

### Breaking

- `tls.Suite` lists the suites of both versions by IANA number (the three of TLS 1.3 and six of TLS 1.2); `suites` options take both and default to all nine, and `min_version` and `max_version` (`tls.Version`) bound the versions. A version is offered only when one of its suites is listed, and a client whose versions leave only TLS 1.2 must list a TLS 1.2 suite. `Info` says the `version`.
- `tls.Session.open` and `accept` take their options last, after the buffers. `tls.Session.Signer.sign` takes the whole `SignRequest`: the scheme as a `tls.SignatureScheme`, the content, and `prehashed` for a TLS 1.2 digest. `tls.Session.finish` returns `tls.Session.FinishError`.
- Times are `std.Io.Timestamp` and spans `std.Io.Duration` across the public surface: `types.Request.time`, a receipt's `validation_time`, `expires` and `revocation_expires`, `Identity.expires`, `NativeVerification.take`'s `now`, the `time` a handshake asks for (`tls.Connection.Answer.time`), `tls.Session.Clock.fixed`, and `types.RevocationPolicy.clock_skew` and `max_age` (still at most a day and a year). Certificates and revocation evidence still count whole seconds inside, rounded down from the request's time once.
- `PrivateKey.noiseLength` returns `usize`: every key a parse returns signs in the package (`Identity.noiseLength` stays optional for keys held elsewhere). `PrivateKey.max_noise` is 96 and `PrivateKey.max_signature` 512, RSA's needs. `PrivateKey.sign` with noise of the wrong length is `InvalidNoise`, no longer `SigningFailed`.
- A parsed RSA key keeps its CRT form instead of the private exponent; a valid key with a factor above 2048 bits is refused at parse as `UnsupportedKey`.
- `certificates.ecdh` is no longer public: key exchange is the TLS engine's, on cloak's own P-256 kernel and the masked P-384 walk.

### Added

- TLS 1.2, both roles, in `tls.Connection` and `tls.Session`: ECDHE (X25519, P-256, P-384) with the six AEAD suites (ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305); the extended master secret and secure renegotiation indication required; ECDSA, Ed25519 and RSA (PSS and PKCS#1 v1.5) certificates; client certificates, ALPN and RFC 5705 exporters. The downgrade sentinel and TLS_FALLBACK_SCSV are enforced; renegotiation is refused with a warning no_renegotiation and the connection goes on; compression, RSA key exchange, CBC and legacy suites are refused.
- RSA signing: `PrivateKey.sign` takes `.pss` (MGF1 on the signing hash, a salt as long as the hash) or `.rsa` (PKCS#1 v1.5) on SHA-256, SHA-384 or SHA-512 for RSA keys of 2048 to 4096 bits, of any bit length. The private operation is constant time in the key (fixed-window CRT exponentiation with masked table reads), blinded with a value drawn from 96 bytes of noise that also carry the PSS salt, and checked against the public key on the exact bytes it releases. A TLS 1.3 CertificateVerify and a client's answer to a CertificateRequest are signed by cloak for RSA keys with rsa_pss_rsae_sha256/384/512; a key restricted to RSASSA-PSS parameters signs only under the schemes they allow.
- `PrivateKey.signDigest` and `certificates.signature.verifyDigest`: signatures over a digest already computed, as a TLS 1.2 CertificateVerify needs.
- `tls.Session.closeNotified`: whether the peer ended with close_notify, for a caller that allows a bare transport end but whose framing cannot detect truncation.
- Wycheproof campaigns for ECDH on raw P-256 and P-384 points, RSA PKCS#1 v1.5 signing known answers at 2048, 3072 and 4096 bits, and every PSS salt length of `rsa_pss_misc`.

### Changed

- P-256 key generation, agreement, ECDSA signing and verification, and a parsed key's public point, run cloak's own kernel: a precomputed base comb with complete additions, constant-time signed windows over the peer's multiples, a public double-base walk for verification, and the field in assembly on AArch64 (portable Zig elsewhere, tested equal on every pair of 256-bit operands).
- Key parsing, signing and key agreement run in a frame of their own under data-independent timing (PSTATE.DIT on AArch64 with FEAT_DIT), and the stack below them is erased when they return: the compiler's spills and copies of key material no owner can name. Keys are parsed into the owner that keeps them; parsing an RSA key reaches about 40 KB of stack, where it reached about 180 KB.
- Pins aegis 0.1.6.

### Fixed

- Keying material asked of a failed connection returned through erased secrets and stopped the process; it is `WrongPhase`.
- A TLS key or traffic secret handed from the handshake to the record layer left a copy in its queue slot and in the frames between; each copy is erased.
- A TLS 1.2 ServerHello answered ec_point_formats when the client had not sent it.
- A TLS 1.2 ClientHello that lists another compression method beside null, or a legacy version above TLS 1.2 without supported_versions, is answered in TLS 1.2, as RFC 8446 requires; TLS 1.3 hellos still list null alone.
- TLS 1.2 warning alerts (unrecognized_name before a ServerHello) are passed over a few times instead of ending the handshake; TLS 1.3 keeps every alert but close_notify and user_canceled fatal.
- TLS 1.2 failures send TLS 1.2's alerts: unsupported_extension for an unsolicited ServerHello extension, handshake_failure for a non-empty initial renegotiation_info or a hello without signature_algorithms or supported_groups, record_overflow for an oversized record.

## [0.3.0] - 2026-10-13

### Breaking

- On macOS cloak opens Security from the system the first time it evaluates native policy, where it linked Security and CoreFoundation. An Apple target links only libSystem, from what Zig ships, and builds on any host without an SDK. A system without Security, or without a symbol cloak calls, makes native evaluation return `error.SystemTrustUnavailable`, which `NativeVerification.TakeError` now holds.

## [0.2.2] - 2026-10-12

### Changed

- The tests take shakedown as bay gives it, with no `.aegis = .consumer` or `useAegis` binding: bay gives a graph one aegis, so shakedown's is this package's.

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
