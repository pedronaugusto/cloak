# Changelog

All notable changes are documented here, following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Fixed

- The private TLS transition table requires the requested client certificate response before local Finished and gates supplied credentials on possession proof.

- P-256/P-384 private-key derivation uses compiler-resistant masked field reduction and returns only affine public coordinates; named temporary owners are erased, with compiler-created copy limits documented.

- Private PEM enforces its input cap before trimming and decodes Base64 with arithmetic classification instead of character-indexed tables.
- Native completion cleanup releases its mutation guard before allocator callbacks; request hashing also runs outside that guard.
- Freestanding cross checks compile the caller-service core root, while hosted test and measurement programs keep their OS I/O contract. The integer oracle uses a word-sized small addend on 32-bit targets.

- System CA bundles omit roots the strict parser cannot use, retaining usable roots without weakening explicit imports or resource limits.

- Cumulative name-constraint and policy work is bounded separately from discovery and policy-node storage, including failed candidate paths and native-selected verification.

### Changed

- Breaking: `tls.Suite` lists the suites of both versions by IANA number (the TLS 1.3 three and the six TLS 1.2 ones), `suites` options take both and default to all nine, and `min_version` and `max_version` (`tls.Version`) bound the versions; a version is offered only when one of its suites is listed. `Info` says the `version`. `tls.Session.Signer.sign` takes the whole `SignRequest` (scheme, content, and `prehashed` for a TLS 1.2 digest).
- Breaking: `PrivateKey.noiseLength` returns `usize`, since every key a parse returns signs in the package (`Identity.noiseLength` stays optional for keys held elsewhere). `PrivateKey.max_noise` is 96 (was 48) and `PrivateKey.max_signature` 512 (was 104), RSA's needs. A parsed RSA key keeps its CRT form instead of the private exponent, and a valid key with a factor above 2048 bits is refused at parse as `UnsupportedKey`.
- Breaking: times are `std.Io.Timestamp` and spans `std.Io.Duration` across the public surface: `types.Request.time`, a receipt's `validation_time`, `expires` and `revocation_expires`, `Identity.expires`, `NativeVerification.take`'s `now`, the `time` a handshake asks for (`tls.Connection.Answer.time`), `tls.Session.Clock.fixed`, and `types.RevocationPolicy.clock_skew` and `max_age` (still at most a day and a year). Certificates and revocation evidence still count whole seconds inside, rounded down from the request's time once.
- Breaking: `tls.Session.open` and `accept` take their options last, after the buffers; `tls.Session.Signer.sign` names the scheme as `tls.SignatureScheme`, not a raw integer; `tls.Session.finish` returns `tls.Session.FinishError`; `PrivateKey.sign` with noise of the wrong length is `InvalidNoise`, no longer `SigningFailed`.
- P-256 key generation, agreement, ECDSA signing and verification run cloak's own kernel: a precomputed base comb with complete additions, constant-time signed windows over the peer's multiples, a public double-base walk for verification, and the field in assembly on AArch64 (portable Zig elsewhere, tested equal).
- Breaking: `cloak` is one build module. `cloak.certificates` and `cloak.tls` are no longer modules to import; use `cloak.certificates` and `cloak.tls` as namespaces of `@import("cloak")`. TLS builds on the certificates, which link the native trust store, so every TLS user linked it already and a second module bought nothing. Code that wrote `@import("cloak").tls` is unchanged. DTLS, when it exists, is a namespace unless it gains a dependency others should not fetch.

### Added

- TLS 1.2, both roles, as a `tls.Connection`, `tls.Session` client and server: ECDHE (X25519, P-256, P-384) with the six AEAD suites (ECDHE-ECDSA and ECDHE-RSA with AES-128-GCM, AES-256-GCM and ChaCha20-Poly1305), the extended master secret and secure renegotiation indication required, ECDSA, Ed25519 and RSA (PSS and PKCS#1 v1.5) certificates, client certificates, ALPN and RFC 5705 exporters; the downgrade sentinel and TLS_FALLBACK_SCSV are enforced, and renegotiation, compression and legacy suites are refused.
- `PrivateKey.signDigest` and `certificates.signature.verifyDigest`: signatures over a digest already computed, as a TLS 1.2 CertificateVerify needs.
- RSA signing: `PrivateKey.sign` takes `.pss` (MGF1 on the signing hash, a salt as long as the hash) or `.rsa` (PKCS#1 v1.5) on SHA-256, SHA-384 or SHA-512 for RSA keys of 2048 to 4096 bits, and `PrivateKey.signDigest` signs a digest computed elsewhere. The private operation is constant time in the key (fixed-window CRT exponentiation with masked table reads), blinded with a value drawn from 96 bytes of noise that also carry the PSS salt, and checked against the public key on the exact bytes it releases. A TLS 1.3 server CertificateVerify and a client's answer to a CertificateRequest are signed by cloak for RSA keys with rsa_pss_rsae_sha256/384/512, SHA-256 first, the noise drawn with the handshake's first entropy; the `sign` request remains for `initExternal` identities only.
- `Identity.initPem` and `ClientAuth.initPem`: a chain from the usual PEM file of a leaf and its intermediates, every block a certificate. `tls.Session.Diagnostics`, filled by `open` and `accept` when the handshake fails and by `Session.diagnostics` afterwards, says why a connection ended, which alerts crossed it, and whether a certificate was asked for; `Session.rebind` gives a kept session the `Io` of the task that reads it next.
- `PrivateKey.sign` and `Identity.sign`: ECDSA on P-256 and P-384 and Ed25519 signatures from a parsed key, with hedged nonces for ECDSA (32 or 48 bytes of noise, taken from the entropy request a handshake already makes), a masked secret multiplication and erased temporaries. The server's CertificateVerify and a client's response to a CertificateRequest are signed by cloak with them; `tls.Session`'s `signer` is needed only for a key cloak does not hold, and `open` and `accept` return `SignerRequired` up front when one is missing. `Identity.initExternal` and `ClientAuth.initExternal` carry a chain whose key is held elsewhere (a module, another process); a handshake then raises a `sign` request, and the signature is checked against the leaf before it is sent.
- `tls.Connection.server`, `tls.Session.accept` and `tls.quic.Handshake.server`: the TLS 1.3 server, with a hostile-input ClientHello parser, one HelloRetryRequest checked against the first hello, credential selection by server name (exact or one-label wildcard), the server's order for suite, group and ALPN, optional or required client certificates verified through the same request and receipt path, and CertificateVerify signed by cloak for the credential's key. In QUIC the client's transport parameters are accepted before the server sends anything. A server connection allocates its handshake scratch when the first ClientHello arrives, not when it is created, so a connection nobody has spoken to costs 896 bytes.
- Benchmarks for server handshake CPU, and a scripted client peer for testing servers.
- `tls.Connection`, a sans-I/O TLS 1.3 client with X25519MLKEM768, X25519, P-256 and P-384 key exchange (P-curves through HelloRetryRequest), ALPN, SNI, an explicit reference identity, client certificates, key updates, exporters and an NSS key-log sink. A server's certificate chain, CertificateVerify and Finished must all verify before any application byte is readable or writable.
- `tls.Session`, the same client over `std.Io` readers and writers, with a strict truncation default.
- `tls.quic.Handshake`, the record-free client handshake for QUIC: per-level handshake data, traffic secrets, provisional transport parameters and authentication as events.
- `certificates.certificate` and `certificates.signature` for strict certificate parsing and public-key signature checks.
- Bounded handshake messages (Certificate, CertificateRequest, CertificateVerify, Finished, NewSessionTicket, KeyUpdate), TLS key shares, a shared service gateway with request tokens, and a scripted test peer with named misbehaviours.
- Benchmarks for client handshake CPU and private-scalar ECDH.
- `certificates` and `tls` namespaces of the `cloak` module.
- Private TLS 1.3 AEAD epochs, strict inner/outer records, checked usage caps, erased HKDF/Finished, bounded transcripts and client/server transition foundations.
- Strict ClientHello/ServerHello/EncryptedExtensions negotiation, full erased TLS 1.3 key schedules and directional traffic-secret updates. Portable probes execute all suites and published schedule checkpoints without hosted Io.
- RFC 8448 protected-flight vectors and adversarial record, transition and extension-parser regressions. These foundations do not yet provide an encrypted stream.
- Published green aegis, preflight and shakedown pins; benchmark callers use shakedown's typed error parameter.


- Structured shakedown benchmark rows and additional private-armor and native ownership regressions.

- Package build, preflight CI and production layer checks.
- Immutable indexed trust snapshots, retained private keys, identities and client authentication.
- Bounded portable paths, request-bound receipts, modern signatures, pins and offline CRL/OCSP evidence.
- Offline macOS/Windows native jobs with bounded admission, caller executors and late-completion ownership.
- Complete bounded RSA/EC/Ed key formats, encrypted PKCS8/legacy PEM, mathematical RSA validation and caller entropy.
- Safety-pilot local secret/guarded owners, optimized checks, vectors, parser fuzz targets and owned benchmark rows.
- Checked README usage and the private vulnerability reporting policy.


[Unreleased]: https://github.com/pedronaugusto/cloak/commits/main

## Unreleased

- Adopt published aegis secret, full-capacity byte and spin-guard owners, with
  checked C1 parser/allocation boundaries and typed admission counts.
- Breaking: verification trust/policy generations, completion token fields and
  identity/snapshot generations use distinct aegis ID domains. Construct them
  with `.fromRaw(value)`; use `.raw()` only at encoding/native boundaries.
