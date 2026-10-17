# Changelog

All notable changes are documented here, following [Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.12.0] - 2026-10-17

### Added

- ML-DSA-44, -65 and -87 (FIPS 204) in certificates and TLS 1.3 CertificateVerify (RFC 9881, draft-ietf-tls-mldsa: schemes `mldsa44`, `mldsa65`, `mldsa87`), both roles, server and client certificates, in cloak's own implementation: the matrix is expanded where it is used, never held, so ML-DSA-87 signs in 18 KiB of stack and verifies in 12 KiB (std's key generation and signing take 770 KiB, its verification 290 KiB). Private keys in every RFC 9881 form (seed, expanded, both), each checked; hedged signing. Matches std byte for byte and passes Wycheproof's ML-DSA vectors. Interop with OpenSSL 4.0.3 and wolfSSL 5.9.4 both roles.
- `require_pq_auth` (client and server options of every carrier): the peer authenticates with ML-DSA, its CertificateVerify and every signature on its verified path up to the anchor; a hybrid key exchange never meets it, a provisioned PSK does. TLS 1.3 only; fails with `PqAuthenticationRequired` (insufficient_security).

### Changed

- Breaking: `certificates.certificate.Algorithm.Signature` and `.PublicKey` gain `.mldsa`; `PrivateKey.max_signature` is ML-DSA-87's 4627 bytes.
- A client offering both versions lists ML-DSA's schemes after TLS 1.2's; a TLS 1.2 handshake never selects them, and a server whose credential is ML-DSA has no TLS 1.2 suite.

### Fixed

- An Ed25519 certificate whose keyUsage asserts keyEncipherment, dataEncipherment, keyAgreement, encipherOnly or decipherOnly is refused (RFC 8410 section 5), as an ML-DSA one is (RFC 9881).
- A DTLS client's hello answering a retry request leads with its cookie, so that when the path's MTU cuts it, a stateless server finds the cookie in the first fragment: a hello made longer (here by the ML-DSA schemes) had moved the cookie past it at a 256-byte MTU, and the handshake timed out.

## [0.11.3] - 2026-10-17

### Fixed

- cloak builds for every architecture again: 0.11.2's aegis 0.1.10 gave its AArch64 data-independent-timing instructions to the assembler of an unoptimized build on x86_64 (and every architecture without the mode), which refused them, so a Debug build reaching a secret computation failed outside AArch64. On aegis 0.1.11, which keeps them to AArch64 at compile time.

## [0.11.2] - 2026-10-17

### Fixed

- X25519's time depended on its secret on an Apple M3: the key shares (`x25519`, X25519MLKEM768) and HPKE (an ECH server's long-lived key, a client's encapsulation) ran without the processor's data-independent timing mode, and the timing campaign on the ReleaseFast build told a fixed secret from random ones (|t| 20 to 30; with the mode, under 3). On AArch64 Linux (an M3 under virtualization) the 32-byte comparison behind every Finished, binder, tag and cookie check was told apart by where its inputs differed (|t| 18 to 23; with the mode, about 1). Every cloak call that computes with a secret (a connection's, a QUIC handshake's or a DTLS association's calls, the cookie check and key rotation, ticket-key rotation) now runs under aegis `Timing` (Arm FEAT_DIT), and the key-exchange and HPKE kernels run as `aegis.secret.scrubbed` computations, which also erase the stack they used: their temporaries were left on it. The P-curve agreements and the signatures already were. Nothing changes where the processor has no such mode.

### Changed

- aegis 0.1.10: data-independent timing is set on AArch64 Linux builds for a baseline CPU too, where the processor has it.
- The 32-bit Montgomery arithmetic for RSA factor validation is gone: nothing has called it since 0.6.0 dropped the primality checks, and its selects had no value barrier.
- The session cache's byte bound is an aegis budget: each kept ticket holds a reservation of its bytes and returns it as it leaves its slot (taken, expired, displaced or cleared), so the count is never adjusted by hand.

## [0.11.1] - 2026-10-17

### Added

- Kernel record layers (kTLS): after the handshake either direction of a `tls.Connection` moves to the kernel through `offload(direction, installer)`, which hands over that direction's keys and record number only at a clean boundary (every byte read given to `receive`, every record and message in it complete, every plaintext byte consumed, every byte of output acknowledged) and erases its copy once the kernel holds them; a kernel that refuses them leaves the direction in software as it was. The kernel then seals or opens application data, and the connection keeps the rest: records the kernel opens that are not application data come in through `receiveControl` (alerts, NewSessionTicket, KeyUpdate, a TLS 1.2 HelloRequest), records it sends go out through `control` and `acknowledgeControl` for the kernel to seal with their type, and `offloadRecords` keeps each epoch within its record limit from the kernel's counts (a TLS 1.3 key update a quarter before it; TLS 1.2 ends there). A TLS 1.3 key update in a kernel direction turns the epoch at once and gives the kernel the next keys through `offload` again (`offloadPending`); a kernel that refuses them ends the connection rather than go back to keys the peer has dropped. Under a kernel a KeyUpdate must be its record's only message, since Linux stops its receive path only after a record that starts with one. `send`, `output`, `acknowledge` and `receive` stop a caller that uses them on a direction the kernel holds.
- `tls.offload.linux`: `Socket.install` (the "tls" upper-layer protocol, then SOL_TLS TLS_TX or TLS_RX with the cipher's uAPI struct), `Socket.records` (the kernel's record count), `CryptoInfo` (the uAPI bytes, for a caller that installs by its own path) and `probe`, which installs throwaway keys on loopback connections and reports the versions, ciphers and directions the running kernel takes and whether it takes TLS 1.3 key updates (Linux 6.14 and later). Every cipher a kernel has: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 and AES-128-CCM, TLS 1.2 and 1.3; AES-256-CCM has no kernel cipher and stays in software. Tested on Linux 6.8 (no key updates: the connection ends at one) and 7.0 (key updates both ways), sendfile included.

## [0.11.0] - 2026-10-17

### Added

- `types.Token.eql`: a request token's generation and number, compared once where a receipt, a native path or an answer is matched to its request.

### Changed

- Breaking: `tls.Group`, `tls.Suite`, `tls.SignatureScheme` and the SRTP profiles (`tls.dtls.Datagram.Srtp`) are open enums, as `tls.Alert`, the HPKE identifiers and the certificate-compression algorithms already were: any IANA number is a value, so a group, suite, scheme or profile cloak names later is no break for a caller's `switch` (one over these now needs a `_` or `else` prong), and a number read off the wire is representable. `supported()` says whether cloak speaks one. `Group.clientShareLength`/`serverShareLength`, `Suite.version` and `Srtp.keyLength`/`saltLength` return null for one it does not. `tls.Version` stays closed: TLS versions are no registry, and their order is the min/max policy.
- Breaking: `services.Budget` is made with `Budget.init(.{ .max_jobs, .max_bytes })` and keeps its counts as two aegis budgets; `reserve` returns the `Charge` a job holds and `Charge.release` returns it under the budget's guard, so a release returns exactly what its admission took (a second release of one charge stops a Debug build).
- Options naming a group, suite or SRTP profile cloak does not speak are refused (`InvalidOptions`); before, such a value could not be written. A peer's selection of one, a ticket or a DTLS cookie naming one, is refused as before, now by an explicit check at each place a number becomes one of these types.

## [0.10.5] - 2026-10-15

### Fixed

- A caller that consumes more plaintext than is readable (`Connection.consume`) or acknowledges more ciphertext than is pending (`Connection.acknowledge`, and `quic.Handshake.ack` past an event's data) is stopped in every build mode. The checks were `std.debug.assert`, which ReleaseFast takes as a fact to optimize on: such a call ran on there, with the buffer's cursors past their ends. `zig build check-failstop` runs each misuse in ReleaseFast and requires the stop.

### Changed

- Every runtime invariant (record and transcript lengths, CCM and HPKE buffer shapes, DTLS replay windows and record versions, RSA reduction bounds) is an aegis fail-stop in every build mode instead of an assertion ReleaseFast assumes.

## [0.10.4] - 2026-10-15

### Changed

- The handshake's state table is two aegis typestate machines, one per role, both versions: aegis validates each topology when it is analyzed (one edge per state and event, every state reachable from the start, no state without a way out) and a step is one table load. The states now carry what the old table kept in flags and rewrote after a step (a resumption, a certificate the server asked for, a TLS 1.2 certificate whose CertificateVerify must follow), so every transition is the table's. The phases callers see are unchanged.

## [0.10.3] - 2026-10-15

### Added

- DTLS connection IDs, both versions (RFC 9146; RFC 9147 section 9): `connection_id` on either end's options is the ID it receives with, offered or answered; once agreed every protected record carries the peer's (DTLS 1.2's tls12_cid records, DTLS 1.3's C bit), and one without this end's own, or with one when none was agreed, is dropped. `Datagram.connectionIds`, `Datagram.connectionIdOf` (the ID on a datagram, for the caller's lookup before `receive`) and `receivedNewest` (the datagram authenticated a record newer than any before it, RFC 9146 section 6's condition for following a peer to a new address). DTLS 1.3: `newConnectionIds` (spare or immediate), `requestConnectionIds`, `connectionIdsRequested`, `spareConnectionIds`, `useSpareConnectionId`; the peer's NewConnectionId and RequestConnectionId are taken only when the agreement allows them, and a request while its last is unanswered ends the association with too_many_cids_requested (`tls.Alert` names it).
- use_srtp (RFC 5764) for WebRTC: `srtp` profiles on either end's options (AES128_CM_HMAC_SHA1_80 and _32, AEAD_AES_128_GCM and AEAD_AES_256_GCM; no NULL-cipher profile, no MKI), the chosen one in `Info.srtp`, and `Datagram.srtpKeys` for this end's and the peer's master keys and salts from the "EXTRACTOR-dtls_srtp" exporter.
- `exportKeyingMaterial` (`Connection`, `Session`, `quic.Handshake`, `dtls.Datagram`) takes an optional context: null is RFC 5705's form without one, which TLS 1.2 tells from an empty context (DTLS-SRTP and EAP-TLS use it); in TLS 1.3 the two are the same. Callers passing a context are unchanged.
- A DTLS server of DTLS 1.2 alone answers the first fragment of a client's first hello with a HelloVerifyRequest (`dtls.Cookies`): OpenSSL on macOS falls back to the 256-byte minimum MTU and fragments a hello with use_srtp. A server that also speaks DTLS 1.3 still drops such a fragment, since the hello's versions may lie beyond it.
- Live interop of all this against wolfSSL 5.9.4 (DTLS 1.3 and 1.2), OpenSSL 4.0.3 and pion/dtls 3.1.12 (DTLS 1.2), both roles: connection IDs, SRTP keying material equal to each peer's, resumption from either side's tickets, key updates from cloak's side.
- After a DTLS 1.3 handshake each NewSessionTicket, KeyUpdate, NewConnectionId and RequestConnectionId is a flight of its own with its own timer (RFC 9147 section 5.8.4). A client that receives records under keys it does not hold yet answers with an ACK of what it has, or of nothing, and a server sends its handshake flight again at such an ACK or a partial one, at most once a timer period.

### Fixed

- The TLS 1.2 exporter always put a context in its seed, so keying material meant to have none (RFC 5705 section 4) could not be had; null now leaves it out.
- DTLS 1.3: a peer's KeyUpdate request while this end's NewSessionTicket waited for its ACK started a new flight, and the ticket was never sent again; a ticket lost then was lost for good.
- DTLS 1.3: a client took the server's application data for the ACK of its final flight and stopped sending that flight again, so a server that sends before the client's Finished arrives (RFC 9147 section 5.8.1 allows it) never completed when that flight was lost. Only the ACK ends the wait now.
- DTLS 1.3: a client ACKed the server's last handshake flight, which its own final flight answers (RFC 9147 section 7.1); an ACK too long for the datagram was never sent, and now lists the newest records that fit, in increasing order.

### Changed

- A server connection is 32 bytes larger at creation (two options), 1,144 bytes; an idle client connection 2,024 bytes with its struct, of the design's 2 KiB.

## [0.10.2] - 2026-10-15

### Changed

- Every comparison of a secret or a MAC (Finished, PSK binders, the AES-CCM tag, ECH confirmations, DTLS cookies, certificate pins, verification request digests, the curve-scalar range check) runs aegis's `Choice` kernels instead of std's `timing_safe`, releasing only the completed verdict. aegis 0.1.9, whose kernels now compile for every target cloak builds for.

## [0.10.1] - 2026-10-15

### Fixed

- A client that offers certificate compression and ECH together completes the handshake: its compress_certificate extension sat inside the run of extensions the encoded inner hello leaves to the outer one, so the server rebuilt an inner hello in another order than the client's, the two transcripts split, and the handshake failed with bad_record_mac. It now comes before that run.

## [0.10.0] - 2026-10-15

### Breaking

- `tls.Group` gains `mlkem768` (MLKEM768, 513) and `mlkem1024` (MLKEM1024, 514), pure ML-KEM key exchange (draft-ietf-tls-mlkem): an exhaustive switch over the groups needs the two arms.

### Added

- MLKEM768 and MLKEM1024, both roles, TLS 1.3, QUIC and DTLS 1.3: the client's share is the encapsulation key, the server's the ciphertext, the secret ML-KEM's alone; the server checks the encapsulation key (FIPS 203) and a damaged ciphertext is implicitly rejected. For a policy that wants no elliptic curve in its key exchange (CNSA 2.0): never in the default offer, used only when listed in `groups`. They are not hybrids: `require_hybrid` is not met by them, and a list of only pure groups with `require_hybrid` is refused. Failure catalogue row F91 covers them. Live interop against OpenSSL 4.0.3 (both groups) and Go 1.27.1 (MLKEM1024), both roles.
- `Group.default`, the one default offer every carrier's options take, and `Group.classical`, the groups TLS 1.2 has.

### Changed

- TLS 1.2 is offered or accepted only when a classical group (X25519, P-256, P-384) is listed: a list of only post-quantum groups no longer advertises a version it cannot agree on.
- A DTLS client's first hello carries at most one classical share (X25519 when listed), and none for a hybrid-only or post-quantum-only list: their shares do not fit one datagram beside the hello, so a stateless cookie server dropped it and the handshake timed out (X25519MLKEM768 alone, or `require_hybrid`, included). The server asks for its group with the retry request that brings its cookie.

## [0.9.2] - 2026-10-14

### Added

- DTLS 1.3 (RFC 9147) and DTLS 1.2 (RFC 6347), both roles: `tls.dtls.Datagram`, a sans-I/O association that takes whole datagrams and the caller's monotonic time, the same handshake as TLS (suites, groups, certificates, client certificates, ALPN, exporters, TLS 1.3 tickets) over its own records: epochs, record-number encryption, replay windows, message sequencing, fragmentation to the MTU (`setMtu`) and reassembly, the flight and its retransmission timer, DTLS 1.3 ACKs and key updates. Invalid datagrams are dropped, never fatal; failed openings count against each AEAD's forgery limit. `tls.dtls.Cookies` checks a server's client statelessly first (a HelloRetryRequest with a cookie, or a HelloVerifyRequest), and the admitted association resumes from it; without one the server sends at most three times what it received until the client's keys prove its address. Live interop against OpenSSL 4.0.3 (DTLS 1.2) and wolfSSL 5.9.4 (DTLS 1.3 and 1.2), both roles. Connection IDs are not built yet.
- The failure catalogue's DTLS rows (F77-F82) and fuzz properties of the datagram carrier.

### Changed

- A session ticket's format byte names its carrier too: a DTLS ticket never resumes over TLS or the reverse. TLS tickets keep their format.

## [0.9.1] - 2026-10-14

### Added

- Provisioned (external) PSKs, PSK-DHE only, TLS 1.3 and QUIC: a client offers `external_psk` (an opaque identity, its key and the key's hash) instead of a ticket; a server finds keys through `external_psk`, a lookup that sees the identity, the server name, the chosen protocol and the transport, so the caller binds each key to what it was provisioned for. A handshake on a key authenticates both ends by it, with no certificate either way and no X.509 identity implied (`Info.external_psk`); its binder is RFC 8446's "ext binder", so a key never passes for a ticket; identities are compared as exact bytes; such a session issues and keeps no tickets. Failure catalogue rows F85 and F86.

### Changed

- An idle client connection holds 48 bytes more heap (the key option, 1,992 bytes with its struct, near the design's 2 KiB) and a server connection 16 more.

## [0.9.0] - 2026-10-14

### Breaking

- `tls.Group` gains `secp256r1_mlkem768` (SecP256r1MLKEM768, 4587) and `secp384r1_mlkem1024` (SecP384r1MLKEM1024, 4589), the NIST-curve ML-KEM hybrids of draft-ietf-tls-ecdhe-mlkem: an exhaustive switch over the groups needs the two arms.

### Added

- The two hybrids, both roles, TLS 1.3 (and QUIC): the ECDH value first, then ML-KEM's, in the key share and the secret (X25519MLKEM768 keeps its ML-KEM-first order). Not in the default offer; list them in `groups`. `require_hybrid` accepts any of the three hybrids. A TLS 1.2-only offer without a classical group is refused. Failure catalogue row F91 (the group layouts).

### Changed

- The largest key share is now 1,665 bytes, so a client handshake's peak grows by about 1.4 KB (two shares and the hello's room for them), to about 49 KiB; SecP384r1MLKEM1024 keeps its ML-KEM seed and expands it again to decapsulate, rather than hold a larger expanded key in every share.

## [0.8.2] - 2026-10-14

### Added

- Certificate compression (RFC 8879) through codecs the caller supplies: `certificate_compression` on clients (decoders, offered in TLS 1.3) and servers (encoders, used when the client lists the algorithm and the result is smaller), in `tls.Connection`, `tls.Session` and `tls.quic.Handshake`; `tls.certificate_compression.Codec`. cloak holds no codec. A compressed certificate's declared length is bounded by the handshake message limit before it is decoded, and must be what the codec produces. Failure catalogue row F87.

### Changed

- An idle connection holds 16 bytes more heap (the codec option), and a server connection never spoken to 16 more.

## [0.8.1] - 2026-10-14

### Added

- Encrypted Client Hello (RFC 9849), both roles, in `tls.Connection`, `tls.Session` and `tls.quic.Handshake`, on cloak's own HPKE (RFC 9180 base mode: X25519, HKDF-SHA256, AES-GCM and ChaCha20-Poly1305). A client's `ech` option takes the server's ECHConfigList, which makes ECH required (TLS 1.3 only; `error.EchRejected` with an ech_required alert when the server does not accept it), or `.grease`. After a rejection that authenticated the config's public name, the server's retry configs are `echRetryConfigs()` (a `tls.Session` hands them over through `ech_retry`). A server's `ech_keys` are its configs with their X25519 secrets; `tls.ech` builds configs, lists and key pairs. `Info.ech_accepted` says whether a handshake used the inner hello. Failure catalogue rows F75 and F76.

### Changed

- An idle connection holds 8 bytes more in its struct (`Info.ech_accepted`), and 32 bytes more heap for a client (the ECH mode and its retry configs) and 16 for a server (its ECH keys); a client handshake's peak grows by about 750 bytes (the inner transcript and HPKE context ECH may need).

## [0.8.0] - 2026-10-14

### Breaking

- `tls.Suite` gains `aes_128_ccm_sha256`, `ecdhe_ecdsa_aes_128_ccm` and `ecdhe_ecdsa_aes_256_ccm`: an exhaustive switch over it needs the three cases.

### Added

- AES-CCM: TLS_AES_128_CCM_SHA256 (TLS 1.3) and TLS_ECDHE_ECDSA_WITH_AES_128_CCM and _AES_256_CCM (TLS 1.2, RFC 7251), for devices whose AES lacks a fast GHASH. They are offered and accepted only when listed in `suites`, never by default; CCM_8's eight-byte tag is not offered. The AEAD is cloak's own AES-CCM with a 12-byte nonce and a 16-byte tag (std's fixes a 13-byte nonce), pinned by Wycheproof, its tag checked in constant time before any plaintext is released. A CCM key protects at most 2^23 records (RFC 9147 appendix B, half GCM's), so a TLS 1.3 connection updates its keys sooner and a TLS 1.2 one closes sooner.

## [0.7.2] - 2026-10-14

### Changed

- The handshake engine is told what carries it (a stream, QUIC or datagrams), the seam the DTLS carrier drives (C8, docs/design.md "DTLS"): over datagrams it speaks DTLS's wire versions (0xfefd, 0xfefc), the ClientHello's cookie field, the "dtls13" label prefix of DTLS 1.3, DTLS 1.2's transcript of messages with their DTLS headers, and the client's answer to a HelloVerifyRequest, with no middlebox compatibility. TLS and QUIC connections are unchanged; nothing public changed.

## [0.7.1] - 2026-10-14

### Fixed

- A TLS 1.2 client certificate with an Ed25519 key is presented and signed: Ed25519 signs the handshake messages themselves (RFC 8422 section 5.10), which the client now keeps whole while such a certificate is configured. The client answered with no certificate, and a server that required one refused the connection (found by relic against OpenSSL). A TLS 1.2 server asking for a certificate accepts an Ed25519 one the same way, keeping the messages until the client's CertificateVerify.

## [0.7.0] - 2026-10-14

### Breaking

- `tls.SessionCache.take` takes the protocol version of the ticket wanted; a cache entry's `secret` (a TLS 1.3 PSK or a TLS 1.2 master secret) replaces `psk`, its `suite` is a `tls.Suite` of either version, and it records its `version` and key exchange `group`. Callers that only hand a cache to connections are not affected.

### Added

- TLS 1.2 session tickets (RFC 5077), off unless both ends ask: `resumption.tls12` on a client, `tls12_tickets` on a server (`tls.Connection`, `tls.Session`), from the same `tls.SessionCache` and `tls.TicketKeys`. An abbreviated handshake reuses the session's master secret without a new key exchange, which is why it is opt-in; the extended master secret stays required. A ticket's format names its version, so neither version's ticket resumes the other. `Info.group` of a resumed TLS 1.2 session is the original handshake's.

### Changed

- Tickets issued by 0.6.1 servers no longer open (their state gained the key exchange group): clients holding them do one full handshake.

## [0.6.1] - 2026-10-14

### Added

- TLS 1.3 session resumption, PSK-DHE only, in `tls.Connection`, `tls.Session` and `tls.quic.Handshake`. A client resumes from a `tls.SessionCache` (`resumption` option: the cache, a namespace and a maximum age), keyed by everything the session's authority depended on (server name, reference identity, ALPN, transport, the whole verification policy and trust generation, the client certificate), each ticket offered once and kept no longer than its lifetime, the maximum age from the session's full handshake and the server authentication's expiry. A server issues two tickets after each handshake and resumes from them with `tls.TicketKeys` (`tickets` option), a ring the caller rotates with its own key material: each ticket is sealed under a key derived from a fresh salt, so no nonce state is shared, and a ticket resumes only with a suite of its hash, the same server name, ALPN protocol and client-certificate policy, before its expiry and the client authentication's. `Info.resumed` says whether a handshake resumed. A resumed handshake keeps the original authentication and sends no certificate either way. Under the system's verifier a `tls.Session` resumes for at most an hour after the full handshake.
- Early data is never accepted, and a server now skips a client's declined early data (up to 64 KiB, `error.EarlyDataLimit` past it) instead of failing on it; a second ClientHello that offers early data is refused.
- Failure catalogue rows F65-F74 (resumption) and the RFC 8448 section 3 and 4 resumption vectors.

### Changed

- An idle client connection holds 192 bytes more heap and a server connection 80 more (the resumption master secret, the ticket options and the cache key).

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
