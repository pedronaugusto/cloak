# Credentials and certificate verification

Cloak constructs and retains credentials and verifies certificate paths.
It does not provide a TLS connection or encrypted stream.

## Layers and owners

Public owners live at the package root. `PrivateKey` retains immutable key
material, `Identity` owns public certificate encodings and a retained matched
key, and `ClientAuth` retains that identity. Final private-key release wipes its
owned material. Import preparation validates components and ranges; it is not a
private signing implementation. A passphrase is borrowed only
during construction. `credentials` owns private formats/arithmetic below those
owners, without depending on public verification orchestration.

`Trust` builds explicit roots and freezes immutable retained snapshots. A
snapshot owns its index and certificates; verification borrows a retained
snapshot. Atomic reference counts control lifetime. Mutable admission and
native completion payloads each have one owner behind one `aegis.Guarded`
lock. There is no hidden root store, background network fetch or thread owner.

`wire` validates hostile DER before `certificate` interprets it. `verify`
searches bounded candidate paths, rechecks every selected path, enforces
identity/constraints/policy/revocation and returns owned accepted-path evidence.
Constraint and policy work are cumulative, including failed candidates and
mismatched comparisons. Request limits, identity, generations, time and token
participate in receipt binding. Neither a diagnostic nor an OS verdict alone
is an authorization receipt.

The native service owns one bounded copied request and an independent completion
with one caller and one executor handle. The executor must run and release its
retained handle, even after abandonment or shutdown. Abandoned work remains
charged until its last handle is reaped. Phase/result mutations occur under one
lease; path cleanup and allocator callbacks occur after that lease is released.
Ready request hashing borrows immutable inputs outside the lock and reacquires
and rechecks readiness before transferring the result. The caller must keep the
allocator, budget and executor context alive through reaping. OS-private memory
is outside the cloak allocator and is bounded separately by job admission.

## Parsing and private material

Parsers and state transitions explicitly enable runtime safety in every build
mode. Casts carry local range/layout reasons, and temporary acquisitions use
`defer`/`errdefer` until ownership transfers. Errors contain typed status, never
private bytes. PEM enforces its cap before whitespace scanning. Private Base64
classification uses arithmetic masks at public offsets; a small separate
classifier writes directly to named wiped scratch to avoid the inspected
inline compiler spill. Public length/padding framing and the final validity
predicate are declassified. Decoder errors clear the destination. PEM compact
and DER buffers clear before release. The published aegis SecretBytes owner
retains full allocation capacity and calls rawFree after erasure, so the
allocator hook observes zeros in every mode.

Private P-256/P-384 base multiplication uses a local subset of Zig 0.17.0's
complete a=-3 point formulas and fixed-width Montgomery arithmetic (Zig contributors'
MIT notice in LICENSE). Each arithmetic truncation retains a low word or carry. Products
use double-width arithmetic with a documented overflow bound; REDC needs
one masked subtraction because canonical inputs produce a result below 2p.
Runtime safety remains enabled; fixed public limb indices and proven
double-word bounds prevent secret-dependent safety failures. Parsers and state code keep safety enabled. Selection
uses a tied register barrier on x86-64/AArch64; other backends use a live
volatile mask slot erased before return. Mask bits remain zero or all ones,
while the optimizer cannot substitute carry branches. Public fixed loop
indices select scalar bytes and scan every table entry. Inversion uses the
fixed public Fermat exponent. Only invalid-key status and the final affine
public point are disclosed; a private projective denominator never escapes.

Curve accumulator, selected point, digit and mask share one scratch owner;
field results, inversion state and point-formula intermediates have named
owners with volatile full-capacity byte wipes after last use on success and
error. Live-owner tests inspect initialized bytes before lifetime ends;
allocator tests inspect only before raw free and require erased owned buffers
in every build mode. Never inspect freed storage or an undefined typed value. These checks
and optimized caller inspection establish the named wipes. What no owner can
name (compiler spills, saved registers, by-value arguments and results in the
callees' frames) is erased by `aegis.secret.scrubbed`: key parsing, signing
and ECDH each run in a frame of their own under data-independent timing
(PSTATE.DIT where the target has FEAT_DIT), and the stack below the entry is
zeroed when they return, to a depth a test measures for every key type,
scheme and build mode. Keys are parsed into the owner that keeps them, so no
copy of the material travels back through the parser's frames. Live registers,
the entry function's own frame and a signal stack stay out of reach. Wasm
inspection cannot establish a downstream JIT's spill behavior.

## Build and verification decisions

The shipped module uses published aegis, std and native platform trust APIs.
Repository-only tooling is lazy; named test roots and exact package paths are
explicit. CI is generated by the single
canonical preflight planner. Hosted targets compile the complete tests and
measurement programs with the native SDK/linking contract. Freestanding checks
compile the caller-service core and execute its vectors in the Wasm runner;
hosted I/O/thread tests and benchmarks are not freestanding runtime claims.
Benchmarks use `Config.bench` and the test-only measurement helper, retaining
receipt/key/armor correctness checks and source metadata. Constraint and policy evaluation is outlined while preserving cumulative
work charging and request binding.

## Safety owners and scalar boundaries

The runtime pins published aegis for Secret(T), spin Guarded(T), SecretBytes,
IDs, units, checked/ranged integers and always-on programmer contracts. The
private-key state receives Material by moveInto, erasing the parser owner;
retained references and final release remain cloak policy. SecretBytes owns
PEM compact/DER and decrypted key allocations, including padding/slack. Legacy
CBC parsing borrows a shrunk live prefix from the original full allocation;
no second DER copy or truncated free exists. KDF digest/pad/derived-key owners
use inline Secret; caller passphrase and input/output borrows remain caller-owned.

Connection generation, request, trust, policy and identity generations occupy
distinct non-exhaustive enum(u64) domains. Importing an ID does not establish
freshness or authority. Request hashes serialize raw integers explicitly and
retain their existing wire encoding. Times at the public surface are `std.Io.Timestamp` (a request's
validation time, a receipt's times, `Identity.expires`, the time a handshake asks for,
`Session.Clock.fixed`) and spans are `std.Io.Duration` (revocation skew and maximum
age); inside, certificates and revocation evidence count whole seconds, rounded down
from the request's time once. Identity expiry is stored as a real-clock seconds
Instant; certificate encodings and native scalar calls use explicit raw values.
Service admission is two aegis budgets, jobs and bytes, under one spin guard, their
ceilings fixed by `Budget.init`. A job holds its `Charge` (one reservation of each)
and returns it under the guard, so a release returns exactly what was reserved, and
Debug builds catch a second release; a refused admission leaves both counts as they
were. Observational counts are raw scalar snapshots. Checked integers cover DER numeric decoding,
identity/receipt/service allocation sizes and KDF narrowing; ranged integers
reject zero rounds. Required admission invariants remain active in every mode.

The spin sections contain only bounded phase/count/result mutations and fixed
request-digest comparison. Hashing, verification, result cleanup and allocator
calls occur outside the guard. Reference counts and detached executor completion
ownership are independent of this lock and retain their existing reaping rules.

Later aegis APIs are not dependencies: owned request/path/receipt values and
checked token matching remain local pending published handle/own/input APIs.
TLS-specific policy, refcount and job lifetime are not generic owner substitutes.
Existing fixed-width constant-time arithmetic/select and volatile spill barriers
remain the reviewed local kernels pending published constant-time values.
Secret owners erase their explicit storage on ordinary success/error cleanup;
they do not prove erasure of prior compiler copies, registers, arbitrary spills,
OS paging or process abort, nor hardware constant-time behavior.

## TLS 1.3 foundations (C2 in progress)

Certificates and keys are the `certificates` namespace of the one `cloak` module,
and TLS is `tls`. A separate build module buys something only where it keeps
dependencies from users who do not need that part, or keeps a part from linking
something. Here it bought neither: the TLS client and server use the certificates
directly, and the certificates reach the native trust store (Security on macOS,
opened from the system on first use, and crypt32 on Windows, linked), so every
TLS user reaches it already, and both parts have the same package dependencies
(aegis). Zig's lazy analysis leaves out what a program does not use. On macOS
nothing is linked but libSystem, so an Apple target builds on any host without
an SDK. The layering inside the module is
enforced by the layer check at file level: the TLS layers import the certificates
facade downward and nothing in the certificates imports TLS. The portable probes are a private
module of their own, since they reach files the public surface does not.
DTLS is the namespace `tls.dtls` (below), a third carrier of the same handshake;
it brings no dependency of its own. The private TLS handshake imports crypto and wire;
record protection imports crypto only. Neither imports an adapter or facade.

`record.Epoch` owns one direction's key, IV, sequence and byte/record counts.
Seal commits a nonce exactly once; a future Connection retains those committed
bytes across partial output acknowledgement. Insufficient space and partial
overlap leave state untouched. Open validates the actual header as AAD and
withholds plaintext until tag verification; a malformed/authentication failure
wipes the directional key/IV and any touched plaintext, and is terminal.
Exact alias is the ciphertext body, starting five bytes into a record; all
other overlap is rejected before write. There is no public raw record API.
Connection authentication, partial-input leases, EOF and update scheduling
are not supplied by this primitive and remain C2 integration work.

TLSInnerPlaintext is capped at 16,385 bytes, content at 16,384, and outer
ciphertext at 16,640 (RFC 8446 §§5.1–5.2). Epoch caps are at most 2^24 records
and 2^38 inner bytes, including content type, controls and padding. At the
maximum inner size the record cap already limits the epoch to approximately
2^38 bytes. The record cap is below RFC 8446 §5.5's AES-GCM recommendation of
2^24.5 full records; ChaCha's sequence-space bound is stricter here too.
Lower caller/test caps are accepted; raising caps is refused. Connection must
reserve and send an update under old keys before exhaustion. A receiver closes
at exhaustion and on its first failed authentication attempt; no retry oracle.

TLS HKDF owns and wipes HMAC state, label blocks and Finished keys. Traffic keys
and IVs use published aegis Secret. Checked transcript counts use aegis checked
integers. Published aegis has no typestate API, so full TLS 1.3 transitions are
an explicit always-checked table with proof and epoch requirements, version as one
of its keys (TLS 1.2 edges sit beside the TLS 1.3 ones). A resumed TLS 1.3 handshake
has edges of its own, chosen by a flag set once, as the ServerHello accepts a PSK: no
certificate flight in either direction. ECH and DTLS branches are absent until their phases. The table alone is
not a certificate/signature verifier: its internal proof arguments must be
issued by the crypto/verification driver. Named tests cover individual catalogue
components; the complete F27–F45 rows remain open until integration and campaigns.

Every comparison of a secret or a MAC runs aegis's `Choice` kernels (Finished, binders,
the CCM tag, ECH confirmations, DTLS cookies, pins, request digests, the curve-scalar
range), each releasing only its completed verdict through a named `declassify`. They
compile for every target cloak builds for; `aegis.secret.Choice.audited` says whether a
build is one whose lowering aegis inspects (the hosted targets at their baseline and
common CPU models, the BSDs, wasm32), and cloak's timing checks on the built binary cover
the rest. AEAD selects std's kernels and rejects `.none` mitigations
independently of caller options. Generated-code/timing campaigns remain required
before a complete TLS security claim. Named wipes cover owned storage, not all
compiler-created argument copies, register spills or std AEAD local schedules.

RFC 8448 §3 supplies independently published transcript, protected-flight,
key/IV and Finished checkpoints. Its 1024-bit certificate is deliberately not
accepted under cloak's security floor. These tests prove vector agreement, not
live peer interoperability or reviewed endpoint security.

Hello negotiation checks exact nested lengths, positive suite/group/signature
allowlists, session echoes and duplicates before returning borrowed fields.
Server choices bind to the client offers. ALPN is one offered nonempty protocol;
QUIC requires ALPN and the presence of opaque transport parameters. Empty
parameter bytes are allowed: the eventual consumer owns parameter validation
and acceptance. Cookie-only HRR is valid; a requested group must not already
have a share. The handshake owner must bind the subsequent suite and enforce
one retry. No ephemeral key generation or handshake randomness is supplied by
the encoder, and none is injected through a consumer API.

The types that name IANA-registered numbers are open enums: `Group`, `Suite`,
`SignatureScheme`, the SRTP profiles, `Alert`, the HPKE identifiers and the
certificate-compression algorithms. Any number is a value, so a peer's list reads
whole, and a value cloak names later does not break a caller's `switch`. What cloak
speaks is a separate question, `supported()`, answered by the named values. Options
are refused when they list a value cloak does not speak (`Hello.validate`), and every
later step relies on that: the exchange kernels and SRTP key lengths take a value
outside the named set as a broken contract (an aegis fail-stop), not as input. Where a
number becomes one of these types (a peer's selection, a ServerKeyExchange's curve,
a signature's scheme, a sealed ticket, a DTLS cookie) an explicit `supported()`
check stands beside the offered-list check; `std.enums.fromInt` is not that check, as
it never fails on an open enum. Internal types stay closed where they mean what
cloak speaks (`Suite13`, `Suite12`, `Cipher`). `Version` stays closed: TLS versions
are no registry, a new one is a new protocol, and their order is the min/max policy.

The schedule owns handshake/master and exporter roots, wipes displaced roots,
and transfers directional traffic owners to records. Exporters are gated on
completion; the future handshake driver must issue completion only after peer
verification and local Finished commitment. `Epoch.initTraffic` consumes its
source only on success. Updates derive the next traffic secret and replace
erased key/IV/secret storage, resetting only that direction's counters. The
connection must commit or accept KeyUpdate under old keys before updating,
retain committed ciphertext through output acknowledgement, and prohibit
handshake messages spanning a key transition. Primitive tests establish the
derivation and old-key ordering; they do not establish connection scheduling.

Private freestanding probes exercise all three record suites and the RFC 8448
handshake schedule checkpoint. This is executable portable kernel evidence,
not a freestanding network endpoint, memory peak measurement or interop claim.

The checked client flight requires a Certificate response after a server
CertificateRequest: an empty Certificate may omit CertificateVerify, while a
supplied identity requires possession proof before local Finished. Unsolicited
client credentials and a direct Finished after a request fail terminally.
Independent client/server flight traces cover retry, optional/required client
authentication, wrong actions, epochs, proofs and record boundaries. These are
state-kernel tests, not evidence that service tokens or signatures are integrated.

## TLS 1.3 client

`Connection` is a sans-I/O client. Callers feed wire bytes to `receive`, write
`output` and acknowledge it, answer each `request` through `provide`, and read
authenticated plaintext from `readable`. It performs no I/O, never reads a clock
or generator, and has one driver. Output is views over state the connection keeps
until acknowledged: committed ciphertext is sealed once and a partial write never
re-seals. The design's event queue (`next`/`ack`) is these views for streams and
the event type for QUIC, where levels and secrets need an ordered stream.

Owners, bottom to top. `crypto` holds suites, HKDF and key shares (`Exchange`).
`record` holds `Epoch` and `Protection`, the one sequence and limit owner per
direction. `handshake` holds the message parsers, the checked state table (`State`: one
aegis typestate machine per role, whose topology aegis validates when it is analyzed and
whose states carry the history the protocol depends on, a resumption, a certificate asked
for or sent, so no transition is rewritten after it is taken; each edge's epoch, proof and
record boundary and the client-auth, ticket and retry policy are checked before it is
committed), the transcript, the schedule and `Client`, which consumes whole handshake messages and
returns outputs through a queue: messages to send, traffic secrets to install, and
requests for entropy, time, peer verification and signing. `Connection` turns those
outputs into records and key slots; `quic.Handshake` turns the same outputs into
per-level events. There is one handshake and no second engine.

A request carries a token naming this connection and request. An answer to another
token, or to nothing, is refused without progress. A rejected scalar draw
(`InvalidEntropy`) is public and leaves the request open; every other failed
answer ends the connection. Verification receipts are checked against the request
the engine issued, so a receipt for another chain, name, time or policy generation
cannot authenticate. Possession is proven by the engine itself: it parses the
leaf of the accepted path, binds the CertificateVerify scheme to that key's type
and curve, and verifies the signature; `verify = .none` still proves possession
and reports an unauthenticated connection. A client certificate whose key cloak holds
is signed inside the engine; one held elsewhere is signed through a request, and the
engine verifies the answer against the identity's public key before it leaves, so a
bad signer cannot put a bad CertificateVerify on the wire.

Key shares are fresh per hello and per retry. The default offer is X25519MLKEM768
plus an independent X25519 share; P-256 and P-384 are obtained through
HelloRetryRequest. Group 4588 sends the ML-KEM encapsulation key first, and its
secret is the ML-KEM secret then the X25519 secret. SecP256r1MLKEM768 (4587) and SecP384r1MLKEM1024 (4589), the
NIST-curve hybrids of draft-ietf-tls-ecdhe-mlkem, go the other way: the uncompressed ECDH point
then the ML-KEM key (or ciphertext), and the ECDH secret then the ML-KEM one. They are offered only
when listed, and obtained through a retry request like P-256; any of the three hybrids satisfies
`require_hybrid`, and none exists in TLS 1.2. MLKEM768 (513) and MLKEM1024 (514) of
draft-ietf-tls-mlkem are ML-KEM alone: the encapsulation key from the client, the ciphertext
from the server, the 32-byte ML-KEM secret; the server refuses an encapsulation key that fails
FIPS 203's check. They are for a policy that wants no elliptic curve in its key exchange (CNSA
2.0), so they are never in `Group.default`, the one default offer, and are used only when listed;
they are not hybrids and do not meet `require_hybrid`, so such a policy is a `groups` list of
them alone. As for the hybrid with the same KEM, a client keeps ML-KEM-768's expanded key and
ML-KEM-1024's seed. TLS 1.2 has only the classical groups, and is offered or accepted only when
one is listed. P-256 key generation, agreement, ECDSA
signing and verification run cloak's own kernel (`src/crypto/p256.zig`): a precomputed
comb of the base point with complete projective additions for secret scalars, signed
five-bit windows over a public table of the peer's multiples for agreement (every entry
scanned; identity and doubling handled by selection), and a public double-base walk
for verification. Field arithmetic is Montgomery over four limbs, in assembly on AArch64
and portable Zig elsewhere, the two tested equal; the generated code of the secret walks
has no branch on secret data. P-384 agreement runs the masked fixed-window walk
(`Ecdh`). std's multiplication of a secret scalar is not used. X25519 and ML-KEM come from std, with implicit rejection for
ML-KEM and refusal of an all-zero X25519 secret; their generated code is not yet
reviewed here.

Hostile input. A record is accepted only with a 0x0303 legacy version; protected
records authenticate before any plaintext leaves the record buffer, and the first
failed authentication ends the connection. One compatibility change_cipher_spec is
ignored, only between messages before the server Finished. Handshake messages are
bounded before they are buffered. A message that changes keys (ServerHello,
Finished) must end its record, or in QUIC its level, with nothing after it; QUIC
refuses a message that straddles levels. Extensions are unique, unsolicited ones
are refused, and every selection must have been offered. Post-handshake control
messages (tickets, key updates) are counted between application data and end the
connection past a bound. A server that answers with an older version is refused with protocol_version, or
illegal_parameter when its random carries the downgrade sentinel. Each failure sends one alert chosen by the failure class
and then every call returns `Closed`. Nothing is authenticated, readable or
exportable after a failure.

Key updates. The write side sends KeyUpdate under the old key and then switches,
before the record or byte budget can run out; the read side asks the peer to update
when its own budget runs low. Budgets default to 2^24 records and 2^38 bytes per
epoch and direction; tests lower them.

Memory. A running handshake holds one scratch block (offered key shares, the
transcript, queued outputs, the peer chain) of about 25 KiB, a flight buffer, a
record buffer sized to the record being read, a message buffer and the output
buffer: about 50 KiB at the peak for the default offer. When the connection is
established the scratch block and flight are freed; `trim` returns the record and
message buffers and `trimOutput` the output buffer when nothing is pending, and `Session`
calls them before it waits to read and after it flushes. What remains for an idle connection is the struct (664 bytes) and one
heap block of 1,328 bytes (the key schedule's exporter and resumption secrets among it), 1,992
bytes in total, in a Debug build. These are heap figures from a counting allocator; stack use
is not measured here.

`Session` drives a `Connection` over `std.Io` readers and writers. It answers
requests with the system's secure randomness and calendar clock (or a fixed time),
the portable verifier over a trust snapshot (or a caller's verifier), and, for
a key cloak does not hold, a caller's signer. After the handshake one task may read
while another writes, as Go's `tls.Conn` and a split rustls stream allow (HTTP/2 and
WebSocket need it). The connection is then two halves with record states of their own:
the read half (input reassembly, the read keys, post-handshake messages) and the write half
(the write keys, the output). What crosses them is a handful of atomic bits: the KeyUpdate a
peer's request owes, a key update the read half asks for before its epoch runs out, the
warning that refuses renegotiation, and a read failure's fatal alert; status (the phase,
the first failure, the alerts sent and received) is atomic too. The write half writes what
is owed before its next record. The session holds a write lock over the write half and the
transport's writer; the reading task takes it only if it is free and otherwise leaves what
it owes to the writer, which takes the lock back for it as it lets go. A reader never
waits for the writer: two ends each blocked writing to a peer that is not reading would
otherwise each hold the lock the other's reader needs. A transport end without close_notify is
a truncation unless the caller chose `.allow` for protocols whose framing detects it.
Per-call deadlines are the transport's own; the session adds none. A `Session` drives
readers and writers it does not own and cannot interrupt a blocking read, so a timeout
option would hold only where the transport already enforces one. Bound a handshake with
the transport's deadline (reactor's streams do) or by cancelling the task running
`open` or `accept`: a cancelled read or write comes back as `ReadFailed` or
`WriteFailed` (the transport keeps `error.Canceled`), `open` has already released
the connection, and one caller deadline covers every flight and service.

`quic.Handshake` takes contiguous CRYPTO bytes per level and yields events: handshake
data per level, traffic secrets (each once, erased on acknowledgement), the peer's
transport parameters (provisional until accepted), authentication, and an alert. It
installs a level's secrets before it yields data at that level. It has no record, no
ChangeCipherSpec, no close_notify and no KeyUpdate, and it refuses a post-handshake
CertificateRequest. Transport parameters are opaque bytes to cloak.

## TLS 1.3 server

`Connection.server` is the same sans-I/O connection around `handshake.Server`;
`Session.accept` drives it over `std.Io`, and `quic.Handshake.server` yields the
per-level QUIC events. `handshake.Machine` is the one dispatch between the two roles
(a tagged choice, not an interface), so records, key slots, request tokens and
trimming have one implementation.

A `Credential` is a certificate chain (a `certificates.Identity`) plus the names it
answers for: exact, or `*.` plus a domain for exactly one label, matched without case.
A credential without names answers for any name. The first matching credential
answers; when none matches, the first answers, or with `unknown_name = .reject` the
connection ends with unrecognized_name. The signature scheme is the first the client
accepts that the leaf's key type and curve can make.

Cloak signs the CertificateVerify itself with the key its identity holds (`Sign.zig`):
ECDSA on P-256 and P-384, Ed25519, and RSA (rsa_pss_rsae with SHA-256, SHA-384 or
SHA-512, SHA-256 first among what the peer accepts). The secret multiplication is the masked
fixed-window walk that builds public keys, the scalar arithmetic is std's constant-time
field, and every temporary is erased. ECDSA nonces are hedged: derived from the key,
the message hash and fresh noise, so a weak or repeated draw alone cannot repeat a
nonce and one faulted signature does not give the key away. The noise is part of the
entropy request the handshake already makes (the server's random and key exchange, the
client's hello), 32 bytes for P-256, 48 for P-384 and 96 for RSA, so no signature waits
on a second round trip to the driver. Ed25519 follows RFC 8032 and draws none. An ECDSA
or Ed25519 signature is not verified after it is made: the key was matched to the leaf
when the identity was built, and the cost of a verification (about as much as the
signature) buys protection only against a fault in the signer.

RSA signing is the private operation of `crypto/rsa.zig` under the RFC 8017 encodings
(EMSA-PSS with MGF1 and a salt as long as the hash, and EMSA-PKCS1-v1_5 with the exact
DigestInfo for TLS 1.2). The key keeps n, e, p, q, dp, dq and qinv, checked at parse to
agree (n = pq, e d = 1 modulo p - 1 and q - 1, dp, dq and qinv) and erased with the key; d
is checked and not kept. Whether p and q are prime is the key generator's to ensure, as Go,
BoringSSL and ring hold it: a key whose factors are not releases no wrong signature, since
every RSA signature is checked against the public key before it leaves. Moduli of 2048 to 4096 bits sign; a valid key with a factor above 2048 bits is
refused at parse as `UnsupportedKey`. The operation uses the Chinese remainder theorem:
each half raises the message to dp or dq modulo its factor in fixed four-bit windows over
the factor's full width, every window's multiple read by a masked scan of the whole table,
on 64-bit limbs at the key's public widths with masked conditional subtractions, so the
instructions and addresses depend only on the key's size. The message is blinded first,
m r^e with r drawn by SHAKE256 from 32 bytes of the noise, a secret the key derives from
its factors and the message, and r^-1 is taken in each half by Fermat with the same
exponentiation; Garner recombines the halves. A fault in either half would give the
factors away (Bellcore), so every result is checked against the public key on the exact
bytes to be released: they must encode a value below n whose e-th power is the encoded
message, and nothing is written otherwise. The check costs a public exponentiation, a
small share of the private one. The rest of the 96 noise bytes is the PSS salt;
PKCS#1 v1.5 draws the same 96 and leaves the salt unused, so a key's noise length does not
depend on the scheme. `PrivateKey.signDigest` signs a digest computed elsewhere, for the
TLS 1.2 transcript hash.

An identity made with `initExternal` holds no key. For it the server asks its driver to sign through
a `sign` request, then checks the answer against the leaf's public key before it can
reach the wire, so a faulty signer cannot put a bad CertificateVerify on the wire. A
signer that fails ends the connection with internal_error.

A server connection holds no handshake scratch until a peer sends a ClientHello that
the state table accepts: a connection created and never spoken to, or one fed a few
bytes, costs its state and credential table (1,112 bytes), not the scratch (3.7 KB
before the first flight grows it). Established connections release it as before.

A ClientHello is parsed once into borrowed views (`ClientHello`), checking structure
and uniqueness but no policy: duplicate extensions, a key share for a group
`supported_groups` does not list, a repeated share group, a compression other than
null, a pre_shared_key that is not last or lacks its exchange modes, a cookie in a
first hello, a malformed host name and a missing supported_versions are refused
before anything is negotiated. Policy then follows the server's order: its suite,
its group (a group with a share beats one that needs a retry), its ALPN. A client
with no usable share gets one HelloRetryRequest; the second hello must equal the
first except for the key share, cookie, early data and PSK, which a SHA-256 over
the random, session id, suites and sorted remaining extensions decides, so a client
cannot change its offer between the hellos, and the second may not offer early data. A
PSK resumes a session when the server has ticket keys (below); early data is never accepted.

Client authentication is `none`, `optional` or `required`. A presented chain goes out
as a `verify` request, the receipt is bound to the request digest as on the client,
and possession is proven by the engine against the leaf of the accepted path before
the connection reports an authenticated peer. An empty Certificate under `required`
ends the connection with certificate_required.

In QUIC the client's transport parameters are provisional: the server emits them as
an event before it asks for entropy or sends anything, and sends nothing, not even
a ServerHello, until the caller accepts them. ALPN is required.

The server flight, the application keys and the handshake scratch are built under
the same bounds and released at the same moments as the client's. Measured here:
about 25 KiB at the handshake peak and 1,123 bytes of heap beside the 664-byte struct
once established (counting allocator, Debug test), and key updates behave as in the client. The server's CPU rows are in
`bench/handshake.zig`; they include harness signing with std's ECDSA.

Test support lives in `src/testing`: a scripted server peer that speaks real records
or per-level QUIC messages and a scripted client peer (with a hostile ClientHello and
client flight in named ways), both able to misbehave on purpose, and drivers that run a
client or a server against them in memory, or the two QUIC roles against each other. The peer reuses cloak's HKDF, schedule and record
protection, which the RFC 8448 vectors pin; its parsing, message assembly and
signatures are its own. The test PKI is disposable material generated once with
OpenSSL, recorded in `src/testing/pki/provenance.md`.

## TLS 1.3 resumption

Resumption is PSK-DHE only (RFC 8446 section 2.2): a ticket replaces the certificate flight
and its signature, never the key exchange, so a resumed connection keeps forward secrecy. The
PSK enters the early secret; the (EC)DHE secret follows as in a full handshake. A resumed
handshake has no certificate in either direction, and the state table refuses one.

A client resumes from a `SessionCache`, given as `Resumption` with a namespace and a maximum
age (seven days by default; `Session` makes it an hour when the system verifies, whose trust can
change without a generation to say so). The cache key is a SHA-256 over everything the session's
authority depended on: the namespace, the server name and reference identity, ALPN, QUIC or not,
`require_hybrid`, the whole verification policy (through the digest of a verification request
with no chain, time or token: trust and policy generations, pins, evidence, limits, anchors) and
the client certificate chain. A change in any of them finds no ticket. The client asks for the
time before its hello, takes the newest live ticket for its key, removing it, so a ticket is
offered once (it is a bearer token that links the connections that use it), and offers it if one
of its suites has the ticket's hash: one identity with its obfuscated age and a binder over the
transcript up to the binders. With a cache it always sends psk_key_exchange_modes with PSK-DHE
alone, which is what asks a server for tickets. After a retry request
the binder is made again over the new transcript, or the ticket is dropped when the server's
suite has another hash. A ServerHello that selects anything but that one identity, or selects
one in a retry request or a TLS 1.2 answer, is refused. A ticket the server declines is spent
all the same. A resumed connection reports `resumed` and the original handshake's
authentication. Tickets that arrive later are kept with the PSK of their nonce; each expires at
the first of its lifetime, the maximum age counted from the full handshake that began the
session, and the expiry of the server's authentication in that handshake (its receipt and
revocation evidence), so a chain of resumptions never extends authority. A ticket arrives, for
its age, at the time the handshake was told; one the cache cannot keep is dropped and never
fails the connection. The cache is bounded by entries, bytes and four tickets per key, behind
one lock whose sections are bounded; allocation and erasure happen outside it.

A server issues and resumes with `TicketKeys`, a ring the caller rotates with 32 bytes of key
material of its own drawing (all zeros, a missing key's usual stand-in, and material already
held are refused). A key issues tickets for its rotation period (six hours by default) from
its installation, or until the next rotation, and opens them until the last can have expired,
a lifetime (a day by default, at most seven) later; a ring whose newest key has stopped issuing
issues nothing, so a forgotten rotation costs full handshakes, not a stale key. Each rotation
publishes an immutable snapshot that a handshake retains for one call. There is no nonce state:
a ticket is sealed with AES-256-GCM under a key HKDF derives from the ring key and a fresh
128-bit salt drawn with the handshake's entropy, used for that one ticket, so no (key, nonce)
pair repeats however many processes or restarts share a ring key. The ticket is a version, the
ring key's identifier (from its material), the salt and the ciphertext of the session's suite,
PSK, issue time, the session's expiry, the age obfuscator, the ALPN protocol and server name,
the client's authentication and its expiry, and a digest of the server's client-certificate
policy. A server with tickets holds a ClientHello until the clock answers. It looks at the
first eight identities offered and takes the first that its ring opens and that matches: a suite
of the same hash, not expired, the same server name (ignoring case) and ALPN protocol, the same
policy digest, a client certificate still valid if there was one, and one there if the server
requires it. That identity's binder is checked in constant time and a wrong one is fatal
(decrypt_error); a ticket that does not open or match is passed over for a full handshake.
The obfuscated ticket age is not checked: it bounds 0-RTT replay, and nothing rides on it here.
After each TLS 1.3 handshake whose client asked for PSK-DHE, the server sends two tickets under
the application keys before the connection completes, outside the transcript, each with its own
nonce, PSK, salt and age obfuscator; a resumed session's tickets keep the expiry its first
had, and none outlives the client's authentication.

No ticket permits early data and no connection accepts it. A server whose client offered early
data skips the client's early records: when it answered with a retry request, every protected
record before the second hello (and nothing after it); otherwise each record that fails to open
under the handshake keys, until one opens; at most 64 KiB in all, past which the connection ends with unexpected_message. An
EndOfEarlyData is an unexpected message. QUIC resumes through the same engine (tickets travel at
the application level) and offers no 0-RTT; its early packets are the QUIC stack's to drop.

TLS 1.2 resumes from session tickets (RFC 5077) when both ends ask: `Resumption.tls12` on the
client, `tls12_tickets` on the server, from the same cache and ring. An abbreviated TLS 1.2
handshake reuses the session's master secret with fresh randoms and no key exchange, so it gives
up forward secrecy between the connections of a session; that is why it is off by default. The
extended master secret is required in every TLS 1.2 handshake, the abbreviated one included
(RFC 7627 section 5.3). There is no server session-ID cache: tickets keep no state on the server.
A client with TLS 1.2 tickets sends the SessionTicket extension (empty, or with a ticket of its
cache key and a suite it offers) and a session id, which the server echoes to resume. A ticket's
format byte names its version, so a TLS 1.3 ticket never opens as TLS 1.2 state or the reverse.
The server resumes a ticket under the same rules as in TLS 1.3, with the ticket's own suite,
which both sides must still accept; the client refuses a resumption with any other suite. The
resumed flight is the ServerHello, a NewSessionTicket when the ServerHello said one follows, and
the server's ChangeCipherSpec and Finished, then the client's two. A NewSessionTicket comes
exactly when promised and before the server's ChangeCipherSpec, in a full handshake too, and the
client keeps it only once the server's Finished has proven it. A resumed session reports the
original handshake's authentication and key exchange group.

## Encrypted Client Hello

ECH (RFC 9849) hides the ClientHello that names the server inside one that names a public
name. std has no HPKE, so cloak has its own (`tls/crypto/Hpke.zig`, RFC 9180 base mode):
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305
on std's X25519, HMAC and AEADs, with the sequence counter of section 5.2 (a failed open leaves
it unchanged). It is pinned by RFC 9180 A.1.1 and by the base-mode vectors of all three AEADs
in Go's testdata, over 1,000 messages each. No PSK or authenticated mode and no exporter: ECH
needs none.

A client's `ech` is `off`, `grease`, or the server's ECHConfigList (from its HTTPS record:
finding it is the caller's). A list makes ECH required: the first usable config is taken
(X25519, a supported suite, a public name that is a DNS name and not an IPv4 literal, no
mandatory extension), a list with none is `InvalidOptions` and never a reason to send the true
name in clear, and the connection offers TLS 1.3 alone. Three encodings of one hello are made:
the ClientHelloInner (the true name, the inner marker, the real PSK offer), which the inner
transcript hashes; its encoded form, with an empty session id and supported_groups,
signature_algorithms, supported_versions, ALPN, cookie and key_share left to the outer hello
(ech_outer_extensions), padded by section 6.1.3 with the config's maximum name length; and the
ClientHelloOuter on the wire: the same key shares, the public name, a fresh random, and in place
of a PSK offer random bytes of the inner offer's lengths (section 6.1.2), so no ticket or binder
of the true session is ever outside the encryption. The outer hello with a zeroed payload is the
HPKE associated data. A retry request that confirms acceptance (its encrypted_client_hello
matches the inner transcript with those bytes zeroed) is answered by a second inner and outer
hello sealed under the same context with an empty enc; one that does not is answered by the
outer hello alone, its ECH extension unchanged. The ServerHello accepts when the last eight bytes
of its random confirm the inner transcript; the inner transcript then becomes the transcript.
A retry request that accepted binds the ServerHello to accept too (illegal_parameter otherwise).
Rejected, the handshake goes on with the outer hello only to authenticate the public name: the
verification request names it, without the origin's pins; a PSK selection is refused (the outer
offer was GREASE); after the server's Finished the client sends ech_required instead of its
own flight and fails with `EchRejected`. The server's retry configurations are released
(`echRetryConfigs`, Session's `ech_retry`) only when the public name was authenticated: empty
when it sent none, ECH then securely disabled; null for any other outcome. Nothing else of a
rejected handshake reaches the caller: no info, plaintext, exporter or ticket. The engine does
not reconnect. GREASE sends a random ECH extension as long as a real one would be (kept for a
second hello) and is otherwise an ordinary handshake; its retry configs are checked for syntax
and dropped. The ticket cache key holds the ECH config list, so a session from an ECH handshake
resumes only inside the same ECH policy.

A server holds `ech_keys` (at most 16, borrowed): each an ECHConfig and the X25519 secret of its
public key, checked against each other at init. It tries the keys of the offered config id
whose config lists the offered suite; a failure to decrypt is no error (it may be GREASE): the
handshake goes on with the outer hello and EncryptedExtensions offers the configs marked
`retry`. A decrypted inner hello is rebuilt linearly (section 5.1: the outer session id, and
each named outer extension copied once, in order, never encrypted_client_hello itself; nonzero
padding refused), parsed like any hello, and must carry the inner marker and offer TLS 1.3 and
nothing older. From then on it is the hello: its name, ALPN, PSK and transcript. Acceptance is
confirmed in the ServerHello random and, after a retry request, in the retry request's own
extension; the second outer hello must name the same config and suite with an empty enc and open
under the first one's context, or the handshake ends with decrypt_error. An inner hello arriving
from the network is illegal_parameter. A server without keys ignores the extension entirely.

Live peers (trials): cloak against OpenSSL 4.0.3 and Go 1.27.1 both roles, accepted, across a
retry request, resumed inside ECH, rejected with retry configs, GREASE, and QUIC against Go.
OpenSSL 4.0.3's client sends an empty binder in its outer GREASE PSK (below RFC 8446's 32
bytes); cloak's server refuses that hello with decode_error, as Go's does.

## Certificate compression

RFC 8879 lets a server send its Certificate compressed. cloak holds no codec: a caller passes
`certificate_compression`, codecs naming their algorithm (zlib, brotli, zstd) with a decoder
(a client offers those, TLS 1.3 only) or an encoder (a server uses the first, in its order,
whose algorithm the client lists). In the family the codecs are warp's. A server compresses the
Certificate message's body and sends the CompressedCertificate only when it is smaller; the
CertificateVerify signs the transcript with the compressed message in it, as it went on the
wire. A client takes a CompressedCertificate only when it offered a codec: the algorithm must be
one it offered (illegal_parameter), the declared length is checked against the handshake message
limit before anything is allocated, and the codec must produce exactly that length from all of
the input (bad_certificate otherwise: short, long, trailing bytes or a malformed stream); the
chain is read from the decompressed message and verified as any other, and the transcript takes
the compressed message. A tiny stream that would expand past the limit never runs. What a codec
costs in time within those sizes is the caller's codec's to bound. Client certificates are never
compressed: a cloak server does not offer it in its CertificateRequest. Tests use std's zlib as
the codec.

## Provisioned PSKs

A key both ends hold beforehand (RFC 8446 section 4.2.11, RFC 9257's guidance), PSK-DHE only:
the exchange is always a fresh (EC)DHE one. A client's `external_psk` is an identity (1 to 1,024
opaque bytes), the key and its hash; it is offered instead of a ticket, with an obfuscated age of
zero and a binder under "ext binder", and needs a TLS 1.3 suite of its hash. A server's
`external_psk` is a lookup: it sees the offered identity, the server name, the protocol the server
chose and the transport, so the caller decides what each key is bound to (endpoint, application,
transport); its answer must name the queried identity byte for byte and be a valid key, or it is
passed over, and a binder that fails is fatal (decrypt_error). Keys are tried before tickets. A
handshake on a key sends no certificate either way and authenticates both ends by the key alone,
whatever the certificate policy; `Info.external_psk` says so, and no X.509 identity is implied.
Such a session issues no tickets and the client keeps none: it resumes by offering the key again.
Reflection (an endpoint that is both client and server answering its own hello) needs the same
key provisioned for both roles, which is the caller's to avoid (RFC 9257 section 4.1). Live peer:
OpenSSL's `-psk` both roles; Go has no provisioned PSKs.

## TLS 1.2

TLS 1.2 is a second path through the same `Client` and `Server`: the ServerHello (client)
or a ClientHello without TLS 1.3 (server) moves the machine onto TLS 1.2 edges of the one
state table, and `Client12`/`Server12` hold the messages; neither imports a role, so the
two versions share entropy, time, verification and signing requests, the flight queue and
the transcript owner. Suites, versions and their bounds are one option set: `suites` lists
both versions in preference order, `min_version`/`max_version` bound them, and a version is
offered only when one of its suites is listed (QUIC and `require_hybrid` are TLS 1.3 only).
A server prefers TLS 1.3 whenever the client offers it.

Only the modern subset exists. Key exchange is ECDHE on X25519, P-256 or P-384 (the hybrid
group is TLS 1.3's), with a fresh share per connection; the record ciphers are AES-128-GCM,
AES-256-GCM and ChaCha20-Poly1305 (RFC 5288, RFC 7905), the GCM explicit nonce being the
record sequence; the master secret is always the extended one (RFC 7627), and a peer
without it is refused, as is one without the secure renegotiation indication (RFC 5746).
No suite of RSA key exchange, finite-field DHE, static ECDH, CBC, RC4, 3DES or NULL exists
to be negotiated; compression other than null, SSLv2 hellos, MD5 and SHA-1 signatures,
renegotiation (a HelloRequest or a second ClientHello) is refused; resumption is the session
tickets above, off unless both ends ask.
A server that speaks TLS 1.3 marks its TLS 1.2 random with the downgrade sentinel and
refuses TLS_FALLBACK_SCSV; a client that offered TLS 1.3 refuses a marked TLS 1.2 answer.

ChangeCipherSpec is a real message here: it is accepted only between messages, as a
plaintext record, where the table expects it; the keys it switches to are derived before
and installed by the connection when the record arrives. Handshake and alert records under
TLS 1.2 keys are decrypted like application data, in place after the explicit nonce. The
ServerKeyExchange signature covers both randoms and the parameters; TLS 1.2 binds an ECDSA
scheme to its hash rather than to the key's curve, and PKCS#1 v1.5 RSA signatures are
accepted and made only in TLS 1.2. A CertificateVerify signs the transcript hash of its
scheme: both SHA-256 and SHA-384 transcripts run through a TLS 1.2 handshake, so the
signature goes through `signDigest`/`verifyDigest`. Ed25519 signs the handshake messages
themselves rather than a digest (RFC 8422 section 5.10), so the transcript also keeps the messages whole when an Ed25519 signature may be needed: in
a client whose certificate key is Ed25519, from its hello, and in a server that asks for a
certificate, from the client's hello; the copy is bounded by the handshake limit, erased with the
scratch, and dropped as soon as TLS 1.3 is chosen. A key held elsewhere receives the digest with
`prehashed` set, or for Ed25519 the messages. There is no key update: a TLS 1.2 connection
closes before the record and byte caps instead. The exporter is RFC 5705's over the
extended master secret, with the caller's context, or none when the caller passes null, which
RFC 5705 tells from an empty one (TLS 1.3 does not).

What a TLS 1.2 connection keeps past its handshake (the master secret and both randoms,
for the exporter) is one allocation made only when TLS 1.2 is negotiated, so a connection
nobody has spoken to stays as small as before. Tests run a cloak client against a cloak
server for every suite, group and certificate key, client certificates, version selection
both ways, one-byte delivery and the failure catalogue's TLS 1.2 rows (F46–F64); live
peers are the trials campaign's.

## DTLS (C8): contract and transitions

DTLS is a third carrier of the one handshake, beside stream records (`Connection`) and QUIC
levels (`quic.Handshake`). DTLS 1.3 (RFC 9147) takes TLS 1.3's messages, key schedule,
suites and checked edges; DTLS 1.2 (RFC 6347) takes the TLS 1.2 ones. What is new is only
the datagram carrier, `tls.dtls.Datagram`, and the rules by which a datagram handshake
differs on the wire and in its transcript. There is no second state machine and no copy of
handshake logic: `handshake.Machine` is driven exactly as the other carriers drive it.

### What the engine learns (the carrier seam)

The machine is told its transport (`stream`, `quic` or `datagram`, a carrier's choice that
callers of `Connection` never set), and these follow from it, nothing else:

- Versions. A datagram handshake speaks DTLS 1.2 (0xfefd) and DTLS 1.3 (0xfefc) where a
  stream speaks TLS 1.2 and 1.3, and `Info.version` names the same generation (`tls12`,
  `tls13`): the versions are shared, their wire numbers are the carrier's. A hello's
  legacy_version is 0xfefd, supported_versions lists 0xfefc and 0xfefd, the ServerHello's
  legacy_version is 0xfefd, and the downgrade sentinel marks a DTLS 1.2 answer from a server
  that speaks DTLS 1.3 exactly as in TLS.
- The ClientHello carries a legacy_cookie after the session id. In DTLS 1.3 it is empty and
  a server refuses any other with illegal_parameter; in DTLS 1.2 it holds a
  HelloVerifyRequest's cookie, at most 255 bytes.
- No middlebox compatibility: no legacy session id in DTLS 1.3, none echoed, and no
  ChangeCipherSpec outside DTLS 1.2. The state table refuses a compat_ccs in datagram mode.
- Labels. Every HKDF-Expand-Label of DTLS 1.3 uses the prefix "dtls13" where TLS uses
  "tls13 " (RFC 9147 section 5.9): the schedule, Finished, binders, tickets, exporters, the
  record keys and IVs, key updates and the record-number keys. The schedule holds the prefix,
  so no derivation can take the wrong one.
- Transcript. DTLS 1.3 hashes the TLS-form messages; the carrier strips message_seq and the
  fragment fields before the machine sees a message. DTLS 1.2 hashes each message with its
  twelve-byte DTLS header as if sent unfragmented (message_seq, offset 0, fragment length
  the message length; RFC 6347 section 4.2.6), and the transcript numbers messages itself:
  its own from the carrier's first sequence, the peer's in the order the carrier delivers
  them, which is strictly message_seq order. A client offering both versions hashes its
  hello both ways until the ServerHello chooses. The Ed25519 copy of the messages is kept in
  the same form.
- HelloVerifyRequest (DTLS 1.2) is a client edge `hello -> hello_verify -> hello`: the
  client sends its hello again, unchanged but for the cookie, with the next message_seq; the
  first hello and the request leave the transcript. At most three requests are answered.
  A ServerHello choosing DTLS 1.3 after a HelloVerifyRequest is refused (a DTLS 1.3 server
  never sends one). The server machine never sends one: return routability is the stateless
  `dtls.Cookies` check before any association exists (below).
- No EndOfEarlyData and no early data: none is offered or accepted, as in TLS.
- Two hello extensions are datagram-only: connection_id (RFC 9146, in the ClientHello and either
  version's ServerHello, never a retry request) and use_srtp (RFC 5764: the ClientHello, a DTLS
  1.2 ServerHello or DTLS 1.3 EncryptedExtensions). An answer to one not offered is
  unsupported_extension; a use_srtp answer names exactly one offered profile and an empty MKI
  (cloak keys none, so a server MKI differs from the client's, illegal_parameter). The server
  answers connection_id when it has an ID of its own to receive with and the client offered one,
  and chooses the first of its SRTP profiles the client lists; the engine keeps the peer's
  connection ID for the carrier until the handshake ends and the profile in `Info.srtp`. The
  NULL-cipher SRTP profiles are not offered.
- A record's epoch is explicit, so a message that changes keys needs no record of its own as
  on a stream: the table's epoch check refuses a message under the wrong keys.

Every other edge, check and proof is the TLS one: hello negotiation, HelloRetryRequest
(once), certificates, CertificateVerify, Finished, client authentication, resumption, key
update. A datagram is never a reason to skip a check.

### What the carrier owns

`dtls.Datagram` owns, for one association: the record layer of both versions (epochs,
explicit sequence numbers, DTLS 1.3 record-number encryption, the replay window), handshake
message sequencing, fragmentation to the MTU and reassembly, the flight cache and its
retransmission timer, DTLS 1.3 ACKs and the pre-validation output allowance. It exchanges
whole datagrams (`receive`, `send`) and takes the caller's monotonic `now`; it stores no `Io`,
socket or clock and performs no I/O, like `Connection`. Requests (entropy, time,
verification, signing) are the same service tokens as on the other carriers. Application
data is one record per datagram (`write`), and what `receive` opened is read in place
(`read`).

- Records. DTLS 1.2: the 13-byte header (type, version, 16-bit epoch, 48-bit sequence,
  length); the additional data is epoch and sequence, the record's own type and version and
  the plaintext length (RFC 6347 section 4.1.2.1; RFC 9146's form for a record with a
  connection ID). GCM and CCM put the explicit nonce on the wire: cloak sends its epoch and
  sequence and reads whatever value the peer sent (RFC 5288 asks only that it never repeat;
  OpenSSL's does not follow the record number), which the additional data's record number
  binds anyway. DTLS 1.3: the unified header (16-bit sequence and a length on what cloak
  sends), the AEAD nonce from the 64-bit sequence alone, the header before record-number
  encryption as additional data, and the sequence masked with AES-ECB or ChaCha20 under the
  epoch's "sn" key over the first 16 bytes of ciphertext (a 16-byte tag makes every
  ciphertext long enough; a shorter one is dropped). Epochs: 0 plaintext, 2 handshake, 3
  application, 4 and up per key update (DTLS 1.3); 0 then 1 after ChangeCipherSpec (DTLS
  1.2). The sequence is reconstructed nearest one past the highest authenticated one, the
  epoch from its two bits as the newest read epoch that has them.
- Connection IDs. Once the hellos agree, every protected record this end sends carries the
  peer's ID (DTLS 1.2's tls12_cid records with RFC 9146's additional data, DTLS 1.3's C bit),
  and a protected record arriving without this end's own (or with one when none was agreed) is
  dropped, though it would authenticate in the other form (RFC 9146 section 3). An empty ID in a
  direction means none on those records. A record does not say its ID's length, so the IDs an
  end hands out all have its own's length; `connectionIdOf` reads it off a datagram for the
  caller's lookup before any association is involved. DTLS 1.3's NewConnectionId and
  RequestConnectionId are the carrier's, never the engine's: they are accepted only after the
  handshake under application keys and only when the agreement allows them (NewConnectionId
  from a peer that takes IDs, RequestConnectionId from one that sends with this end's,
  unexpected_message otherwise); immediate usage switches at once, spares are kept (four, the
  rest discarded), and a request while the peer's last one is unanswered is
  too_many_cids_requested. The caller hands IDs out (`newConnectionIds`), since they are its
  routing keys, sees how many the peer asked for, asks for more and moves to a spare on a new
  path. Addresses are the caller's: `receivedNewest` says a datagram authenticated a record newer
  than any before it, the condition RFC 9146 section 6 sets before following a peer to a new
  address, with the caller's own check that the address answers.
- Invalid input is dropped, never fatal (RFC 9147 section 4.5.2): a record that fails to
  parse, to authenticate, falls outside the replay window or names an epoch with no keys is
  discarded without touching the association, its timers or its handshake, and its failed
  authentications count per key against the AEAD's forgery limit (2^36 for GCM and
  ChaCha20-Poly1305, 2^23.5 for CCM), past which the association ends (`ForgeryLimit`). A
  record is marked in the replay window only after it authenticates. A datagram's records
  reach the engine one by one, so the keys a ServerHello or ChangeCipherSpec brings open the
  records after it in the same datagram. Once the peer's keys are in (or the handshake is
  over) a new plaintext handshake message can only be forged: it is dropped, where the engine
  would refuse it and end the association. A plaintext alert counts only before any key.
- Flights. The handshake's flight is one state machine; after the handshake each NewSessionTicket,
  KeyUpdate, NewConnectionId and RequestConnectionId is a flight of its own with its own timer
  (RFC 9147 section 5.8.4), so a message of one kind never stops another's retransmission: at
  most one KeyUpdate, one NewConnectionId and one RequestConnectionId wait at once, tickets as
  the server issues them. A record an ACK names belongs to one flight by its slot and
  generation, and a partial ACK makes that flight's missing part go again early.
- Handshake reliability. Messages carry message_seq; up to 16 ahead of the expected are
  buffered, older ones are a retransmission, further ahead dropped. Reassembly checks offset
  plus length against the declared total in 64 bits before any write and before allocation,
  and keeps a message's type, total, epoch and overlapping bytes fixed (F77): a fragment that
  disagrees with what is held is dropped when what is held came under keys, wins when both
  are plaintext (a forged fragment that came first is undone by the genuine one), and always
  wins with keys over plaintext; at most 16 incomplete messages and 256 KiB. The flight cache
  keeps each sent message's exact bytes; a retransmission re-fragments from it at the current
  MTU (`setMtu`) into fresh records, never from a send cursor. The timer (1 s, doubling to
  60 s, at most 7 retransmissions, then `HandshakeTimeout`) runs until the peer's whole answer
  has made the engine speak again or the handshake ends (RFC 9147 section 5.8.1): a partial
  answer does not stop it, and at its expiry DTLS 1.3 ACKs what it has (the peer resends the
  rest) where DTLS 1.2 resends its flight. A repeated peer message our flight answers sends
  our flight again (at most once per half period); one that answered our flight sends our ACK
  again. DTLS 1.3 ACKs what no flight of its own answers: the client's final flight at a
  server, NewSessionTicket and KeyUpdate, with records named by an ACK freed from
  retransmission and an ACK of every record ending the flight; the peer's application data
  does not end a client's wait for the ACK of its final flight, since a server may send it before
  that flight arrives (RFC 9147 section 5.8.1); only the ACK does, and the server's own last
  handshake flight is answered by the client's, never ACKed. After the handshake each record of
  a peer's message is ACKed, a repeat too, and an ACK lists the newest records that fit the
  datagram, in increasing order. A client that receives records under keys it does not hold yet
  (the datagram with the ServerHello lost) sends an ACK of what it has, or of nothing, in the
  clear before it has keys (RFC 9147 section 7.1); an ACK in the clear proves nothing, so what it
  names counts for nothing, but like an authenticated partial ACK it may make the handshake
  flight go again before its timer, once a timer period, so no ACK makes a flight go more than
  twice a period. After the handshake a flight whose ACK never comes, or whose keys a later
  update retired, is given up on without ending the association. DTLS 1.2's last flight has no
  timer: it goes again when the peer repeats its own.
- Return routability. A server first checks a ClientHello with `dtls.Cookies`, statelessly:
  a hello without a valid cookie gets a HelloVerifyRequest (DTLS 1.2) or a HelloRetryRequest
  with a cookie (DTLS 1.3) written into the caller's buffer, at most three times the
  datagram's size, and nothing is allocated. A cookie is an HMAC-SHA256 under the current or
  the previous caller-rotated key over the client's address as the caller names it, a time
  (honoured for a minute) and: for DTLS 1.3 the transcript hash of the first hello, the
  suite and group the retry request named, whether it asked for a share and the hello's
  fingerprint, from which the admitted association resumes (`Server.resumeRetry`: the
  transcript holds the hello's hash and the request, and the second hello must match the
  first, offer the suite and bring the share); for DTLS 1.2 the hello's random, session id
  and suites, in 32 bytes (DTLS 1.0's limit, which wolfSSL keeps: it sent back an empty
  cookie for a longer one). A hello that does not fit one datagram is checked only by a
  cookie its first fragment carries, so a client's first DTLS hello offers at most one
  classical share (X25519 when listed) and none for a hybrid-only or post-quantum-only list,
  whose shares do not fit beside the hello (wolfSSL's client empties its first key share
  likewise); a server that wants another group asks for it in the retry request that brings
  its cookie. A server of DTLS 1.2 alone answers the first fragment of a cookieless hello
  with a HelloVerifyRequest over the random, session id and suites it starts with (OpenSSL
  falls back to DTLS's 256-byte minimum MTU where it cannot read the path's, and fragments a
  hello with use_srtp); one that also speaks DTLS 1.3 drops it, since the versions may lie
  beyond the fragment and a DTLS 1.3 server sends no HelloVerifyRequest. A server without cookies (an ICE-validated path, `.{}`) is trusted; one created
  with no admission sends at most three times the bytes it received until the client's
  handshake keys prove the path.
- use_srtp. `srtpKeys` gives the master keys and salts of the agreed profile from the
  "EXTRACTOR-dtls_srtp" exporter without a context (which in DTLS 1.2 differs from an empty
  one, RFC 5705 section 4) in RFC 5764 section 4.2's layout, split into this end's and the
  peer's, in a value the caller erases; the SRTP itself is the application's.
- Key updates (DTLS 1.3): one at a time (`UpdatePending` until its ACK); the KeyUpdate goes
  under the old keys and the sender switches when it is acknowledged; a peer's update adds
  the next read epoch beside the current, which a record under the new one retires; a write
  epoch updates by itself with an eighth of its records left; epochs stop at 2^48. DTLS 1.2
  has none, and its association ends at the record limit.
- Resumption: TLS 1.3 tickets as on a stream; a ticket's format byte names its carrier, so a
  DTLS ticket (its keys from "dtls13" labels) never resumes over TLS or the reverse.

Defaults are design §5.7's: MTU 1,200, replay window 128 records per retained epoch,
reassembly 16 messages / 256 KiB, flight cache 256 KiB, pre-validation output 3x.

### AES-CCM

AES-128-CCM (16-byte tag) is a suite of TLS 1.3 and DTLS 1.3 (TLS_AES_128_CCM_SHA256), and
ECDHE_ECDSA with AES-128-CCM and AES-256-CCM of TLS 1.2 and DTLS 1.2 (RFC 7251), offered
only when listed, never by default. CCM_8's 8-byte tag is refused: RFC 9147 section 4.5.3
forbids it in DTLS without other forgery protection, and TLS gains nothing from it. std's
CCM fixes a 13-byte nonce, so cloak's CCM is its own (12-byte nonce, 16-byte tag) in
`src/crypto/`, pinned by Wycheproof's and RFC 3610's vectors, its tag compared in constant
time. CCM's confidentiality limit is 2^23 records per key (RFC 9147 Appendix B), below
the GCM limit, and its records fail authentication at most 2^23.5 times per key.
