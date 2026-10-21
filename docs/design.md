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
copy of the material travels back through the parser's frames. Traffic secrets
and record keys take the same two rules. Every point where they meet a std
primitive is a scrubbed kernel (`tls/crypto/Kernels.zig`): HMAC over a secret
(HKDF-Expand-Label and Extract, the TLS 1.2 PRF, the DTLS cookie and ticket-key
MACs, a ticket key's derivation) to 8 KiB, and record sealing, opening and DTLS
1.3's record-number mask to 4 KiB of their own, since every record pays for it.
The AEAD nonce is made inside the kernel from the IV and the public counter. And
every owner of them is made where it is kept and moved, never passed or returned
by value: the key schedule, the handshake's outputs (claimed in their queue slot,
`Flight.claim`), stream and DTLS epochs and record protection. Live registers,
the entry function's own frame and a signal stack stay out of reach. Wasm
inspection cannot establish a downstream JIT's spill behavior.

A key can also be built from its numbers (`PrivateKey.fromComponents`), as a JWK carries them
(RFC 7518 section 6, RFC 8037): an EC scalar of exactly the curve's width with its optional
public point, an Ed25519 seed with its optional public key, or a two-prime RSA key's eight
numbers in their fewest bytes. There is no second validator: the DER parsers extract the same
numbers and call the same constructors (`Key.ecKey`, `Key.ed25519Key`, `Rsa.fromIntegers`), so
both routes check the scalar's range, derive the public half and compare it when given, and check
that RSA's numbers agree (n = pq, the exponents and CRT values) and are minimal. An RSA key needs
all eight: the private operation is CRT's, and a JWK with d alone (or more than two primes) is
refused by its reader. The build runs in a scrubbed frame like a parse.

An RSA modulus with the ROCA fingerprint (CVE-2017-15361: Infineon's library made primes that
anyone factors from the public key) is refused wherever cloak takes an RSA key: a certificate's
or raw key's SubjectPublicKeyInfo (`Algorithm.checkRsa`, also bounding the size and exponent),
a key a caller builds for `signature.verify` (a JWK's n and e: the verifier runs the same
check, so no path skips it), and a private key, parsed or from its numbers. The test is the
published detector's moduli test, its masks derived from their definition (the powers of 65537
modulo each prime up to 167) and checked against the published ones; a random modulus passes it
with probability below 2^-150. Trusting such a key is the failure, not its speed: a certificate
with one is invalid (bad_certificate), like any malformed key.

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
and `Charge.release` returns it under the guard, so a release returns exactly what was reserved, and
Debug builds catch a second release; a refused admission leaves both counts as they
were. Observational counts are raw scalar snapshots. Checked integers cover DER numeric decoding,
identity/receipt/service allocation sizes and KDF narrowing; ranged integers
reject zero rounds. Required admission invariants remain active in every mode.

The spin sections contain only bounded phase/count/result mutations and fixed
request-digest comparison. Hashing, verification, result cleanup and allocator
calls occur outside the guard. Reference counts and detached executor completion
ownership are independent of this lock and retain their existing reaping rules.

The rest of aegis has no site here, by what each would add. Handles: cloak keeps no
generational storage (one open request per connection, jobs counted by reference), and
request tokens are typed aegis IDs compared by `Token.eql`. `Untrusted`: every parser
reads peer bytes, or bytes cloak's own MAC or AEAD authenticated, and nothing else, so
the marker would restate what each assumes; the refinement it stands for is the parsers'
typed results, and an open code point becomes a negotiated value only through
`supported()` and the offered list. `err.Context`: cloak's diagnostics are one flat
typed record per connection (phase, reason, alerts sent and received), not a stack of
frames. `own`: the owners that must not be copied (budget reservations, secrets) carry
aegis's own exactly-once witness already. The session cache's bytes are an aegis budget,
each kept ticket holding its reservation until it leaves its slot. TLS-specific policy,
refcount and job lifetime are not generic owner substitutes.
Existing fixed-width constant-time arithmetic/select and volatile spill barriers
remain the reviewed local kernels pending published constant-time values.
Secret owners erase their explicit storage on ordinary success/error cleanup,
are made where they are kept, and every std primitive that takes their bytes runs
in a scrubbed frame ("Parsing and private material"; F93 searches the stack and
released memory); none of this reaches registers, the entry frame, OS paging or
process abort, nor proves hardware constant-time behavior.

## TLS 1.3 foundations

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
Seal commits a nonce exactly once; the Connection retains those committed
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
issued by the crypto/verification driver. Each catalogue row's tests are listed in
"Failure catalogue: the test map" below.

Every comparison of a secret or a MAC runs aegis's `Choice` kernels (Finished, binders,
the CCM tag, ECH confirmations, DTLS cookies, pins, request digests, the curve-scalar
range), each releasing only its completed verdict through a named `declassify`. They
compile for every target cloak builds for; `aegis.secret.Choice.audited` says whether a
build is one whose lowering aegis inspects (the hosted targets at their baseline and
common CPU models, the BSDs, wasm32), and cloak's timing checks on the built binary cover
the rest. Every call that computes with a secret runs under the processor's
data-independent timing mode (aegis `Timing`: Arm FEAT_DIT, which on Apple's M3 and later
also stops the data memory-dependent prefetcher), set at the carriers' entry points and
the cookie and ticket-key rotations, and restored as found. The kernels with secret
temporaries (key shares, HPKE, the P-curve agreements, signing, key parsing) also run as
`aegis.secret.scrubbed` computations, which erase the stack they reached; each key-exchange
group is its own instance with its own depth. `zig build timing` is the evidence on the
ReleaseFast build: shakedown's leak test (dudect: a fixed and a random class of the
secret, interleaved, Welch's t) per kernel. On an Apple M3 without the mode std's X25519
was told apart by its secret (|t| 16 to 37) and the P-curves, ML-KEM, AES-GCM,
ChaCha20-Poly1305, HMAC, the Choice comparison and the signatures were not; on AArch64
Linux on the same machine the Choice comparison was told apart by where its inputs
differed (|t| 18 to 23), which is why the mode is set at the entry points and not only
around the key exchanges; with the mode none was. A run finds a leak with some confidence and never proves there is none. The
curve and RSA kernels keep their own masks (one value barrier per mask, reused across a
table entry's limbs and vectors): aegis's `Choice` selects one integer per barrier and
hands out no raw mask, so moving them would cost a barrier per word or widen `Choice` to
what it exists to avoid, for no change in what the built code does; their evidence is the
codegen review of the AArch64 field and the timing rows. AEAD selects std's kernels and rejects `.none` mitigations
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

GREASE (RFC 8701) is the caller's choice, off by default: a hello under `grease` leads its
suites, supported_groups (with a one-byte key share in a first hello), supported_versions and
signature_algorithms with a reserved value each, opens its extensions with an empty reserved one
and closes them, before pre_shared_key, with another of one zero byte. The six values come from
the hello's entropy, one per kind, the two extensions apart, and stay across a retry, whose
second hello drops the reserved share (RFC 8446 section 4.1.2: the named group's share alone).
An ECH inner, encoded and outer hello carry the same values, so the server rebuilds the inner
hello the client hashed. The lists a ServerHello, retry request or EncryptedExtensions is
checked against never hold a reserved value, so a server choosing one is refused (RFC 8701
section 3.1). A server sends none (section 3.2 is a MAY).

Key shares are fresh per hello and per retry. The caller's group order decides which go in the
first hello: a share for the first post-quantum or hybrid group listed and one for the first
classical group, at most two, in supported_groups' order (RFC 8446 section 4.2.8 lets a client
send any subset); under `require_hybrid`, the first hybrid alone. The default order gives
X25519MLKEM768 plus an independent X25519 share; a list led by MLKEM1024 shares MLKEM1024 and the
first classical group. Any other listed group a server prefers, P-256 and P-384 by default, is
obtained through HelloRetryRequest. Group 4588 sends the ML-KEM encapsulation key first, and its
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

Hostile input. A protected record is accepted only with a 0x0303 legacy version, a
plaintext one with any {03,XX} (the field is ignored, RFC 8446 section 5.1); protected
records authenticate before any plaintext leaves the record buffer, and the first
failed authentication ends the connection. One change_cipher_spec is ignored after the
first ClientHello, only between messages before the peer's Finished, whether or not
either side asked for middlebox compatibility; a server takes a plaintext alert as the
client's own until a record opens under the client's handshake keys (a client refusing
the ServerHello has none to write under). Handshake messages are
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
when its own budget runs low. A peer's request is answered with one KeyUpdate before the
next application data, so requests that arrive while this end is silent get one answer
(RFC 8446 section 4.6.3); under a kernel holding the write keys, which sends that data
unseen, the answer goes at once. Budgets default to 2^24 records and 2^38 bytes per
epoch and direction; tests lower them.

Memory. A running handshake holds one scratch block (offered key shares, the
transcript, queued outputs, the peer chain) of about 25 KiB, a flight buffer, a
record buffer sized to the record being read, a message buffer and the output
buffer: about 50 KiB at the peak for the default offer. When the connection is
established the scratch block and flight are freed; `trim` returns the record and
message buffers and `trimOutput` the output buffer when nothing is pending, and `Session`
calls them before it waits to read and after it flushes. What remains for an idle connection is the struct (688 bytes) and one
heap block of 832 bytes (the key schedule's exporter and resumption secrets among it), 1,520
bytes in total, in a Debug build: the client's options live in the handshake scratch and go with
it, and only what outlives the handshake (the ticket cache, the message bound, the server name
and the client certificate's identity) stays; post-handshake authentication, when offered, adds
its 336 bytes. These are heap figures from a counting allocator; stack use
is not measured here.

`Session` drives a `Connection` over `std.Io` readers and writers. It answers
requests with the system's secure randomness and calendar clock (or a fixed time),
the portable verifier over a trust snapshot (or a caller's verifier), and, for
a key cloak does not hold, a caller's signer. A refused chain goes out as the verifier's reason
(RFC 8446 section 6.2): no path to an anchor unknown_ca, a validity outside the time
certificate_expired, a revoked certificate certificate_revoked, revocation evidence missing,
stale or unacceptable bad_certificate_status_response (RFC 6066 section 8), a corrupt
certificate or a signature that does not verify bad_certificate, a caller's verifier saying no
for reasons of its own certificate_unknown. The portable verifier reports a path refused by its
revocation evidence as that refusal, not as no path found (F153). Whichever verifier
took a chain, the engine checks that the leaf's Key Usage, when present, allows signing before
it trusts the CertificateVerify the leaf's key made (RFC 8446 section 4.4.2.2; bad_certificate,
F152); with verification off (`Trust.none`, pinned leaf keys) nothing of the certificate is
checked. After the handshake one task may read
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
A credential without names answers for any name. The candidates are the credentials
answering the client's name; when none does, every credential is one, or with
`unknown_name = .reject` the connection ends with unrecognized_name. The first candidate,
in the server's order, that the client can take answers (RFC 8446 section 4.4.2.2): a form
it takes (RFC 7250), and in TLS 1.3 a usable delegated credential or a scheme it lists that
the leaf's key type and curve can make; in TLS 1.2 a certificate suite of the key's kind
both offer, an ECDSA key's curve among its groups (RFC 8422 section 5.1) and a
ServerKeyExchange scheme it lists. One server can so hold an ECDSA and an RSA credential, a
P-256 and a P-384 one, or an ML-DSA and a classical one, and answer each client with one it
takes. A credential of another name is never taken, since the client would refuse it. With
no candidate fitting, the refusal is the furthest one got: unsupported_certificate when none
is of a form the client takes, handshake_failure otherwise. The chain's own signatures
(signature_algorithms_cert) do not rank credentials: RFC 8446 lets a server send a chain the
client may not verify, and the client's verifier decides. The signature scheme is the first
the client accepts that the leaf's key type and curve can make, in cloak's order, or in the
credential's own when it names its schemes (`Credential.schemes`, a client's
`ClientCredential.schemes`, as Go's `SupportedSignatureAlgorithms` and BoringSSL's per-credential
signing preferences): a key held where only some schemes may be used, or an order other than
cloak's. The list restricts and reorders cloak's and never adds to it, a scheme the key or the
version cannot make passed over, so one list serves both versions; a credential with none the
peer takes is not chosen. The schemes an end takes from its peer are cloak's unless the caller names
its own (`peer_schemes`, either role and every carrier, at most 16: BoringSSL's verify
preferences, the lists a FIPS or CNSA policy allows): they then restrict and reorder cloak's
for the version and never add to them, in the hello's signature_algorithms, every
CertificateRequest, and every check of the peer's CertificateVerify or ServerKeyExchange; a list
that leaves a hello, or a CertificateRequest of a version the server speaks, nothing to name is
refused at init (a server's needs one version it speaks to name some; a handshake of a version
its list leaves nothing ends with handshake_failure). `Info.peer_scheme` names the scheme the peer proved possession under
in the handshake (null when it signed nothing, a resumption among them). `Info.credential` names the
credential each end presented by its index (the server's answer, a client's to a
CertificateRequest), null on a resumption, a provisioned key or an empty client Certificate;
TLS 1.2 weighs a credential while choosing the suite and drops it when a ticket or a key then
authenticates instead.

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
offer was GREASE); after the server's Finished the client completes the handshake (RFC 9849
section 6.1.6), a CertificateRequest answered with an empty Certificate, never its own (6.1.7),
then its Finished, and only then sends ech_required, under its application keys, and fails with
`EchRejected` (F154). The server's retry configurations are released
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
the exchange is always a fresh (EC)DHE one. A client's `external_psks` are up to four keys, each
an identity (1 to 1,024 opaque bytes), the key and its hash, offered in that order instead of a
ticket, each with an obfuscated age of zero and a binder under "ext binder", and each needing a
TLS 1.3 suite of its hash; after a retry request the second hello keeps the offers of the chosen
suite's hash alone (RFC 8446 section 4.1.2), and the server's index counts that list. A server's
`external_psk` is a lookup: it sees the offered identity, the server name, the protocol the server
chose and the transport, so the caller decides what each key is bound to (endpoint, application,
transport); its answer must name the queried identity byte for byte and be a valid key, or it is
passed over, and a binder that fails is fatal (decrypt_error). Keys are tried before tickets. A
handshake on a key sends no certificate either way and authenticates both ends by the key alone,
whatever the certificate policy; `Info.external_psk` names the key's identity at both ends (a
server learns which provisioned client it is talking to), and no X.509 identity is implied.
Such a session issues no tickets and the client keeps none: it resumes by offering the key again.
Reflection (an endpoint that is both client and server answering its own hello) needs the same
key provisioned for both roles, which is the caller's to avoid (RFC 9257 section 4.1). Live peer:
OpenSSL's `-psk` both roles; Go has no provisioned PSKs.

A key may be imported (RFC 9258, `External.imported`; owner's call 2026-10-21): an external key
of 16 to 1,024 bytes, never used as it is. The client offers it once for each hash of the TLS 1.3
suites it offers, under an ImportedIdentity (the external identity, the key's `context`, the
target protocol, TLS 1.3's 0x0304 or DTLS 1.3's 0xfefc with QUIC counted as TLS 1.3, and the
target KDF), and under the key derived for that protocol and hash: HKDF-Extract of the key under
a zero salt, expanded by "derived psk" over the hash of the ImportedIdentity, both by the hash the
key is imported with (`External.hash`), with the protocol's label prefix; its binder is under
"imp binder". So one provisioned key serves both hashes and never the same derived key for two
protocols (RFC 9257 section 6). A server reads an offered identity no plain key answers as an
ImportedIdentity: one for its own protocol and the chosen suite's hash is looked up by its
external identity with the context in the query (`Query.imported`), and only an imported key of
that context answers it, as only a plain key answers a plain identity: a key provisioned for
import is never used directly, nor a direct one imported.

A key is for one version (`External.version`; RFC 8446 appendix E.7 forbids sharing one), and a
lookup is told the version it answers for (`Query.version`); an answer of the other version is
passed over. A server's credentials may be empty when it has a lookup: it then authenticates by
keys alone, and a client offering none it knows ends with handshake_failure (`PskRequired`).
For that the TLS 1.3 server decides the PSK before it chooses a credential: the credential, its
scheme and the certificate types are chosen only for a handshake no PSK authenticates (a key
offered by a client that takes only raw keys meets a server holding only X.509, and the key
decides).

### TLS 1.2 PSK

CoAP's and LwM2M's PSK mode (RFC 7252 section 9.1.3.1, RFC 7925 section 4.2, LwM2M 1.1/1.2) is
TLS 1.2 plain PSK (RFC 4279) with TLS_PSK_WITH_AES_128_CCM_8 (0xC0A8, the mandatory one) or
TLS_PSK_WITH_AES_128_CCM (0xC0A4, RFC 6655), over DTLS 1.2 or TLS 1.2. Plain PSK has no key
exchange: the premaster is the key alone (its length, as many zeros, the length again, the key),
so a key that leaks opens every session ever recorded under it, and anyone who records one
handshake can test guesses at the key offline against its Finished. The profiles mandate it;
cloak speaks it only when the suites are listed with a TLS 1.2 key, at both ends, never by
default, and refuses keys shorter than 16 bytes (a password-like key is a search away) or longer
than RFC 4279's 64. The ECDHE_PSK suites (RFC 8442's AEAD ones) would give forward secrecy, but
no profile asks for them and no peer here speaks them (OpenSSL has only ECDHE-PSK with CBC and
ChaCha20): a candidate, not built.

The wire is RFC 4279's: the server sends ServerHello and ServerHelloDone, no Certificate and no
ServerKeyExchange (no identity hint: keys are named by the client alone); a client ignores a
hint a server sends, unsigned, in a ServerKeyExchange; the client names its key in
ClientKeyExchange (`opaque psk_identity<0..2^16-1>`), then ChangeCipherSpec and Finished. The
extended master secret is required and the renegotiation indication treated as for every TLS 1.2
handshake; neither side presents or requests a certificate, so the server answers no certificate
types and no point formats, and a ServerHello choosing a PSK suite that answers certificate types
is refused. In the state table the decision is an event, `psk12`, taken before the ServerHello's
edge (as `resumed12` is), and the path's own states (`p_`) project onto the full handshake's
phases; past the key exchange it joins the full handshake.

The server chooses by its own order among the suites the client offers: a PSK suite when it has
a lookup, a certificate suite of its credential's key otherwise, so one server can take both
kinds of client. The identity arrives only in ClientKeyExchange, after the suite is chosen. An
identity the lookup does not know, one of the other version, an empty or oversized one, or an
answer naming another identity, is not refused there: the server goes on with a random key drawn
with its hello's entropy, and the client's Finished fails to open as a wrong key's does
(bad_record_mac), so a prober cannot tell a known identity from an unknown one (RFC 4279 section
2 allows either). A session on a key gets no ticket (the server promises none; a client that is
sent one anyway keeps none), and `Info.group` is null: there was no key exchange. Kernel TLS takes
the CCM suite as its ECDHE sibling; CCM_8 stays in software. Live peers: OpenSSL 4.0.3 (`-psk`,
its CCM_8 only at `@SECLEVEL=0`) and wolfSSL 5.9.4 built with PSK, both roles, over TLS 1.2 and
DTLS 1.2.

## Raw public keys

A raw public key (RFC 7250) is a key trusted for itself, by a pin the caller provisioned, with
no certificate, issuer, name or expiry. It is its own trust, separate from X.509: a client's
`verify` is `.raw_key` (the SHA-256 of each SubjectPublicKeyInfo it accepts) instead of `.full`,
and a server's `client_verify` the same, so one connection trusts one kind of evidence and a
certificate is never accepted where a key is pinned, nor a key where a chain is verified. Both
versions, every carrier (TLS 1.2 and DTLS 1.2 since the CoAP and LwM2M profiles need them; RFC
7925 section 4.3).

A client pinning keys sends server_certificate_type listing the raw key alone. A server that
does not answer it would send X.509, which the client refuses at EncryptedExtensions (TLS 1.2:
at the ServerHello, which carries the answers there) with unsupported_certificate, before
anything is verified. The Certificate must carry exactly one
entry, a SubjectPublicKeyInfo that parses and whose SHA-256 one pin names (every pin compared;
which one matched is released, as `Info.pin`); the CertificateVerify is then checked
against that key under the schemes offered, as for a leaf. No service is asked: there is no
time, chain or trust store in it. A client whose credentials include a raw key
(`ClientAuth.initRawKey`) sends client_certificate_type listing the forms it holds in the order
they first appear in `credentials` (no extension for certificates alone, which is what its absence
means) and presents a credential of the type the server selected; a server that answers nothing
asks for X.509, and a client holding raw keys alone then answers a CertificateRequest with an
empty Certificate.

An `Identity` has a form: certificates, or a raw key (`initRawKey`, `initRawKeyExternal`), whose
`chain()` is empty and whose `entries()` is the one SubjectPublicKeyInfo a Certificate carries
(`PrivateKey.publicKeyInfo` writes it from the key alone, the bytes its certificate would hold);
`publicKey()` is the key either form signs with, so no step reads a raw key as a certificate. A
server picks the first credential answering the name whose form the client takes (X.509
unless its server_certificate_type lists only other types; the raw key when it lists one) and
whose key it can take, and
answers server_certificate_type when the client sent it; with no credential of a form the client
takes, the handshake ends with unsupported_certificate. A server asking for a client certificate
answers client_certificate_type with the type its `client_verify` takes when the client listed
it, and otherwise says nothing, so the client sends X.509 or nothing; a chain where a key is
pinned ends with unsupported_certificate.

Resumption keeps the trust apart: the client's cache key holds the pins (or the verification
policy) and the server's ticket policy digest holds them too, so a session from one kind of
trust never resumes under the other, and a ticket keeps which pin the client proved. A ticket
also keeps the form the server proved itself with: a resumption answers a client's
server_certificate_type with that type (no answer reads as X.509, RFC 7250 section 4.2, and a
client taking raw keys alone, as BoringSSL's, refuses it), and a client whose list leaves the
session's type out gets a full handshake instead. A rejected
ECH attempt authenticates the public name's certificate, which a client pinning a key cannot,
so ECH with a config list is refused with `.raw_key`. Post-quantum authentication with a pinned
key is an ML-DSA key: the CertificateVerify schemes offered are ML-DSA's alone.

In TLS 1.2 and DTLS 1.2 the ServerHello answers both types, and a Certificate of the raw key
type is the SubjectPublicKeyInfo alone, one 24-bit length and the key, with no list around it
(RFC 7250 section 3). The key signs the ServerKeyExchange and the client's CertificateVerify as a
leaf's would, and picks the suite family the same way (ECDSA suites for EC and Ed25519 keys, RSA
suites for RSA keys); an ML-DSA key has no TLS 1.2 suite. A client the server asked for a key
but that has none to present sends the empty form, the same three zero bytes as an empty X.509
list (the raw form itself is at least one byte), which the server takes as no certificate. A
TLS 1.2 session ticket carries the client's proved pin as a TLS 1.3 one does, and the client's
cache entry the server's.

## Pinned leaf keys

A pin with no authorities (cloak 0.19.0; curl's CURLOPT_PINNEDPUBLICKEY with peer verification
off, which is git's `http.pinnedPubkey` under `http.sslVerify=false`): `Verify.leaf_key` (Session's
`Trust.leaf_keys`, either role) takes certificates as `.none` does and trusts the leaf's key by its
pin alone, the SHA-256 of the leaf's SubjectPublicKeyInfo, the same value `pins` adds to full
verification. The leaf is parsed, its key's pin compared with every pin (which one matched is
released, as `Info.pin`), and a mismatch is `PinMismatch` (bad_certificate) at the Certificate,
before the CertificateVerify; nothing else of the chain is checked (issuer, path, name, validity,
usage, revocation) and no service is asked. The CertificateVerify then proves the pinned key,
so the peer is authenticated by it, unlike `.none`, which checks nothing and reports an
unauthenticated peer. It is X.509 on the wire: no certificate type is negotiated, so a raw key is
never taken where a leaf is pinned. The cache key and the server's ticket digest hold the mode
and its pins, as for raw keys, so a session resumes only under the same pinned leaf keys. Refused
at init with it: no pins, a Session's `pins` beside it (the trust's are the only ones), a
transparency policy, delegated credentials (full verification's) and ECH with a config list
(whose rejection authenticates the public name's certificate). TLS 1.3 and 1.2, every carrier,
post-handshake answers too. F141.

## Delegated credentials

A delegated credential (RFC 9345) is a short-lived key the holder of an end-entity certificate
signs for, so a TLS 1.3 endpoint proves possession with it while the certificate's key stays
elsewhere: an edge holds credentials that expire within days, the origin keeps the certificate's
key. `Delegation.zig` holds the format, the receiver's checks and the owned credential; both
roles use it, and only the signed label differs ("TLS, server delegated credentials" or
"client"). Every carrier (stream, QUIC, DTLS 1.3) takes it, since it lives in the handshake;
TLS 1.2 has none and ignores the extension.

Receiving. A client taking one (`accept_delegated`) lists in its hello's delegated_credential the
schemes a credential's key may use: the TLS 1.3 CertificateVerify schemes but rsa_pss_rsae_*, an
rsaEncryption key never being a credential's (RFC 9345 section 4), and ML-DSA's alone under
`require_pq_auth`. A server taking a client's lists the same in its CertificateRequest. Taking one
needs `.full` verification: the credential's lifetime counts from the certificate's notBefore, and
the clock and the verified chain are what a check stands on, so a pinned raw key or `verify = .none`
has nothing to check it against (the raw-key namespace never meets a credential). The Certificate
parser takes the extension only where it was offered and only on the leaf's entry: unoffered is
unexpected_message, on another entry or twice illegal_parameter, any other entry extension
unsupported_extension. After the chain's receipt is accepted, the credential is checked (RFC 9345
sections 4.1.1-4.1.3), each failure illegal_parameter: its scheme is one this end listed and may
use and binds to its key, the delegation's algorithm is one this end lists in signature_algorithms
(TLS 1.3's schemes, never PKCS#1 v1.5), the certificate carries DelegationUsage (NULL, non-critical)
and the digitalSignature key usage, the credential has not expired (valid up to the second before
notBefore + valid_time), has at most seven days to run, and expires before the certificate does,
and the certificate's key signed it. CertificateVerify is then verified with the credential's key
under the one scheme it names; any other scheme is unoffered. `Info.delegated_credential` reports
it. A session's tickets authenticate no longer than the credential: the client's cache entry and the
server's ticket both end at its expiry, as they end at the chain verdict's, so resumption cannot
stretch the delegation (F89). The client's cache key and the server's ticket policy say whether
credentials are taken.

Sending. A credential is a `delegated_credentials.Credential`: the wire bytes and the private key,
retained and shared like an identity. `Credential.init` checks it against the identity's certificate
when it is made (the certificate may delegate, the key matches, the scheme suits it, the delegation
verifies, it ends before the certificate), so a credential no peer could take is refused once, not at
every handshake; `issue` makes one with the certificate's key, which cloak must hold. A server's goes
in its `Credential` beside the identity it belongs to, a client's in its `ClientCredential`
beside its certificate. It is sent only while a peer would take it: the peer listed its scheme for
credentials and its algorithm in signature_algorithms, it has not expired and has no more than seven
days to run. A server whose credential has one asks for the clock before it answers a hello that
offers the extension, as it does for tickets; a client knows the clock from verifying the server. When
the credential does not fit, the certificate's key signs as before (or the signing request goes to
the caller when that key is held elsewhere), so a stale credential costs a fallback, never a failed
handshake. The credential's key is always held by cloak and signs inside the engine with hedged noise
drawn with the handshake's entropy.

A server that never holds the certificate's key (its owner issues the credentials and keeps the
key) marks its `Credential` `delegated_only`: the identity may be the chain alone, no signer is
needed, and the credential is offered only to a TLS 1.3 client that takes its delegated credential
while it is valid; for any other client it is passed over for the next credential, as one of a form
or scheme the client cannot take is (BoringSSL's delegated credential, a credential of its own).
Alone, it answers such a client with no credential: the handshake fails rather than sign with a
key it does not have.

Peers: NSS 3.128's tstclnt (`-B`) verifies a cloak server's credential (trials `--dc`); no available
server sends one (OpenSSL and Go speak no RFC 9345, BoringSSL's bssl tool has no option for one, NSS's
selfserv cannot load one), so cloak's client is tested against cloak's server, and the offer against
OpenSSL's server, which ignores it.

## Certificate Transparency

Certificate Transparency (RFC 6962) is a verification policy, not a TLS feature: `types.Policy`
names a `TransparencyPolicy`, borrowed, and the verifier (`verify/transparency.zig`) checks the
signed certificate timestamps of the path it accepts, beside revocation and with the same owners.
TLS only carries SCTs to it. Version 1 SCTs only: RFC 9162's v2 has no deployed logs.

The policy is the caller's: the logs (each a key and an operator, and when it retired), the counts
and when the log list stops being current. A log's ID is the SHA-256 of its key, so an ID never
names another key, and every listed key is checked (ECDSA P-256 or RSA, SHA-256) whatever the
certificate carries. An SCT counts when it names a listed log not yet counted, is timestamped no
later than now and before its log retired, and its signature verifies; anything else is skipped,
never trusted, since a certificate may carry SCTs from logs this caller does not list. A
certificate is compliant by its embedded SCTs (over the precertificate: the TBS with the SCT list
extension removed and re-encoded, and the issuer key's hash, the issuer being the path's next
certificate) from `embedded` distinct logs, `embedded_long` when it is valid longer than
`long_lifetime`, one of them not retired; or by SCTs delivered beside it (over the certificate
itself: the TLS extension, a caller's list) from `delivered` distinct logs none retired; either
way from `operators` distinct operators. The defaults are the counts Chrome's and Apple's policies
ask of public certificates. Log lists, their distribution and freshness, inclusion proofs and
gossip are upstream: cloak checks what it is given.

Errors are typed: a malformed list `InvalidTransparency`, too few SCTs `MissingTransparency`
(the verifier reports it instead of `NoTrustedPath` when it is why no path was accepted), a list
past its `expires` `StaleTransparency`, a policy that cannot decide `InvalidTransparencyPolicy`.
Each SCT signature is charged to the request's signature budget. The receipt says `compliant`
and holds no longer than the list's `expires`, so a session resumed from it does not outlive the
list; the request digest covers the policy and the delivered lists, so the client's cache key
keeps sessions verified under one policy from resuming under another, and a service's owned
request copies both.

TLS: a client whose policy names one asks for SCTs (signed_certificate_timestamp, empty) in
both versions; the server's list comes in the leaf's CertificateEntry (TLS 1.3; on another entry
illegal_parameter, unasked unsupported_extension, empty decode_error) or in the ServerHello
(TLS 1.2), and joins the request after the caller's lists. A server's `Credential.scts` is a
list for its certificate as it is, checked for framing when the server is made, sent only to a
client that asks, never with a raw key. SCTs inside a stapled OCSP response are not read.

## OCSP stapling

status_request (RFC 6066 section 8; RFC 8446 section 4.4.2.1). A client that verifies with
revocation on (the default `.if_present`, or `.required`) asks for the server's stapled status
(type ocsp, no responder IDs or extensions), and the response joins the verification request's
evidence after the caller's own: the verifier judges it as any supplied evidence (a stale or
unverifiable staple fails, as RFC 6960's checks do for evidence the caller hands in), and a
Must-Staple certificate (TLS feature status_request) now verifies with its staple, where before
only a caller holding the response could verify one. TLS 1.3 carries the status in the leaf's
CertificateEntry (on another entry illegal_parameter, unasked unsupported_extension). TLS 1.2:
the ServerHello answers the extension empty and a CertificateStatus may follow the Certificate;
a server that answered may still send none (RFC 6066 section 8), so the client verifies the
chain at the CertificateStatus or, when a ServerKeyExchange comes in its place, holds that
message, verifies, then takes it. A CertificateStatus the ServerHello did not announce is
unexpected_message, a status type other than ocsp illegal_parameter. A server's
`Credential.ocsp` is the DER OCSPResponse it staples (the caller fetches and refreshes it;
checked when the server is made to read as an OCSPResponse, at most 16 KiB), sent only to a
client that asks for an ocsp status, never with a raw key, never on a resumption (no
Certificate).

Peers: OpenSSL 4.0.3's `s_client -ct` (strict, with `-ctlogfile`) verifies a cloak server's
embedded and delivered SCTs, and cloak's client verifies OpenSSL's server's (`-serverinfo`).

## Post-handshake client authentication

TLS 1.3 over a stream lets a server ask for a client certificate after the handshake (RFC 8446
section 4.6.2), the way an HTTP/1.1 server asks for one only for some resource. Neither end does
it unless asked: a client offers post_handshake_auth with `post_handshake_auth`, a server asks
only a client that offered it and only with its own `post_handshake_auth`. QUIC forbids it (RFC
9001 section 4.4) and cloak's datagrams do not build it, so both options are refused there; TLS
1.2 has none. A client that did not offer it ends the connection at a request with
unexpected_message.

What outlives the handshake for it (`handshake/PostAuth.zig`) is kept only when both ends took
it: the transcript's hash state through the client's Finished, a hash state and no messages
(336 bytes with its bookkeeping, measured: an idle client that offered it holds 1,856 bytes
with its struct, an idle server that keeps it 2,243). Every exchange starts from that hash: its
CertificateRequest, the client's Certificate and CertificateVerify, then the Finished over them.
Nothing of an exchange enters the handshake's transcript or another exchange's, so a signature or
Finished made for one request stands for no other. The Finished key comes from the current
application traffic secret of the client's write direction (RFC 8446 section 4.4:
client_application_traffic_secret_N), which the record layer holds and turns at each key update,
so the record layer makes and checks that MAC (`Protection.finished`, `Protection.checkFinished`)
and the secret never leaves it; under a kernel record layer (kTLS) it is still the connection's,
since the epoch keeps its traffic secret for the next update.

An exchange crosses the connection's halves, and one half holds it at a time, handed over through
an atomic owner. At the server `requestCertificate` (the write half) builds a request whose context
is the request's number, eight bytes, never repeated on the connection, which is what RFC 8446
asks of it (unique within the connection); randomness would add nothing a signature over the
connection's own transcript does not already give, and would need an entropy service on the write
half. After the request is sealed the read half owns the exchange: a Certificate with any other
context is illegal_parameter (a replay of an earlier answer, or one made for nothing); one with
no request outstanding is unexpected_message. A chain is verified as in the handshake by the
server's `client_verify`, through a `verify` request with a fresh `time` request first, since the
handshake's clock is long past; a pinned raw key when the handshake agreed that type (RFC 7250).
The CertificateVerify is checked against the leaf's key over the exchange's transcript, and then
the record layer checks the Finished under the read keys it arrived under. The answer's messages
come together with nothing between them (RFC 8446 section 4.6.2): application data or a KeyUpdate
inside an answer is unexpected_message, so one key covers it. Only then does the exchange count:
`postAuthentication` reaches the request's number, with `authenticated` saying whether the client
proved a certificate the policy authenticates. An empty Certificate counts with `authenticated`
false: declining is the client's right and the application's to weigh. A refused chain, a bad
signature or Finished end the connection. One request is outstanding at a time
(`RequestOutstanding`). The application gates the action a request was made for on the outcome
reaching that request's number; `Session.awaitCertificate` reads until it does, for a client that
sends nothing more until it is answered (an HTTP/1.1 client waiting for its response), keeping any
plaintext that comes first in the reader's buffer as far as it holds. The handshake's
`Info.peer_authenticated` stays the handshake's, and tickets carry the handshake's
authentication, never a later one.

At the client the read half takes a request and answers with one of the client's `credentials`
the request takes (a scheme it lists for the credential's key, and the certificate type the
handshake agreed), the first that chains to an authority the request names, else the first;
otherwise with an empty Certificate. Delegated credentials answer only the
handshake's request: here the certificate's key signs. The signature takes fresh noise through an
`entropy` request, or a `sign` request for a key held elsewhere, checked against the identity's key
before it is used, as in the handshake. The Certificate and CertificateVerify then go to the write
half, which makes room in its record budget first (so no key update falls inside the answer), makes
the Finished under its current write keys and sends all three. A second request while an answer is
still to be written is refused as a second one outstanding: cloak's server and OpenSSL's keep one
outstanding, and holding requests would make the reader wait on the writer, which the halves never
do. Each request counts as a control message toward the flood bound.

Under a kernel record layer that holds the server's read keys, application data reaches the
application without the connection, so an answer with application data inside it is not seen
as such there; its messages and Finished are still checked. Peers: OpenSSL 4.0.3 (`s_client
-enable_pha`, and `s_server`'s `c` command) and NSS (`tstclnt -E`, `selfserv -E` with three `-r`).

## Record size limit (RFC 8449)

A constrained peer says how large a protected record it can take: record_size_limit, the most
plaintext a record sent to it may carry, counted as the RFC counts it (TLS 1.3's inner content
type and padding in it, TLS 1.2's plaintext alone). The CoAP and LwM2M devices of the CCM_8
profiles send it; cloak honors it in both roles and both versions, over streams and datagrams.
QUIC has no TLS records, so it is neither offered nor answered there.

A client always offers it (RFC 8449 section 4: it SHOULD, so a server may name a limit of its
own), with the `record_size_limit` option or the maximum of the versions it offers: 2^14 + 1
with TLS 1.3, 2^14 for TLS 1.2 alone. A server answers it only to a client that sent it, in
EncryptedExtensions (TLS 1.3) or the ServerHello (TLS 1.2), with its own option or the
negotiated version's maximum. A value under 64 is illegal_parameter either way, and a length
other than two bytes decode_error. A value past the negotiated version's maximum is taken as
that maximum: a server must not refuse it (the client may speak a version the server does
not), and a client takes it too rather than using the RFC's MAY to abort, since a server may
name its TLS 1.3 value in a TLS 1.2 answer. Options take 64 to the maximum of the versions the
end allows.

The handshake tells the carrier what it negotiated (`Flight.RecordLimits`, an emit before the
first record it binds): what this end may seal, the peer's value, and what it opens, its own,
each clamped to the version's maximum. A server knows both from the ClientHello, before any
protected record of its own; a TLS 1.3 client learns the server's in EncryptedExtensions, before
it seals anything, and holds the server to its own limit from the record after that answer; a
TLS 1.2 client learns it in the ServerHello. Without an answer the extension is not negotiated
and neither end is held to anything but the protocol (section 4).

Sealing splits records to the peer's limit: application data (`send` takes at most one
record's worth), handshake messages and post-handshake messages. The RFC binds protected records
only, but plaintext records sent once the peer's limit is known (a server's after the
ClientHello, a TLS 1.2 client's after the ServerHello; a datagram's epoch 0) are cut to it too:
a constrained peer's buffer takes no larger record whatever protects it, and GnuTLS's client
refuses a TLS 1.2 certificate flight past its limit. A protected
record whose plaintext would pass this end's limit is record_overflow on a stream, told by the
record's length before any decryption (its body less the tag and TLS 1.2's explicit nonce);
DTLS drops it, as section 4 allows and as it drops any record it cannot take. Declined early
data a server skips is not checked: it is skipped unopened. In DTLS the limit stands beside the
MTU: a handshake fragment and an ACK fit both, and `Datagram.write` refuses plaintext past
`writeLimit`. DTLS 1.2 records with a connection ID carry their content type inside, as DTLS
1.3 records do, and count it. Resumption negotiates the limit anew, as every handshake does.

Under a kernel record layer (C9) the write direction takes the peer's limit as
TLS_TX_MAX_PAYLOAD_LEN (Linux 6.18; the limit less TLS 1.3's content type), set before the keys:
a kernel without it refuses, and the direction stays in software. A kernel opens records up to
2^14 bytes whatever this end named, so a read direction under a limit below the version's
maximum stays in software (`Unsupported`).

This end may bound its own records lower, whatever the peer takes: `max_fragment` (Connection
and Session, both roles; BoringSSL's and OpenSSL's max_send_fragment), the most plaintext one
record it sends carries, 64 to 2^14, handshake records included. It is not negotiated: the lower
of it and the peer's limit holds, and a kernel's write direction takes that lower one. Datagrams
have no such option: the MTU already bounds their records.

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
group is TLS 1.3's), with a fresh share per connection, except for the provisioned-key suites
of the IoT profiles (above), which have none; the record ciphers are AES-128-GCM,
AES-256-GCM and ChaCha20-Poly1305 (RFC 5288, RFC 7905), the GCM explicit nonce being the
record sequence; the master secret is always the extended one (RFC 7627), and a peer
without it is refused. A client requires the server's secure renegotiation indication
(RFC 5746): a legacy server could be spliced into a renegotiation it does not know is one, and
only the client can tell. A server answers the indication when the client sends it (the
extension or the SCSV) and goes on without it (RFC 5746 section 4.4): the splice needs a server
that renegotiates, and this one never does, so requiring it bought nothing and turned away
clients built without it (wolfSSL's default build among them).
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
scheme to its hash rather than to the key's curve (RFC 8446 section 4.2.3), in both
directions: a P-384 key signs under ecdsa_secp256r1_sha256 when that is what the peer lists
(its own curve's scheme first), the signer taking a hash not the curve's own as RFC 6979's
bits2int, as Go and BoringSSL do, and such signatures are accepted. PKCS#1 v1.5 RSA signatures
are accepted and made only in TLS 1.2. A CertificateVerify signs the transcript hash of its
scheme: both SHA-256 and SHA-384 transcripts run through a TLS 1.2 handshake, so the
signature goes through `signDigest`/`verifyDigest`, and a TLS 1.2 CertificateVerify is made and
taken under those hashes' schemes alone (no SHA-512 transcript runs; a server lists none of its
schemes in a CertificateRequest, and a client asked for SHA-512 alone answers with an empty
Certificate). Ed25519 signs the handshake messages
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
  records after it in the same datagram. Plaintext proves nothing of its sender, so no
  plaintext record ends the association: an unknown content type, an alert that is not one
  two-byte alert, application data before the handshake, a ChangeCipherSpec other than the one
  byte 1, a handshake record cut inside a fragment are all dropped. Once the peer's keys are in
  (or the handshake is over) a new plaintext handshake message can only be forged: it is
  dropped (F82), and so is one held from before the keys whose turn comes after them, or before
  the peer's ChangeCipherSpec, its place left for the genuine message (F148). A plaintext alert
  counts only before any key. What the peer holding the keys sends against the protocol ends
  the association: application data under DTLS 1.3's handshake keys (RFC 9147 section 6.1,
  F144), an inner plaintext naming no content type (RFC 8446 section 5.4, F146), a handshake
  message after the peer's KeyUpdate under the epoch it retired (RFC 8446 section 5.1, F150), a
  handshake fragment cut short, past its record or its message, or of a message past
  `limits.handshake.message` (F160: a plaintext one is dropped, and one under keys would never
  be taken however often it came).
  The message_seq never wraps (RFC 9147 section 5.2, F161): after message 0xffff no message is new
  (message 0 again is an old one, discarded) and this end sends none (`MessageSequenceExhausted`,
  which ends a KeyUpdate or a ticket that would need one).
  A record over the size limit is dropped unopened, as RFC 8449 section 4 allows a DTLS end.
  A fatal alert of a DTLS 1.3 handshake goes under the handshake keys until this end's
  Finished went out, since the peer reads no newer epoch before (F149).
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
  MTU (`setMtu`) into fresh records, never from a send cursor. Under DTLS 1.3 keys a datagram
  carries one record per epoch, holding as many messages and fragments as fit (RFC 9147
  section 5.5 lets a record carry several): a flight costs one header and tag per epoch and
  datagram, which counts at a 256-byte MTU. Plaintext and DTLS 1.2 records carry one message
  each, as tinydtls reads no more from a record. A datagram is left only when not one byte more
  of the next message fits. A retransmission leaves out the bytes an ACK covered (RFC 9147
  section 7.2), and a partial ACK makes the rest go at once, at most once a timer period (its
  SHOULD; BoringSSL waits for its timer). A repeated peer flight is answered once, at its last
  message (RFC 9147 section 5.8.1). The timer (1 s, doubling to 60 s, at most 7
  retransmissions, then `HandshakeTimeout`), which `setTiming` changes mid-association (a running wait
  becomes the new first wait doubled once per retransmission so far, from when it started; a
  waiting ACK moves with it) runs until the peer's answer stops it: in DTLS 1.3,
  once the version is settled (the client has the ServerHello or a retry request, the server
  answered or asked to retry), any message of the peer's next flight acknowledges ours whole
  and it goes no more (RFC 9147 section 7.1); in DTLS 1.2, and before the version is settled,
  only the whole answer stops it and a partial one leaves our flight to go again. DTLS 1.3 ACKs
  every handshake record whose fragments were all processed or held, a repeat's too, and never
  one with a fragment dropped (RFC 9147 section 7: an ACK of it could deadlock, F151), plaintext
  records of the handshake included (the ServerHello, by the ACK the handshake keys carry; in
  the clear before any keys once the version is settled). The list holds the newest 64 records
  and outlives each ACK, so an ACK names as many as fit and a lost one costs nothing; this end's
  next handshake flight clears it. An ACK waits a quarter of the retransmission wait after the
  first record it names, so what arrives meanwhile shares it, and goes before post-handshake
  flights; the client's final flight is ACKed at once. DTLS 1.3 ACKs what no flight of its own
  answers: the client's final flight at a server, NewSessionTicket and KeyUpdate; the peer's
  application data does not end a client's wait for the ACK of its final flight, since a server
  may send it before that flight arrives (RFC 9147 section 5.8.1). A client that receives
  records under keys it does not hold yet (the datagram with the ServerHello lost) sends an ACK
  of what it has, or of nothing, in the clear before it has keys (RFC 9147 section 7.1). An ACK
  in the clear counts once DTLS 1.3 is settled, and for plaintext records only (an ACK's epoch
  is at least its records'): a forged one holds back at most one retransmission of a plaintext
  flight, which the peer's own timer recovers; an empty one makes the handshake flight go again
  before its timer, once a timer period. After the handshake a flight whose ACK never comes, or
  whose keys a later update retired, is given up on without ending the association (BoringSSL
  ends it). DTLS 1.2's last flight has no timer: it goes again when the peer repeats its own.
- Return routability. A server first checks a ClientHello with `dtls.Cookies`, statelessly:
  a hello without a valid cookie gets a HelloVerifyRequest (DTLS 1.2) or a HelloRetryRequest
  with a cookie (DTLS 1.3) written into the caller's buffer, at most three times the
  datagram's size, and nothing is allocated. A cookie is an HMAC-SHA256 under the current or
  the previous caller-rotated key over the client's address as the caller names it, a time
  (honoured for a minute) and: for DTLS 1.3 the transcript hash of the first hello, the
  suite and group the retry request named, whether it asked for a share and the hello's
  fingerprint, from which the admitted association resumes (`Server.resumeRetry`: the
  transcript holds the hello's hash and the request, and the second hello must match the
  first by content, its extensions in ascending type order, not as sent (F104, F115), offer
  the suite and bring the share); for DTLS 1.2 the hello's random, session id and suites,
  in 32 bytes (DTLS 1.0's limit, which wolfSSL keeps: it sent back an empty cookie for a
  longer one). A hello that does not fit one datagram is checked only by a
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
  the next read epoch beside the current, and the first record under the new one sets the old
  to go four minutes later (two maximum segment lifetimes, as BoringSSL keeps it): records of an
  older epoch SHOULD still be read (RFC 9147 section 8), and the keys are erased at the next
  receive or send after that time; a write epoch updates by itself with an eighth of its records
  left; epochs stop at 2^48. DTLS 1.2 has none, and its association ends at the record limit.
- Resumption: TLS 1.3 tickets as on a stream; a ticket's format byte names its carrier, so a
  DTLS ticket (its keys from "dtls13" labels) never resumes over TLS or the reverse.

Defaults are design §5.7's: MTU 1,200, replay window 256 records per retained epoch,
reassembly 16 messages / 256 KiB, flight cache 256 KiB, pre-validation output 3x.

### AES-CCM

AES-128-CCM (16-byte tag) is a suite of TLS 1.3 and DTLS 1.3 (TLS_AES_128_CCM_SHA256), and
ECDHE_ECDSA with AES-128-CCM and AES-256-CCM of TLS 1.2 and DTLS 1.2 (RFC 7251), offered
only when listed, never by default. std's CCM fixes a 13-byte nonce, so cloak's CCM is its
own (12-byte nonce, 16- or 8-byte tag) in `src/tls/crypto/`, pinned by Wycheproof's vectors,
its tag compared in constant time. CCM's confidentiality limit is 2^23 records per key (RFC 9147
Appendix B), below the GCM limit, and its records fail authentication at most 2^23.5 times per
key.

CCM_8 (AEAD_AES_128_CCM_8, RFC 6655: CCM with an 8-byte tag) is in for one suite,
ECDHE_ECDSA_WITH_AES_128_CCM_8 (0xC0AE, RFC 7251), over TLS 1.2 and DTLS 1.2, listed only by a
caller who needs it: it is the mandatory suite of the CoAP and LwM2M profiles for raw keys and
certificates (RFC 7252 section 9, RFC 7925 section 4.3, LwM2M 1.1/1.2 transport section 5.2.9),
and constrained peers often speak nothing else. The security judgement is the forgery bound. A
64-bit tag lets one forged record pass with probability 2^-64. On a stream that is all an
attacker gets: a record that fails ends the connection. In a datagram association a failed
record is dropped and the next tried, so RFC 9147 section 4.5.3 asks for a limit on failures
(appendix B.3). cloak keeps the margin every other cipher has, 2^-57 per key: a CCM_8 key ends
its association after 2^7 records fail to open (`ForgeryLimit`). That trades integrity for
availability, not the reverse: whoever can put 128 forged datagrams on the association's path
can end it (the application then makes a new handshake). A deployment that cannot accept that
lists a 16-byte-tag suite first, which CoAP peers that implement RFC 7251 also speak. Out:
AES-256-CCM_8 (no profile asks for it), TLS 1.3's TLS_AES_128_CCM_8_SHA256 (the profiles in
scope are (D)TLS 1.2; IANA marks it not recommended, and RFC 9147 forbids it in DTLS 1.3
without safeguards: the same limit would apply if a profile needed it), and the CBC suites
LwM2M servers must also offer (TLS_*_WITH_AES_128_CBC_SHA256: RFC 7457's attacks; LwM2M
itself tells clients not to use them), so a cloak LwM2M server meets the client side of the
profile, not that server line. Linux's kernel TLS has no CCM_8: such a connection stays in
software.

## Kernel record layer (C9)

On Linux a connection's direction can move to the kernel's TLS record layer (kTLS) once the
handshake completes: the kernel seals or opens that direction's records, the application's
data passes the connection by (sendfile included), and the connection keeps the rest of TLS.
The handshake never runs in the kernel, and QUIC and DTLS cannot use it.

The move is one call, `Connection.offload(direction, installer)`. It needs a clean boundary:
for the read direction no part of a record or handshake message held and no plaintext unread
(and every byte the caller read from the transport given to `receive`, which only the caller
can know); for the write direction no output unacknowledged. The connection copies the
direction's keys and the next record's number into `offload.Keys`, the installer gives them to
the kernel, and only on its success does the epoch release them (`Protection.release`): its key
and IV are erased, its owner is the kernel, and sealing or opening it here fails. A refused
install leaves the direction in software, unchanged. TLS 1.2 GCM and CCM keys carry the next
record's number as the explicit nonce, which the kernel sends and counts up with the records,
so the records go on as cloak's own would. The traffic secret of a TLS 1.3 epoch stays for the
next key update; nothing else of the direction does.

After the move the connection is driven through three calls besides the halves' usual status.
`receiveControl` takes a record the kernel opened that is not application data, by its record
type and plaintext, and processes it as `receive` would (alerts, NewSessionTicket, KeyUpdate,
a TLS 1.2 HelloRequest and its refusal). `control` hands out each record the connection sends
(an alert, a KeyUpdate, the close_notify of `finish`) as its record type and plaintext, for the
kernel to seal (TLS_SET_RECORD_TYPE); the write half frames them in its output buffer instead
of sealing them. `offloadRecords` reports the kernel's record count, read from it
(`Socket.records`), at least every `offloadInterval` records: a quarter of the epoch's limit
before it, a TLS 1.3 connection updates its write keys or asks the peer to update its own, and
TLS 1.2, which has no key update, ends the connection. Application data never reaches the
connection, so the run of control records that counts as a flood resets when a report shows
records beyond the control ones.

A key update in a kernel direction turns the epoch here at once, as in software: a KeyUpdate
received, or one sent once `control` has handed it out and it is acknowledged (records queued
behind it wait). The epoch's owner is then `next` (`offloadPending`), and `offload` gives the
kernel the next keys. Linux took TLS 1.3 key updates in 6.14: before it a second install of a
direction is EBUSY (`RekeyUnsupported`). The old keys are gone by then and the peer reads and
writes under the next ones, so the connection ends (NoKeyUpdate; a fatal alert still goes out
when the write keys are untouched) rather than going back to them (design 8.2). Linux stops its
receive path after a handshake record whose first byte is KeyUpdate's type, and only there, so
under a kernel a KeyUpdate must be its record's only message: one later in a record would leave
the kernel opening under dropped keys, and a record that starts with the type without being a
whole KeyUpdate would stop it with nothing to give it. Both end the connection. A record the
kernel opened after a KeyUpdate, before the next keys, is refused.

The Linux backend is `tls.offload.linux`: `Socket.install` attaches the "tls" upper-layer
protocol and installs `CryptoInfo`, the cipher's uAPI struct (the IV's first four bytes are
the salt, its last eight the IV, ChaCha20-Poly1305 taking all twelve); `Socket.records` reads
the record number back (the kernel answers only a buffer of its struct's exact size, keys
included, which are erased); `probe` installs throwaway keys on loopback connections for every
version, cipher and direction, and installs TLS 1.3 again as a key update would, so what a
kernel takes is a probe's verdict, never its version string. The control-message I/O, sendfile
and the wait when the receive path stops for new keys are the caller's (reactor's, in the
family). TLS_TX_ZEROCOPY_RO is never set, so a file sent is sealed as it was when sent; a peer's
record_size_limit is TLS_TX_MAX_PAYLOAD_LEN ("Record size limit"). Tests
play a kernel in software (every OS) and run the real one in Linux VMs on 6.8 and 7.0.

## ML-DSA (C10)

ML-DSA-44, -65 and -87 (FIPS 204) sign certificates and TLS 1.3 CertificateVerify messages:
pure ML-DSA with an empty context, over the TBSCertificate (RFC 9881) or the TLS 1.3 signed
content (draft-ietf-tls-mldsa, schemes 0x0904 to 0x0906). The identifiers are pinned: OIDs
2.16.840.1.101.3.4.3.17 to .19 with absent parameters, public keys and signatures of their
exact lengths, and TLS 1.2 never negotiates them (an ML-DSA credential has no TLS 1.2 suite; a
client that offers both versions lists the ML-DSA schemes for TLS 1.3). A key whose keyUsage
asserts keyEncipherment, dataEncipherment, keyAgreement, encipherOnly or decipherOnly is
refused, as RFC 9881 says of ML-DSA and RFC 8410 of Ed25519.

The implementation is cloak's (`src/crypto/mldsa.zig`), after the review the design asked of
std's: std's arithmetic is branch-free on secrets where it should be, but its key types cache
the whole matrix A, and its key generation with a signature puts 770 KiB of ML-DSA-87 on the
stack in ReleaseFast and its verification 290 KiB, past a 512 KiB thread stack. cloak's expands A one polynomial at a time where
it is used and keeps nothing but the expanded private key: ML-DSA-87 signs in 18 KiB of stack,
verifies in 12 KiB, derives a key in 15 KiB. Secret values (s1, s2, t0, the mask y, w0, the
hints before they are released) are handled branch-free and index-free, the norm checks
included; a rejected candidate's verdict is public, as are A, c and the signature, and ExpandS's
rejection sampling over the seed's SHAKE stream varies as FIPS 204's reference does. Signing is
hedged with 32 fresh bytes (`PrivateKey.noiseLength`). It matches std byte for byte (keys,
deterministic and hedged signatures, each verifying the other's) and passes Wycheproof's
ML-DSA vectors: verification of all three sets with malformed hints, norm violations and wrong
lengths, signing from seeds with their randomness, and expanded keys out of range refused.
Timing evidence on the built binary belongs with C7's.

A private key is read in every RFC 9881 form: the 32-byte seed, the expanded key, or both. A
seed derives the key; both must agree byte for byte; an expanded key alone is checked against
itself (s1 and s2 within eta, t0 the low bits of A s1 + s2, tr the hash of the public key that
results). What is kept is the expanded key and the public key, and `Identity` checks the public
key against the certificate's.

Post-quantum authentication is required explicitly, never implied: `require_pq_auth` on a
client means the server's CertificateVerify is ML-DSA (only those schemes are offered) and every
certificate on its verified path up to the anchor carries an ML-DSA signature (the receipt's
path, portable or native, is checked); on a server it means the same of the client, whose
certificate is then required and verified. A hybrid key exchange does not meet it; a
provisioned PSK, being symmetric, does. The policy is TLS 1.3's, binds the session cache key,
and fails with `PqAuthenticationRequired` (insufficient_security). A client's handshake memory
with an ML-DSA-87 chain (13 KiB of certificates) peaks at 81 KiB (82,752 bytes).

## Certificate authorities (RFC 8446 4.2.4)

A peer may name the anchors it trusts: certificate_authorities, a list of Distinguished Names, in a
ClientHello and a TLS 1.3 CertificateRequest (the handshake's and a post-handshake one), and as a
field of the TLS 1.2 CertificateRequest (RFC 5246 section 7.4.4). Received, the list is decoded
whole (`authorities<3..2^16-1>` of `DistinguishedName<1..2^16-1>`, TLS 1.2's list may be empty,
nothing trailing; decode_error otherwise) and the names are compared as bytes, never parsed.

A credential may require a match instead (`Credential.must_match_issuer`,
`ClientCredential.must_match_issuer`; BoringSSL's must-match-issuer, owner's call 2026-10-22): it
is taken only when the peer named an issuer in its chain, never as the first that fits, so it
serves only the peers that ask for its authority. A server left with no credential for that reason
ends with handshake_failure (`NoMatchingIssuer`); a client passes such a credential over as one the
request does not take (an empty Certificate when none other fits).

Otherwise it is a preference in credential choice, never a refusal (the RFC's SHOULD): a credential chains to
a named authority when a certificate of its chain, the leaf included, has an issuer Name equal to a
named one, as Go's `SupportsCertificate` decides; a raw public key never does. Of the credentials
the peer can take, the first that chains to a name answers, else the first. The server's walk is
the one it always made (the name, the form the client takes, the version's fit: TLS 1.3 schemes or
a usable delegated credential, TLS 1.2 a shared suite, curve and scheme). A client holds its
credentials in a list (`credentials`, at most 32, certificates or raw keys or both, each with its
delegated credential), walked the same way: the type the server selected, then a scheme the request lists or
a usable delegated credential (TLS 1.2: a certificate type it names and a scheme). The request's
names are reduced to a bit per credential when it arrives, so nothing of the list outlives it.
BoringSSL's per-credential `must_match_issuer`, which refuses, is not built. An external signer is
told which credential signs (`SignRequest.credential`).

Sending is the caller's: `certificate_authorities` lists DER Names (borrowed, each checked to be a
Name), at most `max_authorities_bytes` (8 KiB on the wire, about a hundred names; a system store's
~150 anchors are past what a hello should carry). A server names them in every CertificateRequest,
so it needs client authentication or post-handshake authentication on; a client in a hello offering
TLS 1.3, an ECH hello's inner one alone (the names say what the client trusts). None by default.

## Failure catalogue: the test map

The design book's failure catalogue lists each known TLS and X.509 failure class with its
evidence, the guard and the assertion its test must make; the repo carries the tests. Every
catalogue test is named `Fnn catalogue_<name> (what it checks)`, so `-Dtest-filter="Fnn "` runs
one row's guards (the files below are under `src/`). The mutation column records a change to the
guard that its named tests were run against and failed on; a row without one has tests but no
recorded mutation.

What a row cannot assert stays named: the caller cloning its own generator (F01), naming the
logical origin as the reference (F18) and authorizing actions from the receipt (F42) are the
caller's; physical fault injection (F02) is out of scope; the compiler campaign (F03) and
constant-time behaviour (F04) rest on the built binary's evidence (`zig build timing`), not on a
source test; a native platform's own policy (F23) is the operating system's. F42's setter order
is absent by construction: options are one immutable value given at creation. F93 searches the
stack below the caller in every build, but only optimized frames keep a copy long enough for it to
be found, and released memory only in the builds that ship (under runtime safety, `free` writes
over it first): its evidence is the ReleaseFast tier's. What it cannot see is the design's
remainder: live registers, the entry function's own frame, and a QUIC caller's or key-log sink's
copies of what cloak hands them. F40's lock across
a wait: `Connection` holds none, it asks and returns; a `Session` signs on the task that reads
and takes its write lock only to send the answer. Corpus rows (F10–F13, F16, F17, F19, F20, F24)
name the x509-limbo cases they rest on; the batches run the whole corpus. Rows from F96 on are
conformance failures C7's suites (tlsfuzzer, BoGo) found, each with its failing test first.

| Id | Catalogue test | Files | A mutation its named tests catch |
|---|---|---|---|
| F01 | `catalogue_entropy_clone_and_unready_source` | `tls/catalogue_test.zig` | a weak fixed fallback answering a failed draw |
| F02 | `catalogue_private_operation_blinding_and_fault` | `crypto/rsa_test.zig` | the fault check skipped; the seed left out of the blinding draw |
| F03 | `catalogue_compiler_preserves_secret_operations` | `tls/Timing_test.zig` | `receive` run outside data-independent timing |
| F04 | `catalogue_scalar_nonce_length_and_tail_dispatch` | `crypto/p256_test.zig`, `credentials/Sign_test.zig` | a zero window selecting the base multiple instead of the identity |
| F05 | `catalogue_kernel_carries_lengths_and_dispatch` | `crypto/p256/Montgomery_test.zig`, `credentials/Uint_test.zig`, `credentials/curve/Montgomery_test.zig`, `tls/crypto/Ccm_test.zig` | the portable field addition dropping its carry |
| F06 | `catalogue_key_import_failure_and_kdf_budget` | `credentials/Key_test.zig`, `credentials/Parser_test.zig`, `credentials/Pem_test.zig`, `credentials/Base64_test.zig` | the KDF iteration bound removed |
| F07 | `catalogue_der_lengths_children_and_depth` | `wire/Der_test.zig` | a nonminimal long-form length accepted; the hard depth ceiling removed |
| F08 | `catalogue_signature_workspace_and_rsa_size` | `crypto/rsa_test.zig`, `verify/signature_test.zig`, `verify/wycheproof_test.zig` | the RSA signature length check removed |
| F09 | `catalogue_rsa_signature_full_encoding` | `verify/signature_test.zig`, `verify/wycheproof_test.zig` | the DigestInfo compared by its first byte; the PSS trailer unchecked |
| F10 | `catalogue_ca_bit_usage_and_pathlen` | `certificate/Extensions_test.zig`, `verify/limbo_test.zig` | path length unenforced on intermediates; an intermediate without the CA bit accepted |
| F11 | `catalogue_untrusted_self_signed_and_verifier_error` | `Trust_test.zig`, `verify/limbo_test.zig`, `verify/Verification_test.zig` | verification none claiming authentication |
| F12 | `catalogue_alternate_chain_rechecks_constraints` | `verify/limbo_test.zig` | no alternate path tried after a rejected candidate |
| F13 | `catalogue_cross_signed_cycles_and_chain_depth` | `verify/limbo_test.zig` | cycle detection removed; the intermediate count limit removed |
| F14 | `catalogue_verification_flood_charges_every_branch` | `verify/constraints_test.zig`, `verify/Verifier_test.zig` |  |
| F15 | `catalogue_constraints_across_all_cas` | `verify/constraints_test.zig` |  |
| F16 | `catalogue_wildcard_constraint_intersection_and_case` | `verify/constraints_test.zig`, `verify/limbo_test.zig` | a wildcard matching across labels |
| F17 | `catalogue_nul_san_and_no_cn_fallback` | `certificate/Name_test.zig`, `verify/limbo_test.zig` | any byte allowed in a DNS label |
| F18 | `catalogue_reference_identity_required_and_separate` | `tls/Connection_test.zig` | full verification allowed without a reference identity |
| F19 | `catalogue_general_name_syntax_and_constraint_forms` | `certificate/Extensions_test.zig`, `verify/constraints_test.zig`, `verify/limbo_test.zig` | IP constraints ignoring their mask |
| F20 | `catalogue_crldp_generalname_and_expansion_budget` | `certificate/Extensions_test.zig`, `verify/limbo_test.zig` | an unknown critical CRL extension accepted; critical distribution points accepted |
| F21 | `catalogue_policy_leaf_mapping_and_enablement` | `verify/policy_test.zig` |  |
| F22 | `catalogue_revocation_matching_entry_and_responder` | `verify/revocation_test.zig` |  |
| F23 | `catalogue_native_receipt_path_token_and_clock` | `NativeVerification_test.zig`, `verify/Verifier_test.zig`, `services/windows_test.zig` | expiry not rechecked at completion; a backwards clock accepted |
| F24 | `catalogue_algorithm_identifier_and_empty_point` | `certificate/Algorithm_test.zig`, `verify/limbo_test.zig` | inner and outer algorithms not compared; Ed25519 parameters accepted |
| F25 | `catalogue_trust_snapshot_extension_race_and_time` | `Trust_test.zig` |  |
| F26 | `catalogue_verify_job_cancel_alloc_and_late_result` | `NativeVerification_test.zig`, `services/Job_test.zig` | a released job returning its charge before it is reaped |
| F27 | `catalogue_heartbeat_and_nested_length_overread` | `tls/catalogue_test.zig`, `tls/wire/Extensions_test.zig` |  |
| F28 | `catalogue_possession_verification_cannot_be_skipped` | `tls/ServerConnection_test.zig`, `tls/Connection_test.zig`, `tls/handshake/State_test.zig` |  |
| F29 | `catalogue_smack_authentication_skip_edges` | `tls/Connection_test.zig`, `tls/handshake/State_test.zig` |  |
| F30 | `catalogue_key_change_record_alignment` | `tls/ServerConnection_test.zig`, `tls/Connection_test.zig`, `tls/handshake/State_test.zig` |  |
| F31 | `catalogue_hrr_illegal_group_ch2_and_reallocation` | `tls/ServerConnection_test.zig`, `tls/Connection_test.zig`, `tls/handshake/Transcript_test.zig`, `tls/handshake/Hello_test.zig` |  |
| F32 | `catalogue_extension_uniqueness_and_negotiation_allowlist` | `tls/ServerConnection_test.zig`, `tls/Connection_test.zig`, `tls/CodePoints_test.zig`, `tls/dtls/Cookies_test.zig`, `tls/wire/Extensions_test.zig` |  |
| F33 | `catalogue_ecdh_invalid_curve_and_noncontributory_share` | `tls/Connection_test.zig` |  |
| F34 | `catalogue_nonce_uniqueness_partial_retry_and_wrap` | `tls/Connection_test.zig`, `tls/record/Epoch_test.zig` |  |
| F35 | `catalogue_record_outer_type_and_wire_aad` | `tls/Connection_test.zig`, `tls/record/Epoch_test.zig` |  |
| F36 | `catalogue_bad_tag_no_plaintext_or_alias_damage` | `tls/record/Epoch_test.zig` |  |
| F37 | `catalogue_keyupdate_flood_and_step_budget` | `tls/Connection_test.zig` |  |
| F38 | `catalogue_eof_at_every_record_and_application_boundary` | `tls/Connection_test.zig` |  |
| F39 | `catalogue_clienthello_close_notify_no_spin` | `tls/Connection_test.zig` |  |
| F40 | `catalogue_partial_output_identity_swap_and_late_sign` | `tls/Connection_test.zig` | a stale token answering the request; the caller's client identity borrowed, not retained |
| F41 | `catalogue_alpaca_protocol_and_port_binding` | `tls/Connection_test.zig`, `tls/handshake/Hello_test.zig` |  |
| F42 | `catalogue_mtls_builder_order_and_optional_usage` | `tls/catalogue_test.zig` | a leaf's extended key usage unchecked |
| F43 | `catalogue_hybrid_share_order_and_implicit_rejection` | `tls/Connection_test.zig`, `tls/crypto/Exchange_test.zig` | require_hybrid unchecked at the client; the X25519 secret placed before ML-KEM's |
| F44 | `catalogue_quic_levels_hrr_parameters_and_secret_authority` | `tls/quic/Handshake_test.zig` |  |
| F45 | `catalogue_finished_entropy_failure_is_never_success` | `tls/Connection_test.zig`, `tls/crypto/Labels_test.zig` |  |
| F46 | `catalogue_ccs_injection_all_reachable_states` | `tls/Tls12_test.zig` |  |
| F47 | `catalogue_freak_export_rsa_and_unoffered_exchange` | `tls/catalogue12_test.zig` |  |
| F48 | `catalogue_logjam_export_and_weak_dh` | `tls/catalogue12_test.zig` |  |
| F49 | `catalogue_raccoon_secret_encoding_and_ephemeral_reuse` | `tls/catalogue12_test.zig` |  |
| F50 | `catalogue_poodle_ssl3_and_cbc_fallback` | `tls/catalogue12_test.zig` |  |
| F51 | `catalogue_beast_chained_iv_profile_refused` | `tls/catalogue12_test.zig` |  |
| F52 | `catalogue_cbc_oracle_absence_and_aead_failure_work` | `tls/catalogue12_test.zig` |  |
| F53 | `catalogue_robot_rsa_kex_and_rsa_psk_refused` | `tls/catalogue12_test.zig` |  |
| F54 | `catalogue_drown_ssl2_and_shared_service_boundary` | `tls/catalogue12_test.zig` |  |
| F55 | `catalogue_sweet32_suite_and_usage_limits` | `tls/catalogue12_test.zig` |  |
| F56 | `catalogue_null_rc4_and_obsolete_hash_policy` | `tls/catalogue12_test.zig` |  |
| F57 | `catalogue_renegotiation_prefix_and_initial_signal` | `tls/catalogue12_test.zig` |  |
| F58 | `catalogue_triple_handshake_ems_and_exporter_context` | `tls/catalogue12_test.zig` |  |
| F59 | `catalogue_version_rollback_sentinel_and_scsv` | `tls/catalogue12_test.zig` |  |
| F60 | `catalogue_sloth_signature_hash_and_context_downgrade` | `tls/catalogue12_test.zig` |  |
| F61 | `catalogue_kci_static_dh_and_role_reflection` | `tls/catalogue12_test.zig` |  |
| F62 | `catalogue_crime_record_compression_refused` | `tls/catalogue12_test.zig` |  |
| F63 | `catalogue_breach_consumer_compression_policy` | `tls/catalogue12_test.zig` |  |
| F64 | `catalogue_starttls_strip_and_plaintext_fallback` | `tls/catalogue12_test.zig` |  |
| F65 | `catalogue_ticket_supplied_key_and_derivation_failure` | `tls/Resumption_test.zig` |  |
| F66 | `catalogue_ticket_workers_rotation_restart_and_nonce` | `tls/Resumption_test.zig` |  |
| F67 | `catalogue_ticket_age_add_and_identifier_privacy` | `tls/Resumption_test.zig` |  |
| F68 | `catalogue_psk_binder_lengths_index_and_retry` | `tls/Resumption_test.zig`, `tls/handshake/Hello_test.zig` |  |
| F69 | `catalogue_resume_after_cloned_policy_mutation` | `tls/Resumption_test.zig` |  |
| F70 | `catalogue_tls13_ticket_hrr_missing_versions` | `tls/Resumption_test.zig` |  |
| F71 | `catalogue_early_data_replay_rejection_budget` | `tls/Resumption_test.zig` |  |
| F72 | `catalogue_ticket_ems_derivation_and_callback_errors` | `tls/Resumption_test.zig` |  |
| F73 | `catalogue_session_serialization_tamper_and_reset` | `tls/Resumption_test.zig` |  |
| F74 | `catalogue_resumed_mtls_evidence_expiry_and_refresh` | `tls/Resumption_test.zig` |  |
| F75 | `catalogue_ech_rejection_no_target_authority` | `tls/Ech_test.zig` |  |
| F76 | `catalogue_ech_outer_psk_identity_and_guess_oracle` | `tls/Ech_test.zig` |  |
| F77 | `catalogue_dtls_fragment_arithmetic_and_conflicting_total` | `tls/dtls/catalogue_test.zig` |  |
| F78 | `catalogue_dtls_duplicate_replay_and_message_order` | `tls/dtls/catalogue_test.zig` |  |
| F79 | `catalogue_dtls_timer_during_suspended_flight` | `tls/dtls/catalogue_test.zig` |  |
| F80 | `catalogue_dtls_client_random_cookie_and_amplification` | `tls/dtls/Cookies_test.zig`, `tls/dtls/catalogue_test.zig` |  |
| F81 | `catalogue_dtls_short_aead_ccm_tag_and_survival` | `tls/dtls/Record_test.zig`, `tls/dtls/catalogue_test.zig` |  |
| F82 | `catalogue_dtls_corruption_renegotiation_and_reset` | `tls/dtls/catalogue_test.zig` |  |
| F83 | `catalogue_ktls_partial_handoff_sequence_owner` | `tls/offload/Offload_test.zig` |  |
| F84 | `catalogue_ktls_rekey_failure_and_sendfile_immutability` | `tls/offload/Offload_test.zig` |  |
| F85 | `catalogue_selfie_psk_role_reflection_and_context` | `tls/Psk_test.zig` |  |
| F86 | `catalogue_external_psk_embedded_nul_identity` | `tls/Psk_test.zig` |  |
| F87 | `catalogue_certificate_compression_bomb_and_transcript` | `tls/CertificateCompression_test.zig`, `tls/handshake/Compression_test.zig` |  |
| F88 | `catalogue_ct_sct_lengths_wrong_entry_and_log_generation` | `verify/transparency_test.zig`, `tls/Transparency_test.zig` |  |
| F89 | `catalogue_delegated_parent_expiry_and_raw_key_namespace` | `tls/handshake/Delegation_test.zig`, `tls/RawKey_test.zig`, `tls/Delegated_test.zig` |  |
| F90 | `catalogue_post_handshake_auth_context_and_action_gate` | `tls/PostAuth_test.zig` |  |
| F91 | `catalogue_pq_group_specific_layout_and_auth_policy` | `tls/Pq_test.zig`, `tls/crypto/Exchange_test.zig`, `tls/MlDsa_test.zig` |  |
| F92 | `catalogue_quic_transport_admission_boundary` | `tls/quic/Admission_test.zig` | the header limit, the straddle check, or either end's transport-parameter gate removed |
| F93 | `catalogue_secret_diagnostics_and_release_campaign` | `tls/Secrets_test.zig`, `tls/crypto/Kernels.zig`, `tls/crypto/Labels.zig`, `tls/crypto/Prf.zig`, `tls/resumption/Ticket.zig`, `tls/dtls/Cookies.zig` | each in ReleaseFast: a DTLS epoch built on the stack and copied into its slot, a handshake secret passed by value, stream protection built on the stack, record sealing or HKDF unscrubbed (found by the campaign: DTLS 1.3 epochs and the handshake's outputs were passed by value, and a verifier's copy of a parsed certificate carried that stack into the heap) |
| F94 | `catalogue_roca_fingerprinted_rsa_key_refused` | `Roca_test.zig` |  |
| F95 | `catalogue_psk12_identity_probe_and_offline_guess` | `tls/Psk12_test.zig` |  |
| F96 | `catalogue_legacy_record_version_ignored` | `tls/ServerConnection_test.zig` | plaintext records held to 03,01-03,03 (found by tlsfuzzer: its hellos come as 03,00) |
| F97 | `catalogue_authenticated_inner_content_unexpected` | `tls/ServerConnection_test.zig`, `tls/record/Epoch_test.zig` | the authenticated refusals answered as a tag failure (bad_record_mac), as before (found by tlsfuzzer's test-tls13-empty-alert) |
| F98 | `catalogue_obsolete_legacy_hello_version` | `tls/ServerConnection_test.zig` | the check left out: TLS 1.3 negotiated over a hello naming 03,00 (found by tlsfuzzer's test-tls13-legacy-version) |
| F99 | `catalogue_groups_without_key_share` | `tls/ServerConnection_test.zig` | the check left out: a retry request answered a hello with no key_share (found by tlsfuzzer's test-tls13-keyshare-omitted) |
| F100 | `catalogue_no_record_between_handshake_fragments` | `tls/ServerConnection_test.zig` | the check left out: data between a KeyUpdate's fragments read (found by tlsfuzzer's test-tls13-keyupdate) |
| F101 | `catalogue_extension_count_unbounded_unique` | `wire/Extensions_test.zig`, `tls/handshake/ClientHello_test.zig`, `tls/ServerConnection_test.zig` | the whole-block check skipped; its passes keyed by 13 bits (found by tlsfuzzer's test-tls13-large-number-of-extensions: hellos past 64 extensions were refused) |
| F102 | `catalogue_inner_plaintext_overflow` | `tls/ServerConnection_test.zig` | the overflow answered as a tag failure (bad_record_mac), as before (found by tlsfuzzer's test-tls13-record-layer-limits) |
| F103 | `catalogue_plaintext_alert_answering_server_hello` | `tls/ServerConnection_test.zig` | the check left out: the client's plaintext alert refused as an unexpected record (found by tlsfuzzer's test-tls13-unencrypted-alert) |
| F104 | `catalogue_retry_hello_extension_order` | `tls/handshake/ClientHello_test.zig`, `tls/ServerConnection_test.zig` | the fingerprint taking the extensions in the order sent, as 0.17.3 to 0.17.5 did (tlsfuzzer's test-tls13-shuffled-extentions asks a reordered second hello refused; RFC 8446 4.1.2 binds the client, so cloak compares content: main's call 2026-10-18) |
| F105 | `catalogue_ccs_without_compatibility_mode` | `tls/ServerConnection_test.zig`, `tls/Connection_test.zig` | the change_cipher_spec held to a hello with a session id, and its record version to 03,03 after the keys, as before (found by tlsfuzzer's test-tls13-multiple-ccs-messages) |
| F106 | `catalogue_psk_hello_without_signature_algorithms` | `tls/Psk_test.zig` | signature_algorithms required of every TLS 1.3 hello, as before (found by tlsfuzzer's test-tls13-psk_dhe_ke) |
| F107 | `catalogue_key_share_count_unbounded_unique` | `tls/handshake/ClientHello_test.zig` | the 32-share table, as before (found by tlsfuzzer's test-tls13-unrecognised-groups) |
| F108 | `catalogue_credential_by_client_capability` | `tls/ServerConnection_test.zig`, `tls/Tls12_test.zig`, `tls/MlDsa_test.zig` | the name boundary dropped; the first unfit candidate's refusal returned; the suite or curve check of TLS 1.2 loosened (found by tlsfuzzer's test-tls13-ecdsa-support and C4's review: a server chose by name alone) |
| F109 | `catalogue_hello_decoded_before_judged` | `tls/handshake/ClientHello_test.zig` | the null-method check before the extensions' framing, or an empty compression list taken (found by tlsfuzzer's test-invalid-client-hello-w-record-overflow) |
| F110 | `catalogue_oversized_handshake_message_decode_error` | `tls/ServerConnection_test.zig` | HandshakeLimit answered with internal_error, as before (found by tlsfuzzer's test-truncating-of-client-hello) |
| F111 | `catalogue_hello_version_tolerance` | `tls/handshake/ClientHello_test.zig` | the 0xfe00 cutoff on a stream's legacy_version, as before (found by tlsfuzzer's test-version-numbers) |
| F112 | `catalogue_server_name_ranges_decode_error` | `tls/handshake/ClientHello_test.zig` | the empty list or name answered illegal_parameter, as before (found by tlsfuzzer's test-invalid-server-name-extension) |
| F113 | `catalogue_fallback_scsv_before_version` | `tls/catalogue12_test.zig` | the version refusal before the fallback check, as before (found by tlsfuzzer's test-fallback-scsv) |
| F114 | `catalogue_server_without_renegotiation_indication` | `tls/catalogue12_test.zig` | the indication answered whether or not the client sent it (a policy change, main's call 2026-10-18: a server that never renegotiates refused hellos without it; tlsfuzzer's test-aesccm, test-cve-2016-6309, test-cve-2016-7054, test-ssl-death-alert and wolfSSL's default build send none) |
| F115 | `catalogue_dtls_retry_reordered_hello` | `tls/dtls/catalogue_test.zig` | the fingerprint taking the extensions in the order sent, as 0.17.3 to 0.17.5 did (found by wolfSSL 5.9.4's DTLS 1.3 client, refused after every retry request) |
| F116 | `catalogue_compat_ccs_before_first_protected_record` | `tls/Connection_test.zig` | the change_cipher_spec sent only before the second flight, as before (found by BoGo: an alert refusing the server's flight came encrypted with none before it) |
| F117 | `catalogue_no_server_name_ack_on_resumption` | `tls/Resumption_test.zig` | server_name acknowledged on a resumed handshake, as before (found by BoGo; RFC 6066 section 3) |
| F118 | `catalogue_tls12_only_hello_offers_classical_groups` | `tls/handshake/Hello_test.zig` | every configured group listed whatever the versions, as before (found by BoGo's TLS12ClientShouldNotOffer rows) |
| F119 | `catalogue_declined_early_record_shorter_than_tag` | `tls/Resumption_test.zig` | the header's length check before the skip, as before (found by BoGo's SkipEarlyData-TLS13: four-byte fake early data refused with bad_record_mac) |
| F120 | `catalogue_unsolicited_extension_unsupported` | `tls/handshake/Hello_test.zig` | unsolicited answers mapped to illegal_parameter, as before (found by BoGo's UnofferedExtension, UnknownExtension and UnsolicitedServerNameAck rows) |
| F121 | `catalogue_field_out_of_range_decode_error` | `tls/handshake/Hello_test.zig`, `tls/handshake/Messages_test.zig` | the session id echo, empty ticket and server_name data answered illegal_parameter, as before (found by BoGo) |
| F122 | `catalogue_second_retry_unexpected_first` | `tls/Connection_test.zig` | the retry's contents judged before its being a second one, as before (found by BoGo's SecondHelloRetryRequest-TLS13) |
| F123 | `catalogue_protected_record_before_read_keys_unexpected` | `tls/Resumption_test.zig` | the short-record check answering bad_record_mac before any read key, as before (found by BoGo's SkipEarlyData-OmitEarlyDataExtension-HelloRetryRequest-TLS13) |
| F124 | `catalogue_empty_exporter_label` | `tls/crypto/Labels_test.zig`, `tls/crypto/Prf_test.zig` | the empty label refused in HKDF-Expand-Label and the TLS 1.2 exporter, as before (found re-auditing BoGo's disablings: RFC 8446 7.5 takes the label format from RFC 5705 4, which sets no minimum) |
| F125 | `catalogue_tls12_server_groups_ignored` | `tls/handshake/Hello_test.zig` | supported_groups in any ServerHello illegal_parameter, as before (found re-auditing BoGo's SupportedCurves-ServerHello-TLS12: no TLS 1.2 text forbids it) |
| F126 | `catalogue_update_requests_one_answer` | `tls/Connection_test.zig` | the answer owed at once, as before (found re-auditing BoGo's KeyUpdate-Requested: RFC 8446 4.6.3, requests while silent get a single update) |
| F127 | `catalogue_quic_parameters_off_quic_unsupported` | `tls/handshake/ClientHello_test.zig`, `tls/handshake/Hello_test.zig` | the parameters taken by a stream server and answered illegal_parameter by a stream client, as before (RFC 9001 8.2) |
| F128 | `catalogue_tls12_hello_no_session_id_unresumed` | `tls/Tls12_test.zig` | the compatibility session id in every stream hello, as before (found by BoGo's TLS12NoSessionID-TLS13; RFC 5246 7.4.1.2) |
| F129 | `catalogue_alert_any_level_error_alert` | `tls/Connection_test.zig` | a level outside warning and fatal answered unexpected_message, as before (found by BoGo's SendBogusAlertType; RFC 8446 6.2) |
| F130 | `catalogue_client_hello_ends_its_record` | `tls/Tls12_test.zig` | the received ClientHello's edges without the record boundary, as before (found by BoGo's Partial*WithClientHello rows; RFC 8446 5.1) |
| F131 | `catalogue_key_shares_in_group_order` | `tls/Pq_test.zig` | the two initial shares in a fixed order, as before (found by BoGo's MLKEMKeyShareIncluded*-X25519MLKEM768; RFC 8446 4.2.8) |
| F132 | `catalogue_early_data_between_hello_fragments_unexpected` | `tls/Resumption_test.zig` | declined early data skipped inside the second hello, as before (found by BoGo's SkipEarlyData-HRR-Interleaved-TLS13; RFC 8446 5.1) |
| F133 | `catalogue_warning_flood_refused_here` | `tls/Connection_test.zig` | the fifth warning reported as the peer's alert and closed unanswered, as before (found by BoGo's SendWarningAlerts-TooMany rows under strict errors) |
| F134 | `catalogue_empty_alpn_selection_decode_error` | `tls/handshake/Hello_test.zig` | an empty selected name answered illegal_parameter, as before (found by BoGo's ALPNClient-EmptyProtocolName-*; RFC 7301 3.1) |
| F135 | `catalogue_empty_retry_cookie_decode_error` | `tls/handshake/Hello_test.zig` | an empty cookie answered illegal_parameter, as before (found by BoGo's HelloRetryRequest-EmptyCookie-TLS13; RFC 8446 4.2.2) |
| F136 | `catalogue_server_hello_without_key_share_missing_extension` | `tls/handshake/Hello_test.zig` | a ServerHello without key_share answered illegal_parameter, as before (found by BoGo's MissingKeyShare-Client-TLS13 and NegotiatePSKResumption-TLS13; RFC 8446 6.2) |
| F137 | `catalogue_empty_plaintext_record_unexpected` | `tls/Connection_test.zig` | an empty plaintext record answered record_overflow, as before (found by BoGo's V2ClientHello-EmptyRecordPrefix under strict errors; RFC 8446 5, 5.1) |
| F138 | `catalogue_certificate_authorities_decoded` | `tls/handshake/ClientHello_test.zig`, `tls/handshake/Messages_test.zig` | the empty-list check removed from `Authorities.parse`; before, the extension went unread in both messages (found by BoGo's RejectEmptyCertificateAuthorities and ExtensionTrailingData-CertificateAuthorities rows; RFC 8446 4.2.4) |
| F139 | `catalogue_server_credential_by_named_authority` | `tls/CertificateAuthorities_test.zig` | the preference taken as true in `Server.chooseCredential`, and the issuer comparison in `Authorities.chains`; before, the client's names were not read (RFC 8446 4.2.4, main's call 2026-10-20) |
| F140 | `catalogue_client_credential_by_named_authority` | `tls/CertificateAuthorities_test.zig` | the preference taken as true in each client walk (TLS 1.3, TLS 1.2, post-handshake); before, a client held one credential and read no names (RFC 8446 4.2.4, RFC 5246 7.4.4) |
| F141 | `catalogue_pin_without_authorities` | `tls/LeafKey_test.zig` | the pin check made to pass in each role's leaf-key branch (TLS 1.3 and 1.2 client and server), the cache key's mode label, and the empty-pins refusal; before, a pin was checked only beside full verification, so a caller verifying no chain could not hold a pinned key (main's call 2026-10-21, designs/cloak.md §5.2) |
| F142 | `catalogue_tls12_ecdsa_scheme_names_hash_not_curve` | `tls/handshake/Possession_test.zig`, `credentials/Key_test.zig` | the signer bound back to each curve's own hash, and the client's TLS 1.2 chooser to its curve's scheme; before, a TLS 1.2 server took a P-384 key for a client listing only ecdsa_secp256r1_sha256 and failed to sign (internal_error), and the client never offered the pairing (BoGo's CertificateSelection-*-SignatureAlgorithmECDSACurve-TLS-TLS12) |
| F143 | `catalogue_resumed_server_certificate_type` | `tls/RawKey_test.zig`, `tls/resumption/Ticket_test.zig` | each resumption's answer (TLS 1.3 EncryptedExtensions, TLS 1.2 ServerHello) and each server's type check on a ticket removed; before, a resumed handshake answered server_certificate_type with nothing, which a client offering raw keys alone reads as X.509 and refuses (BoGo's ServerCertificateType-Server-*) |
| F144 | `catalogue_dtls13_application_data_under_handshake_keys` | `tls/dtls/Datagram_test.zig` | the epoch check on application records removed; before, application data under the DTLS 1.3 handshake keys reached the application once the handshake completed (BoGo's AppDataBeforeTLS13KeyChange-DTLS; RFC 9147 section 6.1) |
| F145 | `catalogue_dtls_hello_version_tolerance` | `tls/handshake/ClientHello_test.zig` | the 0xfe00 floor on a datagram's legacy_version, as before (BoGo's MajorVersionTolerance-DTLS; 0xfdff is above DTLS 1.2) |
| F146 | `catalogue_dtls_record_without_content_type` | `tls/dtls/Datagram_test.zig` | an authenticated record naming no content type dropped, as before, where RFC 8446 section 5.4 asks unexpected_message (BoGo's TLS13-OnlyPadding-DTLS) |
| F147 | `catalogue_empty_hello_verify_cookie` | `tls/handshake/Datagram_test.zig` | the refusal of an empty HelloVerifyRequest cookie, as before (BoGo's DTLS-HelloVerifyRequest-0; RFC 6347 section 4.2.1's opaque cookie<0..2^8-1>) |
| F148 | `catalogue_dtls_plaintext_held_past_the_keys` | `tls/dtls/Datagram_test.zig` | the drop of a plaintext message held until after the keys or due after the peer's ChangeCipherSpec, each half alone; before, one forged datagram buffered ahead of its turn ended the handshake at delivery (found by BoGo's KeyChangeWithBufferedMessages-DTLS) |
| F149 | `catalogue_dtls13_handshake_alert_epoch` | `tls/dtls/Datagram_test.zig` | the handshake epoch for a fatal alert before this end's Finished went out, and the mark that it went; before, a client failing on the server's flight sent its alert under application keys the server could not read (BoGo's DTLS13-SendExtraFinished-Packed) |
| F150 | `catalogue_dtls13_message_after_key_update` | `tls/dtls/Datagram_test.zig` | the epoch floor a peer's KeyUpdate sets removed; before, a handshake message after a KeyUpdate under the retired epoch was taken (BoGo's KeyUpdate-ExtraMessage-DTLS and -Buffered; RFC 8446 section 5.1) |
| F151 | `catalogue_dtls13_ack_skips_dropped_fragments` | `tls/dtls/Datagram_test.zig` | ACKing a record with a fragment dropped, and clearing the list after each ACK; before, a record was ACKed when any of its fragments was new, against RFC 9147 section 7's MUST (BoGo's DTLS-Retransmit-Server-DoNotACKDiscardedFragments) |
| F152 | `catalogue_verified_leaf_must_allow_signing` | `tls/catalogue_test.zig`, `tls/PostAuth_test.zig` | the engine's Key Usage check removed at the client, the server and post-handshake authentication, each alone; before, a caller's verifier that did not look at key usage let a leaf whose key may not sign prove possession (BoGo's ECDSAKeyUsage-Server, RSAKeyUsage-Server-WantSignature-GotEncipherment; RFC 8446 4.4.2.2) |
| F153 | `catalogue_revocation_verdict_surfaces` | `verify/Verifier_test.zig`, `tls/Session_test.zig` | the verifier's record of a revocation refusal removed, and the Revoked and status mappings, each alone; before, a path refused by its revocation evidence reported NoTrustedPath, so a revoked certificate went out as unknown_ca (found by the OCSP stapling interop rows) |
| F154 | `catalogue_ech_rejection_answers_a_certificate_request` | `tls/Ech_test.zig` | the rejected client's flight (empty Certificate, Finished) before its ech_required; before, the client ended at the server's Finished with no flight, so a server asking for a certificate never got the empty Certificate RFC 9849 6.1.7 requires (BoGo's ECH-Client-Reject-NoClientCertificate) |
| F155 | `catalogue_ct_sct_list_framing_checked_on_receipt` | `tls/Transparency_test.zig` | `Messages.sctList` at the TLS 1.3 leaf entry and the TLS 1.2 ServerHello; before, an empty SignedCertificateTimestampList, an empty SCT or a list that did not frame reached the verifier, which a policy then judged as missing SCTs, where RFC 6962 3.3's syntax makes it malformed (decode_error; BoGo's SignedCertificateTimestampListEmpty and EmptySCT) |
| F156 | `catalogue_extensions_on_intermediates_ignored` | `tls/Transparency_test.zig` | a solicited status or SCT list on an intermediate's CertificateEntry ignored, a delegated credential there still refused; before, both were illegal_parameter, though RFC 8446 4.4.2 and 4.4.2.1 let each certificate's entry carry its own (BoGo's IgnoreExtensionsOnIntermediates) |
| F160 | `catalogue_dtls_authenticated_fragment_refused` | `tls/dtls/Datagram_test.zig` | the refusal of each unfit fragment under keys alone (cut short, past its record, past its message, past the limit), DTLS 1.3 and 1.2; before, each was dropped as a forged plaintext one is, and the handshake waited out its timer (BoGo's LargeMessage-Reject-DTLS) |
| F161 | `catalogue_dtls13_message_seq_never_wraps` | `tls/dtls/Datagram_test.zig` | the receive and send counters' wrap, each alone; before, both wrapped at 2^16, so message 0 after 0xffff was taken as the next message and a 65,537th message went out as message 0 (BoGo's KeyUpdate-ReadMessageOverflow-DTLS and -WriteMessageOverflow-DTLS) |
