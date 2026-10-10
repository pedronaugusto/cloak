# Credentials and certificate verification

Cloak constructs and retains credentials and verifies certificate paths.
It does not provide a TLS connection or encrypted stream.

## Layers and owners

Public owners live at the package root. `PrivateKey` retains immutable key
material, `Identity` owns public certificate encodings and a retained matched
key, and `ClientAuth` retains that identity. Final private-key release wipes its
owned material. Import preparation validates components and ranges; it is not a
private signing implementation. Entropy and passphrase inputs are borrowed only
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
and optimized caller inspection establish the named wipes, not universal
secret-copy erasure: Zig provides no control over compiler-created registers,
spills, by-value argument/result copies or callee-private temporaries. There
is no claim that arbitrary registers or all stack copies are erased. Wasm
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
retain their existing wire encoding. Identity expiry is a real-clock seconds
Instant; certificate encodings and native scalar calls use explicit raw values.
Service admission keeps jobs and Bytes counts under one spin guard; observational
counts are raw scalar snapshots. Checked integers cover DER numeric decoding,
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
directly, and the certificates link the native trust store (Security and
CoreFoundation on macOS, crypt32 on Windows), so every TLS user links it already,
and both parts have the same package dependencies (aegis). Zig's lazy analysis
leaves out what a program does not use. The layering inside the module is
enforced by the layer check at file level: the TLS layers import the certificates
facade downward and nothing in the certificates imports TLS. The portable probes are a private
module of their own, since they reach files the public surface does not.
DTLS is reserved for a datagram concern at C8 with no claim of datagram support;
it will be a namespace unless it brings a dependency others should not fetch. The private TLS handshake imports crypto and wire;
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
an explicit always-checked table with proof and epoch requirements. Resumed,
TLS 1.2, ECH and DTLS branches are absent until their phases. The table alone is
not a certificate/signature verifier: its internal proof arguments must be
issued by the crypto/verification driver. Named tests cover individual catalogue
components; the complete F27–F45 rows remain open until integration and campaigns.

Published aegis constant-time choices currently require baseline hosted LLVM
profiles. They cannot serve native CPU dispatch or freestanding/wasm TLS yet.
Finished uses std's fixed-size timing-safe comparison, with only the completed
verdict released. AEAD selects std's kernels and rejects `.none` mitigations
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
direction. `handshake` holds the message parsers, the checked state table, the
transcript, the schedule and `Client`, which consumes whole handshake messages and
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
secret is the ML-KEM secret then the X25519 secret. P-256/P-384 agreement runs the
masked fixed-window walk (`Ecdh`), which reuses credential construction's arithmetic
with a table built from the public peer point; std's multiplication of a secret
scalar is not used. X25519 and ML-KEM come from std, with implicit rejection for
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
buffer: about 37 KiB at the peak for the default offer. When the connection is
established the scratch block and flight are freed; `trim` returns the record,
message and output buffers when nothing is pending, and `Session` calls it before it
waits to read. What remains for an idle connection is the struct (576 bytes) and one
heap block of 928 bytes, 1,504 bytes in total. These are heap figures from
a counting allocator; stack use is not measured here.

`Session` drives a `Connection` over `std.Io` readers and writers. It answers
requests with the system's secure randomness and calendar clock (or a fixed time),
the portable verifier over a trust snapshot (or a caller's verifier), and, for
a key cloak does not hold, a caller's signer. It is used from one task at a time. A transport end without close_notify is
a truncation unless the caller chose `.allow` for protocols whose framing detects it.
Per-call deadlines are the transport's own; the session adds none.

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
ECDSA on P-256 and P-384, and Ed25519. The secret multiplication is the masked
fixed-window walk that builds public keys, the scalar arithmetic is std's constant-time
field, and every temporary is erased. ECDSA nonces are hedged: derived from the key,
the message hash and fresh noise, so a weak or repeated draw alone cannot repeat a
nonce and one faulted signature does not give the key away. The noise is part of the
entropy request the handshake already makes (the server's random and key exchange, the
client's hello), 32 bytes for P-256 and 48 for P-384, so no signature waits on a second
round trip to the driver. Ed25519 follows RFC 8032 and draws none. A signature is not
verified after it is made: the key was matched to the leaf when the identity was built,
and the cost of a verification (about as much as the signature) buys protection only
against a fault in the signer.

An identity made with `initExternal` holds no key, and an RSA key is parsed but not
signed with until RSA-PSS lands. For these the server asks its driver to sign through
a `sign` request, then checks the answer against the leaf's public key before it can
reach the wire, so a faulty signer cannot put a bad CertificateVerify on the wire. A
signer that fails ends the connection with internal_error.

A server connection holds no handshake scratch until a peer sends a ClientHello that
the state table accepts: a connection created and never spoken to, or one fed a few
bytes, costs its state and credential table (896 bytes), not the scratch (3.7 KB
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
cannot change its offer between the hellos. The server never accepts a PSK or early
data: it answers every hello with a full handshake, and it does not skip early-data records
a client sends anyway.

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
about 15 KiB at the handshake peak and 891 bytes of heap beside the 584-byte struct
once established (counting allocator, ReleaseSafe test), no tickets are sent, and key
updates behave as in the client. The server's CPU rows are in
`bench/handshake.zig`; they include harness signing with std's ECDSA.

Test support lives in `src/testing`: a scripted server peer that speaks real records
or per-level QUIC messages and a scripted client peer (with a hostile ClientHello and
client flight in named ways), both able to misbehave on purpose, and drivers that run a
client or a server against them in memory, or the two QUIC roles against each other. The peer reuses cloak's HKDF, schedule and record
protection, which the RFC 8448 vectors pin; its parsing, message assembly and
signatures are its own. The test PKI is disposable material generated once with
OpenSSL, recorded in `src/testing/pki/provenance.md`.
