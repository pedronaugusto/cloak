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
native completion payloads each have one owner behind one `services.Guarded`
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
and DER buffers clear before release; Safe allocator poisoning makes raw-free
observation a poison observation rather than a direct zero observation.

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
allocator tests inspect only before raw free, with Safe poison observations
labeled. Never inspect freed storage or an undefined typed value. These checks
and optimized caller inspection establish the named wipes, not universal
secret-copy erasure: Zig provides no control over compiler-created registers,
spills, by-value argument/result copies or callee-private temporaries. There
is no claim that arbitrary registers or all stack copies are erased. Wasm
inspection cannot establish a downstream JIT's spill behavior.

## Build and verification decisions

The shipped module uses only std. Repository-only tooling is lazy, named test
roots and exact package paths are explicit. CI is generated by the single
canonical preflight planner. Hosted targets compile the complete tests and
measurement programs with the native SDK/linking contract. Freestanding checks
compile the caller-service core and execute its vectors in the Wasm runner;
hosted I/O/thread tests and benchmarks are not freestanding runtime claims.
Benchmarks use `Config.bench` and the test-only measurement helper, retaining
receipt/key/armor correctness checks and source metadata. Outlined constraints
and policy calls reduced the older harness regression; the canonical harness
is approximately neutral. Both measurements remain in the ledger.

## Local safety forms

Unshipped aegis APIs are not imported. Later adoption sites are
`credentials/Secret.zig` for retained material and local `secureZero` scratch
owners (including `Base64.decode`); `services/Guarded.zig` for Job completion and
Budget counts; Trust/PrivateKey/Identity/ClientAuth/Job retained handles;
OwnedRequest/Path/Verification move contracts; and `verify/Work.zig` for bounded
work arithmetic. These are explicit borrow/move contracts, not linear types or
stale-handle detection. Future phases require their own authorization and gates.
