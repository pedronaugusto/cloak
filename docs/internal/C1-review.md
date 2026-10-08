# C1 review and gate ledger

## Status

C1 is a reviewable credentials/verification draft, not an adopted TLS engine.
The verification owner finished and explicitly released its assigned paths.
The root owns integration and all Git operations. No new reviewer ship is
started, and C0/C2 are gated by the owner after C1 lands.

The remaining C1 blocker is private-primitive erasure/review closure. The
independent verifier owner reported unwiped std scalar copies at
`std.crypto.ecc.Edwards25519.clampedMul` (local `t`) and P-256/P-384 `mul`
(endian-swapped `s`). Root confirmed those sites in installed Zig 0.17.0.
Wiping caller-owned scalar/pair/hash buffers does not erase a callee's copies.
The new `credentials/Uint.zig` helper and final resource-admission rewrite were
completed after that independent review; their deterministic checks pass, but
no independent review of those final changes is claimed. Assembly/spill/erasure
and class-separated timing review of the private primitives remains open.

Owner question: identify the review/remediation closure path while preserving
the instruction to start no new ships. This records an unresolved gate, not a
request to waive erasure or permit adoption. Root continues unaffected floor,
portable checks, benchmarks and branch CI. Main remains unmodified while the
gate is open.

## Safety pilot

All 265 production functions in local src explicitly retain runtime safety,
including ReleaseFast. No runtime-safety-off block is introduced. Every cast
has its range/layout/truncation reason; parsers never use unchecked pointer
reinterprets to consume hostile bytes. Acquisitions have errdefer until ownership
publication, or unconditional defer when that acquisition is temporary.

`credentials.Secret(T)` owns private material and erases it on final release;
formatting that wrapper rejects secret output. Credential parsing erases PEM
blocks, decrypted plaintext, key-pair staging, KDF/HMAC contexts and round
blocks, AES/DES schedules, RSA integers, witnesses and Montgomery scratch.
Borrowed passphrases and caller Io are never retained. Errors contain typed
status only. Regression failures never print material. No secret lookup table
or secret-indexed load is introduced by owned AES/DES/Montgomery arithmetic;
constant-time claims still require the open assembly/timing review.

`services.Guarded(T)` gives a single owner and lock to phase/result and admission
counts. Abandoned work stays charged until its executor handle is reaped. Deep
inputs use one bounded backing allocation, and admission includes State/path
and temporary descriptors rather than estimating arena growth. Framework
private allocation is outside the cloak allocator and limited by job count.
There are no session caches, ticket keys or handshake state machine in C1.

Local replacements for future aegis:

- `credentials/Secret.zig`: retained PrivateKey material; KDF/curve/RSA scratch
  are currently local var + secureZero/defer owners.
- `services/Guarded.zig`: Job phase/result and Budget counts, one lock per owner.
- Retained handles: Trust.Snapshot, PrivateKey, Identity, ClientAuth and Job.
- Move owners: services.OwnedRequest, services.Path and types.Verification.
- Public verifier temporary workspace and certificate.Issuers are described in
  src/verify/fixtures/evidence.txt.

The local forms rely on explicit move/borrow contracts. They do not promise
compile-time linear types, a borrow checker or stale-handle detection.

## Review findings and regressions

Independent review caught accepted composite RSA factors and SEC1 pair copies.
Root replaced small-factor-only acceptance with 64 fresh-CSPRNG Miller-Rabin
rounds per factor and added pair erasure. Independent full-width Montgomery,
strong-pseudoprime, RFC8032 and PBKDF2 differential cases pass.

Follow-up root regressions failed before their fixes for malformed PKCS8
Attribute grammar/implicit SET ordering, mixed native policy + explicit trust
anchors, and congruent out-of-range RSA CRT coefficients. Root fixed all three.
The fixed-width borrowed Uint helper removes unwiped by-value std bigint
orchestration, with a 512-case independent u128 arithmetic property and 128 full-width
public-oracle cases across 1..1,024-byte widths. Service
allocation-failure, late-reap, no-executor, arithmetic-overflow and admission-
bytes tests check the final single-backing allocation form.

## Corpus and parser campaigns

Verifier evidence pins the entire x509-limbo corpus, profile departures and
29 Wycheproof files: 9,802 matches for each flat/indexed path builder and 6,955
signature vectors, zero unexpected verdicts. That report includes optimized
checks, allocation-failure coverage, offline CRL/OCSP cases and initial fuzz.

Root LLVM campaigns, each separately selected because the limited compiler
runner executes only its first discovered target:

- Key parser, ReleaseSafe: 507,568 executions; 7,357 unique inputs;
  1,837/15,075 edges (12.19%).
- KDF parser, ReleaseFast: 101,305 executions; 1,203 unique inputs;
  747/9,892 edges (7.55%).
- PEM parser, ReleaseFast: 100,236 executions; 202 unique inputs;
  370/8,594 edges (4.31%).

These are smoke campaigns with no crashes, not 24 CPU-hour claims. The design's
initial-engine 24 CPU-hour/stateful, sanitizer and full stack/resource campaigns
remain later engine/adoption closure work. All enabled targets must retain the
floor and grow corpus coverage; none is waived by C1 implementation.

Final optimized verifier campaign refresh, after workspace changes:

- DER/certificate/authentication: 101,719 executions; 1,621 unique inputs;
  1,218/13,033 edges (9.35%).
- Offline CRL/OCSP: 101,179 executions; 1,104 unique inputs;
  837/11,985 edges (6.98%).

No crashes. Corpus/edge counts belong to their individual compiled target;
coverage percentages are not compared across changing instrumentation.

## Tooling observations

Pinned preflight's ordinary runner reports fuzz=false during compiler discovery;
`zig build fuzz` uses the std LLVM runner separately. Normal CI remains preflight.
Pinned shakedown's hosted Source has a 32-bit usize/u64 mismatch and hosted
Threaded Io cannot run freestanding. The freestanding core is therefore compiled
and executed with caller storage and portable vectors by `check-wasm`; hosted
checks still compile the full test declarations for every hosted target.

`preflight-cross` is a preflight run-command pseudo-step, not a Zig build step;
the hosted reusable workflow owns it. Local checks compile each configured
`-Dtarget` explicitly. Object-only checks omit native linking; hosted tests and
runtime consumer modules link Security/CoreFoundation or crypt32 as required.

## Security intake

SECURITY.md records the owner decision: main is supported until the first release,
reports go privately through GitHub private vulnerability reporting, never public
issues. The owner enables that setting when making the repository public. Neither
visibility nor settings were changed. Intake must privately triage severity,
reproduce with a deterministic regression, prepare reviewed fixes and issue the
GitHub security advisory when applicable; no certification is claimed.
