# C1 review and gate ledger

Current continuation evidence and superseding pin/build status: [C1-next.md](C1-next.md).
The entries below retain their historical source states and counters.

## Current resume status

The fresh C1 continuation preserves published history from
3a66309c49ab024be4e2647c9c3da4550e740ac0. Main remains the infrastructure floor;
no bootstrap is recreated. Owner confirms cloak is public and private reporting
is enabled. No repository settings are changed. Details, current checks and
remaining gates are in [C1-resume.md](C1-resume.md).

The single independent whole-C1 reviewer, task17/node19, failed with a backend
content flag for possible cybersecurity risk. Its partial source/check evidence
is retained, but no completed closure verdict exists for that checkpoint or
this continuation. It is not retried, replaced or routed around. Nav must
resolve the unavailable independent closure; no gate is waived.

## Historical checkpoint status

C1 is a credentials/verification draft. The original verification owner released
its paths; all implementation/Git integration is now in the standalone C1 clone.
The owner authorized a separate infrastructure-only main bootstrap and exactly
one independent read-only Codex gpt-6.1-sol reviewer of a stable published C1
checkpoint, followed by that same retained reviewer's re-review of any fixes.
No C1/security adoption follows from the floor. C2/C0 remain nav-gated.

The concrete std scalar-copy sites are bypassed by a borrowed-scalar owned
multiplier; a failing-before SEC1 `n+1` import regression is fixed. See
C1-primitives.md for provenance, vectors, generated code and A/B. Security
closure is still open: x86-64 generated P-curve field arithmetic has
secret-derived carry branches, and extra point/callee spill copies are not
covered by named scratch wipes. This checkpoint is not a constant-time or
complete-erasure attestation. All critical/major findings must be fixed and
independently closed before main can receive C1.

C1-failures.md maps every reachable catalogue row to actual source/tests,
executed subsets and remaining assertions. Catalogue names in the book are
planned; the locally implemented multi-CA constraints, signed multi-entry OCSP and
concurrent snapshot regressions add executed `catalogue_*` tests here. Resource fixture measurements do not
prove hostile/default-cap/embedded maxima. Mandatory duration, target and
sanitizer/security proofs are not moved to a later phase by this ledger.

## Safety pilot

Owned production functions in src explicitly retain runtime safety,
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

These are smoke campaigns with no crashes, not 24 CPU-hour claims. The design's initial-engine 24 CPU-hour target floor is not established.
Reachable C1 parser duration, sanitizer/optimized primitive and complete
stack/resource obligations remain open; no applicable gate is reassigned to
C2/C0 or waived by a smoke run.

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
issues. The owner enables that setting when making the repository public. Visibility and private-vulnerability-reporting settings remain unchanged.
The default branch was explicitly corrected to main after the floor bootstrap. Intake must privately triage severity,
reproduce with a deterministic regression, prepare reviewed fixes and issue the
GitHub security advisory when applicable; no certification is claimed.

## Historical branch and hosted CI state

Initial published c1 history ends at d3d790f14211924ef974918cdfe2203b8e90ab62.
The owner-authorized floor-only main is c53aa6149fa09dc945bf55b6aabc322bdd06f7cc:
build, preflight-generated CI/matrices, module stub, LICENSE, README and package
policy/configuration files. It contains no credential or verification code.
The required `gh repo edit pedronaugusto/cloak --default-branch main` ran and
GitHub verified default_branch main, PRIVATE visibility. Vulnerability-reporting
settings were not modified. CI workflow registration is now present.

Local c1 reconciles the unrelated floor ancestry by merge commit 6495d06;
all initial c1 history is preserved, with no force/rewrite. Main is an ancestor
of this branch. Future main must be a genuine fast-forward only after independent
final-code closure and exact-commit hosted fast/merge success; recheck remote
state first and never overwrite concurrent landed work.

Floor push run 37771993127 failed before starting: check-run 113293568212
has no steps and GitHub's failure annotation says account payments failed or
spending limit needs increasing. This is an owner-only billing issue to nav,
not an attestation/test failure or a waiver. No C1 hosted fast/merge execution
or Windows/Linux runtime success is claimed at this checkpoint.

Current pins: preflight 9af905ed85cab6dbb19d9431c65ee3f41fbaa74d;
shakedown d5d19d39bc60cec59456aca947a3a7b484b87318 (both lazy tooling only).
Local current-kernel proof: ReleaseFast targeted catalogue/curve selection
91 passed / 1 Linux-only skip; ReleaseSafe same plus public corpus
120 passed / 1 Linux-only skip. Windows test bodies return on macOS, so their
reported passes are not native Windows evidence. Both current runs matched
9,802 Limbo cases on flat and indexed builders; ReleaseSafe matched all
6,955 Wycheproof vectors across 29 files, no unexpected verdicts. Earlier
source/pin/results remain historical evidence, not substituted for this code.

The authorized independent review task/node and exact SHA are recorded in the
root task report once deployed. No independent closure is claimed yet.

Current-source configured compile checks: all 12 ci/workflow.json targets
succeeded with `zig build check -Dci-lint=false -Doptimize=safe -Dtarget=...`.
This is compile evidence, not native execution, generated-code safety or campaign
proof. Preflight lint plus required extras passed 8/8; current workflow matrices
match fast, merge and release plans generated by preflight 9af905e exactly.

The later F15/F22/F25 catalogue-only selection passed 39/39 in both optimized
modes, and preflight import/style corrections are followed by lint 8/8 success
(seed 1828038789 for its required targeted test extra). Full source declarations,
including the concurrent snapshot test, compiled on all 12 targets.
