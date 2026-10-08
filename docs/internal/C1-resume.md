# C1 resume: remediation and remaining acceptance gates

Baseline: published c1 3a66309c49ab024be4e2647c9c3da4550e740ac0.
Authoritative main at initial verification: c53aa6149fa09dc945bf55b6aabc322bdd06f7cc,
already default. Preflight 9af905ed85cab6dbb19d9431c65ee3f41fbaa74d and test-only
shakedown d5d19d39bc60cec59456aca947a3a7b484b87318 matched remote main at
initial pin verification. A later preflight update requires its own verified
landing, exact green SHA and canonical workflow regeneration.
No bootstrap, new ship, C2/C0 work, visibility or setting changes occur here.

## Remediation and provenance

The retained read-only review found uncharged name-constraint comparisons and
policy comparison work. Its signed synthetic public path, with 1,900 SANs and
1,900 excluded subtrees, performs 3,610,000 comparisons while staying within the
wire cap. On unchanged baseline, catalogue_verification_constraint_flood_is_bounded
failed (seed 545135129): an authenticated receipt was returned instead of a
VerificationLimit. The unexpected receipt in that first failure was printed as
public DER by expectError and leaked only in the failing test; the retained
regression now releases unexpected receipts and prints status only.

Search now owns two cumulative Work values. Constraint scans charge visits and
byte work even for mismatched name tags; matching reserves byte work and a
conservative directoryName rescan allowance. Policy capacity visits, comparisons,
node deduplication, mappings and final request/anchor intersection charge the
separate policy owner. Node storage retains its existing independent cap.
Arithmetic cannot wrap; exhausted and failed candidates retain all prior
charges. Native-selected and portable paths share the same guards. Explicit
anchor constraint bytes/policy counts are bounded before processing. New public
limits participate in Request.digest and receipt binding.

Fixtures under src/verify/fixtures/work are MIT synthetic signed public
certificates retained from the authorized C1 review artifacts. No private key
is published. Small signed neighbor accepts; large signed path rejects in both
portable and native-selected verification. Unit tests cover exact-work boundaries,
no refund/reuse, mapping comparisons and every Limits field in the digest.
These assertions improve F14/F21; they do not close the whole failure class.

The tentative email/SAN finding in early reviewer artifacts was explicitly
withdrawn by the reviewer after checking RFC 5280. No acceptance change is made
for that discarded candidate.

## Hosted clean-build remediation

Fast run 37795614291 on e7f9034b167fb1cefc175321048454e55659e71d
failed before testing: the top-level import of a lazy preflight dependency was
unavailable in the clean runner. The package build now uses Zig 0.17 lazyImport
after the consumer return, so configuration requests the missing build helper
and reruns after fetching; consumers still return before requesting CI tools.
This follows the installed std.Build contract without making dependencies eager.

Fast run 37797157383 on 78c647448a83b9ae6773340fa2d7f9e86d57d4e3
passed clean setup but failed the Linux system-bundle test with InvalidTime.
One unusable certificate previously poisoned the whole system import. The
retained regression uses a synthetic month-13 root plus a valid signed neighbor
and fails unchanged loading with InvalidTime (seed 3928676711). System bundles
now omit unparseable/unsupported roots; each retained root still passes the
strict parser. Explicit imports remain strict/transactional. System import
charges every block against the root cap, including omitted entries; PEM
framing, per-certificate/file/store limits and allocation failures still fail
and roll back. An all-unusable bundle cannot freeze. No load-time validity
filter, weaker calendar/profile, fallback trust authorization or native root
dump is introduced. NoResize/checkAllAllocationFailures covers these cases.
The targeted trust selection passed 45 tests with the Linux-only host test
skipped on macOS in both ReleaseSafe and ReleaseFast. The synthetic private-loader
assertion executes on this host, including NoResize/allocation-failure schedules.
Lint/extras and all twelve configured target declaration checks pass after the fix.
Hosted Linux subsequently passed the system-bundle assertion on 2bf68c1.
Its overall hosted gate still failed during foreign-target linking, below.
This startup-loader change does not change a measured verification hot path.

Fast run 37800069272 on 0ef5413581d0204eb427402c5209039fb4205f1b
passed the Linux system-bundle regression and 156 tests, then the combined
9,802-case flat/indexed Limbo test exceeded the unchanged 120-second body
watchdog (seed 1002029105). The same fixture and profile mappings now run in
eight disjoint residue batches. Each asserts the fixed fixture cardinality,
its exact case count and both builder verdicts; their counts sum to 9,802
for each builder. Every batch keeps the default watchdog. No timeout, expected
result, fixture, compiler mode or CI gate is relaxed.

Exact-head x86-64 and AArch64 curve assembly regeneration matches the hashes in
C1-curve-assembly.txt byte for byte; the recorded carry branches remain.

## Current local validation

Zig 0.17.0, Apple M3 Max, Darwin 25.2.0. Targeted ReleaseSafe and ReleaseFast
selections each passed 103/103 tests after batching (seeds 2930080272 and 2129299202). Filters:
portable , Wycheproof, catalogue, policy, constraints, native verification,
verification work and verification request. Each mode matched all 9,802 Limbo
cases on flat and indexed builders and all 6,955 Wycheproof vectors in 29 files,
zero mismatches. Corpus source revisions remain in fixtures/evidence.txt.
Targeted host Thread Sanitizer run passed 38 declarations/tests, including the
four-worker concurrent snapshot verification/reload/release assertion, with
zig test -OReleaseSafe -fsanitize-thread --test-filter catalogue_trust_snapshot
and the pinned test dependency/native frameworks. No race report was emitted.
This single schedule does not prove exhaustive races or other targets.

Local native macOS bodies execute; Windows bodies on this host do not establish
Windows runtime proof. The later hosted Windows run below executes its scoped
policy body; it does not establish the entire native campaign.

All twelve ci/workflow.json targets compiled with zig build check
-Dci-lint=false -Doptimize=safe -Dtarget=...; check and preflight lint/extras passed.
Wasm vectors/negative consumer options are included in lint extras. Compile-only
evidence does not establish native execution or generated crypto correctness.

## Exact-head hosted evidence and owner-owned CI dependency

Both recorded tiers below tested published c1
2bf68c1f3cb970e16085f04157cbbcda2ecc00cd. This is tested evidence for that commit,
not an acceptance claim for subsequent documentation or dependency changes.

- [Fast 37802720437](https://github.com/pedronaugusto/cloak/actions/runs/37802720437):
  failure. Linux reported 164 passing tests, all 9,802 Limbo cases for each
  builder and all 6,955 Wycheproof vectors with zero mismatches. Foreign-target
  linking then failed when Linux could not locate Security/CoreFoundation for
  macOS test/benchmark executables. No final fast success exists.
- [Merge 37805208575](https://github.com/pedronaugusto/cloak/actions/runs/37805208575):
  failure. Linux Debug failed at the same SDK linking step after passing its
  tests. Native macOS Debug job 113407728582 and Windows Debug job 113407728601
  succeeded. Each timing artifact records 163 pass and one Linux-bundle skip
  out of 164 declarations/tests; an opposite-platform early return counted as
  pass is not native execution evidence. Zig master Linux Debug succeeded as
  a non-blocking canary, not a substitute for the binding Linux gate.

Artifact 11562577211, timings-ebda036faf315e75, records the macOS scoped-policy
body at 0.022751209 seconds. Its checks include the accepted two-certificate
path/request binding, wrong reference identity and wrong scoped anchor.
Artifact 11562622772, timings-03c230abe180e8e9, records the Windows scoped-policy
body at 0.0066283 seconds. Its existing assertion checks accepted two-certificate
path length and wrong reference identity. Despite its test name containing
"distrust fixture", it is not evidence for an explicit Windows distrust/root
store campaign. Both native runs execute the concurrent snapshot assertion.
Artifact file SHA-256s: macOS
e98b77795fe66e1cee8368d68a9fa29a57dc6ea3a93445510bc658785d27db45;
Windows c38228d82f71a736edfbac0f599f095b196bc49fa94dfd01a9bf653bfe03f0ae.

Additional current-head private-key failure selection passed 47/47 in
ReleaseSafe (seed 2367627862) and ReleaseFast (seed 3938895682). Filters:
credential primality, credential complete RSA, credential RSA mathematical,
credential Montgomery, credential fixed integer, credential KDF, credential
AES CBC, credential input and KDF, credential final ownership. These execute
entropy failure, CRT/range rejection, public carry oracles, bounded KDF/CBC and
NoResize/allocation-failure ownership assertions. They do not close generated
private arithmetic, erasure, all dispatches or entropy-provider fork/readiness.

The owner assigns the shared changes to one nav-owned preflight ship: Linux
foreign-target object compilation with SDK-backed linking on native runners,
the canonical workflow-regeneration interface, and F04 incomplete-lint failure
semantics. This clone does not modify shared preflight or work around the
Linux/macOS linking failure. Existing lint success is not complete source-audit
proof while incomplete-lint semantics remain open. After nav verifies preflight
LANDED, pin that exact green main, regenerate through its canonical interface,
and run fast then merge on the same final published C1 commit. Repeat only for
actual fixed failures. All security, performance and independent-review gates
below remain binding even if both tiers later turn green.

## Performance and resources

Own signed-path row is bench/constraints.zig. Nine interleaved ReleaseFast native
batches retain best/median/spread in C1-work-ab.json. Common portable verification
best 98.446 to 110.611 us/op (+12.36%), median 100.362 to 112.761 (+12.35%):
a measured miss, still open. Signed constraint path best 198.483 to 198.936
(+0.23%), median 202.337 to 202.284 (-0.03%). Native scoped-policy best
768.160 to 783.190 (+1.96%); scheduling outliers remain. CPU pinning/frequency
are uncontrolled; batch p95 is not per-operation tail latency. Separate
instrumentation measured verify about 102 us and receipt checking about 0.42 us
on both variants, but does not invalidate the normal benchmark regression.
A no-inline acceptance experiment did not help and is reverted. No performance
acceptance, matched external implementation or no-regression claim is made.

Current common peak heap is 7,197 bytes with 941-byte retained receipt, up 32
bytes for request limits/work owners. The baseline stack/heap fixtures in
C1-performance.md are historical, not fresh maximum proof. Hostile/default-cap,
embedded, revocation, native-private allocations and worker-tail maxima remain open.

## Mandatory unresolved gates

- Generated x86 P-256/P-384 secret carry branches and unwiped point/callee spills
  remain concrete defects. Curve/EdKey/SEC1 code is unchanged by this resume.
  All private field/hash/KDF/RSA/AES/DES/PEM-import paths and enabled compiler,
  optimization, ISA and dispatch combinations still require generated-code,
  erasure, class-separated timing and hot-path A/B proof. Private PEM's indexed
  std Base64 decoding is an additional retained review site, not a closed finding.
- No 24 CPU-hour-per-target sustained C1 parser campaign is complete. Historical
  smoke counts cannot be summed into that floor. Required coverage growth,
  sanitizer/optimized runs and remaining F07-F26/F01-F06/F93 assertions in
  C1-failures.md remain construction/acceptance obligations.
- Complete default/hostile/embedded heap plus stack maxima and matched performance
  targets are unproved; the common-path regression above remains open.
- Native offline networking/trust/distrust campaigns and consumer lifetime,
  executor, reload, store-generation and environment evidence remain incomplete.
  A three-host unit suite is not complete whole-platform security proof.
- Independent whole-C1 critical/major closure is unavailable. Task17/node19
  partially inspected 3a66309, regenerated matching assembly and independently
  confirmed the P-curve branch. It then FAILED with a backend flag for possible
  cybersecurity risk, not a verdict. No retry, rephrase, replacement reviewer or
  alternative backend is deployed. Nav must resolve this block; current code
  has no independent closure verdict and main cannot receive C1.

Hosted tiers above identify their actual published candidate SHA and conclusions.
No final exact-head hosted acceptance or main fast-forward has occurred. Final
authoritative main must be read again from GitHub before reporting any landing. Hosted green does not waive any gate above. README
continues to say work in progress, and SECURITY.md retains main-until-first-release
support and private reports only. The owner confirms reporting enabled/public
status; no settings mutation follows. The book has no cloak repo page and its
old C0-first/publication assumptions are stale. No book or station state is edited.

## Local safety forms

No runtime-safety-off region or secret operation is introduced. Work contains
public, per-call remaining budgets with one Search owner; it needs no lock.
It is a future-aegis checked/bounded-integer replacement site alongside
certificate/Name and revocation bounded arrays. Existing Secret, Guarded,
retained handles, move owners and borrow sites remain inventoried in
C1-review.md and fixtures/evidence.txt. No unbuilt aegis API is adopted.
