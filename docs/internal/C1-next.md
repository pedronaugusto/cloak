# C1 next: repaired subsets and retained acceptance gates

2026-10-08. Fresh standalone branch `c1` began exactly at published
`7e6c16c9d322a3126e17a20a78683e24f67825f7`; main remains the infrastructure floor
`c53aa6149fa09dc945bf55b6aabc322bdd06f7cc`, already an ancestor. Normal descendant
commits preserve published history. No bootstrap, settings, releases, C2/C0 or
consumer changes occur. README remains WIP and SECURITY.md uses GitHub private
reporting, with main supported until the first release. Earlier ledgers remain
historical evidence; this file supersedes their current pin/build/blocker claims.

Implementation `1b35b1be378fe4cab786b7f3f37e6a1078349a98` is the measured runtime
source. Later additions are a native concurrency regression and documentation;
[the summary](C1-next-performance-summary.json) pins all touched runtime/bench
file hashes, checked again when preserving this evidence. Native task35/node37
receipt identified model gpt-6.1-sol, effort high. The authorized scoped clone and
build/code/Git writes succeeded through normal automatic escalation review.
Predecessor trees were read only, including their failure and performance ledgers.

## Tooling remediation

Pinned preflight main `b28046cc22055fcd32640117fc0e6965283a8ae5`, independently
verified exact green FAST37821750595 and MERGE37823307574. Pinned shakedown main
`9357a9ab398ac25fa8a408a71e77a124bc51d311`, verified green runs37817170226,
37818062956 and37820085077. Both dependencies are lazy repository-only tooling;
`test_dependencies` and the exact `.paths` remain explicit. Canonical generation
is `zig build plan -- --workflow .github/workflows/ci.yml`; the duplicate local
planner is removed. The new native SDK/object contract exposed a real 32-bit
Uint test-oracle assignment and hosted I/O roots in the Wasm graph. The oracle
now generates its addend as usize with an independent u128 result; before x86
compile failed at the u64-to-usize assignment, after compiled. Freestanding CI
checks actual core objects/vectors, while hosted test/measurement roots remain
hosted. All twelve configured cross targets passed the canonical cross driver.
These are compilation results, not target runtime or security proof.

## Repairs and catalogue mappings

The following are closed concrete implementation defects or passing named
assertions, not blanket failure-class closure. [Raw local output](C1-next-local.txt)
retains before failures, final passes and seeds.

| Item / mapping | Named evidence and actual result | Remaining limits |
|---|---|---|
| PEM cap before scanning, F06 | `catalogue_key_import_armor_limit_precedes_whitespace_scan`: before oversized whitespace returned null instead of InputLimit; after rejects before scanning. | Whole key parser campaign and maximum resource proof remain open. |
| Character-indexed private armor lookup, F03/F05/F06 | `catalogue_key_import_base64_all_characters_match_standard`: four positions x 256 bytes and strict tail/padding; `catalogue_key_import_base64_byte_roundtrip_and_erasure`: lengths 0..256; `catalogue_key_import_base64_generated_roundtrip`: 1,024 cases, seed0xc1b640, up to1,024 bytes. Fixed arithmetic classification replaces lookup; optimized kernels inspected below. | Whole import/callee/dispatch constant-time and erasure remain open. |
| Owned PEM release, F06/F93 | `catalogue_key_import_pem_owned_buffers_clear_before_raw_free`, NoResize plus every allocation failure: Fast observes16 zero releases, Safe observes16 allocator-poison releases, both dirty0. Decoder error destination wipes asserted. | Safe free writes undefined before rawFree: uniform0xaa is allocator poison, not observed zero. Compiler-created copies and all other secret owners require proof. |
| Path cleanup under completion spin lease, F26 | `catalogue_verify_job_path_cleanup_releases_spin_guard`: before4 locked frees, after0. `catalogue_verify_job_native_abandon_during_evaluation_reaps_outside_guard`: real macOS native evaluation before2 locked frees, after0. | Consumer executor contract and all native platform/fault schedules remain open. |
| Real concurrent native abandon/reap, F26 | `catalogue_verify_job_native_concurrent_abandon_retains_charge_until_reap`: pause first real native allocation after running, drop caller handle, assert charge remains1, release worker, assert job/byte counts0 and locked frees0. Before published implementation fails with2 locked frees. Both optimized modes and fresh Thread Sanitizer pass. | One deterministic schedule on macOS; not saturation or Windows runtime proof locally. |
| Native owned failure/resource assertions, F23/F26 | `catalogue_native_completion_owned_allocation_failures_without_resize`; `catalogue_native_completion_repeated_release_keeps_owned_heap_and_budget_bounded`:256 accepted/released native receipts, peak9,630 owned bytes, live0. | OS-private resources, network isolation/distrust campaigns, other OSes and maximal configured workloads unproved. |
| Scoped Windows anchor, F23 | `catalogue_native_windows_wrong_scoped_anchor_rejects` adds an actual wrong-anchor rejection. The old scoped-policy test is renamed honestly and checks the returned path. | Explicit macOS/Linux skip; only hosted Windows execution can establish that body. No explicit OS distrust-store proof claimed. |
| Word-width test oracle, F05 | Existing Uint independent arithmetic property now compiles for32-bit; failure before and successful test-object compilation after retained. | Does not close all generated private arithmetic/ISA/canary combinations. |
| Existing work-budget repairs, F14/F21 | Existing charged constraints/policy guards and signed flood regressions are retained; outlined accept calls preserve charging and receipt checks. | Maximal tree/resource/native permutations and independent closure remain open. |

Final `zig build lint check test -Doptimize=safe
-Dtest-filter=catalogue_verify_job -Dtest-filter=catalogue_key_import --summary all`
passed29/29 steps and45/45 tests, seed1754672132; lint's required Fast extra seed
2327519155 passed. Same selection Fast with `-Dci-lint=false` passed45/45,
seed1169078323. Zig0.17.0 is explicitly first on PATH for lint subprocesses.
Test totals include namespace checks and are not counts of independent campaign
cases. Earlier broad Safe run150 passed/1 Windows skip, seed2553185822, executed
all9,802 Limbo cases per flat/indexed builder and6,955 Wycheproof vectors across29
files, zero mismatches. Broad Fast148 passed/1 skip, seed1681437189, also matched
both corpora. Those broad runs precede later test-only instrumentation additions;
exact-head hosted tiers remain separately required.

Fresh native `zig test -OReleaseSafe -fsanitize-thread`, with the pinned shakedown
module/native frameworks and filters `catalogue_verify_job_native_concurrent`
and `catalogue_trust_snapshot`, passed40/40 declarations/tests with no race
report. Both real concurrent bodies ran on macOS26.2 / Darwin25.2.0 / Apple M3
Max (16 physical/logical CPUs). No replacement reviewer was deployed.

## Generated code, erasure and timing

[Assembly commands/hashes](C1-next-armor-assembly.json) and
[all nine classifier excerpts](C1-next-classifiers.txt) record Zig0.17.0 baseline
x86_64-linux-gnu, aarch64-macos and wasm32-freestanding in ReleaseFast, Safe and
Small. In these inspected classifier bodies character masks use arithmetic,
without character-indexed loads or conditional branches. Native bodies write
two bytes at fixed owner offsets and save only frame/return state, no character
or mask stack spills. Wasm arithmetic locals/stores say nothing about a JIT's
register/spill/erasure policy. Decoder input loads use public group offsets;
framing branches depend on public length/padding and aggregate final validity.
Named nine-byte scratch is zeroed on normal return and error destinations are
cleared. This is narrow generated-code evidence: caller/callee/register copies,
all imports, every error path and all target/dispatch combinations remain open.

Curve code was not repaired. Fresh full optimized inspection assembly matches
prior full hashes: aarch64 `ae5240308c138a622996ef3f682e8e9487e86a921fdb10df71980a1081df12d4`,
x86_64 `1e156974c7629108016ec6a168d264a4cf5bc7ccba38cb4833b70983d5d582f1`.
The retained x86 P256 field carry sequence at67035 (`test dil,1` then `je
.LBB195_8`) selects secret-derived arithmetic; P384 carry branches and unwiped
point/callee spills in C1-curve-assembly.txt remain critical closure findings.
Named point/scalar wipes do not cover these copies.

[Fresh probe output](C1-next-probes.txt) records24,000 randomized class-separated
samples per kernel on this one M3 host: armor Welch t=-3.194, P2560.404,
P384-0.831 and Edwards-0.448, with raw counts/means/variances. CSPRNG/class setup
is outside timing; only statistics are emitted and synthetic scratch is wiped.
No non-significant statistic proves constant time; the known x86 defect still
blocks closure. No new sustained parser campaign was executed. Historical smoke
execution/edge counts remain historical, not this batch's24 CPU-hour proof.

Reproduce optimized curve assembly using `zig build-obj -OReleaseFast -target
<TARGET> -fstrip -femit-asm=curve.s -fno-emit-bin --dep credentials
-Mroot=ci/primitive_probe.zig -OReleaseFast -target <TARGET>
-Mcredentials=src/credentials.zig` (aarch64-macos or x86_64-linux).
Host timing uses the same module pair with `build-exe -OReleaseFast -mcpu=native`
on both modules. Armor timing uses `--dep armor_decode -Mroot=ci/armor_probe.zig
-OReleaseFast -mcpu=native -Marmor_decode=src/credentials/Base64.zig` with the
root also ReleaseFast/native. Resource probe uses the command in C1-performance
with the new shakedown path; the probe's source is unchanged.

## Performance and resources

[Napkin math](C1-next-napkin.txt) predates new measurements. Canonical benches
now use shakedown.bench via Config.bench, `--commit SHA` metadata and the same
receipt/key validation/armor SHA256 checks for every A/B participant. [Exact
compile commands](C1-next-performance-commands.json), [raw output/timings](C1-next-performance-raw.json) and [81 samples per row/variant and summaries](C1-next-performance-summary.json) retain nine alternating interleaved batches
of nine samples, ReleaseFast/native explicitly set on every module. No other
local compiler/tests/benchmarks ran during measurement. Frequency/core pinning
was uncontrolled; samples are batch means, not per-operation tail percentiles.

Values below are microseconds, best / median / max-minus-min spread:

| Row | Before work budgets | Published7e6c | Candidate1b35 |
|---|---:|---:|---:|
| Common portable receipt |97.875 /99.942 /4.768|97.909 /100.080 /4.632|97.947 /100.253 /23.144|
| Native scoped receipt |653.290 /671.108 /90.108|650.569 /671.035 /447.944|653.390 /671.506 /69.300|
| Signed constraint path |197.935 /204.569 /292.191|198.382 /202.605 /386.627|197.962 /202.125 /207.143|
| Armor decode |—|0.446 /0.460 /0.718|0.815 /0.869 /0.923|
| Ed25519 cold import |—|33.029 /33.915 /19.195|33.207 /34.790 /46.465|
| P256 cold import |—|82.594 /85.156 /29.505|83.487 /87.102 /62.721|
| P384 cold import |—|220.542 /226.203 /24.490|222.531 /230.333 /120.844|
| RSA2048 cold import |—|512677.334 /523922.917 /394140.291|512271.042 /523107.250 /331038.292|

Common canonical best+0.074% and median+0.311% versus pre-work are inside the
observed spreads. This does not erase contrary evidence: [the fresh legacy
harness A/B](C1-next-legacy-ab.json) reproduced pre-work100.193/104.489/7.637,
published112.324/117.681/7.762, candidate101.898/106.960/7.361. Outlining reduced
that regression, leaving best+1.70% and median+2.36% against pre-work. A diagnostic
module probe confirmed both root/import already used fast/apple_m3 even with
only root flags; wrong optimization or CPU flags are not an established cause.
Harness/call-layout/profile differences remain unresolved. The armor-only
security repair costs~83% best/~89% median; cold import medians increase for
Ed/P curves. No performance gate is waived by a security rationale. Matched
external competitors, per-operation native p95, hostile/default-cap and embedded
size/resource profiles remain unexecuted and acceptance remains open.

Fresh resource probe: common peak owned heap7,197, touched pthread stack30,672,
sum37,869 bytes, live0;16 duplicate peers/4,096 duplicate indexed anchors peak
owned heap24,093, same touched stack, sum54,765, live0. Below-entry stack24,319.
Shared index/storage excluded (page allocator); pthread/harness included; sentinel
scanning may miss unchanged writes. These fixture results require corroboration,
not worst-case, embedded or OS-private allocation proof. The256 native release
unit exercises actual owned memory; it is not a full platform resource campaign.

## Acceptance and owner-only blocker

Concrete repairs above are reviewable on c1. Main must not receive C1 yet:
known secret carry/spill defects, complete import/dispatch/erasure proof,
performance findings/comparisons/tails, sustained24 CPU-hour reachable parser
campaigns, native resource/offline trust/distrust/fault campaigns and remaining
catalogue assertions are open. SDK CI repair addresses none of those gates.

Independent whole-C1 closure is unavailable: task17/node19 failed with a backend
content flag for possible cybersecurity risk and produced no completed verdict;
its last progress confirmed the P-curve carry branches. This batch neither retries,
rephrases, reroutes nor deploys another reviewer. Nav/owner must resolve that
owner-only availability blocker; no waiver or approval is inferred. Hosted FAST
then exact-final-head MERGE will be recorded as CI evidence, not review/security
closure. C2/C0 remain distinct nav-scheduled future batches.

Book rows remain stale and read only: package page/bootstrap visibility assumptions,
the original first-phase ordering, old72/test and catalogue source-inspection
counts, predecessor SDK/pin and hosted failures. No book write is authorized by
this batch. Published candidate history and floor/default main are preserved.
