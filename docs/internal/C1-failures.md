# C1 failure catalogue coverage

Book reference: cloak design commit 58e6dfe81b7ef91b83d8abb8cfc945f147cf2731,
2026-10-08, whole design plus safety.md read. Section 17 has 93 failure classes,
102 references and 144 CVE IDs. Its `catalogue_*` identifiers are planned;
section 17.13 inspected source assertions at d3d790f are not executed evidence.
This table is a C1 construction/closure inventory, not a class-completeness claim.

## Historical executed selection and limits

Apple M3 Max / Darwin 25.2.0 / Zig 0.17.0; preflight 9af905e, test-only
shakedown d5d19d3. ReleaseFast selected 92 tests (91 passed, Linux bundle skipped),
seed 3378321501. ReleaseSafe selected the same tests plus Wycheproof: 121
(120 passed, Linux bundle skipped), seed 347630315. macOS native bodies ran;
Windows bodies return early on macOS and are not runtime proof.

Command prefix is `zig build test -Dci-lint=false -Doptimize=fast` or `safe`.
Selections were explicit `-Dtest-filter` arguments: `credential curve`,
`SEC1 rejects congruent`, `owned Ed expansion`, `credential key formats`,
`DER rejects`, `DER hard recursion`, `constraints reject`, `unsupported critical`,
`portable `, `directoryName`, `wildcard constraints`, `SAN DNS`, `policy tree`,
`anyPolicy`, `public certificate signature`, `public Ed25519 signature`,
`offline CRL`, `offline delegated`, `verification request digest`,
`native verification`, `service `, `trust `, `receipt `, `certificate time`,
`issuer index`, `catalogue_revocation`; the safe command added `Wycheproof`.
Full corpus test matches `portable `: 9,802 flat plus 9,802 indexed checks,
zero mismatches in both runs. Safe public-signature corpus: 29 files / 6,955
vectors / zero mismatches. Pinned corpus revisions are in fixtures/evidence.txt.
These selections do not establish every adversarial assertion below.

## Reachable C1 classes

Paths are under src. Exact existing test names can be found in the named files;
short quoted substrings here are the executed filters, not invented new tests.
"Open" identifies missing catalogue-specific assertions/proofs and retains the
phase gate; corpus success is not a blanket waiver.

| F-id | Implemented guard and passing assertions | Remaining obligations |
|---|---|---|
| F07 | wire/Der.zig validates lengths/integers/parent bounds and hard recursion; wire/Der_test.zig `DER rejects`, `DER hard recursion`, both optimized modes. | 24 CPU-hour DER/certificate campaign, whole-call byte/work/resource measurements and sanitizer evidence. |
| F08 | certificate/Algorithm.zig bounds public RSA/EC types before fixed-buffer work; Certificate.zig bounds signature encodings. verify/signature_test.zig modern max RSA/PSS vectors; safe Wycheproof. | Dedicated huge structure/canary and maximal-work measurements, full dispatch coverage. |
| F09 | verify/signature.zig checks complete PKCS1 DigestInfo/padding/PSS; public signature vectors and all safe Wycheproof cases match. | Explicit combined e=3/BER/trailing/MGF mutation fixture coverage and optimized full operation review. |
| F10 | Verifier.link/accept and identity.purpose enforce CA, KU/EKU/path length on accepted paths; Extensions basic/default tests; Limbo pathlen/CA corpus. | Catalogue combinations under every native-selected path, including diagnostics on/off and rollover boundaries. |
| F11 | Verifier uses explicit anchors, verifies link signatures, errors fail closed; `portable selected path`, `trust empty`, receipt none assertions. | Catalogue impostor/empty/custom authorization schedules across native platforms; caller anchor provisioning remains an input contract. |
| F12 | Search rechecks every candidate, constraints/policy on returned path; complete flat/indexed Limbo including bettertls pathbuilding. | Dedicated candidate permutation/non-CA cross-sign receipt assertions and native equivalents. |
| F13 | Search.cycle uses exact DER; limits bound paths/discovery; Limbo pathological intermediate-cycle distinct/same-logical cases match. | Explicit >16/max-cap hostile resource/work proof and all candidate orderings. |
| F14 | Search.charge includes unmatched discovery/dedup/parses/signatures/rejections; policy has its own work cap; `portable indexed verification` and budget overflow checks. | The resume adds cumulative constraint/policy work owners, signed constraint-flood rejection for portable/native-selected paths, exact-budget and no-refund tests. Maximum heap+stack, full adversarial permutations and whole-C1 independent closure remain open. |
| F15 | constraints.check imposes every CA's permitted/excluded forms on each applicable subordinate, self-issued handling; critical-form tests and complete Limbo. | New `catalogue_constraints_all_ca_permitted_and_excluded` passes the isolated accumulation guard with valid/invalid neighbors; signed end-to-end/native-selected variants remain open. |
| F16 | constraints DNS intersection normalizes case/labels; `wildcard constraints exclude intersecting hosts and preserve label depth` passes. | Full catalogue mixed-case/suffix/native permutations; one unit subset is not complete class evidence. |
| F17 | Name canonicalDns rejects NUL/invalid/oversized syntax, identity.check uses SAN without CN fallback; `SAN DNS identity` plus corpus. | Overlong CN beside malformed/URI-only SAN end-to-end fixture and diagnostic bound counters. |
| F18 | identity.validate requires a reference for server authentication; no SNI input substitutes for it; wrong-name/none receipt tests. | Consumer proxy/reference-swapping boundary tests belong to that consumer; engine configurations are not built in C1. |
| F19 | Extensions validates tagged forms; binary IP; constraints URI/email/directoryName boundaries; critical-form, directoryName and wildcard tests. | Combined IPv6-zone/URI/A-label/email fault matrix and native-selected equivalents. |
| F20 | Tagged extension parsing, CRL unsupported scope fails; revocation caps 64 evidence blobs/262144 bytes and CRL duplicate offsets 4096. | EDIPARTYNAME/X.400/relative-CRLDP expansion attacks, peak/canary/resource proof. No online CRLDP fetch exists. |
| F21 | policy.check enforces leaf/request/anchor sets, bounded mappings and inhibition; `policy tree` and `anyPolicy cannot bridge` tests pass. | The resume adds charged policy visits/OID comparisons, mapping/dedup charges and exact-budget/no-refund assertions. Dedicated maximal branching trees and native-selected policy permutations remain open. |
| F22 | revocation validates offline serial/issuer/signature/authority/freshness/coverage and rejects bad supplied evidence. Existing CRL/OCSP/delegated/rollover tests pass. New signed `catalogue_revocation_multi_entry_target_and_order` accepts a valid neighbor and rejects first-good/target-revoked in both orders and unrelated-only evidence. | Wrong-scope/multi-path/full-coverage permutations and sustained evidence parser campaign; default if_present is not comprehensive revocation. |
| F23 | NativeVerification/Path bind digest/token/generations/time, check native-selected path with portable floors; macOS selected-chain/receipt/backward-clock tests pass, scoped anchors only. | Hosted 2bf68c1 merge executes native Windows/macOS scoped-policy bodies and Linux system-bundle import; the overall tier fails at shared SDK linking. Explicit Windows distrust/network-disabled failure campaigns, weak/explicit-param native acceptance, OS patch evidence and store-generation consumer notifications remain open. |
| F24 | Certificate/Algorithm enforce identical inner/outer encoding, legal PSS/Ed parameters and supported SPKI; modern signature vectors, zero-serial/native floors and safe public corpus. | Dedicated zero-length point/weak intermediate/native mixed algorithm regressions. |
| F25 | Trust snapshot owns immutable roots/index under atomic retained references; duplicate extension parser rejects; snapshot reload/poison/transactional tests plus corpus duplicate/critical/time cases pass. | New `catalogue_trust_snapshot_concurrent_verify_reload_release`: four retained worker owners each verify 64 times after releasing/reloading the original owner. Targeted arm64 macOS Thread Sanitizer execution passes the concurrent snapshot test in the resume; exhaustive schedules, other sanitizer targets and full expiry/notBefore boundaries remain open. |
| F26 | OwnedRequest one backing allocation, Job/Budget one locked owner, abandonment charge held until executor reap; selected `service` NoResize/failure/deadline/budget/poison tests pass. | Saturated concurrent abandon/success schedules, consumer executor contract, all native platform late completions. |

## C0 classes already reachable by C1

| F-id | Current guard/assertion | Open proof |
|---|---|---|
| F01 | RSA primality requests fresh CSPRNG per witness, no seed fallback; `credential primality independent entropy failure fails closed` exists. | The resume re-executes the targeted entropy, CRT/range and Montgomery failure selection in both optimized modes (47/47); generated private arithmetic/erasure and caller entropy ready/fork/clone behavior remain open. |
| F02 | C1 validates RSA components with full-width Montgomery and 64 witnesses per factor. No private signing/CRT-result output exists here. | Preparation's secret arithmetic/timing/erasure/fault review remains C1; future signing blinding gates stay C0/C2 rather than being claimed by import validation. |
| F03/F04 | Curve borrows scalar, rejects none options, scans public tables; final generated source is pinned by assembly evidence. | Concrete x86-64 field carry branches and unwiped point spills block closure. All secret operations/targets/dispatch/failure paths still require optimized review and timing evidence. |
| F05 | Checked parser sizes, Uint/Montgomery carry oracle properties, public curve/signature vectors. | All private-kernel carry/tail/dispatch/canary combinations and generated optimized arithmetic audit. |
| F06 | Owned Secret/defer wipes, bounded key/KDF, strict PKCS8/CRT, new SEC1 n+1 regression (failed before range check; now passing). | Full callee/spill erasure, all allocation/KDF failure campaigns and private material resource/timing proof. |
| F93 | Typed errors, no secret diagnostics, Secret.format refuses formatting, owned cleanup. | Compiler-resistant every-exit erasure of all reachable private copies and diagnostic/failure/poison schedules. |

F69/F74's request/evidence expiry and trust generation vocabulary are already
covered by receipt/digest/revocation tests; resumption itself does not exist in
C1. F27–F92 engine/record/ticket/ECH/DTLS/offload/extensions obligations remain
with their named construction phases, with no claim that C1 executes them.

## Closure and blockers

No completed 24 CPU-hour campaign is claimed from the smoke counts. Common and
indexed fixture measurements in C1-performance.md are measured heap+stack but
not worst/default-cap/embedded proof. No independent closure, successful binding
hosted C1 fast/merge, whole-platform native/security campaign, or matched-rival
proof is claimed. Exact-head hosted failures and native job successes are in
C1-resume.md. The historical billing block is owner-confirmed resolved. Nav owns
the shared preflight SDK/compilation, canonical regeneration and incomplete-lint
semantics changes. These retained gates are not waived by an owner-owned issue.
Task17/node19 failed with a backend content flag and produced no completed
closure verdict. Its last progress independently confirmed the P-curve branches.
No replacement or reroute is authorized; unavailable independent closure is
reported to nav. Final code must receive independent closure before landing.

Additional targeted F15/F22/F25 run after adding the two missing assertions:
`zig build test -Dci-lint=false -Doptimize=fast -Dtest-filter=catalogue_
--summary all`: 39/39 tests passed, seed 2492016608 (36 namespace/import checks
and the three named catalogue assertions). The accumulation test isolates the
constraint guard using parsed certificate views; it is not a newly signed
end-to-end chain. The snapshot test synchronizes workers before first verification
and joins/cancels every future before freeing its borrowed gate/backend. Atomic
retain counters protect snapshot lifetime; Job/Budget mutable payloads use
Guarded single-lock owners. These are distinct synchronization sites for review.

The three catalogue assertions also passed ReleaseSafe: 39/39, seed
3457464961. Those two additional tests required only test import/style corrections
after execution; final preflight validation covers the corrected import layout.
