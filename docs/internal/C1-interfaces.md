# C1 ownership and integration

This batch implements the authentication floor described by the private book's `workspaces/tycho/missions/packages-released/designs/cloak.md` and follows `packages-released/designs/safety.md`. It contains credentials, verification and service ownership. C2 implements the new engine; C0 moves the old fork and its checks after the separate consumer-adoption gate. Neither phase is implemented here.

## Owners and layers

`types` is request/evidence vocabulary; `wire` owns strict bounded DER; `certificate` owns parsed public certificate data and the immutable issuer index. Credentials, portable verification and native services are independent siblings that import these lower layers. `NativeVerification` orchestrates native policy and portable floors above the siblings. `root.zig` is a facade. `ci/layers.zig` enforces the dependency direction and sibling boundaries.

`Trust` is a single-writer builder. Loading takes Io and timeout per call; finite loading uses that Io's concurrency and joins cancellation before rolling back borrowed builder memory. `freeze` prepares the issuer index before publication, transfers DER ownership and leaves future builder changes independent. `Snapshot` retains immutable anchors/index/generation/system-policy metadata. `issuers()` borrows the index for the retained snapshot's lifetime. The normal portable entry is `verify.indexed`; the flat-anchor entry is appropriate only for small stores within its explicit work budget. No native OS root dump becomes a portable trust decision. Native metadata and explicit roots cannot be mixed in one builder; construct separate owners for separate policies.

`PrivateKey` retains immutable material; its last release erases it. RSA validation checks complete CRT relationships and both factors using independent fresh CSPRNG witnesses. `ParseOptions.entropy` is required for RSA; `Entropy.fromIo` borrows a caller Io only during construction. There is no private RSA signing API in C1. C2 must introduce and review blinding, constant-time exponentiation, fault checks and explicit signing entropy before signing. `Identity` owns DER and encoded three-byte-length CertificateList entries and retains the matched key. TLS-version message headers/extensions belong to C2/C3. `ClientAuth` retains the same identity owner.

`services.Job` deep-copies request, roots and evidence only after bounded admission. The caller handle and executor handle retain one independent completion. The executor's successful submission takes a handle and must run and release it even during shutdown. No connection pointer is retained. Abandonment discards a ready path or marks running work abandoned; inputs/admission remain owned until the executor releases its final handle. Budget limits are configured before sharing. Mutable admission and phase/result have separate single owners, each behind one lock.

A finite native timeout without an executor fails before copying inputs. The future connection/session driver captures and enforces the overall deadline and abandons expired jobs. C1 does not create a watchdog pool or retain Io in a native completion. Native calls prohibit network retrieval and copy the exact OS-selected chain. Raw native evidence is provisional: `NativeVerification.take` checks its request binding, validates portable floors on that selected path, checks the receipt and current time, then returns owned accepted-path evidence. It never rebuilds OS trust or turns an OS rejection into success.

## Receipt and reload contract

`types.Request` binds peer chain, DNS/IP identity, purpose/mode, pins, policy/OIDs, offline CRL/OCSP evidence, anchor policies, supplied time, limits, trust/policy/identity generations and completion token. Receipts own selected DER and bind the complete request digest. Mutation, expired evidence, token reuse or backwards time cannot silently accept an old completion. Explicit `.none` stays unauthenticated.

Generation numbers are scoped to each trust/identity owner, rather than a global counter. Replacing an owner therefore also changes the caller's policy generation/token namespace and invalidates outstanding work/cache entries. C2 must bind service receipts to its current generation and token, acknowledge borrowed events once, and retain owners across reload. C5 owns session caches and ticket keys; C1 creates neither.

## Disjoint phase handoff

C2 adds engine/state/record/QUIC/session files and may extend `src/types.zig`; it integrates through `Trust.Snapshot.issuers`, `Identity.certificateList`, `PrivateKey`, `NativeVerification` and the bounded executor contract. C0 adds moved fork/checks/provenance in its separate clone and changes consumers only beyond cloak. Both phases may need `src/root.zig`, `build.zig`, `build.zig.zon`, `ci/layers.zig`, `ci/preflight.json`, `ci/workflow.json`, `.github/workflows/ci.yml`, README and CHANGELOG. The second landing merges current main before checks; these shared registry files require explicit reconciliation. C0 must not replace this verifier with a root dump; C2 must not inherit an unreviewed unblinded RSA signer.

Final gate status and aegis replacement sites are in [C1-review.md](C1-review.md).
