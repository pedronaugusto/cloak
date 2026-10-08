# C1 private-primitive evidence and open gates

## Scope

`credentials/Curve.zig` owns a borrowed-scalar, four-bit-window base-point
multiplier for P-256, P-384 and Edwards25519 credential construction. It
precomputes only public base-point tables at compile time, scans every table
entry at fixed addresses, and reads scalar bytes in public loop order. It
clamps an owned Ed25519 expanded scalar in place. P-curves validate `0 < s < n`
(the zero result is rejected), then borrow big-endian bytes without an
endian-swapped scalar array. The exact std `clampedMul` local `t` and P-curve
`mul` local `s` are no longer reached by private key construction. Caller
wipes are not represented as callee-copy erasure. Public signature verification
still uses the std public-operation API intentionally.

The named accumulator, selected point, digit and mask are one scratch owner,
wiped on success and identity rejection. Runtime safety remains enabled in
all owned functions. No secret selects a source-level branch or table index;
the first-iteration shortcut depends only on the public loop counter. Rejected
key validity is an explicitly observable final predicate. `.none` side-channel
options fail compilation. This source argument does not establish generated
constant time or complete erasure.

## Provenance and regression

The fixed-window/precomputation/selection loops adapt installed Zig 0.17.0
`pcMul16`/`pcSelect`; the Zig contributors' MIT notice is retained in LICENSE.
The installed sources are unchanged. SHA-256 source pins:

- `crypto/pcurves/p256.zig`: b45d8e9026c21f4f05a41c364e57bd1b174e72ed42165959b05ccaa7183ae727
- `crypto/pcurves/p384.zig`: e76b5ff2b137ceb913fc5c61d815e05db9dbc49c0d465b80ea5c52a74ff6e2e4
- `crypto/25519/edwards25519.zig`: 1b3bb241dc6bc275a7558e1983a9311f307d494a1f70ad94751fad2bd7aba988

`Curve_test.zig` compares 96 synthetic scalar cases on each curve against the
independent std operation, including both P-curve byte orders (seed 0xc1b017).
Zero and subgroup order reject. RFC8032 public-key derivation and existing
credential format/matching vectors pass. The new SEC1 regression failed
before the range guard: `n+1`, without an explicit public point, became an
accepted private key. It now returns InvalidKey for P-256 and P-384; failure
output is boolean/status only and all test staging is wiped.

## Generated code: blocker remains

`ci/primitive_probe.zig` exports three no-inline inspection entry points.
`C1-curve-assembly.txt` retains hashes, prologues, branches, zero-store excerpts
and a concrete carry branch. Full generated assembly can be reproduced using:

```sh
zig build-obj -OReleaseFast -target aarch64-macos -fstrip -femit-asm=curve-aarch64.s -fno-emit-bin --dep credentials -Mroot=ci/primitive_probe.zig -OReleaseFast -target aarch64-macos -Mcredentials=src/credentials.zig
zig build-obj -OReleaseFast -target x86_64-linux -fstrip -femit-asm=curve-x86_64.s -fno-emit-bin --dep credentials -Mroot=ci/primitive_probe.zig -OReleaseFast -target x86_64-linux -Mcredentials=src/credentials.zig
```

In x86-64 baseline code, P-256 and P-384 field additions/reductions inlined
from std Fiat select logic generate conditional jumps controlled by secret
carry/reduction results. For example P256 `test dil, 1; je .LBB195_8` follows
field arithmetic, not the public scalar loop counter. Both targets erase named
scratch but leave other point temporaries/spills outside that wipe range.
These are concrete open F03/F04/F06/F93 gates. All std field callees, hashing,
KDF, RSA preparation, AES/DES schedules and target/optimization/dispatch
combinations still need complete secret-operation and spill review. Neither
source masks nor `.none` rejection repairs a compiler-created branch.

## Timing and performance

Class-separated 24,000-sample curves probe: random class ordering, leading-zero
versus full random synthetic scalars, entropy outside timed interval, awake
clock; prints only public timing distributions. A non-significant result is
not constant-time proof and one arm64 CPU does not cover x86/BSD/Windows/wasm.
Final source SHA-256 `85439b65a2c7a192e63067b666c1fa2c87dcacde78ae4202f9d0fe113c0b0915`.
Final host probe (`zig build-exe -OReleaseFast -mcpu=native --dep credentials
-Mroot=ci/primitive_probe.zig -OReleaseFast -mcpu=native
-Mcredentials=src/credentials.zig`, then execute):

| Curve | Class counts | Mean ns (0 / 1) | Variance (0 / 1) | Welch t |
|---|---|---|---|---|
| P256 | 12047 / 11953 | 71441.140 / 71464.929 | 2760730.303 / 3157076.971 | -1.071 |
| P384 | 11991 / 12009 | 211232.257 / 211150.764 | 17773878.504 / 14986818.697 | 1.560 |
| Edwards | 11944 / 12056 | 29110.582 / 31461.094 | 798035256.857 / 36312797900.400 | -1.340 |

Scheduling outliers are present. Nothing in these arm64 statistics closes the
concrete baseline x86-64 branches or the all-target erasure obligation.

`C1-curve-ab.json` retains all seven interleaved original/final cold-import
batches and the earlier attempt. Same host Apple M3 Max, Darwin 25.2.0,
Zig 0.17.0 ReleaseFast `mcpu=native`, 5,000 imports per curve, RSA three imports
as unchanged control. No core pinning. Best/median and batch p95/max are
reported; batch p95 is not per-operation tail latency. The earlier attempt
regressed P256/P384 best samples by 0.15%/0.10%. Removing the first public
identity addition yielded best changes Ed -1.66%, P256 -0.072%, P384 -0.472%;
P256 median still changed 85.520 to 85.576 us/op and P384 has an outlier.
These measurements do not establish a statistically resolved no-regression
claim or close matched-rival/embedded/worker-tail gates.

## Adoption

Concrete scalar-copy remediation and deterministic vectors are ready for
independent review. Complete secret erasure and generated constant time are
not closed. C1 must not fast-forward main or unblock C2/C0 on this evidence.

Supporting std field/compiler source pins for the carry-branch finding:

- `crypto/pcurves/common.zig`: 630e4bd0bb8e8fb1853f9033b62fd75d0eab573ea13cc6048a32ef8cddf011a8
- `crypto/pcurves/p256/p256_64.zig`: 2e26333d4d15e9e216038e2652e7fbd13dbae61a8424d9052a70c07432a66a67
- `crypto/pcurves/p384/p384_64.zig`: e8b7d0b943464e5593bed156abcf7dfd261c0cf810dff9b76d68b2e686949493
- `crypto/25519/field.zig`: e94bca77c3be0655f7c7cda95d3ec4643f5a8a1d4e49326a1cb9af6e0790b4a1
- Compiler executable SHA-256: 1c5f706db0ed6d55451940f31dc05a6177d05696bc1fa5d853696d04c718b523; `zig version`: 0.17.0.
