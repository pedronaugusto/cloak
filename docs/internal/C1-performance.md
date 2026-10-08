# C1 resource and performance evidence

Current continuation evidence and superseding pin/build status: [C1-next.md](C1-next.md).
The entries below retain their historical source states and counters.

## Work estimate

The default trust owner bounds DER storage at 16 MiB / 4,096 roots. A frozen
issuer index is separate from the peer chain limit of 64 KiB / 16 certificates.
The measured common verifier peak is 7,165 allocator bytes, with a 941-byte
retained receipt and a 2,816-byte parsed Certificate value. These are fixture
measurements, not maximum-path claims.

Native admission has one shared owner and lock: 64 jobs / 16 MiB of charged
cloak allocations. Each request has one backing allocation, including alignment
slack for every input slice. The charge includes retained State, input backing,
selected path bytes, descriptors and name scratch. Framework/CryptoAPI private
allocations are OS-owned and bounded by concurrent job count, not measured as
cloak allocator bytes. Abandoned jobs remain charged until the executor reaps
its retained handle.

RSA preparation is cold setup. Two factors each require 64 fresh-CSPRNG
Miller-Rabin rounds. Each round runs two Montgomery products per encoded factor
bit and a fixed maximum square chain. Schoolbook word products therefore grow
roughly with factor bits times word-width squared. For a 1,024-bit factor this is
hundreds of millions of 32-bit products per two-factor validation. Runtime
safety remains enabled; no signing or TLS handshake throughput is implied.

## Measurement method

Own programs live in bench/. The build compiles them for CI and executes smoke
inputs during targeted tests. Manual timed measurements use Zig 0.17.0,
ReleaseFast, the host CPU target, std guarded curve/hash primitives and owned
RSA Montgomery/AES/3DES kernels. Time uses std.Io.Clock.awake; no CPU/core pinning
is applied. Each cold RSA row performs three independently randomized full
preparations. Keep cold key preparation separate from retained warm identity
use. Host noise is a limitation, and statistical timings never gate CI.

The initial full-width RSA implementation measured 3,204,605.222 us/op; encoded
public-width loops and wiped reusable scalar slots measured 876,986.986 us/op.
Those earlier single runs explain the optimization; the final interleaved
best-of-several results are recorded below before landing.

The first borrowed-Uint A/B regressed RSA preparation by 3.87% (551,386.361 to
572,709.680 us/op, best of three). Inspection found needless u128 subtraction
in every fixed-width reduction limb: the radix already reserves the machine
high bit for borrow. Native-width subtraction restores that invariant without
changing any validation rounds or bounds. Final interleaved evidence follows.

Final interleaved best-of-three cold RSA: 535469.820 us/op before and
520384.722 us/op after (-2.82%). CPU Apple M3 Max, Darwin kernel
25.2.0. The after variant uses native-width borrowed subtraction and retains
all safety, erasure, range and 64-round witness checks. Ed25519 control rows and
all raw runs are in C1-key-ab.json.

## Runtime fixture stack and heap (C1 continuation)

`ci/resource_probe.zig` uses a joined POSIX worker on a caller-owned 2 MiB stack
filled with 0xa5, then scans changed bytes and measures Counting allocator peak.
Zig 0.17.0 ReleaseSafe / Apple M3 Max / Darwin 25.2.0:

| Fixture | Per-call peak heap | Live after cleanup | Entire supplied-stack touched | Below worker entry | Heap + entire touched stack |
|---|---:|---:|---:|---:|---:|
| Common leaf + anchor | 7,165 | 0 | 30,656 | 24,335 | 37,821 |
| 16 duplicate peers / 4,096 duplicate anchors, indexed | 24,061 | 0 | 30,656 | 24,335 | 54,717 |

Root index preparation/storage uses its separate shared page allocator and is
excluded from the per-call heap column. Both fixture calls succeed. Duplicate
anchors deduplicate; this is deliberately not described as a worst issuer flood.
Read-only input arrays live outside the worker stack. Touched-stack bytes include
pthread/runtime/harness cost; the below-entry value is also not an engine-only
peak. A sentinel scan can undercount unchanged sentinel bytes and requires
corroborating instrumentation. CRL/OCSP, worst/default-cap path and embedded
profiles, OS-internal native heap, shared storage amortization and worker storms
are still unmeasured. Static assembly prologues are not substituted for runtime
maxima. No 64/512 KiB or embedded phase gate is closed by these two fixtures.

Reproduction (replace the package hash only if its pin changes):

```sh
zig build-exe -OReleaseSafe -lc -femit-bin=resource-probe --dep cloak --dep shakedown -Mroot=ci/resource_probe.zig -OReleaseSafe -Mcloak=src/root.zig -framework Security -framework CoreFoundation -OReleaseSafe -Mshakedown=zig-pkg/shakedown-0.1.0-BR8U4wgEDgAy2m7lSRtXgIZd_M19hPZ256UdmaPT_9Nj/src/shakedown.zig
./resource-probe
```

The cold-curve import A/B and prior attempt are in C1-curve-ab.json; limitations
and exact private-kernel security blockers are in C1-primitives.md. They do not
replace matched-rival or distribution/worker-tail requirements.
