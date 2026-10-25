# Vendored verified arithmetic

Two upstreams, each formally verified, taken unchanged. cloak computes with them through one
field interface per curve (`src/crypto/field/`). They are never edited here: a change comes
from upstream at a new pinned commit, with this file and the hashes below updated.

## s2n-bignum

- Upstream: https://github.com/awslabs/s2n-bignum
- Commit: 330672965f9ee29eaa27df14c484806d7b8ef0bc (2026-10-23)
- Licence: Apache-2.0 OR ISC OR MIT-0 (`s2n-bignum/LICENSE`, `s2n-bignum/NOTICE`); cloak takes it
  under MIT-0 and keeps the notice.
- Proof: each routine's functional correctness and constant-time behaviour are proved in HOL
  Light against its object code (upstream `x86/proofs`, `arm/proofs`); `non_ct_functions.txt`
  upstream lists the routines that are not constant time, and none of them is taken.
- Assembled by `build.zig` (`addAssembly`) with Zig's assembler, through the preprocessor:
  `-I src/crypto/vendor/shim -I src/crypto/vendor -DWINDOWS_ABI=<0|1>`. The shim headers
  (cloak's, not upstream's) include upstream's header unchanged and then name every routine
  `cloak_<routine>`, private to the image, and on Windows give COFF's function directive.
  x86_64: every target, the Microsoft x64 prologues where `WINDOWS_ABI=1`. AArch64: ELF and
  Mach-O targets (upstream's AArch64 files carry no COFF directives).

Files (path here = path upstream, under `s2n-bignum/`):

| File | SHA-256 |
|---|---|
| `s2n-bignum/arm/p521/bignum_add_p521.S` | `f3866df7bec7f70fb30715eeb5622603671876c5d1978816c111557e96416e97` |
| `s2n-bignum/arm/p521/bignum_inv_p521.S` | `954cc29c9dc223cfce5085c8f1f7701b60e6fd85c94bf00275b3448243f3bcfb` |
| `s2n-bignum/arm/p521/bignum_mul_p521_alt.S` | `dd57d10846250d7b1faecdad370c94d1ea415509bddbdfd44fbeefef1844c9e5` |
| `s2n-bignum/arm/p521/bignum_mul_p521.S` | `5a524305592ea101234ed2c8c2e01b888a071ec104bbc63c178931eef2e437f9` |
| `s2n-bignum/arm/p521/bignum_neg_p521.S` | `77cdd367c549ec86a998a8070a6c09697dfcae9490e4a8efffc84c73a134be39` |
| `s2n-bignum/arm/p521/bignum_sqr_p521_alt.S` | `6dd9677b86efc62980fd7071d487d1cd9bafe421dc1bcf8d73164874c6488da4` |
| `s2n-bignum/arm/p521/bignum_sqr_p521.S` | `52860eb1bbe618afa1f6f3333127d9876aa343be2958de241fc9c817d50a9fbe` |
| `s2n-bignum/arm/p521/bignum_sub_p521.S` | `1ec5441d692fcaad41b37854b824cffebb143da0c71d9aabcfd35918726487de` |
| `s2n-bignum/include/_internal_s2n_bignum_arm.h` | `1cb6d1fedc55ae2ab2f8fad1efd349be2fc2284ea7b5558a787a23448047475b` |
| `s2n-bignum/include/_internal_s2n_bignum_x86.h` | `32e93f25e504f9aef6d16250e4eaf0e6214ca00c6312d44d909d6be13a0c249d` |
| `s2n-bignum/LICENSE` | `41c6380384dc6065456d01405ef0b43e5fe39ba1bccc4ec67801cc66142728e5` |
| `s2n-bignum/NOTICE` | `d4290ed64c2edd0fce1d84e3f9dfb2881240fe534def76b8cd29ed6af683e287` |
| `s2n-bignum/x86/p521/bignum_add_p521.S` | `9debe94be99cc46b75aa8cecb38f1e5969414328cab8f5608802560689a36851` |
| `s2n-bignum/x86/p521/bignum_inv_p521.S` | `973440294b44eaf0fd6751ea14412611eff24f4ea96256394666dd08d847e4ab` |
| `s2n-bignum/x86/p521/bignum_mul_p521_alt.S` | `5f374c4b267e0084bcb70c8cae0a9af0cd3eeaf326f858f5ea4d4097eafc46cd` |
| `s2n-bignum/x86/p521/bignum_mul_p521.S` | `c0f3dd351056b3e34d0857a8cdf4c288d4e8296ba82726ae1d04a1aefaaa6e76` |
| `s2n-bignum/x86/p521/bignum_neg_p521.S` | `2591767632655c8bbbe81dbf03f521b229f857e7dd2078bbe94ede83a86ae232` |
| `s2n-bignum/x86/p521/bignum_sqr_p521_alt.S` | `0effdc98430deba2ace74ec180614f1702bc3f994519121132c3a8da2df91da7` |
| `s2n-bignum/x86/p521/bignum_sqr_p521.S` | `ea0d7bb6d4e66eabcfda4419523485ae7259dc21a59a9bfdd3ec8a7d19f14c0c` |
| `s2n-bignum/x86/p521/bignum_sub_p521.S` | `a965b5d0e3157e04f9cc86142250630419437d371698b51796c8e77761e25180` |

## fiat-crypto

- Upstream: https://github.com/mit-plv/fiat-crypto
- Commit: 1e721c6f18c43b90922e7bc57fd64848e5cff2be (2026-10-19)
- Licence: MIT OR Apache-2.0 OR BSD-1-Clause (`fiat/COPYRIGHT`, `fiat/AUTHORS`); cloak takes it
  under MIT (`fiat/LICENSE-MIT`).
- Proof: the generated code is extracted from Rocq proofs of functional correctness; upstream's
  CI regenerates every committed `fiat-zig/src/*.zig` from the generator at that commit and
  fails on any difference, so the committed file is the generator's output. cloak runs no
  generator. The command line that produced each file is its first line.
- Imported as Zig by `src/crypto/field/<curve>.zig`.

| File | Upstream path | SHA-256 |
|---|---|---|
| `fiat/p521_64.zig` | `fiat-zig/src/p521_64.zig` | `cffc59be1320b1070ac5fc3230f35a15b92d6b6e64b5989c07393772d0950b5e` |

Fields fiat does not commit (P-521's group order n) use cloak's generic constant-time
Montgomery field, `src/crypto/field/Montgomery.zig`, as Go's nistec pairs fiat's base fields
with its generic constant-time scalars; it is tested against wide-integer arithmetic.

To check a file against upstream: `git -C <checkout> show <commit>:<upstream path> | shasum -a 256`
gives the hash listed here. The fiat licence files (`COPYRIGHT`, `AUTHORS`, `LICENSE-MIT`) are
upstream's top-level files at the same commit.
