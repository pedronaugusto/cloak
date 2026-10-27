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
| `s2n-bignum/LICENSE` | `41c6380384dc6065456d01405ef0b43e5fe39ba1bccc4ec67801cc66142728e5` |
| `s2n-bignum/NOTICE` | `d4290ed64c2edd0fce1d84e3f9dfb2881240fe534def76b8cd29ed6af683e287` |
| `s2n-bignum/arm/curve25519/curve25519_x25519.S` | `ad7bff4496bf394c3612757d22dc839cde861265a702c9c246fc8ea870b55cba` |
| `s2n-bignum/arm/curve25519/curve25519_x25519_alt.S` | `e667d0667db1592f4503b29d09c763fe23e4948478f11cbf2c0e8ac290047c80` |
| `s2n-bignum/arm/curve25519/curve25519_x25519base.S` | `d6195d8a6360559bd1925d3e581f2b59320d378876df94a46bd655318c7c7e99` |
| `s2n-bignum/arm/curve25519/curve25519_x25519base_alt.S` | `a4d4108d17fec73602c31bea8fc91f95492c017d16638c82acd4ae6eede98da5` |
| `s2n-bignum/arm/p256/bignum_montinv_p256.S` | `339a8276bb1aa3721c2dc9f76abbd28b3d597983446427a68c39393a589ec650` |
| `s2n-bignum/arm/p256/bignum_montmul_p256.S` | `eb892a473af5ea1933912732b5036cff6b54a5c75af774223b71d57d0d884fc1` |
| `s2n-bignum/arm/p256/bignum_montmul_p256_alt.S` | `74f06eedcfbd25328a7a09bbe55d3c90c7f7ef58bb9532ef981bb809d0e63406` |
| `s2n-bignum/arm/p256/bignum_montsqr_p256.S` | `24d868666a7d9483ce0e8dc50bc0902e7a6f229150ba4f1b7b6db69f2e646f28` |
| `s2n-bignum/arm/p256/bignum_montsqr_p256_alt.S` | `23c1e644bee9135b22ffa6a229098b046e5d1677a330c22c59c505a61fd74924` |
| `s2n-bignum/arm/p384/bignum_montinv_p384.S` | `ad1b6d4c921d284e2b4819e4b83ee451571487fa52a558926b3ba9ce7a352a41` |
| `s2n-bignum/arm/p384/bignum_montmul_p384.S` | `bbbe66f0f71abf979086591a9463d05f48ffc4d0840c2a2ad4268dadf18cd12b` |
| `s2n-bignum/arm/p384/bignum_montmul_p384_alt.S` | `5b119f852fe2dc36f3eeaec1cfb4e056bd40b71739fac6a91bbf30200af3d7d8` |
| `s2n-bignum/arm/p384/bignum_montsqr_p384.S` | `e151526b29b9a284ecbb374ad579f3aa9f9a9b8f64868e88d9f05f78e99367cc` |
| `s2n-bignum/arm/p384/bignum_montsqr_p384_alt.S` | `303630570ee478bb568c76afd042284c6d5629a5235f0d0c430b173602d95caf` |
| `s2n-bignum/arm/p521/bignum_add_p521.S` | `f3866df7bec7f70fb30715eeb5622603671876c5d1978816c111557e96416e97` |
| `s2n-bignum/arm/p521/bignum_inv_p521.S` | `954cc29c9dc223cfce5085c8f1f7701b60e6fd85c94bf00275b3448243f3bcfb` |
| `s2n-bignum/arm/p521/bignum_mul_p521.S` | `5a524305592ea101234ed2c8c2e01b888a071ec104bbc63c178931eef2e437f9` |
| `s2n-bignum/arm/p521/bignum_mul_p521_alt.S` | `dd57d10846250d7b1faecdad370c94d1ea415509bddbdfd44fbeefef1844c9e5` |
| `s2n-bignum/arm/p521/bignum_neg_p521.S` | `77cdd367c549ec86a998a8070a6c09697dfcae9490e4a8efffc84c73a134be39` |
| `s2n-bignum/arm/p521/bignum_sqr_p521.S` | `52860eb1bbe618afa1f6f3333127d9876aa343be2958de241fc9c817d50a9fbe` |
| `s2n-bignum/arm/p521/bignum_sqr_p521_alt.S` | `6dd9677b86efc62980fd7071d487d1cd9bafe421dc1bcf8d73164874c6488da4` |
| `s2n-bignum/arm/p521/bignum_sub_p521.S` | `1ec5441d692fcaad41b37854b824cffebb143da0c71d9aabcfd35918726487de` |
| `s2n-bignum/include/_internal_s2n_bignum_arm.h` | `1cb6d1fedc55ae2ab2f8fad1efd349be2fc2284ea7b5558a787a23448047475b` |
| `s2n-bignum/include/_internal_s2n_bignum_x86.h` | `32e93f25e504f9aef6d16250e4eaf0e6214ca00c6312d44d909d6be13a0c249d` |
| `s2n-bignum/x86/curve25519/curve25519_x25519.S` | `c0b55b787efa4e75b20c7d0e61d630996ba33b276478fdbfc98aad6dd716879b` |
| `s2n-bignum/x86/curve25519/curve25519_x25519_alt.S` | `6019f718d94aa334d50c8b1caaee53aa4dabc1bfda76f785364d0c727e5e1b29` |
| `s2n-bignum/x86/curve25519/curve25519_x25519base.S` | `12a43626622921f5ab490b10e77203fe13e28b77212926c71069c34710b567cf` |
| `s2n-bignum/x86/curve25519/curve25519_x25519base_alt.S` | `aa82a1fd40e3af98d4b3c7a2b464f8868895f372644dd5b8aba3a8fcf14a8b39` |
| `s2n-bignum/x86/p256/bignum_montinv_p256.S` | `91c61153ac18116a2a1fd6bdb9f1be4fffed53deca44923732632a8837fd4339` |
| `s2n-bignum/x86/p256/bignum_montmul_p256.S` | `67054aa23bc758c6c63126d4b72653a9a8bce9edf3fb5920daacb12a965f5920` |
| `s2n-bignum/x86/p256/bignum_montmul_p256_alt.S` | `57abd32623288e7fd69c7d14a9322450bc7f96877f97079e67655984aa1f8885` |
| `s2n-bignum/x86/p256/bignum_montsqr_p256.S` | `d2423a6d39fb9e118a4f10f8a8f3cd9bca5d833474a67a6ab194f4cb300d3fd8` |
| `s2n-bignum/x86/p256/bignum_montsqr_p256_alt.S` | `ba968e36c0b3abab3bfbcf0489964e76e1562ba1151de694369c65a58484222a` |
| `s2n-bignum/x86/p384/bignum_montinv_p384.S` | `3c5d2f78be30b06585df2e6bccf0a279479b3012f08fad4fa318c698bbe70e49` |
| `s2n-bignum/x86/p384/bignum_montmul_p384.S` | `1ffc9eb8afafe1519eee4b8b6f68bb8682300c70f2b1a06b77979cb9d4025c38` |
| `s2n-bignum/x86/p384/bignum_montmul_p384_alt.S` | `355f658a27fca7aa3848dcf8d5b7fde10eec8a77461b5a29a0af3badaf25299e` |
| `s2n-bignum/x86/p384/bignum_montsqr_p384.S` | `1a1e6bcb6abf6bc2509095596ef0e4029be378c7593735cb777a7d84d907417f` |
| `s2n-bignum/x86/p384/bignum_montsqr_p384_alt.S` | `e6a830270ec90304b9fadff85a94ec42cd0a6b8f6333ec1ebac65230d09ff5c3` |
| `s2n-bignum/x86/p521/bignum_add_p521.S` | `9debe94be99cc46b75aa8cecb38f1e5969414328cab8f5608802560689a36851` |
| `s2n-bignum/x86/p521/bignum_inv_p521.S` | `973440294b44eaf0fd6751ea14412611eff24f4ea96256394666dd08d847e4ab` |
| `s2n-bignum/x86/p521/bignum_mul_p521.S` | `c0f3dd351056b3e34d0857a8cdf4c288d4e8296ba82726ae1d04a1aefaaa6e76` |
| `s2n-bignum/x86/p521/bignum_mul_p521_alt.S` | `5f374c4b267e0084bcb70c8cae0a9af0cd3eeaf326f858f5ea4d4097eafc46cd` |
| `s2n-bignum/x86/p521/bignum_neg_p521.S` | `2591767632655c8bbbe81dbf03f521b229f857e7dd2078bbe94ede83a86ae232` |
| `s2n-bignum/x86/p521/bignum_sqr_p521.S` | `ea0d7bb6d4e66eabcfda4419523485ae7259dc21a59a9bfdd3ec8a7d19f14c0c` |
| `s2n-bignum/x86/p521/bignum_sqr_p521_alt.S` | `0effdc98430deba2ace74ec180614f1702bc3f994519121132c3a8da2df91da7` |
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
| `fiat/AUTHORS` | `AUTHORS` | `ad74c036a6afaedc418fed65f171c877c2f74a4c70938a03930aa11c98a20508` |
| `fiat/COPYRIGHT` | `COPYRIGHT` | `6c935d087a2992d0f092665400a2fa99c98db58d96fbe29368f8f48182bed9aa` |
| `fiat/LICENSE-MIT` | `LICENSE-MIT` | `0034712d5e97a4f5b900a160a5c19d582b740d8e0638b4e44fd07e7b492dcd13` |
| `fiat/curve25519_64.zig` | `fiat-zig/src/curve25519_64.zig` | `516dcf3b161ecf3de43ebdf599625824b469c7e5c1c5e0c444217715c58c4c61` |
| `fiat/p256_64.zig` | `fiat-zig/src/p256_64.zig` | `302d5b040a93fb608bc85521ee63079eaf4c2e68ae457c360f1f9c0f2d3abffb` |
| `fiat/p256_scalar_64.zig` | `fiat-zig/src/p256_scalar_64.zig` | `d2873c59a1e566bd23e00fa140facaa54d9f0924861a730bdc4050fc2d86785f` |
| `fiat/p384_64.zig` | `fiat-zig/src/p384_64.zig` | `90705a96ff05b0b6a0e5dcb82ba3721cf8a6fe22ad72cab9cb523af2ba96fdc3` |
| `fiat/p384_scalar_64.zig` | `fiat-zig/src/p384_scalar_64.zig` | `9296f96bf39b49d8a93c05ae13aec87607bfcf47c2d019bf6f7cfe990fb989dd` |
| `fiat/p521_64.zig` | `fiat-zig/src/p521_64.zig` | `cffc59be1320b1070ac5fc3230f35a15b92d6b6e64b5989c07393772d0950b5e` |

The curves' scalar fields (their group orders n) use cloak's generic constant-time Montgomery
field, `src/crypto/field/Montgomery.zig`, for every curve, as Go's nistec pairs fiat's base
fields with its generic constant-time scalars: fiat commits no scalar field for P-521, and one
way for every scalar field beats a verified one for two of three. It is tested against
wide-integer arithmetic.

To check a file against upstream: `git -C <checkout> show <commit>:<upstream path> | shasum -a 256`
gives the hash listed here. The fiat licence files (`COPYRIGHT`, `AUTHORS`, `LICENSE-MIT`) are
upstream's top-level files at the same commit.
