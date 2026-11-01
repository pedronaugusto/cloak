NIST's Automated Cryptographic Validation Protocol vectors, from
https://github.com/usnistgov/ACVP-Server at commit 975de31eb83d87039ec88934fdc47d8c312b892d (2026-08-12):
each file is `gen-val/json-files/<name>/internalProjection.json` (the prompts with their expected
results), copied unchanged and renamed `<name>.json`.

| File | SHA-256 |
|---|---|
| ECDSA-SigVer-FIPS186-5.json | 45f9e9425e68b099d9c029e0e75ec04e9cc5943b60fa24cdb4d5af778f350b63 |
| ECDSA-KeyVer-FIPS186-5.json | b8c47508838e8fb9f57eac1fbfda75a4f0b7d340e3a685bc667a19fc8c8c4aaa |
| EDDSA-SigVer-1.0.json | 8556b9c48ef7ff209a9f866ed83e3c3881cfdd3c4c1ee1abe2602da69c1e97b0 |
| EDDSA-SigGen-1.0.json | 794d58fb39f08de4f852d63cb98b95c39bcc38ea42c7d42d09e92c15dadd5d81 |
| XECDH-SSC-RFC7748.json | 8cb5804c341c48caada3a2d37da13b7a37ff2930a77efa9afd2736e708debd37 |
| RSA-SigVer-FIPS186-5.json | 86088be5f46b3b10794357495c6d914af4a4c03b97bd3d185482f2d47d338578 |

`acvp_test.zig` runs the vectors of the curves, hashes and forms cloak has and counts the rest.
Not taken: KAS-ECC-CDH-Component-Sp800-56Ar3 (at this commit only P-192, K-163 and B-163, none of
them cloak's; ECDH is Wycheproof's campaign), EdDSA KeyVer (cloak has no Ed25519 public key check
apart from verification), the SigGen sets of randomized signatures (nothing to compare).

ACVP-Server's licence notice, whole (its README, "License"); the source is the National Institute of
Standards and Technology:

NIST-developed software is provided by NIST as a public service. You may use, copy, and distribute copies of the software in any medium, provided that you keep intact this entire notice. You may improve, modify, and create derivative works of the software or any portion of the software, and you may copy and distribute such modifications or works. Modified works should carry a notice stating that you changed the software and should note the date and nature of any such change. Please explicitly acknowledge the National Institute of Standards and Technology as the source of the software. 

NIST-developed software is expressly provided "AS IS." NIST MAKES NO WARRANTY OF ANY KIND, EXPRESS, IMPLIED, IN FACT, OR ARISING BY OPERATION OF LAW, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, AND DATA ACCURACY. NIST NEITHER REPRESENTS NOR WARRANTS THAT THE OPERATION OF THE SOFTWARE WILL BE UNINTERRUPTED OR ERROR-FREE, OR THAT ANY DEFECTS WILL BE CORRECTED. NIST DOES NOT WARRANT OR MAKE ANY REPRESENTATIONS REGARDING THE USE OF THE SOFTWARE OR THE RESULTS THEREOF, INCLUDING BUT NOT LIMITED TO THE CORRECTNESS, ACCURACY, RELIABILITY, OR USEFULNESS OF THE SOFTWARE.

You are solely responsible for determining the appropriateness of using and distributing the software and you assume all risks associated with its use, including but not limited to the risks and costs of program errors, compliance with applicable laws, damage to or loss of data, programs or equipment, and the unavailability or interruption of operation. This software is not intended to be used in any situation where a failure could cause risk of injury or damage to property. The software developed by NIST employees is not subject to copyright protection within the United States.
