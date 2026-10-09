The disposable key inputs come from [uplink's MIT test fixtures](https://github.com/pedronaugusto/uplink/tree/869dd0c8bedee138538d0999d61680c5d71ce4be/src/tls/key/testdata). They authenticate no service. The local P-256 chain and explicit time are the C1 verification vectors maintained in this repository under `src/verify/fixtures/vectors`; their generation/provenance is recorded there.

The P-256 and P-384 disposable key inputs are exact copies of `src/credentials/testdata/p256.pkcs8.pem` and `p384.pkcs8.pem`, with the same pinned uplink provenance. These rows measure cold import, scalar validation and public-key derivation; they do not authenticate any service.

`p256.legacy-aes128.pem` is the synthetic credential fixture from
`src/credentials/testdata/`, with its provenance recorded there.
