The P-256 path vectors and explicit time come from this repository's `src/verify/fixtures/vectors`. The Ed25519 disposable key/certificate comes from the retained MIT credential fixtures, originally [uplink](https://github.com/pedronaugusto/uplink/tree/869dd0c8bedee138538d0999d61680c5d71ce4be/src/tls/key/testdata); the certificate is decoded to DER without changing its contents.

P-256/P-384 disposable inputs and exact certificates are copied from the same
MIT credential fixtures at the pinned uplink commit above. The certificates
are decoded to DER without changing contents. They exercise portable key
derivation, certificate matching and final release through the public API.
