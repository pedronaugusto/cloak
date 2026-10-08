All twenty original credential fixture files are retained from [uplink](https://github.com/pedronaugusto/uplink/tree/869dd0c8bedee138538d0999d61680c5d71ce4be/src/tls/key/testdata), under the MIT licence. They are disposable test-only keys and certificates, with passphrase `correct-horse`. These are format/regression inputs; no extracted TLS engine or signing implementation is included in C1.

`ed25519.enc-low-work.pem` re-encodes the same disposable Ed25519 fixture as PBES2/PBKDF2/HMAC-SHA256/AES-128-CBC with one iteration solely to exercise successful decryption in bounded fuzzing. The fixture password is `correct-horse`; it is public test data, not a recommended key-storage work factor.

`rsa.invalid-qinv-range.der` and `rsa.invalid-d-range.der` re-encode the public
dummy RSA fixture with congruent but noncanonical CRT coefficient/private
exponent. They test range rejection before expensive prime validation.
