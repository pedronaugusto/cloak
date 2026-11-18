Certification requests written by other implementations (2026-10-29, Apple M3), each over a key made for it
and thrown away: subject C=PT, CN=api.example.com, and an extensionRequest asking for the subjectAltName
DNS:api.example.com. Public test data.

- `openssl.<kind>.csr.der`: OpenSSL 4.0.3, `openssl req -new -newkey <kind> -nodes -subj /C=PT/CN=api.example.com
  -addext subjectAltName=DNS:api.example.com -outform DER`, the key `ec -pkeyopt ec_paramgen_curve:P-256`,
  `ed25519`, `ML-DSA-44`, and `rsa:2048 -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest`
  (RSASSA-PSS).
- `go.<kind>.csr.der`: Go 1.27.1 `crypto/x509.CreateCertificateRequest` with `Subject` {Country PT, CommonName
  api.example.com} and `DNSNames` {api.example.com}, the key from `ecdsa.GenerateKey(elliptic.P521())`,
  `ed25519.GenerateKey`, `rsa.GenerateKey(2048)` (PKCS#1 v1.5, SHA-256) and `mldsa.GenerateKey(mldsa.MLDSA65())`.

The writers are trials `cloak/issue` (`go/main.go`'s `write`, and the OpenSSL commands in `src/main.zig`), which
also checks every kind of both: 22 requests read, verified and issued from.
