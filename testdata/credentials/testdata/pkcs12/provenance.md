Disposable test keys and certificates (a P-256 root and intermediate, and P-256, P-384, RSA-2048
and Ed25519 leaves) and their PKCS#12 files from six writers. The password is `correct-horse`
unless a file's name says otherwise (`empty-password`: empty; `unicode`: `pässwörd😀`).

The generators are in trials, branch `cloak-m1`, `cloak/pkcs12/` (`make-openssl.sh`, then
`make-others.sh`), run from this directory on 2026-10-25:

- OpenSSL 4.0.3: `*.default.p12` (PBES2 AES-256-CBC, PBKDF2-SHA256, SHA-256 MAC, 2048 rounds),
  `*.legacy.p12` (`-legacy`: 3DES key, RC2-40 certificates, SHA-1 MAC), `p256.pbmac1*.p12`
  (RFC 9579), `p256.nomac.p12`, `p256.noenc.p12` (key and certificates unencrypted),
  `p256.mixed.p12` (AES-128 key, 3DES certificates, SHA-512 MAC), `p256.pbe-2des-rc2-128.p12`,
  `p256.iter1.p12`, `p256.iter2048.p12`, the empty and non-ASCII password files,
  `truststore.p12` (`-nokeys`), and `p256.pbe-sha1-*.pk8.pem`, `p256.pbes2-iter1.pk8.der`
  (encrypted PKCS#8). `*.der` and `*.key.der` are the certificates and PKCS#8 keys as OpenSSL
  extracts them, for the byte comparisons.
- NSS pk12util 3.128: `nss.p12` (BER, indefinite lengths; AES, 600,000 rounds) and
  `nss.legacy.p12` (3DES and RC2-40 under a SHA-1 MAC).
- go-pkcs12 v0.7.4 (software.sslmate.com/src/go-pkcs12): `go.modern`, `go.modern2023`,
  `go.legacy`, `go.legacydes`, `go.passwordless` (no MAC, no encryption), `go.truststore`.
- Python cryptography 46.0.5: `python.aes`, `python.3des`, `python.unencrypted`.
- macOS `security export` (from a keychain that imported `p256.legacy.p12`): `macos.p12`, the
  identity alone, a SHA-1 MAC of one round.
