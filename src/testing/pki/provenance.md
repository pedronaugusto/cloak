# Test PKI

Disposable keys and certificates for tests only; nothing here is a production credential.
Generated once with OpenSSL 3.6.5. The root is a P-256 CA (`ca.der`, path length 0). The
leaves are signed by it: `p256`, `p384`, `ed25519` and `rsa` (2048-bit) server certificates
for `example.com`, `*.example.org` and `192.0.2.7`, and `client` (P-256) and `client_ed25519`
client-authentication certificates for `client.example.com`. Validity runs from 2026-10-10 for
a hundred years; tests supply their own time.

`*.secret` hold the raw private scalar (EC) or seed (Ed25519) so a test peer can sign without
a PKCS parser. `client.key.pem` and `client_ed25519.key.pem` are the same client keys for
`PrivateKey.parse`. `rsa-pss-sha256.sig` and `rsa-pkcs1-sha256.sig` are signatures by the RSA
key over the bytes `cloak possession test content` (PSS with a 32-byte salt and MGF1-SHA-256).

Commands: `openssl ecparam -genkey`, `openssl genpkey`, `openssl req -new -x509`,
`openssl x509 -req -CA` with `basicConstraints`, `keyUsage`, `extendedKeyUsage` and
`subjectAltName` extensions, `openssl pkeyutl -sign -rawin`.
