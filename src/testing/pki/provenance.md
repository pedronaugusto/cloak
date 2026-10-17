# Test PKI

Disposable keys and certificates for tests only; nothing here is a production credential.
Generated once with OpenSSL 3.6.5. The root is a P-256 CA (`ca.der`, path length 0). The
leaves are signed by it: `p256`, `p384`, `ed25519` and `rsa` (2048-bit) server certificates
for `example.com`, `*.example.org` and `192.0.2.7`, and `client` (P-256) and `client_ed25519`
client-authentication certificates for `client.example.com`. Validity runs from 2026-10-10 for
a hundred years; tests supply their own time.

`p256.key.pem`, `p384.key.pem`, `ed25519.key.pem` and `rsa.key.pem` are the server leaf keys for `PrivateKey.parse`.
`*.secret` hold the raw private scalar (EC) or seed (Ed25519) so a test peer can sign without
a PKCS parser. `client.key.pem` and `client_ed25519.key.pem` are the same client keys for
`PrivateKey.parse`. `rsa-pss-sha256.sig` and `rsa-pkcs1-sha256.sig` are signatures by the RSA
key over the bytes `cloak possession test content` (PSS with a 32-byte salt and MGF1-SHA-256).

Commands: `openssl ecparam -genkey`, `openssl genpkey`, `openssl req -new -x509`,
`openssl x509 -req -CA` with `basicConstraints`, `keyUsage`, `extendedKeyUsage` and
`subjectAltName` extensions, `openssl pkeyutl -sign -rawin`.

The ML-DSA set, made with OpenSSL 4.0.3 (`genpkey -algorithm ML-DSA-*`, keys in its default
PKCS#8 form, the seed and the expanded key together): `mldsa_ca.der`, an ML-DSA-65 root (path
length 0), and the leaves it signs: `mldsa44`, `mldsa65`, `mldsa87` (server certificates as
above), `client_mldsa65` (client authentication) and `p256_pqca` (a P-256 server key under the
ML-DSA root). `mixed_ca.der` is a P-256 root signing `mldsa44_classical`, an ML-DSA-44 server
certificate whose path is classical. Every certificate names its key (subjectKeyIdentifier) and
its issuer's (authorityKeyIdentifier). `*.key.pem` are the leaf keys.
`ed25519_key_encipherment.der` is an Ed25519 server certificate under `mixed_ca` whose keyUsage
adds keyEncipherment, which RFC 8410 forbids a signature-only key.

The delegated-credential set (RFC 9345), made with OpenSSL 4.0.3: `dc_ca.der`, a P-256 root
(path length 0), and the leaves it signs, each carrying the non-critical DelegationUsage
extension (1.3.6.1.4.1.44363.44, NULL): `dc_p256` (a server certificate for `example.com`,
`*.example.org` and `192.0.2.7` on the `p256` key), `dc_client` (client authentication on the
`client` key) and `dc_no_signature` (a server certificate whose keyUsage is keyAgreement alone,
which RFC 9345 section 4.2 refuses as a delegator). Validity from 2026-10-10 for a hundred years;
subject and authority key identifiers named. The delegated credentials themselves are issued by
the tests with `tls.DelegatedCredential.issue`.
