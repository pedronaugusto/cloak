Disposable test-only RSA keys; nothing here is a production credential.

`rsa2048.der`, `rsa2056.der`, `rsa3072.der` and `rsa4096.der` are two-prime PKCS#1 keys made
with `openssl genpkey`. 2056 bits gives a modulus of 33 limbs and factors of 17, widths that
are not a multiple of the 2048-bit shapes.

`rsa2056-pkcs1-sha256.sig`, `rsa3072-pkcs1-sha384.sig` and `rsa4096-pkcs1-sha512.sig` are
RSASSA-PKCS1-v1_5 signatures over the bytes `cloak rsa known answer`, made once with OpenSSL
3.6.5: `openssl pkeyutl -sign -rawin -digest <hash> -inkey rsa<bits>.der -keyform DER`.

`rsa3070.der` came from `openssl genpkey -pkeyopt rsa_keygen_bits:3071`, which made a
3070-bit modulus, converted to PKCS#1 with `openssl rsa -traditional`. `rsa2049.der` is a
2049-bit key from a 1025-bit and a 1024-bit prime drawn by a Python Miller-Rabin script (64
rounds), d, dp, dq and qinv from `pow(x, -1, m)`, written by `openssl asn1parse -genconf` and
accepted by `openssl rsa -check`. `rsa2049-pss-sha256.sig` (salt 32) and
`rsa3070-pss-sha384.sig` (salt 48) are RSASSA-PSS signatures over `cloak rsa known answer`
with MGF1 on the signing hash: `openssl pkeyutl -sign -rawin -digest <hash> -pkeyopt
rsa_padding_mode:pss -pkeyopt rsa_pss_saltlen:<len> -pkeyopt rsa_mgf1_md:<hash>`.

`rsa-unbalanced.der` is a valid 3136-bit key whose factors have 2112 and 1024 bits, built to
exceed the private operation's 2048-bit factor limit: the primes from `openssl prime -generate`,
d, dp, dq and qinv computed once with Python's `pow(x, -1, m)`, the DER written by
`openssl asn1parse -genconf` and accepted by `openssl rsa -check`.

`roca/` holds the ROCA detector's own test vectors (crocs-muni/roca df6071d, `roca/tests/data`,
MIT): `mod03.txt` (2048 bits) and `mod09.txt` (4096 bits), `cert04.pem`, `cert05.pem`,
`pubkey03.pem` and `privkey05.pem` have the fingerprint; `mod04.txt`, `cert01.pem`, `cert06.pem`,
`pubkey01.pem` and `privkey03.pem` do not. Copied unchanged.
