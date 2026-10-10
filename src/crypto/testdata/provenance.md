Disposable test-only RSA keys; nothing here is a production credential.

`rsa2048.der`, `rsa2056.der`, `rsa3072.der` and `rsa4096.der` are two-prime PKCS#1 keys made
with `openssl genpkey`. 2056 bits gives a modulus of 33 limbs and factors of 17, widths that
are not a multiple of the 2048-bit shapes.

`rsa2056-pkcs1-sha256.sig`, `rsa3072-pkcs1-sha384.sig` and `rsa4096-pkcs1-sha512.sig` are
RSASSA-PKCS1-v1_5 signatures over the bytes `cloak rsa known answer`, made once with OpenSSL
3.6.5: `openssl pkeyutl -sign -rawin -digest <hash> -inkey rsa<bits>.der -keyform DER`.

`rsa-unbalanced.der` is a valid 3136-bit key whose factors have 2112 and 1024 bits, built to
exceed the private operation's 2048-bit factor limit: the primes from `openssl prime -generate`,
d, dp, dq and qinv computed once with Python's `pow(x, -1, m)`, the DER written by
`openssl asn1parse -genconf` and accepted by `openssl rsa -check`.
