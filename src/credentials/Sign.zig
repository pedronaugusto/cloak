//! Signatures with a private key: ECDSA over P-256, P-384 and P-521, and Ed25519. ECDSA's point
//! multiplication by the secret nonce is cloak's curve (`crypto/weierstrass.zig`), its modular
//! arithmetic the generic constant-time Montgomery field mod n, and every named temporary that
//! held a secret is erased before return; the stack the kernels spill to is the caller's to
//! scrub (`PrivateKey.sign` does). ECDSA nonces are hedged: the draft "Deterministic
//! ECDSA and EdDSA Signatures with Additional Randomness" derives them from the key, the
//! message hash and fresh noise, so a weak or repeated draw alone cannot repeat a nonce
//! and a fault in one signature does not leak the key. Ed25519 follows RFC 8032 and is
//! deterministic. RSA signs RSASSA-PSS and RSASSA-PKCS1-v1_5 encodings through the blinded,
//! constant-time CRT operation of `crypto/rsa.zig`, which checks every result against the
//! public key before it is written.
const std = @import("std");
const edwards25519 = @import("../crypto/edwards25519.zig");
const p256 = @import("../crypto/p256.zig");
const p384 = @import("../crypto/p384.zig");
const p521 = @import("../crypto/p521.zig");
const kernel = @import("../crypto/rsa.zig");
const rfc8017 = @import("../crypto/pkcs1.zig");

pub const Error = error{SigningFailed};

/// The longest ECDSA signature: a DER SEQUENCE (a two-byte length) of two INTEGERs of 66 bytes
/// and a leading zero.
pub const max_ecdsa_signature = 3 + 2 * (2 + 1 + 66);
/// How an ECDSA signature is written: DER, as X.509 and TLS have it, or r || s at the scalar width
/// (IEEE P1363), as JOSE, COSE and WebAuthn have it.
pub const Form = enum { der, p1363 };
/// The longest signature any scheme here writes: RSA's, as long as a 4096-bit modulus.
pub const max_signature = @max(max_ecdsa_signature, rsa.max_length);

/// ECDSA over one of cloak's curves (`crypto/p256.zig`, `p384.zig`, `p521.zig`) with the hash of
/// its security level, hedged nonces as above. RFC 6979's bits2int takes the leftmost bits of a
/// draw as wide as the order (all of a P-256 or P-384 draw, 521 of P-521's 528), and a draw
/// outside [1, n) is drawn again.
pub fn Ecdsa(comptime curve: type, comptime Hash: type) type {
    return struct {
        const Prf = std.crypto.auth.hmac.Hmac(Hash);
        const Scalar = curve.Scalar;
        const width = curve.scalar_length;
        pub const secret_length = width;
        /// Bytes of fresh noise one signature draws.
        pub const noise_length = width;

        /// The signature over `message` by the big-endian secret scalar, in `form`, written
        /// into `out`. `noise` null makes the signature deterministic.
        pub fn sign(secret: *const [secret_length]u8, message: []const u8, noise: ?*const [noise_length]u8, form: Form, out: *[max_signature]u8) Error![]const u8 {
            @setRuntimeSafety(true);
            var digest: [Hash.digest_length]u8 = undefined;
            Hash.hash(message, &digest, .{});
            return signAnyDigest(secret, &digest, noise, form, out);
        }

        /// The signature over a digest of any hash: its leftmost bits when longer than the
        /// order, all of it when shorter, as RFC 6979's bits2int takes it (section 2.3.2). TLS
        /// 1.2 and X.509 bind an ECDSA signature to a hash, not to the curve (RFC 8446
        /// section 4.2.3).
        pub fn signAnyDigest(secret: *const [secret_length]u8, digest: []const u8, noise: ?*const [noise_length]u8, form: Form, out: *[max_signature]u8) Error![]const u8 {
            @setRuntimeSafety(true);
            const e = curve.digestScalar(digest);
            var k_bytes = nonce(&e.toBytes(), secret, noise);
            defer std.crypto.secureZero(u8, &k_bytes);
            const r = curve.signR(&k_bytes) orelse return error.SigningFailed;
            // r is part of the signature: public.
            if (r.isZero()) return error.SigningFailed;
            var d = Scalar.fromBytes(secret) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&d));
            if (d.isZeroMask() != 0) return error.SigningFailed;
            var k = Scalar.fromBytes(&k_bytes) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
            var k_inverse = k.powModulusMinusTwo();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k_inverse));
            // r * d with r public gives d: named, and erased.
            var rd = r.mul(d);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&rd));
            var blend = e.add(rd);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&blend));
            const s = k_inverse.mul(blend);
            if (s.isZero()) return error.SigningFailed;
            return write(&r.toBytes(), &s.toBytes(), form, out);
        }

        /// r and s in the form asked for: r || s at the order's width, or DER's minimal
        /// INTEGERs.
        fn write(r: *const [width]u8, s: *const [width]u8, form: Form, out: *[max_signature]u8) []const u8 {
            switch (form) {
                .p1363 => {
                    out[0..width].* = r.*;
                    out[width..][0..width].* = s.*;
                    return out[0 .. 2 * width];
                },
                .der => {
                    // Each INTEGER: its magnitude without leading zeros, a zero first when the
                    // top bit is set. Each fits 67 bytes (a one-byte length) and the body 138.
                    var at: usize = 3;
                    inline for (.{ r, s }) |value| {
                        var start: usize = 0;
                        while (start < width - 1 and value[start] == 0) start += 1;
                        const pad: usize = @intFromBool(value[start] & 0x80 != 0);
                        const length = width - start + pad;
                        out[at] = 2;
                        out[at + 1] = @intCast(length); // safe: at most 67
                        out[at + 2] = 0;
                        @memcpy(out[at + 2 + pad ..][0 .. width - start], value[start..]);
                        at += 2 + length;
                    }
                    const body = at - 3;
                    if (body < 0x80) {
                        // Short form: move the body up one byte.
                        @memmove(out[2 .. 2 + body], out[3 .. 3 + body]);
                        out[0] = 0x30;
                        out[1] = @intCast(body); // safe: below 0x80
                        return out[0 .. 2 + body];
                    }
                    out[0] = 0x30;
                    out[1] = 0x81;
                    out[2] = @intCast(body); // safe: at most 138
                    return out[0..at];
                },
            }
        }

        /// HMAC-DRBG over the key, the reduced digest (bits2octets) and the noise, in the
        /// draft's order, drawing the order's width and keeping its leftmost bits until a value
        /// in [1, n).
        fn nonce(h: *const [width]u8, secret: *const [width]u8, noise: ?*const [noise_length]u8) [width]u8 {
            const Wide = @Int(.unsigned, 8 * width);
            const spare = 8 * width - Scalar.bits;
            var k: [Hash.digest_length]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &k);
            var m: [Hash.digest_length + 1 + noise_length + width + width]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &m);
            var t: [width + Hash.digest_length]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &t);
            const m_v = m[0..Hash.digest_length];
            const m_i = &m[m_v.len];
            const m_z = m[m_v.len + 1 ..][0..noise_length];
            const m_x = m[m_v.len + 1 + noise_length ..][0..width];
            const m_h = m[m.len - width ..];
            @memset(m_v, 0x01);
            m_i.* = 0x00;
            if (noise) |bytes| @memcpy(m_z, bytes);
            @memcpy(m_x, secret);
            @memcpy(m_h, h);
            Prf.create(&k, &m, &k);
            Prf.create(m_v, m_v, &k);
            m_i.* = 0x01;
            Prf.create(&k, &m, &k);
            Prf.create(m_v, m_v, &k);
            while (true) {
                var offset: usize = 0;
                while (offset < width) : (offset += m_v.len) {
                    Prf.create(m_v, m_v, &k);
                    t[offset..][0..m_v.len].* = m_v.*;
                }
                var candidate: [width]u8 = undefined;
                std.mem.writeInt(Wide, &candidate, std.mem.readInt(Wide, t[0..width], .big) >> spare, .big);
                if (curve.scalarInRange(&candidate)) return candidate;
                std.crypto.secureZero(u8, &candidate);
                m_i.* = 0x00;
                Prf.create(&k, m[0 .. m_v.len + 1], &k);
                Prf.create(m_v, m_v, &k);
            }
        }
    };
}

pub const P256 = Ecdsa(p256, std.crypto.hash.sha2.Sha256);
pub const P384 = Ecdsa(p384, std.crypto.hash.sha2.Sha384);
pub const P521 = Ecdsa(p521, std.crypto.hash.sha2.Sha512);

pub const ed25519 = struct {
    const Sha512 = std.crypto.hash.sha2.Sha512;

    /// The secret key as stored: the 32-byte seed, then the public key.
    pub const key_length = 64;
    pub const signature_length = 64;

    /// Writes the RFC 8032 signature over `message` by the key into `out`.
    pub fn sign(key: *const [key_length]u8, message: []const u8, out: *[signature_length]u8) Error!void {
        @setRuntimeSafety(true);
        var expanded: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &expanded);
        var hash = Sha512.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
        hash.update(key[0..32]);
        hash.final(&expanded);
        var scalar: [32]u8 = expanded[0..32].*;
        defer std.crypto.secureZero(u8, &scalar);
        scalar[0] &= 248;
        scalar[31] = (scalar[31] & 127) | 64;
        var wide: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &wide);
        hash = Sha512.init(.{});
        hash.update(expanded[32..64]);
        hash.update(message);
        hash.final(&wide);
        var nonce = edwards25519.reduce64(&wide);
        defer std.crypto.secureZero(u8, &nonce);
        // A nonce of zero gives the identity as R: a valid signature that verifiers refuse.
        var commitment: [32]u8 = undefined;
        edwards25519.base(&commitment, &nonce);
        if (std.mem.eql(u8, &commitment, &edwards25519.Affine.identity_encoding)) return error.SigningFailed;
        hash = Sha512.init(.{});
        hash.update(&commitment);
        hash.update(key[32..64]);
        hash.update(message);
        hash.final(&wide);
        const challenge = edwards25519.reduce64(&wide);
        out[0..32].* = commitment;
        out[32..64].* = edwards25519.mulAdd(&challenge, &scalar, &nonce);
    }
};

/// RSA signatures (RFC 8017): EMSA-PSS with MGF1 over the message hash and a salt as long as
/// the hash, as TLS's rsa_pss_rsae and rsa_pss_pss schemes require, and EMSA-PKCS1-v1_5 with
/// the exact DigestInfo, for TLS 1.2. The encodings are of public data; the private operation
/// is the kernel's: blinded, constant time in the key, checked against the public key.
pub const rsa = struct {
    pub const Key = kernel.PrivateKey;
    pub const seed_length = kernel.seed_length;
    /// The longest salt: as long as SHA-512's digest.
    pub const max_salt = 64;
    /// Noise for one signature: the blinding seed, then the salt. PKCS#1 v1.5 draws the same
    /// amount and leaves the salt unused, so a key's noise length does not depend on the scheme.
    pub const noise_length = seed_length + max_salt;
    /// The longest signature: the size of a 4096-bit modulus.
    pub const max_length = kernel.max_bytes;

    /// The RSASSA-PSS signature over `message` with MGF1 and the salt both on `Hash`, the salt
    /// `Hash.digest_length` bytes of `noise` after the seed. Returns the modulus-sized signature.
    pub fn pss(comptime Hash: type, key: *const Key, message: []const u8, noise: *const [noise_length]u8, out: *[max_signature]u8) Error![]const u8 {
        @setRuntimeSafety(true);
        var digest: [Hash.digest_length]u8 = undefined;
        Hash.hash(message, &digest, .{});
        return pssDigest(Hash, key, &digest, noise, out);
    }

    /// `pss` over a message whose `Hash` digest is already computed, as a TLS 1.2 transcript is.
    pub fn pssDigest(comptime Hash: type, key: *const Key, digest: *const [Hash.digest_length]u8, noise: *const [noise_length]u8, out: *[max_signature]u8) Error![]const u8 {
        @setRuntimeSafety(true);
        const h_len = Hash.digest_length;
        const salt = noise[seed_length..][0..h_len];
        // emBits = modBits - 1; the encoding fills the low emLen bytes of the modulus-sized input.
        const em_bits = key.bits - 1;
        const em_len = (em_bits + 7) / 8;
        if (em_len < 2 * h_len + 2) return error.SigningFailed;
        var input: [max_signature]u8 = @splat(0);
        const em = input[key.size - em_len .. key.size];
        const db_len = em_len - h_len - 1;
        // H = Hash(0^8 || mHash || salt), after the masked DB.
        var h = Hash.init(.{});
        h.update(&@as([8]u8, @splat(0)));
        h.update(digest);
        h.update(salt);
        const h_out = em[db_len..][0..h_len];
        h.final(h_out);
        // DB = PS || 0x01 || salt, masked with MGF1(H), its bits above emBits cleared.
        const db = em[0..db_len];
        @memset(db, 0);
        db[db_len - h_len - 1] = 1;
        @memcpy(db[db_len - h_len ..], salt);
        rfc8017.mgf1(comptime .of(Hash), h_out, db);
        db[0] &= @as(u8, 0xff) >> @intCast(8 * em_len - em_bits); // safe: emLen is ceil(emBits / 8), so the shift is below eight
        em[em_len - 1] = 0xbc;
        return private(key, input[0..key.size], noise[0..seed_length], out);
    }

    /// The RSASSA-PKCS1-v1_5 signature over `message` with the DigestInfo of `Hash` (SHA-256,
    /// SHA-384 or SHA-512). Deterministic: only the blinding draws on `noise`.
    pub fn pkcs1(comptime Hash: type, key: *const Key, message: []const u8, noise: *const [noise_length]u8, out: *[max_signature]u8) Error![]const u8 {
        @setRuntimeSafety(true);
        var digest: [Hash.digest_length]u8 = undefined;
        Hash.hash(message, &digest, .{});
        return pkcs1Digest(Hash, key, &digest, noise, out);
    }

    /// `pkcs1` over a message whose `Hash` digest is already computed.
    pub fn pkcs1Digest(comptime Hash: type, key: *const Key, digest: *const [Hash.digest_length]u8, noise: *const [noise_length]u8, out: *[max_signature]u8) Error![]const u8 {
        @setRuntimeSafety(true);
        const prefix = digestInfo(Hash);
        const t_len = prefix.len + Hash.digest_length;
        const k = key.size;
        if (k < t_len + 11) return error.SigningFailed;
        // EM = 0x00 || 0x01 || PS (0xff, at least eight) || 0x00 || DigestInfo || H.
        var em: [max_signature]u8 = undefined;
        em[0] = 0;
        em[1] = 1;
        @memset(em[2 .. k - t_len - 1], 0xff);
        em[k - t_len - 1] = 0;
        @memcpy(em[k - t_len ..][0..prefix.len], prefix);
        @memcpy(em[k - Hash.digest_length ..][0..Hash.digest_length], digest);
        return private(key, em[0..k], noise[0..seed_length], out);
    }

    /// The DER DigestInfo prefix for a hash: AlgorithmIdentifier with NULL parameters, then the
    /// OCTET STRING header (RFC 8017 9.2 note 1).
    fn digestInfo(comptime Hash: type) []const u8 {
        const sha2 = std.crypto.hash.sha2;
        return switch (Hash) {
            sha2.Sha256 => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
            sha2.Sha384 => "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
            sha2.Sha512 => "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
            else => @compileError("PKCS#1 v1.5 signs with SHA-256, SHA-384 or SHA-512"),
        };
    }

    /// The private operation on the encoded message; the kernel writes `out` only after the
    /// result has passed its public check.
    fn private(key: *const Key, em: []const u8, seed: *const [seed_length]u8, out: *[max_signature]u8) Error![]const u8 {
        @setRuntimeSafety(true);
        key.private(em, seed, out[0..key.size]) catch return error.SigningFailed;
        return out[0..key.size];
    }
};

test {
    _ = @import("Sign_test.zig");
}
