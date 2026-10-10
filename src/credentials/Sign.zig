//! Signatures with a private key: ECDSA over P-256 and P-384, and Ed25519. The point
//! multiplication by the secret nonce is the masked fixed-window walk of `Curve`, the
//! modular arithmetic is std's constant-time scalar field, and every temporary that held
//! a secret is erased before return. ECDSA nonces are hedged: the draft "Deterministic
//! ECDSA and EdDSA Signatures with Additional Randomness" derives them from the key, the
//! message hash and fresh noise, so a weak or repeated draw alone cannot repeat a nonce
//! and a fault in one signature does not leak the key. Ed25519 follows RFC 8032 and is
//! deterministic. RSA signs RSASSA-PSS and RSASSA-PKCS1-v1_5 encodings through the blinded,
//! constant-time CRT operation of `crypto/rsa.zig`, which checks every result against the
//! public key before it is written.
const std = @import("std");
const Curve = @import("Curve.zig");
const p256 = @import("../crypto/p256.zig");
const kernel = @import("../crypto/rsa.zig");

pub const Error = error{SigningFailed};

/// The longest ECDSA signature: a DER SEQUENCE of two INTEGERs of 48 bytes.
pub const max_ecdsa_signature = 2 + 2 * (2 + 1 + 48);
/// The longest signature any scheme here writes: RSA's, as long as a 4096-bit modulus.
pub const max_signature = @max(max_ecdsa_signature, rsa.max_length);

/// An ECDSA signature scheme: a curve with the hash of its security level.
pub fn Ecdsa(comptime Point: type, comptime Hash: type) type {
    const Scheme = std.crypto.sign.ecdsa.Ecdsa(Point, Hash);
    comptime std.debug.assert(Hash.digest_length == Point.scalar.encoded_length);
    return struct {
        const Scalar = Point.scalar.Scalar;
        const Prf = std.crypto.auth.hmac.Hmac(Hash);
        pub const secret_length = Point.scalar.encoded_length;
        /// Bytes of fresh noise one signature draws.
        pub const noise_length = Point.scalar.encoded_length;

        /// DER-encodes the signature over `message` by the big-endian secret scalar
        /// into `out` and returns it. `noise` null makes the signature deterministic.
        pub fn sign(secret: *const [secret_length]u8, message: []const u8, noise: ?*const [noise_length]u8, out: *[max_signature]u8) Error![]const u8 {
            @setRuntimeSafety(true);
            var digest: [Hash.digest_length]u8 = undefined;
            Hash.hash(message, &digest, .{});
            var k = nonce(&digest, secret, noise);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
            var k_bytes = k.toBytes(.big);
            defer std.crypto.secureZero(u8, &k_bytes);
            if (comptime Point == std.crypto.ecc.P256) return signP256(secret, &digest, &k_bytes, out);
            var point = Curve.base(Point, .big, &k_bytes) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
            const r = reduce(Point.Fe.encoded_length, point.affineCoordinates().x.toBytes(.big));
            if (r.isZero()) return error.SigningFailed;
            var d = Scalar.fromBytes(secret.*, .big) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&d));
            if (d.isZero()) return error.SigningFailed;
            var k_inverse = k.invert();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k_inverse));
            var blend = reduce(secret_length, digest).add(r.mul(d));
            defer std.crypto.secureZero(u8, std.mem.asBytes(&blend));
            const s = k_inverse.mul(blend);
            if (s.isZero()) return error.SigningFailed;
            const signature: Scheme.Signature = .{ .r = r.toBytes(.big), .s = s.toBytes(.big) };
            var der: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
            const encoded = signature.toDer(&der);
            @memcpy(out[0..encoded.len], encoded);
            return out[0..encoded.len];
        }

        /// P-256 through cloak's own kernel: comb multiplication by the nonce, Montgomery
        /// scalars with a fixed-exponent inversion. Every secret scalar is erased.
        fn signP256(secret: *const [32]u8, digest: *const [32]u8, k_bytes: *const [32]u8, out: *[max_signature]u8) Error![]const u8 {
            @setRuntimeSafety(true);
            const r = p256.signR(k_bytes) orelse return error.SigningFailed;
            // r is part of the signature: public.
            if (r.isZero()) return error.SigningFailed;
            var d = p256.Scalar.fromBytes(secret) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&d));
            if (d.isZeroMask() != 0) return error.SigningFailed;
            var k = p256.Scalar.fromBytes(k_bytes) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
            var k_inverse = k.powModulusMinusTwo();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k_inverse));
            var blend = p256.Scalar.reduce(p256.Scalar.limbsFromBytes(digest)).add(r.mul(d));
            defer std.crypto.secureZero(u8, std.mem.asBytes(&blend));
            const s = k_inverse.mul(blend);
            if (s.isZero()) return error.SigningFailed;
            const signature: Scheme.Signature = .{ .r = r.toBytes(), .s = s.toBytes() };
            var der: [Scheme.Signature.der_encoded_length_max]u8 = undefined;
            const encoded = signature.toDer(&der);
            @memcpy(out[0..encoded.len], encoded);
            return out[0..encoded.len];
        }

        fn reduce(comptime length: usize, bytes: [length]u8) Scalar {
            comptime if (length > 64) @compileError("scalars reduce from at most 64 bytes");
            if (length >= 48) {
                var padded: [64]u8 = @splat(0);
                @memcpy(padded[padded.len - length ..], &bytes);
                return Scalar.fromBytes64(padded, .big);
            }
            var padded: [48]u8 = @splat(0);
            @memcpy(padded[padded.len - length ..], &bytes);
            return Scalar.fromBytes48(padded, .big);
        }

        /// HMAC-DRBG over the key, the hash and the noise, in the draft's order.
        fn nonce(digest: *const [Hash.digest_length]u8, secret: *const [secret_length]u8, noise: ?*const [noise_length]u8) Scalar {
            var k: [Hash.digest_length]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &k);
            var m: [Hash.digest_length + 1 + noise_length + secret_length + Hash.digest_length]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &m);
            var t: [Point.scalar.encoded_length]u8 = @splat(0);
            defer std.crypto.secureZero(u8, &t);
            const m_v = m[0..Hash.digest_length];
            const m_i = &m[m_v.len];
            const m_z = m[m_v.len + 1 ..][0..noise_length];
            const m_x = m[m_v.len + 1 + noise_length ..][0..secret_length];
            const m_h = m[m.len - Hash.digest_length ..];
            @memset(m_v, 0x01);
            m_i.* = 0x00;
            if (noise) |bytes| @memcpy(m_z, bytes);
            @memcpy(m_x, secret);
            @memcpy(m_h, digest);
            Prf.create(&k, &m, &k);
            Prf.create(m_v, m_v, &k);
            m_i.* = 0x01;
            Prf.create(&k, &m, &k);
            Prf.create(m_v, m_v, &k);
            while (true) {
                var offset: usize = 0;
                while (offset < t.len) : (offset += m_v.len) {
                    const end = @min(offset + m_v.len, t.len);
                    Prf.create(m_v, m_v, &k);
                    @memcpy(t[offset..end], m_v[0 .. end - offset]);
                }
                if (Scalar.fromBytes(t, .big)) |candidate| {
                    if (!candidate.isZero()) return candidate;
                } else |_| {}
                m_i.* = 0x00;
                Prf.create(&k, m[0 .. m_v.len + 1], &k);
                Prf.create(m_v, m_v, &k);
            }
        }
    };
}

pub const P256 = Ecdsa(std.crypto.ecc.P256, std.crypto.hash.sha2.Sha256);
pub const P384 = Ecdsa(std.crypto.ecc.P384, std.crypto.hash.sha2.Sha384);

pub const ed25519 = struct {
    const Edwards = std.crypto.ecc.Edwards25519;
    const Sha512 = std.crypto.hash.sha2.Sha512;
    const scalars = Edwards.scalar;

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
        scalars.clamp(&scalar);
        var wide: [64]u8 = undefined;
        defer std.crypto.secureZero(u8, &wide);
        hash = Sha512.init(.{});
        hash.update(expanded[32..64]);
        hash.update(message);
        hash.final(&wide);
        var nonce = scalars.reduce64(wide);
        defer std.crypto.secureZero(u8, &nonce);
        var point = Curve.base(Edwards, .little, &nonce) catch return error.SigningFailed;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        const commitment = point.toBytes();
        hash = Sha512.init(.{});
        hash.update(&commitment);
        hash.update(key[32..64]);
        hash.update(message);
        hash.final(&wide);
        var challenge = scalars.reduce64(wide);
        defer std.crypto.secureZero(u8, &challenge);
        var s = scalars.mulAdd(challenge, scalar, nonce);
        defer std.crypto.secureZero(u8, &s);
        out[0..32].* = commitment;
        out[32..64].* = s;
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
        mgf1(Hash, h_out, db);
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

    /// XORs MGF1(seed) on `Hash` into `out`.
    fn mgf1(comptime Hash: type, seed: []const u8, out: []u8) void {
        @setRuntimeSafety(true);
        var counter: u32 = 0;
        var at: usize = 0;
        while (at < out.len) : (counter += 1) {
            var h = Hash.init(.{});
            h.update(seed);
            var count: [4]u8 = undefined;
            std.mem.writeInt(u32, &count, counter, .big);
            h.update(&count);
            const block = h.finalResult();
            const take = @min(block.len, out.len - at);
            for (out[at..][0..take], block[0..take]) |*o, b| o.* ^= b;
            at += take;
        }
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
