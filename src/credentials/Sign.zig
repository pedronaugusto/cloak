//! Signatures with a private key: ECDSA over P-256 and P-384, and Ed25519. The point
//! multiplication by the secret nonce is the masked fixed-window walk of `Curve`, the
//! modular arithmetic is std's constant-time scalar field, and every temporary that held
//! a secret is erased before return. ECDSA nonces are hedged: the draft "Deterministic
//! ECDSA and EdDSA Signatures with Additional Randomness" derives them from the key, the
//! message hash and fresh noise, so a weak or repeated draw alone cannot repeat a nonce
//! and a fault in one signature does not leak the key. Ed25519 follows RFC 8032 and is
//! deterministic.
const std = @import("std");
const Curve = @import("Curve.zig");
const p256 = @import("../crypto/p256.zig");

pub const Error = error{SigningFailed};

/// The longest signature `ecdsa` writes: a DER SEQUENCE of two INTEGERs of 48 bytes.
pub const max_signature = 2 + 2 * (2 + 1 + 48);

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
            return signDigest(secret, &digest, noise, out);
        }

        /// The same signature over an already computed digest of the scheme's hash.
        pub fn signDigest(secret: *const [secret_length]u8, digest: *const [Hash.digest_length]u8, noise: ?*const [noise_length]u8, out: *[max_signature]u8) Error![]const u8 {
            @setRuntimeSafety(true);
            var k = nonce(digest, secret, noise);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k));
            var k_bytes = k.toBytes(.big);
            defer std.crypto.secureZero(u8, &k_bytes);
            if (comptime Point == std.crypto.ecc.P256) return signP256(secret, digest, &k_bytes, out);
            var point = Curve.base(Point, .big, &k_bytes) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
            const r = reduce(Point.Fe.encoded_length, point.affineCoordinates().x.toBytes(.big));
            if (r.isZero()) return error.SigningFailed;
            var d = Scalar.fromBytes(secret.*, .big) catch return error.SigningFailed;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&d));
            if (d.isZero()) return error.SigningFailed;
            var k_inverse = k.invert();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&k_inverse));
            var blend = reduce(secret_length, digest.*).add(r.mul(d));
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

test {
    _ = @import("Sign_test.zig");
}
