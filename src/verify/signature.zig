//! Public signature verification only. Variable-time exponentiation has public inputs.
const std = @import("std");
const Der = @import("../wire/Der.zig");
const A = @import("../certificate/Algorithm.zig");
const p256 = @import("../crypto/p256.zig");
const p384 = @import("../crypto/p384.zig");
const p521 = @import("../crypto/p521.zig");
const edwards25519 = @import("../crypto/edwards25519.zig");
const mldsa = @import("../crypto/mldsa.zig");
const pkcs1 = @import("../crypto/pkcs1.zig");
pub const Error = error{ InvalidSignature, UnsupportedAlgorithm, InvalidPublicKey };
/// The longest digest an algorithm here uses.
pub const max_digest = 64;
pub fn verify(key: A.PublicKey, algorithm: A.Signature, message: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    switch (algorithm) {
        .unsupported => return error.UnsupportedAlgorithm,
        .ed25519 => switch (key) {
            .ed25519 => |k| {
                if (signature.len != 64 or k.len != 32) return error.InvalidSignature;
                return ed25519(k[0..32], message, signature[0..64]);
            },
            else => return error.InvalidPublicKey,
        },
        // Pure ML-DSA over the message with an empty context, as X.509 (RFC 9881) and TLS
        // (draft-ietf-tls-mldsa) use it.
        .mldsa => |level| switch (key) {
            .mldsa => |k| {
                if (k.level != level) return error.InvalidPublicKey;
                return switch (level) {
                    inline else => |tag| {
                        const M = mldsa.Scheme(tag);
                        if (k.bytes.len != M.public_key_length) return error.InvalidPublicKey;
                        if (signature.len != M.signature_length) return error.InvalidSignature;
                        M.verify(k.bytes[0..M.public_key_length], message, "", signature[0..M.signature_length]) catch return error.InvalidSignature;
                    },
                };
            },
            else => return error.InvalidPublicKey,
        },
        .rsa, .ecdsa, .ecdsa_p1363 => |hash| return verifyHashed(hash, key, algorithm, message, signature),
        .pss => |p| return verifyHashed(p.hash, key, algorithm, message, signature),
    }
}
/// Verifies a signature over the digest of `message` under `hash`, the algorithm's own.
fn verifyHashed(hash: A.Hash, key: A.PublicKey, algorithm: A.Signature, message: []const u8, signature: []const u8) Error!void {
    return switch (hash) {
        inline else => |h| {
            var hasher = Hash(h).init(.{});
            hasher.update(message);
            return verifyDigest(key, algorithm, &hasher.finalResult(), signature);
        },
    };
}
/// RFC 8032 5.1.7, cofactorless (std's `verifyStrict`, RFC 8032's "[S]B = R + [k]A"): S below L,
/// A and R decoded and neither of x = 0, and R's bytes the encoding of [S]B - [k]A. A key whose
/// y is not below p is a bad key; every other failure is a bad signature.
fn ed25519(key: *const [32]u8, message: []const u8, signature: *const [64]u8) Error!void {
    if (!edwards25519.isCanonicalY(key)) return error.InvalidPublicKey;
    const s = signature[32..64];
    if (!edwards25519.isCanonical(s)) return error.InvalidSignature;
    const a = edwards25519.decode(key) orelse return error.InvalidSignature;
    const r = edwards25519.decode(signature[0..32]) orelse return error.InvalidSignature;
    if (a.xIsZero() or r.xIsZero()) return error.InvalidSignature;
    var hash = std.crypto.hash.sha2.Sha512.init(.{});
    hash.update(signature[0..32]);
    hash.update(key);
    hash.update(message);
    const k = edwards25519.reduce64(&hash.finalResult());
    var check: [32]u8 = undefined;
    edwards25519.mulDoubleBasePublic(&check, &k, &a.neg(), s);
    if (!std.mem.eql(u8, &check, signature[0..32])) return error.InvalidSignature;
}

/// The message hash a hashing algorithm signs; Ed25519 has none.
pub fn digestOf(algorithm: A.Signature, message: []const u8, out: *[max_digest]u8) []const u8 {
    @setRuntimeSafety(true);
    const hash: A.Hash = switch (algorithm) {
        .rsa, .ecdsa, .ecdsa_p1363 => |h| h,
        .pss => |p| p.hash,
        .ed25519, .mldsa, .unsupported => unreachable, // callers route these elsewhere
    };
    return switch (hash) {
        inline else => |h| {
            const H = Hash(h);
            H.hash(message, out[0..H.digest_length], .{});
            return out[0..H.digest_length];
        },
    };
}
/// Verifies a signature over an already computed digest of the algorithm's hash (a TLS 1.2
/// CertificateVerify signs the running transcript hash). Ed25519 signs messages, not digests.
pub fn verifyDigest(key: A.PublicKey, algorithm: A.Signature, digest: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    switch (algorithm) {
        .unsupported, .ed25519, .mldsa => return error.UnsupportedAlgorithm,
        .rsa => |h| switch (key) {
            .rsa => |k| {
                if (k.pss_only) return error.UnsupportedAlgorithm;
                return switch (h) {
                    inline else => |hash| rsaPkcs1(Hash(hash), k, digest, signature),
                };
            },
            else => return error.InvalidPublicKey,
        },
        .pss => |p| switch (key) {
            .rsa => |k| {
                if (k.pss) |restriction| if (p.hash != restriction.hash or p.mgf_hash != restriction.mgf_hash or p.salt_length < restriction.salt_length) return error.UnsupportedAlgorithm;
                return switch (p.hash) {
                    inline else => |h| switch (p.mgf_hash) {
                        inline else => |mgf| rsaPss(Hash(h), Hash(mgf), k, p.salt_length, digest, signature),
                    },
                };
            },
            else => return error.InvalidPublicKey,
        },
        .ecdsa => |h| switch (key) {
            .ec => |k| return switch (k.curve) {
                .p256 => switch (h) {
                    inline else => |hash| ecdsa(p256, Hash(hash), .der, k.bytes, digest, signature),
                },
                .p384 => switch (h) {
                    inline else => |hash| ecdsa(p384, Hash(hash), .der, k.bytes, digest, signature),
                },
                .p521 => switch (h) {
                    inline else => |hash| ecdsa(p521, Hash(hash), .der, k.bytes, digest, signature),
                },
            },
            else => return error.InvalidPublicKey,
        },
        .ecdsa_p1363 => |h| switch (key) {
            .ec => |k| return switch (k.curve) {
                .p256 => switch (h) {
                    inline else => |hash| ecdsa(p256, Hash(hash), .p1363, k.bytes, digest, signature),
                },
                .p384 => switch (h) {
                    inline else => |hash| ecdsa(p384, Hash(hash), .p1363, k.bytes, digest, signature),
                },
                .p521 => switch (h) {
                    inline else => |hash| ecdsa(p521, Hash(hash), .p1363, k.bytes, digest, signature),
                },
            },
            else => return error.InvalidPublicKey,
        },
    }
}
fn Hash(comptime h: A.Hash) type {
    @setRuntimeSafety(true);
    return switch (h) {
        .sha256 => std.crypto.hash.sha2.Sha256,
        .sha384 => std.crypto.hash.sha2.Sha384,
        .sha512 => std.crypto.hash.sha2.Sha512,
    };
}
/// ECDSA on one of cloak's curves, public inputs only: the signature as DER (r and s minimal
/// positive INTEGERs, nothing after them) or as r || s at the order's width (IEEE P1363), the
/// digest's leftmost bits as wide as the order.
fn ecdsa(comptime curve: type, comptime H: type, comptime form: enum { der, p1363 }, bytes: []const u8, digest: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (digest.len != H.digest_length) return error.InvalidSignature;
    const width = curve.scalar_length;
    var r: [width]u8 = @splat(0);
    var s: [width]u8 = @splat(0);
    switch (form) {
        .p1363 => {
            if (signature.len != 2 * width) return error.InvalidSignature;
            r = signature[0..width].*;
            s = signature[width..][0..width].*;
        },
        .der => {
            var reader = (Der.single(signature, 0x30) catch return error.InvalidSignature).reader();
            inline for (.{ &r, &s }) |out| {
                const value = Der.integer((reader.expect(2) catch return error.InvalidSignature).value) catch return error.InvalidSignature;
                if (value.len > width) return error.InvalidSignature;
                @memcpy(out[width - value.len ..], value);
            }
            reader.finish() catch return error.InvalidSignature;
        },
    }
    const key = curve.Affine.fromSec1(bytes) catch return error.InvalidPublicKey;
    if (!curve.verify(&key, curve.digestScalar(digest), &r, &s)) return error.InvalidSignature;
}
const rsa_key = @FieldType(A.PublicKey, "rsa");
fn recover(key: rsa_key, signature: []const u8, out: *[512]u8) Error!struct { bytes: []const u8, bits: usize } {
    @setRuntimeSafety(true);
    const Modulus = std.crypto.ff.Modulus(4096);
    // A key built by a caller gets the checks a parsed one got.
    try A.checkRsa(key.modulus, key.exponent);
    // checkRsa's bounds, where the slices below are taken: 2048 to 4096 bits.
    const len = key.modulus.len;
    if (len < 256 or len > out.len) return error.InvalidPublicKey;
    if (signature.len != len) return error.InvalidSignature;
    const n = Modulus.fromBytes(key.modulus, .big) catch return error.InvalidPublicKey;
    const m = Modulus.Fe.fromBytes(n, signature, .big) catch return error.InvalidSignature;
    const e = Modulus.Fe.fromBytes(n, key.exponent, .big) catch return error.InvalidPublicKey;
    const value = n.powPublic(m, e) catch return error.InvalidPublicKey;
    const bytes = out[0..len];
    value.toBytes(bytes, .big) catch return error.InvalidSignature;
    const bits = n.bits();
    if (bits < 2048 or bits > 4096) return error.InvalidPublicKey;
    return .{ .bytes = bytes, .bits = bits };
}
fn rsaPkcs1(comptime H: type, key: rsa_key, digest: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (digest.len != H.digest_length) return error.InvalidSignature;
    var buf: [512]u8 = @splat(0);
    const em = (try recover(key, signature, &buf)).bytes;
    // Exact DigestInfo encoding, including NULL parameters, prevents BER ambiguity.
    const prefix = switch (H.digest_length) {
        32 => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        48 => "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
        64 => "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
        else => unreachable,
    };
    // EM = 0x00 0x01 PS 0x00 DigestInfo, PS at least eight 0xff bytes (RFC 8017 9.2), read
    // from the end: DigestInfo, the separator before it, and PS between.
    const info_len = prefix.len + H.digest_length;
    if (em.len < info_len + 11) return error.InvalidSignature;
    const info = em[em.len - info_len ..];
    const separator = em.len - info_len - 1;
    if (em[0] != 0 or em[1] != 1 or em[separator] != 0) return error.InvalidSignature;
    for (em[2..separator]) |b| if (b != 255) return error.InvalidSignature;
    if (!std.mem.eql(u8, info[0..prefix.len], prefix)) return error.InvalidSignature;
    if (!std.mem.eql(u8, info[prefix.len..], digest)) return error.InvalidSignature;
}
fn rsaPss(comptime H: type, comptime M: type, key: rsa_key, salt_length: usize, digest: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (digest.len != H.digest_length) return error.InvalidSignature;
    var buf: [512]u8 = @splat(0);
    const result = try recover(key, signature, &buf);
    const recovered = result.bytes;
    // recover's bounds, where the positions below are taken: 2048 to 4096 bits in that many bytes.
    if (result.bits < 2048 or result.bits > 4096 or recovered.len > buf.len) return error.InvalidSignature;
    const em_bits = result.bits - 1;
    // emLen is ceil(emBits / 8), so the bits it does not use are fewer than eight.
    const em_len = (em_bits + 7) / 8;
    const unused: u3 = @truncate(em_len * 8 - em_bits);
    if (em_len > recovered.len) return error.InvalidSignature;
    for (recovered[0 .. recovered.len - em_len]) |b| if (b != 0) return error.InvalidSignature;
    const em = recovered[recovered.len - em_len ..];
    // EM = DB || H || 0xbc, DB = PS || 0x01 || salt (RFC 8017 9.1.2).
    if (salt_length > em.len or em.len < H.digest_length + salt_length + 2 or em[em.len - 1] != 0xbc) return error.InvalidSignature;
    const db_len = em.len - H.digest_length - 1;
    const h = em[db_len..][0..H.digest_length];
    const mask: u8 = @as(u8, 255) >> unused;
    if (em[0] & ~mask != 0) return error.InvalidSignature;
    var db: [512]u8 = @splat(0);
    const masked = db[0..db_len];
    @memcpy(masked, em[0..db_len]);
    pkcs1.mgf1(comptime .of(M), h, masked);
    masked[0] &= mask;
    if (salt_length + 1 > masked.len) return error.InvalidSignature;
    const pad_len = masked.len - salt_length - 1;
    for (masked[0..pad_len]) |b| if (b != 0) return error.InvalidSignature;
    if (masked[pad_len] != 1) return error.InvalidSignature;
    var final = H.init(.{});
    final.update(&@as([8]u8, @splat(0)));
    final.update(digest);
    final.update(masked[masked.len - salt_length ..]);
    if (!std.mem.eql(u8, h, &final.finalResult())) return error.InvalidSignature;
}
test {
    _ = @import("signature_test.zig");
}
