//! Public signature verification only. Variable-time exponentiation has public inputs.
const std = @import("std");
const Der = @import("../wire/Der.zig");
const A = @import("../certificate/Algorithm.zig");
const p256 = @import("../crypto/p256.zig");
pub const Error = error{ InvalidSignature, UnsupportedAlgorithm, InvalidPublicKey };
pub fn verify(key: A.PublicKey, algorithm: A.Signature, message: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    switch (algorithm) {
        .unsupported => return error.UnsupportedAlgorithm,
        .rsa => |h| switch (key) {
            .rsa => |k| {
                if (k.pss_only) return error.UnsupportedAlgorithm;
                return switch (h) {
                    inline else => |hash| rsaPkcs1(Hash(hash), k, message, signature),
                };
            },
            else => return error.InvalidPublicKey,
        },
        .pss => |p| switch (key) {
            .rsa => |k| {
                if (k.pss) |restriction| if (p.hash != restriction.hash or p.mgf_hash != restriction.mgf_hash or p.salt_length < restriction.salt_length) return error.UnsupportedAlgorithm;
                return switch (p.hash) {
                    inline else => |h| switch (p.mgf_hash) {
                        inline else => |mgf| rsaPss(Hash(h), Hash(mgf), k, p.salt_length, message, signature),
                    },
                };
            },
            else => return error.InvalidPublicKey,
        },
        .ecdsa => |h| switch (key) {
            .ec => |k| return switch (k.curve) {
                .p256 => switch (h) {
                    inline else => |hash| ecdsa(std.crypto.ecc.P256, Hash(hash), k.bytes, message, signature),
                },
                .p384 => switch (h) {
                    inline else => |hash| ecdsa(std.crypto.ecc.P384, Hash(hash), k.bytes, message, signature),
                },
            },
            else => return error.InvalidPublicKey,
        },
        .ed25519 => switch (key) {
            .ed25519 => |k| {
                if (signature.len != 64 or k.len != 32) return error.InvalidSignature;
                const pk = std.crypto.sign.Ed25519.PublicKey.fromBytes(k[0..32].*) catch return error.InvalidPublicKey;
                std.crypto.sign.Ed25519.Signature.fromBytes(signature[0..64].*).verifyStrict(message, pk) catch return error.InvalidSignature;
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
fn ecdsa(comptime Curve: type, comptime H: type, bytes: []const u8, message: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = (Der.single(signature, 0x30) catch return error.InvalidSignature).reader();
    for (0..2) |_| {
        _ = Der.integer((r.expect(2) catch return error.InvalidSignature).value) catch return error.InvalidSignature;
    }
    r.finish() catch return error.InvalidSignature;
    if (Curve == std.crypto.ecc.P256) return ecdsaP256(H, bytes, message, signature);
    const E = std.crypto.sign.ecdsa.Ecdsa(Curve, H);
    const key = E.PublicKey.fromSec1(bytes) catch return error.InvalidPublicKey;
    const sig = E.Signature.fromDer(signature) catch return error.InvalidSignature;
    sig.verify(message, key) catch return error.InvalidSignature;
}
const rsa_key = @FieldType(A.PublicKey, "rsa");
fn recover(key: rsa_key, signature: []const u8, out: *[512]u8) Error!struct { bytes: []const u8, bits: usize } {
    @setRuntimeSafety(true);
    const Modulus = std.crypto.ff.Modulus(4096);
    if (signature.len != key.modulus.len) return error.InvalidSignature;
    const n = Modulus.fromBytes(key.modulus, .big) catch return error.InvalidPublicKey;
    const m = Modulus.Fe.fromBytes(n, signature, .big) catch return error.InvalidSignature;
    const e = Modulus.Fe.fromBytes(n, key.exponent, .big) catch return error.InvalidPublicKey;
    const value = n.powPublic(m, e) catch return error.InvalidPublicKey;
    const bytes = out[0..key.modulus.len];
    value.toBytes(bytes, .big) catch return error.InvalidSignature;
    return .{ .bytes = bytes, .bits = n.bits() };
}
fn rsaPkcs1(comptime H: type, key: rsa_key, message: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    var buf: [512]u8 = undefined;
    const em = (try recover(key, signature, &buf)).bytes;
    // Exact DigestInfo encoding, including NULL parameters, prevents BER ambiguity.
    const prefix = switch (H.digest_length) {
        32 => "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20",
        48 => "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30",
        64 => "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40",
        else => unreachable,
    };
    const padding = em.len - prefix.len - H.digest_length - 3;
    if (padding < 8 or em[0] != 0 or em[1] != 1 or em[2 + padding] != 0) return error.InvalidSignature;
    for (em[2..][0..padding]) |b| if (b != 255) return error.InvalidSignature;
    if (!std.mem.eql(u8, em[3 + padding ..][0..prefix.len], prefix)) return error.InvalidSignature;
    var digest: [H.digest_length]u8 = undefined;
    H.hash(message, &digest, .{});
    if (!std.mem.eql(u8, em[em.len - H.digest_length ..], &digest)) return error.InvalidSignature;
}
fn rsaPss(comptime H: type, comptime M: type, key: rsa_key, salt_length: usize, message: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    var buf: [512]u8 = undefined;
    const result = try recover(key, signature, &buf);
    const em_bits = result.bits - 1;
    const em_len = (em_bits + 7) / 8;
    for (result.bytes[0 .. result.bytes.len - em_len]) |b| if (b != 0) return error.InvalidSignature;
    const em = result.bytes[result.bytes.len - em_len ..];
    if (salt_length > em_len or em_len < H.digest_length + salt_length + 2 or em[em.len - 1] != 0xbc) return error.InvalidSignature;
    const db_len = em.len - H.digest_length - 1;
    const h = em[db_len..][0..H.digest_length];
    const unused: u3 = @intCast(em.len * 8 - em_bits); // safe: emLen is ceil(emBits/8), so the difference is below eight.
    const mask: u8 = @as(u8, 255) >> unused;
    if (em[0] & ~mask != 0) return error.InvalidSignature;
    var db: [512]u8 = undefined;
    var offset: usize = 0;
    var counter: u32 = 0;
    while (offset < db_len) : (counter += 1) {
        var mgf = M.init(.{});
        mgf.update(h);
        var count: [4]u8 = undefined;
        std.mem.writeInt(u32, &count, counter, .big);
        mgf.update(&count);
        const digest = mgf.finalResult();
        const len = @min(digest.len, db_len - offset);
        for (0..len) |i| db[offset + i] = em[offset + i] ^ digest[i];
        offset += len;
    }
    db[0] &= mask;
    const pad_len = db_len - salt_length - 1;
    for (db[0..pad_len]) |b| if (b != 0) return error.InvalidSignature;
    if (db[pad_len] != 1) return error.InvalidSignature;
    var digest: [H.digest_length]u8 = undefined;
    H.hash(message, &digest, .{});
    var final = H.init(.{});
    final.update(&@as([8]u8, @splat(0)));
    final.update(&digest);
    final.update(db[db_len - salt_length ..][0..salt_length]);
    if (!std.mem.eql(u8, h, &final.finalResult())) return error.InvalidSignature;
}
/// P-256 through cloak's kernel: the base comb plus a width-5 NAF over the key, public inputs only.
fn ecdsaP256(comptime H: type, bytes: []const u8, message: []const u8, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const key = p256.Affine.fromSec1(bytes) catch return error.InvalidPublicKey;
    const sig = std.crypto.sign.ecdsa.EcdsaP256Sha256.Signature.fromDer(signature) catch return error.InvalidSignature;
    var digest: [H.digest_length]u8 = undefined;
    H.hash(message, &digest, .{});
    // The leftmost 256 bits of the digest, reduced modulo the order.
    const e = p256.Scalar.reduce(p256.Scalar.limbsFromBytes(digest[0..32]));
    if (!p256.verify(key, e, &sig.r, &sig.s)) return error.InvalidSignature;
}
test {
    _ = @import("signature_test.zig");
}
