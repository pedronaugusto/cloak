//! `PrivateKey.generate` and `PrivateKey.pkcs8`: each kind's key signs what its public half
//! verifies, writes PKCS#8 that `parse` reads back as the same key, and an RSA key also
//! verifies PSS and decrypts OAEP.
const std = @import("std");
const PrivateKey = @import("../PrivateKey.zig");
const certificate = @import("../certificate.zig");
const signature = @import("../verify/signature.zig");
const encryption = @import("../verify/encryption.zig");
const Pem = @import("Pem.zig");

const gpa = std.testing.allocator;
const io = std.testing.io;

fn noise(key: PrivateKey, out: *[PrivateKey.max_noise]u8) []const u8 {
    const length = key.noiseLength();
    io.randomSecure(out[0..length]) catch unreachable; // unreachable: the test Io's source
    return out[0..length];
}

/// Signs a message under `algorithm` with `key` and verifies it under `public`.
fn expectSigns(key: PrivateKey, public: certificate.PublicKey, algorithm: certificate.Algorithm.Signature) !void {
    const message = "cloak generated this key";
    var buffer: [PrivateKey.max_signature]u8 = undefined;
    var random: [PrivateKey.max_noise]u8 = undefined;
    const signed = try key.sign(algorithm, message, noise(key, &random), &buffer);
    try signature.verify(public, algorithm, message, signed);
    try std.testing.expectError(error.InvalidSignature, signature.verify(public, algorithm, "another message", signed));
}

/// The key's PKCS#8, parsed back: the same public half, and a key that signs under it.
fn expectRoundTrip(key: PrivateKey, algorithm: certificate.Algorithm.Signature) !void {
    var der = try key.pkcs8(gpa);
    defer der.deinit(gpa);
    var again = try PrivateKey.parse(gpa, der.expose(), .{});
    defer again.deinit();
    var a: [PrivateKey.max_public_key_info]u8 = undefined;
    var b: [PrivateKey.max_public_key_info]u8 = undefined;
    try std.testing.expectEqualSlices(u8, key.publicKeyInfo(&a), again.publicKeyInfo(&b));
    try expectSigns(again, try certificate.parsePublicKey(key.publicKeyInfo(&a)), algorithm);
    // And through PEM, as a key file holds it.
    var text: std.Io.Writer.Allocating = .init(gpa);
    defer text.deinit();
    try Pem.write(&text.writer, "PRIVATE KEY", der.expose());
    var from_pem = try PrivateKey.parse(gpa, text.written(), .{});
    defer from_pem.deinit();
    try std.testing.expectEqualSlices(u8, key.publicKeyInfo(&a), from_pem.publicKeyInfo(&b));
    std.crypto.secureZero(u8, text.writer.buffer);
}

test "each kind of key generated signs, and its PKCS#8 reads back as itself" {
    const cases = .{
        .{ PrivateKey.Kind.p256, certificate.Algorithm.Signature{ .ecdsa = .sha256 } },
        .{ PrivateKey.Kind.p384, certificate.Algorithm.Signature{ .ecdsa = .sha384 } },
        .{ PrivateKey.Kind.p521, certificate.Algorithm.Signature{ .ecdsa = .sha512 } },
        .{ PrivateKey.Kind.ed25519, certificate.Algorithm.Signature.ed25519 },
        .{ PrivateKey.Kind.mldsa44, certificate.Algorithm.Signature{ .mldsa = .mldsa44 } },
        .{ PrivateKey.Kind.mldsa65, certificate.Algorithm.Signature{ .mldsa = .mldsa65 } },
        .{ PrivateKey.Kind.mldsa87, certificate.Algorithm.Signature{ .mldsa = .mldsa87 } },
    };
    inline for (cases) |case| {
        var key = try PrivateKey.generate(gpa, io, case[0]);
        defer key.deinit();
        var info: [PrivateKey.max_public_key_info]u8 = undefined;
        try expectSigns(key, try certificate.parsePublicKey(key.publicKeyInfo(&info)), case[1]);
        try expectRoundTrip(key, case[1]);
    }
}

test "two keys generated are two keys" {
    var a = try PrivateKey.generate(gpa, io, .p256);
    defer a.deinit();
    var b = try PrivateKey.generate(gpa, io, .p256);
    defer b.deinit();
    var x: [PrivateKey.max_public_key_info]u8 = undefined;
    var y: [PrivateKey.max_public_key_info]u8 = undefined;
    try std.testing.expect(!std.mem.eql(u8, a.publicKeyInfo(&x), b.publicKeyInfo(&y)));
}

test "a generated RSA key signs PKCS#1 v1.5 and PSS, decrypts OAEP, and its PKCS#8 reads back" {
    var key = try PrivateKey.generate(gpa, io, .{ .rsa = .@"2048" });
    defer key.deinit();
    var info: [PrivateKey.max_public_key_info]u8 = undefined;
    const public = try certificate.parsePublicKey(key.publicKeyInfo(&info));
    try std.testing.expectEqual(@as(usize, 256), public.rsa.modulus.len);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01 }, public.rsa.exponent);
    try expectSigns(key, public, .{ .rsa = .sha256 });
    try expectSigns(key, public, .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } });
    const scheme: certificate.Algorithm.Encryption = .{ .oaep = .{ .hash = .sha256, .mgf_hash = .sha256 } };
    var seed: [64]u8 = undefined;
    io.randomSecure(seed[0..encryption.seedLength(scheme)]) catch unreachable; // unreachable: the test Io's source
    var ciphertext: [encryption.max_ciphertext]u8 = undefined;
    const sealed = try encryption.encrypt(public, scheme, "a secret for the key", seed[0..encryption.seedLength(scheme)], &ciphertext);
    var plaintext: [PrivateKey.max_plaintext]u8 = undefined;
    var random: [PrivateKey.max_noise]u8 = undefined;
    try std.testing.expectEqualStrings("a secret for the key", try key.decrypt(scheme, sealed, noise(key, &random), &plaintext));
    try expectRoundTrip(key, .{ .rsa = .sha256 });
}
