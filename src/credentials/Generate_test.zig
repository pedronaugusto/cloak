//! `PrivateKey.generate` and `PrivateKey.pkcs8`: each kind's key signs what its public half
//! verifies, writes PKCS#8 that `parse` reads back as the same key, and an RSA key also
//! verifies PSS and decrypts OAEP. An ML-DSA key is written in RFC 9881's seed form whenever
//! its seed is known, and as its expanded key only when it is not.
const std = @import("std");
const PrivateKey = @import("../PrivateKey.zig");
const certificate = @import("../certificate.zig");
const signature = @import("../verify/signature.zig");
const encryption = @import("../verify/encryption.zig");
const Pem = @import("Pem.zig");
const Der = @import("../wire/Der.zig");

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

/// The public value `agree` takes from a peer: the EC point or the X25519 key.
fn peerValue(info: []const u8) ![]const u8 {
    return switch (try certificate.parsePublicKey(info)) {
        .ec => |ec| ec.bytes,
        .x25519 => |bytes| bytes,
        else => error.TestUnexpectedResult,
    };
}

test "two keys generated for agreement agree, each way, on every curve, and an X25519 key's PKCS#8 reads back" {
    inline for (.{ PrivateKey.Kind.p256, PrivateKey.Kind.p384, PrivateKey.Kind.p521, PrivateKey.Kind.x25519 }) |kind| {
        var a = try PrivateKey.generate(gpa, io, kind);
        defer a.deinit();
        var b = try PrivateKey.generate(gpa, io, kind);
        defer b.deinit();
        var x: [PrivateKey.max_public_key_info]u8 = undefined;
        var y: [PrivateKey.max_public_key_info]u8 = undefined;
        var ab: [PrivateKey.max_shared]u8 = undefined;
        var ba: [PrivateKey.max_shared]u8 = undefined;
        const one = try a.agree(try peerValue(b.publicKeyInfo(&y)), &ab);
        const other = try b.agree(try peerValue(a.publicKeyInfo(&x)), &ba);
        try std.testing.expectEqualSlices(u8, one, other);
        try std.testing.expect(!std.mem.eql(u8, a.publicKeyInfo(&x), b.publicKeyInfo(&y)));
        if (kind == .x25519) {
            var der = try a.pkcs8(gpa);
            defer der.deinit(gpa);
            var again = try PrivateKey.parse(gpa, der.expose(), .{});
            defer again.deinit();
            try std.testing.expectEqualSlices(u8, a.publicKeyInfo(&x), again.publicKeyInfo(&y));
        }
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

/// A key fixture's DER, its PEM decoded.
fn fixture(text: []const u8) !Pem.Block {
    var pem = Pem.init(text);
    return (try pem.next(gpa, 1 << 16)) orelse error.TestUnexpectedResult;
}

/// What a PKCS#8 ML-DSA key's privateKey holds: RFC 9881's seed, expandedKey or both.
fn choice(der: []const u8) ![]const u8 {
    var r = (try Der.single(der, 0x30)).reader();
    _ = try r.expect(0x02);
    _ = try r.expect(0x30);
    const key = (try r.expect(0x04)).value;
    try r.finish();
    return key;
}

test "a generated ML-DSA key's PKCS#8 is RFC 9881's seed form" {
    inline for (.{ PrivateKey.Kind.mldsa44, PrivateKey.Kind.mldsa65, PrivateKey.Kind.mldsa87 }) |kind| {
        var key = try PrivateKey.generate(gpa, io, kind);
        defer key.deinit();
        var der = try key.pkcs8(gpa);
        defer der.deinit(gpa);
        const held = try choice(der.expose());
        try std.testing.expectEqual(@as(usize, 34), held.len);
        try std.testing.expectEqualSlices(u8, &.{ 0x80, 32 }, held[0..2]);
    }
}

test "an ML-DSA key read is written back in the seed form when its form carries the seed, as its expanded key when not" {
    // The seed alone and the expanded key alone come back as they were read.
    for ([_][]const u8{ @embedFile("testdata/mldsa44.seed.pem"), @embedFile("testdata/mldsa87.expanded.pem") }) |text| {
        var read = try fixture(text);
        defer read.deinit(gpa);
        var key = try PrivateKey.parse(gpa, text, .{});
        defer key.deinit();
        var der = try key.pkcs8(gpa);
        defer der.deinit(gpa);
        try std.testing.expectEqualSlices(u8, read.der, der.expose());
    }
    // Both: the seed alone, the same key.
    const both = @embedFile("testdata/mldsa65.both.pem");
    var read = try fixture(both);
    defer read.deinit(gpa);
    var pair = (try Der.single(try choice(read.der), 0x30)).reader();
    const seed = (try pair.expect(0x04)).value;
    var key = try PrivateKey.parse(gpa, both, .{});
    defer key.deinit();
    var der = try key.pkcs8(gpa);
    defer der.deinit(gpa);
    const held = try choice(der.expose());
    try std.testing.expectEqualSlices(u8, &.{ 0x80, 32 }, held[0..2]);
    try std.testing.expectEqualSlices(u8, seed, held[2..]);
    try expectRoundTrip(key, .{ .mldsa = .mldsa65 });
}

test "an ML-DSA key in both forms whose seed and expanded key disagree is refused" {
    const both = @embedFile("testdata/mldsa65.both.pem");
    // The seed's byte, then the expanded key's last.
    for ([_]bool{ true, false }) |in_seed| {
        var read = try fixture(both);
        defer read.deinit(gpa);
        const held = try choice(read.der);
        const at = @intFromPtr(held.ptr) - @intFromPtr(read.der.ptr) + if (in_seed) 6 else held.len - 1;
        read.der[at] ^= 1;
        try std.testing.expectError(error.InvalidKey, PrivateKey.parse(gpa, read.der, .{}));
    }
}

test "an ML-DSA key from its seed (RFC 9964's AKP priv) is the key its PKCS#8 holds, its public key checked when given" {
    const text = @embedFile("testdata/mldsa44.seed.pem");
    var read = try fixture(text);
    defer read.deinit(gpa);
    const seed = (try choice(read.der))[2..];
    var parsed = try PrivateKey.parse(gpa, text, .{});
    defer parsed.deinit();
    var info_buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const info = parsed.publicKeyInfo(&info_buffer);
    const public = info[info.len - certificate.Algorithm.mldsaPublicKeyLength(.mldsa44) ..];
    var key = try PrivateKey.fromComponents(gpa, .{ .mldsa = .{ .level = .mldsa44, .seed = seed, .public = public } });
    defer key.deinit();
    var der = try key.pkcs8(gpa);
    defer der.deinit(gpa);
    try std.testing.expectEqualSlices(u8, read.der, der.expose());
    try expectRoundTrip(key, .{ .mldsa = .mldsa44 });
    // Another level's key from the same seed, a public key that is not the seed's, a short seed.
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .mldsa = .{ .level = .mldsa65, .seed = seed, .public = public } }));
    var other: [1312]u8 = public[0..1312].*;
    other[0] ^= 1;
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .mldsa = .{ .level = .mldsa44, .seed = seed, .public = &other } }));
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .mldsa = .{ .level = .mldsa44, .seed = seed[1..] } }));
}
