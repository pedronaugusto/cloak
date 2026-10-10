//! Signing against std's independent implementations and RFC 8032; failure output never prints keys.
const std = @import("std");
const shakedown = @import("shakedown");
const Sign = @import("Sign.zig");

test "ecdsa signatures equal std's for the same key, message and noise" {
    try shakedown.check(std.testing.allocator, {}, ecdsaDifferential, .{ .cases = 64, .seed = 0x51a9e });
}

fn ecdsaDifferential(_: void, case: *shakedown.Case) !void {
    inline for (.{
        .{ Sign.P256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ Sign.P384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
    }) |pair| {
        const Ours, const Std = pair;
        var seed: [Std.KeyPair.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        for (&seed) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var key = Std.KeyPair.generateDeterministic(seed) catch return;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        var message: [200]u8 = undefined;
        const length = shakedown.gen.int(case.source, u8) % message.len;
        for (message[0..length]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var noise: [Ours.noise_length]u8 = undefined;
        for (&noise) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var out: [Sign.max_signature]u8 = undefined;
        for ([_]?*const [Ours.noise_length]u8{ null, &noise }) |hedge| {
            const ours = try Ours.sign(&key.secret_key.bytes, message[0..length], hedge, &out);
            var expected_der: [Std.Signature.der_encoded_length_max]u8 = undefined;
            const expected = (try key.sign(message[0..length], if (hedge) |bytes| bytes.* else null)).toDer(&expected_der);
            try std.testing.expectEqualSlices(u8, expected, ours);
            const parsed = try Std.Signature.fromDer(ours);
            try parsed.verify(message[0..length], key.public_key);
        }
    }
}

test "ecdsa hedged signatures differ with the noise and both verify" {
    const Std = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var key = try Std.KeyPair.generateDeterministic(@splat(7));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    var first: [Sign.max_signature]u8 = undefined;
    var second: [Sign.max_signature]u8 = undefined;
    const a = try Sign.P256.sign(&key.secret_key.bytes, "hello", &@as([32]u8, @splat(1)), &first);
    const b = try Sign.P256.sign(&key.secret_key.bytes, "hello", &@as([32]u8, @splat(2)), &second);
    try std.testing.expect(!std.mem.eql(u8, a, b));
    try (try Std.Signature.fromDer(a)).verify("hello", key.public_key);
    try (try Std.Signature.fromDer(b)).verify("hello", key.public_key);
}

test "ecdsa rejects a secret scalar outside the group order" {
    var out: [Sign.max_signature]u8 = undefined;
    const too_big: [32]u8 = @splat(0xff);
    try std.testing.expectError(error.SigningFailed, Sign.P256.sign(&too_big, "x", null, &out));
    const zero: [48]u8 = @splat(0);
    try std.testing.expectError(error.SigningFailed, Sign.P384.sign(&zero, "x", null, &out));
}

const Vector = struct { seed: []const u8, message: []const u8, signature: []const u8 };

test "ed25519 matches the RFC 8032 vectors" {
    const vectors = [_]Vector{
        .{
            .seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            .message = "",
            .signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        .{
            .seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            .message = "72",
            .signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        .{
            .seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            .message = "af82",
            .signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
    };
    for (vectors) |vector| {
        var key: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(key[0..32], vector.seed);
        const std_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(key[0..32].*);
        key[32..64].* = std_pair.public_key.toBytes();
        var message: [8]u8 = undefined;
        const message_bytes = try std.fmt.hexToBytes(&message, vector.message);
        var expected: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, vector.signature);
        var out: [64]u8 = undefined;
        try Sign.ed25519.sign(&key, message_bytes, &out);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "ed25519 signatures equal std's deterministic signatures and verify" {
    try shakedown.check(std.testing.allocator, {}, edDifferential, .{ .cases = 64, .seed = 0xed25519 });
}

fn edDifferential(_: void, case: *shakedown.Case) !void {
    const Std = std.crypto.sign.Ed25519;
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    for (&seed) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    var pair = try Std.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
    var message: [200]u8 = undefined;
    const length = shakedown.gen.int(case.source, u8) % message.len;
    for (message[0..length]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    var out: [64]u8 = undefined;
    try Sign.ed25519.sign(&pair.secret_key.bytes, message[0..length], &out);
    const expected = try pair.sign(message[0..length], null);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &out);
    try Std.Signature.fromBytes(out).verifyStrict(message[0..length], pair.public_key);
}
