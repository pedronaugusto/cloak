const std = @import("std");
const shakedown = @import("shakedown");
const Ecdh = @import("Ecdh.zig");

fn hex(comptime value: []const u8) [value.len / 2]u8 {
    var bytes: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, value) catch unreachable;
    return bytes;
}

// Independent derivation by a production TLS library, recorded in the fixture notes.
test "credential ecdh agrees with an independently derived P-256 secret" {
    const a = hex("26390c2a1a47e7a8446b9c4c548f389269dc05af556942a24b6a842244c5224a");
    const b = hex("48ecb129c78ad2d343ed2ed511e127aee333adfb04895f27d59b79580925c7b2");
    const a_public = hex("048e598db42ff9db5781d2027dca42a04cce002901cb43a7ea8f9f1cbfec4626eb8a3e9f6b7c81c590c827a163d3c09a491b10c23f070f7fe8c1dc8e608c9d5412");
    const b_public = hex("049efdb00473f6ca26b5b631d5b802241f059acd7bfa616eed59c898922912e774fa7d9e7d1f30dcfdf26bb72da5d19a265d366da66ec4f89f78236f15ab4838ce");
    var derived: [65]u8 = undefined;
    try Ecdh.P256.publicKey(&a, &derived);
    try std.testing.expectEqualSlices(u8, &a_public, &derived);
    try Ecdh.P256.publicKey(&b, &derived);
    try std.testing.expectEqualSlices(u8, &b_public, &derived);
    var shared: [32]u8 = undefined;
    try Ecdh.P256.agree(&a, &b_public, &shared);
    try std.testing.expectEqualSlices(u8, &hex("294ba8179046821b9ea1fecf9b8e5f82221e653c4c5fc38f69aa94ceb4f3ab7a"), &shared);
    var other: [32]u8 = undefined;
    try Ecdh.P256.agree(&b, &a_public, &other);
    try std.testing.expectEqualSlices(u8, &shared, &other);
}

test "credential ecdh agrees with an independently derived P-384 secret" {
    const a = hex("268c99c75c7aed6543b37fdd78d8edcb98ec24ed88fc3b570c7b4675965b0f795970f0fb5c9e4c75a9336be82e94412a");
    const b_public = hex("04818786518e3930b8290892288d69810bf3210b51e8783dde118503ad175ae60292ed7e4aefa776c5819d53f71acc3d4d30e9077adcc83485284349dd1ddb3eab97828816489ee6ec12a139bda130fc1f35ce80ee0536793dcec0f8f5be149eff");
    var shared: [48]u8 = undefined;
    try Ecdh.P384.agree(&a, &b_public, &shared);
    try std.testing.expectEqualSlices(u8, &hex("13005d1de266a9c1981a1bce0d31990ff3c30d27360683e1c590bc91d58ee5f219acf87436db8fb69284abbcb7d867df"), &shared);
}

test "credential ecdh matches std on random scalars and peers" {
    try shakedown.check(std.testing.allocator, {}, differential, .{ .cases = 48, .seed = 0xec1d });
}
fn differential(_: void, case: *shakedown.Case) !void {
    inline for (.{ .{ Ecdh.P256, std.crypto.ecc.P256 }, .{ Ecdh.P384, std.crypto.ecc.P384 } }) |pair| {
        const G = pair[0];
        const Point = pair[1];
        var a: [G.scalar_length]u8 = undefined;
        var b: [G.scalar_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &a);
        defer std.crypto.secureZero(u8, &b);
        for (&a) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        for (&b) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        G.check(&a) catch return;
        G.check(&b) catch return;
        var a_public: [G.public_length]u8 = undefined;
        var b_public: [G.public_length]u8 = undefined;
        try G.publicKey(&a, &a_public);
        try G.publicKey(&b, &b_public);
        const reference = try Point.basePoint.mul(a, .big);
        try std.testing.expectEqualSlices(u8, &reference.toUncompressedSec1(), &a_public);
        var one: [G.scalar_length]u8 = undefined;
        var two: [G.scalar_length]u8 = undefined;
        try G.agree(&a, &b_public, &one);
        try G.agree(&b, &a_public, &two);
        try std.testing.expectEqualSlices(u8, &one, &two);
        const expected = (try Point.fromSec1(&b_public)).mulPublic(a, .big);
        try std.testing.expectEqualSlices(u8, &(try expected).affineCoordinates().x.toBytes(.big), &one);
    }
}

test "credential ecdh rejects out of range scalars and invalid peers" {
    inline for (.{ Ecdh.P256, Ecdh.P384 }) |G| {
        var zero: [G.scalar_length]u8 = @splat(0);
        var out: [G.public_length]u8 = undefined;
        try std.testing.expectError(error.InvalidScalar, G.publicKey(&zero, &out));
        var full: [G.scalar_length]u8 = @splat(0xff);
        try std.testing.expectError(error.InvalidScalar, G.publicKey(&full, &out));
        var one: [G.scalar_length]u8 = @splat(0);
        one[one.len - 1] = 1;
        var secret: [G.scalar_length]u8 = undefined;
        try G.publicKey(&one, &out);
        // Off-curve, wrong length, compressed and identity-shaped encodings.
        var bad = out;
        bad[bad.len - 1] ^= 1;
        try std.testing.expectError(error.InvalidPublicKey, G.agree(&one, &bad, &secret));
        try std.testing.expectError(error.InvalidPublicKey, G.agree(&one, out[0 .. out.len - 1], &secret));
        var compressed = out;
        compressed[0] = 2;
        try std.testing.expectError(error.InvalidPublicKey, G.agree(&one, compressed[0 .. 1 + G.scalar_length], &secret));
        try std.testing.expectError(error.InvalidPublicKey, G.agree(&one, &[_]u8{0}, &secret));
        var infinity: [G.public_length]u8 = @splat(0);
        infinity[0] = 4;
        try std.testing.expectError(error.InvalidPublicKey, G.agree(&one, &infinity, &secret));
    }
}
