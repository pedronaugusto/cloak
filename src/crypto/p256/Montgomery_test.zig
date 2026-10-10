const std = @import("std");
const Montgomery = @import("Montgomery.zig");

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const Fe = Montgomery.Field(p);
const Scalar = Montgomery.Field(n);

fn toU256(l: Montgomery.Limbs) u256 {
    return @as(u256, l[0]) | @as(u256, l[1]) << 64 | @as(u256, l[2]) << 128 | @as(u256, l[3]) << 192;
}
fn fromU256(v: u256) Montgomery.Limbs {
    return .{ @truncate(v), @truncate(v >> 64), @truncate(v >> 128), @truncate(v >> 192) };
}

fn check(comptime F: type, comptime modulus: u256, random: std.Random) !void {
    for (0..2000) |i| {
        var a: u256 = random.int(u256) % modulus;
        var b: u256 = random.int(u256) % modulus;
        // Edges: zero, one, modulus minus one.
        if (i == 0) a = 0;
        if (i == 1) b = modulus - 1;
        if (i == 2) a = modulus - 1;
        if (i == 3) b = 1;
        const x = F.fromInt(fromU256(a));
        const y = F.fromInt(fromU256(b));
        try std.testing.expectEqual(a, toU256(x.toInt()));
        const product: u256 = @intCast((@as(u512, a) * b) % modulus);
        try std.testing.expectEqual(product, toU256(x.mul(y).toInt()));
        try std.testing.expectEqual(@as(u256, @intCast((@as(u512, a) * a) % modulus)), toU256(x.sqr().toInt()));
        try std.testing.expectEqual(@as(u256, @intCast((@as(u257, a) + b) % modulus)), toU256(x.add(y).toInt()));
        try std.testing.expectEqual(@as(u256, @intCast((@as(u257, a) + modulus - b) % modulus)), toU256(x.sub(y).toInt()));
        try std.testing.expectEqual(@as(u256, @intCast((modulus - a) % modulus)), toU256(x.neg().toInt()));
        if (a != 0) try std.testing.expectEqual(@as(u256, 1), toU256(x.mul(x.powModulusMinusTwo()).toInt()));
        try std.testing.expectEqual(a == 0, x.isZeroMask() == std.math.maxInt(u64));
        try std.testing.expectEqual(a == b, x.eqlMask(y) == std.math.maxInt(u64));
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, a, .big);
        try std.testing.expect((try F.fromBytes(&bytes)).eql(x));
        try std.testing.expectEqualSlices(u8, &bytes, &x.toBytes());
    }
    var max: [32]u8 = undefined;
    std.mem.writeInt(u256, &max, modulus, .big);
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&max));
    @memset(&max, 0xff);
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&max));
    try std.testing.expectEqual(@as(u256, @intCast(std.math.maxInt(u256) % modulus)), toU256(F.reduce(fromU256(std.math.maxInt(u256))).toInt()));
}

test "P-256 field and scalar Montgomery arithmetic match big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x256);
    try check(Fe, p, prng.random());
    try check(Scalar, n, prng.random());
}

test "P-256 field arithmetic matches std's field" {
    var prng = std.Random.DefaultPrng.init(7);
    const Std = std.crypto.ecc.P256.Fe;
    for (0..500) |_| {
        var bytes: [32]u8 = undefined;
        std.mem.writeInt(u256, &bytes, prng.random().int(u256) % p, .big);
        const ours = try Fe.fromBytes(&bytes);
        const theirs = try Std.fromBytes(bytes, .big);
        // Both keep Montgomery limbs with R = 2^256.
        try std.testing.expectEqualSlices(u64, &theirs.limbs, &ours.limbs);
        try std.testing.expectEqualSlices(u64, &theirs.sq().mul(theirs).limbs, &ours.sqr().mul(ours).limbs);
    }
}
