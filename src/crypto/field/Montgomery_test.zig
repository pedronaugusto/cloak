const std = @import("std");
const Montgomery = @import("Montgomery.zig");

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const Fe = Montgomery.Field(p);
const Scalar = Montgomery.Field(n);

/// P-521's group order: its scalars take the generic field with nine limbs.
const n521 = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409;
const Scalar521 = Montgomery.Field(n521);

fn toInt(comptime T: type, l: anytype) T {
    var v: T = 0;
    for (l, 0..) |limb, i| v |= @as(T, limb) << @intCast(64 * i);
    return v;
}
fn fromInt(comptime count: usize, v: anytype) [count]u64 {
    var l: [count]u64 = undefined;
    for (&l, 0..) |*limb, i| limb.* = @truncate(v >> @intCast(64 * i)); // each limb keeps its own 64 bits
    return l;
}

/// Every operation against the same operation on integers twice as wide as the modulus.
fn check(comptime F: type, comptime modulus: comptime_int, random: std.Random) !void {
    const T = @Int(.unsigned, 64 * F.n);
    const Wide = @Int(.unsigned, 128 * F.n);
    for (0..2000) |i| {
        var a: T = random.int(T) % modulus;
        var b: T = random.int(T) % modulus;
        // Edges: zero, one, modulus minus one.
        if (i == 0) a = 0;
        if (i == 1) b = modulus - 1;
        if (i == 2) a = modulus - 1;
        if (i == 3) b = 1;
        const x = F.fromInt(fromInt(F.n, a));
        const y = F.fromInt(fromInt(F.n, b));
        try std.testing.expectEqual(a, toInt(T, x.toInt()));
        const product: T = @intCast((@as(Wide, a) * b) % modulus);
        try std.testing.expectEqual(product, toInt(T, x.mul(y).toInt()));
        try std.testing.expectEqual(@as(T, @intCast((@as(Wide, a) * a) % modulus)), toInt(T, x.sqr().toInt()));
        try std.testing.expectEqual(@as(T, @intCast((@as(Wide, a) + b) % modulus)), toInt(T, x.add(y).toInt()));
        try std.testing.expectEqual(@as(T, @intCast((@as(Wide, a) + modulus - b) % modulus)), toInt(T, x.sub(y).toInt()));
        try std.testing.expectEqual(@as(T, @intCast((modulus - a) % modulus)), toInt(T, x.neg().toInt()));
        if (a != 0) try std.testing.expectEqual(@as(T, 1), toInt(T, x.mul(x.powModulusMinusTwo()).toInt()));
        try std.testing.expectEqual(a == 0, x.isZeroMask() == std.math.maxInt(u64));
        try std.testing.expectEqual(a == b, x.eqlMask(y) == std.math.maxInt(u64));
        var bytes: [F.encoded_length]u8 = undefined;
        std.mem.writeInt(@Int(.unsigned, 8 * F.encoded_length), &bytes, @intCast(a), .big);
        try std.testing.expect((try F.fromBytes(&bytes)).eql(x));
        try std.testing.expectEqualSlices(u8, &bytes, &x.toBytes());
        // Any n-limb value reduces.
        const raw = random.int(T);
        try std.testing.expectEqual(raw % modulus, toInt(T, F.reduce(fromInt(F.n, raw)).toInt()));
    }
    var max: [F.encoded_length]u8 = undefined;
    std.mem.writeInt(@Int(.unsigned, 8 * F.encoded_length), &max, modulus, .big);
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&max));
    @memset(&max, 0xff);
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&max));
    try std.testing.expectEqual(@as(T, std.math.maxInt(T) % modulus), toInt(T, F.reduce(fromInt(F.n, @as(T, std.math.maxInt(T)))).toInt()));
}

test "the generic Montgomery field on P-256's prime and order matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x256);
    try check(Fe, p, prng.random());
    try check(Scalar, n, prng.random());
}

test "P-521 scalar Montgomery arithmetic on nine limbs matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x521);
    try check(Scalar521, n521, prng.random());
}
