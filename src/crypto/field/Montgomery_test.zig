const std = @import("std");
const Montgomery = @import("Montgomery.zig");

const p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
const n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;
const Fe = Montgomery.Field(p);
const Scalar = Montgomery.Field(n);

/// P-521's group order: its scalars take the generic field with nine limbs.
const n521 = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409;
const Scalar521 = Montgomery.Field(n521);

fn toU256(l: [4]u64) u256 {
    return toInt(u256, l);
}
fn fromU256(v: u256) [4]u64 {
    return fromInt(4, v);
}

fn toInt(comptime T: type, l: anytype) T {
    var v: T = 0;
    for (l, 0..) |limb, i| v |= @as(T, limb) << @intCast(64 * i);
    return v;
}
fn fromInt(comptime count: usize, v: anytype) [count]u64 {
    var l: [count]u64 = undefined;
    for (&l, 0..) |*limb, i| limb.* = @truncate(v >> @intCast(64 * i)); // safe: each limb keeps its own 64 bits
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

test "P-256 field and scalar Montgomery arithmetic match big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x256);
    try check(Fe, p, prng.random());
    try check(Scalar, n, prng.random());
}

test "P-521 scalar Montgomery arithmetic on nine limbs matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x521);
    try check(Scalar521, n521, prng.random());
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

test "F05 catalogue_kernel_carries_lengths_and_dispatch (P-256 field: the platform kernel equals the portable arithmetic)" {
    var prng = std.Random.DefaultPrng.init(17);
    const edges = [_]u256{ 0, 1, 2, p - 1, p - 2, (1 << 255), (1 << 224), p >> 1 };
    for (0..20000 + edges.len * edges.len) |i| {
        const pair = i < edges.len * edges.len;
        const a: u256 = if (pair) edges[i / edges.len] else prng.random().int(u256) % p;
        const b: u256 = if (pair) edges[i % edges.len] else prng.random().int(u256) % p;
        const x: Fe = .{ .limbs = fromU256(a) };
        const y: Fe = .{ .limbs = fromU256(b) };
        try std.testing.expectEqualSlices(u64, &x.mulPortable(y).limbs, &x.mul(y).limbs);
        try std.testing.expectEqualSlices(u64, &x.sqrPortable().limbs, &x.sqr().limbs);
        try std.testing.expectEqualSlices(u64, &x.addPortable(y).limbs, &x.add(y).limbs);
        try std.testing.expectEqualSlices(u64, &x.subPortable(y).limbs, &x.sub(y).limbs);
    }
}

test "F05 catalogue_kernel_carries_lengths_and_dispatch (P-256 field: the platform kernel equals the portable arithmetic on limbs at or above p)" {
    // Two operands near 2^256 overflowed a five-limb accumulator in the assembly's rows.
    const near_a: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff90fc3d64;
    const near_b: u256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffff69c01f72;
    // 2^-256 mod p.
    const r_inverse: u512 = 0xfffffffe00000003fffffffd0000000200000001fffffffe0000000300000000;
    var prng = std.Random.DefaultPrng.init(23);
    for (0..20000) |i| {
        const high = std.math.maxInt(u256) - p;
        const a: u256 = if (i == 0) near_a else p + prng.random().int(u256) % high;
        const b: u256 = if (i == 0) near_b else if (i % 2 == 0) p + prng.random().int(u256) % high else prng.random().int(u256);
        const x: Fe = .{ .limbs = fromU256(a) };
        const y: Fe = .{ .limbs = fromU256(b) };
        const product = x.mul(y);
        try std.testing.expectEqualSlices(u64, &x.mulPortable(y).limbs, &product.limbs);
        // Congruent to a * b / 2^256 whatever the operands' form.
        const want: u256 = @intCast(@as(u512, a) * b % p * r_inverse % p);
        try std.testing.expectEqual(want, toU256(product.limbs) % p);
        try std.testing.expectEqualSlices(u64, &x.sqrPortable().limbs, &x.sqr().limbs);
        try std.testing.expectEqualSlices(u64, &x.addPortable(y).limbs, &x.add(y).limbs);
        try std.testing.expectEqualSlices(u64, &x.subPortable(y).limbs, &x.sub(y).limbs);
    }
}
