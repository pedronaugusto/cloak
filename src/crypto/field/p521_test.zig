const std = @import("std");
const p521 = @import("p521.zig");
const Fiat = p521.Field(.fiat);

const p: u521 = std.math.maxInt(u521);

fn encode(v: u528) [66]u8 {
    var out: [66]u8 = undefined;
    std.mem.writeInt(u528, &out, v, .big);
    return out;
}

fn decode(bytes: [66]u8) u528 {
    return std.mem.readInt(u528, &bytes, .big);
}

/// Values every routine must get right: zero, one, two, p - 1, p - 2, the powers of two at limb
/// and 58-bit boundaries, all-ones below them, and the halves of p.
fn edges() [24]u521 {
    var e: [24]u521 = undefined;
    const fixed = [_]u521{ 0, 1, 2, p - 1, p - 2, p >> 1, (p >> 1) + 1, 1 << 520, (1 << 520) - 1, 1 << 512, (1 << 512) - 1, 1 << 64, (1 << 64) - 1, 1 << 58, (1 << 58) - 1, 1 << 116, (1 << 464) - 1, 1 << 463, 3, p - 3 };
    @memcpy(e[0..fixed.len], &fixed);
    e[20] = 0x5555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555555;
    e[21] = e[20] << 1;
    e[22] = (p / 3);
    e[23] = (p / 3) * 2;
    return e;
}

/// Each operation of `F` against wide-integer arithmetic on random and edge operands.
fn checkAgainstIntegers(comptime F: type, random: std.Random) !void {
    const e = edges();
    for (0..3000 + e.len * e.len) |i| {
        const pair = i < e.len * e.len;
        const a: u521 = if (pair) e[i / e.len] else random.int(u521) % p;
        const b: u521 = if (pair) e[i % e.len] else random.int(u521) % p;
        const x = try F.fromBytes(&encode(a));
        const y = try F.fromBytes(&encode(b));
        try std.testing.expectEqual(@as(u528, a), decode(x.toBytes()));
        try std.testing.expectEqual(@as(u528, @intCast(@as(u1042, a) * b % p)), decode(x.mul(&y).toBytes()));
        try std.testing.expectEqual(@as(u528, @intCast(@as(u1042, a) * a % p)), decode(x.sqr().toBytes()));
        try std.testing.expectEqual(@as(u528, @intCast((@as(u522, a) + b) % p)), decode(x.add(&y).toBytes()));
        try std.testing.expectEqual(@as(u528, @intCast((@as(u522, a) + p - b) % p)), decode(x.sub(&y).toBytes()));
        try std.testing.expectEqual(@as(u528, @intCast((p - @as(u522, a)) % p)), decode(x.neg().toBytes()));
        try std.testing.expectEqual(a == 0, x.isZero());
        try std.testing.expectEqual(a == b, x.eql(&y));
        if (i % 16 == 0 or pair) {
            const inverse = x.invert();
            if (a == 0) {
                try std.testing.expect(inverse.isZero());
            } else {
                try std.testing.expectEqual(@as(u528, 1), decode(x.mul(&inverse).toBytes()));
            }
        }
    }
}

fn checkEncodings(comptime F: type) !void {
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(p)));
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(@as(u528, p) + 1)));
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(1 << 522)));
    try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(std.math.maxInt(u528))));
    _ = try F.fromBytes(&encode(p - 1));
    try std.testing.expect(F.one.mul(&F.one).eql(&F.one));
    try std.testing.expect(F.zero.isZero());
    try std.testing.expect(F.select(0, &F.one, &F.zero).eql(&F.one));
    try std.testing.expect(F.select(std.math.maxInt(u64), &F.one, &F.zero).isZero());
}

test "P-521 field: fiat-crypto's Zig matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x521f);
    try checkAgainstIntegers(Fiat, prng.random());
    try checkEncodings(Fiat);
}

test "P-521 field: the build's field matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x521e);
    try checkAgainstIntegers(p521.Fe, prng.random());
    try checkEncodings(p521.Fe);
}

/// Two backends' operations equal on random and edge operands.
fn checkAgree(comptime S: type, random: std.Random) !void {
    const e = edges();
    for (0..20000 + e.len * e.len) |i| {
        const pair = i < e.len * e.len;
        const a: u521 = if (pair) e[i / e.len] else random.int(u521) % p;
        const b: u521 = if (pair) e[i % e.len] else random.int(u521) % p;
        const fa = try Fiat.fromBytes(&encode(a));
        const fb = try Fiat.fromBytes(&encode(b));
        const x = try S.fromBytes(&encode(a));
        const y = try S.fromBytes(&encode(b));
        try std.testing.expectEqual(decode(fa.mul(&fb).toBytes()), decode(x.mul(&y).toBytes()));
        try std.testing.expectEqual(decode(fa.sqr().toBytes()), decode(x.sqr().toBytes()));
        try std.testing.expectEqual(decode(fa.add(&fb).toBytes()), decode(x.add(&y).toBytes()));
        try std.testing.expectEqual(decode(fa.sub(&fb).toBytes()), decode(x.sub(&y).toBytes()));
        try std.testing.expectEqual(decode(fa.neg().toBytes()), decode(x.neg().toBytes()));
        if (i % 16 == 0 or pair) try std.testing.expectEqual(decode(fa.invert().toBytes()), decode(x.invert().toBytes()));
    }
}

test "P-521 field: s2n-bignum's routines, every variant this processor runs, equal fiat-crypto's" {
    if (!p521.assembly) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x5e2b);
    try checkAgree(p521.FieldWith(.s2n, .alt), prng.random());
    if (p521.s2n.plainRuns()) try checkAgree(p521.FieldWith(.s2n, .plain), prng.random());
}
