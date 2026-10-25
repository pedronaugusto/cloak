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

/// s2n-bignum's limbs: the value itself, little-endian.
fn limbs(v: u521) p521.Limbs {
    var l: p521.Limbs = undefined;
    for (&l, 0..) |*limb, i| limb.* = @truncate(v >> @intCast(64 * i)); // safe: each limb keeps its own 64 bits
    return l;
}

fn value(l: p521.Limbs) u576 {
    var v: u576 = 0;
    for (l, 0..) |limb, i| v |= @as(u576, limb) << @intCast(64 * i);
    return v;
}

test "P-521 field: s2n-bignum's routines, every variant this processor runs, equal fiat-crypto's" {
    if (!p521.assembly) return error.SkipZigTest;
    const s = p521.s2n;
    const plain = s.plainRuns();
    var prng = std.Random.DefaultPrng.init(0x5e2b);
    const random = prng.random();
    const e = edges();
    for (0..20000 + e.len * e.len) |i| {
        const pair = i < e.len * e.len;
        const a: u521 = if (pair) e[i / e.len] else random.int(u521) % p;
        const b: u521 = if (pair) e[i % e.len] else random.int(u521) % p;
        const fa = try Fiat.fromBytes(&encode(a));
        const fb = try Fiat.fromBytes(&encode(b));
        const x = limbs(a);
        const y = limbs(b);
        var z: p521.Limbs = undefined;
        const product = decode(fa.mul(&fb).toBytes());
        s.cloak_bignum_mul_p521_alt(&z, &x, &y);
        try std.testing.expectEqual(@as(u576, product), value(z));
        if (plain) {
            s.cloak_bignum_mul_p521(&z, &x, &y);
            try std.testing.expectEqual(@as(u576, product), value(z));
        }
        const square = decode(fa.sqr().toBytes());
        s.cloak_bignum_sqr_p521_alt(&z, &x);
        try std.testing.expectEqual(@as(u576, square), value(z));
        if (plain) {
            s.cloak_bignum_sqr_p521(&z, &x);
            try std.testing.expectEqual(@as(u576, square), value(z));
        }
        s.cloak_bignum_add_p521(&z, &x, &y);
        try std.testing.expectEqual(@as(u576, decode(fa.add(&fb).toBytes())), value(z));
        s.cloak_bignum_sub_p521(&z, &x, &y);
        try std.testing.expectEqual(@as(u576, decode(fa.sub(&fb).toBytes())), value(z));
        s.cloak_bignum_neg_p521(&z, &x);
        try std.testing.expectEqual(@as(u576, decode(fa.neg().toBytes())), value(z));
        if (i % 16 == 0 or pair) {
            s.cloak_bignum_inv_p521(&z, &x);
            if (a != 0) try std.testing.expectEqual(@as(u576, decode(fa.invert().toBytes())), value(z));
        }
    }
}
