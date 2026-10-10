const std = @import("std");
const p256 = @import("p256.zig");
const table = @import("p256/table.zig");
const Std = std.crypto.ecc.P256;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;

fn scalarBytes(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .big);
    return out;
}

fn sameAffine(ours: p256.Affine, theirs: Std) !void {
    const a = theirs.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &a.x.toBytes(.big), &ours.x.toBytes());
    try std.testing.expectEqualSlices(u8, &a.y.toBytes(.big), &ours.y.toBytes());
}

test "P-256 base comb equals the standard library's multiples" {
    var base = Std.basePoint;
    for (0..table.windows) |i| {
        var point = base;
        for (0..1 << (table.bits - 1)) |j| {
            const a = point.affineCoordinates();
            try std.testing.expectEqualSlices(u64, &(a.x.limbs ++ a.y.limbs), &table.base[i][j]);
            point = point.add(base);
        }
        for (0..table.bits) |_| base = base.dbl();
    }
}

test "P-256 signed recoding reconstructs the scalar" {
    var prng = std.Random.DefaultPrng.init(3);
    for (0..500) |i| {
        var value: u256 = prng.random().int(u256) % p256.order;
        if (i == 0) value = p256.order - 1;
        if (i == 1) value = 1;
        if (i == 2) value = std.math.maxInt(u256);
        const bytes = scalarBytes(value);
        const limbs = p256.scalarLimbs(&bytes);
        inline for (.{ .{ 6, 43 }, .{ 5, 52 } }) |shape| {
            var digits: [shape[1]]p256.Digit = undefined;
            p256.recode(shape[0], &limbs, shape[1], &digits);
            var sum: i512 = 0;
            for (digits, 0..) |d, k| {
                try std.testing.expect(d.magnitude <= 1 << (shape[0] - 1));
                const term = @as(i512, d.magnitude) << @intCast(shape[0] * k);
                sum += if (d.negative == 1) -term else term;
            }
            try std.testing.expectEqual(@as(i512, value), sum);
        }
    }
}

test "P-256 base and variable-point multiplication agree with the standard library" {
    var prng = std.Random.DefaultPrng.init(11);
    const edges = [_]u256{ 1, 2, 3, 31, 32, 33, 63, 64, p256.order - 1, p256.order - 2, p256.order - 32, 1 << 255, (1 << 252) - 1 };
    for (0..200 + edges.len) |i| {
        const value = if (i < edges.len) edges[i] else 1 + prng.random().int(u256) % (p256.order - 1);
        const k = scalarBytes(value);
        const expected = try Std.basePoint.mul(k, .big);
        try sameAffine(p256.baseMul(&k).affine(), expected);
        // A peer point from another scalar.
        const other = scalarBytes(1 + prng.random().int(u256) % (p256.order - 1));
        const peer = try Std.basePoint.mul(other, .big);
        const peer_ours = try p256.Affine.fromSec1(&peer.toUncompressedSec1());
        try sameAffine(p256.mul(peer_ours, &k).affine(), try peer.mul(k, .big));
        // The doubling case inside the walk: the peer is the base point itself.
        const g = try p256.Affine.fromSec1(&Std.basePoint.toUncompressedSec1());
        try sameAffine(p256.mul(g, &k).affine(), expected);
    }
}

test "P-256 point decoding accepts exactly the points std accepts" {
    var prng = std.Random.DefaultPrng.init(5);
    for (0..100) |_| {
        const point = try Std.basePoint.mul(scalarBytes(1 + prng.random().int(u256) % (p256.order - 1)), .big);
        try sameAffine(try p256.Affine.fromSec1(&point.toUncompressedSec1()), point);
        try sameAffine(try p256.Affine.fromSec1(&point.toCompressedSec1()), point);
        var bad = point.toUncompressedSec1();
        bad[64] ^= 1;
        try std.testing.expectError(error.InvalidEncoding, p256.Affine.fromSec1(&bad));
    }
    var zeros: [65]u8 = @splat(0);
    zeros[0] = 4;
    try std.testing.expectError(error.InvalidEncoding, p256.Affine.fromSec1(&zeros));
    try std.testing.expectError(error.InvalidEncoding, p256.Affine.fromSec1(&.{0}));
}

test "P-256 verification accepts std signatures and rejects altered ones" {
    var prng = std.Random.DefaultPrng.init(9);
    for (0..100) |i| {
        var seed: [32]u8 = undefined;
        prng.random().bytes(&seed);
        const pair = try Ecdsa.KeyPair.generateDeterministic(seed);
        var message: [40]u8 = undefined;
        prng.random().bytes(&message);
        const signature = try pair.sign(&message, null);
        const q = try p256.Affine.fromSec1(&pair.public_key.toUncompressedSec1());
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&message, &digest, .{});
        const e = p256.Scalar.reduce(p256.Scalar.limbsFromBytes(&digest));
        try std.testing.expect(p256.verify(q, e, &signature.r, &signature.s));
        var r = signature.r;
        r[31 - i % 32] ^= 1;
        try std.testing.expect(!p256.verify(q, e, &r, &signature.s));
        const other = p256.Scalar.reduce(.{ 1, 0, 0, 0 });
        try std.testing.expect(!p256.verify(q, other, &signature.r, &signature.s));
        const zero: [32]u8 = @splat(0);
        try std.testing.expect(!p256.verify(q, e, &zero, &signature.s));
        const n = scalarBytes(p256.order);
        try std.testing.expect(!p256.verify(q, e, &signature.r, &n));
    }
}

test "P-256 field inversion" {
    var prng = std.Random.DefaultPrng.init(13);
    for (0..100) |_| {
        const x = p256.Fe.reduce(.{ prng.random().int(u64), prng.random().int(u64), prng.random().int(u64), prng.random().int(u64) });
        if (x.isZero()) continue;
        try std.testing.expect(x.mul(p256.invert(x)).eql(p256.Fe.one));
        try std.testing.expect(p256.invert(x).eql(x.powModulusMinusTwo()));
    }
}
