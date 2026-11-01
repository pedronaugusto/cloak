const std = @import("std");
const p384 = @import("p384.zig");
const Std = std.crypto.ecc.P384;
const Ecdsa = std.crypto.sign.ecdsa.EcdsaP384Sha384;

fn scalarBytes(value: u384) [48]u8 {
    var out: [48]u8 = undefined;
    std.mem.writeInt(u384, &out, value, .big);
    return out;
}

fn sameAffine(ours: *const p384.Affine, theirs: Std) !void {
    const a = theirs.affineCoordinates();
    try std.testing.expectEqualSlices(u8, &a.x.toBytes(.big), &ours.x.toBytes());
    try std.testing.expectEqualSlices(u8, &a.y.toBytes(.big), &ours.y.toBytes());
}

test "P-384 base and variable-point multiplication agree with the standard library for every leading-zero class" {
    var prng = std.Random.DefaultPrng.init(0x384);
    const edges = [_]u384{ 1, 2, 3, 15, 16, 17, 31, 32, 33, p384.order - 1, p384.order - 2, p384.order - 16, 1 << 383, (1 << 380) - 1 };
    for (0..edges.len + 48 + 100) |i| {
        const value = if (i < edges.len) edges[i] else if (i < edges.len + 48) blk: {
            const zeros = i - edges.len;
            const width: u9 = 8 * @as(u9, @intCast(48 - zeros)); // zeros is below 48
            const bound: u384 = if (width == 384) p384.order else @as(u384, 1) << @intCast(width);
            break :blk 1 + prng.random().int(u384) % (bound - 1);
        } else 1 + prng.random().int(u384) % (p384.order - 1);
        const k = scalarBytes(value);
        const expected = try Std.basePoint.mul(k, .big);
        try sameAffine(&p384.baseMul(&k).affine(), expected);
        const other = scalarBytes(1 + prng.random().int(u384) % (p384.order - 1));
        const peer = try Std.basePoint.mul(other, .big);
        const peer_ours = try p384.Affine.fromSec1(&peer.toUncompressedSec1());
        try sameAffine(&p384.mul(&peer_ours, &k).affine(), try peer.mul(k, .big));
        // The doubling case inside the walk: the peer is the base point itself.
        try sameAffine(&p384.mul(&p384.generator, &k).affine(), expected);
    }
}

test "P-384 point decoding accepts exactly the points std accepts" {
    var prng = std.Random.DefaultPrng.init(0x385);
    for (0..100) |_| {
        const point = try Std.basePoint.mul(scalarBytes(1 + prng.random().int(u384) % (p384.order - 1)), .big);
        try sameAffine(&try p384.Affine.fromSec1(&point.toUncompressedSec1()), point);
        try sameAffine(&try p384.Affine.fromSec1(&point.toCompressedSec1()), point);
        var bad = point.toUncompressedSec1();
        bad[96] ^= 1;
        try std.testing.expectError(error.InvalidEncoding, p384.Affine.fromSec1(&bad));
    }
    var zeros: [97]u8 = @splat(0);
    zeros[0] = 4;
    try std.testing.expectError(error.InvalidEncoding, p384.Affine.fromSec1(&zeros));
}

test "P-384 verification accepts std signatures and rejects altered ones" {
    var prng = std.Random.DefaultPrng.init(0x386);
    for (0..60) |i| {
        var seed: [48]u8 = undefined;
        prng.random().bytes(&seed);
        const pair = try Ecdsa.KeyPair.generateDeterministic(seed);
        var message: [40]u8 = undefined;
        prng.random().bytes(&message);
        const signature = try pair.sign(&message, null);
        const q = try p384.Affine.fromSec1(&pair.public_key.toUncompressedSec1());
        var digest: [48]u8 = undefined;
        std.crypto.hash.sha2.Sha384.hash(&message, &digest, .{});
        const e = p384.digestScalar(&digest);
        try std.testing.expect(p384.verify(&q, e, &signature.r, &signature.s));
        var r = signature.r;
        r[47 - i % 48] ^= 1;
        try std.testing.expect(!p384.verify(&q, e, &r, &signature.s));
        try std.testing.expect(!p384.verify(&q, p384.digestScalar("\x01"), &signature.r, &signature.s));
        const n = scalarBytes(p384.order);
        try std.testing.expect(!p384.verify(&q, e, &signature.r, &n));
    }
}
