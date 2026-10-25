const std = @import("std");
const p521 = @import("p521.zig");

const prime: u521 = std.math.maxInt(u521);
const n: u521 = p521.order;
const gx: u521 = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66;
const gy: u521 = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650;

fn bytes66(value: u528) [66]u8 {
    var out: [66]u8 = undefined;
    std.mem.writeInt(u528, &out, value, .big);
    return out;
}

fn int(fe: p521.Fe) u521 {
    return @intCast(std.mem.readInt(u528, &fe.toBytes(), .big));
}

/// A reference on integers, apart from the field seam and the formulas under test: textbook
/// Jacobian doubling and addition (Cohen-Miyaji-Ono, a = -3) with the exceptional cases decided
/// on the integers, double-and-add, one inversion at the end.
const Reference = struct {
    const Point = ?struct { x: u521, y: u521 };
    const J = struct { x: u521, y: u521, z: u521 };

    fn mulmod(a: u521, c: u521) u521 {
        return @intCast(@as(u1042, a) * c % prime);
    }
    fn addmod(a: u521, c: u521) u521 {
        return @intCast((@as(u522, a) + c) % prime);
    }
    fn submod(a: u521, c: u521) u521 {
        return @intCast((@as(u522, a) + prime - c) % prime);
    }
    fn inverse(a: u521) u521 {
        var result: u521 = 1;
        var base = a;
        var e: u521 = prime - 2;
        while (e != 0) : (e >>= 1) {
            if (e & 1 == 1) result = mulmod(result, base);
            base = mulmod(base, base);
        }
        return result;
    }
    fn double(p: J) J {
        if (p.z == 0 or p.y == 0) return .{ .x = 1, .y = 1, .z = 0 };
        // M = 3(X - Z^2)(X + Z^2), S = 4XY^2, X' = M^2 - 2S, Y' = M(S - X') - 8Y^4, Z' = 2YZ.
        const zz = mulmod(p.z, p.z);
        const m = mulmod(3, mulmod(submod(p.x, zz), addmod(p.x, zz)));
        const yy = mulmod(p.y, p.y);
        const s = mulmod(4, mulmod(p.x, yy));
        const x = submod(mulmod(m, m), mulmod(2, s));
        return .{ .x = x, .y = submod(mulmod(m, submod(s, x)), mulmod(8, mulmod(yy, yy))), .z = mulmod(2, mulmod(p.y, p.z)) };
    }
    fn add(p: J, q: J) J {
        if (p.z == 0) return q;
        if (q.z == 0) return p;
        const z1 = mulmod(p.z, p.z);
        const z2 = mulmod(q.z, q.z);
        const u_1 = mulmod(p.x, z2);
        const u_2 = mulmod(q.x, z1);
        const s1 = mulmod(p.y, mulmod(q.z, z2));
        const s2 = mulmod(q.y, mulmod(p.z, z1));
        if (u_1 == u_2) return if (s1 == s2) double(p) else .{ .x = 1, .y = 1, .z = 0 };
        const h = submod(u_2, u_1);
        const r = submod(s2, s1);
        const hh = mulmod(h, h);
        const hhh = mulmod(h, hh);
        const v = mulmod(u_1, hh);
        const x = submod(submod(mulmod(r, r), hhh), mulmod(2, v));
        return .{ .x = x, .y = submod(mulmod(r, submod(v, x)), mulmod(s1, hhh)), .z = mulmod(h, mulmod(p.z, q.z)) };
    }
    fn mul(k: u521, p: Point) Point {
        const a = p.?;
        const base: J = .{ .x = a.x, .y = a.y, .z = 1 };
        var acc: J = .{ .x = 1, .y = 1, .z = 0 };
        var i: usize = 521;
        while (i > 0) {
            i -= 1;
            acc = double(acc);
            if ((k >> @intCast(i)) & 1 == 1) acc = add(acc, base);
        }
        if (acc.z == 0) return null;
        const zi = inverse(acc.z);
        const zi2 = mulmod(zi, zi);
        return .{ .x = mulmod(acc.x, zi2), .y = mulmod(acc.y, mulmod(zi2, zi)) };
    }
};

fn expectPoint(want: Reference.Point, got: p521.Jacobian) !void {
    const w = want orelse return std.testing.expect(got.z.isZero());
    const a = got.affine();
    try std.testing.expectEqual(w.x, int(a.x));
    try std.testing.expectEqual(w.y, int(a.y));
}

test "P-521 generator is on the curve and has order n" {
    try std.testing.expect(p521.generator.onCurve());
    try std.testing.expectEqual(gx, int(p521.generator.x));
    // (n - 1) G = -G.
    const minus = p521.baseMul(&bytes66(n - 1)).affine();
    try std.testing.expectEqual(gx, int(minus.x));
    try std.testing.expectEqual(prime - gy, int(minus.y));
}

test "P-521 signed recoding reconstructs the scalar" {
    var prng = std.Random.DefaultPrng.init(0x5219);
    for (0..300) |i| {
        var value: u521 = prng.random().int(u521) % n;
        if (i == 0) value = n - 1;
        if (i == 1) value = 1;
        if (i == 2) value = std.math.maxInt(u521);
        const limbs = p521.Scalar.limbsFromBytes(&bytes66(value));
        var digits: [105]p521.Digit = undefined;
        p521.recode(&limbs, &digits);
        var sum: i600 = 0;
        for (digits, 0..) |d, k| {
            try std.testing.expect(d.magnitude <= 16);
            const term = @as(i600, d.magnitude) << @intCast(5 * k);
            sum += if (d.negative == 1) -term else term;
        }
        try std.testing.expectEqual(@as(i600, value), sum);
    }
}

test "P-521 multiplications agree with an integer reference, edge scalars and the doubling case included" {
    var prng = std.Random.DefaultPrng.init(0x521a);
    const g: Reference.Point = .{ .x = gx, .y = gy };
    const edges = [_]u521{ 1, 2, 3, 15, 16, 17, 31, 32, 33, n - 1, n - 2, n - 16, 1 << 520, (1 << 519) - 1 };
    for (0..edges.len + 6) |i| {
        const k: u521 = if (i < edges.len) edges[i] else 1 + prng.random().int(u521) % (n - 1);
        const want = Reference.mul(k, g);
        try expectPoint(want, p521.baseMul(&bytes66(k)));
        // A peer point, and the public double-base form.
        const other: u521 = 1 + prng.random().int(u521) % (n - 1);
        const peer_ref = Reference.mul(other, g).?;
        const peer: p521.Affine = .{ .x = try p521.Fe.fromBytes(&bytes66(peer_ref.x)), .y = try p521.Fe.fromBytes(&bytes66(peer_ref.y)) };
        try std.testing.expect(peer.onCurve());
        try expectPoint(Reference.mul(k, .{ .x = peer_ref.x, .y = peer_ref.y }), p521.mul(&peer, &bytes66(k)));
        const g_part = p521.Scalar.limbsFromBytes(&bytes66(k));
        const q_part = p521.Scalar.limbsFromBytes(&bytes66(other));
        // k G + other G = (k + other) G.
        const sum: u521 = @intCast((@as(u522, k) + other) % n);
        try expectPoint(Reference.mul(sum, g), p521.mulDoubleBasePublic(&g_part, &p521.generator, &q_part));
    }
}

test "P-521 SEC1 encodings: uncompressed and compressed round-trip, off-curve and non-canonical refused" {
    var prng = std.Random.DefaultPrng.init(0x521b);
    for (0..20) |_| {
        const k = 1 + prng.random().int(u521) % (n - 1);
        const point = p521.baseMul(&bytes66(k)).affine();
        const encoded = point.toSec1();
        const back = try p521.Affine.fromSec1(&encoded);
        try std.testing.expect(back.x.eql(&point.x) and back.y.eql(&point.y));
        var compressed: [67]u8 = undefined;
        compressed[0] = 2 | (encoded[132] & 1);
        @memcpy(compressed[1..], encoded[1..67]);
        const decompressed = try p521.Affine.fromSec1(&compressed);
        try std.testing.expect(decompressed.y.eql(&point.y));
        var off = encoded;
        off[132] ^= 1;
        try std.testing.expectError(error.InvalidEncoding, p521.Affine.fromSec1(&off));
    }
    var big = p521.generator.toSec1();
    big[1] = 2; // x >= 2^521
    try std.testing.expectError(error.InvalidEncoding, p521.Affine.fromSec1(&big));
    try std.testing.expectError(error.InvalidEncoding, p521.Affine.fromSec1(&.{0}));
}

test "P-521 scalar range" {
    try std.testing.expect(!p521.scalarInRange(&bytes66(0)));
    try std.testing.expect(p521.scalarInRange(&bytes66(1)));
    try std.testing.expect(p521.scalarInRange(&bytes66(n - 1)));
    try std.testing.expect(!p521.scalarInRange(&bytes66(n)));
    try std.testing.expect(!p521.scalarInRange(&bytes66(std.math.maxInt(u528))));
}

test "P-521 ECDSA pieces: a signature made with signR verifies, a changed one does not" {
    var prng = std.Random.DefaultPrng.init(0x521c);
    for (0..8) |_| {
        const d: u521 = 1 + prng.random().int(u521) % (n - 1);
        const k: u521 = 1 + prng.random().int(u521) % (n - 1);
        var digest: [64]u8 = undefined;
        prng.random().bytes(&digest);
        const q = p521.baseMul(&bytes66(d)).affine();
        const e = p521.digestScalar(&digest);
        const r = p521.signR(&bytes66(k)).?;
        const d_s = try p521.Scalar.fromBytes(&bytes66(d));
        const k_s = try p521.Scalar.fromBytes(&bytes66(k));
        const s = k_s.powModulusMinusTwo().mul(e.add(r.mul(d_s)));
        const r_bytes = r.toBytes();
        const s_bytes = s.toBytes();
        try std.testing.expect(p521.verify(&q, e, &r_bytes, &s_bytes));
        const other = p521.digestScalar(&[_]u8{1});
        try std.testing.expect(!p521.verify(&q, other, &r_bytes, &s_bytes));
        try std.testing.expect(!p521.verify(&q, e, &s_bytes, &r_bytes));
    }
}

test "P-521 digest scalar: SHA-512's bits whole, longer digests their leftmost 521 bits" {
    var digest: [66]u8 = @splat(0xff);
    // 528 ones shifted right by seven: 521 ones, which is p, reduced mod n.
    const want: u521 = @intCast(@as(u522, prime) % n);
    try std.testing.expectEqual(want, std.mem.readInt(u528, &p521.digestScalar(&(digest ++ [_]u8{0})).toBytes(), .big));
    digest = @splat(0);
    digest[63] = 5;
    try std.testing.expectEqual(@as(u528, 5), std.mem.readInt(u528, &p521.digestScalar(digest[0..64]).toBytes(), .big));
}

test "Wycheproof P-521 ECDH at the curve: every valid uncompressed vector's shared x" {
    const gpa = std.testing.allocator;
    const text = @embedFile("../verify/fixtures/wycheproof/ecdh_secp521r1_ecpoint_test.json");
    const parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
    defer parsed.deinit();
    var checked: usize = 0;
    for (parsed.value.object.get("testGroups").?.array.items) |group| {
        for (group.object.get("tests").?.array.items) |case| {
            const result = case.object.get("result").?.string;
            if (std.mem.eql(u8, result, "invalid")) continue;
            const public_hex = case.object.get("public").?.string;
            var public: [133]u8 = undefined;
            if (public_hex.len != 266) continue; // compressed points are the acceptance campaign's
            _ = try std.fmt.hexToBytes(&public, public_hex);
            const private_hex = case.object.get("private").?.string;
            var private_raw: [70]u8 = undefined;
            const raw = try std.fmt.hexToBytes(&private_raw, private_hex);
            var private: [66]u8 = @splat(0);
            const trimmed = std.mem.trimStart(u8, raw, &.{0});
            @memcpy(private[66 - trimmed.len ..], trimmed);
            var shared: [66]u8 = undefined;
            _ = try std.fmt.hexToBytes(&shared, case.object.get("shared").?.string);
            const peer = try p521.Affine.fromSec1(&public);
            const product = p521.mul(&peer, &private).affine();
            try std.testing.expectEqualSlices(u8, &shared, &product.x.toBytes());
            checked += 1;
        }
    }
    try std.testing.expect(checked > 100);
}
