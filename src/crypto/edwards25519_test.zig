const std = @import("std");
const edwards25519 = @import("edwards25519.zig");
const s2n = @import("field/s2n.zig");
const Fiat = edwards25519.With(.fiat, null);
const Std = std.crypto.ecc.Edwards25519;
const Affine = edwards25519.Affine;

fn hex(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // unreachable: the vectors are 64 hex digits
    return out;
}

fn int(value: u256) [32]u8 {
    var out: [32]u8 = undefined;
    std.mem.writeInt(u256, &out, value, .little);
    return out;
}

const p: u256 = (1 << 255) - 19;
const order: u256 = edwards25519.order;

/// The eight points of order dividing 8, by their canonical encodings, then two non-canonical
/// spellings (x = 0 with the sign bit set) that decoding refuses.
const small_order = [_][32]u8{
    hex("0100000000000000000000000000000000000000000000000000000000000000"),
    hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
    hex("0000000000000000000000000000000000000000000000000000000000000000"),
    hex("0000000000000000000000000000000000000000000000000000000000000080"),
    hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
    hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
    hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
    hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
};
const refused = [_][32]u8{
    hex("0100000000000000000000000000000000000000000000000000000000000080"),
    hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
};

/// Scalars at the edges of every range the walks handle.
const edge_scalars = [_][32]u8{ int(0), int(1), int(2), int(7), int(8), int(order - 1), int(order), int(order + 1), int(1 << 252), int((1 << 255) - 1), int(std.math.maxInt(u256)) };

/// Encodings at the edges of decoding: y at 0, 1, p - 1, p, p + 1 and 2^255 - 1, both signs.
fn edgeEncodings() [12][32]u8 {
    var out: [12][32]u8 = undefined;
    for ([_]u256{ 0, 1, p - 1, p, p + 1, (1 << 255) - 1 }, 0..) |y, i| {
        out[2 * i] = int(y);
        out[2 * i + 1] = int(y | (1 << 255));
    }
    return out;
}

test "edwards25519: the base point, B's multiples and the identity" {
    var out: [32]u8 = undefined;
    edwards25519.base(&out, &int(1));
    try std.testing.expectEqualSlices(u8, &Std.basePoint.toBytes(), &out);
    edwards25519.base(&out, &int(0));
    try std.testing.expectEqualSlices(u8, &Affine.identity_encoding, &out);
    edwards25519.base(&out, &int(order));
    try std.testing.expectEqualSlices(u8, &Affine.identity_encoding, &out);
    Fiat.base(&out, &int(order));
    try std.testing.expectEqualSlices(u8, &Affine.identity_encoding, &out);
}

test "edwards25519: base multiplication equals std's, both backends" {
    var random = std.Random.DefaultPrng.init(0xed25519);
    for (0..200) |_| {
        var scalar: [32]u8 = undefined;
        random.fill(&scalar);
        const expected = (Std.basePoint.mulPublic(scalar) catch continue).toBytes();
        var out: [32]u8 = undefined;
        edwards25519.base(&out, &scalar);
        try std.testing.expectEqualSlices(u8, &expected, &out);
        Fiat.base(&out, &scalar);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "edwards25519: decoding's verdicts and points equal std's (canonical, x = 0 refused with the sign bit)" {
    var random = std.Random.DefaultPrng.init(0xdec0de);
    var encodings: [2000 + 12 + small_order.len + refused.len][32]u8 = undefined;
    for (encodings[0..2000]) |*e| random.fill(e);
    encodings[2000..][0..12].* = edgeEncodings();
    encodings[2012..][0..small_order.len].* = small_order;
    encodings[2012 + small_order.len ..][0..refused.len].* = refused;
    for (&encodings) |*encoding| {
        const ours = edwards25519.decode(encoding);
        try std.testing.expectEqual(ours == null, Fiat.decode(encoding) == null);
        const theirs: ?Std = blk: {
            Std.rejectNonCanonical(encoding.*) catch break :blk null;
            const point = Std.fromBytes(encoding.*) catch break :blk null;
            if (point.x.isZero() and encoding[31] >> 7 == 1) break :blk null;
            break :blk point;
        };
        try std.testing.expectEqual(theirs == null, ours == null);
        if (ours) |a| {
            try std.testing.expectEqualSlices(u8, encoding, &a.encode());
            try std.testing.expectEqualSlices(u8, std.mem.asBytes(&a.words), std.mem.asBytes(&Fiat.decode(encoding).?.words));
            try std.testing.expectEqual(theirs.?.x.isZero(), a.xIsZero());
        }
    }
}

test "edwards25519: the double base equals std's on the whole curve, torsion included" {
    var random = std.Random.DefaultPrng.init(0xd0ab1e);
    var done: usize = 0;
    while (done < 150) {
        var encoding: [32]u8 = undefined;
        random.fill(&encoding);
        const a = edwards25519.decode(&encoding) orelse continue;
        const point = Std.fromBytes(encoding) catch unreachable; // unreachable: decoded above
        var h: [32]u8 = undefined;
        var s: [32]u8 = undefined;
        random.fill(&h);
        random.fill(&s);
        h[31] &= 0x1f; // below 2^253: the scalars verification passes are below L
        s[31] &= 0x1f;
        var out: [32]u8 = undefined;
        edwards25519.mulDoubleBasePublic(&out, &h, &a, &s);
        const expected = point.mulPublic(h) catch Std.identityElement;
        const sum = expected.add(Std.basePoint.mulPublic(s) catch Std.identityElement);
        try std.testing.expectEqualSlices(u8, &sum.toBytes(), &out);
        var fiat: [32]u8 = undefined;
        Fiat.mulDoubleBasePublic(&fiat, &h, &a, &s);
        try std.testing.expectEqualSlices(u8, &out, &fiat);
        done += 1;
    }
}

test "edwards25519: the subgroup check and negation" {
    var random = std.Random.DefaultPrng.init(0x5b9);
    for (small_order) |encoding| {
        const t = edwards25519.decode(&encoding).?;
        try std.testing.expectEqual(std.mem.eql(u8, &encoding, &Affine.identity_encoding), edwards25519.inPrimeOrderSubgroup(&t));
    }
    for (refused) |encoding| try std.testing.expect(edwards25519.decode(&encoding) == null);
    for (0..40) |i| {
        var scalar: [32]u8 = undefined;
        random.fill(&scalar);
        scalar[31] &= 0x7f; // a public double-base scalar, below 2^255
        var encoding: [32]u8 = undefined;
        edwards25519.base(&encoding, &scalar);
        const a = edwards25519.decode(&encoding).?;
        try std.testing.expect(edwards25519.inPrimeOrderSubgroup(&a));
        // a + t for a torsion point t other than the identity leaves the subgroup.
        const t = edwards25519.decode(&small_order[1 + i % (small_order.len - 1)]).?;
        var mixed: [32]u8 = undefined;
        edwards25519.mulDoubleBasePublic(&mixed, &int(1), &t, &scalar);
        try std.testing.expect(!edwards25519.inPrimeOrderSubgroup(&edwards25519.decode(&mixed).?));
        // A + (-A) is the identity.
        var zero: [32]u8 = undefined;
        edwards25519.mulDoubleBasePublic(&zero, &int(1), &a.neg(), &edwards25519.reduce64(&(scalar ++ @as([32]u8, @splat(0)))));
        try std.testing.expectEqualSlices(u8, &Affine.identity_encoding, &zero);
    }
}

test "F05 catalogue_kernel_carries_lengths_and_dispatch (Ed25519: s2n-bignum's base, double base and decoding equal the portable path)" {
    if (!s2n.assembly) return error.SkipZigTest;
    inline for (.{ s2n.Variant.alt, s2n.Variant.plain }) |variant| {
        if (variant == .alt or s2n.plainRuns()) try agree(edwards25519.With(.s2n, variant));
    }
}

fn agree(comptime X: type) !void {
    var random = std.Random.DefaultPrng.init(0xa9ee);
    var scalars: [2000 + edge_scalars.len][32]u8 = undefined;
    for (scalars[0..2000]) |*s| random.fill(s);
    scalars[2000..].* = edge_scalars;
    for (&scalars) |*scalar| {
        var ours: [32]u8 = undefined;
        var theirs: [32]u8 = undefined;
        X.base(&ours, scalar);
        Fiat.base(&theirs, scalar);
        try std.testing.expectEqualSlices(u8, &theirs, &ours);
    }
    var encodings: [2000 + 12 + small_order.len + refused.len][32]u8 = undefined;
    for (encodings[0..2000]) |*e| random.fill(e);
    encodings[2000..][0..12].* = edgeEncodings();
    encodings[2012..][0..small_order.len].* = small_order;
    encodings[2012 + small_order.len ..][0..refused.len].* = refused;
    for (&encodings, 0..) |*encoding, i| {
        const ours = X.decode(encoding);
        const theirs = Fiat.decode(encoding);
        try std.testing.expectEqual(theirs == null, ours == null);
        const a = ours orelse continue;
        try std.testing.expectEqualSlices(u64, &theirs.?.words, &a.words);
        // Every point that decodes, its small-order component kept, against public scalars
        // below 2^255, the edges among them.
        const h = if (i < edge_scalars.len and edge_scalars[i][31] < 128) edge_scalars[i] else scalars[i % 2000];
        var hs = h;
        var ss = scalars[(i + 1) % 2000];
        hs[31] &= 0x7f;
        ss[31] &= 0x7f;
        var x: [32]u8 = undefined;
        var y: [32]u8 = undefined;
        X.mulDoubleBasePublic(&x, &hs, &a, &ss);
        Fiat.mulDoubleBasePublic(&y, &hs, &a, &ss);
        try std.testing.expectEqualSlices(u8, &y, &x);
    }
}

test "edwards25519 scalars: reduce64, mulAdd and the canonical check equal std's" {
    var random = std.Random.DefaultPrng.init(0x5ca1a7);
    for (0..2000) |i| {
        var wide: [64]u8 = undefined;
        random.fill(&wide);
        if (i < 4) wide = if (i % 2 == 0) @splat(0xff) else @splat(0);
        try std.testing.expectEqualSlices(u8, &Std.scalar.reduce64(wide), &edwards25519.reduce64(&wide));
        var a: [32]u8 = undefined;
        var b: [32]u8 = undefined;
        var c: [32]u8 = undefined;
        random.fill(&a);
        random.fill(&b);
        random.fill(&c);
        a = Std.scalar.reduce(a);
        c = Std.scalar.reduce(c);
        b[0] &= 248;
        b[31] = (b[31] & 127) | 64; // a clamped secret scalar, as signing passes it
        try std.testing.expectEqualSlices(u8, &Std.scalar.mulAdd(a, b, c), &edwards25519.mulAdd(&a, &b, &c));
        const s = if (i < edge_scalars.len) edge_scalars[i] else wide[0..32].*;
        const canonical = if (Std.scalar.rejectNonCanonical(s)) |_| true else |_| false;
        try std.testing.expectEqual(canonical, edwards25519.isCanonical(&s));
    }
}
