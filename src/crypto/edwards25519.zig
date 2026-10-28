//! The edwards25519 group (RFC 8032 5.1) and its scalars, as Ed25519 uses them: s2n-bignum's
//! verified base and double-base multiplications and decoding on x86_64 and AArch64, and
//! elsewhere cloak's extended-coordinate formulas over fiat-crypto's verified field
//! (`field/curve25519.zig`), which are also the reference the assembly is tested against.
//! Scalars modulo the group order L run on cloak's generic constant-time Montgomery field.
//!
//! `base` computes with a secret scalar and runs the same instructions for every scalar; the
//! assembly writes its temporaries to the stack, so callers run it inside
//! `aegis.secret.scrubbed`. Decoding, `mulDoubleBasePublic` and the subgroup check compute with
//! public values.
//!
//! The double base is exact on the whole curve: s2n-bignum subtracts L from a scalar only when
//! it is at least 2^255, and every scalar passed here (below L, or L itself) is below that, so
//! a point with a small-order component gives [h]A + [s]B as written, as std computes it.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const s2n = @import("field.zig").s2n;
const Fe = @import("field.zig").curve25519.Fe;
const Montgomery = @import("field.zig").Montgomery;

pub const encoded_length = 32;

/// The prime order of the base point.
pub const order = (1 << 252) + 27742317777372353535851937790883648493;

/// Scalars modulo L, in Montgomery form.
pub const Scalar = Montgomery.Field(order);

pub const Backend = enum { fiat, s2n };

/// The backend this build computes with.
pub const backend: Backend = if (s2n.assembly) .s2n else .fiat;

/// A decoded point: x then y, each four little-endian 64-bit words below p, as s2n-bignum
/// holds them. Public.
pub const Affine = struct {
    words: [8]u64,

    /// The encoding of the identity, (0, 1).
    pub const identity_encoding: [encoded_length]u8 = .{1} ++ @as([encoded_length - 1]u8, @splat(0));

    /// RFC 8032 5.1.2: y, with x's low bit as the top bit.
    pub fn encode(a: *const Affine) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        for (0..4) |i| std.mem.writeInt(u64, out[8 * i ..][0..8], a.words[4 + i], .little);
        out[31] |= @as(u8, @truncate(a.words[0] & 1)) << 7; // safe: x's low bit
        return out;
    }

    /// (-x, y).
    pub fn neg(a: *const Affine) Affine {
        var x: [encoded_length]u8 = undefined;
        for (0..4) |i| std.mem.writeInt(u64, x[8 * i ..][0..8], a.words[i], .little);
        const negated = Fe.fromBytes(&x).neg().toBytes();
        var r = a.*;
        for (0..4) |i| r.words[i] = std.mem.readInt(u64, negated[8 * i ..][0..8], .little);
        return r;
    }

    /// Whether x is zero: the identity or (0, -1), the points no key or commitment may be.
    pub fn xIsZero(a: *const Affine) bool {
        return a.words[0] | a.words[1] | a.words[2] | a.words[3] == 0;
    }
};

/// The encoding of [scalar]B, for any 256-bit little-endian scalar.
pub fn base(out: *[encoded_length]u8, scalar: *const [32]u8) void {
    With(backend, null).base(out, scalar);
}

/// RFC 8032 5.1.3: the point an encoding names, or null when y is not below p, no x exists,
/// or x is zero with the sign bit set.
pub fn decode(bytes: *const [encoded_length]u8) ?Affine {
    return With(backend, null).decode(bytes);
}

/// Whether an encoding's y (its low 255 bits) is below p.
pub fn isCanonicalY(bytes: *const [encoded_length]u8) bool {
    var masked = bytes.*;
    masked[31] &= 127;
    return std.mem.eql(u8, &Fe.fromBytes(&masked).toBytes(), &masked);
}

/// The encoding of [h]A + [s]B, for public scalars below 2^255.
pub fn mulDoubleBasePublic(out: *[encoded_length]u8, h: *const [32]u8, a: *const Affine, s: *const [32]u8) void {
    With(backend, null).mulDoubleBasePublic(out, h, a, s);
}

/// Whether [L]A is the identity: A has no small-order component.
pub fn inPrimeOrderSubgroup(a: *const Affine) bool {
    var out: [encoded_length]u8 = undefined;
    mulDoubleBasePublic(&out, &order_bytes, a, &zero_scalar);
    return std.mem.eql(u8, &out, &Affine.identity_encoding);
}

const order_bytes: [32]u8 = blk: {
    var bytes: [32]u8 = undefined;
    std.mem.writeInt(u256, &bytes, order, .little);
    break :blk bytes;
};
const zero_scalar: [32]u8 = @splat(0);

/// A backend, and for s2n-bignum its variant (null is the build's choice), for testing and
/// measuring each.
pub fn With(comptime chosen: Backend, comptime variant: ?s2n.Variant) type {
    if (chosen == .s2n and !s2n.assembly) @compileError("s2n-bignum's assembly is not in this build");
    return struct {
        fn alt() bool {
            return (variant orelse s2n.chosen()) == .alt;
        }

        pub fn base(out: *[encoded_length]u8, scalar: *const [32]u8) void {
            switch (chosen) {
                .fiat => portable.base(out, scalar),
                .s2n => {
                    var owner: Secret(struct { point: Affine, scalar: [4]u64 }) = .init(undefined);
                    defer owner.deinit();
                    const words = owner.exposeMut();
                    words.scalar = toWords(scalar);
                    const F = fn (*[8]u64, *const [4]u64) callconv(.c) void;
                    const f = if (alt()) s2n.routine(F, "edwards25519_scalarmulbase_alt") else s2n.routine(F, "edwards25519_scalarmulbase");
                    f(&words.point.words, &words.scalar);
                    out.* = words.point.encode();
                },
            }
        }

        pub fn decode(bytes: *const [encoded_length]u8) ?Affine {
            switch (chosen) {
                .fiat => return portable.decode(bytes),
                .s2n => {
                    var a: Affine = undefined;
                    const F = fn (*[8]u64, *const [encoded_length]u8) callconv(.c) u64;
                    const f = if (alt()) s2n.routine(F, "edwards25519_decode_alt") else s2n.routine(F, "edwards25519_decode");
                    return if (f(&a.words, bytes) == 0) a else null;
                },
            }
        }

        pub fn mulDoubleBasePublic(out: *[encoded_length]u8, h: *const [32]u8, a: *const Affine, s: *const [32]u8) void {
            std.debug.assert(h[31] < 128);
            std.debug.assert(s[31] < 128);
            switch (chosen) {
                .fiat => portable.mulDoubleBasePublic(out, h, a, s),
                .s2n => {
                    var r: Affine = undefined;
                    const hw = toWords(h);
                    const sw = toWords(s);
                    const F = fn (*[8]u64, *const [4]u64, *const [8]u64, *const [4]u64) callconv(.c) void;
                    const f = if (alt()) s2n.routine(F, "edwards25519_scalarmuldouble_alt") else s2n.routine(F, "edwards25519_scalarmuldouble");
                    f(&r.words, &hw, &a.words, &sw);
                    out.* = r.encode();
                },
            }
        }
    };
}

fn toWords(bytes: *const [32]u8) [4]u64 {
    var words: [4]u64 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
    return words;
}

// ---------------------------------------------------------------- scalars

/// x mod L for a 64-byte little-endian x (RFC 8032's SHA-512 outputs): lo + hi * (2^256 mod L).
pub fn reduce64(wide: *const [64]u8) [32]u8 {
    const lo = Scalar.reduce(toWords(wide[0..32]));
    const hi = Scalar.reduce(toWords(wide[32..64]));
    const shifted = hi.mul(comptime Scalar.constant((1 << 256) % order));
    return toBytes(lo.add(shifted));
}

/// a * b + c mod L, for any 256-bit little-endian a, b and c.
pub fn mulAdd(a: *const [32]u8, b: *const [32]u8, c: *const [32]u8) [32]u8 {
    var owner: Secret(struct { product: Scalar, sum: Scalar }) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    s.product = Scalar.reduce(toWords(a)).mul(Scalar.reduce(toWords(b)));
    s.sum = s.product.add(Scalar.reduce(toWords(c)));
    return toBytes(s.sum);
}

/// Whether a little-endian scalar is below L (RFC 8032 5.1.7's check on S).
pub fn isCanonical(s: *const [32]u8) bool {
    return Scalar.lessThanModulus(toWords(s));
}

fn toBytes(a: Scalar) [32]u8 {
    var owner: Secret([4]u64) = .init(a.toInt());
    defer owner.deinit();
    const value = owner.exposeMut();
    var out: [32]u8 = undefined;
    for (0..4) |i| std.mem.writeInt(u64, out[8 * i ..][0..8], value[i], .little);
    return out;
}

// ---------------------------------------------------------------- the portable group

const portable = struct {
    /// -121665 / 121666, and twice it.
    const d = Fe.constant(37095705934669439343138083508754565189542113879843219016388785533085940283555);
    const d2 = Fe.constant(16295367250680780974490674513165176452449235426866156013048779062215315747161);
    const sqrtm1 = Fe.constant(19681161376707505956807079304988542015446066515923890162744021073123829784752);

    /// Extended coordinates (X : Y : Z : T), x = X/Z, y = Y/Z, xy = T/Z.
    const Point = struct {
        x: Fe,
        y: Fe,
        z: Fe,
        t: Fe,

        const identity: Point = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.one, .t = Fe.zero };

        fn fromAffine(x: Fe, y: Fe) Point {
            return .{ .x = x, .y = y, .z = Fe.one, .t = x.mul(&y) };
        }

        /// add-2008-hwcd-3: complete for a = -1 with d not a square, so it also doubles and
        /// takes the identity.
        fn add(p: *const Point, q: *const Point) Point {
            const a = p.y.sub(&p.x).mul(&q.y.sub(&q.x));
            const b = p.y.add(&p.x).mul(&q.y.add(&q.x));
            const c = p.t.mul(&d2).mul(&q.t);
            const zz = p.z.mul(&q.z);
            const dd = zz.add(&zz);
            const e = b.sub(&a);
            const f = dd.sub(&c);
            const g = dd.add(&c);
            const h = b.add(&a);
            return .{ .x = e.mul(&f), .y = g.mul(&h), .z = f.mul(&g), .t = e.mul(&h) };
        }

        /// dbl-2008-hwcd with a = -1.
        fn dbl(p: *const Point) Point {
            const a = p.x.sqr();
            const b = p.y.sqr();
            const zz = p.z.sqr();
            const c = zz.add(&zz);
            const e = p.x.add(&p.y).sqr().sub(&a).sub(&b);
            const g = b.sub(&a);
            const f = g.sub(&c);
            const h = a.add(&b).neg();
            return .{ .x = e.mul(&f), .y = g.mul(&h), .z = f.mul(&g), .t = e.mul(&h) };
        }

        fn select(bit: u1, a: *const Point, b: *const Point) Point {
            return .{ .x = Fe.select(bit, &a.x, &b.x), .y = Fe.select(bit, &a.y, &b.y), .z = Fe.select(bit, &a.z, &b.z), .t = Fe.select(bit, &a.t, &b.t) };
        }

        fn encode(p: *const Point) [encoded_length]u8 {
            const inverse = p.z.invert();
            const x = p.x.mul(&inverse);
            var out = p.y.mul(&inverse).toBytes();
            out[31] |= @as(u8, x.isNegative()) << 7;
            return out;
        }
    };

    const generator = Point.fromAffine(
        Fe.constant(15112221349535400772501151409588531511454012693041857206046113283949847762202),
        Fe.constant(46316835694926478169428394003475163141307993866256225615783033603165251855960),
    );

    /// 0 * B to 15 * B.
    const base_table: [16]Point = blk: {
        @setEvalBranchQuota(1_000_000);
        var table: [16]Point = undefined;
        table[0] = Point.identity;
        for (1..16) |i| table[i] = table[i - 1].add(&generator);
        break :blk table;
    };

    /// The 4-bit digit `i` of a little-endian scalar, counted from the bottom.
    fn digit(scalar: *const [32]u8, i: usize) u4 {
        return @truncate(scalar[i / 2] >> @intCast(4 * (i % 2))); // safe: one nibble
    }

    const BaseState = struct { q: Point, selected: Point, digit: u8 };

    /// Sixty-four windows from the top, each four doublings and the addition of a table entry
    /// found by scanning all sixteen.
    fn base(out: *[encoded_length]u8, scalar: *const [32]u8) void {
        var owner: Secret(BaseState) = .init(undefined);
        defer owner.deinit();
        const s = owner.exposeMut();
        s.q = Point.identity;
        var i: usize = 64;
        while (i > 0) {
            i -= 1;
            s.q = s.q.dbl().dbl().dbl().dbl();
            s.digit = digit(scalar, i);
            s.selected = Point.identity;
            inline for (1..16) |j| {
                // One when the digit is j: (digit ^ j) - 1 borrows only from zero.
                const hit: u1 = @truncate(((@as(u32, s.digit) ^ j) -% 1) >> 31); // safe: the borrow bit
                s.selected = Point.select(hit, &s.selected, &base_table[j]);
            }
            s.q = s.q.add(&s.selected);
        }
        out.* = s.q.encode();
    }

    fn decode(bytes: *const [encoded_length]u8) ?Affine {
        if (!isCanonicalY(bytes)) return null;
        const y = Fe.fromBytes(bytes);
        // x^2 = u / v with u = y^2 - 1 and v = d y^2 + 1; the candidate u v^3 (u v^7)^((p-5)/8).
        const yy = y.sqr();
        const u = yy.sub(&Fe.one);
        const v = yy.mul(&d).add(&Fe.one);
        const v3 = v.sqr().mul(&v);
        const v7 = v3.sqr().mul(&v);
        var x = u.mul(&v3).mul(&u.mul(&v7).pow22523());
        const vxx = x.sqr().mul(&v);
        if (!vxx.eql(&u)) {
            if (!vxx.eql(&u.neg())) return null;
            x = x.mul(&sqrtm1);
        }
        const sign: u1 = @truncate(bytes[31] >> 7); // safe: the top bit
        if (x.isZero() and sign == 1) return null;
        if (x.isNegative() != sign) x = x.neg();
        return toAffine(&x, &y);
    }

    fn toAffine(x: *const Fe, y: *const Fe) Affine {
        const xb = x.toBytes();
        const yb = y.toBytes();
        var a: Affine = undefined;
        for (0..4) |i| {
            a.words[i] = std.mem.readInt(u64, xb[8 * i ..][0..8], .little);
            a.words[4 + i] = std.mem.readInt(u64, yb[8 * i ..][0..8], .little);
        }
        return a;
    }

    fn fromAffine(a: *const Affine) Point {
        var xb: [32]u8 = undefined;
        var yb: [32]u8 = undefined;
        for (0..4) |i| {
            std.mem.writeInt(u64, xb[8 * i ..][0..8], a.words[i], .little);
            std.mem.writeInt(u64, yb[8 * i ..][0..8], a.words[4 + i], .little);
        }
        return Point.fromAffine(Fe.fromBytes(&xb), Fe.fromBytes(&yb));
    }

    /// Interleaved 4-bit windows over both scalars, public.
    fn mulDoubleBasePublic(out: *[encoded_length]u8, h: *const [32]u8, a: *const Affine, s: *const [32]u8) void {
        var table: [16]Point = undefined;
        table[0] = Point.identity;
        table[1] = fromAffine(a);
        for (2..16) |i| table[i] = table[i - 1].add(&table[1]);
        var q = Point.identity;
        var i: usize = 64;
        while (i > 0) {
            i -= 1;
            q = q.dbl().dbl().dbl().dbl();
            const hd = digit(h, i);
            const sd = digit(s, i);
            if (hd != 0) q = q.add(&table[hd]);
            if (sd != 0) q = q.add(&base_table[sd]);
        }
        out.* = q.encode();
    }
};

test {
    _ = @import("edwards25519_test.zig");
}
