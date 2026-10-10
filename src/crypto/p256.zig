//! P-256 (secp256r1): key generation, ECDH and ECDSA arithmetic.
//!
//! Secret scalars (private keys, ECDSA nonces, ECDH secrets) only meet constant-time code:
//! the base multiplication walks a precomputed comb with a full scan of each window and
//! complete projective additions, which have no exceptional cases; the variable-point
//! multiplication walks signed five-bit windows over a public table of the peer's multiples,
//! scans every entry and handles the identity and the doubling case by selection, never by a
//! branch. Signature verification sees only public values and may branch on them.
//!
//! Field and scalar values are Montgomery residues held in registers; the multiplications keep
//! their long-lived secret state (accumulator, selected point, digits) in one scratch owner that
//! is wiped before they return.
const std = @import("std");
const Montgomery = @import("p256/Montgomery.zig");
const table = @import("p256/table.zig");

pub const Fe = Montgomery.Field(0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff);
pub const Scalar = Montgomery.Field(0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551);
pub const order: u256 = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551;

const b = Fe.constant(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b);
const three_b = Fe.constant(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b * 3 % 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff);

pub const scalar_length = 32;
pub const public_length = 65;

/// Comb parameters of the base table: signed six-bit windows.
pub const comb_bits = table.bits;
pub const comb_windows = table.windows;
const comb_entries = 1 << (comb_bits - 1);

/// x^(p-2) by the usual P-256 addition chain: 255 squarings and 12 multiplications.
pub fn invert(x: Fe) Fe {
    const x2 = x.sqr().mul(x);
    const x3 = x2.sqr().mul(x);
    const x6 = x3.sqrn(3).mul(x3);
    const x12 = x6.sqrn(6).mul(x6);
    const x15 = x12.sqrn(3).mul(x3);
    const x30 = x15.sqrn(15).mul(x15);
    const x32 = x30.sqrn(2).mul(x2);
    var t = x32.sqrn(32).mul(x);
    t = t.sqrn(128).mul(x32);
    t = t.sqrn(32).mul(x32);
    t = t.sqrn(30).mul(x30);
    return t.sqrn(2).mul(x);
}

pub const Affine = struct {
    x: Fe,
    y: Fe,

    /// The curve equation y^2 = x^3 - 3x + b, checked on public coordinates.
    pub fn onCurve(p: Affine) bool {
        const rhs = p.x.sqr().mul(p.x).sub(p.x.dbl().add(p.x)).add(b);
        return p.y.sqr().eql(rhs);
    }

    /// An uncompressed (0x04) or compressed (0x02/0x03) SEC1 encoding of a point on the
    /// curve; the identity has no encoding here.
    pub fn fromSec1(bytes: []const u8) error{InvalidEncoding}!Affine {
        if (bytes.len == public_length and bytes[0] == 4) {
            const p: Affine = .{
                .x = Fe.fromBytes(bytes[1..33]) catch return error.InvalidEncoding,
                .y = Fe.fromBytes(bytes[33..65]) catch return error.InvalidEncoding,
            };
            if (!p.onCurve()) return error.InvalidEncoding;
            return p;
        }
        if (bytes.len == 33 and (bytes[0] == 2 or bytes[0] == 3)) {
            const x = Fe.fromBytes(bytes[1..33]) catch return error.InvalidEncoding;
            const rhs = x.sqr().mul(x).sub(x.dbl().add(x)).add(b);
            // p = 3 mod 4: a square root is rhs^((p+1)/4).
            var y = sqrtCandidate(rhs);
            if (!y.sqr().eql(rhs)) return error.InvalidEncoding;
            const odd = y.toInt()[0] & 1;
            if (odd != bytes[0] & 1) y = y.neg();
            return .{ .x = x, .y = y };
        }
        return error.InvalidEncoding;
    }

    pub fn toSec1(p: Affine) [public_length]u8 {
        var out: [public_length]u8 = undefined;
        out[0] = 4;
        out[1..33].* = p.x.toBytes();
        out[33..65].* = p.y.toBytes();
        return out;
    }
};

fn sqrtCandidate(a: Fe) Fe {
    // (p+1)/4 = 2^254 - 2^222 + 2^190 + 2^94
    var r = a;
    const exponent: u256 = (0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff + 1) / 4;
    var acc = Fe.one;
    var i: usize = 256;
    while (i > 0) {
        i -= 1;
        acc = acc.sqr();
        if ((exponent >> @intCast(i)) & 1 == 1) acc = acc.mul(r);
    }
    r = acc;
    return r;
}

// ---------------------------------------------------------------- complete projective points

/// Homogeneous projective coordinates (X:Y:Z), x = X/Z. The identity is (0:1:0).
pub const Projective = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    pub const identity: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

    /// Complete addition of an affine point (Renes, Costello and Batina 2015, algorithm 5,
    /// a = -3): correct for every `p`, including the identity and `p == q`.
    pub fn addAffine(p: Projective, q: Affine) Projective {
        var t0 = p.x.mul(q.x);
        var t1 = p.y.mul(q.y);
        var t3 = q.x.add(q.y);
        var t4 = p.x.add(p.y);
        t3 = t3.mul(t4);
        t4 = t0.add(t1);
        t3 = t3.sub(t4);
        t4 = q.y.mul(p.z);
        t4 = t4.add(p.y);
        var y3 = q.x.mul(p.z);
        y3 = y3.add(p.x);
        var z3 = b.mul(p.z);
        var x3 = y3.sub(z3);
        z3 = x3.dbl();
        x3 = x3.add(z3);
        z3 = t1.sub(x3);
        x3 = t1.add(x3);
        y3 = b.mul(y3);
        t1 = p.z.dbl();
        var t2 = t1.add(p.z);
        y3 = y3.sub(t2);
        y3 = y3.sub(t0);
        t1 = y3.dbl();
        y3 = t1.add(y3);
        t1 = t0.dbl();
        t0 = t1.add(t0);
        t0 = t0.sub(t2);
        t1 = t4.mul(y3);
        t2 = t0.mul(y3);
        y3 = x3.mul(z3);
        y3 = y3.add(t2);
        x3 = t3.mul(x3);
        x3 = x3.sub(t1);
        z3 = t4.mul(z3);
        t1 = t3.mul(t0);
        z3 = z3.add(t1);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    pub fn select(mask: u64, a: Projective, c: Projective) Projective {
        return .{ .x = Fe.select(mask, a.x, c.x), .y = Fe.select(mask, a.y, c.y), .z = Fe.select(mask, a.z, c.z) };
    }

    /// The affine point; the identity maps to (0, 0), which callers reject.
    pub fn affine(p: Projective) Affine {
        const inverse = invert(p.z);
        return .{ .x = p.x.mul(inverse), .y = p.y.mul(inverse) };
    }
};

// ---------------------------------------------------------------- Jacobian points

/// Jacobian coordinates (X:Y:Z), x = X/Z^2, y = Y/Z^3. Z = 0 is the identity.
pub const Jacobian = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    pub const identity: Jacobian = .{ .x = Fe.one, .y = Fe.one, .z = Fe.zero };

    pub fn fromAffine(p: Affine) Jacobian {
        return .{ .x = p.x, .y = p.y, .z = Fe.one };
    }

    /// dbl-2001-b for a = -3: 3M + 5S. The identity doubles to the identity.
    pub fn dbl(p: Jacobian) Jacobian {
        const delta = p.z.sqr();
        const gamma = p.y.sqr();
        const beta = p.x.mul(gamma);
        const t = p.x.sub(delta).mul(p.x.add(delta));
        const alpha = t.dbl().add(t);
        const beta4 = beta.dbl().dbl();
        const x3 = alpha.sqr().sub(beta4.dbl());
        const z3 = p.y.add(p.z).sqr().sub(gamma).sub(delta);
        const gamma2 = gamma.sqr();
        const y3 = alpha.mul(beta4.sub(x3)).sub(gamma2.dbl().dbl().dbl());
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// add-2007-bl without its exceptional cases resolved: the caller handles an identity
    /// input and p == q. Returns the sum and the two values that detect p == +-q.
    fn addRaw(p: Jacobian, q: Jacobian) struct { sum: Jacobian, h: Fe, r: Fe } {
        const z1z1 = p.z.sqr();
        const z2z2 = q.z.sqr();
        const x1z = p.x.mul(z2z2);
        const x2z = q.x.mul(z1z1);
        const s1 = p.y.mul(q.z).mul(z2z2);
        const s2 = q.y.mul(p.z).mul(z1z1);
        const h = x2z.sub(x1z);
        const i = h.dbl().sqr();
        const j = h.mul(i);
        const r = s2.sub(s1).dbl();
        const v = x1z.mul(i);
        const x3 = r.sqr().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(s1.mul(j).dbl());
        const z3 = p.z.add(q.z).sqr().sub(z1z1).sub(z2z2).mul(h);
        return .{ .sum = .{ .x = x3, .y = y3, .z = z3 }, .h = h, .r = r };
    }

    /// Constant-time sum for every input pair: the identity cases and p == q are selected,
    /// the doubling always computed.
    pub fn addConstantTime(p: Jacobian, q: Jacobian) Jacobian {
        const raw = addRaw(p, q);
        const doubled = p.dbl();
        const same = raw.h.isZeroMask() & raw.r.isZeroMask();
        var out = select(same, raw.sum, doubled);
        out = select(p.z.isZeroMask(), out, q);
        out = select(q.z.isZeroMask(), out, p);
        return out;
    }

    /// Public sum: branches on the exceptional cases.
    pub fn addPublic(p: Jacobian, q: Jacobian) Jacobian {
        if (p.z.isZero()) return q;
        if (q.z.isZero()) return p;
        const raw = addRaw(p, q);
        if (raw.h.isZero()) return if (raw.r.isZero()) p.dbl() else identity;
        return raw.sum;
    }

    /// madd-2007-bl, public inputs: p plus an affine point. 7M + 4S.
    pub fn addAffinePublic(p: Jacobian, q: Affine) Jacobian {
        if (p.z.isZero()) return fromAffine(q);
        const z1z1 = p.z.sqr();
        const x2z = q.x.mul(z1z1);
        const s2 = q.y.mul(p.z).mul(z1z1);
        const h = x2z.sub(p.x);
        const r = s2.sub(p.y).dbl();
        if (h.isZero()) return if (r.isZero()) p.dbl() else identity;
        const hh = h.sqr();
        const i = hh.dbl().dbl();
        const j = h.mul(i);
        const v = p.x.mul(i);
        const x3 = r.sqr().sub(j).sub(v.dbl());
        const y3 = r.mul(v.sub(x3)).sub(p.y.mul(j).dbl());
        const z3 = p.z.add(h).sqr().sub(z1z1).sub(hh);
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    pub fn neg(p: Jacobian) Jacobian {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    pub fn select(mask: u64, a: Jacobian, c: Jacobian) Jacobian {
        return .{ .x = Fe.select(mask, a.x, c.x), .y = Fe.select(mask, a.y, c.y), .z = Fe.select(mask, a.z, c.z) };
    }

    pub fn affine(p: Jacobian) Affine {
        const zi = invert(p.z);
        const zi2 = zi.sqr();
        return .{ .x = p.x.mul(zi2), .y = p.y.mul(zi2.mul(zi)) };
    }
};

// ---------------------------------------------------------------- scalars

/// Signed windows of `bits` bits (Booth recoding): digit i is the value of scalar bits
/// [bits*i - 1, bits*i + bits - 1], mapped to a magnitude in [0, 2^(bits-1)] and a sign.
/// Branch-free over secret scalars.
pub fn recode(comptime bits: u6, scalar: *const [4]u64, comptime windows: usize, out: *[windows]Digit) void {
    const mask: u64 = (1 << (bits + 1)) - 1;
    inline for (0..windows) |i| {
        const position: i32 = @as(i32, bits) * @as(i32, i) - 1;
        const raw = window(scalar, position, bits + 1) & mask;
        const negative = 0 -% (raw >> bits); // all ones when the top bit is set
        var d = ((mask - raw) & negative) | (raw & ~negative);
        d = (d >> 1) + (d & 1);
        out[i] = .{ .magnitude = @truncate(d), .negative = @truncate(negative & 1) }; // safe: d <= 2^(bits-1) and the sign is one bit
    }
}

pub const Digit = struct { magnitude: u8, negative: u1 };

/// `width` bits of the 256-bit scalar starting at `position` (which may be -1; bits outside the
/// scalar read as zero). Positions are public, so the shifts are fixed.
inline fn window(scalar: *const [4]u64, comptime position: i32, comptime width: u7) u64 {
    if (position < 0) return (scalar[0] << 1) & ((@as(u64, 1) << width) - 1);
    const limb = @as(usize, @intCast(position)) / 64;
    const shift: u6 = @intCast(@as(usize, @intCast(position)) % 64);
    if (limb >= 4) return 0;
    var value = scalar[limb] >> shift;
    if (shift != 0 and limb + 1 < 4) value |= scalar[limb + 1] << @intCast(64 - @as(u7, shift));
    return value;
}

pub fn scalarLimbs(bytes: *const [32]u8) [4]u64 {
    return Scalar.limbsFromBytes(bytes);
}

/// Whether 0 < scalar < n, in constant time; only the verdict is released.
pub fn scalarInRange(bytes: *const [32]u8) bool {
    const value = Scalar.limbsFromBytes(bytes);
    const nonzero = ~Montgomery.zeroMask(value[0] | value[1] | value[2] | value[3]);
    const below = Scalar.lessThanModulus(value);
    return (nonzero & 1) == 1 and below;
}

// ---------------------------------------------------------------- base multiplication

const BaseScratch = struct {
    acc: Projective,
    selected: Affine,
    digits: [comb_windows]Digit,
    limbs: [4]u64,
};

/// scalar * G for a secret big-endian scalar in [1, n). The comb walk adds one table entry
/// per window with the complete formula, so neither the identity nor a repeated point needs a
/// branch.
pub fn baseMul(scalar: *const [32]u8) Projective {
    var s: BaseScratch = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&s));
    s.limbs = scalarLimbs(scalar);
    recode(comb_bits, &s.limbs, comb_windows, &s.digits);
    s.acc = Projective.identity;
    for (0..comb_windows) |i| {
        selectBase(&s.selected, i, s.digits[i]);
        const sum = s.acc.addAffine(s.selected);
        // A zero digit adds nothing.
        const skip = Montgomery.zeroMask(s.digits[i].magnitude);
        s.acc = Projective.select(skip, sum, s.acc);
    }
    return s.acc;
}

/// The entry for `digit` of window `i`, negated for a negative digit; every entry is read.
fn selectBase(out: *Affine, i: usize, digit: Digit) void {
    var x: @Vector(4, u64) = @splat(0);
    var y: @Vector(4, u64) = @splat(0);
    const entries = &table.base[i];
    for (entries, 1..) |*entry, j| {
        const hit: @Vector(4, u64) = @splat(Montgomery.zeroMask(@as(u64, digit.magnitude) ^ j));
        x |= hit & @as(@Vector(4, u64), entry[0..4].*);
        y |= hit & @as(@Vector(4, u64), entry[4..8].*);
    }
    out.x = .{ .limbs = x };
    const y_fe: Fe = .{ .limbs = y };
    out.y = Fe.select(Montgomery.maskOf(digit.negative), y_fe, y_fe.neg());
}

/// Public scalar * G for verification: the same comb, indexed directly.
fn baseMulPublic(scalar: *const [4]u64) Jacobian {
    var digits: [comb_windows]Digit = undefined;
    recode(comb_bits, scalar, comb_windows, &digits);
    var acc = Jacobian.identity;
    for (digits, 0..) |digit, i| {
        if (digit.magnitude == 0) continue;
        const entry = &table.base[i][digit.magnitude - 1];
        var q: Affine = .{ .x = .{ .limbs = entry[0..4].* }, .y = .{ .limbs = entry[4..8].* } };
        if (digit.negative == 1) q.y = q.y.neg();
        acc = acc.addAffinePublic(q);
    }
    return acc;
}

// ---------------------------------------------------------------- variable-point multiplication

const point_bits = 5;
const point_windows = 52; // 5 * 52 = 260 > 257 bits of the recoded scalar

const PointScratch = struct {
    acc: Jacobian,
    selected: Jacobian,
    digits: [point_windows]Digit,
    limbs: [4]u64,
};

/// scalar * p for a secret big-endian scalar in [1, n) and a public point on the curve.
pub fn mul(p: Affine, scalar: *const [32]u8) Jacobian {
    // Public table: 1p .. 16p.
    var multiples: [16]Jacobian = undefined;
    multiples[0] = Jacobian.fromAffine(p);
    multiples[1] = multiples[0].dbl();
    for (2..16) |i| multiples[i] = if (i % 2 == 1) multiples[i / 2].dbl() else multiples[i - 1].addPublic(multiples[0]);
    var s: PointScratch = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&s));
    s.limbs = scalarLimbs(scalar);
    recode(point_bits, &s.limbs, point_windows, &s.digits);
    var i: usize = point_windows;
    s.acc = Jacobian.identity;
    while (i > 0) {
        i -= 1;
        if (i != point_windows - 1) {
            inline for (0..point_bits) |_| s.acc = s.acc.dbl();
        }
        selectPoint(&s.selected, &multiples, s.digits[i]);
        s.acc = s.acc.addConstantTime(s.selected);
    }
    return s.acc;
}

/// The multiple for `digit`, negated when negative, the identity for zero; every entry is read.
fn selectPoint(out: *Jacobian, multiples: *const [16]Jacobian, digit: Digit) void {
    out.* = Jacobian.identity;
    for (multiples, 1..) |*entry, j| {
        const hit = Montgomery.zeroMask(@as(u64, digit.magnitude) ^ j);
        out.* = Jacobian.select(hit, out.*, entry.*);
    }
    out.y = Fe.select(Montgomery.maskOf(digit.negative), out.y, out.y.neg());
}

/// Public u1 * G + u2 * q for verification.
pub fn mulDoubleBasePublic(g_scalar: *const [4]u64, q: Affine, q_scalar: *const [4]u64) Jacobian {
    // Odd multiples q, 3q, .., 15q for a width-5 NAF.
    var odd: [8]Jacobian = undefined;
    odd[0] = Jacobian.fromAffine(q);
    const twice = odd[0].dbl();
    for (1..8) |i| odd[i] = odd[i - 1].addPublic(twice);
    var naf: [257]i8 = undefined;
    const top = wnaf(q_scalar, &naf);
    var acc = Jacobian.identity;
    var i: usize = top;
    while (i > 0) {
        i -= 1;
        acc = acc.dbl();
        const d = naf[i];
        if (d > 0) acc = acc.addPublic(odd[@intCast(@divTrunc(d - 1, 2))]);
        if (d < 0) acc = acc.addPublic(odd[@intCast(@divTrunc(-d - 1, 2))].neg());
    }
    return acc.addPublic(baseMulPublic(g_scalar));
}

/// Width-5 non-adjacent form of a public scalar; returns the number of digits used.
fn wnaf(scalar: *const [4]u64, out: *[257]i8) usize {
    var k: u257 = @as(u257, scalar[0]) | @as(u257, scalar[1]) << 64 | @as(u257, scalar[2]) << 128 | @as(u257, scalar[3]) << 192;
    var len: usize = 0;
    while (k != 0) : (len += 1) {
        if (k & 1 == 1) {
            var d: i8 = @intCast(k & 31);
            if (d > 15) d -= 32;
            out[len] = d;
            if (d > 0) k -= @intCast(d) else k += @intCast(-d);
        } else out[len] = 0;
        k >>= 1;
    }
    return len;
}

// ---------------------------------------------------------------- ECDSA pieces

/// x(R) mod n for R = k*G, as a scalar in Montgomery form, or null if R is the identity.
pub fn signR(k: *const [32]u8) ?Scalar {
    var r = baseMul(k);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r));
    if (r.z.isZero()) return null;
    const x = r.affine().x.toInt();
    return Scalar.reduce(x);
}

/// Checks an ECDSA signature (r, s) over a reduced digest scalar `e`, given in normal form.
pub fn verify(q: Affine, e: Scalar, r_bytes: *const [32]u8, s_bytes: *const [32]u8) bool {
    const r = Scalar.fromBytes(r_bytes) catch return false;
    const s = Scalar.fromBytes(s_bytes) catch return false;
    if (r.isZero() or s.isZero()) return false;
    const w = s.powModulusMinusTwo();
    const u_1 = e.mul(w).toInt();
    const u_2 = r.mul(w).toInt();
    const point = mulDoubleBasePublic(&u_1, q, &u_2);
    if (point.z.isZero()) return false;
    // x(point) = X / Z^2; compare X with r * Z^2, and with (r + n) * Z^2 when r + n < p.
    const z2 = point.z.sqr();
    const r_int = r.toInt();
    const r_fe = Fe.fromInt(r_int);
    if (r_fe.mul(z2).eql(point.x)) return true;
    const r_wide: u257 = @as(u257, r_int[0]) | @as(u257, r_int[1]) << 64 | @as(u257, r_int[2]) << 128 | @as(u257, r_int[3]) << 192;
    const shifted = r_wide + order;
    const p_value: u257 = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
    if (shifted >= p_value) return false;
    const limbs: [4]u64 = .{ @truncate(shifted), @truncate(shifted >> 64), @truncate(shifted >> 128), @truncate(shifted >> 192) };
    return Fe.fromInt(limbs).mul(z2).eql(point.x);
}

test {
    _ = Montgomery;
    _ = @import("p256_test.zig");
}
