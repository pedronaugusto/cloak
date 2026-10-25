//! P-521 (secp521r1): key generation, ECDH and ECDSA arithmetic over the field seam
//! (`field/p521.zig`: s2n-bignum's verified assembly or fiat-crypto's verified Zig) and the
//! generic constant-time Montgomery field for the scalars mod n.
//!
//! Secret scalars (private keys, ECDSA nonces, ECDH secrets) only meet constant-time code: a
//! multiplication walks signed five-bit windows over a table of the point's multiples, scans
//! every entry and handles the identity and the doubling case by selection, never by a branch;
//! the base point takes the same walk. Signature verification sees only public values and may
//! branch on them. The multiplications keep their long-lived secret state (accumulator,
//! selected point, digits) in one scratch owner that is wiped before they return; callers run
//! them inside `aegis.secret.scrubbed`, which scrubs what the field's assembly leaves below.
const std = @import("std");
const field = @import("field/p521.zig");
const Montgomery = @import("field/Montgomery.zig");

pub const Fe = field.Fe;
pub const order = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409;
pub const Scalar = Montgomery.Field(order);
const prime: u522 = std.math.maxInt(u521);

const b = Fe.constant(0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00);
pub const generator: Affine = .{
    .x = Fe.constant(0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66),
    .y = Fe.constant(0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650),
};

pub const scalar_length = 66;
pub const field_length = 66;
pub const public_length = 1 + 2 * field_length;
pub const Limbs = Scalar.Limbs;

pub const Affine = struct {
    x: Fe,
    y: Fe,

    /// The right-hand side of the curve equation, x^3 - 3x + b.
    fn rhs(x: *const Fe) Fe {
        return x.sqr().mul(x).sub(&x.dbl().add(x)).add(&b);
    }

    /// y^2 = x^3 - 3x + b, checked on public coordinates.
    pub fn onCurve(p: *const Affine) bool {
        return p.y.sqr().eql(&rhs(&p.x));
    }

    /// An uncompressed (0x04) or compressed (0x02/0x03) SEC1 encoding of a point on the
    /// curve; the identity has no encoding here.
    pub fn fromSec1(bytes: []const u8) error{InvalidEncoding}!Affine {
        if (bytes.len == public_length and bytes[0] == 4) {
            const p: Affine = .{
                .x = Fe.fromBytes(bytes[1..67]) catch return error.InvalidEncoding,
                .y = Fe.fromBytes(bytes[67..133]) catch return error.InvalidEncoding,
            };
            if (!p.onCurve()) return error.InvalidEncoding;
            return p;
        }
        if (bytes.len == 1 + field_length and (bytes[0] == 2 or bytes[0] == 3)) {
            const x = Fe.fromBytes(bytes[1..67]) catch return error.InvalidEncoding;
            const square = rhs(&x);
            // p = 3 mod 4: a square root is square^((p+1)/4) = square^(2^519).
            var y = square.sqrn(519);
            if (!y.sqr().eql(&square)) return error.InvalidEncoding;
            if (y.toBytes()[field_length - 1] & 1 != bytes[0] & 1) y = y.neg();
            return .{ .x = x, .y = y };
        }
        return error.InvalidEncoding;
    }

    pub fn toSec1(p: *const Affine) [public_length]u8 {
        var out: [public_length]u8 = undefined;
        out[0] = 4;
        out[1..67].* = p.x.toBytes();
        out[67..133].* = p.y.toBytes();
        return out;
    }
};

/// Jacobian coordinates (X:Y:Z), x = X/Z^2, y = Y/Z^3. Z = 0 is the identity.
pub const Jacobian = struct {
    x: Fe,
    y: Fe,
    z: Fe,

    pub const identity: Jacobian = .{ .x = Fe.one, .y = Fe.one, .z = Fe.zero };

    pub fn fromAffine(p: *const Affine) Jacobian {
        return .{ .x = p.x, .y = p.y, .z = Fe.one };
    }

    /// dbl-2001-b for a = -3: 3M + 5S. The identity doubles to the identity.
    pub fn dbl(p: *const Jacobian) Jacobian {
        const delta = p.z.sqr();
        const gamma = p.y.sqr();
        const beta = p.x.mul(&gamma);
        const t = p.x.sub(&delta).mul(&p.x.add(&delta));
        const alpha = t.dbl().add(&t);
        const beta4 = beta.dbl().dbl();
        const x3 = alpha.sqr().sub(&beta4.dbl());
        const z3 = p.y.add(&p.z).sqr().sub(&gamma).sub(&delta);
        const y3 = alpha.mul(&beta4.sub(&x3)).sub(&gamma.sqr().dbl().dbl().dbl());
        return .{ .x = x3, .y = y3, .z = z3 };
    }

    /// add-2007-bl without its exceptional cases resolved: the caller handles an identity
    /// input and p == q. Returns the sum and the two values that detect p == +-q.
    fn addRaw(p: *const Jacobian, q: *const Jacobian) struct { sum: Jacobian, h: Fe, r: Fe } {
        const z1z1 = p.z.sqr();
        const z2z2 = q.z.sqr();
        const x1z = p.x.mul(&z2z2);
        const x2z = q.x.mul(&z1z1);
        const s1 = p.y.mul(&q.z).mul(&z2z2);
        const s2 = q.y.mul(&p.z).mul(&z1z1);
        const h = x2z.sub(&x1z);
        const i = h.dbl().sqr();
        const j = h.mul(&i);
        const r = s2.sub(&s1).dbl();
        const v = x1z.mul(&i);
        const x3 = r.sqr().sub(&j).sub(&v.dbl());
        const y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).dbl());
        const z3 = p.z.add(&q.z).sqr().sub(&z1z1).sub(&z2z2).mul(&h);
        return .{ .sum = .{ .x = x3, .y = y3, .z = z3 }, .h = h, .r = r };
    }

    /// Constant-time sum for every input pair: the identity cases and p == q are selected,
    /// the doubling always computed.
    pub fn addConstantTime(p: *const Jacobian, q: *const Jacobian) Jacobian {
        const raw = addRaw(p, q);
        const doubled = p.dbl();
        const same = raw.h.isZeroMask() & raw.r.isZeroMask();
        var out = select(same, &raw.sum, &doubled);
        out = select(p.z.isZeroMask(), &out, q);
        out = select(q.z.isZeroMask(), &out, p);
        return out;
    }

    /// Public sum: branches on the exceptional cases.
    pub fn addPublic(p: *const Jacobian, q: *const Jacobian) Jacobian {
        if (p.z.isZero()) return q.*;
        if (q.z.isZero()) return p.*;
        const raw = addRaw(p, q);
        if (raw.h.isZero()) return if (raw.r.isZero()) p.dbl() else identity;
        return raw.sum;
    }

    pub fn neg(p: *const Jacobian) Jacobian {
        return .{ .x = p.x, .y = p.y.neg(), .z = p.z };
    }

    pub fn select(mask: u64, a: *const Jacobian, c: *const Jacobian) Jacobian {
        return .{ .x = Fe.select(mask, &a.x, &c.x), .y = Fe.select(mask, &a.y, &c.y), .z = Fe.select(mask, &a.z, &c.z) };
    }

    /// The affine point; the identity maps to (0, 0), which callers reject.
    pub fn affine(p: *const Jacobian) Affine {
        const zi = p.z.invert();
        const zi2 = zi.sqr();
        return .{ .x = p.x.mul(&zi2), .y = p.y.mul(&zi2.mul(&zi)) };
    }
};

// ---------------------------------------------------------------- scalars

pub const Digit = struct { magnitude: u8, negative: u1 };

const window_bits = 5;
/// 5 * 105 = 525 > 522 bits of the recoded scalar (its 521 bits and the top window's carry).
const windows = 105;

/// Signed windows of five bits (Booth recoding): digit i is the value of scalar bits
/// [5i - 1, 5i + 4], mapped to a magnitude in [0, 16] and a sign. Branch-free over secret
/// scalars.
pub fn recode(scalar: *const Limbs, out: *[windows]Digit) void {
    const mask: u64 = (1 << (window_bits + 1)) - 1;
    inline for (0..windows) |i| {
        const raw = window(scalar, @as(i32, window_bits) * @as(i32, i) - 1) & mask;
        const negative = 0 -% (raw >> window_bits); // all ones when the top bit is set
        var d = ((mask - raw) & negative) | (raw & ~negative);
        d = (d >> 1) + (d & 1);
        out[i] = .{ .magnitude = @truncate(d), .negative = @truncate(negative & 1) }; // safe: d <= 16 and the sign is one bit
    }
}

/// Six bits of the scalar from `position` (which may be -1; bits outside it read as zero).
/// Positions are public, so the shifts are fixed.
inline fn window(scalar: *const Limbs, comptime position: i32) u64 {
    if (position < 0) return scalar[0] << 1;
    const limb = @as(usize, @intCast(position)) / 64;
    const shift: u6 = @intCast(@as(usize, @intCast(position)) % 64);
    if (limb >= scalar.len) return 0;
    var value = scalar[limb] >> shift;
    if (shift != 0 and limb + 1 < scalar.len) value |= scalar[limb + 1] << @intCast(64 - @as(u7, shift));
    return value;
}

/// Whether 0 < scalar < n, in constant time; only the verdict is released.
pub fn scalarInRange(bytes: *const [scalar_length]u8) bool {
    const value = Scalar.limbsFromBytes(bytes);
    var any: u64 = 0;
    for (value) |limb| any |= limb;
    const nonzero = ~Montgomery.zeroMask(any);
    return (nonzero & 1) == 1 and Scalar.lessThanModulus(value);
}

// ---------------------------------------------------------------- multiplication

const Scratch = struct {
    acc: Jacobian,
    selected: Jacobian,
    digits: [windows]Digit,
    limbs: Limbs,
};

/// scalar * p for a secret big-endian scalar in [1, n) and a public point on the curve.
pub fn mul(p: *const Affine, scalar: *const [scalar_length]u8) Jacobian {
    // Public table: 1p .. 16p.
    var multiples: [16]Jacobian = undefined;
    multiples[0] = Jacobian.fromAffine(p);
    multiples[1] = multiples[0].dbl();
    for (2..16) |i| multiples[i] = if (i % 2 == 1) multiples[i / 2].dbl() else multiples[i - 1].addPublic(&multiples[0]);
    var s: Scratch = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&s));
    s.limbs = Scalar.limbsFromBytes(scalar);
    recode(&s.limbs, &s.digits);
    s.acc = Jacobian.identity;
    var i: usize = windows;
    while (i > 0) {
        i -= 1;
        if (i != windows - 1) {
            inline for (0..window_bits) |_| s.acc = s.acc.dbl();
        }
        selectPoint(&s.selected, &multiples, s.digits[i]);
        s.acc = s.acc.addConstantTime(&s.selected);
    }
    return s.acc;
}

/// scalar * G for a secret big-endian scalar in [1, n): the same walk from the base point.
pub fn baseMul(scalar: *const [scalar_length]u8) Jacobian {
    return mul(&generator, scalar);
}

/// The multiple for `digit`, negated when negative, the identity for zero; every entry is read.
fn selectPoint(out: *Jacobian, multiples: *const [16]Jacobian, digit: Digit) void {
    out.* = Jacobian.identity;
    for (multiples, 1..) |*entry, j| {
        const hit = Montgomery.zeroMask(@as(u64, digit.magnitude) ^ j);
        out.* = Jacobian.select(hit, out, entry);
    }
    out.y = Fe.select(Montgomery.maskOf(digit.negative), &out.y, &out.y.neg());
}

/// Public u1 * G + u2 * q for verification, by width-5 NAFs over both.
pub fn mulDoubleBasePublic(g_scalar: *const Limbs, q: *const Affine, q_scalar: *const Limbs) Jacobian {
    const g_odd = oddMultiples(&generator);
    const q_odd = oddMultiples(q);
    var g_naf: [522]i8 = undefined;
    var q_naf: [522]i8 = undefined;
    const g_top = wnaf(g_scalar, &g_naf);
    const q_top = wnaf(q_scalar, &q_naf);
    var acc = Jacobian.identity;
    var i: usize = @max(g_top, q_top);
    while (i > 0) {
        i -= 1;
        acc = acc.dbl();
        if (i < g_top) acc = addDigit(&acc, &g_odd, g_naf[i]);
        if (i < q_top) acc = addDigit(&acc, &q_odd, q_naf[i]);
    }
    return acc;
}

/// p, 3p, .., 15p.
fn oddMultiples(p: *const Affine) [8]Jacobian {
    var odd: [8]Jacobian = undefined;
    odd[0] = Jacobian.fromAffine(p);
    const twice = odd[0].dbl();
    for (1..8) |i| odd[i] = odd[i - 1].addPublic(&twice);
    return odd;
}

fn addDigit(acc: *const Jacobian, odd: *const [8]Jacobian, d: i8) Jacobian {
    if (d > 0) return acc.addPublic(&odd[@intCast(@divTrunc(d - 1, 2))]);
    if (d < 0) return acc.addPublic(&odd[@intCast(@divTrunc(-d - 1, 2))].neg());
    return acc.*;
}

/// Width-5 non-adjacent form of a public scalar; returns the number of digits used.
fn wnaf(scalar: *const Limbs, out: *[522]i8) usize {
    var k: u577 = 0;
    for (scalar, 0..) |limb, i| k |= @as(u577, limb) << @intCast(64 * i);
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

/// The ECDSA digest scalar: the leftmost 521 bits of `digest` as an integer (SEC1 4.1.3
/// step 5), reduced mod n, in Montgomery form. SHA-512's 512 bits are all taken.
pub fn digestScalar(digest: []const u8) Scalar {
    var bytes: [scalar_length]u8 = @splat(0);
    if (digest.len <= scalar_length) {
        @memcpy(bytes[scalar_length - digest.len ..], digest);
    } else {
        // Longer than 521 bits: the leftmost 528, shifted right by seven.
        std.mem.writeInt(u528, &bytes, std.mem.readInt(u528, digest[0..scalar_length], .big) >> 7, .big);
    }
    return Scalar.reduce(Scalar.limbsFromBytes(&bytes));
}

/// x(R) mod n for R = k*G, as a scalar in Montgomery form, or null if R is the identity.
pub fn signR(k: *const [scalar_length]u8) ?Scalar {
    var r = baseMul(k);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&r));
    if (r.z.isZero()) return null;
    const x = r.affine().x.toBytes();
    return Scalar.reduce(Scalar.limbsFromBytes(&x));
}

/// Checks an ECDSA signature (r, s) over a digest scalar `e` (`digestScalar`).
pub fn verify(q: *const Affine, e: Scalar, r_bytes: *const [scalar_length]u8, s_bytes: *const [scalar_length]u8) bool {
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
    const r_fe = Fe.fromBytes(r_bytes) catch return false;
    if (r_fe.mul(&z2).eql(&point.x)) return true;
    // r < n (checked above), so the sum fits 528 bits.
    const shifted = std.mem.readInt(u528, r_bytes, .big) + order;
    if (shifted >= prime) return false;
    var shifted_bytes: [field_length]u8 = undefined;
    std.mem.writeInt(u528, &shifted_bytes, shifted, .big);
    const shifted_fe = Fe.fromBytes(&shifted_bytes) catch return false;
    return shifted_fe.mul(&z2).eql(&point.x);
}

test {
    _ = @import("p521_test.zig");
}
