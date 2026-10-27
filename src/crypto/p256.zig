//! P-256 (secp256r1): key generation, ECDH and ECDSA arithmetic, `weierstrass.zig`'s curve over
//! `field/nist.zig`'s field with a precomputed comb for the base point.
//!
//! The base multiplication walks the comb with a full scan of each window and complete
//! projective additions, which have no exceptional cases; the comb's table holds the field's
//! Montgomery limbs, which both of its backends share. Everything else is the shared curve's.
const Secret = @import("aegis").secret.Secret;
const Montgomery = @import("field/Montgomery.zig");
const weierstrass = @import("weierstrass.zig");
const table = @import("p256/table.zig");

pub const Fe = @import("field/nist.zig").Fe(.p256);

const C = weierstrass.Curve(.{
    .Fe = Fe,
    .order = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551,
    .b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b,
    .gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    .gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5,
    .Comb = Comb,
});

pub const Scalar = C.Scalar;
pub const order = C.order;
pub const b = C.b;
pub const Affine = C.Affine;
pub const Jacobian = C.Jacobian;
pub const Digit = C.Digit;
pub const scalar_length = C.scalar_length;
pub const public_length = C.public_length;
pub const recode = C.recode;
pub const scalarInRange = C.scalarInRange;
pub const mul = C.mul;
pub const baseMul = C.baseMul;
pub const mulDoubleBasePublic = C.mulDoubleBasePublic;
pub const digestScalar = C.digestScalar;
pub const signR = C.signR;
pub const verify = C.verify;

/// Comb parameters of the base table: signed six-bit windows.
pub const comb_bits = table.bits;
pub const comb_windows = table.windows;

pub fn scalarLimbs(bytes: *const [32]u8) [4]u64 {
    return Scalar.limbsFromBytes(bytes);
}

/// The base point's comb: one table entry added per six-bit window.
fn Comb(comptime Curve: type) type {
    return struct {
        /// Homogeneous projective coordinates (X:Y:Z), x = X/Z. The identity is (0:1:0).
        pub const Projective = struct {
            x: Fe,
            y: Fe,
            z: Fe,

            pub const identity: Projective = .{ .x = Fe.zero, .y = Fe.one, .z = Fe.zero };

            /// Complete addition of an affine point (Renes, Costello and Batina 2015, algorithm 5,
            /// a = -3): correct for every `p`, including the identity and `p == q`.
            pub fn addAffine(p: *const Projective, q: *const Curve.Affine) Projective {
                var t0 = p.x.mul(&q.x);
                var t1 = p.y.mul(&q.y);
                var t3 = q.x.add(&q.y);
                var t4 = p.x.add(&p.y);
                t3 = t3.mul(&t4);
                t4 = t0.add(&t1);
                t3 = t3.sub(&t4);
                t4 = q.y.mul(&p.z);
                t4 = t4.add(&p.y);
                var y3 = q.x.mul(&p.z);
                y3 = y3.add(&p.x);
                var z3 = Curve.b.mul(&p.z);
                var x3 = y3.sub(&z3);
                z3 = x3.dbl();
                x3 = x3.add(&z3);
                z3 = t1.sub(&x3);
                x3 = t1.add(&x3);
                y3 = Curve.b.mul(&y3);
                t1 = p.z.dbl();
                var t2 = t1.add(&p.z);
                y3 = y3.sub(&t2);
                y3 = y3.sub(&t0);
                t1 = y3.dbl();
                y3 = t1.add(&y3);
                t1 = t0.dbl();
                t0 = t1.add(&t0);
                t0 = t0.sub(&t2);
                t1 = t4.mul(&y3);
                t2 = t0.mul(&y3);
                y3 = x3.mul(&z3);
                y3 = y3.add(&t2);
                x3 = t3.mul(&x3);
                x3 = x3.sub(&t1);
                z3 = t4.mul(&z3);
                t1 = t3.mul(&t0);
                z3 = z3.add(&t1);
                return .{ .x = x3, .y = y3, .z = z3 };
            }

            pub fn select(mask: u64, a: *const Projective, c: *const Projective) Projective {
                return .{ .x = Fe.select(mask, &a.x, &c.x), .y = Fe.select(mask, &a.y, &c.y), .z = Fe.select(mask, &a.z, &c.z) };
            }

            /// The affine point; the identity maps to (0, 0), which callers reject.
            pub fn affine(p: *const Projective) Curve.Affine {
                const inverse = p.z.invert();
                return .{ .x = p.x.mul(&inverse), .y = p.y.mul(&inverse) };
            }
        };

        const BaseScratch = struct {
            acc: Projective,
            selected: Curve.Affine,
            digits: [comb_windows]Curve.Digit,
            limbs: [4]u64,
        };

        /// scalar * G for a secret big-endian scalar in [1, n). The comb walk adds one table entry
        /// per window with the complete formula, so neither the identity nor a repeated point needs a
        /// branch.
        pub fn secret(scalar: *const [32]u8) Projective {
            var owner: Secret(BaseScratch) = .init(undefined);
            defer owner.deinit();
            const s = owner.exposeMut();
            s.limbs = Curve.Scalar.limbsFromBytes(scalar);
            Curve.recode(comb_bits, &s.limbs, comb_windows, &s.digits);
            s.acc = Projective.identity;
            for (0..comb_windows) |i| {
                selectBase(&s.selected, i, s.digits[i]);
                const sum = s.acc.addAffine(&s.selected);
                // A zero digit adds nothing.
                const skip = Montgomery.zeroMask(s.digits[i].magnitude);
                s.acc = Projective.select(skip, &sum, &s.acc);
            }
            return s.acc;
        }

        /// The entry for `digit` of window `i`, negated for a negative digit; every entry is read.
        fn selectBase(out: *Curve.Affine, i: usize, digit: Curve.Digit) void {
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
            out.y = Fe.select(Montgomery.maskOf(digit.negative), &y_fe, &y_fe.neg());
        }

        /// Public scalar * G for verification: the same comb, indexed directly.
        pub fn public(scalar: *const [4]u64) Curve.Jacobian {
            var digits: [comb_windows]Curve.Digit = undefined;
            Curve.recode(comb_bits, scalar, comb_windows, &digits);
            var acc = Curve.Jacobian.identity;
            for (digits, 0..) |digit, i| {
                if (digit.magnitude == 0) continue;
                const entry = &table.base[i][digit.magnitude - 1];
                var q: Curve.Affine = .{ .x = .{ .limbs = entry[0..4].* }, .y = .{ .limbs = entry[4..8].* } };
                if (digit.negative == 1) q.y = q.y.neg();
                acc = acc.addAffinePublic(&q);
            }
            return acc;
        }
    };
}

test {
    _ = @import("p256_test.zig");
}
