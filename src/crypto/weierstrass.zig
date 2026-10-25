//! The NIST prime curves y^2 = x^3 - 3x + b (P-256, P-384, P-521) over one body of code: a
//! curve is its field (`field/nist.zig` or `field/p521.zig`, each s2n-bignum's verified assembly
//! or fiat-crypto's verified Zig behind `Fe`), its constants, and its scalars on the generic
//! constant-time Montgomery field mod n.
//!
//! Secret scalars (private keys, ECDSA nonces, ECDH secrets) only meet constant-time code: a
//! multiplication walks signed five-bit windows over a table of the point's multiples, scans
//! every entry and handles the identity and the doubling case by selection, never by a branch.
//! The base point takes the same walk unless the curve brings a precomputed comb (P-256's).
//! Signature verification sees only public values and may branch on them. The multiplications
//! keep their long-lived secret state (accumulator, selected point, digits) in one scratch owner
//! that is wiped before they return; callers run them inside `aegis.secret.scrubbed`, which
//! scrubs what the field's assembly leaves below.
const std = @import("std");
const Montgomery = @import("field/Montgomery.zig");

pub const Params = struct {
    /// The base field: `mul`, `sqr`, `add`, `sub`, `neg`, `invert`, `select`, encodings.
    Fe: type,
    /// The group order n.
    order: comptime_int,
    b: comptime_int,
    gx: comptime_int,
    gy: comptime_int,
    /// A precomputed base-point multiplication replacing the walk from the generator, or null:
    /// `secret(scalar)` returns a point with `z` and `affine()`, `public(limbs)` a Jacobian
    /// point.
    Comb: ?fn (comptime type) type = null,
};

pub fn Curve(comptime params: Params) type {
    return struct {
        const Self = @This();
        pub const Fe = params.Fe;
        pub const order = params.order;
        pub const Scalar = Montgomery.Field(order);
        pub const Limbs = Scalar.Limbs;
        const prime = Fe.modulus;

        pub const field_length = Fe.encoded_length;
        pub const scalar_length = Scalar.encoded_length;
        pub const public_length = 1 + 2 * field_length;

        pub const b = Fe.constant(params.b);
        pub const generator: Affine = .{ .x = Fe.constant(params.gx), .y = Fe.constant(params.gy) };

        const Base = if (params.Comb) |Comb| Comb(Self) else Walk;

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
                        .x = Fe.fromBytes(bytes[1..][0..field_length]) catch return error.InvalidEncoding,
                        .y = Fe.fromBytes(bytes[1 + field_length ..][0..field_length]) catch return error.InvalidEncoding,
                    };
                    if (!p.onCurve()) return error.InvalidEncoding;
                    return p;
                }
                if (bytes.len == 1 + field_length and (bytes[0] == 2 or bytes[0] == 3)) {
                    const x = Fe.fromBytes(bytes[1..][0..field_length]) catch return error.InvalidEncoding;
                    const square = rhs(&x);
                    var y = sqrtCandidate(&square);
                    if (!y.sqr().eql(&square)) return error.InvalidEncoding;
                    if (y.toBytes()[field_length - 1] & 1 != bytes[0] & 1) y = y.neg();
                    return .{ .x = x, .y = y };
                }
                return error.InvalidEncoding;
            }

            pub fn toSec1(p: *const Affine) [public_length]u8 {
                var out: [public_length]u8 = undefined;
                out[0] = 4;
                out[1..][0..field_length].* = p.x.toBytes();
                out[1 + field_length ..][0..field_length].* = p.y.toBytes();
                return out;
            }
        };

        /// a^((p+1)/4), a square root of `a` when it has one: every one of these primes is
        /// 3 mod 4. The exponent is public.
        fn sqrtCandidate(a: *const Fe) Fe {
            const Wide = @Int(.unsigned, 8 * field_length);
            const exponent: Wide = (prime + 1) / 4;
            var acc = Fe.one;
            var k: usize = 8 * field_length;
            while (k > 0) {
                k -= 1;
                acc = acc.sqr();
                if ((exponent >> @intCast(k)) & 1 == 1) acc = acc.mul(a);
            }
            return acc;
        }

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

            /// add-2007-bl without its exceptional cases resolved: the caller handles an
            /// identity input and p == q. Returns the sum and the two values that detect
            /// p == +-q.
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

            /// Constant-time sum for every input pair: the identity cases and p == q are
            /// selected, the doubling always computed.
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

            /// madd-2007-bl, public inputs: p plus an affine point. 7M + 4S.
            pub fn addAffinePublic(p: *const Jacobian, q: *const Affine) Jacobian {
                if (p.z.isZero()) return fromAffine(q);
                const z1z1 = p.z.sqr();
                const x2z = q.x.mul(&z1z1);
                const s2 = q.y.mul(&p.z).mul(&z1z1);
                const h = x2z.sub(&p.x);
                const r = s2.sub(&p.y).dbl();
                if (h.isZero()) return if (r.isZero()) p.dbl() else identity;
                const hh = h.sqr();
                const i = hh.dbl().dbl();
                const j = h.mul(&i);
                const v = p.x.mul(&i);
                const x3 = r.sqr().sub(&j).sub(&v.dbl());
                const y3 = r.mul(&v.sub(&x3)).sub(&p.y.mul(&j).dbl());
                const z3 = p.z.add(&h).sqr().sub(&z1z1).sub(&hh);
                return .{ .x = x3, .y = y3, .z = z3 };
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

        // ------------------------------------------------------------ scalars

        pub const Digit = struct { magnitude: u8, negative: u1 };

        /// The walk's windows: five bits each over the recoded scalar, which is one bit longer
        /// than n (the top window's carry). P-256 52, P-384 77, P-521 105.
        pub const window_bits = 5;
        pub const windows = (Scalar.bits + 1 + window_bits - 1) / window_bits;

        /// Signed windows of `bits` bits (Booth recoding): digit i is the value of scalar bits
        /// [bits*i - 1, bits*i + bits - 1], mapped to a magnitude in [0, 2^(bits-1)] and a sign.
        /// Branch-free over secret scalars.
        pub fn recode(comptime bits: u6, scalar: *const Limbs, comptime count: usize, out: *[count]Digit) void {
            const mask: u64 = (1 << (bits + 1)) - 1;
            inline for (0..count) |i| {
                const raw = window(scalar, @as(i32, bits) * @as(i32, i) - 1) & mask;
                const negative = 0 -% (raw >> bits); // all ones when the top bit is set
                var d = ((mask - raw) & negative) | (raw & ~negative);
                d = (d >> 1) + (d & 1);
                out[i] = .{ .magnitude = @truncate(d), .negative = @truncate(negative & 1) }; // safe: d <= 2^(bits-1) and the sign is one bit
            }
        }

        /// The scalar's bits from `position` (which may be -1; bits outside it read as zero).
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

        // ------------------------------------------------------------ multiplication

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
            recode(window_bits, &s.limbs, windows, &s.digits);
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

        /// scalar * G for a secret big-endian scalar in [1, n): the curve's comb, or the walk.
        pub fn baseMul(scalar: *const [scalar_length]u8) @TypeOf(Base.secret(scalar)) {
            return Base.secret(scalar);
        }

        /// The walk from the generator, for a curve without a comb.
        const Walk = struct {
            fn secret(scalar: *const [scalar_length]u8) Jacobian {
                return mul(&generator, scalar);
            }

            fn public(scalar: *const Limbs) Jacobian {
                return mulPublic(&generator, scalar);
            }
        };

        /// The multiple for `digit`, negated when negative, the identity for zero; every entry
        /// is read.
        fn selectPoint(out: *Jacobian, multiples: *const [16]Jacobian, digit: Digit) void {
            out.* = Jacobian.identity;
            for (multiples, 1..) |*entry, j| {
                const hit = Montgomery.zeroMask(@as(u64, digit.magnitude) ^ j);
                out.* = Jacobian.select(hit, out, entry);
            }
            out.y = Fe.select(Montgomery.maskOf(digit.negative), &out.y, &out.y.neg());
        }

        /// The recoded scalar's length in bits, with the width-5 NAF's carry.
        const naf_length = Scalar.bits + 1;

        /// Public u1 * G + u2 * q for verification: the curve's comb for G, or one width-5 NAF
        /// walk over both.
        pub fn mulDoubleBasePublic(g_scalar: *const Limbs, q: *const Affine, q_scalar: *const Limbs) Jacobian {
            if (params.Comb != null) return mulPublic(q, q_scalar).addPublic(&Base.public(g_scalar));
            const g_odd = oddMultiples(&generator);
            const q_odd = oddMultiples(q);
            var g_naf: [naf_length]i8 = undefined;
            var q_naf: [naf_length]i8 = undefined;
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

        /// Public scalar * q by a width-5 NAF.
        fn mulPublic(q: *const Affine, scalar: *const Limbs) Jacobian {
            const odd = oddMultiples(q);
            var naf: [naf_length]i8 = undefined;
            const top = wnaf(scalar, &naf);
            var acc = Jacobian.identity;
            var i: usize = top;
            while (i > 0) {
                i -= 1;
                acc = acc.dbl();
                acc = addDigit(&acc, &odd, naf[i]);
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
        fn wnaf(scalar: *const Limbs, out: *[naf_length]i8) usize {
            const Wide = @Int(.unsigned, 64 * Scalar.n + 1);
            var k: Wide = 0;
            for (scalar, 0..) |limb, i| k |= @as(Wide, limb) << @intCast(64 * i);
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

        // ------------------------------------------------------------ ECDSA pieces

        /// The ECDSA digest scalar: the leftmost bits of `digest`, as many as n has, as an
        /// integer (SEC1 4.1.3 step 5), reduced mod n, in Montgomery form.
        pub fn digestScalar(digest: []const u8) Scalar {
            var bytes: [scalar_length]u8 = @splat(0);
            if (digest.len <= scalar_length) {
                @memcpy(bytes[scalar_length - digest.len ..], digest);
            } else {
                // Longer: the leftmost bytes, shifted right past the bits n does not have.
                const Wide = @Int(.unsigned, 8 * scalar_length);
                const spare = 8 * scalar_length - Scalar.bits;
                std.mem.writeInt(Wide, &bytes, std.mem.readInt(Wide, digest[0..scalar_length], .big) >> spare, .big);
            }
            return Scalar.reduce(Scalar.limbsFromBytes(&bytes));
        }

        /// x(R) mod n for R = k*G, as a scalar in Montgomery form, or null if R is the identity.
        pub fn signR(k: *const [scalar_length]u8) ?Scalar {
            var r = baseMul(k);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&r));
            if (r.z.isZero()) return null;
            const x = r.affine().x.toBytes();
            var padded: [@max(scalar_length, field_length)]u8 = @splat(0);
            padded[padded.len - field_length ..].* = x;
            return Scalar.reduce(Scalar.limbsFromBytes(padded[padded.len - scalar_length ..]));
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
            const Wide = @Int(.unsigned, 8 * field_length + 8);
            const r_value: Wide = std.mem.readInt(@Int(.unsigned, 8 * scalar_length), r_bytes, .big);
            inline for (.{ 0, order }) |offset| {
                const candidate = r_value + offset;
                if (candidate < prime) {
                    var bytes: [field_length]u8 = undefined;
                    std.mem.writeInt(@Int(.unsigned, 8 * field_length), &bytes, @intCast(candidate), .big);
                    const x = Fe.fromBytes(&bytes) catch return false;
                    if (x.mul(&z2).eql(&point.x)) return true;
                }
            }
            return false;
        }
    };
}
