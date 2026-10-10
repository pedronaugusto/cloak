//! Four-limb Montgomery arithmetic modulo a 256-bit odd modulus, R = 2^256. Every operation
//! on secret operands runs the same instructions for every value: carries move through
//! add/subtract-with-carry chains and the one conditional subtraction selects through a mask
//! the compiler cannot see through. The P-256 field prime gets a reduction without
//! multiplications (its lowest limb is 2^64 - 1, so each Montgomery factor is the limb itself).
const std = @import("std");
const builtin = @import("builtin");

pub const Limbs = [4]u64;

pub inline fn addc(a: u64, b: u64, c: u1) struct { u64, u1 } {
    const s1 = @addWithOverflow(a, b);
    const s2 = @addWithOverflow(s1[0], c);
    return .{ s2[0], s1[1] | s2[1] };
}

pub inline fn subb(a: u64, b: u64, c: u1) struct { u64, u1 } {
    const s1 = @subWithOverflow(a, b);
    const s2 = @subWithOverflow(s1[0], c);
    return .{ s2[0], s1[1] | s2[1] };
}

inline fn wide(a: u64, b: u64) struct { u64, u64 } {
    const w = @as(u128, a) * b;
    return .{ @truncate(w), @truncate(w >> 64) }; // safe: low and high product words
}

/// `a * b` as five limbs, in one carry chain.
inline fn row(a: u64, b: Limbs) [5]u64 {
    const l0, const h0 = wide(a, b[0]);
    const l1, const h1 = wide(a, b[1]);
    const l2, const h2 = wide(a, b[2]);
    const l3, const h3 = wide(a, b[3]);
    var r: [5]u64 = undefined;
    var c: u1 = 0;
    r[0] = l0;
    r[1], c = addc(l1, h0, 0);
    r[2], c = addc(l2, h1, c);
    r[3], c = addc(l3, h2, c);
    // The high word of a 64x64 product is at most 2^64 - 2, so the carry fits.
    r[4] = h3 + c;
    return r;
}

/// Hides a mask from the optimizer so a selection stays a selection and never becomes a branch.
pub inline fn barrier(value: u64) u64 {
    var v = value;
    if (@inComptime()) return v;
    switch (builtin.cpu.arch) {
        .x86_64, .aarch64 => asm volatile (""
            : [v] "+r" (v),
        ),
        else => {
            const slot: *volatile u64 = &v;
            return slot.*;
        },
    }
    return v;
}

/// All ones when `bit` is 1, zero when 0.
pub inline fn maskOf(bit: u1) u64 {
    return barrier(0 -% @as(u64, bit));
}

/// All ones when `x` is zero.
pub inline fn zeroMask(x: u64) u64 {
    const nonzero: u1 = @truncate((x | (0 -% x)) >> 63); // safe: the top bit is set exactly when x != 0
    return maskOf(nonzero ^ 1);
}

pub fn Field(comptime modulus: u256) type {
    return struct {
        const Self = @This();
        limbs: Limbs,

        pub const m: Limbs = split(modulus);
        /// -m^-1 mod 2^64.
        const inverse: u64 = blk: {
            var v: u64 = 1;
            for (0..7) |_| v *%= 2 -% m[0] *% v;
            break :blk 0 -% v;
        };
        /// The P-256 prime: m0 = 2^64 - 1, m1 = 2^32 - 1, m2 = 0.
        const special = modulus == 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff;
        const r2: Self = .{ .limbs = split(@intCast((@as(u513, 1) << 512) % modulus)) };

        pub const zero: Self = .{ .limbs = .{ 0, 0, 0, 0 } };
        pub const one: Self = .{ .limbs = split(@intCast((@as(u257, 1) << 256) % modulus)) };

        comptime {
            std.debug.assert(modulus & 1 == 1 and modulus >> 255 == 1);
            std.debug.assert(m[0] *% inverse == std.math.maxInt(u64));
            if (special) std.debug.assert(inverse == 1);
        }

        fn split(value: u256) Limbs {
            return .{ @truncate(value), @truncate(value >> 64), @truncate(value >> 128), @truncate(value >> 192) }; // safe: each limb keeps its own 64 bits
        }

        /// The Montgomery form of a public constant.
        pub fn constant(comptime value: u256) Self {
            comptime {
                @setEvalBranchQuota(100_000);
                std.debug.assert(value < modulus);
                return .{ .limbs = split(@intCast((@as(u512, value) << 256) % modulus)) };
            }
        }

        /// Subtracts the modulus when `t` (five limbs, below 2m) is not already below it.
        inline fn final(t: [5]u64) Self {
            var d: Limbs = undefined;
            var b: u1 = 0;
            inline for (0..4) |i| d[i], b = subb(t[i], m[i], b);
            _, b = subb(t[4], 0, b);
            // A borrow means t < m: keep t.
            const keep = maskOf(b);
            var r: Self = undefined;
            inline for (0..4) |i| r.limbs[i] = (t[i] & keep) | (d[i] & ~keep);
            return r;
        }

        pub fn mul(a: Self, b: Self) Self {
            var t: [6]u64 = .{ 0, 0, 0, 0, 0, 0 };
            inline for (0..4) |i| {
                const r = row(a.limbs[i], b.limbs);
                var c: u1 = 0;
                t[0], c = addc(t[0], r[0], 0);
                t[1], c = addc(t[1], r[1], c);
                t[2], c = addc(t[2], r[2], c);
                t[3], c = addc(t[3], r[3], c);
                t[4], c = addc(t[4], r[4], c);
                t[5] = c;
                reduceStep(&t);
            }
            return final(t[0..5].*);
        }

        /// One limb of reduction: adds q*m so the lowest limb cancels, then shifts it out.
        inline fn reduceStep(t: *[6]u64) void {
            var c: u1 = 0;
            if (special) {
                // q = t0. t0 + q*m0 = q*2^64; t1 + q*m1 + q = t1 + q*2^32; m2 = 0.
                const q = t[0];
                // q * m3 = q * 2^64 - q * 2^32 + q, by shifts and one borrow.
                const low = @subWithOverflow(q, q << 32);
                const ql = low[0];
                const qh = q - (q >> 32) - low[1];
                t[0], c = addc(t[1], q << 32, 0);
                t[1], c = addc(t[2], q >> 32, c);
                t[2], c = addc(t[3], ql, c);
                t[3], c = addc(t[4], qh, c);
            } else {
                const q = t[0] *% inverse;
                const s = row(q, m);
                _, c = addc(t[0], s[0], 0);
                t[0], c = addc(t[1], s[1], c);
                t[1], c = addc(t[2], s[2], c);
                t[2], c = addc(t[3], s[3], c);
                t[3], c = addc(t[4], s[4], c);
            }
            t[4] = t[5] + c;
        }

        pub fn sqr(a: Self) Self {
            if (!special) return mul(a, a);
            const x = a.limbs;
            const l01, const h01 = wide(x[0], x[1]);
            const l02, const h02 = wide(x[0], x[2]);
            const l03, const h03 = wide(x[0], x[3]);
            const l12, const h12 = wide(x[1], x[2]);
            const l13, const h13 = wide(x[1], x[3]);
            const l23, const h23 = wide(x[2], x[3]);
            var w: [8]u64 = undefined;
            var c: u1 = 0;
            w[1] = l01;
            w[2], c = addc(l02, h01, 0);
            w[3], c = addc(l03, h02, c);
            w[4] = h03 + c;
            const r4, c = addc(l13, h12, 0);
            const r5 = h13 + c;
            w[3], c = addc(w[3], l12, 0);
            w[4], c = addc(w[4], r4, c);
            w[5] = r5 + c;
            w[5], c = addc(w[5], l23, 0);
            w[6] = h23 + c;
            w[7] = w[6] >> 63;
            w[6] = (w[6] << 1) | (w[5] >> 63);
            w[5] = (w[5] << 1) | (w[4] >> 63);
            w[4] = (w[4] << 1) | (w[3] >> 63);
            w[3] = (w[3] << 1) | (w[2] >> 63);
            w[2] = (w[2] << 1) | (w[1] >> 63);
            w[1] = w[1] << 1;
            const s0l, const s0h = wide(x[0], x[0]);
            const s1l, const s1h = wide(x[1], x[1]);
            const s2l, const s2h = wide(x[2], x[2]);
            const s3l, const s3h = wide(x[3], x[3]);
            w[0] = s0l;
            w[1], c = addc(w[1], s0h, 0);
            w[2], c = addc(w[2], s1l, c);
            w[3], c = addc(w[3], s1h, c);
            w[4], c = addc(w[4], s2l, c);
            w[5], c = addc(w[5], s2h, c);
            w[6], c = addc(w[6], s3l, c);
            w[7] = w[7] + s3h + c;
            // Reduce the low half by four limbs, then add the high half.
            var t: [6]u64 = .{ w[0], w[1], w[2], w[3], 0, 0 };
            inline for (0..4) |_| {
                t[5] = 0;
                reduceStep(&t);
            }
            var r: [5]u64 = undefined;
            r[0], c = addc(t[0], w[4], 0);
            r[1], c = addc(t[1], w[5], c);
            r[2], c = addc(t[2], w[6], c);
            r[3], c = addc(t[3], w[7], c);
            r[4] = t[4] + c;
            return final(r);
        }

        pub fn sqrn(a: Self, comptime n: usize) Self {
            var r = a;
            for (0..n) |_| r = r.sqr();
            return r;
        }

        pub fn add(a: Self, b: Self) Self {
            var t: [5]u64 = undefined;
            var c: u1 = 0;
            inline for (0..4) |i| t[i], c = addc(a.limbs[i], b.limbs[i], c);
            t[4] = c;
            return final(t);
        }

        pub fn dbl(a: Self) Self {
            return a.add(a);
        }

        pub fn sub(a: Self, b: Self) Self {
            var d: Limbs = undefined;
            var borrow: u1 = 0;
            inline for (0..4) |i| d[i], borrow = subb(a.limbs[i], b.limbs[i], borrow);
            // On a borrow, add the modulus back.
            const fix = maskOf(borrow);
            var r: Self = undefined;
            var c: u1 = 0;
            inline for (0..4) |i| r.limbs[i], c = addc(d[i], m[i] & fix, c);
            return r;
        }

        pub fn neg(a: Self) Self {
            return zero.sub(a);
        }

        /// `b` where `mask` is all ones, `a` where it is zero.
        pub fn select(mask: u64, a: Self, b: Self) Self {
            var r: Self = undefined;
            inline for (0..4) |i| r.limbs[i] = (b.limbs[i] & mask) | (a.limbs[i] & ~mask);
            return r;
        }

        /// All ones when the value is zero.
        pub fn isZeroMask(a: Self) u64 {
            return zeroMask(a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3]);
        }

        /// All ones when equal.
        pub fn eqlMask(a: Self, b: Self) u64 {
            var x: u64 = 0;
            inline for (0..4) |i| x |= a.limbs[i] ^ b.limbs[i];
            return zeroMask(x);
        }

        /// Public comparisons only.
        pub fn isZero(a: Self) bool {
            return a.limbs[0] | a.limbs[1] | a.limbs[2] | a.limbs[3] == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u64, &a.limbs, &b.limbs);
        }

        pub fn fromInt(value: Limbs) Self {
            return mul(.{ .limbs = value }, r2);
        }

        pub fn toInt(a: Self) Limbs {
            return mul(a, .{ .limbs = .{ 1, 0, 0, 0 } }).limbs;
        }

        /// A big-endian value below the modulus; the check is constant time and only its verdict
        /// is released.
        pub fn fromBytes(bytes: *const [32]u8) error{NonCanonical}!Self {
            const value = limbsFromBytes(bytes);
            if (!lessThanModulus(value)) return error.NonCanonical;
            return fromInt(value);
        }

        pub fn toBytes(a: Self) [32]u8 {
            const value = toInt(a);
            var out: [32]u8 = undefined;
            inline for (0..4) |i| std.mem.writeInt(u64, out[24 - 8 * i ..][0..8], value[i], .big);
            return out;
        }

        pub fn limbsFromBytes(bytes: *const [32]u8) Limbs {
            var value: Limbs = undefined;
            inline for (0..4) |i| value[i] = std.mem.readInt(u64, bytes[24 - 8 * i ..][0..8], .big);
            return value;
        }

        /// Whether a raw value is below the modulus, computed without branches.
        pub fn lessThanModulus(value: Limbs) bool {
            var b: u1 = 0;
            inline for (0..4) |i| _, b = subb(value[i], m[i], b);
            return b == 1;
        }

        /// Reduces any 256-bit value (below 2m, as every 256-bit value is for these moduli).
        pub fn reduce(value: Limbs) Self {
            return final(.{ value[0], value[1], value[2], value[3], 0 }).toMontgomery();
        }

        fn toMontgomery(raw: Self) Self {
            return mul(raw, r2);
        }

        /// a^(m-2) by a fixed public exponent, four bits at a time; the exponent is public, so
        /// the walk over it is the same for every `a`.
        pub fn powModulusMinusTwo(a: Self) Self {
            const exponent = comptime split(modulus - 2);
            var table: [16]Self = undefined;
            table[0] = one;
            table[1] = a;
            for (2..16) |i| table[i] = table[i - 1].mul(a);
            var r = one;
            var first = true;
            var limb: usize = 4;
            while (limb > 0) {
                limb -= 1;
                var shift: u7 = 64;
                while (shift > 0) {
                    shift -= 4;
                    if (!first) r = r.sqrn(4);
                    const digit: u4 = @truncate(exponent[limb] >> @as(u6, @intCast(shift))); // safe: public exponent nibble
                    if (digit != 0) r = if (first) table[digit] else r.mul(table[digit]);
                    if (digit != 0) first = false;
                }
            }
            std.crypto.secureZero(u8, std.mem.asBytes(&table));
            return r;
        }
    };
}

test {
    _ = @import("Montgomery_test.zig");
}
