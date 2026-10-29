//! Montgomery arithmetic modulo an odd modulus of n 64-bit limbs, R = 2^(64n): cloak's one
//! generic constant-time field, for the curves' scalars (their group orders) and RSA, as Go's
//! nistec pairs fiat-crypto's base fields with generic constant-time scalars. The base fields
//! are the verified ones in this directory. Every operation on secret operands runs the same
//! instructions for every value: carries move through add/subtract-with-carry chains and the
//! one conditional subtraction selects through a mask the compiler cannot see through.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const builtin = @import("builtin");

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
    return .{ @truncate(w), @truncate(w >> 64) }; // low and high product words
}

/// `a * b` as n + 1 limbs, in one carry chain.
inline fn row(comptime n: usize, a: u64, b: [n]u64) [n + 1]u64 {
    var r: [n + 1]u64 = undefined;
    var high: u64 = 0;
    var c: u1 = 0;
    inline for (0..n) |i| {
        const low, const next = wide(a, b[i]);
        const step = addc(low, high, c);
        r[i] = step[0];
        c = step[1];
        high = next;
    }
    // The high word of a 64x64 product is at most 2^64 - 2, so the carry fits.
    r[n] = high + c;
    return r;
}

/// Hides a mask from the optimizer so a selection stays a selection and never becomes a branch.
pub inline fn barrier(value: u64) u64 {
    var v = value;
    if (@inComptime()) return v;
    switch (builtin.cpu.arch) {
        // aegis: boundary: an empty asm that ties the value to a register, so the optimizer cannot see through a mask
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
    const nonzero: u1 = @truncate((x | (0 -% x)) >> 63); // the top bit is set exactly when x != 0
    return maskOf(nonzero ^ 1);
}

pub fn Field(comptime modulus: comptime_int) type {
    return struct {
        const Self = @This();
        limbs: Limbs,

        /// The modulus's width: n limbs, and its big-endian encoding's length.
        pub const bits = width(modulus);
        pub const n = (bits + 63) / 64;
        pub const encoded_length = (bits + 7) / 8;
        pub const Limbs = [n]u64;
        pub const m: Limbs = split(modulus);
        /// -m^-1 mod 2^64.
        const inverse: u64 = blk: {
            var v: u64 = 1;
            for (0..7) |_| v *%= 2 -% m[0] *% v;
            break :blk 0 -% v;
        };
        const r2: Self = .{ .limbs = split((1 << (128 * n)) % modulus) };

        pub const zero: Self = .{ .limbs = @splat(0) };
        pub const one: Self = .{ .limbs = split((1 << (64 * n)) % modulus) };

        comptime {
            std.debug.assert(modulus & 1 == 1);
            std.debug.assert(m[0] *% inverse == std.math.maxInt(u64));
        }

        fn split(comptime value: comptime_int) Limbs {
            comptime {
                @setEvalBranchQuota(100_000);
                var limbs: Limbs = undefined;
                for (&limbs, 0..) |*limb, i| limb.* = (value >> (64 * i)) & std.math.maxInt(u64);
                return limbs;
            }
        }

        /// The Montgomery form of a public constant.
        pub fn constant(comptime value: comptime_int) Self {
            comptime {
                @setEvalBranchQuota(100_000);
                std.debug.assert(value < modulus);
                return .{ .limbs = split((value << (64 * n)) % modulus) };
            }
        }

        /// Subtracts the modulus when `t` (n + 1 limbs, below 2m) is not already below it.
        inline fn final(t: [n + 1]u64) Self {
            var d: Limbs = undefined;
            var b: u1 = 0;
            inline for (0..n) |i| {
                const step = subb(t[i], m[i], b);
                d[i] = step[0];
                b = step[1];
            }
            _, b = subb(t[n], 0, b);
            // A borrow means t < m: keep t.
            const keep = maskOf(b);
            var r: Self = undefined;
            inline for (0..n) |i| r.limbs[i] = (t[i] & keep) | (d[i] & ~keep);
            return r;
        }

        pub fn mul(a: Self, b: Self) Self {
            var t: [n + 2]u64 = @splat(0);
            inline for (0..n) |i| {
                const r = row(n, a.limbs[i], b.limbs);
                var c: u1 = 0;
                inline for (0..n + 1) |j| t[j], c = addc(t[j], r[j], c);
                t[n + 1] = c;
                reduceStep(&t);
            }
            return final(t[0 .. n + 1].*);
        }

        /// One limb of reduction: adds q*m so the lowest limb cancels, then shifts it out.
        inline fn reduceStep(t: *[n + 2]u64) void {
            const q = t[0] *% inverse;
            const s = row(n, q, m);
            var c: u1 = 0;
            _, c = addc(t[0], s[0], 0);
            inline for (1..n + 1) |j| t[j - 1], c = addc(t[j], s[j], c);
            t[n] = t[n + 1] + c;
        }

        pub fn sqr(a: Self) Self {
            return mul(a, a);
        }

        pub fn sqrn(a: Self, comptime count: usize) Self {
            var r = a;
            for (0..count) |_| r = r.sqr();
            return r;
        }

        pub fn add(a: Self, b: Self) Self {
            var t: [n + 1]u64 = undefined;
            var c: u1 = 0;
            inline for (0..n) |i| {
                const step = addc(a.limbs[i], b.limbs[i], c);
                t[i] = step[0];
                c = step[1];
            }
            t[n] = c;
            return final(t);
        }

        pub fn dbl(a: Self) Self {
            return a.add(a);
        }

        pub fn sub(a: Self, b: Self) Self {
            var d: Limbs = undefined;
            var borrow: u1 = 0;
            inline for (0..n) |i| {
                const step = subb(a.limbs[i], b.limbs[i], borrow);
                d[i] = step[0];
                borrow = step[1];
            }
            // On a borrow, add the modulus back.
            const fix = maskOf(borrow);
            var r: Self = undefined;
            var c: u1 = 0;
            inline for (0..n) |i| {
                const step = addc(d[i], m[i] & fix, c);
                r.limbs[i] = step[0];
                c = step[1];
            }
            return r;
        }

        pub fn neg(a: Self) Self {
            return zero.sub(a);
        }

        /// `b` where `mask` is all ones, `a` where it is zero.
        pub fn select(mask: u64, a: Self, b: Self) Self {
            var r: Self = undefined;
            inline for (0..n) |i| r.limbs[i] = (b.limbs[i] & mask) | (a.limbs[i] & ~mask);
            return r;
        }

        /// All ones when the value is zero.
        pub fn isZeroMask(a: Self) u64 {
            var x: u64 = 0;
            inline for (0..n) |i| x |= a.limbs[i];
            return zeroMask(x);
        }

        /// All ones when equal.
        pub fn eqlMask(a: Self, b: Self) u64 {
            var x: u64 = 0;
            inline for (0..n) |i| x |= a.limbs[i] ^ b.limbs[i];
            return zeroMask(x);
        }

        /// Public comparisons only.
        pub fn isZero(a: Self) bool {
            var x: u64 = 0;
            inline for (0..n) |i| x |= a.limbs[i];
            return x == 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return std.mem.eql(u64, &a.limbs, &b.limbs);
        }

        pub fn fromInt(value: Limbs) Self {
            return mul(.{ .limbs = value }, r2);
        }

        pub fn toInt(a: Self) Limbs {
            var unit: Limbs = @splat(0);
            unit[0] = 1;
            return mul(a, .{ .limbs = unit }).limbs;
        }

        /// A big-endian value below the modulus; the check is constant time and only its verdict
        /// is released.
        pub fn fromBytes(bytes: *const [encoded_length]u8) error{NonCanonical}!Self {
            const value = limbsFromBytes(bytes);
            if (!lessThanModulus(value)) return error.NonCanonical;
            return fromInt(value);
        }

        pub fn toBytes(a: Self) [encoded_length]u8 {
            const value = toInt(a);
            var out: [8 * n]u8 = undefined;
            inline for (0..n) |i| std.mem.writeInt(u64, out[8 * (n - 1 - i) ..][0..8], value[i], .big);
            // The bytes above the modulus's width are zero for a value below it.
            return out[8 * n - encoded_length ..].*;
        }

        /// A big-endian encoding's limbs, whatever their value.
        pub fn limbsFromBytes(bytes: *const [encoded_length]u8) Limbs {
            var padded: [8 * n]u8 = @splat(0);
            padded[8 * n - encoded_length ..].* = bytes.*;
            var value: Limbs = undefined;
            inline for (0..n) |i| value[i] = std.mem.readInt(u64, padded[8 * (n - 1 - i) ..][0..8], .big);
            return value;
        }

        /// Whether a raw value is below the modulus, computed without branches.
        pub fn lessThanModulus(value: Limbs) bool {
            var b: u1 = 0;
            inline for (0..n) |i| _, b = subb(value[i], m[i], b);
            return b == 1;
        }

        /// Reduces any n-limb value: below R, its product with R^2 reduces below 2m, which the
        /// final subtraction brings below m.
        pub fn reduce(value: Limbs) Self {
            return mul(.{ .limbs = value }, r2);
        }

        /// a^(m-2) by a fixed public exponent, four bits at a time; the exponent is public, so
        /// the walk over it is the same for every `a`.
        pub fn powModulusMinusTwo(a: Self) Self {
            const exponent = comptime split(modulus - 2);
            var owner: Secret([16]Self) = .init(undefined);
            defer owner.deinit();
            const table = owner.exposeMut();
            table[0] = one;
            table[1] = a;
            for (2..16) |i| table[i] = table[i - 1].mul(a);
            var r = one;
            var first = true;
            var limb: usize = n;
            while (limb > 0) {
                limb -= 1;
                var shift: u7 = 64;
                while (shift > 0) {
                    shift -= 4;
                    if (!first) r = r.sqrn(4);
                    const digit: u4 = @truncate(exponent[limb] >> @as(u6, @intCast(shift))); // public exponent nibble
                    if (digit != 0) r = if (first) table[digit] else r.mul(table[digit]);
                    if (digit != 0) first = false;
                }
            }
            return r;
        }
    };
}

/// The bit width of a positive comptime integer.
fn width(comptime value: comptime_int) comptime_int {
    comptime {
        var count = 0;
        var v = value;
        while (v != 0) : (v >>= 1) count += 1;
        return count;
    }
}

test {
    _ = @import("Montgomery_test.zig");
}
