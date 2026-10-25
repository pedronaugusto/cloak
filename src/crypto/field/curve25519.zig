//! The field of curve25519, p = 2^255 - 19: fiat-crypto's verified Zig (`curve25519_64.zig`,
//! unsaturated, five limbs of 51 bits) behind one small type, for the portable paths of X25519
//! and Ed25519. Every value held is tight (each limb below 2^51 plus a little), so every
//! operation takes and returns tight limbs; fiat's loose intermediates stay inside.
//!
//! Every operation runs the same instructions for every value. `isZero`, `isNegative` and
//! `eql` compute on canonical bytes and release one bit.
const std = @import("std");
const fiat = @import("../vendor/fiat/curve25519_64.zig");

pub const Fe = struct {
    limbs: [5]u64,

    pub const encoded_length = 32;
    pub const zero: Fe = .{ .limbs = @splat(0) };
    pub const one: Fe = .{ .limbs = .{ 1, 0, 0, 0, 0 } };

    /// The value of 32 little-endian bytes, the top bit ignored (RFC 7748 5, RFC 8032 5.1.3);
    /// a value from p to 2^255 - 1 is taken modulo p.
    pub fn fromBytes(bytes: *const [encoded_length]u8) Fe {
        var masked = bytes.*;
        masked[31] &= 127;
        var r: Fe = undefined;
        fiat.fromBytes(&r.limbs, masked);
        return r;
    }

    /// The canonical encoding: the value below p, little-endian, the top bit clear.
    pub fn toBytes(a: *const Fe) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        fiat.toBytes(&out, a.limbs);
        return out;
    }

    /// A public constant from its integer value.
    pub fn constant(comptime value: comptime_int) Fe {
        comptime {
            var bytes: [encoded_length]u8 = undefined;
            std.mem.writeInt(u256, &bytes, value, .little);
            return fromBytes(&bytes);
        }
    }

    pub fn mul(a: *const Fe, b: *const Fe) Fe {
        var r: Fe = undefined;
        fiat.carryMul(&r.limbs, a.limbs, b.limbs);
        return r;
    }

    pub fn sqr(a: *const Fe) Fe {
        var r: Fe = undefined;
        fiat.carrySquare(&r.limbs, a.limbs);
        return r;
    }

    pub fn sqrn(a: *const Fe, comptime count: usize) Fe {
        var r = a.*;
        for (0..count) |_| r = r.sqr();
        return r;
    }

    pub fn add(a: *const Fe, b: *const Fe) Fe {
        var loose: [5]u64 = undefined;
        fiat.add(&loose, a.limbs, b.limbs);
        var r: Fe = undefined;
        fiat.carry(&r.limbs, loose);
        return r;
    }

    pub fn sub(a: *const Fe, b: *const Fe) Fe {
        var loose: [5]u64 = undefined;
        fiat.sub(&loose, a.limbs, b.limbs);
        var r: Fe = undefined;
        fiat.carry(&r.limbs, loose);
        return r;
    }

    pub fn neg(a: *const Fe) Fe {
        var loose: [5]u64 = undefined;
        fiat.opp(&loose, a.limbs);
        var r: Fe = undefined;
        fiat.carry(&r.limbs, loose);
        return r;
    }

    /// a * 121666, X25519's (A + 2) / 4.
    pub fn mul121666(a: *const Fe) Fe {
        var loose: [5]u64 = undefined;
        fiat.relax(&loose, a.limbs);
        var r: Fe = undefined;
        fiat.carryScmul121666(&r.limbs, loose);
        return r;
    }

    /// `b` when `bit` is 1, `a` when 0, by fiat's constant-time selection.
    pub fn select(bit: u1, a: *const Fe, b: *const Fe) Fe {
        var r: Fe = undefined;
        fiat.selectznz(&r.limbs, bit, a.limbs, b.limbs);
        return r;
    }

    /// Swaps `a` and `b` when `bit` is 1.
    pub fn cswap(bit: u1, a: *Fe, b: *Fe) void {
        const x = select(bit, a, b);
        const y = select(bit, b, a);
        a.* = x;
        b.* = y;
    }

    pub fn isZero(a: *const Fe) bool {
        const bytes = a.toBytes();
        var any: u8 = 0;
        for (bytes) |byte| any |= byte;
        return any == 0;
    }

    /// Whether the canonical value is odd: RFC 8032's sign of x.
    pub fn isNegative(a: *const Fe) u1 {
        return @truncate(a.toBytes()[0]); // safe: the low bit of the canonical value
    }

    pub fn eql(a: *const Fe, b: *const Fe) bool {
        return a.sub(b).isZero();
    }

    /// z^(p-2) = z^(2^255 - 21), zero for zero: 254 squarings and 11 multiplications.
    pub fn invert(z: *const Fe) Fe {
        const t = chain(z);
        return t.z_250_0.sqrn(5).mul(&t.z11);
    }

    /// z^((p-5)/8) = z^(2^252 - 3), the power RFC 8032 5.1.3 takes square roots with.
    pub fn pow22523(z: *const Fe) Fe {
        const t = chain(z);
        return t.z_250_0.sqrn(2).mul(z);
    }

    /// The shared prefix of both powers: z^11 and z^(2^250 - 1).
    fn chain(z: *const Fe) struct { z11: Fe, z_250_0: Fe } {
        const z2 = z.sqr();
        const z9 = z2.sqrn(2).mul(z);
        const z11 = z9.mul(&z2);
        const z_5_0 = z11.sqr().mul(&z9);
        const z_10_0 = z_5_0.sqrn(5).mul(&z_5_0);
        const z_20_0 = z_10_0.sqrn(10).mul(&z_10_0);
        const z_40_0 = z_20_0.sqrn(20).mul(&z_20_0);
        const z_50_0 = z_40_0.sqrn(10).mul(&z_10_0);
        const z_100_0 = z_50_0.sqrn(50).mul(&z_50_0);
        const z_200_0 = z_100_0.sqrn(100).mul(&z_100_0);
        return .{ .z11 = z11, .z_250_0 = z_200_0.sqrn(50).mul(&z_50_0) };
    }
};
