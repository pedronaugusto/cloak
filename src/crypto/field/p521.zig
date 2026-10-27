//! The P-521 field, p = 2^521 - 1, behind one interface: s2n-bignum's verified assembly on
//! x86_64 and AArch64, fiat-crypto's verified Zig everywhere else and as the reference both are
//! tested against. Curve code sees `Fe` alone; the backends differ only in their limbs.
//!
//! Every operation runs the same instructions for every value. The assembly writes its
//! temporaries to the stack: secret computations run it inside `aegis.secret.scrubbed`, which
//! scrubs that stack and sets the processor's data-independent timing mode around them.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const fiat = @import("../vendor/fiat.zig").p521;
const shared = @import("s2n.zig");
const barrier = @import("Montgomery.zig").barrier;

/// The big-endian encoding's length.
const length = 66;
pub const Limbs = [9]u64;

pub const Backend = enum { fiat, s2n };

pub const assembly = shared.assembly;

/// The field elements this build computes with.
pub const Fe = Field(if (assembly) .s2n else .fiat);

/// The canonical encoding check both backends share: big-endian, below 2^521 (the top byte at
/// most 1) and not p itself (0x01 then 65 bytes of 0xff). Constant time; only the verdict leaves.
fn canonical(bytes: *const [length]u8) bool {
    var all_ones: u8 = 0xff;
    for (bytes[1..]) |b| all_ones &= b;
    const is_p = @intFromBool(bytes[0] == 1) & @intFromBool(all_ones == 0xff);
    return (bytes[0] >> 1 == 0) and is_p == 0;
}

pub fn Field(comptime backend: Backend) type {
    return FieldWith(backend, null);
}

pub const Variant = shared.Variant;

/// `Field` with s2n-bignum's variant fixed, for measuring both; null is the build's choice.
pub fn FieldWith(comptime backend: Backend, comptime variant: ?Variant) type {
    if (backend == .s2n and !assembly) @compileError("s2n-bignum's assembly is not in this build");
    return struct {
        const Self = @This();
        /// fiat: nine 58-bit limbs (the last 57), tight bounds. s2n: nine 64-bit limbs, the
        /// value below p.
        limbs: Limbs,

        pub const encoded_length = length;
        pub const modulus = std.math.maxInt(u521);
        pub const zero: Self = .{ .limbs = @splat(0) };
        pub const one: Self = .{ .limbs = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 } };

        /// A public constant below p, in this backend's limbs.
        pub fn constant(comptime value: u521) Self {
            comptime {
                std.debug.assert(value < std.math.maxInt(u521));
                var r: Self = undefined;
                // fiat: eight 58-bit limbs and a 57-bit one; s2n-bignum: nine 64-bit words.
                const width = if (backend == .fiat) 58 else 64;
                for (&r.limbs, 0..) |*limb, i| limb.* = @truncate((value >> (width * i)) & ((1 << width) - 1));
                return r;
            }
        }

        /// A big-endian value below p.
        pub fn fromBytes(bytes: *const [encoded_length]u8) error{NonCanonical}!Self {
            if (!canonical(bytes)) return error.NonCanonical;
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var owner: Secret([encoded_length]u8) = .init(undefined);
                    defer owner.deinit();
                    const little = owner.exposeMut();
                    for (0..encoded_length) |i| little[i] = bytes[encoded_length - 1 - i];
                    fiat.fromBytes(&r.limbs, little.*);
                },
                .s2n => {
                    var owner: Secret([72]u8) = .init(@splat(0));
                    defer owner.deinit();
                    const padded = owner.exposeMut();
                    padded[72 - encoded_length ..].* = bytes.*;
                    for (0..9) |i| r.limbs[i] = std.mem.readInt(u64, padded[72 - 8 * (i + 1) ..][0..8], .big);
                },
            }
            return r;
        }

        /// The canonical big-endian encoding.
        pub fn toBytes(a: *const Self) [encoded_length]u8 {
            var out: [encoded_length]u8 = undefined;
            switch (backend) {
                .fiat => {
                    var owner: Secret([encoded_length]u8) = .init(undefined);
                    defer owner.deinit();
                    const little = owner.exposeMut();
                    fiat.toBytes(little, a.limbs);
                    for (0..encoded_length) |i| out[i] = little[encoded_length - 1 - i];
                },
                .s2n => {
                    var owner: Secret([72]u8) = .init(undefined);
                    defer owner.deinit();
                    const padded = owner.exposeMut();
                    for (0..9) |i| std.mem.writeInt(u64, padded[72 - 8 * (i + 1) ..][0..8], a.limbs[i], .big);
                    out = padded[72 - encoded_length ..].*;
                },
            }
            return out;
        }

        pub fn mul(a: *const Self, b: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => fiat.carryMul(&r.limbs, a.limbs, b.limbs),
                .s2n => s2n.mul(variant, &r.limbs, &a.limbs, &b.limbs),
            }
            return r;
        }

        pub fn sqr(a: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => fiat.carrySquare(&r.limbs, a.limbs),
                .s2n => s2n.sqr(variant, &r.limbs, &a.limbs),
            }
            return r;
        }

        pub fn sqrn(a: *const Self, comptime count: usize) Self {
            var r = a.*;
            for (0..count) |_| r = r.sqr();
            return r;
        }

        pub fn add(a: *const Self, b: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var loose: Limbs = undefined;
                    fiat.add(&loose, a.limbs, b.limbs);
                    fiat.carry(&r.limbs, loose);
                },
                .s2n => s2n.call("add", false, .{ &r.limbs, &a.limbs, &b.limbs }),
            }
            return r;
        }

        pub fn dbl(a: *const Self) Self {
            return a.add(a);
        }

        pub fn sub(a: *const Self, b: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var loose: Limbs = undefined;
                    fiat.sub(&loose, a.limbs, b.limbs);
                    fiat.carry(&r.limbs, loose);
                },
                .s2n => s2n.call("sub", false, .{ &r.limbs, &a.limbs, &b.limbs }),
            }
            return r;
        }

        pub fn neg(a: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var loose: Limbs = undefined;
                    fiat.opp(&loose, a.limbs);
                    fiat.carry(&r.limbs, loose);
                },
                .s2n => s2n.call("neg", false, .{ &r.limbs, &a.limbs }),
            }
            return r;
        }

        /// a^-1, and zero for zero. s2n-bignum's divstep inversion; fiat's field has none, so
        /// a^(p-2) by a fixed chain: p - 2 = 4 * (2^519 - 1) + 1.
        pub fn invert(a: *const Self) Self {
            switch (backend) {
                .s2n => {
                    var r: Self = undefined;
                    s2n.call("inv", false, .{ &r.limbs, &a.limbs });
                    // Zero has no inverse; the routine's answer for it is not specified.
                    return select(a.isZeroMask(), &r, &zero);
                },
                .fiat => {
                    // x_k = a^(2^k - 1); x_(j+k) = x_j^(2^k) * x_k.
                    const x2 = a.sqr().mul(a);
                    const x4 = x2.sqrn(2).mul(&x2);
                    const x7 = x4.sqrn(2).mul(&x2).sqr().mul(a);
                    const x8 = x4.sqrn(4).mul(&x4);
                    const x16 = x8.sqrn(8).mul(&x8);
                    const x32 = x16.sqrn(16).mul(&x16);
                    const x64 = x32.sqrn(32).mul(&x32);
                    const x128 = x64.sqrn(64).mul(&x64);
                    const x256 = x128.sqrn(128).mul(&x128);
                    const x512 = x256.sqrn(256).mul(&x256);
                    const x519 = x512.sqrn(7).mul(&x7);
                    return x519.sqrn(2).mul(a);
                },
            }
        }

        /// `b` where `mask` is all ones, `a` where it is zero.
        pub fn select(mask: u64, a: *const Self, b: *const Self) Self {
            const m = barrier(mask);
            var r: Self = undefined;
            for (0..9) |i| r.limbs[i] = (b.limbs[i] & m) | (a.limbs[i] & ~m);
            return r;
        }

        /// All ones when the value is zero. fiat's tight limbs can hold p for zero, so the
        /// canonical bytes decide there.
        pub fn isZeroMask(a: *const Self) u64 {
            var x: u64 = 0;
            switch (backend) {
                .s2n => for (a.limbs) |limb| {
                    x |= limb;
                },
                .fiat => for (a.toBytes()) |b| {
                    x |= b;
                },
            }
            return zeroMask(x);
        }

        /// All ones when equal.
        pub fn eqlMask(a: *const Self, b: *const Self) u64 {
            return a.sub(b).isZeroMask();
        }

        /// Public comparisons only.
        pub fn isZero(a: *const Self) bool {
            return a.isZeroMask() != 0;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.eqlMask(b) != 0;
        }
    };
}

/// All ones when `x` is zero.
inline fn zeroMask(x: u64) u64 {
    const nonzero: u1 = @truncate((x | (0 -% x)) >> 63); // safe: the top bit is set exactly when x != 0
    return barrier(0 -% @as(u64, nonzero ^ 1));
}

/// s2n-bignum's P-521 routines; `field/s2n.zig` makes the one choice between the plain and `_alt`
/// multiplication and squaring.
pub const s2n = struct {
    const Out = *Limbs;
    const In = *const Limbs;

    pub const chosen = shared.chosen;
    pub const plainRuns = shared.plainRuns;

    /// `bignum_<name>_p521`, or its `_alt` form.
    pub inline fn call(comptime name: []const u8, comptime alt: bool, args: anytype) void {
        const F = if (args.len == 3) fn (Out, In, In) callconv(.c) void else fn (Out, In) callconv(.c) void;
        @call(.auto, shared.routine(F, "bignum_" ++ name ++ "_p521" ++ (if (alt) "_alt" else "")), args);
    }

    pub inline fn mul(comptime variant: ?Variant, z: Out, x: In, y: In) void {
        if ((variant orelse chosen()) == .plain) call("mul", false, .{ z, x, y }) else call("mul", true, .{ z, x, y });
    }

    pub inline fn sqr(comptime variant: ?Variant, z: Out, x: In) void {
        if ((variant orelse chosen()) == .plain) call("sqr", false, .{ z, x }) else call("sqr", true, .{ z, x });
    }
};

test {
    _ = @import("p521_test.zig");
}
