//! The P-256 and P-384 fields behind one interface: s2n-bignum's verified assembly on x86_64 and
//! AArch64, fiat-crypto's verified Zig everywhere else and as the reference both are tested
//! against. Both backends hold the same value the same way, the Montgomery form a * 2^(64n) mod p
//! in n little-endian 64-bit limbs below p, so a constant or a precomputed table serves either,
//! and curve code sees `Fe` alone.
//!
//! Multiplication, squaring and inversion run s2n-bignum's routines where the build has them.
//! Addition, subtraction and negation run fiat-crypto's in both backends: they are a few
//! instructions each, verified like the rest, and inline into the curve formulas, where a call
//! into the assembly (a call, a frame, no inlining) costs more than the operation itself.
//!
//! Every operation runs the same instructions for every value. The assembly writes its
//! temporaries to the stack: secret computations run it inside `aegis.secret.scrubbed`, which
//! scrubs that stack and sets the processor's data-independent timing mode around them.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const s2n = @import("s2n.zig");
const Montgomery = @import("Montgomery.zig");

pub const Curve = enum { p256, p384 };

pub const Backend = enum { fiat, s2n };
pub const Variant = s2n.Variant;

/// The field elements this build computes with.
pub fn Fe(comptime curve: Curve) type {
    return Field(curve, if (s2n.assembly) .s2n else .fiat);
}

pub fn Field(comptime curve: Curve, comptime backend: Backend) type {
    return FieldWith(curve, backend, null);
}

/// `Field` with s2n-bignum's variant fixed, for measuring both; null is the build's choice.
pub fn FieldWith(comptime curve: Curve, comptime backend: Backend, comptime variant: ?Variant) type {
    if (backend == .s2n and !s2n.assembly) @compileError("s2n-bignum's assembly is not in this build");
    return struct {
        const Self = @This();
        const fiat = switch (curve) {
            .p256 => @import("../vendor/fiat/p256_64.zig"),
            .p384 => @import("../vendor/fiat/p384_64.zig"),
        };
        pub const modulus: comptime_int = switch (curve) {
            .p256 => 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff,
            .p384 => 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff,
        };
        pub const n = switch (curve) {
            .p256 => 4,
            .p384 => 6,
        };
        pub const encoded_length = 8 * n;
        pub const Limbs = [n]u64;

        /// The Montgomery form, below p.
        limbs: Limbs,

        pub const zero: Self = .{ .limbs = @splat(0) };
        pub const one: Self = constant(1);
        const r2: Self = .{ .limbs = split((1 << (128 * n)) % modulus) };
        const m: Limbs = split(modulus);

        fn split(comptime value: comptime_int) Limbs {
            comptime {
                @setEvalBranchQuota(100_000);
                var limbs: Limbs = undefined;
                for (&limbs, 0..) |*limb, i| limb.* = (value >> (64 * i)) & std.math.maxInt(u64);
                return limbs;
            }
        }

        /// The Montgomery form of a public constant below p.
        pub fn constant(comptime value: comptime_int) Self {
            comptime {
                @setEvalBranchQuota(100_000);
                std.debug.assert(value < modulus);
                return .{ .limbs = split((value << (64 * n)) % modulus) };
            }
        }

        /// A big-endian value below p; the check is constant time and only its verdict leaves.
        pub fn fromBytes(bytes: *const [encoded_length]u8) error{NonCanonical}!Self {
            var owner: Secret(Limbs) = .init(undefined);
            defer owner.deinit();
            const value = owner.exposeMut();
            inline for (0..n) |i| value[i] = std.mem.readInt(u64, bytes[8 * (n - 1 - i) ..][0..8], .big);
            if (!lessThanModulus(value)) return error.NonCanonical;
            return fromInt(value);
        }

        /// The canonical big-endian encoding.
        pub fn toBytes(a: *const Self) [encoded_length]u8 {
            var owner: Secret(Limbs) = .init(a.toInt());
            defer owner.deinit();
            const value = owner.expose();
            var out: [encoded_length]u8 = undefined;
            inline for (0..n) |i| std.mem.writeInt(u64, out[8 * (n - 1 - i) ..][0..8], value[i], .big);
            return out;
        }

        /// Whether raw limbs are below p, computed without branches.
        pub fn lessThanModulus(value: *const Limbs) bool {
            var b: u1 = 0;
            inline for (0..n) |i| _, b = Montgomery.subb(value[i], m[i], b);
            return b == 1;
        }

        /// The Montgomery form of raw limbs below p.
        pub fn fromInt(value: *const Limbs) Self {
            const raw: Self = .{ .limbs = value.* };
            return raw.mul(&r2);
        }

        /// The value's raw limbs, below p.
        pub fn toInt(a: *const Self) Limbs {
            var unit: Self = zero;
            unit.limbs[0] = 1;
            return a.mul(&unit).limbs;
        }

        pub fn mul(a: *const Self, b: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => fiat.mul(&r.limbs, a.limbs, b.limbs),
                .s2n => if ((variant orelse s2n.chosen()) == .plain) call("montmul", false, .{ &r.limbs, &a.limbs, &b.limbs }) else call("montmul", true, .{ &r.limbs, &a.limbs, &b.limbs }),
            }
            return r;
        }

        pub fn sqr(a: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => fiat.square(&r.limbs, a.limbs),
                .s2n => if ((variant orelse s2n.chosen()) == .plain) call("montsqr", false, .{ &r.limbs, &a.limbs }) else call("montsqr", true, .{ &r.limbs, &a.limbs }),
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
                .fiat, .s2n => fiat.add(&r.limbs, a.limbs, b.limbs),
            }
            return r;
        }

        pub fn dbl(a: *const Self) Self {
            return a.add(a);
        }

        pub fn sub(a: *const Self, b: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat, .s2n => fiat.sub(&r.limbs, a.limbs, b.limbs),
            }
            return r;
        }

        pub fn neg(a: *const Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat, .s2n => fiat.opp(&r.limbs, a.limbs),
            }
            return r;
        }

        /// a^-1, and zero for zero. s2n-bignum's divstep inversion in the Montgomery domain
        /// (zero for zero, as it says); fiat's field has none, so a^(p-2) by a fixed walk over
        /// the public exponent, four bits at a time.
        pub fn invert(a: *const Self) Self {
            switch (backend) {
                .s2n => {
                    var r: Self = undefined;
                    call("montinv", false, .{ &r.limbs, &a.limbs });
                    return r;
                },
                .fiat => {
                    const exponent = comptime split(modulus - 2);
                    var owner: Secret([16]Self) = .init(undefined);
                    defer owner.deinit();
                    const table = owner.exposeMut();
                    table[0] = one;
                    for (1..16) |i| table[i] = table[i - 1].mul(a);
                    var r = one;
                    var limb: usize = n;
                    while (limb > 0) {
                        limb -= 1;
                        var shift: u7 = 64;
                        while (shift > 0) {
                            shift -= 4;
                            r = r.sqrn(4);
                            const digit: u4 = @truncate(exponent[limb] >> @as(u6, @intCast(shift))); // safe: a nibble of the public exponent
                            r = r.mul(&table[digit]);
                        }
                    }
                    return r;
                },
            }
        }

        /// `b` where `mask` is all ones, `a` where it is zero.
        pub fn select(mask: u64, a: *const Self, b: *const Self) Self {
            const k = Montgomery.barrier(mask);
            var r: Self = undefined;
            inline for (0..n) |i| r.limbs[i] = (b.limbs[i] & k) | (a.limbs[i] & ~k);
            return r;
        }

        /// All ones when the value is zero.
        pub fn isZeroMask(a: *const Self) u64 {
            var x: u64 = 0;
            inline for (0..n) |i| x |= a.limbs[i];
            return Montgomery.zeroMask(x);
        }

        /// All ones when equal.
        pub fn eqlMask(a: *const Self, b: *const Self) u64 {
            var x: u64 = 0;
            inline for (0..n) |i| x |= a.limbs[i] ^ b.limbs[i];
            return Montgomery.zeroMask(x);
        }

        /// Public comparisons only.
        pub fn isZero(a: *const Self) bool {
            return a.isZeroMask() != 0;
        }

        pub fn eql(a: *const Self, b: *const Self) bool {
            return a.eqlMask(b) != 0;
        }

        /// `bignum_<name>_<curve>`, or its `_alt` form.
        inline fn call(comptime name: []const u8, comptime alt: bool, args: anytype) void {
            const Out = *Limbs;
            const In = *const Limbs;
            const F = if (args.len == 3) fn (Out, In, In) callconv(.c) void else fn (Out, In) callconv(.c) void;
            @call(.auto, s2n.routine(F, "bignum_" ++ name ++ "_" ++ @tagName(curve) ++ (if (alt) "_alt" else "")), args);
        }
    };
}

test {
    _ = @import("nist_test.zig");
}
