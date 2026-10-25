//! The P-521 field, p = 2^521 - 1, behind one interface: s2n-bignum's verified assembly on
//! x86_64 and AArch64, fiat-crypto's verified Zig everywhere else and as the reference both are
//! tested against. Curve code sees `Fe` alone; the backends differ only in their limbs.
//!
//! Every operation runs the same instructions for every value. The assembly writes its
//! temporaries to the stack: secret computations run it inside `aegis.secret.scrubbed`, which
//! scrubs that stack and sets the processor's data-independent timing mode around them.
const std = @import("std");
const builtin = @import("builtin");
const fiat = @import("../vendor/fiat/p521_64.zig");

pub const encoded_length = 66;
pub const Limbs = [9]u64;

pub const Backend = enum { fiat, s2n };

/// Whether s2n-bignum's assembly is in this build: x86_64, and AArch64 where the object format
/// is ELF or Mach-O (its AArch64 files carry no COFF directives).
pub const assembly = switch (builtin.cpu.arch) {
    .x86_64 => true,
    .aarch64 => builtin.os.tag != .windows,
    else => false,
};

/// The field elements this build computes with.
pub const Fe = Field(if (assembly) .s2n else .fiat);

/// The canonical encoding check both backends share: big-endian, below 2^521 (the top byte at
/// most 1) and not p itself (0x01 then 65 bytes of 0xff). Constant time; only the verdict leaves.
fn canonical(bytes: *const [encoded_length]u8) bool {
    var all_ones: u8 = 0xff;
    for (bytes[1..]) |b| all_ones &= b;
    const is_p = @intFromBool(bytes[0] == 1) & @intFromBool(all_ones == 0xff);
    return (bytes[0] >> 1 == 0) and is_p == 0;
}

pub fn Field(comptime backend: Backend) type {
    if (backend == .s2n and !assembly) @compileError("s2n-bignum's assembly is not in this build");
    return struct {
        const Self = @This();
        /// fiat: nine 58-bit limbs (the last 57), tight bounds. s2n: nine 64-bit limbs, the
        /// value below p.
        limbs: Limbs,

        pub const zero: Self = .{ .limbs = @splat(0) };
        pub const one: Self = .{ .limbs = .{ 1, 0, 0, 0, 0, 0, 0, 0, 0 } };

        /// A big-endian value below p.
        pub fn fromBytes(bytes: *const [encoded_length]u8) error{NonCanonical}!Self {
            if (!canonical(bytes)) return error.NonCanonical;
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var little: [encoded_length]u8 = undefined;
                    for (0..encoded_length) |i| little[i] = bytes[encoded_length - 1 - i];
                    fiat.fromBytes(&r.limbs, little);
                    std.crypto.secureZero(u8, &little);
                },
                .s2n => {
                    var padded: [72]u8 = @splat(0);
                    padded[72 - encoded_length ..].* = bytes.*;
                    for (0..9) |i| r.limbs[i] = std.mem.readInt(u64, padded[72 - 8 * (i + 1) ..][0..8], .big);
                    std.crypto.secureZero(u8, &padded);
                },
            }
            return r;
        }

        /// The canonical big-endian encoding.
        pub fn toBytes(a: Self) [encoded_length]u8 {
            var out: [encoded_length]u8 = undefined;
            switch (backend) {
                .fiat => {
                    var little: [encoded_length]u8 = undefined;
                    fiat.toBytes(&little, a.limbs);
                    for (0..encoded_length) |i| out[i] = little[encoded_length - 1 - i];
                    std.crypto.secureZero(u8, &little);
                },
                .s2n => {
                    var padded: [72]u8 = undefined;
                    for (0..9) |i| std.mem.writeInt(u64, padded[72 - 8 * (i + 1) ..][0..8], a.limbs[i], .big);
                    out = padded[72 - encoded_length ..].*;
                    std.crypto.secureZero(u8, &padded);
                },
            }
            return out;
        }

        pub fn mul(a: Self, b: Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => fiat.carryMul(&r.limbs, a.limbs, b.limbs),
                .s2n => s2n.mul(&r.limbs, &a.limbs, &b.limbs),
            }
            return r;
        }

        pub fn sqr(a: Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => fiat.carrySquare(&r.limbs, a.limbs),
                .s2n => s2n.sqr(&r.limbs, &a.limbs),
            }
            return r;
        }

        pub fn sqrn(a: Self, comptime count: usize) Self {
            var r = a;
            for (0..count) |_| r = r.sqr();
            return r;
        }

        pub fn add(a: Self, b: Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var loose: Limbs = undefined;
                    fiat.add(&loose, a.limbs, b.limbs);
                    fiat.carry(&r.limbs, loose);
                },
                .s2n => s2n.call("add", .{ &r.limbs, &a.limbs, &b.limbs }),
            }
            return r;
        }

        pub fn dbl(a: Self) Self {
            return a.add(a);
        }

        pub fn sub(a: Self, b: Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var loose: Limbs = undefined;
                    fiat.sub(&loose, a.limbs, b.limbs);
                    fiat.carry(&r.limbs, loose);
                },
                .s2n => s2n.call("sub", .{ &r.limbs, &a.limbs, &b.limbs }),
            }
            return r;
        }

        pub fn neg(a: Self) Self {
            var r: Self = undefined;
            switch (backend) {
                .fiat => {
                    var loose: Limbs = undefined;
                    fiat.opp(&loose, a.limbs);
                    fiat.carry(&r.limbs, loose);
                },
                .s2n => s2n.call("neg", .{ &r.limbs, &a.limbs }),
            }
            return r;
        }

        /// a^-1, and zero for zero. s2n-bignum's divstep inversion; fiat's field has none, so
        /// a^(p-2) by a fixed chain: p - 2 = 4 * (2^519 - 1) + 1.
        pub fn invert(a: Self) Self {
            switch (backend) {
                .s2n => {
                    var r: Self = undefined;
                    s2n.call("inv", .{ &r.limbs, &a.limbs });
                    // Zero has no inverse; the routine's answer for it is not specified.
                    return select(a.isZeroMask(), r, zero);
                },
                .fiat => {
                    // x_k = a^(2^k - 1); x_(j+k) = x_j^(2^k) * x_k.
                    const x2 = a.sqr().mul(a);
                    const x4 = x2.sqrn(2).mul(x2);
                    const x7 = x4.sqrn(2).mul(x2).sqr().mul(a);
                    const x8 = x4.sqrn(4).mul(x4);
                    const x16 = x8.sqrn(8).mul(x8);
                    const x32 = x16.sqrn(16).mul(x16);
                    const x64 = x32.sqrn(32).mul(x32);
                    const x128 = x64.sqrn(64).mul(x64);
                    const x256 = x128.sqrn(128).mul(x128);
                    const x512 = x256.sqrn(256).mul(x256);
                    const x519 = x512.sqrn(7).mul(x7);
                    return x519.sqrn(2).mul(a);
                },
            }
        }

        /// `b` where `mask` is all ones, `a` where it is zero.
        pub fn select(mask: u64, a: Self, b: Self) Self {
            const m = barrier(mask);
            var r: Self = undefined;
            for (0..9) |i| r.limbs[i] = (b.limbs[i] & m) | (a.limbs[i] & ~m);
            return r;
        }

        /// All ones when the value is zero. fiat's tight limbs can hold p for zero, so the
        /// canonical bytes decide there.
        pub fn isZeroMask(a: Self) u64 {
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
        pub fn eqlMask(a: Self, b: Self) u64 {
            return a.sub(b).isZeroMask();
        }

        /// Public comparisons only.
        pub fn isZero(a: Self) bool {
            return a.isZeroMask() != 0;
        }

        pub fn eql(a: Self, b: Self) bool {
            return a.eqlMask(b) != 0;
        }
    };
}

/// Hides a mask from the optimizer so a selection stays a selection and never becomes a branch.
inline fn barrier(value: u64) u64 {
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

/// All ones when `x` is zero.
inline fn zeroMask(x: u64) u64 {
    const nonzero: u1 = @truncate((x | (0 -% x)) >> 63); // safe: the top bit is set exactly when x != 0
    return barrier(0 -% @as(u64, nonzero ^ 1));
}

/// s2n-bignum's P-521 routines, as `build.zig` assembles them: each named `cloak_<routine>`.
/// On x86_64 the multiplication and squaring come in two forms: the plain ones use BMI2 and
/// ADX (mulx, adcx, adox), the `_alt` ones the base instruction set. A target that has both
/// features takes the plain ones at compile time; any other x86_64 build asks CPUID once.
pub const s2n = struct {
    const Out = *Limbs;
    const In = *const Limbs;

    pub extern fn cloak_bignum_mul_p521(z: Out, x: In, y: In) callconv(.c) void;
    pub extern fn cloak_bignum_mul_p521_alt(z: Out, x: In, y: In) callconv(.c) void;
    pub extern fn cloak_bignum_sqr_p521(z: Out, x: In) callconv(.c) void;
    pub extern fn cloak_bignum_sqr_p521_alt(z: Out, x: In) callconv(.c) void;
    pub extern fn cloak_bignum_add_p521(z: Out, x: In, y: In) callconv(.c) void;
    pub extern fn cloak_bignum_sub_p521(z: Out, x: In, y: In) callconv(.c) void;
    pub extern fn cloak_bignum_neg_p521(z: Out, x: In) callconv(.c) void;
    pub extern fn cloak_bignum_inv_p521(z: Out, x: In) callconv(.c) void;

    pub inline fn call(comptime name: []const u8, args: anytype) void {
        @call(.auto, @field(@This(), "cloak_bignum_" ++ name ++ "_p521"), args);
    }

    pub inline fn mul(z: Out, x: In, y: In) void {
        if (plain()) cloak_bignum_mul_p521(z, x, y) else cloak_bignum_mul_p521_alt(z, x, y);
    }

    pub inline fn sqr(z: Out, x: In) void {
        if (plain()) cloak_bignum_sqr_p521(z, x) else cloak_bignum_sqr_p521_alt(z, x);
    }

    /// Whether the plain routines run: always on AArch64; on x86_64 where BMI2 and ADX are.
    pub inline fn plain() bool {
        if (builtin.cpu.arch != .x86_64) return true;
        if (comptime std.Target.x86.featureSetHasAll(builtin.cpu.features, .{ .bmi2, .adx })) return true;
        return mulxAvailable();
    }

    /// Whether this x86_64 processor has BMI2 and ADX.
    pub fn mulxAvailable() bool {
        return mulx.get();
    }

    /// The CPUID answer, asked once: 0 unasked, 1 without, 2 with. Racing first calls agree.
    const mulx = struct {
        var state: std.atomic.Value(u8) = .init(0);

        fn get() bool {
            const known = state.load(.monotonic);
            if (known != 0) return known == 2;
            const has = detect();
            state.store(if (has) 2 else 1, .monotonic);
            return has;
        }

        fn detect() bool {
            if (cpuid(0, 0).eax < 7) return false;
            const ebx = cpuid(7, 0).ebx;
            // Leaf 7: BMI2 is EBX bit 8, ADX EBX bit 19.
            return ebx & (1 << 8) != 0 and ebx & (1 << 19) != 0;
        }

        fn cpuid(leaf: u32, subleaf: u32) struct { eax: u32, ebx: u32 } {
            var eax: u32 = undefined;
            var ebx: u32 = undefined;
            asm volatile ("cpuid"
                : [eax] "={eax}" (eax),
                  [ebx] "={ebx}" (ebx),
                : [leaf] "{eax}" (leaf),
                  [subleaf] "{ecx}" (subleaf),
                : .{ .ecx = true, .edx = true });
            return .{ .eax = eax, .ebx = ebx };
        }
    };
};

test {
    _ = @import("p521_test.zig");
}
