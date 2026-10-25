//! s2n-bignum's Montgomery multiplication and squaring for RSA's moduli, of any width up to
//! 64 limbs, R = 2^(64k): verified, constant time, through two paths chosen by the width alone.
//!
//! - Fast, at multiples of 8 limbs on AArch64 and on x86_64 with BMI2 and ADX: the product by
//!   Karatsuba (`bignum_kmul_16_32`/`_32_64`, `bignum_ksqr_16_32`/`_32_64`) at 16 and 32 limbs
//!   or the schoolbook `bignum_mul`/`bignum_sqr` at other multiples of 8, then the reduction
//!   by `bignum_emontredc_8n`, which leaves the result and one carry bit; the caller's masked
//!   subtraction brings it below m. The halves of RSA-2048, -3072 and -4096 take it.
//! - Generic, everywhere else the assembly is: `bignum_montmul`/`bignum_montsqr`, base
//!   instruction set, any width.
//!
//! Operands are below m; results are below 2m with the carry (fast) or below m (generic). The
//! temporaries are wiped before return; the assembly's stack is the caller's to scrub.
const std = @import("std");
const builtin = @import("builtin");
const s2n = @import("s2n.zig");

pub const assembly = s2n.assembly;
pub const max_limbs = 64;

pub const Path = enum { fast, generic };

/// The path a k-limb modulus takes in this process.
pub fn path(k: usize) Path {
    if (k % 8 != 0) return .generic;
    return switch (builtin.cpu.arch) {
        .aarch64 => .fast,
        // The x86_64 fast routines use mulx, adcx and adox: the processor runs them exactly
        // when it runs s2n-bignum's plain forms.
        .x86_64 => if (s2n.chosen() == .plain) .fast else .generic,
        else => unreachable, // unreachable: `assembly` holds only on x86_64 and AArch64
    };
}

/// The words Karatsuba's largest form needs beside its product.
const temporary_words = 96;

/// The unreduced result of the fast path: `wide[k..2k]` plus `carry * R`, below 2m.
pub const Wide = struct {
    words: [2 * max_limbs]u64,
    carry: u64,
};

/// `x * y / R` by the fast path into `out`; k a multiple of 8, `w` = -m^-1 mod 2^64.
pub fn mulFast(out: *Wide, k: usize, x: []const u64, y: []const u64, m: []const u64, w: u64) void {
    var t: [temporary_words]u64 = undefined;
    defer std.crypto.secureZero(u64, &t);
    const z = &out.words;
    switch (k) {
        16 => routine(fn (*[32]u64, *const [16]u64, *const [16]u64, *[32]u64) callconv(.c) void, "bignum_kmul_16_32")(z[0..32], x[0..16], y[0..16], t[0..32]),
        32 => routine(fn (*[64]u64, *const [32]u64, *const [32]u64, *[96]u64) callconv(.c) void, "bignum_kmul_32_64")(z[0..64], x[0..32], y[0..32], t[0..96]),
        else => routine(fn (u64, [*]u64, u64, [*]const u64, u64, [*]const u64) callconv(.c) void, "bignum_mul")(2 * k, z, k, x.ptr, k, y.ptr),
    }
    out.carry = reduce(k, z, m, w);
}

/// `x^2 / R` by the fast path into `out`, as `mulFast`.
pub fn sqrFast(out: *Wide, k: usize, x: []const u64, m: []const u64, w: u64) void {
    var t: [temporary_words]u64 = undefined;
    defer std.crypto.secureZero(u64, &t);
    const z = &out.words;
    switch (k) {
        16 => routine(fn (*[32]u64, *const [16]u64, *[24]u64) callconv(.c) void, "bignum_ksqr_16_32")(z[0..32], x[0..16], t[0..24]),
        32 => routine(fn (*[64]u64, *const [32]u64, *[72]u64) callconv(.c) void, "bignum_ksqr_32_64")(z[0..64], x[0..32], t[0..72]),
        else => routine(fn (u64, [*]u64, u64, [*]const u64) callconv(.c) void, "bignum_sqr")(2 * k, z, k, x.ptr),
    }
    out.carry = reduce(k, z, m, w);
}

/// Montgomery reduction of the 2k-limb product in place: the result in its top k limbs.
fn reduce(k: usize, z: *[2 * max_limbs]u64, m: []const u64, w: u64) u64 {
    return routine(fn (u64, [*]u64, [*]const u64, u64) callconv(.c) u64, "bignum_emontredc_8n")(k, z, m.ptr, w);
}

/// `out = x * y / R mod m` by the generic path; `out` may alias `x` or `y`.
pub fn mulGeneric(out: []u64, x: []const u64, y: []const u64, m: []const u64) void {
    var z: [max_limbs]u64 = undefined;
    defer std.crypto.secureZero(u64, z[0..out.len]);
    routine(fn (u64, [*]u64, [*]const u64, [*]const u64, [*]const u64) callconv(.c) void, "bignum_montmul")(out.len, &z, x.ptr, y.ptr, m.ptr);
    @memcpy(out, z[0..out.len]);
}

/// `out = x^2 / R mod m` by the generic path; `out` may alias `x`.
pub fn sqrGeneric(out: []u64, x: []const u64, m: []const u64) void {
    var z: [max_limbs]u64 = undefined;
    defer std.crypto.secureZero(u64, z[0..out.len]);
    routine(fn (u64, [*]u64, [*]const u64, [*]const u64) callconv(.c) void, "bignum_montsqr")(out.len, &z, x.ptr, m.ptr);
    @memcpy(out, z[0..out.len]);
}

fn routine(comptime F: type, comptime name: []const u8) *const F {
    return s2n.routine(F, name);
}
