//! Borrowed-scalar fixed-window base multiplication on Edwards25519 for Ed25519 signing (the NIST
//! curves are crypto/weierstrass.zig's). Adapted from Zig 0.17 pcMul16/pcSelect; see
//! docs/design.md.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
pub const MultiplyError = error{IdentityElement};

pub fn base(comptime Point: type, comptime endian: std.builtin.Endian, scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8) MultiplyError!Point {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    const private = PrivatePoint(Point);
    var scratch: Secret(Scratch(private)) = .init(undefined);
    defer scratch.deinit();
    return baseOwned(Point, endian, scalar, scratch.exposeMut());
}
fn PrivatePoint(comptime Point: type) type {
    if (Point != std.crypto.ecc.Edwards25519) @compileError("the NIST curves are crypto/weierstrass.zig's");
    return Point;
}
fn Scratch(comptime Point: type) type {
    return struct { q: Point, selected: Point, digit: u8, choice: u1 };
}
fn baseOwned(comptime Point: type, comptime endian: std.builtin.Endian, scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8, scratch: *Scratch(PrivatePoint(Point))) MultiplyError!Point {
    @setRuntimeSafety(true);
    const private = PrivatePoint(Point);
    const table = comptime precompute(private);
    return ladder(Point, endian, &table, scalar, scratch);
}
fn ladder(comptime Point: type, comptime endian: std.builtin.Endian, table: *const [16]PrivatePoint(Point), scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8, scratch: *Scratch(PrivatePoint(Point))) MultiplyError!Point {
    @setRuntimeSafety(true);
    const private = PrivatePoint(Point);
    // One owner for the accumulator, selected point, digit and selection mask: the caller's
    // aegis `Secret`, which erases it.
    scratch.* = .{ .q = private.identityElement, .selected = private.identityElement, .digit = 0, .choice = 0 };
    var remaining: usize = scalar.len * 2;
    while (remaining != 0) {
        remaining -= 1;
        const byte = if (endian == .little) remaining / 2 else scalar.len - 1 - remaining / 2;
        const shift: u3 = if (remaining % 2 == 0) 0 else 4;
        scratch.digit = (scalar[byte] >> shift) & 15;
        scratch.selected = private.identityElement;
        inline for (1..16) |i| {
            const index: u8 = @intCast(i); // safe: the table indices are 1..15
            scratch.choice = @truncate((@as(usize, scratch.digit ^ index) -% 1) >> 8); // safe: only the equality mask low bit is retained
            scratch.selected.x.cMov(table[i].x, scratch.choice);
            scratch.selected.y.cMov(table[i].y, scratch.choice);
            scratch.selected.z.cMov(table[i].z, scratch.choice);
            if (@hasField(private, "t")) scratch.selected.t.cMov(table[i].t, scratch.choice);
        }
        // The first public iteration can assign instead of adding identity.
        scratch.q = if (remaining == scalar.len * 2 - 1) scratch.selected else scratch.q.add(scratch.selected);
        if (remaining != 0) scratch.q = scratch.q.dbl().dbl().dbl().dbl();
    }
    // Only the final invalid-key predicate is released; no secret controls the loop.
    try scratch.q.rejectIdentity();
    return if (private == Point) scratch.q else scratch.q.publicPoint();
}
fn precompute(comptime Point: type) [16]Point {
    @setRuntimeSafety(true);
    @setEvalBranchQuota(1000000);
    var table: [16]Point = undefined;
    table[0] = Point.identityElement;
    table[1] = Point.basePoint;
    for (2..16) |i| table[i] = if (i % 2 == 0) table[i / 2].dbl() else table[i - 1].add(Point.basePoint);
    return table;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Curve_test.zig");
}
