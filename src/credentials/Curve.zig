//! Borrowed-scalar fixed-window base multiplication for credential construction.
//! Adapted from Zig 0.17 pcMul16/pcSelect; see docs/design.md.
const std = @import("std");
const curve_point = @import("curve/Point.zig");
pub const MultiplyError = error{IdentityElement};

pub fn base(comptime Point: type, comptime endian: std.builtin.Endian, scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8) MultiplyError!Point {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    const private = PrivatePoint(Point);
    var scratch: Scratch(private) = undefined;
    return baseOwned(Point, endian, scalar, &scratch);
}
fn PrivatePoint(comptime Point: type) type {
    return if (Point == std.crypto.ecc.P256 or Point == std.crypto.ecc.P384) curve_point.Point(Point) else Point;
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
/// Fixed-window multiplication of an arbitrary public point by a private scalar.
/// The window table is public data built from the peer; the walk over the secret
/// scalar is the same masked selection as `base`. P-256 and P-384 only.
pub fn mul(comptime Point: type, comptime endian: std.builtin.Endian, peer: Point, scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8) MultiplyError!Point {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-scalar multiplication requires std side-channel mitigations");
        if (Point != std.crypto.ecc.P256 and Point != std.crypto.ecc.P384) @compileError("variable-point multiplication is defined for P-256 and P-384");
    }
    const private = PrivatePoint(Point);
    // Public table: peer multiples never depend on the scalar.
    var table: [16]private = undefined;
    table[0] = private.identityElement;
    var open: [16]Point = undefined;
    open[1] = peer;
    table[1] = private.fromPublic(peer);
    for (2..16) |i| {
        open[i] = if (i % 2 == 0) open[i / 2].dbl() else open[i - 1].add(peer);
        table[i] = private.fromPublic(open[i]);
    }
    var scratch: Scratch(private) = undefined;
    return ladder(Point, endian, &table, scalar, &scratch);
}
fn ladder(comptime Point: type, comptime endian: std.builtin.Endian, table: *const [16]PrivatePoint(Point), scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8, scratch: *Scratch(PrivatePoint(Point))) MultiplyError!Point {
    @setRuntimeSafety(true);
    const private = PrivatePoint(Point);
    // One owner for the accumulator, selected point, digit and selection mask.
    scratch.* = .{ .q = private.identityElement, .selected = private.identityElement, .digit = 0, .choice = 0 };
    defer std.crypto.secureZero(u8, std.mem.asBytes(scratch));
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
pub const ValidateError = error{InvalidScalar};
pub fn validate(comptime Point: type, scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8) ValidateError!void {
    @setRuntimeSafety(true);
    const order = comptime value: {
        var bytes: [@sizeOf(Point.scalar.CompressedScalar)]u8 = undefined;
        std.mem.writeInt(@Int(.unsigned, bytes.len * 8), &bytes, Point.scalar.field_order, .big);
        break :value bytes;
    };
    // Comparison borrows bytes; only the final invalid-key result is observable.
    if (std.crypto.timing_safe.compare(u8, scalar, &order, .big) != .lt) return error.InvalidScalar;
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
    _ = @import("curve/Montgomery_test.zig");
    _ = @import("curve/Montgomery.zig");
}

test "credential curve live scratch wipes full capacity on success and rejection" {
    @setRuntimeSafety(true);
    inline for (.{ std.crypto.ecc.P256, std.crypto.ecc.P384, std.crypto.ecc.Edwards25519 }) |Point| {
        var scalar: [@sizeOf(Point.scalar.CompressedScalar)]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &scalar);
        var owner: Scratch(PrivatePoint(Point)) = undefined;
        scalar[0] = 1;
        var point = try baseOwned(Point, .little, &scalar, &owner);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        // The owner is still live and fully initialized; inspect bytes, including padding.
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&owner), 0));
        scalar[0] = 0;
        try std.testing.expectError(error.IdentityElement, baseOwned(Point, .little, &scalar, &owner));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&owner), 0));
    }
}
