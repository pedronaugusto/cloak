//! Borrowed-scalar fixed-window base multiplication for credential construction.
//! Adapted from Zig 0.17 pcMul16/pcSelect; see docs/internal/C1-primitives.md.
const std = @import("std");
pub const MultiplyError = error{IdentityElement};

pub fn base(comptime Point: type, comptime endian: std.builtin.Endian, scalar: *const [@sizeOf(Point.scalar.CompressedScalar)]u8) MultiplyError!Point {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    const table = comptime precompute(Point);
    // One owner for the accumulator, selected point, digit and selection mask.
    var scratch: struct { q: Point, selected: Point, digit: u8 = 0, choice: u1 = 0 } = .{ .q = Point.identityElement, .selected = Point.identityElement };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
    var remaining: usize = scalar.len * 2;
    while (remaining != 0) {
        remaining -= 1;
        const byte = if (endian == .little) remaining / 2 else scalar.len - 1 - remaining / 2;
        const shift: u3 = if (remaining % 2 == 0) 0 else 4;
        scratch.digit = (scalar[byte] >> shift) & 15;
        scratch.selected = Point.identityElement;
        inline for (1..16) |i| {
            const index: u8 = @intCast(i); // safe: the compile-time table indices are 1..15
            scratch.choice = @truncate((@as(usize, scratch.digit ^ index) -% 1) >> 8); // safe: only the equality mask low bit is retained
            scratch.selected.x.cMov(table[i].x, scratch.choice);
            scratch.selected.y.cMov(table[i].y, scratch.choice);
            scratch.selected.z.cMov(table[i].z, scratch.choice);
            if (@hasField(Point, "t")) scratch.selected.t.cMov(table[i].t, scratch.choice);
        }
        // The first public iteration can assign instead of adding identity.
        scratch.q = if (remaining == scalar.len * 2 - 1) scratch.selected else scratch.q.add(scratch.selected);
        if (remaining != 0) scratch.q = scratch.q.dbl().dbl().dbl().dbl();
    }
    // Only the final invalid-key predicate is released; no secret controls the loop.
    try scratch.q.rejectIdentity();
    return scratch.q;
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
    @setEvalBranchQuota(100000);
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
