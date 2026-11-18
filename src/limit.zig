//! A measured value held to a limit, through the limit's own comparison: the limits of
//! `types.Limits`, `Trust.Limits` and the options beside them are aegis scalars, sizes and
//! counts, never compared as bare integers.
//!
//! This file is internal. `root.zig` is the package.
const std = @import("std");

/// Whether `value` is past `limit`. A value no `usize` holds (negative, or too large) is past it.
pub fn over(value: anytype, limit: anytype) bool {
    const v = std.math.cast(usize, value) orelse return true;
    return @TypeOf(limit).fromRaw(v).compare(limit) == .gt;
}

/// Whether `value` has reached `limit`: one more would be past it.
pub fn reached(value: anytype, limit: anytype) bool {
    const v = std.math.cast(usize, value) orelse return true;
    return @TypeOf(limit).fromRaw(v).compare(limit) != .lt;
}

/// Whether `limit` is above `bound`.
pub fn above(limit: anytype, bound: usize) bool {
    return limit.compare(.fromRaw(bound)) == .gt;
}

/// Whether `limit` is below `bound`.
pub fn below(limit: anytype, bound: usize) bool {
    return limit.compare(.fromRaw(bound)) == .lt;
}

/// Whether `limit` allows nothing.
pub fn none(limit: anytype) bool {
    return limit.compare(.fromRaw(0)) == .eq;
}

test "a value is held to its limit by the limit's own comparison" {
    const aegis = @import("aegis");
    const Size = aegis.units.Bytes(usize);
    try std.testing.expect(over(@as(usize, 5), Size.fromRaw(4)));
    try std.testing.expect(!over(@as(usize, 4), Size.fromRaw(4)));
    try std.testing.expect(reached(@as(usize, 4), Size.fromRaw(4)));
    try std.testing.expect(!reached(@as(usize, 3), Size.fromRaw(4)));
    try std.testing.expect(over(@as(i32, -1), Size.fromRaw(4)));
    try std.testing.expect(above(Size.fromRaw(17), 16) and !above(Size.fromRaw(16), 16));
    try std.testing.expect(below(Size.fromRaw(3), 4) and none(Size.fromRaw(0)));
}
