const std = @import("std");
const Der = @import("Der.zig");
test "DER rejects nonminimal lengths integers and escaped children" {
    for ([_][]const u8{ &.{ 4, 0x80, 0, 0 }, &.{ 4, 0x81, 1, 0 }, &.{ 4, 0x82, 0, 128 }, &.{ 0x30, 2, 4, 1 }, &.{ 2, 2, 0, 1 }, &.{ 3, 2, 7, 1 }, &.{ 6, 2, 0x80, 0 }, &.{ 0x31, 6, 2, 1, 2, 2, 1, 1 } }) |b| {
        try std.testing.expectError(error.InvalidDer, Der.validate(b, .{}));
    }
    try Der.validate(&.{ 0x30, 3, 2, 1, 1 }, .{});
    try std.testing.expectError(error.DerLimit, Der.validate(&.{ 0x30, 3, 2, 1, 1 }, .{ .depth = 1 }));
}

test "DER hard recursion cap survives an oversized caller depth in ReleaseFast" {
    var encoded: [512]u8 = undefined;
    encoded[0] = 5;
    encoded[1] = 0;
    var length: usize = 2;
    for (0..70) |_| {
        const header: usize = if (length < 128) 2 else 3;
        @memmove(encoded[header..][0..length], encoded[0..length]);
        encoded[0] = 0x30;
        // safe: seventy wrappers produce fewer than 256 bytes in this fixture.
        const byte: u8 = @intCast(length);
        if (header == 2) encoded[1] = byte else {
            encoded[1] = 0x81;
            encoded[2] = byte;
        }
        length += header;
    }
    try std.testing.expectError(error.DerLimit, Der.validate(encoded[0..length], .{ .depth = std.math.maxInt(usize) }));
    try std.testing.expectError(error.InvalidDer, Der.validate("\x04\x88\xff\xff\xff\xff\xff\xff\xff\xff", .{}));
}
