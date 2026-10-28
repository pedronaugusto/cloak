const std = @import("std");
const Builder = @import("Builder.zig");
const Der = @import("Der.zig");

test "DER builder writes short and long lengths, minimal integers and named bits" {
    const gpa = std.testing.allocator;
    var b = Builder.init(gpa);
    defer b.deinit();
    const outer = try b.open(0x30);
    try b.small(0);
    try b.small(127);
    try b.small(128);
    try b.unsigned(&.{ 0, 0, 0x80, 1 });
    try b.boolean(true);
    try b.namedBits((1 << 0) | (1 << 5)); // digitalSignature, keyCertSign
    try b.namedBits(1 << 0);
    try b.namedBits(1 << 8);
    const long = try b.open(0x04);
    for (0..300) |_| try b.raw("x");
    try b.close(long);
    try b.close(outer);
    const der = try b.toOwnedSlice();
    defer gpa.free(der);
    var r = (try Der.single(der, 0x30)).reader();
    try std.testing.expectEqualSlices(u8, "\x02\x01\x00", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x02\x01\x7f", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x02\x02\x00\x80", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x02\x03\x00\x80\x01", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x01\x01\xff", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x03\x02\x02\x84", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x03\x02\x07\x80", (try r.next()).encoded);
    try std.testing.expectEqualSlices(u8, "\x03\x03\x07\x00\x80", (try r.next()).encoded);
    const string = try r.next();
    try std.testing.expectEqual(300, string.value.len);
    try std.testing.expectEqualSlices(u8, "\x04\x82\x01\x2c", string.encoded[0..4]);
    try r.finish();
    try Der.validate(der, .{});
}
