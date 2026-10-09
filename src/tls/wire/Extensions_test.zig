const std = @import("std");
const shakedown = @import("shakedown");
const E = @import("Extensions.zig");
const R = @import("Reader.zig");
test "C2 catalogue_extension_uniqueness_and_negotiation_allowlist" {
    for ([_]u16{ 0, 43, 51, 0x0a0a, 65535 }) |id| {
        var bytes: [8]u8 = @splat(0);
        std.mem.writeInt(u16, bytes[0..2], id, .big);
        std.mem.writeInt(u16, bytes[4..6], id, .big);
        var ext: E = .{ .reader = .{ .bytes = &bytes } };
        try std.testing.expect((try ext.next()).?.id == id);
        try std.testing.expectError(error.DuplicateExtension, ext.next());
    }
}
test "C2 catalogue_heartbeat_and_nested_length_overread" {
    var reader: R = .{ .bytes = "\xff\xffx" };
    try std.testing.expectError(error.InvalidLength, reader.vector(u16));
    var ext: E = .{ .reader = .{ .bytes = "\x00\x33\xff\xffx" } };
    try std.testing.expectError(error.InvalidLength, ext.next());
    var exact: R = .{ .bytes = "\x00\x01xtrailing" };
    try std.testing.expectEqualSlices(u8, "x", (try exact.vector(u16)).bytes);
    try std.testing.expectError(error.InvalidLength, exact.finish());
}
test "C2 extension parser property bounded hostile bytes" {
    try shakedown.check(std.testing.allocator, {}, property, .{ .cases = 4096, .seed = 0xc2ee });
}
fn property(_: void, case: *shakedown.Case) !void {
    var bytes: [512]u8 = undefined;
    const len = shakedown.gen.intRange(case.source, usize, 0, bytes.len);
    for (bytes[0..len]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    try check(bytes[0..len]);
}
fn check(bytes: []const u8) !void {
    var ext: E = .{ .reader = .{ .bytes = bytes } };
    var steps: usize = 0;
    while (ext.next() catch return) |item| {
        steps += 1;
        try std.testing.expect(steps <= 64 and ext.reader.pos <= bytes.len);
        try std.testing.expect(item.bytes.len <= bytes.len);
    }
}
test "C2 fuzz TLS extension lengths and duplicates" {
    try std.testing.fuzz({}, fuzz, .{ .corpus = shakedown.corpus.entries(&.{ "", "\x00\x33\x00\x02xy", "\x0a\x0a\x00\x00\x0a\x0a\x00\x00", "\x00\x33\xff\xffx" }) });
}
fn fuzz(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    try check(bytes[0..smith.slice(&bytes)]);
}
