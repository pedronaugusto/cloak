const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");
const E = @import("Extensions.zig");
const R = @import("../../wire/Reader.zig");
test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist" {
    for ([_]u16{ 0, 43, 51, 0x0a0a, 65535 }) |id| {
        var bytes: [8]u8 = @splat(0);
        std.mem.writeInt(u16, bytes[0..2], id, .big);
        std.mem.writeInt(u16, bytes[4..6], id, .big);
        var ext: E = .{ .reader = .{ .bytes = &bytes } };
        try std.testing.expect((try ext.next()).?.id == id);
        try std.testing.expectError(error.DuplicateExtension, ext.next());
    }
}
test "F27 catalogue_heartbeat_and_nested_length_overread" {
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
        try std.testing.expect(steps <= bytes.len / 4 and ext.reader.pos <= bytes.len);
        try std.testing.expect(item.bytes.len <= bytes.len);
    }
}
test "C2 fuzz TLS extension lengths and duplicates" {
    try shakedown.check(std.testing.allocator, {}, fuzz, .{});
}
const examples = [_][]const u8{ "", "\x00\x33\x00\x02xy", "\x0a\x0a\x00\x00\x0a\x0a\x00\x00", "\x00\x33\xff\xffx" };
test "C2 TLS extension blocks take the odd examples" {
    for (examples) |input| try check(input);
}
fn fuzz(_: void, case: *shakedown.Case) !void {
    var bytes: [4096]u8 = undefined;
    try check(inputs.draw(case, &bytes, &examples, 48));
}

/// A block of `n` empty extensions with distinct IDs from `first` up, in `out`.
fn block(out: []u8, n: usize, first: u16) []u8 {
    for (0..n) |i| {
        std.mem.writeInt(u16, out[i * 4 ..][0..2], first +% @as(u16, @intCast(i)), .big);
        std.mem.writeInt(u16, out[i * 4 + 2 ..][0..2], 0, .big);
    }
    return out[0 .. n * 4];
}

fn count(bytes: []const u8) !usize {
    var ext: E = .{ .reader = .{ .bytes = bytes } };
    var n: usize = 0;
    while (try ext.next()) |_| n += 1;
    return n;
}

test "F101 catalogue_extension_count_unbounded_unique (any number of extensions is read; a repeat anywhere is refused)" {
    var bytes: [65532]u8 = undefined;
    // tlsfuzzer's test-tls13-large-number-of-extensions sends up to 4,096 more; a block holds 16,383.
    for ([_]usize{ 63, 64, 65, 1024, 4096, 16383 }) |n| try std.testing.expectEqual(n, try count(block(&bytes, n, 0x8000)));
    // A repeat of an early ID late, of a late ID later, across the bit set's passes, and of IDs
    // a pass's 12 low bits share but whose high bits differ (not repeats).
    for ([_][2]usize{ .{ 3, 70 }, .{ 10, 5000 }, .{ 100, 16000 }, .{ 0, 63 }, .{ 0, 64 } }) |pair| {
        const b = block(&bytes, 16383, 0);
        std.mem.writeInt(u16, b[pair[1] * 4 ..][0..2], @intCast(pair[0]), .big);
        try std.testing.expectError(error.DuplicateExtension, count(b));
    }
    const spread = block(&bytes, 100, 0);
    for (0..100) |i| std.mem.writeInt(u16, spread[i * 4 ..][0..2], @intCast(((i % 16) << 12) | (0x123 + i / 16)), .big);
    try std.testing.expectEqual(@as(usize, 100), try count(spread));
}
