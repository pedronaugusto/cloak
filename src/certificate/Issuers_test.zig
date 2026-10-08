const std = @import("std");
const I = @import("Issuers.zig");
const C = @import("Certificate.zig");
const N = @import("Name.zig");
const shakedown = @import("shakedown");
const root = @embedFile("../verify/fixtures/vectors/p256.der");
test "issuer index deduplicates exact DER and preserves normalized subject buckets" {
    const roots: [512][]const u8 = @splat(root);
    var index = try I.init(std.testing.allocator, &roots, .{});
    defer index.deinit();
    const cert = try C.parse(root, .{});
    const found = try index.find(cert.subject);
    try std.testing.expectEqual(@as(usize, 1), found.len);
    try std.testing.expectEqual(@as(usize, 0), found[0].index);
    const a = "\x30\x0f\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x0c\x04Test";
    const b = "\x30\x0f\x31\x0d\x30\x0b\x06\x03\x55\x04\x03\x13\x04tEST";
    try std.testing.expectEqualSlices(u8, &try N.key(a), &try N.key(b));
}
test "issuer index survives each allocation failure without resize" {
    var allocator = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(allocator.allocator(), allocation, .{});
}
fn allocation(gpa: std.mem.Allocator) !void {
    var index = try I.init(gpa, &.{root}, .{});
    defer index.deinit();
}

test "issuer index omits unusable unrelated candidates and preserves policy indices" {
    var index = try I.init(std.testing.allocator, &.{ "\x30\x00", root }, .{});
    defer index.deinit();
    const cert = try C.parse(root, .{});
    const found = try index.find(cert.subject);
    try std.testing.expectEqual(@as(usize, 1), found.len);
    try std.testing.expectEqual(@as(usize, 1), found[0].index);
}
