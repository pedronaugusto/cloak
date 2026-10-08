const std = @import("std");
const shakedown = @import("shakedown");
const Pem = @import("Pem.zig");
test "credential PEM strict armor and bounded inputs" {
    @setRuntimeSafety(true);
    var pem = Pem.init("junk-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----");
    try std.testing.expectError(error.InvalidPem, pem.next(std.testing.allocator, 1024));
    pem = Pem.init("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----");
    try std.testing.expectError(error.InputLimit, pem.next(std.testing.allocator, 8));
    var block = (try pem.next(std.testing.allocator, 1024)).?;
    defer block.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{0}, block.der);
    try std.testing.expectEqual(@as(?Pem.Block, null), try pem.next(std.testing.allocator, 1024));
}
test "credential PEM allocation failures" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), parse, .{});
}
fn parse(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var pem = Pem.init("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----");
    var block = (try pem.next(gpa, 1024)).?;
    defer block.deinit(gpa);
}
