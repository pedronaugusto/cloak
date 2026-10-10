const std = @import("std");
const types = @import("../types.zig");
const Owned = @import("OwnedRequest.zig");
const shakedown = @import("shakedown");
test "service owned request clones policies evidence identity and all allocation failures" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), allocations, .{});
}
fn allocations(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var input = [_]u8{ 'a', 'b', 'c' };
    const request: types.Request = .{ .chain = &.{&input}, .identity = .{ .dns = &input }, .time = .fromNanoseconds(1 * std.time.ns_per_s), .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3), .pins = &.{@splat(7)}, .policy = .{ .required_policies = &.{&input} }, .evidence = .{ .crls = &.{&input}, .ocsp = &.{&input} }, .anchor_policies = &.{.{ .name_constraints = &input, .required_policies = &.{&input} }} };
    const digest = request.digest();
    var owned = try Owned.init(gpa, request, &.{&input});
    defer owned.deinit();
    @memset(&input, 0);
    try std.testing.expectEqualSlices(u8, &digest, &owned.request.digest());
    try std.testing.expectEqualSlices(u8, "abc", owned.anchors[0]);
}
