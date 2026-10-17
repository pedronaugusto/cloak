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
    var log_key = [_]u8{ 'k', 'e', 'y' };
    var operator = [_]u8{ 'o', 'p' };
    const logs = [_]types.TransparencyLog{.{ .key = &log_key, .operator = &operator, .retired = .fromNanoseconds(5) }};
    var transparency: types.TransparencyPolicy = .{ .logs = &logs, .expires = .fromNanoseconds(9) };
    const request: types.Request = .{ .chain = &.{&input}, .identity = .{ .dns = &input }, .time = .fromNanoseconds(1 * std.time.ns_per_s), .trust_generation = .fromRaw(2), .policy_generation = .fromRaw(3), .pins = &.{@splat(7)}, .policy = .{ .required_policies = &.{&input}, .transparency = &transparency }, .evidence = .{ .crls = &.{&input}, .ocsp = &.{&input}, .scts = &.{&input} }, .anchor_policies = &.{.{ .name_constraints = &input, .required_policies = &.{&input} }} };
    const digest = request.digest();
    var owned = try Owned.init(gpa, request, &.{&input});
    defer owned.deinit();
    @memset(&input, 0);
    // Certificate Transparency's policy and SCT lists are owned too, not borrowed from the caller.
    @memset(&log_key, 0);
    @memset(&operator, 0);
    transparency.embedded = 7;
    try std.testing.expectEqualSlices(u8, &digest, &owned.request.digest());
    try std.testing.expectEqualSlices(u8, "abc", owned.anchors[0]);
}
