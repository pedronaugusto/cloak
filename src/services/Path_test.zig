const std = @import("std");
const Path = @import("Path.zig");
const types = @import("../types.zig");
const shakedown = @import("shakedown");
test "service selected path owns poisoned input and binds every request field" {
    @setRuntimeSafety(true);
    var input = [_]u8{ 1, 2, 3 };
    var request: types.Request = .{ .chain = &.{&input}, .time = .fromNanoseconds(10 * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(2) };
    var path = try Path.init(std.testing.allocator, request, &.{&input});
    defer path.deinit();
    try path.check(request);
    input[0] = 4;
    try std.testing.expectEqual(@as(u8, 1), path.chain[0][0]);
    try std.testing.expectError(error.WrongVerificationRequest, path.check(request));
    request.token.id = .fromRaw(1);
    try std.testing.expectError(error.WrongVerificationRequest, path.check(request));
}
test "service path all allocation failures without resize" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), allocations, .{});
}
fn allocations(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    const request: types.Request = .{ .chain = &.{"abc"}, .time = .fromNanoseconds(10 * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(2) };
    var path = try Path.init(gpa, request, request.chain);
    defer path.deinit();
    try path.check(request);
}
