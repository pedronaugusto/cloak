const std = @import("std");
const builtin = @import("builtin");
const Native = @import("windows.zig");
const types = @import("../types.zig");
test "service Windows scoped offline policy chain and wrong identity rejection" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .windows) return;
    const root = @embedFile("../verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("../verify/fixtures/vectors/leaf.der");
    var request: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    var path = try Native.evaluate(std.testing.allocator, request, &.{root});
    defer path.deinit();
    try path.check(request);
    try std.testing.expectEqual(@as(usize, 2), path.chain.len);
    request.identity = .{ .dns = "wrong.invalid" };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{root}));
}

test "catalogue_native_windows_wrong_scoped_anchor_rejects" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .windows) return error.SkipZigTest;
    const request: types.Request = .{ .chain = &.{@embedFile("../verify/fixtures/vectors/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{@embedFile("../verify/fixtures/vectors/p384.der")}));
}
