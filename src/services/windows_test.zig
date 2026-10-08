const std = @import("std");
const builtin = @import("builtin");
const Native = @import("windows.zig");
const types = @import("../types.zig");
test "service Windows scoped offline policy chain and distrust fixture" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .windows) return;
    const root = @embedFile("../verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("../verify/fixtures/vectors/leaf.der");
    var request: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    var path = try Native.evaluate(std.testing.allocator, request, &.{root});
    defer path.deinit();
    try std.testing.expectEqual(@as(usize, 2), path.chain.len);
    request.identity = .{ .dns = "wrong.invalid" };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{root}));
}
