const std = @import("std");
const builtin = @import("builtin");
const Native = @import("macos.zig");
const types = @import("../types.zig");
test "service macOS scoped anchors selected chain and policy rejection offline" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos) return;
    const root = @embedFile("../verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("../verify/fixtures/vectors/leaf.der");
    var request: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var path = try Native.evaluate(std.testing.allocator, request, &.{root});
    defer path.deinit();
    try path.check(request);
    try std.testing.expectEqual(@as(usize, 2), path.chain.len);
    request.identity = .{ .dns = "wrong.invalid" };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{root}));
    request.identity = .{ .dns = "example.com" };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{@embedFile("../verify/fixtures/vectors/p384.der")}));
}
