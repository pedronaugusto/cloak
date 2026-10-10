const std = @import("std");
const builtin = @import("builtin");
const Native = @import("macos.zig");
const types = @import("../types.zig");
test "service macOS scoped anchors selected chain and policy rejection offline" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos) return;
    const root = @embedFile("../verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("../verify/fixtures/vectors/leaf.der");
    var request: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var path = try Native.evaluate(std.testing.allocator, request, &.{root});
    defer path.deinit();
    try path.check(request);
    try std.testing.expectEqual(@as(usize, 2), path.chain.len);
    request.identity = .{ .dns = "wrong.invalid" };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{root}));
    request.identity = .{ .dns = "example.com" };
    try std.testing.expectError(error.NativePolicyFailure, Native.evaluate(std.testing.allocator, request, &.{@embedFile("../verify/fixtures/vectors/p384.der")}));
}
test "service macOS Security opens once and refuses a missing framework or symbol" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos) return;
    const table = try Native.Security.load();
    try std.testing.expectEqual(table, try Native.Security.load());
    var refused: Native.Security = undefined;
    try std.testing.expectError(error.SystemTrustUnavailable, Native.Security.open("/System/Library/Frameworks/Missing.framework/Missing", &refused));
    // CoreFoundation is there, and the SecTrust functions are not in it.
    try std.testing.expectError(error.SystemTrustUnavailable, Native.Security.open("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", &refused));
}
