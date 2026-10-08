const std = @import("std");
const builtin = @import("builtin");
const Native = @import("NativeVerification.zig");
const services = @import("services.zig");
const types = @import("types.zig");
test "native verification receipt binds request and rechecks expiry at completion" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return;
    const root = @embedFile("verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("verify/fixtures/vectors/leaf.der");
    const request: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    var budget: services.Budget = .{};
    const good = try Native.init(std.testing.allocator, &budget, request, .{ .anchors = &.{root} });
    defer good.deinit();
    var receipt = try good.take(std.testing.allocator, request, request.time);
    defer receipt.deinit();
    try receipt.check(request);
    try std.testing.expect(receipt.authenticated);
    const late = try Native.init(std.testing.allocator, &budget, request, .{ .anchors = &.{root} });
    defer late.deinit();
    try std.testing.expectError(error.VerificationExpired, late.take(std.testing.allocator, request, std.math.maxInt(i64)));
}

test "native verification late receipt rejects a backwards real clock" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return;
    const request: types.Request = .{ .chain = &.{@embedFile("verify/fixtures/vectors/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    var budget: services.Budget = .{};
    const native = try Native.init(std.testing.allocator, &budget, request, .{ .anchors = &.{@embedFile("verify/fixtures/vectors/p256.der")} });
    defer native.deinit();
    try std.testing.expectError(error.ValidationTimeChanged, native.take(std.testing.allocator, request, request.time - 1));
}
