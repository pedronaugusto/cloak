const std = @import("std");
const builtin = @import("builtin");
const Native = @import("NativeVerification.zig");
const services = @import("services.zig");
const types = @import("types.zig");
const shakedown = @import("shakedown");
test "native verification receipt binds request and rechecks expiry at completion" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return;
    const root = @embedFile("verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("verify/fixtures/vectors/leaf.der");
    const request: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("verify/fixtures/vectors/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var budget: services.Budget = .{};
    const good = try Native.init(std.testing.allocator, &budget, request, .{ .anchors = &.{root} });
    defer good.deinit();
    var receipt = try good.take(std.testing.allocator, request, request.time);
    defer receipt.deinit();
    try receipt.check(request);
    try std.testing.expect(receipt.authenticated);
    const late = try Native.init(std.testing.allocator, &budget, request, .{ .anchors = &.{root} });
    defer late.deinit();
    try std.testing.expectError(error.VerificationExpired, late.take(std.testing.allocator, request, .fromNanoseconds(std.math.maxInt(i96))));
}

test "native verification late receipt rejects a backwards real clock" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return;
    const request: types.Request = .{ .chain = &.{@embedFile("verify/fixtures/vectors/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("verify/fixtures/vectors/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var budget: services.Budget = .{};
    const native = try Native.init(std.testing.allocator, &budget, request, .{ .anchors = &.{@embedFile("verify/fixtures/vectors/p256.der")} });
    defer native.deinit();
    try std.testing.expectError(error.ValidationTimeChanged, native.take(std.testing.allocator, request, .fromNanoseconds(request.time.nanoseconds - 1)));
}

test "catalogue_native_completion_owned_allocation_failures_without_resize" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), nativeAllocations, .{});
}
fn nativeAllocations(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    const req: types.Request = .{ .chain = &.{@embedFile("verify/fixtures/vectors/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("verify/fixtures/vectors/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var budget: services.Budget = .{};
    defer {
        std.debug.assert(budget.counts().jobs == 0);
        std.debug.assert(budget.counts().bytes == 0);
    }
    const native = try Native.init(gpa, &budget, req, .{ .anchors = &.{@embedFile("verify/fixtures/vectors/p256.der")} });
    defer native.deinit();
    var receipt = try native.take(gpa, req, req.time);
    defer receipt.deinit();
    try receipt.check(req);
}

test "catalogue_native_completion_repeated_release_keeps_owned_heap_and_budget_bounded" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    var counting = shakedown.alloc.Counting.init(std.testing.allocator);
    for (0..256) |_| {
        try nativeAllocations(counting.allocator());
        try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
    }
    // This fixture's own heap, including the caller receipt, fits the default
    // job reservation. OS-private heap/handles and hostile maxima are not counted.
    try std.testing.expect(counting.peak_bytes < 65536);
    std.debug.print("NATIVE owned heap peak={d} live_after={d} accepted/released=256\n", .{ counting.peak_bytes, counting.live_bytes });
}
