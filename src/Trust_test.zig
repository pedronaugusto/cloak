const std = @import("std");
const shakedown = @import("shakedown");
const Trust = @import("Trust.zig");
const builtin = @import("builtin");

test "trust empty portable store fails closed" {
    @setRuntimeSafety(true);
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    try std.testing.expectError(error.NoTrustAnchors, trust.freeze());
}

test "trust bounded and malformed PEM stays empty" {
    @setRuntimeSafety(true);
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    try std.testing.expectError(error.TrustLimit, trust.addPem("0123456789", .{ .file_bytes = 4 }));
    try std.testing.expectError(error.InvalidPem, trust.addPem("", .{}));
    try std.testing.expectError(error.InvalidPem, trust.addPem("garbage", .{}));
    try std.testing.expectError(error.InvalidPem, trust.addPem("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----", .{}));
    try std.testing.expectError(error.NoTrustAnchors, trust.freeze());
}

test "trust snapshot reload retains independent owned state" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), snapshotLifetime, .{});
}

fn snapshotLifetime(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var trust = Trust.init(gpa);
    defer trust.deinit();
    // This lifetime test isolates native policy metadata from certificate parsing.
    trust.system = .macos;
    const first = try trust.freeze();
    defer first.deinit();
    const held = first.retain();
    defer held.deinit();
    trust.system = .windows;
    const next = try trust.freeze();
    defer next.deinit();
    try std.testing.expectEqual(Trust.System.macos, held.systemPolicy());
    try std.testing.expectEqual(Trust.System.windows, next.systemPolicy());
    try std.testing.expectEqual(first.generation() + 1, next.generation());
}

test "trust byte identical dedup transactional PEM and immutable input ownership" {
    @setRuntimeSafety(true);
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    const pem = @embedFile("credentials/testdata/p256.cert.pem");
    var der: [@embedFile("credentials/testdata/p256.cert.der").len]u8 = @embedFile("credentials/testdata/p256.cert.der").*;
    try trust.addDer(&der, .{});
    try trust.addPem(pem, .{});
    try std.testing.expectEqual(@as(usize, 1), trust.roots.items.len);
    try std.testing.expectError(error.InvalidPem, trust.addPem(pem ++ "junk", .{}));
    try std.testing.expectEqual(@as(usize, 1), trust.roots.items.len);
    @memset(&der, 0);
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    try std.testing.expectEqualSlices(u8, @embedFile("credentials/testdata/p256.cert.der"), snapshot.anchors()[0]);
}

test "trust file bounds errors cancellation and deadline preserve prior state" {
    @setRuntimeSafety(true);
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    try trust.addPem(@embedFile("credentials/testdata/p256.cert.pem"), .{});
    const path = "src/credentials/testdata/p256.cert.pem";
    try trust.addFile(std.testing.io, path, .{});
    try std.testing.expectError(error.StreamTooLong, trust.addFile(std.testing.io, path, .{ .limits = .{ .file_bytes = 8 } }));
    var clock = shakedown.Clock.init(std.testing.io, .{ .monotonic = .fromNanoseconds(100) });
    const io = clock.io();
    try std.testing.expectError(error.Timeout, trust.addFile(io, path, .{ .timeout = .{ .deadline = .{ .raw = .fromNanoseconds(99), .clock = .awake } } }));
    try std.testing.expectEqual(@as(usize, 1), trust.roots.items.len);
}

test "trust FaultIo open read cancellation and finite stalled read rollback" {
    @setRuntimeSafety(true);
    const path = "src/credentials/testdata/p256.cert.pem";
    inline for (.{ .dirOpenFile, .fileReadPositional }) |call| {
        const fault = try shakedown.FaultIo.init(std.testing.allocator, std.testing.io, .{ .plan = &.{.{ .at = .{ .nth = .{ .call = call, .n = 1 } }, .fault = .cancel }} });
        defer fault.deinit();
        var trust = Trust.init(std.testing.allocator);
        defer trust.deinit();
        try trust.addPem(@embedFile("credentials/testdata/p256.cert.pem"), .{});
        try std.testing.expectError(error.Canceled, trust.addFile(fault.io(), path, .{}));
        try std.testing.expectEqual(@as(usize, 1), trust.roots.items.len);
    }
    var clock = shakedown.Clock.init(std.testing.io, .{});
    var started: std.Io.Event = .unset;
    const stall: shakedown.IoFault = .stall;
    const fault = try shakedown.FaultIo.init(std.testing.allocator, clock.io(), .{ .plan = &.{.{ .at = .{ .nth = .{ .call = .fileReadPositional, .n = 1 } }, .fault = .{ .call = .{ .f = signalRead, .ctx = &started, .then = &stall } } }} });
    defer fault.deinit();
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    try trust.addPem(@embedFile("credentials/testdata/p256.cert.pem"), .{});
    var work = try std.testing.io.concurrent(Trust.addFile, .{ &trust, fault.io(), path, Trust.LoadOptions{ .timeout = .{ .duration = .{ .raw = .fromMilliseconds(1), .clock = .awake } } } });
    const barrier: std.Io.Timeout = .{ .duration = .{ .raw = .fromSeconds(5), .clock = .awake } };
    started.waitTimeout(std.testing.io, barrier) catch |err| {
        _ = work.cancel(std.testing.io) catch return err;
        return err;
    };
    clock.awaitArmed(1, barrier) catch |err| {
        _ = work.cancel(std.testing.io) catch return err;
        return err;
    };
    clock.advance(.fromMilliseconds(1));
    try std.testing.expectError(error.Timeout, work.await(std.testing.io));
    try std.testing.expectEqual(@as(usize, 1), trust.roots.items.len);
}

fn signalRead(io: std.Io, context: ?*anyopaque) void {
    @setRuntimeSafety(true);
    const started: *std.Io.Event = @ptrCast(@alignCast(context.?)); // safe: this fault owns the aligned Event context until the joined loader finishes
    started.set(io);
}

test "trust native system policy cannot mix with explicit anchors" {
    @setRuntimeSafety(true);
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    trust.system = .macos;
    try std.testing.expectError(error.MixedTrustPolicies, trust.addDer(@embedFile("credentials/testdata/p256.cert.der"), .{}));
}

test "trust Linux system bundle freezes into the indexed explicit store" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    try trust.addSystem(std.testing.io, .{ .timeout = .{ .duration = .{ .raw = .fromSeconds(10), .clock = .awake } } });
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    try std.testing.expect(snapshot.anchors().len > 0);
    try std.testing.expectEqual(Trust.System.portable, snapshot.systemPolicy());
}
