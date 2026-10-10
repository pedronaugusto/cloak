const std = @import("std");
const V = @import("Verifier.zig");
test "portable verifier rejects empty chains and work budget overflow" {
    try std.testing.expectError(error.VerificationLimit, V.verify(std.testing.allocator, .{ .chain = &.{}, .time = .fromNanoseconds(0 * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) }, &.{}));
}

const C = @import("../certificate.zig");
const T = @import("../types.zig");
const shakedown = @import("shakedown");
const root = @embedFile("fixtures/vectors/p256.der");
const leaf = @embedFile("fixtures/vectors/leaf.der");
fn request() T.Request {
    return .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, std.fmt.parseInt(i64, @embedFile("fixtures/vectors/time.txt"), 10) catch unreachable) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(2) };
}
test "portable selected path identity pins limits and native floors" {
    var req = request();
    var receipt = try V.verify(std.testing.allocator, req, &.{ root, root });
    defer receipt.deinit();
    try std.testing.expectEqual(@as(usize, 2), receipt.path.len);
    try receipt.check(req);
    var native = try V.nativePath(std.testing.allocator, req, &.{ leaf, root });
    defer native.deinit();
    try native.check(req);
    try std.testing.expectError(error.InvalidAnchorPolicy, V.nativePath(std.testing.allocator, req, &.{root}));
    req.identity = .{ .dns = "attacker.example" };
    try std.testing.expectError(error.IdentityMismatch, V.verify(std.testing.allocator, req, &.{root}));
    req = request();
    req.pins = &.{@splat(0)};
    try std.testing.expectError(error.PinMismatch, V.verify(std.testing.allocator, req, &.{root}));
    req.mode = .none;
    try std.testing.expectError(error.PinMismatch, V.verify(std.testing.allocator, req, &.{}));
    req.pins = &.{};
    var unauthenticated = try V.verify(std.testing.allocator, req, &.{});
    defer unauthenticated.deinit();
    try std.testing.expect(!unauthenticated.authenticated);
    var native_none = try V.nativePath(std.testing.allocator, req, &.{ leaf, root });
    defer native_none.deinit();
    try std.testing.expect(!native_none.authenticated);
    req = request();
    req.limits.candidates = 0;
    try std.testing.expectError(error.VerificationLimit, V.verify(std.testing.allocator, req, &.{root}));
}
test "portable verifier and receipt survive every allocation failure without resize" {
    var n = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(n.allocator(), allocations, .{});
}
fn allocations(gpa: std.mem.Allocator) !void {
    var receipt = try V.verify(gpa, request(), &.{root});
    defer receipt.deinit();
    try receipt.check(request());
}

test "portable verifier reports bounded common heap and releases path scratch" {
    var counting = shakedown.alloc.Counting.init(std.testing.allocator);
    var receipt = try V.verify(counting.allocator(), request(), &.{root});
    try std.testing.expect(counting.peak_bytes < 65536);
    std.debug.print("VERIFIER common peak heap {d}, retained receipt {d}, Certificate {d} bytes\n", .{ counting.peak_bytes, counting.live_bytes, @sizeOf(C.Certificate) });
    receipt.deinit();
    try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
}

test "portable indexed verification accepts large stores within discovery budget" {
    const roots: [512][]const u8 = @splat(root);
    var index = try C.Issuers.init(std.testing.allocator, &roots, .{});
    defer index.deinit();
    var receipt = try V.indexed(std.testing.allocator, request(), &index);
    defer receipt.deinit();
    try receipt.check(request());
    try std.testing.expectError(error.VerificationLimit, V.verify(std.testing.allocator, request(), &roots));
    var limited = request();
    limited.limits.candidates = 0;
    try std.testing.expectError(error.VerificationLimit, V.indexed(std.testing.allocator, limited, &index));
}

test "portable and native selected leaf share strict serial and issuer metadata floors" {
    const zero = @embedFile("fixtures/limbo-zero-serial.der");
    const cert = try C.parse(zero, .{});
    const req: T.Request = .{ .chain = &.{zero}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, cert.not_before) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    try std.testing.expectError(error.InvalidCertificate, V.verify(std.testing.allocator, req, &.{zero}));
    // A provisional native-selected path must still satisfy the same leaf floor.
    try std.testing.expectError(error.InvalidCertificate, V.nativePath(std.testing.allocator, req, &.{zero}));
}

test "portable native selected scratch covers OS intermediates absent from request" {
    const selected_leaf = @embedFile("fixtures/offline/leaf.der");
    const selected = &.{ selected_leaf, @embedFile("fixtures/offline/rollover.der"), @embedFile("fixtures/offline/ca.der") };
    const req: T.Request = .{ .chain = &.{selected_leaf}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, std.fmt.parseInt(i64, @embedFile("fixtures/offline/time.txt"), 10) catch unreachable) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var receipt = try V.nativePath(std.testing.allocator, req, selected);
    defer receipt.deinit();
    try std.testing.expectEqual(@as(usize, 3), receipt.path.len);
    try receipt.check(req);
}

// F14: signed public inputs within the wire cap cannot evade comparison limits.
test "catalogue_verification_constraint_flood_is_bounded" {
    inline for (.{ 1, 1900 }) |count| {
        const flood_leaf = @embedFile(std.fmt.comptimePrint("fixtures/work/work-leaf-{d}.der", .{count}));
        const issuer = @embedFile(std.fmt.comptimePrint("fixtures/work/work-inter-{d}.der", .{count}));
        const req: T.Request = .{ .chain = &.{ flood_leaf, issuer }, .identity = .{ .dns = "review.example" }, .time = .fromNanoseconds(1791467000 * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1), .limits = .{ .candidates = 16, .parses = 8, .signatures = 2, .rejected = 8, .policy_nodes = 1, .depth = 3 } };
        const anchors = &.{@embedFile("fixtures/work/work-root.der")};
        if (count == 1) {
            var receipt = try V.verify(std.testing.allocator, req, anchors);
            defer receipt.deinit();
            try receipt.check(req);
            var native = try V.nativePath(std.testing.allocator, req, &.{ flood_leaf, issuer, anchors[0] });
            defer native.deinit();
            try native.check(req);
        } else {
            const limited = if (V.verify(std.testing.allocator, req, anchors)) |value| blk: {
                var receipt = value;
                defer receipt.deinit();
                break :blk false;
            } else |err| err == error.VerificationLimit;
            try std.testing.expect(limited);
            try std.testing.expectError(error.VerificationLimit, V.nativePath(std.testing.allocator, req, &.{ flood_leaf, issuer, anchors[0] }));
        }
    }
}
