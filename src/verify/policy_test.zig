const std = @import("std");
const Work = @import("Work.zig");
const C = @import("../certificate.zig");
const P = @import("policy.zig");
const a = "\x2a\x03\x04";
const b = "\x2a\x03\x05";
const policy_a = "\x30\x07\x30\x05\x06\x03\x2a\x03\x04";
const policy_b = "\x30\x07\x30\x05\x06\x03\x2a\x03\x05";
fn extension(cert: *C.Certificate, id: u8, value: []const u8) void {
    const oid = switch (id) {
        32 => "\x55\x1d\x20",
        33 => "\x55\x1d\x21",
        else => unreachable,
    };
    cert.extensions[cert.extension_count] = .{ .oid = oid, .critical = true, .value = value };
    cert.extension_count += 1;
}
test "policy tree explicit OIDs mapping inhibition and null tree are enforced" {
    var work: Work = .{ .remaining = 4 * 1024 * 1024 };
    var path = [_]C.Certificate{ try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p384.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p256.der"), .{}) };
    extension(&path[0], 32, policy_b);
    extension(&path[1], 32, policy_a);
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{}, 256, &work));
    extension(&path[1], 33, "\x30\x0c\x30\x0a\x06\x03\x2a\x03\x04\x06\x03\x2a\x03\x05");
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{}, 256, &work);
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a}, .inhibit_mapping = true }, &.{}, 256, &work));
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{b} }, &.{}, 256, &work));
    path[0].extension_count = 0;
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .explicit_policy = true }, &.{}, 256, &work));
    try std.testing.expectError(error.VerificationLimit, P.check(std.testing.allocator, &path, .{}, &.{}, 0, &work));
}

test "anyPolicy cannot bridge disjoint request and anchor policies" {
    var work: Work = .{ .remaining = 4 * 1024 * 1024 };
    var path = [_]C.Certificate{ try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p256.der"), .{}) };
    extension(&path[0], 32, "\x30\x08\x30\x06\x06\x04\x55\x1d\x20\x00");
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{b}, 256, &work));
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{a}, 256, &work);
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{C.Extensions.any_policy} }, &.{b}, 256, &work);
}

// F14/F21: storage capacity does not stand in for cumulative comparison work.
test "catalogue_policy_comparisons_and_mapping_work_are_bounded" {
    var path = [_]C.Certificate{ try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p384.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p256.der"), .{}) };
    extension(&path[0], 32, policy_b);
    extension(&path[1], 32, policy_a);
    extension(&path[1], 33, "\x30\x0c\x30\x0a\x06\x03\x2a\x03\x04\x06\x03\x2a\x03\x05");
    var measured: Work = .{ .remaining = 4096 };
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{a}, 256, &measured);
    const cost = 4096 - measured.remaining;
    try std.testing.expect(cost > 1);
    var exact: Work = .{ .remaining = cost };
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{a}, 256, &exact);
    try std.testing.expectEqual(@as(usize, 0), exact.remaining);
    // A later candidate shares the owner; it cannot obtain a fresh budget.
    try std.testing.expectError(error.VerificationLimit, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{a}, 256, &exact));
    var short: Work = .{ .remaining = cost - 1 };
    try std.testing.expectError(error.VerificationLimit, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{a}, 256, &short));
    var failing: Work = .{ .remaining = 4096 };
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{b} }, &.{a}, 256, &failing));
    try std.testing.expect(failing.remaining < 4096);
}
