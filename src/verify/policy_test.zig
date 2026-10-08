const std = @import("std");
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
    var path = [_]C.Certificate{ try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p384.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p256.der"), .{}) };
    extension(&path[0], 32, policy_b);
    extension(&path[1], 32, policy_a);
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{}, 256));
    extension(&path[1], 33, "\x30\x0c\x30\x0a\x06\x03\x2a\x03\x04\x06\x03\x2a\x03\x05");
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{}, 256);
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a}, .inhibit_mapping = true }, &.{}, 256));
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{b} }, &.{}, 256));
    path[0].extension_count = 0;
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .explicit_policy = true }, &.{}, 256));
    try std.testing.expectError(error.VerificationLimit, P.check(std.testing.allocator, &path, .{}, &.{}, 0));
}

test "anyPolicy cannot bridge disjoint request and anchor policies" {
    var path = [_]C.Certificate{ try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p256.der"), .{}) };
    extension(&path[0], 32, "\x30\x08\x30\x06\x06\x04\x55\x1d\x20\x00");
    try std.testing.expectError(error.PolicyViolation, P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{b}, 256));
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{a} }, &.{a}, 256);
    try P.check(std.testing.allocator, &path, .{ .required_policies = &.{C.Extensions.any_policy} }, &.{b}, 256);
}
