const std = @import("std");
const C = @import("../certificate.zig");
const D = @import("../wire/Der.zig");
const R = @import("revocation.zig");
test "revocation work requires a bounded selected path" {
    try std.testing.expectError(error.VerificationLimit, R.check(&.{}, 0, .{}, .{}));
    try std.testing.expectEqual(.unchecked, (try R.check(&.{}, 0, .{ .mode = .off }, .{})).status);
}

test "offline CRL and OCSP authority signature serial freshness and required coverage" {
    const now = try std.fmt.parseInt(i64, @embedFile("fixtures/vectors/time.txt"), 10);
    const path = [_]C.Certificate{ try C.parse(@embedFile("fixtures/vectors/leaf.der"), .{}), try C.parse(@embedFile("fixtures/vectors/p256.der"), .{}) };
    const good_crl = @embedFile("fixtures/vectors/good.crl");
    const bad_crl = @embedFile("fixtures/vectors/revoked.crl");
    const good_ocsp = @embedFile("fixtures/vectors/good.ocsp");
    const bad_ocsp = @embedFile("fixtures/vectors/revoked.ocsp");
    try std.testing.expectEqual(.good, (try R.check(&path, now, .{ .mode = .required }, .{ .crls = &.{good_crl} })).status);
    try std.testing.expectEqual(.good, (try R.check(&path, now, .{ .mode = .required }, .{ .ocsp = &.{good_ocsp} })).status);
    try std.testing.expectError(error.Revoked, R.check(&path, now, .{}, .{ .crls = &.{bad_crl} }));
    try std.testing.expectError(error.Revoked, R.check(&path, now, .{}, .{ .ocsp = &.{bad_ocsp} }));
    try std.testing.expectError(error.MissingRevocation, R.check(&path, now, .{ .mode = .required }, .{}));
    try std.testing.expectError(error.StaleRevocation, R.check(&path, now + 86400 * 2, .{}, .{ .ocsp = &.{good_ocsp} }));
    var corrupted: [good_ocsp.len]u8 = good_ocsp.*;
    var response = (try D.single(good_ocsp, 0x30)).reader();
    _ = try response.expect(10);
    var body = (try D.single((try response.expect(0xa0)).value, 0x30)).reader();
    _ = try body.expect(6);
    var basic = (try D.single((try body.expect(4)).value, 0x30)).reader();
    _ = try basic.expect(0x30);
    _ = try basic.expect(0x30);
    const sig = try D.octetBits((try basic.expect(3)).value);
    const offset = std.mem.find(u8, good_ocsp, sig).?;
    corrupted[offset + sig.len - 1] ^= 1;
    try std.testing.expectError(error.InvalidRevocation, R.check(&path, now, .{}, .{ .ocsp = &.{ &corrupted, good_ocsp } }));
}

test "offline delegated responders require their own valid evidence and CRLs cover rollover paths" {
    const now = try std.fmt.parseInt(i64, @embedFile("fixtures/offline/time.txt"), 10);
    const leaf = try C.parse(@embedFile("fixtures/offline/leaf.der"), .{});
    const ca = try C.parse(@embedFile("fixtures/offline/ca.der"), .{});
    const rollover = try C.parse(@embedFile("fixtures/offline/rollover.der"), .{});
    const path = [_]C.Certificate{ leaf, ca };
    const crl = @embedFile("fixtures/offline/good.crl");
    const ocsp = @embedFile("fixtures/offline/delegated.ocsp");
    try std.testing.expectError(error.MissingRevocation, R.check(&path, now, .{}, .{ .ocsp = &.{ocsp} }));
    try std.testing.expectEqual(.good, (try R.check(&path, now, .{ .mode = .required }, .{ .ocsp = &.{ocsp}, .crls = &.{crl} })).status);
    try std.testing.expectError(error.Revoked, R.check(&path, now, .{}, .{ .ocsp = &.{ocsp}, .crls = &.{@embedFile("fixtures/offline/responder-revoked.crl")} }));
    try std.testing.expectError(error.UnsupportedRevocation, R.check(&path, now, .{}, .{ .crls = &.{@embedFile("fixtures/offline/invalid-remove.crl")} }));
    const rolled_path = [_]C.Certificate{ leaf, rollover, ca };
    try std.testing.expectEqual(.good, (try R.check(&rolled_path, now, .{ .mode = .required, .coverage = .whole_path }, .{ .crls = &.{crl} })).status);
    const deadline = (try R.check(&path, now, .{}, .{ .crls = &.{crl} })).expires.?;
    try std.testing.expectEqual(.good, (try R.check(&path, deadline, .{}, .{ .crls = &.{crl} })).status);
    try std.testing.expectError(error.StaleRevocation, R.check(&path, deadline + 1, .{}, .{ .crls = &.{crl} }));
}
