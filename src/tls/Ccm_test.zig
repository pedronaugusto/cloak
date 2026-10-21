//! The AES-CCM suites over streams: TLS_AES_128_CCM_SHA256 (RFC 8446) and the ECDHE_ECDSA CCM
//! suites of TLS 1.2 (RFC 7251), a cloak client against a cloak server.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const suites = @import("crypto/Suite.zig");
const Suite = suites.Suite;
const Protection = @import("record/Protection.zig");

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(std.testing.allocator, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C8 the AES-CCM suites complete in TLS 1.3 and TLS 1.2 and carry data both ways" {
    const cases = [_]struct { suite: Suite, version: suites.Version }{
        .{ .suite = .aes_128_ccm_sha256, .version = .tls13 },
        .{ .suite = .ecdhe_ecdsa_aes_128_ccm, .version = .tls12 },
        .{ .suite = .ecdhe_ecdsa_aes_256_ccm, .version = .tls12 },
        .{ .suite = .ecdhe_ecdsa_aes_128_ccm_8, .version = .tls12 },
    };
    for (cases) |case| for ([_]usize{ 1 << 20, 1 }) |chunk| {
        const duo = try connect(.{ .client_suites = &.{case.suite}, .server_suites = &.{case.suite}, .chunk = chunk });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expectEqual(case.suite, info.suite);
        try std.testing.expectEqual(case.version, info.version);
        try std.testing.expectEqual(case.suite, duo.server.info().?.suite);
        var out: [64]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "ping", try duo.echo(&duo.client, &duo.server, "ping", &out));
        try std.testing.expectEqualSlices(u8, "pong", try duo.echo(&duo.server, &duo.client, "pong", &out));
    };
}

test "C8 the AES-CCM suites are spoken only when listed: the default offer leaves them out" {
    for (Suite.default) |suite| {
        try std.testing.expect(suite != .aes_128_ccm_sha256 and suite != .ecdhe_ecdsa_aes_128_ccm and suite != .ecdhe_ecdsa_aes_256_ccm and suite != .ecdhe_ecdsa_aes_128_ccm_8);
    }
    // A client offering only CCM meets a server on the default list: no shared suite.
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .client_suites = &.{.aes_128_ccm_sha256} }));
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .client_suites = &.{.ecdhe_ecdsa_aes_128_ccm}, .client_max = .tls12 }));
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .client_suites = &.{.ecdhe_ecdsa_aes_128_ccm_8}, .client_max = .tls12 }));
    // Nor is CCM a suite for an RSA certificate.
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .cert = .rsa, .client_suites = &.{.ecdhe_ecdsa_aes_256_ccm}, .server_suites = &.{.ecdhe_ecdsa_aes_256_ccm}, .client_max = .tls12 }));
}

test "C8 a CCM key protects at most 2^23 records, half GCM's" {
    const secret: [32]u8 = @splat(7);
    var ccm: Protection = undefined;
    try ccm.init(.aes_128_ccm_sha256, &secret, .{});
    defer ccm.deinit();
    try std.testing.expectEqual(@as(u64, 1 << 23), ccm.remaining().records);
    var gcm: Protection = undefined;
    try gcm.init(.aes_128_gcm_sha256, &secret, .{});
    defer gcm.deinit();
    try std.testing.expectEqual(@as(u64, 1 << 24), gcm.remaining().records);
    var ccm12: Protection = undefined;
    try ccm12.init12(.aes_256_ccm, &@as([32]u8, @splat(1)), &@as([4]u8, @splat(2)), .{});
    defer ccm12.deinit();
    try std.testing.expectEqual(@as(u64, 1 << 23), ccm12.remaining().records);
    // A lower bound of the caller's still holds.
    var low: Protection = undefined;
    try low.init(.aes_128_ccm_sha256, &secret, .{ .records = 5 });
    defer low.deinit();
    try std.testing.expectEqual(@as(u64, 5), low.remaining().records);
}
