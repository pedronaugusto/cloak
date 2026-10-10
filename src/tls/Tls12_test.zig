//! TLS 1.2, both roles, a cloak client against a cloak server.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Suite = @import("crypto/Suite.zig").Suite;

const ecdsa_suites = [_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256 };

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(std.testing.allocator, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C4 TLS 1.2 completes for every ECDSA suite, group and certificate key, both ways" {
    for (ecdsa_suites) |suite| {
        for ([_]Duo.Cert{ .p256, .p384, .ed25519 }) |cert| {
            for ([_]@import("crypto/Group.zig").Group{ .x25519, .p256, .p384 }) |group| {
                // A TLS 1.2-only client against a server choosing `group`; the client also lists the
                // certificate's curve, as RFC 8422 requires for an ECDSA certificate.
                const curve: @import("crypto/Group.zig").Group = if (cert == .p384) .p384 else .p256;
                const offered = [_]@import("crypto/Group.zig").Group{ group, curve };
                const duo = try connect(.{ .cert = cert, .client_suites = &.{suite}, .client_max = .tls12, .client_groups = if (group == curve) offered[0..1] else &offered, .server_groups = &.{group} });
                defer duo.deinit();
                const info = duo.client.info().?;
                try std.testing.expectEqual(.tls12, info.version);
                try std.testing.expectEqual(suite, info.suite);
                try std.testing.expectEqual(group, info.group);
                try std.testing.expect(info.peer_authenticated);
                try std.testing.expectEqual(info.suite, duo.server.info().?.suite);
                var out: [64]u8 = undefined;
                try std.testing.expectEqualSlices(u8, "ping", try duo.echo(&duo.client, &duo.server, "ping", &out));
                try std.testing.expectEqualSlices(u8, "pong", try duo.echo(&duo.server, &duo.client, "pong", &out));
                var a: [32]u8 = undefined;
                var b: [32]u8 = undefined;
                try duo.client.exportKeyingMaterial(&a, "EXPORTER-test", "ctx");
                try duo.server.exportKeyingMaterial(&b, "EXPORTER-test", "ctx");
                try std.testing.expectEqualSlices(u8, &a, &b);
            }
        }
    }
}

const rsa_suites = [_]Suite{ .ecdhe_rsa_aes_128_gcm_sha256, .ecdhe_rsa_aes_256_gcm_sha384, .ecdhe_rsa_chacha20_poly1305_sha256 };

test "C4 TLS 1.2 RSA suites sign the key exchange with an RSA certificate" {
    for (rsa_suites) |suite| {
        const duo = try connect(.{ .cert = .rsa, .client_suites = &.{suite}, .client_max = .tls12, .client_groups = &.{.x25519} });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expectEqual(suite, info.suite);
        try std.testing.expect(info.peer_authenticated);
    }
    // An ECDSA suite cannot be served from an RSA certificate.
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .cert = .rsa, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_max = .tls12 }));
}

test "C4 TLS 1.2 client certificates: required, optional and missing" {
    for ([_]@import("handshake/State.zig").Auth{ .optional, .required }) |auth| {
        const duo = try connect(.{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_auth = auth, .client_cert = true });
        defer duo.deinit();
        try std.testing.expect(duo.server.info().?.peer_authenticated);
        try std.testing.expect(duo.client.certificateRequested());
    }
    const optional = try connect(.{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_auth = .optional });
    defer optional.deinit();
    try std.testing.expect(!optional.server.info().?.peer_authenticated);
    // TLS 1.2 has no certificate_required alert: handshake_failure.
    {
        const duo = try Duo.init(std.testing.allocator, .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_auth = .required });
        defer duo.deinit();
        try std.testing.expectError(error.NoClientCertificate, duo.handshake());
        try std.testing.expectEqual(.handshake_failure, duo.server.diagnostics().alert_sent.?);
    }
}

test "C4 a client of both versions takes TLS 1.2 from a TLS 1.2 server, and TLS 1.3 otherwise" {
    const old = try connect(.{ .server_max = .tls12 });
    defer old.deinit();
    try std.testing.expectEqual(.tls12, old.client.info().?.version);
    const both = try connect(.{});
    defer both.deinit();
    try std.testing.expectEqual(.tls13, both.client.info().?.version);
    // A client that refuses TLS 1.2 meets a TLS 1.2-only server: protocol_version.
    try std.testing.expectError(error.UnsupportedVersion, connect(.{ .client_min = .tls13, .client_suites = Suite.tls13_only, .server_max = .tls12 }));
    // A TLS 1.2-only client meets a TLS 1.3-only server.
    try std.testing.expectError(error.UnsupportedVersion, connect(.{ .client_max = .tls12, .server_min = .tls13, .server_suites = Suite.tls13_only }));
}

test "C4 TLS 1.2 records survive one-byte delivery" {
    const duo = try connect(.{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_chacha20_poly1305_sha256}, .chunk = 1 });
    defer duo.deinit();
    var out: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "byte by byte", try duo.echo(&duo.client, &duo.server, "byte by byte", &out));
}

/// The records in `bytes`, one per entry.
fn records(bytes: []const u8, out: [][]const u8) usize {
    var count: usize = 0;
    var at: usize = 0;
    while (at + 5 <= bytes.len and count < out.len) {
        const len = 5 + @as(usize, std.mem.readInt(u16, bytes[at + 3 ..][0..2], .big));
        out[count] = bytes[at..][0..len];
        count += 1;
        at += len;
    }
    return count;
}

/// The state table refuses the record (unexpected_message), whichever layer saw it first.
fn refused(result: anytype) !void {
    if (result) |_| return error.TestExpectedError else |err| switch (err) {
        error.UnexpectedMessage, error.UnexpectedRecord => {},
        else => return err,
    }
}

test "F46 catalogue_ccs_injection_all_reachable_states" {
    // A ChangeCipherSpec before the keys are agreed is refused wherever it lands.
    for (1..4) |cut| {
        const duo = try Duo.init(std.testing.allocator, .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
        defer duo.deinit();
        try duo.handshakeUntilServerFlight();
        var cut_records: [8][]const u8 = undefined;
        const n = records(duo.server.output(), &cut_records);
        try std.testing.expect(n >= 4);
        for (cut_records[0..cut]) |record| _ = try duo.client.receive(record);
        try duo.serveClient();
        try refused(duo.client.receive("\x14\x03\x03\x00\x01\x01"));
        try std.testing.expectEqual(.unexpected_message, duo.client.diagnostics().alert_sent.?);
    }
    // At the server, before the client's key exchange.
    const duo = try Duo.init(std.testing.allocator, .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer duo.deinit();
    try duo.handshakeUntilServerFlight();
    try refused(duo.server.receive("\x14\x03\x03\x00\x01\x01"));
    try std.testing.expectEqual(.unexpected_message, duo.server.diagnostics().alert_sent.?);
}

test "C4 an ECDSA certificate on a curve the client does not list is not served (RFC 8422)" {
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .cert = .p256, .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_groups = &.{ .x25519, .p384 } }));
    // A server of only TLS 1.2 suites needs no max_version: the version follows from the suites.
    const duo = try connect(.{ .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer duo.deinit();
    try std.testing.expectEqual(.tls12, duo.client.info().?.version);
}

test "C4 a refusal in a TLS 1.0 record reaches the client as the peer's alert" {
    const duo = try Duo.init(std.testing.allocator, .{ .client_min = .tls13, .client_suites = Suite.tls13_only });
    defer duo.deinit();
    try duo.serveClient();
    try std.testing.expect(duo.client.output().len != 0);
    try std.testing.expectError(error.PeerAlert, duo.client.receive("\x15\x03\x01\x00\x02\x02\x46"));
    try std.testing.expectEqual(.protocol_version, duo.client.diagnostics().alert_received.?);
}
