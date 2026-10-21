//! certificate_authorities (RFC 8446 section 4.2.4; RFC 5246 section 7.4.4) between a cloak
//! client and a cloak server: the names each end sends, and each end's credential choice taking
//! them as a preference, never a refusal.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const certificates = @import("../certificates.zig");
const Authorities = @import("handshake/Authorities.zig");
const ClientHello = @import("handshake/ClientHello.zig");
const Connection = @import("Connection.zig");

const gpa = std.testing.allocator;
const pki = Duo.pki;

fn subject(der: []const u8) []const u8 {
    return (certificates.certificate.parse(der, .{}) catch unreachable).subject; // unreachable: test PKI
}

fn digest(der: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(der, &out, .{});
    return out;
}

test "F139 catalogue_server_credential_by_named_authority (the server answers with the first credential the client can take that chains to an authority it names, else the first it can take)" {
    const Case = struct { names: []const []const u8, server_max: @import("crypto/Suite.zig").Version = .tls13, leaf: []const u8, index: u8 };
    const ct = subject(pki.ct_ca);
    const test_root = subject(pki.ca);
    const elsewhere = subject(pki.mldsa_ca);
    for ([_]Case{
        // No names: the server's order.
        .{ .names = &.{}, .leaf = pki.p256, .index = 0 },
        // The second chains to the named root; so in TLS 1.2, from the same hello.
        .{ .names = &.{ct}, .leaf = pki.ct_plain, .index = 1 },
        .{ .names = &.{ct}, .server_max = .tls12, .leaf = pki.ct_plain, .index = 1 },
        // Both named: the server's order among them.
        .{ .names = &.{ ct, test_root }, .leaf = pki.p256, .index = 0 },
        // None chains to a name: a preference, never a refusal.
        .{ .names = &.{elsewhere}, .leaf = pki.p256, .index = 0 },
    }) |case| {
        const duo = try Duo.init(gpa, .{ .cert = .p256, .server_also = &.{.ct_plain}, .client_authorities = case.names, .server_max = case.server_max });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(digest(case.leaf), duo.peer_leaf[0]);
        // Each end reports what it presented: the server its choice, the client, not asked, none.
        try std.testing.expectEqual(@as(?u8, case.index), duo.server.info().?.credential);
        try std.testing.expectEqual(@as(?u8, null), duo.client.info().?.credential);
    }
}

test "F140 catalogue_client_credential_by_named_authority (the client answers with the first credential the request takes that chains to an authority it names, else the first it takes)" {
    const Case = struct { names: []const []const u8, client_max: @import("crypto/Suite.zig").Version = .tls13, leaf: []const u8, index: u8 };
    const dc = subject(pki.dc_ca);
    const elsewhere = subject(pki.mldsa_ca);
    for ([_]Case{
        .{ .names = &.{}, .leaf = pki.client, .index = 0 },
        .{ .names = &.{dc}, .leaf = pki.dc_client, .index = 1 },
        .{ .names = &.{dc}, .client_max = .tls12, .leaf = pki.dc_client, .index = 1 },
        .{ .names = &.{elsewhere}, .leaf = pki.client, .index = 0 },
    }) |case| {
        const duo = try Duo.init(gpa, .{ .client_cert = true, .client_second = true, .client_auth = .required, .server_authorities = case.names, .client_max = case.client_max });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expect(duo.server.info().?.peer_authenticated);
        try std.testing.expectEqual(digest(case.leaf), duo.peer_leaf[1]);
        try std.testing.expectEqual(@as(?u8, case.index), duo.client.info().?.credential);
        try std.testing.expectEqual(@as(?u8, 0), duo.server.info().?.credential);
    }
    // Asked and holding none: an empty Certificate presents no credential, in either version.
    for ([_]@import("crypto/Suite.zig").Version{ .tls13, .tls12 }) |version| {
        const duo = try Duo.init(gpa, .{ .client_auth = .optional, .client_max = version });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expect(!duo.server.info().?.peer_authenticated);
        try std.testing.expectEqual(@as(?u8, null), duo.client.info().?.credential);
    }
    // After the handshake (RFC 8446 section 4.6.2): each request is answered by its names.
    const duo = try Duo.init(gpa, .{ .client_cert = true, .client_second = true, .client_post_auth = true, .server_post_auth = true, .server_authorities = &.{dc} });
    defer duo.deinit();
    try duo.handshake();
    _ = try duo.server.requestCertificate();
    try duo.pump();
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = true }, duo.server.postAuthentication().?);
    try std.testing.expectEqual(digest(pki.dc_client), duo.peer_leaf[1]);
    // `Info.credential` is the handshake's: a post-handshake answer leaves it.
    try std.testing.expectEqual(@as(?u8, null), duo.client.info().?.credential);
}

test "C7 certificate_authorities is sent only when listed, bounded, and only where TLS 1.3 is offered" {
    const names: []const []const u8 = &.{subject(pki.ca)};
    {
        const duo = try Duo.init(gpa, .{ .client_authorities = names });
        defer duo.deinit();
        try duo.serveClient();
        const hello = try ClientHello.parse(duo.client.output()[5..], .stream);
        var expected: [512]u8 = undefined;
        std.mem.writeInt(u16, expected[0..2], @intCast(names[0].len), .big);
        @memcpy(expected[2..][0..names[0].len], names[0]);
        try std.testing.expectEqualSlices(u8, expected[0 .. 2 + names[0].len], hello.authorities.?);
    }
    {
        const duo = try Duo.init(gpa, .{});
        defer duo.deinit();
        try duo.serveClient();
        try std.testing.expectEqual(@as(?[]const u8, null), (try ClientHello.parse(duo.client.output()[5..], .stream)).authorities);
    }
    // A TLS 1.2-only hello has no such extension; a name that is no DER Name, or names past the
    // bound, are configuration errors; so are names at a server that never asks for a certificate.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_authorities = names, .client_max = .tls12 }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_authorities = &.{"\x30\x01"} }));
    const many: [Authorities.max_bytes / 8][]const u8 = @splat(subject(pki.ca));
    try std.testing.expect(Authorities.wireLength(&many) > Authorities.max_bytes);
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_authorities = &many }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_authorities = names }));
}

test "C7 a client's credentials are at most 32, of either form or both" {
    const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
    defer key.deinit();
    const chain = try certificates.ClientAuth.init(gpa, &.{ pki.client, pki.ca }, key, .{});
    defer chain.deinit();
    const too_many: [33]Connection.ClientCredential = @splat(.{ .auth = chain });
    try std.testing.expectError(error.InvalidOptions, Connection.client(gpa, .{ .identity = .{ .dns = "example.com" }, .verify = .none, .credentials = &too_many }));
    var fine = try Connection.client(gpa, .{ .identity = .{ .dns = "example.com" }, .verify = .none, .credentials = too_many[0..32] });
    fine.deinit();
    // Both forms (RFC 7250): client_certificate_type lists them as they first appear, and the
    // client presents the first credential of the type the server selected, each version.
    const pins = [_][32]u8{Duo.pinOf(pki.client)};
    const Case = struct { raw_first: bool, server_pins: bool, index: u8 };
    for ([_]@import("crypto/Suite.zig").Version{ .tls13, .tls12 }) |version| {
        for ([_]Case{
            .{ .raw_first = true, .server_pins = true, .index = 0 },
            .{ .raw_first = true, .server_pins = false, .index = 1 },
            .{ .raw_first = false, .server_pins = true, .index = 1 },
            .{ .raw_first = false, .server_pins = false, .index = 0 },
        }) |case| {
            const duo = try Duo.init(gpa, .{ .client_cert = true, .client_raw = case.raw_first, .client_second = true, .client_second_raw = !case.raw_first, .client_auth = .required, .server_raw_pins = if (case.server_pins) &pins else null, .client_max = version });
            defer duo.deinit();
            try duo.handshake();
            const server = duo.server.info().?;
            try std.testing.expect(server.peer_authenticated);
            try std.testing.expectEqual(@as(?u16, if (case.server_pins) 0 else null), server.pin);
            try std.testing.expectEqual(@as(?u8, case.index), duo.client.info().?.credential);
        }
    }
}
