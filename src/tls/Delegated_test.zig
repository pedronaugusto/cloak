//! Delegated credentials (RFC 9345) end to end, cloak client against cloak server: the server's,
//! the client's, the fallback to the certificate's key, and resumption bounded by the credential.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Duo = @import("../testing/Duo.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const pki = Duo.pki;
const gpa = std.testing.allocator;

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

fn exportsMatch(duo: *Duo) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try duo.client.exportKeyingMaterial(&a, "cloak dc", "");
    try duo.server.exportKeyingMaterial(&b, "cloak dc", "");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "C10 delegated credentials: a server proves possession with its credential's key" {
    const duo = try connect(.{ .server_delegated = true, .client_accept_delegated = true });
    defer duo.deinit();
    const info = duo.client.info().?;
    try std.testing.expect(info.peer_authenticated and info.delegated_credential);
    try std.testing.expectEqual(.tls13, info.version);
    try exportsMatch(duo);
    var out: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "dc", try duo.echo(&duo.client, &duo.server, "dc", &out));
}

test "C10 delegated credentials: the certificate's key signs for a client that does not take one, or once it is not valid" {
    inline for (.{
        Duo.Options{ .server_delegated = true },
        // Expired, or more than seven days left to run: the server keeps it back.
        Duo.Options{ .server_delegated = true, .client_accept_delegated = true, .delegated_issued = pki.time - 4 * 24 * 60 * 60 },
        Duo.Options{ .server_delegated = true, .client_accept_delegated = true, .delegated_lifetime = 8 * 24 * 60 * 60 },
        // TLS 1.2 has none (RFC 9345 section 4.1.1).
        Duo.Options{ .server_delegated = true, .client_max = .tls12 },
    }) |options| {
        const duo = try connect(options);
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expect(info.peer_authenticated and !info.delegated_credential);
    }
}

test "C10 delegated credentials: a client authenticates with its credential, both ends delegating" {
    for ([_]@import("handshake/Server.zig").Auth{ .required, .optional }) |auth| {
        const duo = try connect(.{ .client_auth = auth, .client_cert = true, .client_delegated = true, .server_accept_delegated = true, .server_delegated = true, .client_accept_delegated = true });
        defer duo.deinit();
        const server = duo.server.info().?;
        try std.testing.expect(server.peer_authenticated and server.delegated_credential);
        try std.testing.expect(duo.client.info().?.delegated_credential);
        try exportsMatch(duo);
    }
    // A server that does not take one gets the certificate's own signature.
    const duo = try connect(.{ .client_auth = .required, .client_cert = true, .client_delegated = true });
    defer duo.deinit();
    const server = duo.server.info().?;
    try std.testing.expect(server.peer_authenticated and !server.delegated_credential);
}

test "C10 delegated credentials: options that cannot hold one are refused" {
    // Taking one needs full verification and TLS 1.3.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_accept_delegated = true, .client_verify_none = true }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_accept_delegated = true, .client_max = .tls12 }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_accept_delegated = true }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_accept_delegated = true, .client_auth = .required, .server_max = .tls12 }));
    // A client's own needs its certificate and full verification of the server.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_cert = true, .client_delegated = true, .client_verify_none = true }));
}

test "F89 catalogue_delegated_parent_expiry_and_raw_key_namespace (delegation: resumption ends with the credential)" {
    const hour = 60 * 60;
    // The server's credential bounds the client's tickets; the client's bounds the server's.
    const cases = [_]Duo.Options{
        .{ .server_delegated = true, .client_accept_delegated = true, .delegated_lifetime = 2 * hour },
        .{ .client_auth = .required, .client_cert = true, .client_delegated = true, .server_accept_delegated = true, .delegated_lifetime = 2 * hour },
    };
    for (cases) |case| {
        var cache = try SessionCache.init(gpa, .{});
        defer cache.deinit();
        var ring = try TicketKeys.init(gpa, .{});
        defer ring.deinit();
        try ring.rotate(&@as([32]u8, @splat(0x77)), certificates.types.instant(pki.time));
        var options = case;
        options.cache = &cache;
        options.tickets = &ring;
        {
            const duo = try connect(options);
            defer duo.deinit();
            try std.testing.expect(duo.client.info().?.delegated_credential or duo.server.info().?.delegated_credential);
        }
        {
            // Within the credential's life a ticket resumes.
            var later = options;
            later.time = pki.time + hour;
            const duo = try connect(later);
            defer duo.deinit();
            try std.testing.expect(duo.client.info().?.resumed and duo.server.info().?.resumed);
        }
        {
            // Past it none does, though the certificates and the tickets would still run.
            var later = options;
            later.time = pki.time + 3 * hour;
            later.delegated_issued = pki.time + 3 * hour - 60;
            const duo = try connect(later);
            defer duo.deinit();
            try std.testing.expect(!duo.client.info().?.resumed and !duo.server.info().?.resumed);
        }
    }
}

test "C10 delegated credentials: a credential that signs only through its delegated credential is offered only to a client that takes it" {
    // RFC 9345's server that never holds the certificate's key: without a delegated credential
    // the client can take, the credential is passed over for the next.
    {
        const duo = try connect(.{ .server_delegated = true, .server_delegated_only = true, .client_accept_delegated = true, .server_also = &.{.p256} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.delegated_credential);
        try std.testing.expectEqual(@as(?u8, 0), duo.server.info().?.credential);
    }
    for ([_]Duo.Options{
        .{ .server_delegated = true, .server_delegated_only = true, .server_also = &.{.p256} },
        .{ .server_delegated = true, .server_delegated_only = true, .client_accept_delegated = true, .server_max = .tls12, .server_also = &.{.p256} },
    }) |options| {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.delegated_credential);
        try std.testing.expectEqual(@as(?u8, 1), duo.server.info().?.credential);
    }
    // Alone, it answers no such client: the handshake fails rather than sign with the certificate's key.
    const alone = try Duo.init(gpa, .{ .server_delegated = true, .server_delegated_only = true });
    defer alone.deinit();
    try std.testing.expectError(error.NoSignatureScheme, alone.handshake());
    // A credential with no delegated credential to sign with is refused.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_delegated_only = true }));
}
