//! Provisioned PSKs (PSK-DHE) end to end, cloak client against cloak server, and the failure
//! catalogue's rows for them (F85, F86).
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Psk = @import("handshake/Psk.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const types = @import("../certificates.zig").types;
const Alert = @import("wire/Alert.zig").Alert;
const Schedule = @import("handshake/Schedule.zig").Schedule;
const gpa = std.testing.allocator;

const key256: [32]u8 = @splat(0x42);
const key384: [48]u8 = @splat(0x43);

/// A server's table: entries matched by exact identity, each optionally bound to a server name
/// and an application protocol.
const Table = struct {
    entries: []const Entry,
    queries: usize = 0,

    const Entry = struct { psk: Psk.External, server_name: ?[]const u8 = null, alpn: ?[]const u8 = null };

    fn find(context: ?*anyopaque, query: Psk.Query) ?Psk.External {
        const self: *Table = @ptrCast(@alignCast(context.?));
        self.queries += 1;
        for (self.entries) |entry| {
            if (!std.mem.eql(u8, entry.psk.identity, query.identity)) continue;
            if (entry.server_name) |name| if (!std.ascii.eqlIgnoreCase(name, query.server_name)) continue;
            if (entry.alpn) |alpn| if (!std.mem.eql(u8, alpn, query.alpn)) continue;
            return entry.psk;
        }
        return null;
    }

    fn lookup(self: *Table) Psk.Lookup {
        return .{ .context = self, .find = find };
    }
};

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

fn exportsMatch(duo: *Duo) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try duo.client.exportKeyingMaterial(&a, "cloak psk", "");
    try duo.server.exportKeyingMaterial(&b, "cloak psk", "");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "C10 a provisioned key authenticates both ends with no certificate, each hash and suite" {
    const cases = [_]struct { psk: Psk.External, suite: Suite }{
        .{ .psk = .{ .identity = "device-7", .secret = &key256 }, .suite = .aes_128_gcm_sha256 },
        .{ .psk = .{ .identity = "device-7", .secret = &key256 }, .suite = .chacha20_poly1305_sha256 },
        .{ .psk = .{ .identity = "device-8", .secret = &key384, .hash = .sha384 }, .suite = .aes_256_gcm_sha384 },
    };
    for (cases) |case| {
        var table: Table = .{ .entries = &.{.{ .psk = case.psk }} };
        const duo = try connect(.{ .client_suites = &.{case.suite}, .client_psks = &.{case.psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        const client = duo.client.info().?;
        const server = duo.server.info().?;
        try std.testing.expect((client.external_psk != null) and (server.external_psk != null));
        try std.testing.expect(client.peer_authenticated and server.peer_authenticated);
        try std.testing.expect(!client.resumed);
        // The server asked nobody to verify anything: no certificate went either way.
        try std.testing.expect(!duo.client.certificateRequested());
        try std.testing.expect(client.credential == null and server.credential == null);
        try exportsMatch(duo);
        var out: [8]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "psk", try duo.echo(&duo.client, &duo.server, "psk", &out));
    }
}

test "C10 a provisioned key across a retry request, with an unverifying client, and over a fallback" {
    const psk: Psk.External = .{ .identity = "device-9", .secret = &key256 };
    var table: Table = .{ .entries = &.{.{ .psk = psk }} };
    {
        const duo = try connect(.{ .server_groups = &.{.p256}, .client_psks = &.{psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect((duo.client.info().?.external_psk != null) and duo.client.info().?.group == .p256);
    }
    // The key authenticates the server whatever the certificate policy.
    {
        const duo = try connect(.{ .client_verify_none = true, .client_psks = &.{psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.peer_authenticated);
    }
    // A server without provisioned keys does a full handshake, authenticated by its certificate.
    {
        const duo = try connect(.{ .client_psks = &.{psk} });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expect((info.external_psk == null) and info.peer_authenticated);
        try std.testing.expect(!duo.server.info().?.peer_authenticated);
    }
    // A SHA-384 key needs a SHA-384 suite offered; a server that picks another suite cannot use it.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_suites = &.{.aes_128_gcm_sha256}, .client_psks = &.{.{ .identity = "x", .secret = &key384, .hash = .sha384 }} }));
    {
        const psk384: Psk.External = .{ .identity = "device-10", .secret = &key384, .hash = .sha384 };
        var table384: Table = .{ .entries = &.{.{ .psk = psk384 }} };
        const duo = try connect(.{ .client_psks = &.{psk384}, .server_suites = &.{ .aes_128_gcm_sha256, .aes_256_gcm_sha384 }, .server_psk = table384.lookup() });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.external_psk == null);
    }
}

test "C10 a wrong key is fatal (decrypt_error), and a session on a key gets no tickets" {
    const other: [32]u8 = @splat(0x24);
    var table: Table = .{ .entries = &.{.{ .psk = .{ .identity = "device-7", .secret = &other } }} };
    {
        const duo = try Duo.init(gpa, .{ .client_psks = &.{.{ .identity = "device-7", .secret = &key256 }}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expectError(error.BadBinder, duo.handshake());
        try std.testing.expectEqual(.decrypt_error, duo.server.diagnostics().alert_sent.?);
    }
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x55)), types.instant(Duo.pki.time));
    var right: Table = .{ .entries = &.{.{ .psk = .{ .identity = "device-7", .secret = &key256 } }} };
    const duo = try connect(.{ .cache = &cache, .tickets = &keys, .client_psks = &.{.{ .identity = "device-7", .secret = &key256 }}, .server_psk = right.lookup() });
    defer duo.deinit();
    try std.testing.expect(duo.client.info().?.external_psk != null);
    try std.testing.expectEqual(0, cache.count());
    // Invalid keys never leave the client: empty, oversized or all-zero.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_psks = &.{.{ .identity = "", .secret = &key256 }} }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_psks = &.{.{ .identity = "x", .secret = key256[0..31] }} }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_psks = &.{.{ .identity = "x", .secret = &@as([32]u8, @splat(0)) }} }));
}

test "F86 catalogue_external_psk_embedded_nul_identity" {
    // The server knows "user"; identities that only begin with it, or differ by a terminator,
    // are other identities: no key, a full handshake, and never "user" authenticated.
    var table: Table = .{ .entries = &.{.{ .psk = .{ .identity = "user", .secret = &key256 } }} };
    for ([_][]const u8{ "user\x00admin", "user\x00", "use", "USER", "user " }) |identity| {
        const duo = try connect(.{ .client_psks = &.{.{ .identity = identity, .secret = &key256 }}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect((duo.server.info().?.external_psk == null) and !duo.server.info().?.peer_authenticated);
    }
    // A lookup that answers with another identity than the one asked is not believed.
    const Lying = struct {
        fn find(_: ?*anyopaque, _: Psk.Query) ?Psk.External {
            return .{ .identity = "user", .secret = &key256 };
        }
    };
    {
        const duo = try connect(.{ .client_psks = &.{.{ .identity = "user\x00admin", .secret = &key256 }}, .server_psk = .{ .find = Lying.find } });
        defer duo.deinit();
        try std.testing.expect(duo.server.info().?.external_psk == null);
    }
    const duo = try connect(.{ .client_psks = &.{.{ .identity = "user", .secret = &key256 }}, .server_psk = table.lookup() });
    defer duo.deinit();
    try std.testing.expect(duo.server.info().?.external_psk != null);
}

test "F85 catalogue_selfie_psk_role_reflection_and_context" {
    // A key is bound by the caller's lookup to the endpoint and application it was provisioned
    // for: offered for another server name or protocol, it is not found.
    const psk: Psk.External = .{ .identity = "svc", .secret = &key256 };
    var table: Table = .{ .entries = &.{.{ .psk = psk, .server_name = "example.com", .alpn = "h2" }} };
    {
        const duo = try connect(.{ .client_alpn = &.{"h2"}, .server_alpn = &.{ "h2", "http/1.1" }, .client_psks = &.{psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect(duo.server.info().?.external_psk != null);
    }
    {
        const duo = try connect(.{ .client_alpn = &.{"http/1.1"}, .server_alpn = &.{ "h2", "http/1.1" }, .client_psks = &.{psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect(duo.server.info().?.external_psk == null);
    }
    // A ticket's binder key and a provisioned key's differ ("res binder", "ext binder"): a
    // provisioned secret offered with a resumption binder never authenticates. Checked at the
    // schedule: the same secret and transcript give different binders.
    const K = @import("handshake/Schedule.zig").Schedule(.aes_128_gcm_sha256);
    const transcript: [32]u8 = @splat(1);
    var res: [32]u8 = undefined;
    var ext: [32]u8 = undefined;
    K.binderOf(.tls13, .resumption, &key256, &transcript, &res);
    K.binderOf(.tls13, .external, &key256, &transcript, &ext);
    try std.testing.expect(!std.mem.eql(u8, &res, &ext));
    try std.testing.expectError(error.BadBinder, K.checkBinderOf(.tls13, .external, &key256, &transcript, &res));
    // Reflection (an endpoint that is both client and server answering its own hello) needs the
    // same key provisioned for both roles: that is the caller's to avoid (RFC 9257 section 4.1),
    // and a server's lookup is a separate table from any client's key.
}

test "C10 a PSK-only server needs no credential, and a key decides before any credential is chosen" {
    const psk: Psk.External = .{ .identity = "device-11", .secret = &key256 };
    var table: Table = .{ .entries = &.{.{ .psk = psk }} };
    {
        const duo = try connect(.{ .server_psk_only = true, .client_verify_none = true, .client_psks = &.{psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect((duo.client.info().?.external_psk != null) and (duo.server.info().?.external_psk != null));
        try exportsMatch(duo);
    }
    // A client that takes only a raw key, against a server holding only X.509: the key it
    // offers authenticates both ends, so no credential form is ever asked of the server.
    {
        const pins = [_][32]u8{@splat(0x77)};
        const duo = try connect(.{ .client_raw_pins = &pins, .client_psks = &.{psk}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expect((duo.client.info().?.external_psk != null) and duo.client.info().?.peer_authenticated);
    }
    // Offered no key it knows, a server without credentials has nothing to authenticate with.
    {
        const duo = try Duo.init(gpa, .{ .server_psk_only = true, .client_verify_none = true, .client_psks = &.{.{ .identity = "stranger", .secret = &key256 }}, .server_psk = table.lookup() });
        defer duo.deinit();
        try std.testing.expectError(error.PskRequired, duo.handshake());
        try std.testing.expectEqual(.handshake_failure, duo.server.diagnostics().alert_sent.?);
    }
    // No credential and no lookup is no server at all.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_psk_only = true }));
}

/// The client's hello with signature_algorithms (13) renamed to an unassigned ID (0x4242) and its
/// one SHA-256 binder, the hello's last 32 bytes, made again under `key256` for the edited bytes.
fn dropSchemes(bytes: []u8) void {
    const message = bytes[5..][0..std.mem.readInt(u16, bytes[3..5], .big)];
    var at: usize = 4 + 2 + 32;
    at += 1 + message[at];
    at += 2 + std.mem.readInt(u16, message[at..][0..2], .big);
    at += 1 + message[at];
    const end = at + 2 + std.mem.readInt(u16, message[at..][0..2], .big);
    at += 2;
    while (at < end) {
        const id = std.mem.readInt(u16, message[at..][0..2], .big);
        if (id == 13) std.mem.writeInt(u16, message[at..][0..2], 0x4242, .big);
        at += 4 + std.mem.readInt(u16, message[at + 2 ..][0..2], .big);
    }
    var truncated: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(message[0 .. message.len - 35], &truncated, .{});
    Schedule(.aes_128_gcm_sha256).binderOf(.tls13, .external, &key256, &truncated, message[message.len - 32 ..][0..32]);
}

test "F106 catalogue_psk_hello_without_signature_algorithms (a hello with a provisioned key needs no signature_algorithms unless the server signs)" {
    // RFC 8446 section 9.2: only a hello without pre_shared_key must carry signature_algorithms;
    // section 4.2.3: a server authenticating by certificate without them ends with
    // missing_extension (tlsfuzzer's test-tls13-psk_dhe_ke sends none).
    var table: Table = .{ .entries = &.{.{ .psk = .{ .identity = "device-7", .secret = &key256 } }} };
    {
        const duo = try Duo.init(gpa, .{ .client_suites = &.{.aes_128_gcm_sha256}, .client_psks = &.{.{ .identity = "device-7", .secret = &key256 }}, .server_psk = table.lookup() });
        defer duo.deinit();
        try duo.deliverEdited(dropSchemes);
        try std.testing.expect(duo.server.output().len != 0);
        try std.testing.expectEqual(@as(?Alert, null), duo.server.diagnostics().alert_sent);
    }
    // A key the server does not know leaves certificates, which need the schemes.
    var empty: Table = .{ .entries = &.{} };
    const duo = try Duo.init(gpa, .{ .client_suites = &.{.aes_128_gcm_sha256}, .client_psks = &.{.{ .identity = "device-7", .secret = &key256 }}, .server_psk = empty.lookup() });
    defer duo.deinit();
    try std.testing.expectError(error.MissingExtension, duo.deliverEdited(dropSchemes));
    try std.testing.expectEqual(Alert.missing_extension, duo.server.diagnostics().alert_sent.?);
}
