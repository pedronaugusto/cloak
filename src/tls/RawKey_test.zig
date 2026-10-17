//! Raw public keys (RFC 7250) end to end, cloak client against cloak server and against the
//! scripted server, and the failure catalogue's raw-key half of F89.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Duo = @import("../testing/Duo.zig");
const Pair = @import("../testing/Pair.zig").Pair;
const Client = @import("handshake/Client.zig");
const Hello = @import("handshake/Hello.zig");
const Ech = @import("handshake/Ech.zig");
const Hpke = @import("crypto/Hpke.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const pki = Duo.pki;
const gpa = std.testing.allocator;

const other: [32]u8 = @splat(0x5a);

fn leafOf(cert: Duo.Cert) []const u8 {
    return switch (cert) {
        .p256 => pki.p256,
        .p384 => pki.p384,
        .ed25519 => pki.ed25519,
        .rsa => pki.rsa,
        .mldsa65 => pki.mldsa65,
        else => unreachable, // unreachable: the cases below
    };
}

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

fn exportsMatch(duo: *Duo) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try duo.client.exportKeyingMaterial(&a, "cloak raw", "");
    try duo.server.exportKeyingMaterial(&b, "cloak raw", "");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "C10 raw public keys: a client trusts the server's pinned key, every key type, no certificate" {
    for ([_]Duo.Cert{ .p256, .p384, .ed25519, .rsa, .mldsa65 }) |cert| {
        const pins = [_][32]u8{ other, Duo.pinOf(leafOf(cert)) };
        // Nothing to verify against: no identity, and the trust store is never asked.
        const duo = try connect(.{ .cert = cert, .server_raw = .only, .client_raw_pins = &pins, .identity = "unrelated.example" });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expect(info.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 1), info.raw_key_pin);
        try std.testing.expectEqual(.tls13, info.version);
        try std.testing.expectEqual(@as(?u16, null), duo.server.info().?.raw_key_pin);
        try exportsMatch(duo);
        var out: [8]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "raw", try duo.echo(&duo.client, &duo.server, "raw", &out));
    }
}

test "C10 raw public keys: a server holding both forms presents what each client takes" {
    const pins = [_][32]u8{Duo.pinOf(pki.p256)};
    {
        const duo = try connect(.{ .server_raw = .both, .client_raw_pins = &pins });
        defer duo.deinit();
        try std.testing.expectEqual(@as(?u16, 0), duo.client.info().?.raw_key_pin);
    }
    {
        // A client that did not ask gets the certificate, verified as ever, TLS 1.2 included.
        const duo = try connect(.{ .server_raw = .both });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expect(info.peer_authenticated and info.raw_key_pin == null);
    }
    {
        const duo = try connect(.{ .server_raw = .both, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectEqual(.tls12, duo.client.info().?.version);
    }
}

test "C10 raw public keys: client authentication by a pinned key, required and optional" {
    const pins = [_][32]u8{ other, other, Duo.pinOf(pki.client) };
    for ([_]@import("handshake/Server.zig").Auth{ .required, .optional }) |auth| {
        const duo = try connect(.{ .client_auth = auth, .client_cert = true, .client_raw = true, .server_raw_pins = &pins });
        defer duo.deinit();
        const server = duo.server.info().?;
        try std.testing.expect(server.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 2), server.raw_key_pin);
        try std.testing.expect(duo.client.info().?.raw_key_pin == null);
    }
    // Both ways at once.
    const server_pins = [_][32]u8{Duo.pinOf(pki.p256)};
    const duo = try connect(.{ .server_raw = .only, .client_raw_pins = &server_pins, .client_auth = .required, .client_cert = true, .client_raw = true, .server_raw_pins = &pins });
    defer duo.deinit();
    try std.testing.expectEqual(@as(?u16, 0), duo.client.info().?.raw_key_pin);
    try std.testing.expectEqual(@as(?u16, 2), duo.server.info().?.raw_key_pin);
}

test "C10 raw public keys: options a pinned key cannot keep are refused" {
    const pins = [_][32]u8{Duo.pinOf(pki.p256)};
    // No pins, or too many.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_raw_pins = &.{} }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_auth = .required, .server_raw_pins = &.{} }));
    // TLS 1.2 has no raw key here.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_raw_pins = &pins, .client_max = .tls12 }));
    // A pinned client key needs a certificate request to answer.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_raw_pins = &pins }));
    // A rejected ECH attempt authenticates a public name, which a pinned key has none of.
    var pair = Hpke.deriveKeyPair(&(@as([32]u8, @splat(9))));
    defer pair.deinit();
    var config_buf: [128]u8 = undefined;
    var list_buf: [140]u8 = undefined;
    const list = try Ech.writeList(&list_buf, &.{try Ech.writeConfig(&config_buf, .{ .id = 1, .public_key = pair.public, .public_name = "public.example", .max_name_length = 24 })});
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_raw_pins = &pins, .client_ech = .{ .config_list = list } }));
}

test "C10 raw public keys: post-quantum authentication by a pinned ML-DSA key" {
    const mldsa = [_][32]u8{Duo.pinOf(pki.mldsa65)};
    {
        const duo = try connect(.{ .cert = .mldsa65, .server_raw = .only, .client_raw_pins = &mldsa, .client_require_pq_auth = true });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.peer_authenticated);
    }
    // A classical key cannot sign a scheme the policy offers.
    const classical = [_][32]u8{Duo.pinOf(pki.p256)};
    const duo = try Duo.init(gpa, .{ .server_raw = .only, .client_raw_pins = &classical, .client_require_pq_auth = true });
    defer duo.deinit();
    try std.testing.expectError(error.NoSignatureScheme, duo.handshake());
}

test "C10 raw public keys: resumption keeps the key's pin and its own namespace" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var ring = try TicketKeys.init(gpa, .{});
    defer ring.deinit();
    try ring.rotate(&@as([32]u8, @splat(0x77)), certificates.types.instant(pki.time));
    const pins = [_][32]u8{ other, Duo.pinOf(pki.p256) };
    const client_pins = [_][32]u8{Duo.pinOf(pki.client)};
    const options: Duo.Options = .{ .server_raw = .both, .client_raw_pins = &pins, .cache = &cache, .tickets = &ring, .client_auth = .required, .client_cert = true, .client_raw = true, .server_raw_pins = &client_pins };
    {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
    {
        const duo = try connect(options);
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expect(info.resumed and info.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 1), info.raw_key_pin);
        const server = duo.server.info().?;
        try std.testing.expect(server.resumed and server.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 0), server.raw_key_pin);
    }
}

test "F89 catalogue_delegated_parent_expiry_and_raw_key_namespace (raw keys: a certificate where a pinned key is, a key where a certificate is)" {
    // A server that does not answer server_certificate_type sends X.509: a client that trusts
    // only a pinned key refuses it with unsupported_certificate, before verifying anything.
    {
        const pins = [_][32]u8{Duo.pinOf(pki.p256)};
        const pair = try Pair(.aes_128_gcm_sha256).init(gpa, .{}, .{ .raw_pins = &pins });
        defer pair.deinit();
        try std.testing.expectError(error.UnsupportedCertificate, pair.handshake());
        try std.testing.expectEqual(.unsupported_certificate, pair.conn.diagnostics().alert_sent.?);
        try std.testing.expectEqual(@as(usize, 0), pair.verified);
    }
    // A client that asks for the raw key alone, of a server with certificates alone.
    {
        const pins = [_][32]u8{Duo.pinOf(pki.p256)};
        const duo = try Duo.init(gpa, .{ .client_raw_pins = &pins });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedCertificate, duo.handshake());
        try std.testing.expectEqual(.unsupported_certificate, duo.server.diagnostics().alert_sent.?);
    }
    // A client that did not ask, of a server with a raw key alone: no certificate to give.
    {
        const duo = try Duo.init(gpa, .{ .server_raw = .only });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedCertificate, duo.handshake());
        try std.testing.expectEqual(.unsupported_certificate, duo.server.diagnostics().alert_sent.?);
    }
    // A key no pin names.
    {
        const pins = [_][32]u8{ other, Duo.pinOf(pki.p384) };
        const duo = try Duo.init(gpa, .{ .server_raw = .only, .client_raw_pins = &pins });
        defer duo.deinit();
        try std.testing.expectError(error.PinMismatch, duo.handshake());
        try std.testing.expectEqual(.bad_certificate, duo.client.diagnostics().alert_sent.?);
    }
    // A client certificate where the server pins a raw key: the client listed no raw key type.
    {
        const pins = [_][32]u8{Duo.pinOf(pki.client)};
        const duo = try Duo.init(gpa, .{ .client_auth = .required, .client_cert = true, .server_raw_pins = &pins });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedCertificate, duo.handshake());
        try std.testing.expectEqual(.unsupported_certificate, duo.server.diagnostics().alert_sent.?);
    }
    // A client raw key where the server verifies certificates: the server does not select the
    // type, so the client sends no certificate, which a required policy refuses.
    {
        const duo = try Duo.init(gpa, .{ .client_auth = .required, .client_cert = true, .client_raw = true });
        defer duo.deinit();
        try std.testing.expectError(error.CertificateRequired, duo.handshake());
    }
    // A session resumed under one trust never resumes under the other: the cache key and the
    // ticket's policy hold which.
    {
        var cache = try SessionCache.init(gpa, .{});
        defer cache.deinit();
        var ring = try TicketKeys.init(gpa, .{});
        defer ring.deinit();
        try ring.rotate(&@as([32]u8, @splat(0x78)), certificates.types.instant(pki.time));
        const pins = [_][32]u8{Duo.pinOf(pki.p256)};
        {
            const duo = try connect(.{ .server_raw = .both, .client_raw_pins = &pins, .cache = &cache, .tickets = &ring });
            defer duo.deinit();
        }
        {
            const duo = try connect(.{ .server_raw = .both, .cache = &cache, .tickets = &ring });
            defer duo.deinit();
            try std.testing.expect(!duo.client.info().?.resumed);
        }
    }
    // The pinned key itself, as a Certificate carries it: one entry, a SubjectPublicKeyInfo.
    const spki = (try certificates.certificate.parse(pki.p256, .{})).spki;
    const pins = [_][32]u8{ other, Duo.pinOf(pki.p256) };
    try std.testing.expectEqual(@as(u16, 1), try Client.pinnedKey(&.{spki}, &pins));
    try std.testing.expectError(error.IllegalParameter, Client.pinnedKey(&.{ spki, spki }, &pins));
    try std.testing.expectError(error.InvalidCertificate, Client.pinnedKey(&.{pki.p256}, &pins));
    try std.testing.expectError(error.PinMismatch, Client.pinnedKey(&.{spki}, &.{other}));
}

test "C10 raw public keys: EncryptedExtensions answers only what was offered, with one type" {
    const raw: Hello.Options = .{ .raw_server_key = true };
    const answer = [_]u8{ 8, 0, 0, 7, 0, 5, 0, 20, 0, 1, 2 };
    try std.testing.expect((try Hello.encrypted(&answer, raw, false)).raw_server_key);
    try std.testing.expectError(error.UnsolicitedExtension, Hello.encrypted(&answer, .{}, false));
    const x509 = [_]u8{ 8, 0, 0, 7, 0, 5, 0, 20, 0, 1, 0 };
    try std.testing.expectError(error.UnofferedSelection, Hello.encrypted(&x509, raw, false));
    const two = [_]u8{ 8, 0, 0, 8, 0, 6, 0, 20, 0, 2, 2, 2 };
    try std.testing.expectError(error.DecodeError, Hello.encrypted(&two, raw, false));
}
