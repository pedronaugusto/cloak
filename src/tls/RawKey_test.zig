//! Raw public keys (RFC 7250) end to end, cloak client against cloak server and against the
//! scripted server, and the failure catalogue's raw-key half of F89.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Duo = @import("../testing/Duo.zig");
const Pair = @import("../testing/Pair.zig").Pair;
const Possession = @import("handshake/Possession.zig");
const Hello = @import("handshake/Hello.zig");
const Ech = @import("handshake/Ech.zig");
const Hpke = @import("crypto/Hpke.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const Messages12 = @import("handshake/Messages12.zig");
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
    try std.testing.expectEqual(@as(u16, 1), try Possession.pinnedKey(&.{spki}, &pins));
    try std.testing.expectError(error.IllegalParameter, Possession.pinnedKey(&.{ spki, spki }, &pins));
    try std.testing.expectError(error.InvalidCertificate, Possession.pinnedKey(&.{pki.p256}, &pins));
    try std.testing.expectError(error.PinMismatch, Possession.pinnedKey(&.{spki}, &.{other}));
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

test "C10 raw public keys over TLS 1.2: a client trusts the server's pinned key, every key type TLS 1.2 signs with" {
    for ([_]Duo.Cert{ .p256, .p384, .ed25519, .rsa }) |cert| {
        const pins = [_][32]u8{ other, Duo.pinOf(leafOf(cert)) };
        const duo = try connect(.{ .cert = cert, .server_raw = .only, .client_raw_pins = &pins, .client_max = .tls12, .identity = "unrelated.example" });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expectEqual(.tls12, info.version);
        try std.testing.expect(info.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 1), info.raw_key_pin);
        try exportsMatch(duo);
        var out: [8]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "raw", try duo.echo(&duo.client, &duo.server, "raw", &out));
    }
    // A client offering both versions to a TLS 1.2 server, which answers in its ServerHello.
    const pins = [_][32]u8{Duo.pinOf(pki.p256)};
    const duo = try connect(.{ .server_raw = .both, .client_raw_pins = &pins, .server_max = .tls12 });
    defer duo.deinit();
    try std.testing.expectEqual(.tls12, duo.client.info().?.version);
    try std.testing.expectEqual(@as(?u16, 0), duo.client.info().?.raw_key_pin);
    // An ML-DSA key has no TLS 1.2 suite.
    const mldsa = [_][32]u8{Duo.pinOf(pki.mldsa65)};
    const refused = try Duo.init(gpa, .{ .cert = .mldsa65, .server_raw = .only, .client_raw_pins = &mldsa, .client_max = .tls12 });
    defer refused.deinit();
    try std.testing.expectError(error.NoSharedSuite, refused.handshake());
}

test "C10 raw public keys over TLS 1.2: client authentication by a pinned key, and both ways" {
    const pins = [_][32]u8{ other, other, Duo.pinOf(pki.client) };
    for ([_]@import("handshake/Server.zig").Auth{ .required, .optional }) |auth| {
        const duo = try connect(.{ .client_auth = auth, .client_cert = true, .client_raw = true, .server_raw_pins = &pins, .client_max = .tls12 });
        defer duo.deinit();
        const server = duo.server.info().?;
        try std.testing.expectEqual(.tls12, server.version);
        try std.testing.expect(server.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 2), server.raw_key_pin);
    }
    const server_pins = [_][32]u8{Duo.pinOf(pki.p256)};
    const duo = try connect(.{ .server_raw = .only, .client_raw_pins = &server_pins, .client_auth = .required, .client_cert = true, .client_raw = true, .server_raw_pins = &pins, .client_max = .tls12 });
    defer duo.deinit();
    try std.testing.expectEqual(@as(?u16, 0), duo.client.info().?.raw_key_pin);
    try std.testing.expectEqual(@as(?u16, 2), duo.server.info().?.raw_key_pin);
    try exportsMatch(duo);
}

test "C10 raw public keys over TLS 1.2: a session ticket keeps both pins" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var ring = try TicketKeys.init(gpa, .{});
    defer ring.deinit();
    try ring.rotate(&@as([32]u8, @splat(0x79)), certificates.types.instant(pki.time));
    const pins = [_][32]u8{ other, Duo.pinOf(pki.p256) };
    const client_pins = [_][32]u8{Duo.pinOf(pki.client)};
    const options: Duo.Options = .{ .server_raw = .both, .client_raw_pins = &pins, .cache = &cache, .tickets = &ring, .client_tls12_tickets = true, .server_tls12_tickets = true, .client_max = .tls12, .client_auth = .required, .client_cert = true, .client_raw = true, .server_raw_pins = &client_pins };
    {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
    const duo = try connect(options);
    defer duo.deinit();
    const info = duo.client.info().?;
    try std.testing.expect(info.resumed and info.peer_authenticated);
    try std.testing.expectEqual(.tls12, info.version);
    try std.testing.expectEqual(@as(?u16, 1), info.raw_key_pin);
    const server = duo.server.info().?;
    try std.testing.expect(server.resumed and server.peer_authenticated);
    try std.testing.expectEqual(@as(?u16, 0), server.raw_key_pin);
}

/// The server's first TLS 1.2 flight without its server_certificate_type answer: the record,
/// ServerHello and extension block lengths shortened by the five bytes taken out.
fn withoutTypeAnswer(bytes: []u8) usize {
    const hello_at = 5;
    var at: usize = hello_at + 4 + 2 + 32;
    at += 1 + bytes[at];
    at += 3;
    const block_at = at;
    var ext = block_at + 2;
    const end = block_at + 2 + std.mem.readInt(u16, bytes[block_at..][0..2], .big);
    while (ext < end) {
        const id = std.mem.readInt(u16, bytes[ext..][0..2], .big);
        const len = std.mem.readInt(u16, bytes[ext + 2 ..][0..2], .big);
        if (id == Hello.server_certificate_type) {
            const rest = bytes[ext + 4 + len ..];
            @memmove(bytes[ext..][0..rest.len], rest);
            const cut: u16 = 4 + len;
            std.mem.writeInt(u16, bytes[3..5], std.mem.readInt(u16, bytes[3..5], .big) - cut, .big);
            std.mem.writeInt(u24, bytes[hello_at + 1 ..][0..3], std.mem.readInt(u24, bytes[hello_at + 1 ..][0..3], .big) - cut, .big);
            std.mem.writeInt(u16, bytes[block_at..][0..2], std.mem.readInt(u16, bytes[block_at..][0..2], .big) - cut, .big);
            return bytes.len - cut;
        }
        ext += 4 + len;
    }
    unreachable; // unreachable: the server answered the type
}

test "F89 catalogue_delegated_parent_expiry_and_raw_key_namespace (raw keys over TLS 1.2)" {
    const pins = [_][32]u8{Duo.pinOf(pki.p256)};
    // A TLS 1.2 ServerHello that does not select the raw key: the X.509 that follows is refused
    // with unsupported_certificate before anything in it is read.
    {
        const duo = try Duo.init(gpa, .{ .server_raw = .only, .client_raw_pins = &pins, .client_max = .tls12 });
        defer duo.deinit();
        try duo.handshakeUntilServerFlight();
        const flight = try gpa.dupe(u8, duo.server.output());
        defer gpa.free(flight);
        duo.server.acknowledge(flight.len);
        const len = withoutTypeAnswer(flight);
        try std.testing.expectError(error.UnsupportedCertificate, deliver(duo, flight[0..len]));
        try std.testing.expectEqual(.unsupported_certificate, duo.client.diagnostics().alert_sent.?);
    }
    // A server with certificates alone, a client that takes a raw key alone.
    {
        const duo = try Duo.init(gpa, .{ .client_raw_pins = &pins, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedCertificate, duo.handshake());
        try std.testing.expectEqual(.unsupported_certificate, duo.server.diagnostics().alert_sent.?);
    }
    // A key no pin names.
    {
        const wrong = [_][32]u8{ other, Duo.pinOf(pki.p384) };
        const duo = try Duo.init(gpa, .{ .server_raw = .only, .client_raw_pins = &wrong, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectError(error.PinMismatch, duo.handshake());
        try std.testing.expectEqual(.bad_certificate, duo.client.diagnostics().alert_sent.?);
    }
    // A client certificate where the server pins a raw key.
    {
        const client_pins = [_][32]u8{Duo.pinOf(pki.client)};
        const duo = try Duo.init(gpa, .{ .client_auth = .required, .client_cert = true, .server_raw_pins = &client_pins, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedCertificate, duo.handshake());
    }
    // A client raw key where the server verifies certificates: an empty answer, refused.
    {
        const duo = try Duo.init(gpa, .{ .client_auth = .required, .client_cert = true, .client_raw = true, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectError(error.NoClientCertificate, duo.handshake());
    }
    // A TLS 1.2 raw-key Certificate is the key alone: no list around it.
    const spki = (try certificates.certificate.parse(pki.p256, .{})).spki;
    var buf: [256]u8 = undefined;
    const message = try Messages12.buildRawKey(&buf, spki);
    try std.testing.expectEqual(4 + 3 + spki.len, message.len);
    try std.testing.expectEqualSlices(u8, spki, try Messages12.rawKey(message));
    var empty: [8]u8 = undefined;
    try std.testing.expectEqual(@as(usize, 0), (try Messages12.rawKey(try Messages12.buildRawKey(&empty, ""))).len);
    message[6] +%= 1;
    try std.testing.expectError(error.InvalidLength, Messages12.rawKey(message));
}

fn deliver(duo: *Duo, bytes: []const u8) !void {
    var at: usize = 0;
    while (at < bytes.len) {
        const n = try duo.client.receive(bytes[at..]);
        at += n;
        if (n == 0) {
            if (duo.client.request() == null) return error.Stalled;
            try duo.serveClient();
        }
    }
    try duo.serveClient();
}

test "C10 raw public keys over TLS 1.2: a ServerHello answers only what was offered, with one type" {
    var buf: [256]u8 = undefined;
    const random: [32]u8 = @splat(3);
    const raw: Hello.Options = .{ .raw_server_key = true, .max_version = .tls12, .suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };
    const answer = try Hello.buildServer12(&buf, .stream, &random, "", .ecdhe_ecdsa_aes_128_gcm_sha256, "", .{ .server_name = false, .point_formats = false, .server_certificate_type = .raw_public_key });
    try std.testing.expect((try Hello.server(answer, "", &.{}, raw, .{})).tls12.raw_server_key);
    try std.testing.expectError(error.UnsolicitedExtension, Hello.server(answer, "", &.{}, .{ .max_version = .tls12, .suites = raw.suites }, .{}));
    var buf2: [256]u8 = undefined;
    const x509 = try Hello.buildServer12(&buf2, .stream, &random, "", .ecdhe_ecdsa_aes_128_gcm_sha256, "", .{ .server_name = false, .point_formats = false, .server_certificate_type = .x509 });
    try std.testing.expectError(error.UnofferedSelection, Hello.server(x509, "", &.{}, raw, .{}));
}
