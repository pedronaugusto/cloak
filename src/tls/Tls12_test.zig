//! TLS 1.2, both roles, a cloak client against a cloak server.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Version = @import("crypto/Suite.zig").Version;

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

test "C4 a TLS 1.2 client certificate with an Ed25519 key signs the handshake messages themselves" {
    // RFC 8422 section 5.10: Ed25519 signs the messages, not a digest. Found at relic's re-pin:
    // the client answered with an empty Certificate and a server requiring one refused it.
    for ([_]@import("handshake/State.zig").Auth{ .optional, .required }) |auth| {
        for ([_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384 }) |suite| {
            const duo = try connect(.{ .client_max = .tls12, .client_suites = &.{suite}, .client_auth = auth, .client_cert = true, .client_ed25519 = true });
            defer duo.deinit();
            try std.testing.expect(duo.server.info().?.peer_authenticated);
            try std.testing.expectEqual(Version.tls12, duo.client.info().?.version);
        }
    }
    // A key held elsewhere is asked to sign the messages themselves, and checked before use.
    {
        const duo = try connect(.{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_auth = .required, .client_cert = true, .client_ed25519 = true, .client_external = true });
        defer duo.deinit();
        try std.testing.expect(duo.server.info().?.peer_authenticated);
    }
    // Under TLS 1.3 the same key signs as before, and nothing is kept.
    const duo = try connect(.{ .client_auth = .required, .client_cert = true, .client_ed25519 = true });
    defer duo.deinit();
    try std.testing.expect(duo.server.info().?.peer_authenticated);
    try std.testing.expectEqual(Version.tls13, duo.client.info().?.version);
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

test "F108 catalogue_credential_by_client_capability (TLS 1.2: the first credential with a suite the client offers, a curve it lists and a scheme it takes)" {
    // An RSA credential first and a P-256 one after: a client of ECDSA suites alone gets the second.
    {
        const duo = try connect(.{ .cert = .rsa, .server_also = &.{.p256}, .client_max = .tls12, .client_suites = &ecdsa_suites });
        defer duo.deinit();
        try std.testing.expectEqual(Suite.ecdhe_ecdsa_aes_128_gcm_sha256, duo.client.info().?.suite);
        try std.testing.expect(duo.client.info().?.peer_authenticated);
    }
    // A P-384 credential first: a client listing P-256 but not P-384 gets the P-256 one (RFC 8422
    // section 5.1 binds the certificate's curve to the client's list).
    {
        const duo = try connect(.{ .cert = .p384, .server_also = &.{.p256}, .client_max = .tls12, .client_suites = &ecdsa_suites, .client_groups = &.{ .x25519, .p256 } });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.peer_authenticated);
    }
    // Both kinds offered: the server's order of credentials, then its order of suites.
    {
        const duo = try connect(.{ .cert = .p256, .server_also = &.{.rsa}, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectEqual(.ecdsa, duo.client.info().?.suite.tls12().?.authentication());
    }
    {
        const duo = try connect(.{ .cert = .rsa, .server_also = &.{.p256}, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectEqual(.rsa, duo.client.info().?.suite.tls12().?.authentication());
    }
    // An ML-DSA credential first (TLS 1.3's only): a TLS 1.2 client gets the next.
    {
        const duo = try connect(.{ .cert = .mldsa65, .server_also = &.{.p256}, .client_max = .tls12 });
        defer duo.deinit();
        try std.testing.expectEqual(.ecdsa, duo.client.info().?.suite.tls12().?.authentication());
    }
    // None fits: the refusal is the one a single credential gets.
    try std.testing.expectError(error.NoSharedSuite, connect(.{ .cert = .p384, .server_also = &.{.rsa}, .client_max = .tls12, .client_suites = &ecdsa_suites, .client_groups = &.{ .x25519, .p256 } }));
}

test "C4 a refusal in a TLS 1.0 record reaches the client as the peer's alert" {
    const duo = try Duo.init(std.testing.allocator, .{ .client_min = .tls13, .client_suites = Suite.tls13_only });
    defer duo.deinit();
    try duo.serveClient();
    try std.testing.expect(duo.client.output().len != 0);
    try std.testing.expectError(error.PeerAlert, duo.client.receive("\x15\x03\x01\x00\x02\x02\x46"));
    try std.testing.expectEqual(.protocol_version, duo.client.diagnostics().alert_received.?);
}

const one12: Duo.Options = .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };

test "C4 keying material after a failed connection is WrongPhase, not a crash, in both versions" {
    for ([_]Duo.Options{ one12, .{} }) |options| {
        const duo = try connect(options);
        defer duo.deinit();
        var out: [32]u8 = undefined;
        try duo.client.exportKeyingMaterial(&out, "EXPORTER-test", "");
        // One forged application record: the connection fails and erases its secrets.
        var junk: [5 + 40]u8 = @splat(0x55);
        junk[0..5].* = .{ 23, 3, 3, 0, 40 };
        try std.testing.expectError(error.BadRecord, duo.client.receive(&junk));
        try std.testing.expectError(error.WrongPhase, duo.client.exportKeyingMaterial(&out, "EXPORTER-test", ""));
        try std.testing.expectEqual(@as(?@import("Connection.zig").Info, null), duo.client.info());
    }
}

test "C4 a TLS 1.2 server that asked for no certificate ends connected in its state table" {
    for ([_]@import("handshake/State.zig").Auth{ .none, .optional }) |auth| {
        var options = one12;
        options.client_auth = auth;
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expectEqual(.connected, duo.server.hs.state.server.state.phase());
        try std.testing.expectEqual(.connected, duo.client.hs.state.client.state.phase());
    }
}

/// A TLS 1.2 ClientHello record with `legacy`, the compression list and the extensions given.
fn helloRecord(out: []u8, legacy: u16, compression: []const u8, extensions: []const u8) []const u8 {
    var w: @import("wire/Writer.zig") = .{ .bytes = out[5..] };
    w.put(&.{ 1, 0, 0, 0 }) catch unreachable;
    w.int(u16, legacy) catch unreachable;
    w.put(&@as([32]u8, @splat(0x42))) catch unreachable;
    w.put(&.{0}) catch unreachable;
    w.int(u16, 2) catch unreachable;
    w.int(u16, 0xc02b) catch unreachable;
    w.vector(u8, compression) catch unreachable;
    w.vector(u16, extensions) catch unreachable;
    std.mem.writeInt(u24, out[6..9], @intCast(w.pos - 4), .big);
    out[0..5].* = .{ 22, 3, 3, 0, 0 };
    std.mem.writeInt(u16, out[3..5], @intCast(w.pos), .big);
    return out[0 .. 5 + w.pos];
}

/// P-256, ecdsa_secp256r1_sha256, EMS and renegotiation_info, and no ec_point_formats.
const plain12 = "\x00\x0a\x00\x04\x00\x02\x00\x17" ++ "\x00\x0d\x00\x04\x00\x02\x04\x03" ++ "\x00\x17\x00\x00" ++ "\xff\x01\x00\x01\x00";

/// The extension ids of the ServerHello at the start of `flight`.
fn serverHelloExtensions(flight: []const u8, out: []u16) []u16 {
    // Record header, handshake header, version, random, empty session id, suite, compression.
    const at = 5 + 4 + 2 + 32 + 1 + 2 + 1;
    const block = flight[at + 2 ..][0..std.mem.readInt(u16, flight[at..][0..2], .big)];
    var count: usize = 0;
    var pos: usize = 0;
    while (pos < block.len) : (count += 1) {
        out[count] = std.mem.readInt(u16, block[pos..][0..2], .big);
        pos += 4 + std.mem.readInt(u16, block[pos + 2 ..][0..2], .big);
    }
    return out[0..count];
}

test "C4 a TLS 1.2 ServerHello answers ec_point_formats only when the client sent it" {
    for ([_]bool{ false, true }) |sent| {
        const duo = try Duo.init(std.testing.allocator, .{});
        defer duo.deinit();
        var record: [512]u8 = undefined;
        _ = try duo.server.receive(helloRecord(&record, 0x0303, &.{0}, if (sent) plain12 ++ "\x00\x0b\x00\x02\x01\x00" else plain12));
        try duo.serveServer();
        var ids: [16]u16 = undefined;
        const answered = serverHelloExtensions(duo.server.output(), &ids);
        try std.testing.expectEqual(sent, std.mem.findScalar(u16, answered, 11) != null);
    }
}

test "C4 TLS 1.2 hellos RFC 8446 says to accept: other compression methods beside null, and a legacy version above TLS 1.2" {
    for ([_]struct { u16, []const u8 }{ .{ 0x0303, &.{ 1, 0 } }, .{ 0x0304, &.{0} }, .{ 0x0305, &.{0} } }) |case| {
        const duo = try Duo.init(std.testing.allocator, .{});
        defer duo.deinit();
        var record: [512]u8 = undefined;
        _ = try duo.server.receive(helloRecord(&record, case[0], case[1], plain12));
        try duo.serveServer();
        const flight = duo.server.output();
        // A TLS 1.2 ServerHello with the null method.
        try std.testing.expectEqual(@as(u8, 2), flight[5]);
        try std.testing.expectEqualSlices(u8, &.{ 3, 3 }, flight[9..11]);
        try std.testing.expectEqual(@as(u8, 0), flight[5 + 4 + 2 + 32 + 1 + 2]);
    }
    // Without the null method there is nothing to agree on.
    const duo = try Duo.init(std.testing.allocator, .{});
    defer duo.deinit();
    var record: [512]u8 = undefined;
    try std.testing.expectError(error.IllegalParameter, duo.server.receive(helloRecord(&record, 0x0303, &.{1}, plain12)));
}

test "C4 TLS 1.2 renegotiation is refused with a warning, and the connection goes on" {
    const duo = try connect(one12);
    defer duo.deinit();
    var buffer: [128]u8 = undefined;
    // A HelloRequest from the server.
    const request = try duo.server.tx.?.seal(.handshake, "\x00\x00\x00\x00", 0, &buffer);
    _ = try duo.client.receive(request);
    // The warning is the write half's to send: it goes out with the client's next output.
    _ = try duo.server.receive(duo.client.output());
    try std.testing.expectEqual(.no_renegotiation, duo.client.diagnostics().alert_sent.?);
    duo.client.acknowledge(duo.client.output().len);
    try std.testing.expectEqual(.no_renegotiation, duo.server.diagnostics().alert_received.?);
    var out: [64]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "still here", try duo.echo(&duo.client, &duo.server, "still here", &out));
    // A ClientHello after the handshake.
    const hello = try duo.client.tx.?.seal(.handshake, "\x01\x00\x00\x00", 0, &buffer);
    _ = try duo.server.receive(hello);
    _ = try duo.client.receive(duo.server.output());
    try std.testing.expectEqual(.no_renegotiation, duo.server.diagnostics().alert_sent.?);
    duo.server.acknowledge(duo.server.output().len);
    try std.testing.expectEqualSlices(u8, "and here", try duo.echo(&duo.server, &duo.client, "and here", &out));
}

/// Hands `bytes` to the client, answering what it asks for on the way.
fn deliver(duo: *Duo, bytes: []const u8) !void {
    var at: usize = 0;
    while (at < bytes.len) {
        const taken = try duo.client.receive(bytes[at..]);
        if (taken == 0) try duo.serveClient();
        at += taken;
    }
}

test "C4 a HelloRequest while negotiating TLS 1.2 is ignored, a ClientHello is out of order" {
    {
        const duo = try Duo.init(std.testing.allocator, one12);
        defer duo.deinit();
        try duo.handshakeUntilServerFlight();
        // After the ServerHello, between the server's records (RFC 5246 section 7.4.1.1).
        var flight: [8][]const u8 = undefined;
        const n = records(duo.server.output(), &flight);
        try deliver(duo, flight[0]);
        try deliver(duo, "\x16\x03\x03\x00\x04\x00\x00\x00\x00");
        for (flight[1..n]) |record| try deliver(duo, record);
        duo.server.acknowledge(duo.server.output().len);
        try duo.handshake();
        try std.testing.expectEqual(.tls12, duo.client.info().?.version);
        try std.testing.expectEqual(@as(?@import("wire/Alert.zig").Alert, null), duo.client.diagnostics().alert_sent);
    }
    const duo = try Duo.init(std.testing.allocator, one12);
    defer duo.deinit();
    try duo.handshakeUntilServerFlight();
    try std.testing.expectError(error.UnexpectedMessage, duo.server.receive("\x16\x03\x03\x00\x04\x01\x00\x00\x00"));
}

test "C4 TLS 1.2 warnings pass, a few times; TLS 1.3 takes every alert as fatal" {
    {
        const duo = try Duo.init(std.testing.allocator, one12);
        defer duo.deinit();
        try duo.serveClient();
        // unrecognized_name at warning level before the ServerHello, as some servers send it.
        _ = try duo.client.receive("\x15\x03\x03\x00\x02\x01\x70");
        try duo.handshake();
        try std.testing.expectEqual(.tls12, duo.client.info().?.version);
        var buffer: [64]u8 = undefined;
        for (0..3) |_| _ = try duo.client.receive(try duo.server.tx.?.seal(.alert, "\x01\x70", 0, &buffer));
        // The fifth is a flood, refused as this end's (F133).
        try std.testing.expectError(error.ControlFlood, duo.client.receive(try duo.server.tx.?.seal(.alert, "\x01\x70", 0, &buffer)));
    }
    const duo = try connect(.{});
    defer duo.deinit();
    try std.testing.expectEqual(.tls13, duo.client.info().?.version);
    var buffer: [64]u8 = undefined;
    try std.testing.expectError(error.PeerAlert, duo.client.receive(try duo.server.tx.?.seal(.alert, "\x01\x70", 0, &buffer)));
}

test "C4 TLS 1.2 alerts name the failure as TLS 1.2 does" {
    // No signature_algorithms or supported_groups: handshake_failure, not TLS 1.3's missing_extension.
    for ([_][]const u8{ plain12[8..], plain12[0..8] ++ plain12[16..] }) |extensions| {
        const duo = try Duo.init(std.testing.allocator, .{});
        defer duo.deinit();
        var record: [512]u8 = undefined;
        try std.testing.expect(std.meta.isError(duo.server.receive(helloRecord(&record, 0x0303, &.{0}, extensions))));
        try std.testing.expectEqual(.handshake_failure, duo.server.diagnostics().alert_sent.?);
    }
    // A record longer than any 2^14-byte plaintext needs: record_overflow, before decryption.
    const duo = try connect(one12);
    defer duo.deinit();
    const big = try std.testing.allocator.alloc(u8, 5 + 16384 + 100);
    defer std.testing.allocator.free(big);
    @memset(big, 0x41);
    big[0..5].* = .{ 23, 3, 3, 0, 0 };
    std.mem.writeInt(u16, big[3..5], 16384 + 100, .big);
    try std.testing.expectError(error.RecordOverflow, duo.client.receive(big));
    try std.testing.expectEqual(.record_overflow, duo.client.diagnostics().alert_sent.?);
}

test "C4 a TLS 1.2 client offers at least one TLS 1.2 suite" {
    const Hello = @import("handshake/Hello.zig");
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .max_version = .tls12, .suites = Suite.tls13_only }));
}

test "C4 an output popped from the queue leaves no key bytes behind" {
    const Flight = @import("handshake/Flight.zig");
    var flight: Flight = .{};
    // Searched for as whole sequences: a single byte can turn up by chance, and Debug fills an
    // emptied slot's payload with 0xaa, its pattern for undefined memory.
    var key: [32]u8 = undefined;
    for (&key, 0..) |*byte, i| byte.* = @intCast(0x40 + i); // safe: i is below 32
    const iv: [12]u8 = .{ 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c };
    var keys: Flight.Keys12 = .{ .cipher = .aes_256_gcm, .key = .init(key), .iv = .init(iv) };
    try flight.push(.{ .keys12 = .{ .direction = .read, .keys = keys } });
    keys.deinit();
    var out: Flight.Emit = undefined;
    try std.testing.expect(flight.pop(&out));
    defer Flight.eraseEmit(&out);
    try std.testing.expectEqualSlices(u8, &key, out.keys12.keys.key.expose());
    for (&flight.queue) |*slot| {
        const bytes = std.mem.asBytes(slot);
        try std.testing.expect(std.mem.find(u8, bytes, key[0..8]) == null);
        try std.testing.expect(std.mem.find(u8, bytes, key[24..32]) == null);
        try std.testing.expect(std.mem.find(u8, bytes, iv[0..8]) == null);
    }
    try std.testing.expect(!flight.pop(&out));
}

test "F128 catalogue_tls12_hello_no_session_id_unresumed (a TLS 1.2-only hello resuming nothing has an empty session id)" {
    // RFC 5246 section 7.4.1.2: the session id is empty when no session is available; the random
    // one of middlebox compatibility is TLS 1.3's (RFC 8446 appendix D.4).
    for ([_]Duo.Options{ one12, .{} }) |options| {
        const duo = try Duo.init(std.testing.allocator, options);
        defer duo.deinit();
        try duo.serveClient();
        const hello = duo.client.output();
        // The record header, the message header, legacy_version and the random.
        const at = 5 + 4 + 2 + 32;
        try std.testing.expect(hello.len > at);
        try std.testing.expectEqual(@as(u8, if (options.client_max == .tls12) 0 else 32), hello[at]);
    }
}

test "F130 catalogue_client_hello_ends_its_record (a ClientHello sharing its record with the start of another message is unexpected_message)" {
    // RFC 8446 section 5.1: a ClientHello can precede a key change, so it must end its record;
    // bytes of the client's next message beside it were sent before the server's answer.
    var buffer: [2048]u8 = undefined;
    // A TLS 1.2 hello and the first byte of a ClientKeyExchange.
    {
        const duo = try Duo.init(std.testing.allocator, .{});
        defer duo.deinit();
        const hello = helloRecord(&buffer, 0x0303, &.{0}, plain12);
        buffer[hello.len] = 16;
        std.mem.writeInt(u16, buffer[3..5], @intCast(hello.len - 5 + 1), .big);
        try std.testing.expectError(error.RecordAlignment, duo.server.receive(buffer[0 .. hello.len + 1]));
        try std.testing.expectEqual(@as(?@import("wire/Alert.zig").Alert, .unexpected_message), duo.server.diagnostics().alert_sent);
    }
    // A TLS 1.3 hello and the first byte of a Finished.
    {
        const duo = try Duo.init(std.testing.allocator, .{});
        defer duo.deinit();
        try duo.serveClient();
        const hello = duo.client.output();
        @memcpy(buffer[0..hello.len], hello);
        buffer[hello.len] = 20;
        std.mem.writeInt(u16, buffer[3..5], @intCast(hello.len - 5 + 1), .big);
        try std.testing.expectError(error.RecordAlignment, duo.server.receive(buffer[0 .. hello.len + 1]));
        try std.testing.expectEqual(@as(?@import("wire/Alert.zig").Alert, .unexpected_message), duo.server.diagnostics().alert_sent);
    }
}
