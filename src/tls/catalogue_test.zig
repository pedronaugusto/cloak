//! Failure-catalogue tests that cross the TLS layers: each names its F-id and catalogue test.
const std = @import("std");
const Alert = @import("wire/Alert.zig").Alert;
const Der = @import("../wire/Der.zig");
const ClientHello = @import("handshake/ClientHello.zig");
const Messages = @import("handshake/Messages.zig");
const Connection = @import("Connection.zig");
const certificates = @import("../certificates.zig");
const pki = @import("../testing/Peer.zig").pki;

/// A ClientHello body around `extensions`, with a correct message header.
fn hello(buffer: []u8, extensions: []const u8) []const u8 {
    var at: usize = 4;
    buffer[at..][0..2].* = .{ 3, 3 };
    @memset(buffer[at + 2 ..][0..32], 'R');
    at += 34;
    const rest = "\x00\x00\x02\x13\x01\x01\x00";
    @memcpy(buffer[at..][0..rest.len], rest);
    at += rest.len;
    @memcpy(buffer[at..][0..extensions.len], extensions);
    at += extensions.len;
    buffer[0] = 1;
    std.mem.writeInt(u24, buffer[1..4], @intCast(at - 4), .big);
    return buffer[0..at];
}

test "F27 catalogue_heartbeat_and_nested_length_overread across DER, hellos, certificates and records" {
    // DER: a child claiming more than its parent holds.
    const outer = try Der.single("\x30\x03\x30\x05\x00", 0x30);
    var inner = outer.reader();
    try std.testing.expectError(error.InvalidDer, inner.next());
    try std.testing.expectError(error.InvalidDer, Der.validate("\x30\x03\x30\x05\x00", .{}));
    // A long-form length past the end of its parent.
    try std.testing.expectError(error.InvalidDer, Der.validate("\x30\x04\x04\x82\x01\x00", .{}));

    var buffer: [256]u8 = undefined;
    // The extension block claims sixteen bytes; four follow.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x10\x00\x0a\x00\x00"), .stream));
    // key_share: the extension is six bytes, its share list claims eight.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x0a\x00\x33\x00\x06\x00\x08\x00\x1d\x00\x20"), .stream));
    // key_share: one entry claims 32 bytes of key and the list ends after two.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x0c\x00\x33\x00\x08\x00\x06\x00\x1d\x00\x20\xaa\xbb"), .stream));
    // server_name: the host name claims more than its list.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x0b\x00\x00\x00\x07\x00\x05\x00\x00\x09ab"), .stream));
    // A handshake header claiming more than the message.
    try std.testing.expectError(error.InvalidLength, Messages.body("\x0b\x00\x00\x09\x00\x00"));

    // Certificate: an entry claiming more than the list; the list claiming more than the message.
    var out: [Messages.max_certificates][]const u8 = undefined;
    try std.testing.expectError(error.InvalidLength, Messages.certificate("\x0b\x00\x00\x0a\x00\x00\x00\x06\x00\x00\x09ab\x00\x00", 16, 65536, &out, .{}));
    try std.testing.expectError(error.InvalidLength, Messages.certificate("\x0b\x00\x00\x06\x00\x00\x00\x40\x00\x00", 16, 65536, &out, .{}));

    // Heartbeat (content type 24) is not a record cloak accepts, before or after the handshake.
    var conn = try Connection.client(std.testing.allocator, .{ .identity = .none, .verify = .none });
    defer conn.deinit();
    // The client sends its hello first; it reads nothing while its entropy request is open.
    while (conn.request()) |request| {
        var entropy: [512]u8 = @splat(7);
        try conn.provide(request.token, .{ .entropy = entropy[0..request.service.entropy] });
    }
    try std.testing.expect(conn.output().len != 0);
    try std.testing.expectError(error.UnexpectedRecord, conn.receive("\x18\x03\x03\x00\x03\x01\x40\x00"));
    const key = try certificates.PrivateKey.parse(std.testing.allocator, pki.p256_pem, .{});
    defer key.deinit();
    const identity = try certificates.Identity.init(std.testing.allocator, &.{ pki.p256, pki.ca }, key, .{});
    defer identity.deinit();
    var server = try Connection.server(std.testing.allocator, .{ .credentials = &.{.{ .identity = identity }} });
    defer server.deinit();
    try std.testing.expectError(error.UnexpectedRecord, server.receive("\x18\x03\x03\x00\x03\x01\x40\x00"));
}

const Duo = @import("../testing/Duo.zig");

test "F01 catalogue_entropy_clone_and_unready_source (entropy failing at any request ends that end, nothing drawn for is sent, the peer never connects)" {
    const gpa = std.testing.allocator;
    const scenarios = [_]Duo.Options{
        .{ .client_auth = .required, .client_cert = true },
        .{ .client_auth = .required, .client_cert = true, .client_max = .tls12, .server_max = .tls12 },
        .{ .client_auth = .required, .client_cert = true, .cert = .rsa },
    };
    for (scenarios) |scenario| for ([_]usize{ 0, 1 }) |end| {
        // Every entropy request a clean handshake makes at this end.
        const clean = try Duo.init(gpa, scenario);
        defer clean.deinit();
        try clean.handshake();
        const requests = clean.entropy_drawn[end];
        try std.testing.expect(requests >= 1);
        for (0..requests) |at| {
            var options = scenario;
            options.entropy_fails = .{ .end = if (end == 0) .client else .server, .at = at };
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try std.testing.expectError(error.EntropyUnavailable, duo.handshake());
            const failed = if (end == 0) &duo.client else &duo.server;
            const peer = if (end == 0) &duo.server else &duo.client;
            try std.testing.expectEqual(Connection.Phase.failed, failed.phase());
            try std.testing.expect(failed.info() == null);
            // Only an alert is left to send: no flight built from the missing draw.
            const out = failed.output();
            try std.testing.expect(out.len == 0 or (out[0] == 21 and out.len == 7));
            try std.testing.expect(peer.phase() != .connected);
        }
    };
    // cloak keeps no generator to clone: every random byte is the caller's draw for this
    // connection. The same draws give the same first flight; fresh draws give a fresh random
    // and fresh shares.
    var flights: [3][]u8 = undefined;
    for (&flights, [_]u64{ 1, 1, 2 }) |*flight, seed| {
        const duo = try Duo.init(gpa, .{ .seed = seed });
        defer duo.deinit();
        try duo.serveClient();
        flight.* = try gpa.dupe(u8, duo.client.output());
    }
    defer for (flights) |flight| gpa.free(flight);
    try std.testing.expectEqualSlices(u8, flights[0], flights[1]);
    try std.testing.expect(!std.mem.eql(u8, flights[0][11..43], flights[2][11..43]));
    try std.testing.expect(flights[0].len == flights[2].len);
    // The random, the session id and the shares (an ML-KEM-768 hybrid among them) all differ.
    var differ: usize = 0;
    for (flights[0], flights[2]) |a, b| differ += @intFromBool(a != b);
    try std.testing.expect(differ > 32 + 32 + 1000);
}

test "F152 catalogue_verified_leaf_must_allow_signing (a verified leaf whose Key Usage leaves out digitalSignature never proves possession, whichever verifier took it)" {
    // BoGo's ECDSAKeyUsage-Server and RSAKeyUsage-Server-WantSignature-GotEncipherment: RFC 8446
    // section 4.4.2.2, the certificate MUST allow its key to sign. A caller's verifier that checks
    // nothing (`accept_any`) takes the chain; the engine refuses it with bad_certificate, as the
    // portable verifier's purpose check does.
    const gpa = std.testing.allocator;
    for ([_]bool{ false, true }) |tls12| {
        const base: Duo.Options = if (tls12) .{ .client_max = .tls12, .server_max = .tls12, .accept_any = true } else .{ .accept_any = true };
        // The server's certificate.
        {
            var options = base;
            options.cert = .dc_no_signature;
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try std.testing.expectError(error.KeyUsage, duo.handshake());
            try std.testing.expectEqual(@as(?Alert, .bad_certificate), duo.client.diagnostics().alert_sent);
        }
        // The client's.
        {
            var options = base;
            options.client_auth = .required;
            options.client_cert = true;
            options.client_no_signature = true;
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try std.testing.expectError(error.KeyUsage, duo.handshake());
            try std.testing.expectEqual(@as(?Alert, .bad_certificate), duo.server.diagnostics().alert_sent);
            try std.testing.expect(duo.server.info() == null);
        }
    }
}

test "F42 catalogue_mtls_builder_order_and_optional_usage (optional and required client authentication: a wrong-usage certificate never authenticates, absence never reports an identity)" {
    const gpa = std.testing.allocator;
    // The policy is one immutable options value given at creation: there is no setter order.
    for ([_]bool{ false, true }) |tls12| {
        const base: Duo.Options = if (tls12) .{ .client_max = .tls12, .server_max = .tls12 } else .{};
        // A certificate for servers only, offered where a client's is asked for: refused under
        // either policy, never a connection that reports the client authenticated.
        for ([_]@TypeOf(base.client_auth){ .optional, .required }) |policy| {
            var options = base;
            options.client_auth = policy;
            options.client_cert = true;
            options.client_server_eku = true;
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try std.testing.expectError(error.VerificationRejected, duo.handshake());
            try std.testing.expectEqual(Connection.Phase.failed, duo.server.phase());
            try std.testing.expect(duo.server.info() == null);
        }
        // No certificate: required fails, optional connects without an authenticated client.
        {
            var options = base;
            options.client_auth = .required;
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try std.testing.expect(std.meta.isError(duo.handshake()));
            try std.testing.expect(duo.server.info() == null);
        }
        {
            var options = base;
            options.client_auth = .optional;
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expect(!duo.server.info().?.peer_authenticated);
        }
        // A client certificate fit for clients authenticates under either policy.
        for ([_]@TypeOf(base.client_auth){ .optional, .required }) |policy| {
            var options = base;
            options.client_auth = policy;
            options.client_cert = true;
            const duo = try Duo.init(gpa, options);
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expect(duo.server.info().?.peer_authenticated);
        }
    }
}
