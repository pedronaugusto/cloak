const std = @import("std");
const certificates = @import("../certificates.zig");
const Session = @import("Session.zig");
const Connection = @import("Connection.zig");
const Alert = @import("wire/Alert.zig").Alert;
const SignatureScheme = @import("handshake/Hello.zig").SignatureScheme;
const peer_module = @import("../testing/Peer.zig");
const Loopback = @import("../testing/Loopback.zig").Loopback;

const pki = peer_module.pki;

fn options(snapshot: certificates.Trust.Snapshot) Session.Options {
    return .{ .identity = .{ .dns = "example.com" }, .trust = .{ .snapshot = snapshot }, .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) }, .alpn = &.{ "h2", "http/1.1" } };
}

test "C2 session streams plaintext both ways over std.Io and closes cleanly" {
    const gpa = std.testing.allocator;
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.ca, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    var peer = peer_module.Peer(.aes_128_gcm_sha256).init(gpa, .{ .alpn = "h2", .tickets = 2 });
    defer peer.deinit();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [256]u8 = undefined;
    var write_buffer: [256]u8 = undefined;
    try session.open(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &write_buffer, options(snapshot));
    defer session.deinit();
    // A kept session is read from a later task's Io.
    session.rebind(std.testing.io);
    try std.testing.expectEqualSlices(u8, "h2", session.info().alpn);
    try std.testing.expect(session.info().peer_authenticated);
    try session.writer().writeAll("GET / HTTP/1.1\r\n\r\n");
    try session.writer().flush();
    try std.testing.expectEqualSlices(u8, "GET / HTTP/1.1\r\n\r\n", peer.received.items);
    try peer.send("HTTP/1.1 200 OK\r\n\r\n");
    var line: [32]u8 = undefined;
    const n = try session.reader().readSliceShort(line[0..19]);
    try std.testing.expectEqualSlices(u8, "HTTP/1.1 200 OK\r\n\r\n", line[0..n]);
    try peer.closeNotify();
    try std.testing.expectEqual(@as(usize, 0), try session.reader().readSliceShort(&line));
    try session.finish();
    try std.testing.expect(peer.close_notify);
}

test "C2 session treats a bare transport end as truncation unless allowed" {
    const gpa = std.testing.allocator;
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.ca, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    inline for (.{ Session.Eof.strict, Session.Eof.allow }) |eof| {
        var peer = peer_module.Peer(.aes_128_gcm_sha256).init(gpa, .{});
        defer peer.deinit();
        var transport: Loopback(@TypeOf(peer)) = undefined;
        var transport_read: [4096]u8 = undefined;
        transport.init(&peer, &transport_read, &.{});
        var session: Session = undefined;
        var settings = options(snapshot);
        settings.eof = eof;
        var read_buffer: [64]u8 = undefined;
        try session.open(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &.{}, settings);
        defer session.deinit();
        var line: [8]u8 = undefined;
        if (eof == .strict) {
            try std.testing.expectError(error.ReadFailed, session.reader().readSliceShort(&line));
            try std.testing.expectEqual(error.Truncated, session.failure.?);
        } else {
            try std.testing.expectEqual(@as(usize, 0), try session.reader().readSliceShort(&line));
        }
    }
}

const Server = @import("handshake/Server.zig");
const client_module = @import("../testing/ClientPeer.zig");

fn signWithFixtures(_: ?*anyopaque, request: Session.SignRequest, out: []u8) error{SigningFailed}!usize {
    if (request.scheme != .ecdsa_p256_sha256 or request.prehashed) return error.SigningFailed;
    const content = request.content;
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const secret = Ecdsa.SecretKey.fromBytes(pki.p256_secret[0..32].*) catch return error.SigningFailed;
    const kp = Ecdsa.KeyPair.fromSecretKey(secret) catch return error.SigningFailed;
    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (kp.sign(content, null) catch return error.SigningFailed).toDer(&der);
    @memcpy(out[0..sig.len], sig);
    return sig.len;
}

test "C3 session accepts over std.Io, serves a request and closes cleanly" {
    const gpa = std.testing.allocator;
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    const identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};
    var peer = client_module.ClientPeer(.aes_128_gcm_sha256).init(gpa, .{ .alpn = &.{ "h2", "http/1.1" } }, 5);
    defer peer.deinit();
    try peer.start();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [256]u8 = undefined;
    var write_buffer: [256]u8 = undefined;
    try session.accept(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &write_buffer, .{
        .credentials = &credentials,
        .alpn = &.{ "http/1.1", "h2" },
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
    });
    defer session.deinit();
    try std.testing.expectEqualSlices(u8, "http/1.1", session.info().alpn);
    try std.testing.expect(!session.info().peer_authenticated);
    try std.testing.expect(peer.certificate_verify_ok and peer.server_finished_ok);
    try peer.send("GET / HTTP/1.1\r\n\r\n");
    var line: [32]u8 = undefined;
    const n = try session.reader().readSliceShort(line[0..18]);
    try std.testing.expectEqualSlices(u8, "GET / HTTP/1.1\r\n\r\n", line[0..n]);
    try session.writer().writeAll("HTTP/1.1 200 OK\r\n\r\n");
    try session.writer().flush();
    try std.testing.expectEqualSlices(u8, "HTTP/1.1 200 OK\r\n\r\n", peer.received.items);
    try peer.closeNotify();
    try std.testing.expectEqual(@as(usize, 0), try session.reader().readSliceShort(&line));
    try session.finish();
    try std.testing.expect(peer.close_notify);
}

test "C3 session sends the alert for a failed handshake before it returns" {
    const gpa = std.testing.allocator;
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    const identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};
    // The client offers an application protocol the server does not serve.
    var peer = client_module.ClientPeer(.aes_128_gcm_sha256).init(gpa, .{ .alpn = &.{"h3"} }, 5);
    defer peer.deinit();
    try peer.start();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [64]u8 = undefined;
    var report: Session.Diagnostics = .{};
    try std.testing.expectError(error.NoApplicationProtocol, session.accept(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &.{}, .{
        .credentials = &credentials,
        .alpn = &.{"h2"},
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
        .diagnostics = &report,
    }));
    try std.testing.expectEqual(@as(?u8, 120), peer.plain_alert);
    // The session is gone, and the report says what it saw.
    try std.testing.expectEqual(@as(?Alert, .no_application_protocol), report.alert_sent);
    try std.testing.expectEqual(@as(?Alert, null), report.alert_received);
    try std.testing.expectEqual(@as(?Connection.Error, error.NoApplicationProtocol), report.reason);
    try std.testing.expect(!report.certificate_requested);
}

test "C3 session accept needs a signer for an identity without a key, and uses it" {
    const gpa = std.testing.allocator;
    const identity = try certificates.Identity.initExternal(gpa, &.{ pki.p256, pki.ca }, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};
    var peer = client_module.ClientPeer(.aes_128_gcm_sha256).init(gpa, .{}, 5);
    defer peer.deinit();
    try peer.start();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [64]u8 = undefined;
    try std.testing.expectError(error.SignerRequired, session.accept(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &.{}, .{
        .credentials = &credentials,
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
    }));
    try session.accept(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &.{}, .{
        .credentials = &credentials,
        .signer = .{ .sign = signWithFixtures },
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
    });
    defer session.deinit();
    try std.testing.expect(peer.certificate_verify_ok and peer.server_finished_ok);
}

test "C3 session accept reports a signer that fails as a failed handshake" {
    const gpa = std.testing.allocator;
    const identity = try certificates.Identity.initExternal(gpa, &.{ pki.p256, pki.ca }, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};
    var peer = client_module.ClientPeer(.aes_128_gcm_sha256).init(gpa, .{}, 5);
    defer peer.deinit();
    try peer.start();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [64]u8 = undefined;
    const failing = struct {
        fn sign(_: ?*anyopaque, _: Session.SignRequest, _: []u8) error{SigningFailed}!usize {
            return error.SigningFailed;
        }
    };
    try std.testing.expectError(error.SigningFailed, session.accept(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &.{}, .{
        .credentials = &credentials,
        .signer = .{ .sign = failing.sign },
        .clock = .{ .fixed = .fromNanoseconds(@as(i96, pki.time) * std.time.ns_per_s) },
    }));
    try std.testing.expect(!peer.server_finished_ok);
}

test "C2 session reports a rejected server chain as the alert it sent" {
    const gpa = std.testing.allocator;
    // Trust a root that did not sign the server's chain.
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.p384, .{});
    const stranger = try trust.freeze();
    defer stranger.deinit();
    var peer = peer_module.Peer(.aes_128_gcm_sha256).init(gpa, .{});
    defer peer.deinit();
    var transport: Loopback(@TypeOf(peer)) = undefined;
    var transport_read: [4096]u8 = undefined;
    transport.init(&peer, &transport_read, &.{});
    var session: Session = undefined;
    var read_buffer: [64]u8 = undefined;
    var report: Session.Diagnostics = .{};
    var settings = options(stranger);
    settings.diagnostics = &report;
    try std.testing.expectError(error.VerificationRejected, session.open(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &.{}, settings));
    try std.testing.expectEqual(@as(?Alert, .unknown_ca), report.alert_sent);
    try std.testing.expectEqual(@as(?Connection.Error, error.VerificationRejected), report.reason);
}

/// A transport whose reads fail the way a cancelled `std.Io` read does: `ReadFailed`, with the
/// cause kept by the transport.
const CancelledTransport = struct {
    buffer: [64]u8 = undefined,
    reader: std.Io.Reader = .{ .vtable = &.{ .stream = stream }, .buffer = &.{}, .seek = 0, .end = 0 },
    writer: std.Io.Writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} },
    err: ?anyerror = null,
    fn stream(r: *std.Io.Reader, _: *std.Io.Writer, _: std.Io.Limit) std.Io.Reader.StreamError!usize {
        const self: *CancelledTransport = @fieldParentPtr("reader", r);
        self.err = error.Canceled;
        return error.ReadFailed;
    }
    fn drain(_: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
        var n: usize = 0;
        for (data[0 .. data.len - 1]) |slice| n += slice.len;
        return n + data[data.len - 1].len * splat;
    }
};

test "a cancelled transport read ends open with ReadFailed and releases the connection" {
    const gpa = std.testing.allocator;
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    try trust.addDer(pki.ca, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    var transport: CancelledTransport = .{};
    transport.reader.buffer = &transport.buffer;
    var session: Session = undefined;
    var read_buffer: [256]u8 = undefined;
    var write_buffer: [256]u8 = undefined;
    try std.testing.expectError(error.ReadFailed, session.open(gpa, std.testing.io, &transport.reader, &transport.writer, &read_buffer, &write_buffer, options(snapshot)));
    try std.testing.expectEqual(@as(?anyerror, error.Canceled), transport.err);
    // The testing allocator reports anything open left behind.
}
