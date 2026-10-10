const std = @import("std");
const certificates = @import("cloak.certificates");
const Session = @import("Session.zig");
const Connection = @import("Connection.zig");
const peer_module = @import("../testing/Peer.zig");
const Loopback = @import("../testing/Loopback.zig").Loopback;

const pki = peer_module.pki;

fn options(snapshot: certificates.Trust.Snapshot) Session.Options {
    return .{ .identity = .{ .dns = "example.com" }, .trust = .{ .snapshot = snapshot }, .clock = .{ .fixed = pki.time }, .alpn = &.{ "h2", "http/1.1" } };
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
    try session.open(gpa, std.testing.io, &transport.reader, &transport.writer, options(snapshot), &read_buffer, &write_buffer);
    defer session.deinit();
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
        try session.open(gpa, std.testing.io, &transport.reader, &transport.writer, settings, &read_buffer, &.{});
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
