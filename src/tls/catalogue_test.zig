//! Failure-catalogue tests that cross the TLS layers: each names its F-id and catalogue test.
const std = @import("std");
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
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x10\x00\x0a\x00\x00")));
    // key_share: the extension is six bytes, its share list claims eight.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x0a\x00\x33\x00\x06\x00\x08\x00\x1d\x00\x20")));
    // key_share: one entry claims 32 bytes of key and the list ends after two.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x0c\x00\x33\x00\x08\x00\x06\x00\x1d\x00\x20\xaa\xbb")));
    // server_name: the host name claims more than its list.
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(hello(&buffer, "\x00\x0b\x00\x00\x00\x07\x00\x05\x00\x00\x09ab")));
    // A handshake header claiming more than the message.
    try std.testing.expectError(error.InvalidLength, Messages.body("\x0b\x00\x00\x09\x00\x00"));

    // Certificate: an entry claiming more than the list; the list claiming more than the message.
    var out: [Messages.max_certificates][]const u8 = undefined;
    try std.testing.expectError(error.InvalidLength, Messages.certificate("\x0b\x00\x00\x0a\x00\x00\x00\x06\x00\x00\x09ab\x00\x00", 16, 65536, &out));
    try std.testing.expectError(error.InvalidLength, Messages.certificate("\x0b\x00\x00\x06\x00\x00\x00\x40\x00\x00", 16, 65536, &out));

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
