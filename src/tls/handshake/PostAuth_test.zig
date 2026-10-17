//! The post-handshake exchange alone; the connection-level tests are in `PostAuth_test.zig` of
//! `src/tls` and the failure catalogue.
const std = @import("std");
const PostAuth = @import("PostAuth.zig");
const Transcripts = @import("Transcripts.zig");

fn base() Transcripts {
    var transcripts: Transcripts = .{};
    transcripts.commit("\x01\x00\x00\x02hi") catch unreachable;
    transcripts.select(.aes_128_gcm_sha256);
    return transcripts;
}

test "C10 post-handshake requests carry their own context, one outstanding at a time" {
    const gpa = std.testing.allocator;
    const transcripts = base();
    const post = try PostAuth.init(gpa, .server, .aes_128_gcm_sha256, &transcripts, false, false);
    defer post.deinit();
    var buf: [256]u8 = undefined;
    const first = try post.request(&buf);
    try std.testing.expectEqual(@as(u64, 1), first.number);
    // The context is the request's number: unique on the connection.
    try std.testing.expectEqualSlices(u8, &.{ 13, 0, 0 }, first.message[0..3]);
    try std.testing.expectEqualSlices(u8, &.{ 8, 0, 0, 0, 0, 0, 0, 0, 1 }, first.message[4..13]);
    post.publish();
    try std.testing.expectError(error.RequestOutstanding, post.request(&buf));
    try std.testing.expectEqual(PostAuth.Outcome{ .generation = 0, .authenticated = false }, post.result());
}

test "C10 post-handshake auth is a stream's: QUIC and datagrams refuse the options" {
    const Hello = @import("Hello.zig");
    const Server = @import("Server.zig");
    try Hello.validate(.{ .post_handshake_auth = true });
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .post_handshake_auth = true, .transport = .quic, .alpn = &.{"h3"} }));
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .post_handshake_auth = true, .transport = .datagram }));
    const gpa = std.testing.allocator;
    const pki = @import("../../testing/Peer.zig").pki;
    const certificates = @import("../../certificates.zig");
    const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
    defer key.deinit();
    const identity = try certificates.Identity.init(gpa, &.{ pki.p256, pki.ca }, key, .{});
    defer identity.deinit();
    const credentials = [_]Server.Credential{.{ .identity = identity }};
    for ([_]@FieldType(Server.Options, "transport"){ .quic, .datagram }) |transport| {
        try std.testing.expectError(error.InvalidOptions, Server.init(gpa, .{ .credentials = &credentials, .transport = transport, .alpn = &.{"h3"}, .post_handshake_auth = true }));
    }
    const server = try Server.init(gpa, .{ .credentials = &credentials, .post_handshake_auth = true });
    server.deinit();
}
