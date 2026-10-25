//! `Connection.peerLeaf`: the peer's leaf certificate as the handshake, or a server's
//! post-handshake answer, proved it, both roles and both versions, a cloak client against a
//! cloak server. What RFC 8705 binds a token to.
const std = @import("std");
const types = @import("../certificates.zig").types;
const Duo = @import("../testing/Duo.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const Version = @import("crypto/Suite.zig").Version;
const pki = Duo.pki;

const gpa = std.testing.allocator;

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C3 peerLeaf: a client certificate proved in a TLS 1.3 or 1.2 handshake is the server's peer leaf, the server's the client's" {
    for ([_]Version{ .tls13, .tls12 }) |version| {
        for ([_]bool{ false, true }) |ed25519| {
            const duo = try connect(.{ .client_max = version, .client_suites = if (version == .tls12) &.{.ecdhe_ecdsa_aes_128_gcm_sha256} else @import("crypto/Suite.zig").Suite.default, .client_auth = .required, .client_cert = true, .client_ed25519 = ed25519, .keep_peer_leaf = true });
            defer duo.deinit();
            try std.testing.expectEqual(version, duo.server.info().?.version);
            try std.testing.expectEqualSlices(u8, if (ed25519) pki.client_ed25519 else pki.client, duo.server.peerLeaf().?);
            try std.testing.expectEqualSlices(u8, pki.p256, duo.client.peerLeaf().?);
        }
    }
}

test "C3 peerLeaf: none for a client that presents no certificate, nor before the handshake completes" {
    for ([_]Version{ .tls13, .tls12 }) |version| {
        for ([_]@import("handshake/State.zig").Auth{ .none, .optional }) |auth| {
            const duo = try Duo.init(gpa, .{ .client_max = version, .client_suites = if (version == .tls12) &.{.ecdhe_ecdsa_aes_128_gcm_sha256} else @import("crypto/Suite.zig").Suite.default, .client_auth = auth, .keep_peer_leaf = true });
            defer duo.deinit();
            try std.testing.expect(duo.server.peerLeaf() == null);
            try std.testing.expect(duo.client.peerLeaf() == null);
            try duo.handshake();
            try std.testing.expect(duo.server.peerLeaf() == null);
            try std.testing.expectEqualSlices(u8, pki.p256, duo.client.peerLeaf().?);
        }
    }
}

test "C5 peerLeaf: a resumed session has none, its ticket carrying no certificate" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x11)), types.instant(pki.time));
    var options: Duo.Options = .{ .seed = 1, .cache = &cache, .tickets = &keys, .client_auth = .required, .client_cert = true, .keep_peer_leaf = true };
    const first = try connect(options);
    try std.testing.expectEqualSlices(u8, pki.client, first.server.peerLeaf().?);
    first.deinit();
    options.seed = 2;
    const second = try connect(options);
    defer second.deinit();
    try std.testing.expect(second.server.info().?.resumed);
    try std.testing.expect(second.server.info().?.peer_authenticated);
    try std.testing.expect(second.server.peerLeaf() == null);
    try std.testing.expect(second.client.peerLeaf() == null);
}

test "C3 peerLeaf: none is kept unless asked for" {
    const duo = try connect(.{ .client_auth = .required, .client_cert = true });
    defer duo.deinit();
    try std.testing.expect(duo.server.info().?.peer_authenticated);
    try std.testing.expect(duo.server.peerLeaf() == null);
    try std.testing.expect(duo.client.peerLeaf() == null);
}

test "C10 peerLeaf: a post-handshake answer that proves a certificate sets it; an empty one keeps none" {
    {
        const duo = try connect(.{ .client_cert = true, .client_post_auth = true, .server_post_auth = true, .keep_peer_leaf = true });
        defer duo.deinit();
        try std.testing.expect(duo.server.peerLeaf() == null);
        _ = try duo.server.requestCertificate();
        try duo.pump();
        try std.testing.expectEqual(@as(u64, 1), duo.server.postAuthentication().?.generation);
        try std.testing.expectEqualSlices(u8, pki.client, duo.server.peerLeaf().?);
        // A second answer replaces it with its own.
        _ = try duo.server.requestCertificate();
        try duo.pump();
        try std.testing.expectEqualSlices(u8, pki.client, duo.server.peerLeaf().?);
        // The client's view of the server is the handshake's.
        try std.testing.expectEqualSlices(u8, pki.p256, duo.client.peerLeaf().?);
    }
    {
        const duo = try connect(.{ .client_post_auth = true, .server_post_auth = true, .keep_peer_leaf = true });
        defer duo.deinit();
        _ = try duo.server.requestCertificate();
        try duo.pump();
        try std.testing.expectEqual(@as(u64, 1), duo.server.postAuthentication().?.generation);
        try std.testing.expect(duo.server.peerLeaf() == null);
    }
}
