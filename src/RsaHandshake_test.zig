//! TLS 1.3 handshakes with RSA certificates signed in-package: the server's CertificateVerify
//! and a client's answer to a CertificateRequest, each checked by the scripted peer with std.
const std = @import("std");
const certificates = @import("certificates.zig");
const Exchange = @import("tls/crypto/Exchange.zig");
const Connection = @import("tls/Connection.zig");
const server_module = @import("testing/ServerPair.zig");
const ServerPair = server_module.ServerPair;
const Pair = @import("testing/Pair.zig").Pair;
const pki = server_module.pki;

test "RSA server certificate: cloak signs rsa_pss_rsae, SHA-256 first among what the client accepts" {
    const cases = .{
        .{ &[_]u16{ 0x0806, 0x0805, 0x0804 }, 0x0804 },
        .{ &[_]u16{ 0x0403, 0x0805, 0x0806 }, 0x0805 },
        .{ &[_]u16{0x0806}, 0x0806 },
    };
    inline for (cases) |case| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .schemes = case[0] }, .{ .cert = .rsa });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(Connection.Phase.connected, pair.conn.phase());
        try std.testing.expect(pair.client.certificate_verify_ok and pair.client.server_finished_ok);
        try std.testing.expectEqual(@as(u16, case[1]), pair.client.certificate_verify_scheme);
        // Signed by the key the identity holds: nothing was asked of the driver.
        try std.testing.expectEqual(@as(usize, 0), pair.signed);
    }
}

test "RSA server certificate: the signature noise comes with the key exchange entropy" {
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .shares = &.{.x25519} }, .{ .cert = .rsa });
    defer pair.deinit();
    try pair.client.start();
    _ = try pair.conn.receive(pair.client.pending());
    _ = try pair.service();
    try std.testing.expectEqual(32 + Exchange.respondEntropyLength(.x25519) + certificates.PrivateKey.max_noise, pair.entropy_requested);
}

test "RSA client certificate: cloak answers a CertificateRequest with rsa_pss_rsae" {
    const gpa = std.testing.allocator;
    const P = Pair(.aes_128_gcm_sha256);
    const key = try certificates.PrivateKey.parse(gpa, pki.rsa_pem, .{ .entropy = certificates.PrivateKey.Entropy.fromIo(&std.testing.io) });
    defer key.deinit();
    const auth = try certificates.ClientAuth.init(gpa, &.{pki.rsa}, key, .{});
    defer auth.deinit();
    const pair = try P.init(gpa, .{ .request_client_cert = true, .request_schemes = &.{ 0x0403, 0x0806, 0x0804 } }, .{ .client_auth = auth });
    defer pair.deinit();
    try pair.handshake();
    try std.testing.expectEqual(@as(usize, 1), pair.peer.client_certificates);
    try std.testing.expect(pair.peer.client_signature_ok and pair.peer.client_finished_ok);
    try std.testing.expectEqualSlices(u8, pki.rsa, pair.peer.client_chain.items);
    try std.testing.expectEqual(@as(usize, 0), pair.signed);
    // The client's first entropy request carried the RSA noise on top of what it draws anyway.
    const bare = try P.init(gpa, .{ .request_client_cert = true }, .{});
    defer bare.deinit();
    try bare.handshake();
    try std.testing.expectEqual(bare.first_entropy + 96, pair.first_entropy);
}

test "RSA client certificate: a request without an RSA scheme gets an empty Certificate" {
    const gpa = std.testing.allocator;
    const key = try certificates.PrivateKey.parse(gpa, pki.rsa_pem, .{ .entropy = certificates.PrivateKey.Entropy.fromIo(&std.testing.io) });
    defer key.deinit();
    const auth = try certificates.ClientAuth.init(gpa, &.{pki.rsa}, key, .{});
    defer auth.deinit();
    const pair = try Pair(.aes_128_gcm_sha256).init(gpa, .{ .request_client_cert = true }, .{ .client_auth = auth });
    defer pair.deinit();
    try pair.handshake();
    try std.testing.expectEqual(@as(usize, 0), pair.peer.client_certificates);
    try std.testing.expect(pair.peer.client_finished_ok);
}
