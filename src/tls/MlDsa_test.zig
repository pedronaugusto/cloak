//! ML-DSA in TLS 1.3 (draft-ietf-tls-mldsa, design section 5.8): server and client certificates
//! of every parameter set, TLS 1.3 only, and the explicit post-quantum authentication policy,
//! which a hybrid key exchange never meets.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Connection = @import("Connection.zig");
const Alert = @import("wire/Alert.zig").Alert;

const gpa = std.testing.allocator;

fn connect(options: Duo.Options) !void {
    const duo = try Duo.init(gpa, options);
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expect(duo.client.info().?.peer_authenticated);
    try std.testing.expectEqual(.tls13, duo.client.info().?.version);
    var buf: [8]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "ml-dsa", try duo.echo(&duo.client, &duo.server, "ml-dsa", &buf));
}

/// Runs a handshake that must fail at `end`; returns that end's diagnostics.
fn refused(options: Duo.Options, end: enum { client, server }) !Connection.Diagnostics {
    const duo = try Duo.init(gpa, options);
    defer duo.deinit();
    // Which end the error came from is read from the ends themselves.
    const completed = if (duo.handshake()) |_| true else |_| false;
    try std.testing.expect(!completed);
    const conn = if (end == .client) &duo.client else &duo.server;
    try std.testing.expectEqual(Connection.Phase.failed, conn.phase());
    return conn.diagnostics();
}

test "C10 ML-DSA server certificates of every parameter set, under an ML-DSA root" {
    for ([_]Duo.Cert{ .mldsa44, .mldsa65, .mldsa87 }) |cert| {
        try connect(.{ .cert = cert });
        // Also when the client offers TLS 1.2 too: it lists ML-DSA for TLS 1.3.
        try connect(.{ .cert = cert, .client_min = .tls12 });
    }
    // An ML-DSA leaf under a classical root, and a classical leaf under an ML-DSA root.
    try connect(.{ .cert = .mldsa44_classical });
    try connect(.{ .cert = .p256_pqca });
}

test "C10 ML-DSA authenticates TLS 1.3 only: a TLS 1.2 handshake has no suite for it" {
    const diagnostics = try refused(.{ .cert = .mldsa65, .client_max = .tls12 }, .server);
    try std.testing.expectEqual(error.NoSharedSuite, diagnostics.reason.?);
    try std.testing.expectEqual(Alert.handshake_failure, diagnostics.alert_sent.?);
}

test "C10 ML-DSA client certificates" {
    try connect(.{ .cert = .mldsa65, .client_auth = .required, .client_cert = true, .client_mldsa = true });
    try connect(.{ .cert = .p256, .client_auth = .required, .client_cert = true, .client_mldsa = true });
}

test "C10 catalogue_pq_group_specific_layout_and_auth_policy: post-quantum authentication is the whole path's, never the key exchange's" {
    // ML-DSA from the leaf's CertificateVerify to the root's signature: met.
    for ([_]Duo.Cert{ .mldsa44, .mldsa65, .mldsa87 }) |cert| try connect(.{ .cert = cert, .client_require_pq_auth = true });
    // A classical signature on the path, with a hybrid key exchange: refused, insufficient_security.
    {
        const diagnostics = try refused(.{ .cert = .mldsa44_classical, .client_require_pq_auth = true, .client_groups = &.{.x25519_mlkem768}, .server_groups = &.{.x25519_mlkem768} }, .client);
        try std.testing.expectEqual(error.PqAuthenticationRequired, diagnostics.reason.?);
        try std.testing.expectEqual(Alert.insufficient_security, diagnostics.alert_sent.?);
    }
    // A classical leaf key under an ML-DSA root: the client offers ML-DSA alone, so the server
    // has no scheme to sign with.
    {
        const diagnostics = try refused(.{ .cert = .p256_pqca, .client_require_pq_auth = true }, .server);
        try std.testing.expectEqual(error.NoSignatureScheme, diagnostics.reason.?);
        try std.testing.expectEqual(Alert.handshake_failure, diagnostics.alert_sent.?);
    }
    // The policy is TLS 1.3's and a verified path's.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_require_pq_auth = true, .client_max = .tls12 }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_require_pq_auth = true, .client_verify_none = true }));
    // A server requiring it of clients: an ML-DSA client certificate passes; a P-256 one has no
    // scheme the server lists and the client sends none.
    try connect(.{ .cert = .mldsa65, .client_auth = .required, .client_cert = true, .client_mldsa = true, .server_require_pq_auth = true });
    {
        const duo = try Duo.init(gpa, .{ .cert = .mldsa65, .client_auth = .required, .client_cert = true, .server_require_pq_auth = true });
        defer duo.deinit();
        try std.testing.expectError(error.CertificateRequired, duo.handshake());
    }
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_auth = .optional, .server_require_pq_auth = true }));
}

test "C10 an ML-DSA-87 handshake's client memory is measured and bounded" {
    var count = @import("shakedown").alloc.Counting.init(gpa);
    const duo = try Duo.init(gpa, .{ .cert = .mldsa87, .client_gpa = count.allocator() });
    defer duo.deinit();
    try duo.handshake();
    duo.client.trim();
    duo.client.trimOutput();
    std.debug.print("\nC10 memory ML-DSA-87 chain: client handshake peak={d} bytes idle heap={d} bytes\n", .{ count.peak_bytes, count.live_bytes });
    // Two certificates of 7.4 and 5.4 KiB, past the 8 KiB chain the 64 KiB target names
    // (designs/cloak.md 7.3), within the 512 KiB cap; the matrix is never held.
    try std.testing.expect(count.peak_bytes <= 96 * 1024);
    try std.testing.expect(count.live_bytes <= 2048);
}
