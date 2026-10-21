//! A credential's own signature schemes (`Credential.schemes`, `ClientCredential.schemes`): the
//! schemes its key signs under, in that end's order, restricting and reordering cloak's; and
//! `Info.peer_scheme`, the scheme the peer proved possession under.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Hello = @import("handshake/Hello.zig");
const Possession = @import("handshake/Possession.zig");

const gpa = std.testing.allocator;

fn versions(tls12: bool, base: Duo.Options) Duo.Options {
    var options = base;
    if (tls12) {
        options.client_max = .tls12;
        options.server_max = .tls12;
    }
    return options;
}

test "C2 a server credential signs under its own schemes, in its order, both versions" {
    const Case = struct { tls12: bool, own: []const Hello.SignatureScheme, signed: Hello.SignatureScheme };
    for ([_]Case{
        .{ .tls12 = false, .own = &.{}, .signed = .rsa_pss_rsae_sha256 },
        // PKCS#1 v1.5 is TLS 1.2's alone: TLS 1.3 takes the next.
        .{ .tls12 = false, .own = &.{ .rsa_pkcs1_sha384, .rsa_pss_rsae_sha512 }, .signed = .rsa_pss_rsae_sha512 },
        .{ .tls12 = true, .own = &.{}, .signed = .rsa_pss_rsae_sha256 },
        .{ .tls12 = true, .own = &.{ .rsa_pkcs1_sha384, .rsa_pss_rsae_sha512 }, .signed = .rsa_pkcs1_sha384 },
    }) |case| {
        const duo = try Duo.init(gpa, versions(case.tls12, .{ .cert = .rsa, .server_schemes = case.own }));
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(case.signed, duo.client.info().?.peer_scheme.?);
        try std.testing.expectEqual(null, duo.server.info().?.peer_scheme);
    }
}

test "C2 a client credential signs under its own schemes, both versions" {
    const Case = struct { tls12: bool, own: []const Hello.SignatureScheme, signed: Hello.SignatureScheme };
    for ([_]Case{
        .{ .tls12 = false, .own = &.{}, .signed = .ecdsa_p256_sha256 },
        // TLS 1.2 names a hash, not a curve (RFC 8446 section 4.2.3): a P-256 key signs under
        // ecdsa_secp384r1_sha384 there.
        .{ .tls12 = true, .own = &.{}, .signed = .ecdsa_p256_sha256 },
        .{ .tls12 = true, .own = &.{ .ed25519, .ecdsa_p384_sha384 }, .signed = .ecdsa_p384_sha384 },
    }) |case| {
        const duo = try Duo.init(gpa, versions(case.tls12, .{ .client_cert = true, .client_auth = .required, .client_schemes = case.own }));
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(case.signed, duo.server.info().?.peer_scheme.?);
    }
}

test "C2 a credential none of whose own schemes fits is passed over" {
    // The P-256 credential names a scheme TLS 1.3 binds to P-384: the server answers with the
    // next credential, the RSA one.
    const duo = try Duo.init(gpa, .{ .server_schemes = &.{.ecdsa_p384_sha384}, .server_also = &.{.rsa} });
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expectEqual(1, duo.server.info().?.credential.?);
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha256, duo.client.info().?.peer_scheme.?);
    // A client whose one credential fits no scheme answers with an empty Certificate.
    const client = try Duo.init(gpa, .{ .client_cert = true, .client_auth = .optional, .client_schemes = &.{.ecdsa_p384_sha384} });
    defer client.deinit();
    try client.handshake();
    try std.testing.expect(!client.server.info().?.peer_authenticated);
    try std.testing.expectEqual(null, client.server.info().?.peer_scheme);
}

test "C2 a credential names at most max_schemes schemes" {
    const many: [Possession.max_schemes + 1]Hello.SignatureScheme = @splat(.ecdsa_p256_sha256);
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_schemes = &many }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_cert = true, .client_schemes = &many }));
}
