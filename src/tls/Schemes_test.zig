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

test "C2 the schemes a client takes from the server restrict what it offers and what it accepts" {
    for ([_]bool{ false, true }) |tls12| {
        // The client takes SHA-384 PSS alone: the server, whose own first choice is SHA-256, signs
        // under it.
        const duo = try Duo.init(gpa, versions(tls12, .{ .cert = .rsa, .client_peer_schemes = &.{ .ecdsa_p256_sha256, .rsa_pss_rsae_sha384 } }));
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha384, duo.client.info().?.peer_scheme.?);
    }
    // A server whose credential signs only outside the client's list has no scheme to sign with.
    const refused = try Duo.init(gpa, .{ .cert = .rsa, .server_schemes = &.{.rsa_pss_rsae_sha256}, .client_peer_schemes = &.{.rsa_pss_rsae_sha384} });
    defer refused.deinit();
    try std.testing.expectError(error.NoSignatureScheme, refused.handshake());
}

test "C2 the schemes a server takes from the client restrict its CertificateRequest" {
    {
        // TLS 1.2 names a hash, not a curve: the P-256 client signs under SHA-384, the one listed.
        const duo = try Duo.init(gpa, versions(true, .{ .client_cert = true, .client_auth = .required, .server_peer_schemes = &.{.ecdsa_p384_sha384} }));
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p384_sha384, duo.server.info().?.peer_scheme.?);
    }
    {
        // TLS 1.3 binds the curve: the P-256 client has no listed scheme and answers with no
        // certificate, which an optional request takes.
        const duo = try Duo.init(gpa, .{ .client_cert = true, .client_auth = .optional, .server_peer_schemes = &.{.ecdsa_p384_sha384} });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expect(!duo.server.info().?.peer_authenticated);
    }
}

test "C2 the schemes taken from the peer must leave some to list" {
    // PKCS#1 v1.5 alone leaves a TLS 1.3 hello nothing; past `max_peer_schemes`, too many.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_min = .tls13, .client_peer_schemes = &.{.rsa_pkcs1_sha256} }));
    const many: [Hello.max_peer_schemes + 1]Hello.SignatureScheme = @splat(.ecdsa_p256_sha256);
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_peer_schemes = &many }));
    // A server asking for certificates needs a listed scheme in some version it speaks; a
    // handshake of a version its list leaves nothing ends with handshake_failure.
    const sha1: Hello.SignatureScheme = @fromBackingInt(0x0201);
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_auth = .optional, .server_peer_schemes = &.{sha1} }));
    // The server speaks both versions, and SHA-512 PSS leaves its TLS 1.2 request nothing.
    const tls12 = try Duo.init(gpa, .{ .client_max = .tls12, .client_auth = .optional, .server_peer_schemes = &.{.rsa_pss_rsae_sha512} });
    defer tls12.deinit();
    try std.testing.expectError(error.NoSignatureScheme, tls12.handshake());
}

test "P-521: a server certificate on P-521 signs ecdsa_secp521r1_sha512 in TLS 1.3, ECDSA in 1.2, and secp521r1 agrees when both list it" {
    const Group = @import("crypto/Group.zig").Group;
    const groups: []const Group = &.{.p521};
    const Case = struct { tls12: bool, signed: Hello.SignatureScheme };
    for ([_]Case{
        .{ .tls12 = false, .signed = .ecdsa_p521_sha512 },
        // TLS 1.2's ServerKeyExchange: the curve's own hash first.
        .{ .tls12 = true, .signed = .ecdsa_p521_sha512 },
    }) |case| {
        const duo = try Duo.init(gpa, versions(case.tls12, .{ .cert = .p521, .client_groups = groups, .server_groups = groups }));
        defer duo.deinit();
        try duo.handshake();
        const info = duo.client.info().?;
        try std.testing.expectEqual(case.signed, info.peer_scheme.?);
        try std.testing.expectEqual(Group.p521, info.group.?);
    }
    // The default groups do not list secp521r1: the certificate still signs under its scheme.
    const duo = try Duo.init(gpa, .{ .cert = .p521 });
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p521_sha512, duo.client.info().?.peer_scheme.?);
    try std.testing.expect(duo.client.info().?.group.? != Group.p521);
}
