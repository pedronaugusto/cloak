//! A pin with no authorities (designs/cloak.md §5.2, F141): `Verify.leaf_key` takes certificates
//! and trusts the leaf's key by its pin alone, both roles, TLS 1.3 and 1.2, nothing else of the
//! chain checked; curl's pinned public key with peer verification off.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Duo = @import("../testing/Duo.zig");
const Session = @import("Session.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const Possession = @import("handshake/Possession.zig");
const pki = Duo.pki;
const gpa = std.testing.allocator;

const Version = @FieldType(Duo.Options, "client_max");
const other: [32]u8 = @splat(0x5a);
/// Long past every fixture's notAfter.
const later = pki.time + 40 * 365 * 24 * 60 * 60;

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "F141 catalogue_pin_without_authorities (a client trusts the server's pinned leaf key alone: no name, validity or path checked, TLS 1.3 and 1.2)" {
    for ([_]Duo.Cert{ .p256, .ed25519, .rsa }) |cert| for ([_]Version{ .tls13, .tls12 }) |version| {
        if (cert == .ed25519 and version == .tls12) continue;
        const leaf = switch (cert) {
            .p256 => pki.p256,
            .ed25519 => pki.ed25519,
            else => pki.rsa,
        };
        const pins = [_][32]u8{ other, Duo.pinOf(leaf) };
        // A name the certificate does not carry, at a time it has expired: full verification
        // refuses both, the pinned key takes them.
        const duo = try connect(.{ .cert = cert, .client_leaf_pins = &pins, .identity = "unrelated.example", .time = later, .client_max = version });
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expectEqual(version, info.version);
        try std.testing.expect(info.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 1), info.pin);
        try std.testing.expectEqual(@as(?u16, null), duo.server.info().?.pin);
        var out: [8]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "leaf", try duo.echo(&duo.client, &duo.server, "leaf", &out));
    };
}

test "F141 catalogue_pin_without_authorities (a leaf key no pin names is refused, bad_certificate, TLS 1.3 and 1.2)" {
    for ([_]Version{ .tls13, .tls12 }) |version| {
        const pins = [_][32]u8{ other, Duo.pinOf(pki.p384) };
        const duo = try Duo.init(gpa, .{ .client_leaf_pins = &pins, .client_max = version });
        defer duo.deinit();
        try std.testing.expectError(error.PinMismatch, duo.handshake());
        try std.testing.expectEqual(.bad_certificate, duo.client.diagnostics().alert_sent.?);
    }
    // The pin is the leaf's: the chain's root, pinned, names no leaf.
    const root = [_][32]u8{Duo.pinOf(pki.ca)};
    const duo = try Duo.init(gpa, .{ .client_leaf_pins = &root });
    defer duo.deinit();
    try std.testing.expectError(error.PinMismatch, duo.handshake());
}

test "F141 catalogue_pin_without_authorities (a server trusts a client's pinned leaf key, required and optional, TLS 1.3 and 1.2; an unpinned one refused)" {
    const pins = [_][32]u8{ other, other, Duo.pinOf(pki.client) };
    for ([_]@import("handshake/Server.zig").Auth{ .required, .optional }) |auth| for ([_]Version{ .tls13, .tls12 }) |version| {
        const duo = try connect(.{ .client_auth = auth, .client_cert = true, .server_leaf_pins = &pins, .time = later, .client_max = version });
        defer duo.deinit();
        const server = duo.server.info().?;
        try std.testing.expectEqual(version, server.version);
        try std.testing.expect(server.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 2), server.pin);
    };
    for ([_]Version{ .tls13, .tls12 }) |version| {
        const wrong = [_][32]u8{other};
        const duo = try Duo.init(gpa, .{ .client_auth = .required, .client_cert = true, .server_leaf_pins = &wrong, .client_max = version });
        defer duo.deinit();
        try std.testing.expectError(error.PinMismatch, duo.handshake());
        try std.testing.expectEqual(.bad_certificate, duo.server.diagnostics().alert_sent.?);
    }
    // Optional, and the client sends nothing: unauthenticated, no pin.
    const duo = try connect(.{ .client_auth = .optional, .server_leaf_pins = &pins });
    defer duo.deinit();
    try std.testing.expect(!duo.server.info().?.peer_authenticated);
    try std.testing.expectEqual(@as(?u16, null), duo.server.info().?.pin);
}

test "F141 catalogue_pin_without_authorities (resumption keeps the pin, under the same pins only)" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var ring = try TicketKeys.init(gpa, .{});
    defer ring.deinit();
    try ring.rotate(&@as([32]u8, @splat(0x7b)), certificates.types.instant(pki.time));
    const pins = [_][32]u8{ other, Duo.pinOf(pki.p256) };
    const client_pins = [_][32]u8{Duo.pinOf(pki.client)};
    const options: Duo.Options = .{ .client_leaf_pins = &pins, .cache = &cache, .tickets = &ring, .client_auth = .required, .client_cert = true, .server_leaf_pins = &client_pins };
    {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
    {
        const duo = try connect(options);
        defer duo.deinit();
        const info = duo.client.info().?;
        try std.testing.expect(info.resumed and info.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 1), info.pin);
        const server = duo.server.info().?;
        try std.testing.expect(server.resumed and server.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 0), server.pin);
    }
    // Full verification is another namespace: a full handshake.
    {
        var verifying = options;
        verifying.client_leaf_pins = null;
        verifying.server_leaf_pins = null;
        const duo = try connect(verifying);
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
}

test "F141 catalogue_pin_without_authorities (a raw key under the same pins is another namespace)" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var ring = try TicketKeys.init(gpa, .{});
    defer ring.deinit();
    try ring.rotate(&@as([32]u8, @splat(0x7c)), certificates.types.instant(pki.time));
    const pins = [_][32]u8{Duo.pinOf(pki.p256)};
    {
        const duo = try connect(.{ .server_raw = .both, .client_leaf_pins = &pins, .cache = &cache, .tickets = &ring });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.pin != null);
    }
    {
        // The same server would resume it: only the client's cache key tells the two apart.
        const duo = try connect(.{ .server_raw = .both, .client_raw_pins = &pins, .cache = &cache, .tickets = &ring });
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.resumed);
    }
    const duo = try connect(.{ .server_raw = .both, .client_leaf_pins = &pins, .cache = &cache, .tickets = &ring });
    defer duo.deinit();
    try std.testing.expect(duo.client.info().?.resumed);
}

test "F141 catalogue_pin_without_authorities (options the pins cannot keep are refused)" {
    const pins = [_][32]u8{Duo.pinOf(pki.p256)};
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_leaf_pins = &.{} }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_auth = .required, .server_leaf_pins = &.{} }));
    // A pinned client key needs a certificate request to answer.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_leaf_pins = &pins }));
    // Delegated credentials are full verification's.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_leaf_pins = &pins, .client_accept_delegated = true }));
    // A session's pins beside the trust: the trust's are the only ones.
    var trust = certificates.Trust.init(gpa);
    defer trust.deinit();
    var transport_in: std.Io.Reader = .fixed("");
    var buffer: [64]u8 = undefined;
    var transport_out: std.Io.Writer = .fixed(&buffer);
    var session: Session = undefined;
    try std.testing.expectError(error.InvalidOptions, session.open(gpa, std.testing.io, &transport_in, &transport_out, &.{}, &.{}, .{
        .identity = .none,
        .trust = .{ .leaf_keys = &pins },
        .pins = &pins,
    }));
    try std.testing.expectEqual(@as(usize, 0), transport_out.end);
}

test "F141 catalogue_pin_without_authorities (the pin is the SubjectPublicKeyInfo's SHA-256, of a parsed leaf)" {
    try std.testing.expectEqual(@as(u16, 0), try Possession.pinnedLeaf(pki.p256, &.{Duo.pinOf(pki.p256)}));
    try std.testing.expectError(error.PinMismatch, Possession.pinnedLeaf(pki.p256, &.{Duo.pinOf(pki.p384)}));
    try std.testing.expectError(error.InvalidCertificate, Possession.pinnedLeaf("not a certificate", &.{other}));
}
