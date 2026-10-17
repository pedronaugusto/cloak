//! Open code points, F32's negotiation allowlist: the IANA-numbered types (`Group`, `Suite`,
//! `SignatureScheme`, the SRTP profiles) are open, so any number is one of them and a value named
//! later is no break, and `supported` says what cloak speaks. A number cloak does not speak is
//! never taken from a caller's options, a peer's selection or a sealed ticket; a peer's list may
//! carry any number (GREASE, RFC 8701), and the rest of it is answered.
const std = @import("std");
const tls = @import("../tls.zig");
const Hello = @import("handshake/Hello.zig");
const Messages12 = @import("handshake/Messages12.zig");
const Possession = @import("handshake/Possession.zig");
const Ticket = @import("resumption/Ticket.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const certificates = @import("../certificates.zig");
const Duo = @import("../testing/Duo.zig");
const ServerPair = @import("../testing/ServerPair.zig").ServerPair;
const pki = @import("../testing/Peer.zig").pki;
const gpa = std.testing.allocator;

/// Numbers no type here names: GREASE, and registered values cloak does not speak (ffdhe2048,
/// TLS_NULL_WITH_NULL_NULL, TLS_AES_128_CCM_8_SHA256, rsa_pkcs1_sha1, SRTP_NULL_HMAC_SHA1_80).
const grease: u16 = 0x0a0a;
const ffdhe2048: tls.Group = @enumFromInt(0x0100);
const ccm8: tls.Suite = @enumFromInt(0x1305);
const sha1: tls.SignatureScheme = @enumFromInt(0x0201);
const srtp_null: tls.dtls.Datagram.Srtp = @enumFromInt(0x0005);

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist (open code points: what cloak speaks)" {
    for (std.enums.values(tls.Group)) |group| {
        try std.testing.expect(group.supported());
        try std.testing.expect(group.clientShareLength() != null and group.serverShareLength() != null);
        try std.testing.expect(group.hybrid() or group.classical() or group == .mlkem768 or group == .mlkem1024);
    }
    for (std.enums.values(tls.Suite)) |suite| try std.testing.expect(suite.supported() and suite.version() != null);
    for (std.enums.values(tls.SignatureScheme)) |scheme| try std.testing.expect(scheme.supported());
    for (std.enums.values(tls.dtls.Datagram.Srtp)) |profile| try std.testing.expect(profile.supported() and profile.keyLength() != null and profile.saltLength() != null);
    for ([_]tls.Group{ @enumFromInt(grease), ffdhe2048, @enumFromInt(0) }) |group| {
        try std.testing.expect(!group.supported() and !group.hybrid() and !group.classical());
        try std.testing.expect(group.clientShareLength() == null and group.serverShareLength() == null);
    }
    for ([_]tls.Suite{ @enumFromInt(grease), ccm8, @enumFromInt(0), @enumFromInt(0x00ff) }) |suite| {
        try std.testing.expect(!suite.supported() and suite.version() == null and suite.tls13() == null and suite.tls12() == null);
    }
    for ([_]tls.SignatureScheme{ @enumFromInt(grease), sha1 }) |scheme| try std.testing.expect(!scheme.supported());
    try std.testing.expect(!srtp_null.supported() and srtp_null.keyLength() == null);
    // The defaults name only what cloak speaks.
    for (tls.Group.default) |group| try std.testing.expect(group.supported());
    for (tls.Suite.default) |suite| try std.testing.expect(suite.supported());
}

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist (open code points: options)" {
    // Listed beside ones it speaks, a number cloak does not speak is refused, at either end.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_groups = &.{ .x25519, ffdhe2048 } }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_groups = &.{ ffdhe2048, .x25519 } }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_suites = &.{ .aes_128_gcm_sha256, ccm8 } }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_suites = &.{ @enumFromInt(grease), .aes_128_gcm_sha256 } }));
    // Not even as the only TLS 1.2 or TLS 1.3 suite, where it would count toward a version.
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .suites = &.{ .aes_128_gcm_sha256, @enumFromInt(0xc009) } }));
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .transport = .datagram, .srtp = &.{ .aes128_cm_hmac_sha1_80, srtp_null } }));
    try Hello.validate(.{ .transport = .datagram, .srtp = &.{.aes128_cm_hmac_sha1_80} });
}

/// The fixture ServerHello (TLS_AES_128_GCM_SHA256, X25519) with its suite or its key_share
/// group replaced.
fn serverHello(out: *[fixture.len]u8, suite: ?u16, group: ?u16) []const u8 {
    out.* = fixture.*;
    if (suite) |id| std.mem.writeInt(u16, out[39..41], id, .big);
    if (group) |id| {
        const at = std.mem.find(u8, out[44..], &.{ 0, 51 }).? + 44;
        std.mem.writeInt(u16, out[at + 4 ..][0..2], id, .big);
    }
    return out;
}
const fixture = @embedFile("handshake/testdata/server-hello.bin");

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist (open code points: a peer's selection)" {
    const share: [32]u8 = @splat(1);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &share }};
    var buffer: [fixture.len]u8 = undefined;
    _ = try Hello.server(serverHello(&buffer, null, null), "", &shares, .{}, .{});
    // A ServerHello selecting a suite or group cloak does not speak (so never offered).
    for ([_]u16{ grease, @backingInt(ccm8), 0x0000 }) |suite| {
        try std.testing.expectError(error.UnofferedSelection, Hello.server(serverHello(&buffer, suite, null), "", &shares, .{}, .{}));
    }
    for ([_]u16{ grease, @backingInt(ffdhe2048) }) |group| {
        try std.testing.expectError(error.UnofferedSelection, Hello.server(serverHello(&buffer, null, group), "", &shares, .{}, .{}));
    }
    // A TLS 1.2 ServerKeyExchange on a group cloak does not speak.
    var params_buf: [64]u8 = undefined;
    var ske_buf: [128]u8 = undefined;
    for ([_]tls.Group{ ffdhe2048, @enumFromInt(grease) }) |group| {
        const params = try Messages12.buildParams(&params_buf, group, &share);
        const ske = try Messages12.buildServerKeyExchange(&ske_buf, params, 0x0403, "sig");
        try std.testing.expectError(error.IllegalParameter, Messages12.serverKeyExchange(ske));
    }
    // A CertificateVerify or ServerKeyExchange signed under a scheme cloak does not speak, even
    // when a caller's list names it.
    const offered = [_]tls.SignatureScheme{ sha1, @enumFromInt(grease), .ecdsa_p256_sha256 };
    for ([_]u16{ @backingInt(sha1), grease }) |scheme| {
        try std.testing.expectError(error.UnofferedScheme, Possession.verify(scheme, &offered, pki.p256, "content", "signature"));
        try std.testing.expectError(error.UnofferedScheme, Possession.verifyMessage12(scheme, &offered, pki.p256, "content", "signature"));
        try std.testing.expectError(error.UnofferedScheme, Possession.verifyDigest12(scheme, &offered, pki.p256, &@as([32]u8, @splat(0)), "signature"));
        const leaf = try certificates.certificate.parse(pki.p256, .{});
        try std.testing.expectError(error.UnofferedScheme, Possession.bind(@enumFromInt(scheme), leaf.public_key));
    }
}

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist (open code points: a peer's list)" {
    // A client listing GREASE and ffdhe2048 among its groups and GREASE among its schemes is
    // answered with what both speak.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(gpa, .{
        .groups = &.{ @enumFromInt(grease), ffdhe2048, .x25519, .p256 },
        .shares = &.{.x25519},
        .schemes = &.{ grease, 0x0201, 0x0403 },
    }, .{});
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(tls.Group.x25519, pair.conn.info().?.group);
    try std.testing.expectEqual(@as(u16, 0x0403), pair.client.certificate_verify_scheme);
}

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist (open code points: a sealed ticket)" {
    // A ticket whose state names a group cloak does not speak opens as no ticket: the server
    // seals only what it negotiated, so only a key that sealed something else gets here.
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(3)), certificates.types.instant(1000));
    var snapshot = keys.acquire().?;
    defer snapshot.release();
    var state: Ticket.State = .{ .suite = .aes_128_gcm_sha256, .group = ffdhe2048, .issued = 1000, .expires = 2000, .age_add = 1, .policy = @splat(9) };
    defer state.deinit();
    @memset(state.secret.exposeMut(), 0x5a);
    var buffer: [Ticket.max_length]u8 = undefined;
    const sealed = try Ticket.seal(snapshot.ring().issuing(1000).?, &@as([16]u8, @splat(4)), &state, &buffer);
    var opened: Ticket.State = undefined;
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), sealed, 1001, &opened));
    state.group = .x25519;
    const good = try Ticket.seal(snapshot.ring().issuing(1000).?, &@as([16]u8, @splat(4)), &state, &buffer);
    try Ticket.open(snapshot.ring(), good, 1001, &opened);
    opened.deinit();
}
