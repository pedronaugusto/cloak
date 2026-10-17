//! Delegated credentials (RFC 9345): the format, the receiver's checks, issuing, and the
//! Certificate message's leaf extension.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const Delegation = @import("Delegation.zig");
const Messages = @import("Messages.zig");
const Hello = @import("Hello.zig");
const Writer = @import("../wire/Writer.zig");
const pki = @import("../../testing/Peer.zig").pki;
const gpa = std.testing.allocator;

const day = 24 * 60 * 60;

fn identityOf(leaf: []const u8, key_pem: []const u8) !certificates.Identity {
    const key = try certificates.PrivateKey.parse(gpa, key_pem, .{});
    defer key.deinit();
    return certificates.Identity.init(gpa, &.{ leaf, pki.dc_ca }, key, .{});
}

fn p384Spki() []const u8 {
    return (certificates.certificate.parse(pki.p384, .{}) catch unreachable).spki; // unreachable: test PKI
}

fn notBefore(leaf: []const u8) i64 {
    return (certificates.certificate.parse(leaf, .{}) catch unreachable).not_before; // unreachable: test PKI
}

fn notAfter(leaf: []const u8) i64 {
    return (certificates.certificate.parse(leaf, .{}) catch unreachable).not_after; // unreachable: test PKI
}

/// A credential signed by `identity`'s key as given, with none of `issue`'s checks: what a peer
/// may send.
fn forge(identity: certificates.Identity, role: Delegation.Role, valid_time: u32, scheme: u16, algorithm: Hello.SignatureScheme, spki: []const u8) ![]u8 {
    var credential_buf: [512]u8 = undefined;
    var w: Writer = .{ .bytes = &credential_buf };
    try w.int(u32, valid_time);
    try w.int(u16, scheme);
    try w.vector(u24, spki);
    const credential = credential_buf[0..w.pos];
    const content = try Delegation.signedContent(gpa, role, identity.chain()[0], credential, @backingInt(algorithm));
    defer gpa.free(content);
    var noise: [certificates.PrivateKey.max_noise]u8 = @splat(7);
    var sig_buf: [certificates.PrivateKey.max_signature]u8 = undefined;
    const signature = try identity.sign(.{ .ecdsa = .sha256 }, content, noise[0..identity.noiseLength().?], &sig_buf);
    const out = try gpa.alloc(u8, credential.len + 4 + signature.len);
    var o: Writer = .{ .bytes = out };
    try o.put(credential);
    try o.int(u16, @backingInt(algorithm));
    try o.vector(u16, signature);
    return out;
}

fn validTime(leaf: []const u8, expires: i64) u32 {
    return @intCast(expires - notBefore(leaf));
}

fn checkAt(bytes: []const u8, leaf: []const u8, role: Delegation.Role, now: i64) Delegation.CheckError!Delegation.Checked {
    return Delegation.check(gpa, try (Delegation.parse(bytes) catch error.IllegalParameter), leaf, role, now, &Hello.schemes, &Delegation.schemes);
}

test "C10 delegated credentials: issued, taken by the owner and checked by a peer" {
    const identity = try identityOf(pki.dc_p256, pki.p256_pem);
    defer identity.deinit();
    var noise: [32]u8 = @splat(3);
    const expires = pki.time + 3 * day;
    const bytes = try Delegation.issue(gpa, identity, .{ .role = .server, .spki = p384Spki(), .scheme = .ecdsa_p384_sha384, .algorithm = .ecdsa_p256_sha256, .expires = certificates.types.instant(expires) }, &noise);
    defer gpa.free(bytes);
    const view = try Delegation.parse(bytes);
    try std.testing.expectEqual(@as(u16, 0x0503), view.scheme);
    try std.testing.expectEqual(@as(u16, 0x0403), view.algorithm);
    const checked = try checkAt(bytes, pki.dc_p256, .server, pki.time);
    try std.testing.expectEqual(expires, checked.expires);
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p384_sha384, checked.scheme);
    // The owner's side: the key must be the credential's.
    const key = try certificates.PrivateKey.parse(gpa, pki.p384_pem, .{});
    defer key.deinit();
    const credential = try Delegation.Credential.init(gpa, identity, bytes, key, .server);
    defer credential.deinit();
    try std.testing.expect(credential.belongsTo(identity));
    try std.testing.expectEqual(expires, certificates.types.seconds(credential.expiresAt()));
    const wrong = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
    defer wrong.deinit();
    try std.testing.expectError(error.KeyMismatch, Delegation.Credential.init(gpa, identity, bytes, wrong, .server));
    // A client's label is not a server's: the delegation does not verify under the other role.
    try std.testing.expectError(error.BadDelegation, Delegation.Credential.init(gpa, identity, bytes, key, .client));
    try std.testing.expectError(error.IllegalParameter, checkAt(bytes, pki.dc_p256, .client, pki.time));
}

test "C10 delegated credentials: a certificate delegates only with DelegationUsage and digitalSignature" {
    var noise: [32]u8 = @splat(3);
    const spec: Delegation.Spec = .{ .role = .server, .spki = p384Spki(), .scheme = .ecdsa_p384_sha384, .algorithm = .ecdsa_p256_sha256, .expires = certificates.types.instant(pki.time + day) };
    inline for (.{ pki.p256, pki.dc_no_signature }) |leaf| {
        const root = if (leaf.ptr == pki.p256.ptr) pki.ca else pki.dc_ca;
        const key = try certificates.PrivateKey.parse(gpa, pki.p256_pem, .{});
        defer key.deinit();
        const identity = try certificates.Identity.init(gpa, &.{ leaf, root }, key, .{});
        defer identity.deinit();
        try std.testing.expectError(error.NotDelegator, Delegation.issue(gpa, identity, spec, &noise));
        // Signed anyway, a peer refuses it.
        const forged = try forge(identity, .server, validTime(leaf, pki.time + day), 0x0503, .ecdsa_p256_sha256, p384Spki());
        defer gpa.free(forged);
        try std.testing.expectError(error.IllegalParameter, checkAt(forged, leaf, .server, pki.time));
    }
}

test "C10 delegated credentials: schemes the credential and the delegation may use" {
    const identity = try identityOf(pki.dc_p256, pki.p256_pem);
    defer identity.deinit();
    const valid = validTime(pki.dc_p256, pki.time + day);
    // rsa_pss_rsae_* is never a credential's scheme (RFC 9345 section 4), nor one its key cannot make.
    for ([_]u16{ 0x0804, 0x0403, 0x0807, 0x0401, 0xfefe }) |scheme| {
        const forged = try forge(identity, .server, valid, scheme, .ecdsa_p256_sha256, p384Spki());
        defer gpa.free(forged);
        try std.testing.expectError(error.IllegalParameter, checkAt(forged, pki.dc_p256, .server, pki.time));
    }
    var noise: [32]u8 = @splat(3);
    try std.testing.expectError(error.UnsupportedScheme, Delegation.issue(gpa, identity, .{ .role = .server, .spki = p384Spki(), .scheme = .rsa_pss_rsae_sha256, .algorithm = .ecdsa_p256_sha256, .expires = certificates.types.instant(pki.time + day) }, &noise));
    // The credential's scheme must be one the receiver listed for credentials, the delegation's
    // one it listed in signature_algorithms.
    const good = try forge(identity, .server, valid, 0x0503, .ecdsa_p256_sha256, p384Spki());
    defer gpa.free(good);
    const view = try Delegation.parse(good);
    try std.testing.expectError(error.IllegalParameter, Delegation.check(gpa, view, pki.dc_p256, .server, pki.time, &Hello.schemes, &.{.ecdsa_p256_sha256}));
    try std.testing.expectError(error.IllegalParameter, Delegation.check(gpa, view, pki.dc_p256, .server, pki.time, &.{.ecdsa_p384_sha384}, &Delegation.schemes));
    _ = try Delegation.check(gpa, view, pki.dc_p256, .server, pki.time, &.{.ecdsa_p256_sha256}, &.{.ecdsa_p384_sha384});
    // A delegation whose signature is damaged.
    const damaged = try gpa.dupe(u8, good);
    defer gpa.free(damaged);
    damaged[damaged.len - 3] ^= 1;
    try std.testing.expectError(error.IllegalParameter, checkAt(damaged, pki.dc_p256, .server, pki.time));
    // Signed by the key of another certificate than the one presented with it.
    try std.testing.expectError(error.IllegalParameter, checkAt(good, pki.dc_client, .server, pki.time));
}

test "C10 delegated credentials: the wire form is exact" {
    const identity = try identityOf(pki.dc_p256, pki.p256_pem);
    defer identity.deinit();
    const good = try forge(identity, .server, 100, 0x0503, .ecdsa_p256_sha256, p384Spki());
    defer gpa.free(good);
    _ = try Delegation.parse(good);
    for (0..good.len) |cut| try std.testing.expectError(error.InvalidCredential, Delegation.parse(good[0..cut]));
    const longer = try std.mem.concat(gpa, u8, &.{ good, "\x00" });
    defer gpa.free(longer);
    try std.testing.expectError(error.InvalidCredential, Delegation.parse(longer));
    // An empty key or signature.
    try std.testing.expectError(error.InvalidCredential, Delegation.parse("\x00\x00\x00\x01\x05\x03\x00\x00\x00\x04\x03\x00\x01\x00"));
    try std.testing.expectError(error.InvalidCredential, Delegation.parse("\x00\x00\x00\x01\x05\x03\x00\x00\x01\x30\x04\x03\x00\x00"));
}

test "F89 catalogue_delegated_parent_expiry_and_raw_key_namespace (delegation: lifetime from the certificate, at most seven days, never past it)" {
    const identity = try identityOf(pki.dc_p256, pki.p256_pem);
    defer identity.deinit();
    const not_after = notAfter(pki.dc_p256);
    var noise: [32]u8 = @splat(3);
    // Issuing refuses a credential that would outlive its certificate, or start before it.
    try std.testing.expectError(error.OutlivesCertificate, Delegation.issue(gpa, identity, .{ .role = .server, .spki = p384Spki(), .scheme = .ecdsa_p384_sha384, .algorithm = .ecdsa_p256_sha256, .expires = certificates.types.instant(not_after) }, &noise));
    try std.testing.expectError(error.OutlivesCertificate, Delegation.issue(gpa, identity, .{ .role = .server, .spki = p384Spki(), .scheme = .ecdsa_p384_sha384, .algorithm = .ecdsa_p256_sha256, .expires = certificates.types.instant(notBefore(pki.dc_p256)) }, &noise));
    // A receiver refuses one that expires with or after its certificate, even near the end.
    const late = try forge(identity, .server, validTime(pki.dc_p256, not_after), 0x0503, .ecdsa_p256_sha256, p384Spki());
    defer gpa.free(late);
    try std.testing.expectError(error.IllegalParameter, checkAt(late, pki.dc_p256, .server, not_after - day));
    // Expired: valid up to the second before its expiry, never at it.
    const short = try forge(identity, .server, validTime(pki.dc_p256, pki.time + 60), 0x0503, .ecdsa_p256_sha256, p384Spki());
    defer gpa.free(short);
    _ = try checkAt(short, pki.dc_p256, .server, pki.time + 59);
    try std.testing.expectError(error.IllegalParameter, checkAt(short, pki.dc_p256, .server, pki.time + 60));
    // At most seven days left to run when it is checked (RFC 9345 section 4.1.3).
    const long = try forge(identity, .server, validTime(pki.dc_p256, pki.time + 8 * day), 0x0503, .ecdsa_p256_sha256, p384Spki());
    defer gpa.free(long);
    try std.testing.expectError(error.IllegalParameter, checkAt(long, pki.dc_p256, .server, pki.time));
    _ = try checkAt(long, pki.dc_p256, .server, pki.time + day);
    // The owner sends it only while a peer would take it.
    const key = try certificates.PrivateKey.parse(gpa, pki.p384_pem, .{});
    defer key.deinit();
    const credential = try Delegation.Credential.init(gpa, identity, long, key, .server);
    defer credential.deinit();
    const list = "\x05\x03";
    const Accepts = struct {
        pub fn accepts(_: @This(), scheme: u16) bool {
            return scheme == 0x0403;
        }
    };
    try std.testing.expect(!credential.usable(pki.time, list, Accepts{}));
    try std.testing.expect(credential.usable(pki.time + day, list, Accepts{}));
    try std.testing.expect(!credential.usable(pki.time + 8 * day, list, Accepts{}));
    try std.testing.expect(!credential.usable(pki.time + day, "\x04\x03", Accepts{}));
}

test "C10 delegated credentials: the Certificate takes one on the leaf, once, and only when offered" {
    var out: [Messages.max_certificates][]const u8 = undefined;
    var buf: [2048]u8 = undefined;
    const credential = "\x00\x00\x00\x01\x05\x03\x00\x00\x01\x30\x04\x03\x00\x01\x00";
    const with = try Messages.buildCertificate(&buf, "", &.{ pki.dc_p256, pki.dc_ca }, .{ .delegated = credential });
    const parsed = try Messages.certificate(with, 16, 65536, &out, .{ .delegated = true });
    try std.testing.expectEqualSlices(u8, credential, parsed.leaf.delegated.?);
    try std.testing.expectEqual(@as(usize, 2), parsed.count);
    // Not offered: unexpected_message (RFC 9345 section 4.1.1).
    try std.testing.expectError(error.UnexpectedMessage, Messages.certificate(with, 16, 65536, &out, .{}));
    // Absent when offered: none.
    var plain_buf: [2048]u8 = undefined;
    const plain = try Messages.buildCertificate(&plain_buf, "", &.{ pki.dc_p256, pki.dc_ca }, .{});
    try std.testing.expectEqual(@as(?[]const u8, null), (try Messages.certificate(plain, 16, 65536, &out, .{ .delegated = true })).leaf.delegated);
    // On another entry, twice on the leaf, or another extension beside it.
    var w: Writer = .{ .bytes = &buf };
    try entryMessage(&w, &.{ .{ pki.dc_p256, "" }, .{ pki.dc_ca, "\x00\x22\x00\x01\x00" } });
    try std.testing.expectError(error.IllegalParameter, Messages.certificate(w.bytes[0..w.pos], 16, 65536, &out, .{ .delegated = true }));
    w = .{ .bytes = &buf };
    try entryMessage(&w, &.{.{ pki.dc_p256, "\x00\x22\x00\x01\x00\x00\x22\x00\x01\x00" }});
    try std.testing.expectError(error.DuplicateExtension, Messages.certificate(w.bytes[0..w.pos], 16, 65536, &out, .{ .delegated = true }));
    w = .{ .bytes = &buf };
    try entryMessage(&w, &.{.{ pki.dc_p256, "\x00\x12\x00\x00" }});
    try std.testing.expectError(error.UnsolicitedExtension, Messages.certificate(w.bytes[0..w.pos], 16, 65536, &out, .{ .delegated = true }));
}

fn entryMessage(w: *Writer, entries: []const struct { []const u8, []const u8 }) !void {
    try Messages.header(w, .certificate);
    try w.int(u8, 0);
    const list_at = w.pos;
    try w.int(u24, 0);
    for (entries) |entry| {
        try w.vector(u24, entry[0]);
        try w.vector(u16, entry[1]);
    }
    std.mem.writeInt(u24, w.bytes[list_at..][0..3], @intCast(w.pos - list_at - 3), .big);
    _ = Messages.seal(w);
}
