//! Certificates and requests issued, read back by cloak and verified as a path: a root, an
//! intermediate and a leaf; a CSR signed, parsed and issued from; and what an issuer refuses.
const std = @import("std");
const Issue = @import("Issue.zig");
const PrivateKey = @import("PrivateKey.zig");
const certificate = @import("certificate.zig");
const Template = @import("certificate/Template.zig");
const Request = @import("certificate/Request.zig");
const Verifier = @import("verify/Verifier.zig");
const T = @import("types.zig");

const gpa = std.testing.allocator;
const io = std.testing.io;

/// 2026-01-01T00:00:00Z, and a year either side of it.
const now_s: i64 = 1_767_225_600;
const now: std.Io.Timestamp = .fromNanoseconds(@as(i96, now_s) * std.time.ns_per_s);
const year_before: std.Io.Timestamp = .fromNanoseconds(@as(i96, now_s - 365 * 86400) * std.time.ns_per_s);
const year_after: std.Io.Timestamp = .fromNanoseconds(@as(i96, now_s + 365 * 86400) * std.time.ns_per_s);

fn spki(key: PrivateKey, buffer: *[PrivateKey.max_public_key_info]u8) []const u8 {
    return key.publicKeyInfo(buffer);
}

const Chain = struct {
    root_key: PrivateKey,
    middle_key: PrivateKey,
    leaf_key: PrivateKey,
    root: []u8,
    middle: []u8,
    leaf: []u8,

    fn deinit(c: *Chain) void {
        gpa.free(c.root);
        gpa.free(c.middle);
        gpa.free(c.leaf);
        c.root_key.deinit();
        c.middle_key.deinit();
        c.leaf_key.deinit();
    }
};

/// A root on `root_kind`, an intermediate on P-384 and a server leaf on `leaf_kind` for
/// example.com.
fn chain(root_kind: PrivateKey.Kind, leaf_kind: PrivateKey.Kind) !Chain {
    var c: Chain = undefined;
    c.root_key = try PrivateKey.generate(gpa, io, root_kind);
    errdefer c.root_key.deinit();
    c.middle_key = try PrivateKey.generate(gpa, io, .p384);
    errdefer c.middle_key.deinit();
    c.leaf_key = try PrivateKey.generate(gpa, io, leaf_kind);
    errdefer c.leaf_key.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const ca_usage: Template.KeyUsage = .{ .key_cert_sign = true, .crl_sign = true, .digital_signature = true };
    c.root = try Issue.issue(gpa, io, &.{
        .subject = .{ .attributes = &.{ .{ .organization = "cloak tests" }, .{ .common_name = "cloak test root" } } },
        .not_before = year_before,
        .not_after = year_after,
        .ca = .{},
        .key_usage = ca_usage,
    }, spki(c.root_key, &buffer), .{ .key = c.root_key });
    errdefer gpa.free(c.root);
    c.middle = try Issue.issue(gpa, io, &.{
        .subject = .{ .attributes = &.{.{ .common_name = "cloak test intermediate" }} },
        .not_before = year_before,
        .not_after = year_after,
        .ca = .{ .path_length = 0 },
        .key_usage = ca_usage,
    }, spki(c.middle_key, &buffer), .{ .key = c.root_key, .certificate = c.root });
    errdefer gpa.free(c.middle);
    c.leaf = try Issue.issue(gpa, io, &.{
        .subject = .{ .attributes = &.{.{ .common_name = "example.com" }} },
        .not_before = year_before,
        .not_after = year_after,
        .names = &.{ .{ .dns = "example.com" }, .{ .dns = "www.example.com" } },
        .key_usage = .{ .digital_signature = true },
        .purposes = &.{.server_auth},
    }, spki(c.leaf_key, &buffer), .{ .key = c.middle_key, .certificate = c.middle });
    return c;
}

/// A server request for `name` over `path`, the leaf and its intermediate.
fn request(path: *const [2][]const u8, name: []const u8) T.Request {
    return .{ .chain = path, .identity = .{ .dns = name }, .time = now, .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
}

test "a root, an intermediate and a leaf issued here verify as a path, on every key kind" {
    const roots = .{ PrivateKey.Kind.ed25519, PrivateKey.Kind.p256, PrivateKey.Kind.p521, PrivateKey.Kind.mldsa65, PrivateKey.Kind{ .rsa = .@"2048" } };
    inline for (roots) |root_kind| {
        var c = try chain(root_kind, .p256);
        defer c.deinit();
        const path: [2][]const u8 = .{ c.leaf, c.middle };
        var verified = try Verifier.verify(gpa, request(&path, "www.example.com"), &.{c.root});
        verified.deinit();
        // Another name, another root: no path.
        try std.testing.expectError(error.IdentityMismatch, Verifier.verify(gpa, request(&path, "example.org"), &.{c.root}));
        var other = try chain(.ed25519, .ed25519);
        defer other.deinit();
        try std.testing.expect(std.meta.isError(Verifier.verify(gpa, request(&path, "example.com"), &.{other.root})));
    }
}

test "what an issued certificate says is what its template asked" {
    var c = try chain(.ed25519, .ed25519);
    defer c.deinit();
    const root = try certificate.parse(c.root, .{});
    const middle = try certificate.parse(c.middle, .{});
    const leaf = try certificate.parse(c.leaf, .{});
    // Self-signed: issuer and subject one Name; each child's issuer its parent's subject.
    try std.testing.expectEqualSlices(u8, root.subject, root.issuer);
    try std.testing.expectEqualSlices(u8, root.subject, middle.issuer);
    try std.testing.expectEqualSlices(u8, middle.subject, leaf.issuer);
    try std.testing.expectEqual(now_s - 365 * 86400, leaf.not_before);
    try std.testing.expectEqual(now_s + 365 * 86400, leaf.not_after);
    // A CA's key identifier is RFC 7093 method 1 over its key; the leaf's authority key
    // identifier is its issuer's.
    const ski = middle.x509(14).?;
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const method1 = try Template.keyIdentifier(spki(c.middle_key, &buffer));
    try std.testing.expectEqualSlices(u8, &method1, ski.value[2..]);
    try std.testing.expect(std.mem.find(u8, leaf.x509(35).?.value, &method1) != null);
    // A random serial: positive, sixteen bytes, two certificates never one.
    try std.testing.expectEqual(@as(usize, 16), leaf.serial.len);
    try std.testing.expect(leaf.serial[0] & 0x80 == 0 and leaf.serial[0] & 0x40 != 0);
    try std.testing.expect(!std.mem.eql(u8, leaf.serial, middle.serial));
}

test "a request signed here parses, proves its key, and a leaf issued from it verifies" {
    var c = try chain(.p256, .p256);
    defer c.deinit();
    var key = try PrivateKey.generate(gpa, io, .{ .rsa = .@"2048" });
    defer key.deinit();
    const der = try Issue.request(gpa, io, &.{
        .subject = .{ .attributes = &.{ .{ .country = "PT" }, .{ .common_name = "api.example.com" } } },
        .names = &.{.{ .dns = "api.example.com" }},
        .key_usage = .{ .digital_signature = true, .key_encipherment = true },
        .purposes = &.{ .server_auth, .client_auth },
    }, key, null);
    defer gpa.free(der);
    const parsed = try Request.parse(der, .{});
    try Issue.verifyRequest(&parsed);
    try std.testing.expect(parsed.extension("\x55\x1d\x11") != null);
    try std.testing.expect(parsed.extension("\x55\x1d\x0f") != null);
    // A CA issues what the request asks, under its subject Name and key.
    const leaf = try Issue.issue(gpa, io, &.{
        .subject = .{ .der = parsed.subject },
        .not_before = year_before,
        .not_after = year_after,
        .names = &.{.{ .dns = "api.example.com" }},
        .purposes = &.{.server_auth},
    }, parsed.spki, .{ .key = c.middle_key, .certificate = c.middle });
    defer gpa.free(leaf);
    var verified = try Verifier.verify(gpa, .{ .chain = &.{ leaf, c.middle }, .identity = .{ .dns = "api.example.com" }, .time = now, .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) }, &.{c.root});
    verified.deinit();
    // A request whose signature is changed proves nothing.
    const broken = try gpa.dupe(u8, der);
    defer gpa.free(broken);
    broken[broken.len - 1] ^= 1;
    const tampered = try Request.parse(broken, .{});
    try std.testing.expectError(error.InvalidSignature, Issue.verifyRequest(&tampered));
}

test "an issuer refuses a key not its certificate's, a certificate that is no CA, and a template a verifier would" {
    var c = try chain(.p256, .p256);
    defer c.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const subject = spki(c.leaf_key, &buffer);
    const plain: Template.Certificate = .{ .subject = .{ .attributes = &.{.{ .common_name = "x" }} }, .not_before = year_before, .not_after = year_after, .names = &.{.{ .dns = "x.example" }} };
    // The root's key with the intermediate's certificate.
    try std.testing.expectError(error.KeyMismatch, Issue.issue(gpa, io, &plain, subject, .{ .key = c.root_key, .certificate = c.middle }));
    // A leaf for an issuer.
    try std.testing.expectError(error.IssuerNotCa, Issue.issue(gpa, io, &plain, subject, .{ .key = c.leaf_key, .certificate = c.leaf }));
    // Self-signed over another key.
    try std.testing.expectError(error.KeyMismatch, Issue.issue(gpa, io, &plain, subject, .{ .key = c.root_key }));
    // Validity backwards; keyCertSign on no CA; a zero serial; an empty subject with no names.
    var backwards = plain;
    backwards.not_after = year_before;
    backwards.not_before = year_after;
    try std.testing.expectError(error.InvalidValidity, Issue.issue(gpa, io, &backwards, subject, .{ .key = c.middle_key, .certificate = c.middle }));
    var signer = plain;
    signer.key_usage = .{ .key_cert_sign = true };
    try std.testing.expectError(error.InvalidTemplate, Issue.issue(gpa, io, &signer, subject, .{ .key = c.middle_key, .certificate = c.middle }));
    var zero = plain;
    zero.serial = &.{0};
    try std.testing.expectError(error.InvalidSerial, Issue.issue(gpa, io, &zero, subject, .{ .key = c.middle_key, .certificate = c.middle }));
    var nameless = plain;
    nameless.subject = .{ .attributes = &.{} };
    nameless.names = &.{};
    try std.testing.expectError(error.InvalidName, Issue.issue(gpa, io, &nameless, subject, .{ .key = c.middle_key, .certificate = c.middle }));
    // An agreement key signs nothing.
    const d: [32]u8 = @splat(7);
    var agree = try PrivateKey.fromComponents(gpa, .{ .x25519 = .{ .d = &d } });
    defer agree.deinit();
    var own: [PrivateKey.max_public_key_info]u8 = undefined;
    try std.testing.expectError(error.UnsupportedAlgorithm, Issue.issue(gpa, io, &plain, spki(agree, &own), .{ .key = agree }));
}
