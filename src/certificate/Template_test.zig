//! What a template writes, read back by cloak's own parsers: every extension it owns, valid as a
//! verifier reads it, and name constraints a verifier then enforces.
const std = @import("std");
const Template = @import("Template.zig");
const Builder = @import("../wire/Builder.zig");
const certificate = @import("../certificate.zig");
const Extensions = @import("Extensions.zig");
const Issue = @import("../Issue.zig");
const PrivateKey = @import("../PrivateKey.zig");
const Verifier = @import("../verify/Verifier.zig");

const gpa = std.testing.allocator;
const io = std.testing.io;

const now_s: i64 = 1_767_225_600;
const now: std.Io.Timestamp = .fromNanoseconds(@as(i96, now_s) * std.time.ns_per_s);
const before: std.Io.Timestamp = .fromNanoseconds(@as(i96, now_s - 86400) * std.time.ns_per_s);
const after: std.Io.Timestamp = .fromNanoseconds(@as(i96, now_s + 86400) * std.time.ns_per_s);

/// The OIDs a template owns, by the last bytes of id-ce (2.5.29.x).
fn idCe(x: u8) [3]u8 {
    return .{ 0x55, 0x1d, x };
}

test "a full template's extensions are each written once and valid as a verifier reads them" {
    var key = try PrivateKey.generate(gpa, io, .ed25519);
    defer key.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const ip4 = [_]u8{ 192, 0, 2, 1 };
    const der = try Issue.issue(gpa, io, &.{
        .serial = &.{ 0x01, 0x02, 0x03 },
        .subject = .{ .attributes = &.{ .{ .country = "PT" }, .{ .organization = "Ação Lda" }, .{ .domain_component = "example" }, .{ .email = "ca@example.com" }, .{ .common_name = "Test CA" } } },
        .not_before = before,
        .not_after = after,
        .names = &.{ .{ .dns = "ca.example.com" }, .{ .ip = &ip4 }, .{ .email = "ca@example.com" }, .{ .uri = "https://ca.example.com/" } },
        .ca = .{ .path_length = 1 },
        .key_usage = .{ .key_cert_sign = true, .crl_sign = true },
        .purposes = &.{ .server_auth, .client_auth, .{ .other = "\x2b\x06\x01\x05\x05\x07\x03\x11" } },
        .subject_key_identifier = .always,
        .ocsp = &.{"http://ocsp.example.com"},
        .ca_issuers = &.{"http://ca.example.com/ca.crt"},
        .crl_distribution_points = &.{"http://ca.example.com/ca.crl"},
        .policies = &.{"\x67\x81\x0c\x01\x02\x01"},
        .name_constraints = .{ .permitted = &.{ .{ .dns = "example.com" }, .{ .ip = &.{ 192, 0, 2, 0, 255, 255, 255, 0 } } }, .excluded = &.{.{ .dns = "bad.example.com" }} },
        .extensions = &.{.{ .oid = "\x2b\x06\x01\x04\x01\x82\xe9\x18\x01", .value = "\x05\x00" }},
    }, key.publicKeyInfo(&buffer), .{ .key = key });
    defer gpa.free(der);
    const cert = try certificate.parse(der, .{});
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 0x03 }, cert.serial);
    // Each extension present once and valid as `parse` validated it; the owned ones by type.
    const basic = try Extensions.basic(cert.x509(19).?.value);
    try std.testing.expect(basic.ca);
    try std.testing.expectEqual(@as(?usize, 1), basic.path_length);
    try std.testing.expect(cert.x509(19).?.critical);
    try std.testing.expect(cert.x509(15).?.critical);
    try std.testing.expectEqual(@as(u16, (1 << 5) | (1 << 6)), try Extensions.keyUsage(cert.x509(15).?.value));
    try Extensions.nameConstraints(cert.x509(30).?.value);
    try std.testing.expect(cert.x509(30).?.critical);
    for ([_]u8{ 14, 17, 31, 32, 37 }) |id| try std.testing.expect(cert.x509(id) != null);
    // The names, in order, as the SAN's GeneralNames.
    var names = try Extensions.sequence(cert.x509(17).?.value);
    try std.testing.expectEqualStrings("ca.example.com", (try names.expect(0x82)).value);
    try std.testing.expectEqualSlices(u8, &ip4, (try names.expect(0x87)).value);
    try std.testing.expectEqualStrings("ca@example.com", (try names.expect(0x81)).value);
    try std.testing.expectEqualStrings("https://ca.example.com/", (try names.expect(0x86)).value);
    try names.finish();
    // The raw extension, as given.
    try std.testing.expect(std.mem.find(u8, der, "\x06\x09\x2b\x06\x01\x04\x01\x82\xe9\x18\x01\x04\x02\x05\x00") != null);
    // A subject attribute that PrintableString cannot hold is UTF8String; one it can, Printable.
    try std.testing.expect(std.mem.find(u8, cert.subject, "\x0c\x0aAção Lda") != null);
    try std.testing.expect(std.mem.find(u8, cert.subject, "\x13\x02PT") != null);
}

test "name constraints written by a CA are enforced on the leaves it issues" {
    var ca_key = try PrivateKey.generate(gpa, io, .p256);
    defer ca_key.deinit();
    var leaf_key = try PrivateKey.generate(gpa, io, .p256);
    defer leaf_key.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const ca = try Issue.issue(gpa, io, &.{
        .subject = .{ .attributes = &.{.{ .common_name = "constrained" }} },
        .not_before = before,
        .not_after = after,
        .ca = .{},
        .key_usage = .{ .key_cert_sign = true },
        .name_constraints = .{ .permitted = &.{.{ .dns = "example.com" }} },
    }, ca_key.publicKeyInfo(&buffer), .{ .key = ca_key });
    defer gpa.free(ca);
    inline for (.{ .{ "www.example.com", true }, .{ "www.example.org", false } }) |case| {
        const leaf = try Issue.issue(gpa, io, &.{
            .subject = .{ .attributes = &.{} },
            .not_before = before,
            .not_after = after,
            .names = &.{.{ .dns = case[0] }},
        }, leaf_key.publicKeyInfo(&buffer), .{ .key = ca_key, .certificate = ca });
        defer gpa.free(leaf);
        const path: [1][]const u8 = .{leaf};
        const result = Verifier.verify(gpa, .{ .chain = &path, .identity = .{ .dns = case[0] }, .time = now, .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) }, &.{ca});
        if (case[1]) {
            var verified = try result;
            verified.deinit();
        } else try std.testing.expectError(error.NoTrustedPath, result);
    }
}

test "a template a verifier would refuse is refused before anything is written" {
    const base: Template.Certificate = .{ .subject = .{ .attributes = &.{.{ .common_name = "x" }} }, .not_before = before, .not_after = after };
    var t = base;
    t.names = &.{.{ .dns = "-bad-.example" }};
    try std.testing.expectError(error.InvalidName, Template.checkCertificate(&t));
    t = base;
    t.names = &.{.{ .ip = &.{ 1, 2, 3 } }};
    try std.testing.expectError(error.InvalidName, Template.checkCertificate(&t));
    t = base;
    t.key_usage = .{};
    try std.testing.expectError(error.InvalidTemplate, Template.checkCertificate(&t));
    t = base;
    t.extensions = &.{.{ .oid = &idCe(17), .value = "\x30\x00" }};
    try std.testing.expectError(error.InvalidTemplate, Template.checkCertificate(&t));
    t = base;
    t.extensions = &.{ .{ .oid = "\x2a\x03", .value = "\x05\x00" }, .{ .oid = "\x2a\x03", .value = "\x05\x00" } };
    try std.testing.expectError(error.InvalidTemplate, Template.checkCertificate(&t));
    t = base;
    t.subject_key_identifier = .{ .bytes = &.{} };
    try std.testing.expectError(error.InvalidTemplate, Template.checkCertificate(&t));
    t = base;
    t.not_before = .fromNanoseconds(-1 * std.time.ns_per_s);
    try std.testing.expectError(error.InvalidValidity, Template.checkCertificate(&t));
    try Template.checkCertificate(&base);
}

test "validity past 2049 is GeneralizedTime, before it UTCTime (RFC 5280 4.1.2.5)" {
    var b = Builder.init(gpa);
    defer b.deinit();
    var key = try PrivateKey.generate(gpa, io, .ed25519);
    defer key.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const far: std.Io.Timestamp = .fromNanoseconds(@as(i96, 2_556_143_999) * std.time.ns_per_s); // 2050-12-31T23:59:59Z
    const der = try Issue.issue(gpa, io, &.{ .subject = .{ .attributes = &.{.{ .common_name = "x" }} }, .not_before = before, .not_after = far }, key.publicKeyInfo(&buffer), .{ .key = key });
    defer gpa.free(der);
    try std.testing.expect(std.mem.find(u8, der, "\x17\x0d251231000000Z") != null);
    try std.testing.expect(std.mem.find(u8, der, "\x18\x0f20501231235959Z") != null);
    const cert = try certificate.parse(der, .{});
    try std.testing.expectEqual(@as(i64, 2_556_143_999), cert.not_after);
}
