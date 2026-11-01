//! PKCS#10 requests read as a CA reads hostile input: each malformed shape refused, and a
//! well-formed one read whatever its other attributes.
const std = @import("std");
const Request = @import("Request.zig");
const Template = @import("Template.zig");
const Builder = @import("../wire/Builder.zig");
const PrivateKey = @import("../PrivateKey.zig");

const gpa = std.testing.allocator;
const io = std.testing.io;

const extension_request = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x0e";
const challenge_password = "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x07";
const san = "\x55\x1d\x11";

const Shape = struct {
    version: u64 = 0,
    /// Each attribute: its OID and its values' SET contents, written as given.
    attributes: []const struct { oid: []const u8, values: []const u8 } = &.{},
};

/// A request of `shape` over `spki`, its signature bytes zero: `parse` reads, never verifies.
fn build(shape: Shape, spki: []const u8) ![]u8 {
    var b = Builder.init(gpa);
    defer b.deinit();
    const outer = try b.open(0x30);
    const info = try b.open(0x30);
    try b.small(shape.version);
    try b.raw("\x30\x0e\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03req");
    try b.raw(spki);
    const attributes = try b.open(0xa0);
    for (shape.attributes) |attribute| {
        const a = try b.open(0x30);
        try b.element(0x06, attribute.oid);
        try b.element(0x31, attribute.values);
        try b.close(a);
    }
    try b.close(attributes);
    try b.close(info);
    try b.raw(try Template.signatureAlgorithm(.ed25519));
    const zeros: [64]u8 = @splat(0);
    try b.bits(&zeros);
    try b.close(outer);
    return b.toOwnedSlice();
}

/// An extensionRequest's value: a SEQUENCE of the extensions given, each already DER.
fn extensions(comptime list: []const []const u8) []const u8 {
    comptime var body: []const u8 = "";
    inline for (list) |e| body = body ++ e;
    return "\x30" ++ [_]u8{body.len} ++ body;
}

const san_dns = "\x30\x13\x06\x03\x55\x1d\x11\x04\x0c\x30\x0a\x82\x08test.org";

test "a request is read with its requested extensions, past attributes that ask nothing" {
    var key = try PrivateKey.generate(gpa, io, .ed25519);
    defer key.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const der = try build(.{ .attributes = &.{
        .{ .oid = challenge_password, .values = "\x0c\x06secret" },
        .{ .oid = extension_request, .values = comptime extensions(&.{san_dns}) },
    } }, key.publicKeyInfo(&buffer));
    defer gpa.free(der);
    const parsed = try Request.parse(der, .{});
    try std.testing.expectEqual(@as(usize, 1), parsed.extension_count);
    try std.testing.expect(parsed.extension(san) != null);
    try std.testing.expectEqualSlices(u8, key.publicKeyInfo(&buffer), parsed.spki);
}

test "a request of another version, two extension requests, an empty value set, an extension twice or a FALSE written out is refused" {
    var key = try PrivateKey.generate(gpa, io, .ed25519);
    defer key.deinit();
    var buffer: [PrivateKey.max_public_key_info]u8 = undefined;
    const spki = key.publicKeyInfo(&buffer);
    const cases = [_]struct { shape: Shape, err: anyerror }{
        .{ .shape = .{ .version = 1 }, .err = error.InvalidRequest },
        .{ .shape = .{ .attributes = &.{ .{ .oid = extension_request, .values = comptime extensions(&.{san_dns}) }, .{ .oid = extension_request, .values = comptime extensions(&.{}) } } }, .err = error.InvalidRequest },
        .{ .shape = .{ .attributes = &.{.{ .oid = challenge_password, .values = "" }} }, .err = error.InvalidRequest },
        .{ .shape = .{ .attributes = &.{.{ .oid = extension_request, .values = comptime extensions(&.{ san_dns, san_dns }) }} }, .err = error.DuplicateExtension },
        .{ .shape = .{ .attributes = &.{.{ .oid = extension_request, .values = comptime extensions(&.{"\x30\x16\x06\x03\x55\x1d\x11\x01\x01\x00\x04\x0c\x30\x0a\x82\x08test.org"}) }} }, .err = error.InvalidDer },
    };
    for (cases) |case| {
        const der = try build(case.shape, spki);
        defer gpa.free(der);
        try std.testing.expectError(case.err, Request.parse(der, .{}));
    }
}

test "a request truncated anywhere is refused" {
    var key = try PrivateKey.generate(gpa, io, .p256);
    defer key.deinit();
    const der = try @import("../Issue.zig").request(gpa, io, &.{ .subject = .{ .attributes = &.{.{ .common_name = "cut" }} }, .names = &.{.{ .dns = "cut.example" }} }, key, null);
    defer gpa.free(der);
    _ = try Request.parse(der, .{});
    for (0..der.len) |len| try std.testing.expect(std.meta.isError(Request.parse(der[0..len], .{})));
}

const dir = "testdata/";
const written_elsewhere = [_][]const u8{
    @embedFile(dir ++ "openssl.p256.csr.der"),
    @embedFile(dir ++ "openssl.ed25519.csr.der"),
    @embedFile(dir ++ "openssl.rsa2048-pss.csr.der"),
    @embedFile(dir ++ "openssl.mldsa44.csr.der"),
    @embedFile(dir ++ "go.p521.csr.der"),
    @embedFile(dir ++ "go.ed25519.csr.der"),
    @embedFile(dir ++ "go.rsa2048.csr.der"),
    @embedFile(dir ++ "go.mldsa65.csr.der"),
};

test "requests OpenSSL and Go wrote are read, their signatures verified and their names read back" {
    const Issue = @import("../Issue.zig");
    for (written_elsewhere) |der| {
        const request = try Request.parse(der, .{});
        try Issue.verifyRequest(&request);
        // OpenSSL writes the common name as a UTF8String, Go as a PrintableString.
        try std.testing.expect(std.mem.endsWith(u8, request.subject, "api.example.com"));
        try std.testing.expectEqualSlices(u8, "\x30\x11\x82\x0fapi.example.com", request.extension(san).?.value);
        // A signature byte changed is a request its key did not sign.
        const flipped = try gpa.dupe(u8, der);
        defer gpa.free(flipped);
        flipped[flipped.len - 1] ^= 1;
        try std.testing.expect(std.meta.isError(Issue.verifyRequest(&try Request.parse(flipped, .{}))));
    }
}

test "fuzz certification request parsing and signature checks" {
    const shakedown = @import("shakedown");
    try shakedown.check(gpa, {}, struct {
        fn run(_: void, case: *shakedown.Case) !void {
            const inputs = @import("../testing/inputs.zig");
            var buffer: [8192]u8 = undefined;
            const input = inputs.draw(case, &buffer, &written_elsewhere, 64);
            const request = Request.parse(input, .{}) catch return;
            // What it read lies in the input, and every part is the request's own.
            for ([_][]const u8{ request.der, request.info, request.subject, request.spki, request.signature }) |part| {
                try std.testing.expect(@intFromPtr(part.ptr) >= @intFromPtr(input.ptr));
                try std.testing.expect(@intFromPtr(part.ptr) + part.len <= @intFromPtr(input.ptr) + input.len);
            }
            try std.testing.expect(request.extension_count <= Request.max_extensions);
            // A mutated request still parses or not, and its signature holds or not; neither crashes.
            if (@import("../Issue.zig").verifyRequest(&request)) |_| {} else |_| {}
        }
    }.run, .{ .cases = 256 });
}
