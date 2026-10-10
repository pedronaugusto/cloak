//! Fuzz properties for certificate, CRL and OCSP parsing, and the vectors they start from.
const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../testing/inputs.zig");
const C = @import("../certificate.zig");
const D = @import("../wire/Der.zig");
const V = @import("Verifier.zig");
const R = @import("revocation.zig");
const T = @import("../types.zig");
const leaf = @embedFile("fixtures/vectors/leaf.der");
const anchor = @embedFile("fixtures/vectors/p256.der");
const now = std.fmt.parseInt(i64, @embedFile("fixtures/vectors/time.txt"), 10) catch unreachable;
const certificate_examples = [_][]const u8{
    leaf,                                             anchor,                                     @embedFile("fixtures/vectors/p384.der"),    @embedFile("fixtures/vectors/ed25519.der"),
    @embedFile("fixtures/vectors/rsa2048.der"),       @embedFile("fixtures/vectors/rsa3072.der"), @embedFile("fixtures/vectors/rsa4096.der"), @embedFile("fixtures/vectors/rsa2048-pss0.der"),
    @embedFile("fixtures/vectors/rsa4096-pss48.der"), "\x30\x80\x00\x00",                         "\x30\x03\x02\x01\xff",
};
const evidence_examples = [_][]const u8{
    @embedFile("fixtures/vectors/good.crl"),       @embedFile("fixtures/vectors/revoked.crl"),
    @embedFile("fixtures/vectors/good.ocsp"),      @embedFile("fixtures/vectors/revoked.ocsp"),
    @embedFile("fixtures/offline/delegated.ocsp"), @embedFile("fixtures/offline/invalid-remove.crl"),
};
test "C1 fuzz DER certificate and bounded authentication" {
    try shakedown.check(std.testing.allocator, {}, certificate, .{ .cases = 64 });
}
fn certificate(_: void, case: *shakedown.Case) !void {
    var buffer: [65536]u8 = undefined;
    try certificateInput(inputs.draw(case, &buffer, &certificate_examples, 48));
}
test "C1 DER certificate parsing and authentication take every vector and the odd examples" {
    for (certificate_examples) |input| try certificateInput(input);
}
fn certificateInput(input: []const u8) !void {
    if (D.validate(input, .{})) |_| {} else |_| {}
    if (C.parse(input, .{})) |parsed| {
        try std.testing.expectEqual(input.len, parsed.der.len);
        try std.testing.expect(parsed.tbs.len <= input.len);
        try std.testing.expect(parsed.spki.len <= parsed.tbs.len);
        try std.testing.expect(parsed.extension_count <= parsed.extensions.len);
    } else |_| {}
    const request: T.Request = .{ .chain = &.{input}, .identity = .{ .dns = "example.com" }, .time = now, .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    if (V.verify(std.testing.allocator, request, &.{anchor})) |value| {
        var receipt = value;
        defer receipt.deinit();
        const accepted = try C.parse(input, .{});
        const original = try C.parse(leaf, .{});
        const trusted = try C.parse(anchor, .{});
        // ECDSA signatures may have equivalent high/low-S encodings. No changed
        // signed content may acquire authority under these fixed fixture keys.
        try std.testing.expect(std.mem.eql(u8, accepted.tbs, original.tbs) or std.mem.eql(u8, accepted.tbs, trusted.tbs));
        try receipt.check(request);
    } else |_| {}
}
test "C1 fuzz offline CRL and OCSP evidence" {
    try shakedown.check(std.testing.allocator, {}, evidence, .{ .cases = 64 });
}
fn evidence(_: void, case: *shakedown.Case) !void {
    var buffer: [65536]u8 = undefined;
    try evidenceInput(inputs.draw(case, &buffer, &evidence_examples, 48));
}
test "C1 offline CRL and OCSP evidence take every vector" {
    for (evidence_examples) |input| try evidenceInput(input);
}
fn evidenceInput(input: []const u8) !void {
    const path = [_]C.Certificate{ try C.parse(leaf, .{}), try C.parse(anchor, .{}) };
    for ([_]T.Evidence{ .{ .crls = &.{input} }, .{ .ocsp = &.{input} } }) |supplied| {
        if (R.check(&path, now, .{ .mode = .required }, supplied)) |result| {
            try std.testing.expectEqual(.good, result.status);
            try std.testing.expect(result.expires.? >= now);
        } else |_| {}
    }
}
