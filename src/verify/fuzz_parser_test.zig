//! Explicit fuzz entry points: discovery must execute fuzz even without builtin.fuzz.
const std = @import("std");
const shakedown = @import("shakedown");
const C = @import("../certificate.zig");
const D = @import("../wire/Der.zig");
const V = @import("Verifier.zig");
const R = @import("revocation.zig");
const T = @import("../types.zig");
const leaf = @embedFile("fixtures/vectors/leaf.der");
const anchor = @embedFile("fixtures/vectors/p256.der");
const now = std.fmt.parseInt(i64, @embedFile("fixtures/vectors/time.txt"), 10) catch unreachable;
test "C1 fuzz DER certificate and bounded authentication" {
    try std.testing.fuzz({}, certificate, .{ .corpus = shakedown.corpus.entries(&.{
        leaf,                                             anchor,                                     @embedFile("fixtures/vectors/p384.der"),    @embedFile("fixtures/vectors/ed25519.der"),
        @embedFile("fixtures/vectors/rsa2048.der"),       @embedFile("fixtures/vectors/rsa3072.der"), @embedFile("fixtures/vectors/rsa4096.der"), @embedFile("fixtures/vectors/rsa2048-pss0.der"),
        @embedFile("fixtures/vectors/rsa4096-pss48.der"), "\x30\x80\x00\x00",                         "\x30\x03\x02\x01\xff",
    }) });
}
fn certificate(_: void, smith: *std.testing.Smith) !void {
    var buffer: [65536]u8 = undefined;
    const input = buffer[0..smith.slice(&buffer)];
    if (D.validate(input, .{})) |_| {} else |_| {}
    if (C.parse(input, .{})) |parsed| {
        try std.testing.expectEqual(input.len, parsed.der.len);
        try std.testing.expect(parsed.tbs.len <= input.len);
        try std.testing.expect(parsed.spki.len <= parsed.tbs.len);
        try std.testing.expect(parsed.extension_count <= parsed.extensions.len);
    } else |_| {}
    const request: T.Request = .{ .chain = &.{input}, .identity = .{ .dns = "example.com" }, .time = now, .trust_generation = 1, .policy_generation = 1 };
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
    try std.testing.fuzz({}, evidence, .{ .corpus = shakedown.corpus.entries(&.{
        @embedFile("fixtures/vectors/good.crl"),       @embedFile("fixtures/vectors/revoked.crl"),
        @embedFile("fixtures/vectors/good.ocsp"),      @embedFile("fixtures/vectors/revoked.ocsp"),
        @embedFile("fixtures/offline/delegated.ocsp"), @embedFile("fixtures/offline/invalid-remove.crl"),
    }) });
}
fn evidence(_: void, smith: *std.testing.Smith) !void {
    var buffer: [65536]u8 = undefined;
    const input = buffer[0..smith.slice(&buffer)];
    const path = [_]C.Certificate{ try C.parse(leaf, .{}), try C.parse(anchor, .{}) };
    for ([_]T.Evidence{ .{ .crls = &.{input} }, .{ .ocsp = &.{input} } }) |supplied| {
        if (R.check(&path, now, .{ .mode = .required }, supplied)) |result| {
            try std.testing.expectEqual(.good, result.status);
            try std.testing.expect(result.expires.? >= now);
        } else |_| {}
    }
}
