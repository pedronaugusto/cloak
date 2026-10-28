const std = @import("std");
const Compression = @import("Compression.zig");
const Zlib = @import("../../testing/Zlib.zig");
const gpa = std.testing.allocator;

fn certificateMessage(buf: []u8, der: []const u8) []u8 {
    // context empty; one entry with no extensions.
    buf[0] = 11;
    buf[4] = 0;
    std.mem.writeInt(u24, buf[5..8], @intCast(3 + der.len + 2), .big);
    std.mem.writeInt(u24, buf[8..11], @intCast(der.len), .big);
    @memcpy(buf[11..][0..der.len], der);
    @memset(buf[11 + der.len ..][0..2], 0);
    const len = 11 + der.len + 2;
    std.mem.writeInt(u24, buf[1..4], @intCast(len - 4), .big);
    return buf[0..len];
}

test "C6 certificate compression: built, parsed and decompressed back exactly" {
    var zlib = Zlib.codec;
    var der: [600]u8 = undefined;
    for (&der, 0..) |*b, i| b.* = @intCast(i % 7);
    var cert_buf: [700]u8 = undefined;
    const certificate = certificateMessage(&cert_buf, &der);
    var out: [700]u8 = undefined;
    const message = Compression.build(&out, &zlib, certificate).?;
    try std.testing.expect(message.len < certificate.len);
    const parsed = try Compression.parse(message);
    try std.testing.expectEqual(Compression.Algorithm.zlib, parsed.algorithm);
    try std.testing.expectEqual(certificate.len - 4, parsed.length);
    const back = try Compression.decompress(gpa, &.{&zlib}, parsed, 1 << 17);
    defer gpa.free(back);
    try std.testing.expectEqualSlices(u8, certificate, back);
}

test "F87 catalogue_certificate_compression_bomb_and_transcript (bounds and codecs)" {
    var zlib = Zlib.codec;
    var der: [600]u8 = @splat(0);
    var cert_buf: [700]u8 = undefined;
    const certificate = certificateMessage(&cert_buf, &der);
    var out: [700]u8 = undefined;
    const message = Compression.build(&out, &zlib, certificate).?;
    var parsed = try Compression.parse(message);
    // An algorithm this side did not offer.
    var other: Compression.Codec = .{ .algorithm = .brotli, .decompress = Zlib.decompress };
    try std.testing.expectError(error.IllegalParameter, Compression.decompress(gpa, &.{&other}, parsed, 1 << 17));
    // A declared length past the limit is refused before anything is allocated or decoded: a
    // tiny stream that would expand to megabytes never runs.
    var bomb = parsed;
    bomb.length = std.math.maxInt(u24);
    try std.testing.expectError(error.HandshakeLimit, Compression.decompress(gpa, &.{&zlib}, bomb, 1 << 17));
    // A declared length that disagrees with the stream, either way, is bad_certificate.
    parsed.length -= 1;
    try std.testing.expectError(error.BadCertificate, Compression.decompress(gpa, &.{&zlib}, parsed, 1 << 17));
    parsed.length += 2;
    try std.testing.expectError(error.BadCertificate, Compression.decompress(gpa, &.{&zlib}, parsed, 1 << 17));
    parsed.length -= 1;
    // Bytes after the stream, and a truncated stream.
    var trailing: [800]u8 = undefined;
    @memcpy(trailing[0..parsed.data.len], parsed.data);
    trailing[parsed.data.len] = 0;
    var extended = parsed;
    extended.data = trailing[0 .. parsed.data.len + 1];
    try std.testing.expectError(error.BadCertificate, Compression.decompress(gpa, &.{&zlib}, extended, 1 << 17));
    var truncated = parsed;
    truncated.data = parsed.data[0 .. parsed.data.len - 1];
    try std.testing.expectError(error.BadCertificate, Compression.decompress(gpa, &.{&zlib}, truncated, 1 << 17));
    // Malformed messages: zero lengths, trailing bytes, the wrong type.
    try std.testing.expectError(error.DecodeError, Compression.parse(message[0 .. message.len - 1]));
    var wrong = out;
    wrong[0] = 11;
    try std.testing.expectError(error.DecodeError, Compression.parse(wrong[0..message.len]));
    const empty = [_]u8{ 25, 0, 0, 8, 0, 1, 0, 0, 5, 0, 0, 0 };
    try std.testing.expectError(error.DecodeError, Compression.parse(&empty));
    // A codec that gains nothing is not used: the plain certificate goes.
    const tiny = certificateMessage(&cert_buf, "x");
    try std.testing.expect(Compression.build(&out, &zlib, tiny) == null);
}

test "C6 certificate compression codecs: validated and chosen in the server's order" {
    var zlib = Zlib.codec;
    var brotli: Compression.Codec = .{ .algorithm = .brotli, .compress = Zlib.compress, .decompress = Zlib.decompress };
    try Compression.validate(&.{ &zlib, &brotli }, .decompress);
    try std.testing.expectError(error.InvalidOptions, Compression.validate(&.{ &zlib, &zlib }, .decompress));
    var bare: Compression.Codec = .{ .algorithm = .zlib };
    try std.testing.expectError(error.InvalidOptions, Compression.validate(&.{&bare}, .compress));
    var unnamed: Compression.Codec = .{ .algorithm = @fromBackingInt(@intCast(0)), .decompress = Zlib.decompress };
    try std.testing.expectError(error.InvalidOptions, Compression.validate(&.{&unnamed}, .decompress));
    // The client lists zstd then brotli then zlib; the server prefers zlib, then brotli.
    const offered = [_]u8{ 6, 0, 3, 0, 2, 0, 1 };
    try std.testing.expectEqual(Compression.Algorithm.zlib, Compression.choose(&.{ &zlib, &brotli }, &offered).?.algorithm);
    try std.testing.expectEqual(Compression.Algorithm.brotli, Compression.choose(&.{ &brotli, &zlib }, &offered).?.algorithm);
    try std.testing.expect(Compression.choose(&.{&zlib}, &.{ 2, 0, 3 }) == null);
    try Compression.checkExtension(&offered);
    try std.testing.expectError(error.DecodeError, Compression.checkExtension(&.{ 1, 0 }));
    try std.testing.expectError(error.DecodeError, Compression.checkExtension(&.{0}));
}

const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");

test "C6 fuzz compressed certificate messages never decode past their bounds" {
    try shakedown.check(gpa, {}, fuzzCompressed, .{});
}

fn fuzzCompressed(_: void, case: *shakedown.Case) !void {
    var zlib = Zlib.codec;
    var der: [300]u8 = undefined;
    for (&der, 0..) |*b, i| b.* = @intCast(i % 5);
    var cert_buf: [400]u8 = undefined;
    const certificate = certificateMessage(&cert_buf, &der);
    var out: [400]u8 = undefined;
    const seed = Compression.build(&out, &zlib, certificate).?;
    var bytes: [512]u8 = undefined;
    const input = inputs.draw(case, &bytes, &.{seed}, 48);
    const parsed = Compression.parse(input) catch return;
    // Algorithm, declared length and the vector fill the message exactly.
    try std.testing.expect(parsed.data.len != 0 and parsed.length != 0 and 4 + 2 + 3 + 3 + parsed.data.len == input.len);
    if (Compression.decompress(gpa, &.{&zlib}, parsed, 4096)) |message| {
        defer gpa.free(message);
        // Exactly the declared length, under its header, never more than the bound.
        try std.testing.expectEqual(@as(usize, parsed.length) + 4, message.len);
        try std.testing.expect(message.len <= 4096);
    } else |_| {}
}
