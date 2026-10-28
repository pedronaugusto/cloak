//! Certificate compression (RFC 8879) end to end, cloak client against cloak server, with a zlib
//! codec from std standing in for the caller's.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Zlib = @import("../testing/Zlib.zig");
const Compression = @import("handshake/Compression.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const gpa = std.testing.allocator;

/// Counts what each side's codec did, to see the compressed path was taken.
const Counter = struct {
    compressed: usize = 0,
    decompressed: usize = 0,
    codec: Compression.Codec = .{ .algorithm = .zlib, .compress = compress, .decompress = decompress },

    fn compress(codec: *Compression.Codec, input: []const u8, out: []u8) Compression.Error!usize {
        const self: *Counter = @fieldParentPtr("codec", codec);
        self.compressed += 1;
        return Zlib.compress(codec, input, out);
    }

    fn decompress(codec: *Compression.Codec, input: []const u8, out: []u8) Compression.Error!void {
        const self: *Counter = @fieldParentPtr("codec", codec);
        self.decompressed += 1;
        return Zlib.decompress(codec, input, out);
    }
};

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C6 a compressed certificate authenticates the server, every TLS 1.3 suite and certificate" {
    for ([_]Duo.Cert{ .p256, .p384, .ed25519, .rsa }) |cert| for (Suite.tls13_only) |suite| {
        var counter: Counter = .{};
        const codec = &counter.codec;
        const duo = try connect(.{ .cert = cert, .client_suites = &.{suite}, .client_codecs = &.{codec}, .server_codecs = &.{codec} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.peer_authenticated);
        // Each side ran its codec once: the server compressed, the client decompressed.
        try std.testing.expectEqual(1, counter.compressed);
        try std.testing.expectEqual(1, counter.decompressed);
        var out: [8]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "hi", try duo.echo(&duo.client, &duo.server, "hi", &out));
    };
}

test "C6 certificate compression is used only when both ends have the codec, and never in TLS 1.2" {
    var counter: Counter = .{};
    const codec = &counter.codec;
    var other: Counter = .{ .codec = .{ .algorithm = .brotli, .compress = Counter.compress, .decompress = Counter.decompress } };
    const cases = [_]Duo.Options{
        .{ .client_codecs = &.{codec} },
        .{ .server_codecs = &.{codec} },
        .{ .client_codecs = &.{&other.codec}, .server_codecs = &.{codec} },
        .{ .client_codecs = &.{codec}, .server_codecs = &.{codec}, .client_max = .tls12 },
    };
    for (cases) |options| {
        const duo = try connect(options);
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.peer_authenticated);
    }
    try std.testing.expectEqual(0, counter.compressed + other.compressed);
    try std.testing.expectEqual(0, counter.decompressed + other.decompressed);
    // A retry request and a client certificate leave it working.
    const duo = try connect(.{ .server_groups = &.{.p256}, .client_auth = .required, .client_cert = true, .client_codecs = &.{codec}, .server_codecs = &.{codec} });
    defer duo.deinit();
    try std.testing.expect(duo.server.info().?.peer_authenticated and duo.client.info().?.peer_authenticated);
    try std.testing.expectEqual(1, counter.decompressed);
}

fn failing(_: *Compression.Codec, _: []const u8, _: []u8) Compression.Error!void {
    return error.Failed;
}

test "F87 a certificate the client's codec cannot decompress ends the handshake with bad_certificate" {
    var counter: Counter = .{};
    var broken: Compression.Codec = .{ .algorithm = .zlib, .decompress = failing };
    const duo = try Duo.init(gpa, .{ .client_codecs = &.{&broken}, .server_codecs = &.{&counter.codec} });
    defer duo.deinit();
    try std.testing.expectError(error.InvalidCertificate, duo.handshake());
    try std.testing.expectEqual(.bad_certificate, duo.client.diagnostics().alert_sent.?);
}
