const std = @import("std");
const shakedown = @import("shakedown");
const ClientHello = @import("ClientHello.zig");
const Hello = @import("Hello.zig");

fn encode(out: []u8, options: Hello.Options, session: []const u8, cookie: []const u8) ![]u8 {
    const x: [32]u8 = @splat(7);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &x }};
    return Hello.client(out, &@as([32]u8, @splat(9)), session, &shares, cookie, options);
}

test "C3 client hello parser reads what the client encoder writes" {
    var out: [4096]u8 = undefined;
    const wire = try encode(&out, .{ .sni = "example.com", .alpn = &.{ "h2", "http/1.1" }, .quic = true, .parameters = "tp" }, "", "");
    const hello = try ClientHello.parse(wire);
    try std.testing.expectEqualSlices(u8, "example.com", hello.server_name);
    try std.testing.expect(hello.offersVersion(0x0304) and !hello.offersVersion(0x0303));
    try std.testing.expect(hello.offersSuite(0x1301) and hello.offersSuite(0x1303) and hello.offersSuite(0x1302));
    try std.testing.expect(hello.offersGroup(.x25519_mlkem768) and hello.offersGroup(.p384));
    try std.testing.expect(hello.accepts(0x0403) and hello.accepts(0x0807) and !hello.accepts(0x0201));
    try std.testing.expect(hello.shareFor(.x25519) != null and hello.shareFor(.p256) == null);
    try std.testing.expect(!hello.sharesOutsideGroups());
    try std.testing.expectEqualSlices(u8, "tp", hello.parameters.?);
    try std.testing.expectEqualSlices(u8, "h2", hello.selectAlpn(&.{ "h3", "h2" }).?);
    try std.testing.expect(hello.selectAlpn(&.{"h3"}) == null);
    try std.testing.expect(!hello.early_data and !hello.has_psk);
}

test "C3 client hello parser rejects hostile structure" {
    var out: [4096]u8 = undefined;
    const good = try encode(&out, .{ .sni = "example.com" }, "0123456789abcdef0123456789abcdef", "");
    var copy: [4096]u8 = undefined;
    // Truncation at every length is a length error.
    for (0..good.len) |len| try std.testing.expect(std.meta.isError(ClientHello.parse(good[0..len])));
    // A session id above 32 bytes, an odd suite list, a non-null compression method.
    @memcpy(copy[0..good.len], good);
    copy[38] = 33;
    try std.testing.expect(std.meta.isError(ClientHello.parse(copy[0..good.len])));
    @memcpy(copy[0..good.len], good);
    copy[38 + 1 + 32 + 1] = 5;
    try std.testing.expect(std.meta.isError(ClientHello.parse(copy[0..good.len])));
    // Trailing bytes after the extension block.
    @memcpy(copy[0..good.len], good);
    copy[good.len] = 0;
    std.mem.writeInt(u24, copy[1..4], @intCast(good.len - 3), .big);
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(copy[0 .. good.len + 1]));
}

test "C3 client hello parser enforces extension rules" {
    // body: version, random, empty session, one suite, null compression, then extensions.
    const prefix = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x02\x13\x01\x01\x00";
    const versions = "\x00\x2b\x00\x03\x02\x03\x04";
    const cases = [_]struct { extensions: []const u8, err: ?anyerror }{
        .{ .extensions = versions, .err = null },
        .{ .extensions = "", .err = null },
        .{ .extensions = versions ++ versions, .err = error.DuplicateExtension },
        .{ .extensions = versions ++ "\x00\x2a\x00\x01x", .err = error.DecodeError },
        .{ .extensions = versions ++ "\x00\x29\x00\x01x\x00\x2d\x00\x02\x01\x01", .err = error.IllegalParameter },
        .{ .extensions = versions ++ "\x00\x2d\x00\x02\x01\x01\x00\x29\x00\x01x", .err = null },
        .{ .extensions = versions ++ "\x00\x29\x00\x01x", .err = error.MissingExtension },
        .{ .extensions = versions ++ "\x00\x00\x00\x0c\x00\x0a\x00\x00\x07a b c.d", .err = error.IllegalParameter },
        .{ .extensions = versions ++ "\x00\x0a\x00\x03\x00\x01\x00", .err = error.DecodeError },
        .{ .extensions = versions ++ "\x00\x33\x00\x0e\x00\x0c\x00\x1d\x00\x02xx\x00\x1d\x00\x02xx", .err = error.IllegalParameter },
        .{ .extensions = versions ++ "\x00\x10\x00\x04\x00\x02\x00h", .err = error.DecodeError },
    };
    for (cases) |case| {
        var message: [256]u8 = undefined;
        const body_len = prefix.len + 2 + case.extensions.len;
        message[0] = 1;
        std.mem.writeInt(u24, message[1..4], @intCast(body_len), .big);
        @memcpy(message[4..][0..prefix.len], prefix);
        std.mem.writeInt(u16, message[4 + prefix.len ..][0..2], @intCast(case.extensions.len), .big);
        @memcpy(message[6 + prefix.len ..][0..case.extensions.len], case.extensions);
        const wire = message[0 .. 4 + body_len];
        if (case.err) |expected| {
            try std.testing.expectError(expected, ClientHello.parse(wire));
        } else _ = try ClientHello.parse(wire);
    }
}

test "C3 client hello fingerprint ignores the extensions a retry may change" {
    var first_buf: [4096]u8 = undefined;
    var second_buf: [4096]u8 = undefined;
    const x: [32]u8 = @splat(7);
    const p256: [65]u8 = @splat(4);
    const random: [32]u8 = @splat(1);
    const first = try ClientHello.parse(try Hello.client(&first_buf, &random, "", &.{.{ .group = .x25519, .bytes = &x }}, "", .{ .sni = "example.com" }));
    const second = try ClientHello.parse(try Hello.client(&second_buf, &random, "", &.{.{ .group = .p256, .bytes = &p256 }}, "cookie", .{ .sni = "example.com" }));
    try std.testing.expectEqual(first.fingerprint(), second.fingerprint());
    // A changed name, ALPN list or random is a different hello.
    const renamed = try ClientHello.parse(try Hello.client(&second_buf, &random, "", &.{.{ .group = .p256, .bytes = &p256 }}, "", .{ .sni = "example.net" }));
    try std.testing.expect(!std.mem.eql(u8, &first.fingerprint(), &renamed.fingerprint()));
    const other_random: [32]u8 = @splat(2);
    const reseeded = try ClientHello.parse(try Hello.client(&second_buf, &other_random, "", &.{.{ .group = .x25519, .bytes = &x }}, "", .{ .sni = "example.com" }));
    try std.testing.expect(!std.mem.eql(u8, &first.fingerprint(), &reseeded.fingerprint()));
}

test "C3 fuzz client hello parser" {
    try std.testing.fuzz({}, fuzz, .{ .corpus = shakedown.corpus.entries(&.{"\x01\x00\x00\x00"}) });
}

fn fuzz(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    var input: []u8 = bytes[0..smith.slice(&bytes)];
    var real: [1024]u8 = undefined;
    if (smith.value(bool)) {
        // Start from a real hello and overwrite a few bytes of it.
        const seed = try encode(&real, .{ .sni = "example.com", .alpn = &.{"h2"} }, "", "");
        for (0..smith.value(u3)) |_| seed[smith.valueRangeAtMost(u16, 0, @intCast(seed.len - 1))] = smith.value(u8);
        input = seed;
    }
    if (ClientHello.parse(input)) |hello| {
        try std.testing.expect(hello.random.len == 32 and hello.session.len <= 32);
        try std.testing.expect(hello.versions.len >= 2 and hello.suites.len >= 2);
        _ = hello.fingerprint();
        _ = hello.shareFor(.x25519);
        _ = hello.selectAlpn(&.{"h2"});
        _ = hello.sharesOutsideGroups();
    } else |_| {}
}

test "C3 client hello without an extension block parses and offers no version" {
    // A TLS 1.2 style hello: version, random, empty session, one suite, null compression, nothing more.
    const body = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x02\xc0\x2b\x01\x00";
    var message: [64]u8 = undefined;
    message[0] = 1;
    std.mem.writeInt(u24, message[1..4], body.len, .big);
    @memcpy(message[4..][0..body.len], body);
    const hello = try ClientHello.parse(message[0 .. 4 + body.len]);
    try std.testing.expect(!hello.offersVersion(0x0304));
    try std.testing.expect(hello.offersSuite(0xc02b));
    try std.testing.expectEqual(@as(usize, 0), hello.extensions.len);
}
