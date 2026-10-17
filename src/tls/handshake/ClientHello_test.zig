const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");
const ClientHello = @import("ClientHello.zig");
const Hello = @import("Hello.zig");

fn encode(out: []u8, options: Hello.Options, session: []const u8, cookie: []const u8) ![]u8 {
    const x: [32]u8 = @splat(7);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &x }};
    return Hello.client(out, &@as([32]u8, @splat(9)), session, "", &shares, cookie, options, .{});
}

test "C3 client hello parser reads what the client encoder writes" {
    var out: [4096]u8 = undefined;
    const wire = try encode(&out, .{ .sni = "example.com", .alpn = &.{ "h2", "http/1.1" }, .transport = .quic, .parameters = "tp" }, "", "");
    const hello = try ClientHello.parse(wire, .stream);
    try std.testing.expectEqualSlices(u8, "example.com", hello.server_name);
    try std.testing.expect(hello.offers13() and !hello.offers12());
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
    for (0..good.len) |len| try std.testing.expect(std.meta.isError(ClientHello.parse(good[0..len], .stream)));
    // A session id above 32 bytes, an odd suite list, a non-null compression method.
    @memcpy(copy[0..good.len], good);
    copy[38] = 33;
    try std.testing.expect(std.meta.isError(ClientHello.parse(copy[0..good.len], .stream)));
    @memcpy(copy[0..good.len], good);
    copy[38 + 1 + 32 + 1] = 5;
    try std.testing.expect(std.meta.isError(ClientHello.parse(copy[0..good.len], .stream)));
    // Trailing bytes after the extension block.
    @memcpy(copy[0..good.len], good);
    copy[good.len] = 0;
    std.mem.writeInt(u24, copy[1..4], @intCast(good.len - 3), .big);
    try std.testing.expectError(error.InvalidLength, ClientHello.parse(copy[0 .. good.len + 1], .stream));
}

test "C3 client hello parser enforces extension rules" {
    // body: version, random, empty session, one suite, null compression, then extensions.
    const prefix = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x02\x13\x01\x01\x00";
    const versions = "\x00\x2b\x00\x03\x02\x03\x04";
    const zeros32: [32]u8 = @splat(0);
    // One identity "x" aged zero, and its 32-byte binder.
    const psk = "\x00\x29\x00\x2c\x00\x07\x00\x01x\x00\x00\x00\x00\x00\x21\x20" ++ zeros32;
    const modes = "\x00\x2d\x00\x02\x01\x01";
    const cases = [_]struct { extensions: []const u8, err: ?anyerror }{
        .{ .extensions = versions, .err = null },
        .{ .extensions = "", .err = null },
        .{ .extensions = versions ++ versions, .err = error.DuplicateExtension },
        .{ .extensions = versions ++ "\x00\x2a\x00\x01x", .err = error.DecodeError },
        .{ .extensions = versions ++ psk ++ modes, .err = error.IllegalParameter },
        .{ .extensions = versions ++ modes ++ psk, .err = null },
        .{ .extensions = versions ++ psk, .err = error.MissingExtension },
        // F68: an offer that is not two lists, an empty identity, a short binder, counts that differ.
        .{ .extensions = versions ++ modes ++ "\x00\x29\x00\x01x", .err = error.InvalidLength },
        .{ .extensions = versions ++ modes ++ "\x00\x29\x00\x2b\x00\x06\x00\x00\x00\x00\x00\x00\x00\x21\x20" ++ zeros32, .err = error.DecodeError },
        .{ .extensions = versions ++ modes ++ "\x00\x29\x00\x2b\x00\x07\x00\x01x\x00\x00\x00\x00\x00\x20\x1f" ++ zeros32[0..31], .err = error.DecodeError },
        .{ .extensions = versions ++ modes ++ "\x00\x29\x00\x33\x00\x0e\x00\x01x\x00\x00\x00\x00\x00\x01y\x00\x00\x00\x00\x00\x21\x20" ++ zeros32, .err = error.IllegalParameter },
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
            try std.testing.expectError(expected, ClientHello.parse(wire, .stream));
        } else _ = try ClientHello.parse(wire, .stream);
    }
}

test "C3 client hello fingerprint ignores the extensions a retry may change" {
    var first_buf: [4096]u8 = undefined;
    var second_buf: [4096]u8 = undefined;
    const x: [32]u8 = @splat(7);
    const p256: [65]u8 = @splat(4);
    const random: [32]u8 = @splat(1);
    const first = try ClientHello.parse(try Hello.client(&first_buf, &random, "", "", &.{.{ .group = .x25519, .bytes = &x }}, "", .{ .sni = "example.com" }, .{}), .stream);
    const second = try ClientHello.parse(try Hello.client(&second_buf, &random, "", "", &.{.{ .group = .p256, .bytes = &p256 }}, "cookie", .{ .sni = "example.com" }, .{}), .stream);
    try std.testing.expectEqual(first.fingerprint(), second.fingerprint());
    // A changed name, ALPN list or random is a different hello.
    const renamed = try ClientHello.parse(try Hello.client(&second_buf, &random, "", "", &.{.{ .group = .p256, .bytes = &p256 }}, "", .{ .sni = "example.net" }, .{}), .stream);
    try std.testing.expect(!std.mem.eql(u8, &first.fingerprint(), &renamed.fingerprint()));
    const other_random: [32]u8 = @splat(2);
    const reseeded = try ClientHello.parse(try Hello.client(&second_buf, &other_random, "", "", &.{.{ .group = .x25519, .bytes = &x }}, "", .{ .sni = "example.com" }, .{}), .stream);
    try std.testing.expect(!std.mem.eql(u8, &first.fingerprint(), &reseeded.fingerprint()));
}

test "C3 fuzz client hello parser" {
    try shakedown.check(std.testing.allocator, {}, fuzz, .{});
}

fn fuzz(_: void, case: *shakedown.Case) !void {
    const s = case.source;
    var bytes: [4096]u8 = undefined;
    var input: []u8 = inputs.draw(case, &bytes, &.{}, 48);
    var real: [1024]u8 = undefined;
    if (shakedown.gen.boolean(s)) {
        // Start from a real hello and overwrite a few bytes of it.
        const seed = try encode(&real, .{ .sni = "example.com", .alpn = &.{"h2"} }, "", "");
        for (0..shakedown.gen.int(s, u3)) |_| seed[shakedown.gen.intRange(s, u16, 0, @intCast(seed.len - 1))] = shakedown.gen.int(s, u8);
        input = seed;
    }
    if (ClientHello.parse(input, .stream)) |hello| {
        try std.testing.expect(hello.random.len == 32 and hello.session.len <= 32);
        // No supported_versions extension (a TLS 1.2 hello, or the extension's type edited away) leaves no versions.
        try std.testing.expect(hello.versions.len == 0 or (hello.versions.len >= 2 and hello.versions.len % 2 == 0));
        try std.testing.expect(hello.suites.len >= 2);
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
    const hello = try ClientHello.parse(message[0 .. 4 + body.len], .stream);
    try std.testing.expect(!hello.offers13());
    try std.testing.expect(hello.offersSuite(0xc02b));
    try std.testing.expectEqual(@as(usize, 0), hello.extensions.len);
}

/// A ClientHello whose extension block is supported_versions and `n` one-byte extensions with
/// IDs spread over every high byte, in the order `order` gives (0: ascending, 1: descending),
/// the extension of index `changed` (if any) holding another byte.
fn spreadHello(out: []u8, n: usize, order: u1, changed: ?usize) ![]const u8 {
    const prefix = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x02\x13\x01\x01\x00";
    const versions = "\x00\x2b\x00\x03\x02\x03\x04";
    var at: usize = 4 + prefix.len + 2;
    @memcpy(out[at..][0..versions.len], versions);
    at += versions.len;
    for (0..n) |k| {
        const i = if (order == 0) k else n - 1 - k;
        // IDs 0x0100 + 0x0101*i wrap over every high byte; none is a known extension's.
        const id: u16 = @truncate(0x0100 + 0x0101 * i);
        std.mem.writeInt(u16, out[at..][0..2], id, .big);
        std.mem.writeInt(u16, out[at + 2 ..][0..2], 1, .big);
        out[at + 4] = if (changed == i) 'y' else 'x';
        at += 5;
    }
    out[0] = 1;
    std.mem.writeInt(u24, out[1..4], @intCast(at - 4), .big);
    @memcpy(out[4..][0..prefix.len], prefix);
    std.mem.writeInt(u16, out[4 + prefix.len ..][0..2], @intCast(at - 6 - prefix.len), .big);
    return out[0..at];
}

test "F101 catalogue_extension_count_unbounded_unique (the retry fingerprint covers every extension of a large hello)" {
    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;
    for ([_]usize{ 3, 64, 200, 1000 }) |n| {
        const first = try ClientHello.parse(try spreadHello(&a, n, 0, null), .stream);
        const same = try ClientHello.parse(try spreadHello(&b, n, 0, null), .stream);
        try std.testing.expectEqual(first.fingerprint(), same.fingerprint());
        for ([_]usize{ 0, n / 2, n - 1 }) |i| {
            const other = try ClientHello.parse(try spreadHello(&b, n, 0, i), .stream);
            try std.testing.expect(!std.mem.eql(u8, &first.fingerprint(), &other.fingerprint()));
        }
    }
}

test "F104 catalogue_retry_hello_extension_order (the retry fingerprint covers the extensions' order)" {
    // RFC 8446 section 4.1.2: reordering is a modification the second hello may not make.
    var a: [8192]u8 = undefined;
    var b: [8192]u8 = undefined;
    for ([_]usize{ 3, 64, 1000 }) |n| {
        const ascending = try ClientHello.parse(try spreadHello(&a, n, 0, null), .stream);
        const descending = try ClientHello.parse(try spreadHello(&b, n, 1, null), .stream);
        try std.testing.expect(!std.mem.eql(u8, &ascending.fingerprint(), &descending.fingerprint()));
    }
}

/// A ClientHello with supported_versions, supported_groups listing `n` groups spread over every
/// high byte and a key share (one byte) for each, the share of index `repeat` (if any) naming
/// group 0's again and the one of index `outside` (if any) a group the list leaves out.
fn sharesHello(out: []u8, n: usize, repeat: ?usize, outside: ?usize) ![]const u8 {
    const prefix = "\x03\x03rrrrrrrrrrrrrrrrrrrrrrrrrrrrrrrr\x00\x00\x02\x13\x01\x01\x00";
    const versions = "\x00\x2b\x00\x03\x02\x03\x04";
    var at: usize = 4 + prefix.len + 2;
    @memcpy(out[at..][0..versions.len], versions);
    at += versions.len;
    const group = struct {
        fn of(i: usize) u16 {
            return @truncate(0x0100 + 0x0101 * i);
        }
    }.of;
    std.mem.writeInt(u16, out[at..][0..2], 10, .big);
    std.mem.writeInt(u16, out[at + 2 ..][0..2], @intCast(2 + 2 * n), .big);
    std.mem.writeInt(u16, out[at + 4 ..][0..2], @intCast(2 * n), .big);
    at += 6;
    for (0..n) |i| {
        std.mem.writeInt(u16, out[at..][0..2], group(i), .big);
        at += 2;
    }
    std.mem.writeInt(u16, out[at..][0..2], 51, .big);
    std.mem.writeInt(u16, out[at + 2 ..][0..2], @intCast(2 + 5 * n), .big);
    std.mem.writeInt(u16, out[at + 4 ..][0..2], @intCast(5 * n), .big);
    at += 6;
    for (0..n) |i| {
        const id = if (repeat == i) group(0) else if (outside == i) group(n) else group(i);
        std.mem.writeInt(u16, out[at..][0..2], id, .big);
        std.mem.writeInt(u16, out[at + 2 ..][0..2], 1, .big);
        out[at + 4] = 'k';
        at += 5;
    }
    out[0] = 1;
    std.mem.writeInt(u24, out[1..4], @intCast(at - 4), .big);
    @memcpy(out[4..][0..prefix.len], prefix);
    std.mem.writeInt(u16, out[4 + prefix.len ..][0..2], @intCast(at - 6 - prefix.len), .big);
    return out[0..at];
}

test "F107 catalogue_key_share_count_unbounded_unique (any number of key shares, each group once and among the groups)" {
    // RFC 8446 section 4.2.8: client_shares<0..2^16-1> sets no count; a group shared twice is
    // illegal_parameter, and so is a share outside supported_groups. tlsfuzzer's
    // test-tls13-unrecognised-groups offers up to 246 (past 32 they were refused).
    var buf: [16384]u8 = undefined;
    for ([_]usize{ 3, 33, 246, 1000 }) |n| {
        const hello = try ClientHello.parse(try sharesHello(&buf, n, null, null), .stream);
        try std.testing.expect(!hello.sharesOutsideGroups());
        for ([_]usize{ 1, n / 2, n - 1 }) |i| {
            try std.testing.expectError(error.IllegalParameter, ClientHello.parse(try sharesHello(&buf, n, i, null), .stream));
            const outside = try ClientHello.parse(try sharesHello(&buf, n, null, i), .stream);
            try std.testing.expect(outside.sharesOutsideGroups());
        }
    }
}

test "F109 catalogue_hello_decoded_before_judged (a hello whose lengths do not add up is decode_error, even when its misread compression methods lack null)" {
    // tlsfuzzer's test-invalid-client-hello-w-record-overflow: one TLS 1.2 hello with its
    // compression methods' length, its cipher suites' length or its session id's length changed.
    // RFC 8446 section 6 (and RFC 5246 section 7.2.2): a field out of its range, or a length that
    // does not fit the message, is decode_error; illegal_parameter is for a hello that decodes.
    const tail = "\x00\x3f\x00\x17\x00\x00\x00\x0a\x00\x06\x00\x04\x00\x17\x01\x00\x00\x0d\x00\x12\x00\x10\x02\x03\x02\x01\x04\x03\x04\x01\x05\x03\x05\x01\x06\x03\x06\x01\x00\x32\x00\x12\x00\x10\x02\x03\x02\x01\x04\x03\x04\x01\x05\x03\x05\x01\x06\x03\x06\x01\xff\x01\x00\x01\x00";
    const head = "\x01\x00\x00\x6a\x03\x03" ++ @as([32]u8, @splat(0));
    // An empty compression list is out of compression_methods<1..2^8-1>.
    try std.testing.expectError(error.DecodeError, ClientHello.parse(head ++ "\x00\x00\x02\xc0\x2f\x00\x00" ++ tail, .stream));
    // 32 bytes of suites: the compression list read from the extensions has no null, and the
    // extensions' length then passes the message's end.
    try undecodable(head ++ "\x00\x00\x20\xc0\x2f\x01\x00" ++ tail);
    // A session id of 26 bytes swallows the suites.
    try undecodable(head ++ "\x1a\x00\x02\xc0\x2f\x01\x00" ++ tail);
    // The same hello, well formed, decodes; without the null method it is illegal_parameter.
    _ = try ClientHello.parse(head ++ "\x00\x00\x02\xc0\x2f\x01\x00" ++ tail, .stream);
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(head ++ "\x00\x00\x02\xc0\x2f\x01\x01" ++ tail, .stream));
}

/// Refused as undecodable: a field out of range or a length past its container, both decode_error.
fn undecodable(wire: []const u8) !void {
    if (ClientHello.parse(wire, .stream)) |_| return error.TestUnexpectedResult else |err| switch (err) {
        error.DecodeError, error.InvalidLength => {},
        else => return err,
    }
}

test "F111 catalogue_hello_version_tolerance (a stream hello naming any version above TLS 1.2 without supported_versions offers TLS 1.2, 0xfefe too)" {
    // tlsfuzzer's test-version-numbers: RFC 5246 appendix E.1 and RFC 8446 section 4.2.1, a server
    // answers a higher legacy_version with the highest version it speaks. A stream knows no DTLS
    // numbering: 0xfefe is a version above TLS 1.2.
    const tail = "\x00\x00\x02\xc0\x2f\x01\x00\x00\x00";
    inline for (.{ "\x03\x03", "\x03\x04", "\x03\xfe", "\x04\x00", "\xfe\xfe", "\xff\xff" }) |version| {
        const wire = "\x01\x00\x00\x2b" ++ version ++ @as([32]u8, @splat(0)) ++ tail;
        const hello = try ClientHello.parse(wire, .stream);
        try std.testing.expect(hello.offers12());
        try std.testing.expect(!hello.offers13());
    }
    const old = try ClientHello.parse("\x01\x00\x00\x2b\x03\x02" ++ @as([32]u8, @splat(0)) ++ tail, .stream);
    try std.testing.expect(!old.offers12());
}
