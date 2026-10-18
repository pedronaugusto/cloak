//! record_size_limit (RFC 8449) in both roles and both versions, over streams and datagrams:
//! offered and answered, each end's protected records held to the limit the peer named, and a
//! record past this end's own limit refused.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const DatagramPair = @import("../testing/DatagramPair.zig");
const server_module = @import("../testing/ServerPair.zig");
const ServerPair = server_module.ServerPair;
const ClientHello = @import("handshake/ClientHello.zig");
const Hello = @import("handshake/Hello.zig");
const Writer = @import("wire/Writer.zig");
const suites = @import("crypto/Suite.zig");
const Suite = suites.Suite;
const Connection = @import("Connection.zig");
const RecordLimits = @import("handshake/RecordLimits.zig");

const gpa = std.testing.allocator;

/// The client's first record, its ClientHello, parsed.
fn firstHello(duo: *Duo) !ClientHello {
    try duo.serveClient();
    const record = duo.client.output();
    return ClientHello.parse(record[5..], .stream);
}

test "C7 record_size_limit is offered: the version's maximum by default, the caller's when set" {
    const Case = struct { max: suites.Version = .tls13, limit: ?u16 = null, offered: u16 };
    for ([_]Case{
        .{ .offered = (1 << 14) + 1 },
        .{ .max = .tls12, .offered = 1 << 14 },
        .{ .limit = 512, .offered = 512 },
        .{ .max = .tls12, .limit = 64, .offered = 64 },
    }) |case| {
        const duo = try Duo.init(gpa, .{ .client_max = case.max, .client_record_size_limit = case.limit });
        defer duo.deinit();
        const hello = try firstHello(duo);
        try std.testing.expectEqual(@as(?u16, case.offered), hello.record_size_limit);
    }
}

test "C7 record_size_limit options: 64 to the versions' maximum, never in QUIC" {
    for ([_]u16{ 0, 63, (1 << 14) + 2, 0xffff }) |limit| {
        try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .record_size_limit = limit }));
    }
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .max_version = .tls12, .record_size_limit = (1 << 14) + 1 }));
    try Hello.validate(.{ .max_version = .tls12, .record_size_limit = 1 << 14 });
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .transport = .quic, .min_version = .tls13, .alpn = &.{"h3"}, .record_size_limit = 1000 }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_record_size_limit = 63 }));
}

/// A TLS 1.2 ClientHello whose extensions end with `tail`.
fn helloWith(out: []u8, tail: []const u8) []const u8 {
    const base = "\x00\x0a\x00\x06\x00\x04\x00\x1d\x00\x17" ++ "\x00\x0d\x00\x04\x00\x02\x04\x03" ++ "\x00\x17\x00\x00" ++ "\xff\x01\x00\x01\x00";
    var w: Writer = .{ .bytes = out };
    w.put(&.{ 1, 0, 0, 0, 3, 3 }) catch unreachable;
    w.put(&@as([32]u8, @splat(0x42))) catch unreachable;
    w.put(&.{ 0, 0, 2, 0xc0, 0x2b, 1, 0 }) catch unreachable;
    w.int(u16, @intCast(base.len + tail.len)) catch unreachable;
    w.put(base) catch unreachable;
    w.put(tail) catch unreachable;
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

test "C7 a ClientHello's record_size_limit is two bytes and at least 64" {
    var buf: [256]u8 = undefined;
    try std.testing.expectError(error.DecodeError, ClientHello.parse(helloWith(&buf, "\x00\x1c\x00\x01\x40"), .stream));
    try std.testing.expectError(error.DecodeError, ClientHello.parse(helloWith(&buf, "\x00\x1c\x00\x03\x00\x40\x00"), .stream));
    try std.testing.expectError(error.IllegalParameter, ClientHello.parse(helloWith(&buf, "\x00\x1c\x00\x02\x00\x3f"), .stream));
    try std.testing.expectEqual(@as(?u16, 64), (try ClientHello.parse(helloWith(&buf, "\x00\x1c\x00\x02\x00\x40"), .stream)).record_size_limit);
    // A value past every version's maximum is the client's to name (RFC 8449 section 4).
    try std.testing.expectEqual(@as(?u16, 0xffff), (try ClientHello.parse(helloWith(&buf, "\x00\x1c\x00\x02\xff\xff"), .stream)).record_size_limit);
}

/// A TLS 1.2 ServerHello with the extension block `extensions`.
fn serverHello12(out: []u8, extensions: []const u8) []const u8 {
    var w: Writer = .{ .bytes = out };
    w.put(&.{ 2, 0, 0, 0, 3, 3 }) catch unreachable;
    w.put(&@as([32]u8, @splat(0x42))) catch unreachable;
    w.put(&.{ 0, 0xc0, 0x2b, 0 }) catch unreachable;
    w.vector(u16, extensions) catch unreachable;
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

test "C7 a server's record_size_limit: TLS 1.2's ServerHello or TLS 1.3's EncryptedExtensions, at least 64" {
    const client12: Hello.Options = .{ .max_version = .tls12, .suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };
    const good = "\x00\x17\x00\x00\xff\x01\x00\x01\x00";
    var buf: [256]u8 = undefined;
    const answer = try Hello.server(serverHello12(&buf, good ++ "\x00\x1c\x00\x02\x01\x00"), "", &.{}, client12, .{});
    try std.testing.expectEqual(@as(?u16, 256), answer.tls12.record_size_limit);
    try std.testing.expectError(error.InvalidHello, Hello.server(serverHello12(&buf, good ++ "\x00\x1c\x00\x02\x00\x3f"), "", &.{}, client12, .{}));
    try std.testing.expectError(error.DecodeError, Hello.server(serverHello12(&buf, good ++ "\x00\x1c\x00\x01\x40"), "", &.{}, client12, .{}));
    // EncryptedExtensions: taken on streams and datagrams, unsolicited in QUIC.
    const ee = "\x08\x00\x00\x08\x00\x06\x00\x1c\x00\x02\x02\x00";
    try std.testing.expectEqual(@as(?u16, 512), (try Hello.encrypted(ee, .{}, false)).record_size_limit);
    try std.testing.expectError(error.UnsolicitedExtension, Hello.encrypted(ee, .{ .transport = .quic, .min_version = .tls13, .alpn = &.{"h3"} }, false));
    try std.testing.expectError(error.InvalidHello, Hello.encrypted("\x08\x00\x00\x08\x00\x06\x00\x1c\x00\x02\x00\x10", .{}, false));
}

/// Sends `message` from `from` to `to`, reading as it goes; returns the longest protected record
/// body it took.
fn transfer(from: *Connection, to: *Connection, message: []const u8, out: []u8) !usize {
    var at: usize = 0;
    while (at < message.len) at += try from.send(message[at..]);
    const bytes = from.output();
    var longest: usize = 0;
    var record: usize = 0;
    while (record + 5 <= bytes.len) {
        const len = std.mem.readInt(u16, bytes[record + 3 ..][0..2], .big);
        longest = @max(longest, len);
        record += 5 + len;
    }
    var fed: usize = 0;
    var got: usize = 0;
    while (got < message.len) {
        const view = to.readable();
        if (view.len != 0) {
            @memcpy(out[got..][0..view.len], view);
            to.consume(view.len);
            got += view.len;
            continue;
        }
        const n = try to.receive(bytes[fed..]);
        if (n == 0) return error.Stalled;
        fed += n;
    }
    from.acknowledge(bytes.len);
    try std.testing.expectEqualSlices(u8, message, out[0..got]);
    return longest;
}

/// A handshake and data both ways under these limits; returns each end's longest protected
/// record body, client first.
fn exchange(options: Duo.Options) ![2]usize {
    const duo = try Duo.init(gpa, options);
    defer duo.deinit();
    try duo.handshake();
    var message: [5000]u8 = undefined;
    for (&message, 0..) |*byte, i| byte.* = @truncate(i);
    var out: [5000]u8 = undefined;
    const sent = try transfer(&duo.client, &duo.server, &message, &out);
    const answered = try transfer(&duo.server, &duo.client, &message, &out);
    return .{ @max(sent, duo.longest_protected[0]), @max(answered, duo.longest_protected[1]) };
}

test "C7 each end seals its protected records within the limit the peer named, handshake records included" {
    // TLS 1.3 counts the inner content type in the limit and its records add a 16-byte tag; TLS
    // 1.2's AES-GCM adds an 8-byte explicit nonce and the tag.
    const Case = struct { suite: Suite, client: ?u16, server: ?u16 };
    for ([_]Case{
        .{ .suite = .aes_128_gcm_sha256, .client = 64, .server = null },
        .{ .suite = .aes_128_gcm_sha256, .client = null, .server = 300 },
        .{ .suite = .chacha20_poly1305_sha256, .client = 1000, .server = 2000 },
        .{ .suite = .ecdhe_ecdsa_aes_128_gcm_sha256, .client = 64, .server = 100 },
        .{ .suite = .ecdhe_ecdsa_chacha20_poly1305_sha256, .client = 1 << 14, .server = 777 },
        .{ .suite = .ecdhe_ecdsa_aes_128_ccm_8, .client = 200, .server = 64 },
    }) |case| {
        const tls13 = case.suite.version() == .tls13;
        const longest = try exchange(.{ .client_suites = &.{case.suite}, .server_suites = &.{case.suite}, .client_record_size_limit = case.client, .server_record_size_limit = case.server });
        const expansion: usize = if (tls13) 16 else switch (case.suite) {
            .ecdhe_ecdsa_chacha20_poly1305_sha256 => 16,
            .ecdhe_ecdsa_aes_128_ccm_8 => 8 + 8,
            else => 8 + 16,
        };
        const full: usize = if (tls13) (1 << 14) + 1 else 1 << 14;
        // What the server sends is bounded by the client's limit, and the other way round.
        try std.testing.expect(longest[1] <= expansion + (case.client orelse full));
        try std.testing.expect(longest[0] <= expansion + (case.server orelse full));
        // And filled to it: the 5000 bytes sent come in records of the limit.
        if (case.client) |limit| if (limit < 4000) try std.testing.expectEqual(expansion + limit, longest[1]);
        if (case.server) |limit| if (limit < 4000) try std.testing.expectEqual(expansion + limit, longest[0]);
    }
}

test "C7 a server answers record_size_limit only to a client that sent it, at most the version's maximum" {
    inline for (.{ @as(?u16, null), @as(?u16, 64), @as(?u16, 0xffff) }) |offered| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(gpa, .{ .record_size_limit = offered }, .{ .record_size_limit = 4000 });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(?u16, if (offered == null) null else 4000), pair.client.record_size_answer);
        // The client's 2^16 - 1 is taken as TLS 1.3's 2^14 + 1: a full record reaches it.
        var big: [1 << 14]u8 = @splat('x');
        try std.testing.expectEqual(if (offered) |limit| @min(limit - 1, 1 << 14) else 1 << 14, try pair.conn.send(&big));
    }
    // Nothing above the maximum is answered: a server of the default names TLS 1.3's 2^14 + 1.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(gpa, .{ .record_size_limit = 1000 }, .{});
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(@as(?u16, (1 << 14) + 1), pair.client.record_size_answer);
}

test "C7 a client's record_size_limit under 64 is illegal_parameter" {
    const pair = try ServerPair(.aes_128_gcm_sha256).init(gpa, .{ .record_size_limit = 63 }, .{});
    defer pair.deinit();
    // The run ends at the server's refusal; its diagnostics say why.
    if (pair.run()) |_| return error.TestUnexpectedResult else |_| {}
    try std.testing.expectEqual(error.IllegalParameter, pair.conn.diagnostics().reason.?);
    try std.testing.expectEqual(@import("wire/Alert.zig").Alert.illegal_parameter, pair.conn.diagnostics().alert_sent.?);
}

test "C7 a server refuses a record past the limit it answered with record_overflow" {
    for ([_]usize{ 199, 200 }) |len| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(gpa, .{ .record_size_limit = 1 << 14 }, .{ .record_size_limit = 200 });
        defer pair.deinit();
        try pair.run();
        var bytes: [256]u8 = @splat('y');
        try pair.client.send(bytes[0..len]);
        var out: [256]u8 = undefined;
        // The inner plaintext is the content and its type: 200 bytes take 199 of content.
        if (len < 200) {
            try std.testing.expectEqual(len, try pair.read(&out));
        } else {
            try std.testing.expectError(error.RecordOverflow, pair.read(&out));
            try std.testing.expectEqual(@import("wire/Alert.zig").Alert.record_overflow, pair.conn.diagnostics().alert_sent.?);
        }
    }
}

test "C7 both ends keep the limits they agreed, and a client refuses a record past its own" {
    for ([_]suites.Version{ .tls13, .tls12 }) |version| {
        const duo = try Duo.init(gpa, .{ .client_max = version, .client_record_size_limit = 100, .server_record_size_limit = 3000 });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(RecordLimits{ .send = 3000, .receive = 100 }, duo.client.record_limits);
        try std.testing.expectEqual(RecordLimits{ .send = 100, .receive = 3000 }, duo.server.record_limits);
        // A server that ignored the client's limit: its record is refused before it is opened.
        duo.server.record_limits.send = RecordLimits.max13;
        var bytes: [200]u8 = @splat('w');
        try std.testing.expectEqual(@as(usize, 200), try duo.server.send(&bytes));
        try std.testing.expectError(error.RecordOverflow, duo.deliverServer());
        try std.testing.expectEqual(@import("wire/Alert.zig").Alert.record_overflow, duo.client.diagnostics().alert_sent.?);
    }
}

test "C7 a TLS 1.2 limit past 2^14 is taken as 2^14" {
    const duo = try Duo.init(gpa, .{ .server_max = .tls12 });
    defer duo.deinit();
    try duo.handshake();
    // The client offered TLS 1.3's 2^14 + 1; in TLS 1.2 it means 2^14.
    try std.testing.expectEqual(RecordLimits{ .send = 1 << 14, .receive = 1 << 14 }, duo.server.record_limits);
}

test "C7 datagrams: each end seals within the peer's limit, writes past it are refused, DTLS 1.3 and 1.2" {
    const lists = [_][]const Suite{ Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };
    for (lists) |list| for ([_]?[]const u8{ null, "cid-1" }) |cid| {
        if (cid != null and list.len != 1) continue;
        const pair = try DatagramPair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_record_size_limit = 64, .server_record_size_limit = 128, .client_cid = cid, .server_cid = cid });
        defer pair.deinit();
        // Every flight goes in fragments within 64 or 128 bytes; one past either would be dropped
        // and the handshake would not end.
        try pair.run();
        const tls13 = list.len != 1;
        const inner: usize = @intFromBool(tls13 or cid != null);
        try std.testing.expectEqual(@as(usize, 128) - inner, pair.client.dtls.writeLimit());
        try std.testing.expectEqual(@as(usize, 64) - inner, pair.server.dtls.writeLimit());
        var out: [512]u8 = undefined;
        var bytes: [128]u8 = @splat('z');
        try std.testing.expectError(error.InvalidLength, pair.server.dtls.write(bytes[0 .. 65 - inner], &out));
        try pair.exchange(&pair.server, bytes[0 .. 64 - inner]);
        try pair.exchange(&pair.client, bytes[0 .. 128 - inner]);
        // A record past the client's own limit, from a server that ignored it, is dropped.
        const before = pair.client.received.items.len;
        pair.server.dtls.record_limits.send = RecordLimits.max13;
        try pair.exchange(&pair.server, bytes[0..100]);
        try std.testing.expectEqual(before, pair.client.received.items.len);
        try std.testing.expect(pair.client.dtls.failure() == null);
    };
}
