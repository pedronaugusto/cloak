const std = @import("std");
const Cookies = @import("Cookies.zig");
const Datagram = @import("Datagram.zig");
const Record = @import("Record.zig");
const gpa = std.testing.allocator;
const Hello = @import("../handshake/Hello.zig");
const suites = @import("../crypto/Suite.zig");

const options: Datagram.ServerOptions = .{ .credentials = &.{} };

/// A client's first DTLS hello in one plaintext record, with `cookie` in the cookie extension (DTLS
/// 1.3) or the cookie field (DTLS 1.2).
fn hello(out: []u8, version: suites.Version, cookie: []const u8, message_seq: u16) ![]u8 {
    var body: [2048]u8 = undefined;
    const share: [32]u8 = @splat(7);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &share }};
    const random: [32]u8 = @splat(3);
    const message = switch (version) {
        .tls13 => try Hello.client(body[12..], &random, "", "", &shares, cookie, .{ .transport = .datagram, .min_version = .tls13, .sni = "example.com" }, .{}),
        .tls12 => try Hello.client(body[12..], &random, "", cookie, &.{}, "", .{ .transport = .datagram, .max_version = .tls12, .suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .sni = "example.com" }, .{}),
    };
    // TLS form to DTLS form: type, length, message_seq, offset 0, fragment length.
    const len = message.len - 4;
    var header: [12]u8 = undefined;
    header[0] = 1;
    std.mem.writeInt(u24, header[1..4], @intCast(len), .big);
    std.mem.writeInt(u16, header[4..6], message_seq, .big);
    header[6..9].* = .{ 0, 0, 0 };
    std.mem.writeInt(u24, header[9..12], @intCast(len), .big);
    @memcpy(body[0..12], &header);
    @memmove(body[12..][0..len], message[4..]);
    return Record.plaintext(.handshake, message_seq, body[0 .. 12 + len], out);
}

/// The cookie a response carries: the retry request's cookie extension, or the
/// HelloVerifyRequest's.
fn cookieOf(response: []const u8, buffer: *[512]u8) []const u8 {
    const body = response[Record.header12 + 12 ..];
    if (response[Record.header12] == 3) {
        const len = body[2];
        @memcpy(buffer[0..len], body[3..][0..len]);
        return buffer[0..len];
    }
    // A retry request: find extension 44.
    const at = std.mem.find(u8, body, &.{ 0, 44 }).?;
    const len = std.mem.readInt(u16, body[at + 4 ..][0..2], .big);
    @memcpy(buffer[0..len], body[at + 6 ..][0..len]);
    return buffer[0..len];
}

fn keyed() !Cookies {
    var cookies: Cookies = .{};
    try cookies.rotate(@splat(0x41));
    return cookies;
}

test "F80 catalogue_dtls_client_random_cookie_and_amplification: a cookie is answered statelessly, bound to its address and time" {
    var cookies = try keyed();
    defer cookies.deinit();
    const now: std.Io.Timestamp = .fromNanoseconds(1000 * std.time.ns_per_s);
    for ([_]suites.Version{ .tls13, .tls12 }) |version| {
        var first_buf: [2048]u8 = undefined;
        const first = try hello(&first_buf, version, "", 0);
        var out: [4096]u8 = undefined;
        const verdict = cookies.check(gpa, &options, "198.51.100.7:4433", now, first, &out);
        const response = verdict.respond;
        // At most three times the hello: no more before the address is proven.
        try std.testing.expect(response.len <= 3 * first.len);
        // Epoch 0, the hello's record sequence, the server's first message.
        try std.testing.expectEqual(@as(u8, 22), response[0]);
        try std.testing.expectEqual(@as(u8, if (version == .tls13) 2 else 3), response[Record.header12]);
        var cookie_buf: [512]u8 = undefined;
        const cookie = cookieOf(response, &cookie_buf);
        var second_buf: [2048]u8 = undefined;
        const second = try hello(&second_buf, version, cookie, 1);
        // The cookie admits this address, now and within its lifetime.
        try std.testing.expect(cookies.check(gpa, &options, "198.51.100.7:4433", now, second, &out) == .admit);
        try std.testing.expect(cookies.check(gpa, &options, "198.51.100.7:4433", .fromNanoseconds(now.nanoseconds + 59 * std.time.ns_per_s), second, &out) == .admit);
        // Not another address, not after its lifetime, not from the far future.
        try std.testing.expect(cookies.check(gpa, &options, "198.51.100.8:4433", now, second, &out) == .drop);
        try std.testing.expect(cookies.check(gpa, &options, "198.51.100.7:4433", .fromNanoseconds(now.nanoseconds + 61 * std.time.ns_per_s), second, &out) == .drop);
        try std.testing.expect(cookies.check(gpa, &options, "198.51.100.7:4433", .fromNanoseconds(now.nanoseconds - 120 * std.time.ns_per_s), second, &out) == .drop);
        // A flipped bit anywhere in the cookie is refused.
        for (0..cookie.len * 8) |bit| {
            var bad: [512]u8 = undefined;
            @memcpy(bad[0..cookie.len], cookie);
            bad[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
            var forged_buf: [2048]u8 = undefined;
            const forged = try hello(&forged_buf, version, bad[0..cookie.len], 1);
            try std.testing.expect(cookies.check(gpa, &options, "198.51.100.7:4433", now, forged, &out) != .admit);
        }
    }
}

test "C8 a rotated cookie key keeps the previous one's cookies, not older ones" {
    var cookies = try keyed();
    defer cookies.deinit();
    const now: std.Io.Timestamp = .fromNanoseconds(5000 * std.time.ns_per_s);
    var first_buf: [2048]u8 = undefined;
    const first = try hello(&first_buf, .tls13, "", 0);
    var out: [4096]u8 = undefined;
    var cookie_buf: [512]u8 = undefined;
    const cookie = cookieOf(cookies.check(gpa, &options, "a", now, first, &out).respond, &cookie_buf);
    var second_buf: [2048]u8 = undefined;
    const second = try hello(&second_buf, .tls13, cookie, 1);
    var copy: [2048]u8 = undefined;
    try cookies.rotate(@splat(0x42));
    @memcpy(copy[0..second.len], second);
    try std.testing.expect(cookies.check(gpa, &options, "a", now, copy[0..second.len], &out) == .admit);
    try cookies.rotate(@splat(0x43));
    @memcpy(copy[0..second.len], second);
    try std.testing.expect(cookies.check(gpa, &options, "a", now, copy[0..second.len], &out) == .drop);
    try std.testing.expectError(error.InvalidKey, cookies.rotate(@splat(0)));
}

test "C8 the cookie check answers only first-epoch hellos and keeps nothing" {
    var cookies = try keyed();
    defer cookies.deinit();
    var out: [4096]u8 = undefined;
    const now: std.Io.Timestamp = .fromNanoseconds(1);
    // Junk, an alert, a record of another epoch, an empty datagram: dropped.
    var junk = [_]u8{ 0x40, 1, 2, 3 };
    try std.testing.expect(cookies.check(gpa, &options, "a", now, &junk, &out) == .drop);
    try std.testing.expect(cookies.check(gpa, &options, "a", now, &.{}, &out) == .drop);
    var alert_buf: [64]u8 = undefined;
    const alert = try Record.plaintext(.alert, 0, &.{ 2, 40 }, &alert_buf);
    try std.testing.expect(cookies.check(gpa, &options, "a", now, alert, &out) == .drop);
    var first_buf: [2048]u8 = undefined;
    const first = try hello(&first_buf, .tls13, "", 0);
    first[4] = 1;
    try std.testing.expect(cookies.check(gpa, &options, "a", now, first, &out) == .drop);
    // No key yet: nothing is answered.
    var empty: Cookies = .{};
    var again_buf: [2048]u8 = undefined;
    try std.testing.expect(empty.check(gpa, &options, "a", now, try hello(&again_buf, .tls13, "", 0), &out) == .drop);
}

/// The first fragment of `record`'s hello, its first `keep` bytes of body, as the only record.
fn firstFragment(record: []u8, keep: usize) []u8 {
    const body = record[Record.header12..];
    std.mem.writeInt(u24, body[9..12], @intCast(keep), .big);
    std.mem.writeInt(u16, record[11..13], @intCast(12 + keep), .big);
    return record[0 .. Record.header12 + 12 + keep];
}

test "C8 a first hello in fragments: a DTLS 1.2 server answers its first fragment, a DTLS 1.3 one drops it" {
    var cookies = try keyed();
    defer cookies.deinit();
    const now: std.Io.Timestamp = .fromNanoseconds(1000 * std.time.ns_per_s);
    var buffer: [2048]u8 = undefined;
    var out: [2048]u8 = undefined;
    // As OpenSSL sends a hello longer than the 256-byte minimum MTU it falls back to: the random,
    // session id, cookie field and suites in the first fragment.
    const whole = try hello(&buffer, .tls12, "", 0);
    const fragment = firstFragment(whole, 60);
    var only12 = options;
    only12.max_version = .tls12;
    const answer = switch (cookies.check(gpa, &only12, "client:1", now, fragment, &out)) {
        .respond => |bytes| bytes,
        else => return error.TestUnexpectedResult,
    };
    // The cookie it carries admits the second hello, whole or in fragments.
    var cookie_buffer: [512]u8 = undefined;
    const cookie = cookieOf(answer, &cookie_buffer);
    var second_buffer: [2048]u8 = undefined;
    const second = try hello(&second_buffer, .tls12, cookie, 1);
    var copy: [2048]u8 = undefined;
    @memcpy(copy[0..second.len], second);
    try std.testing.expect(cookies.check(gpa, &only12, "client:1", now, copy[0..second.len], &out) == .admit);
    try std.testing.expect(cookies.check(gpa, &only12, "client:1", now, firstFragment(second, 80), &out) == .admit);
    // A server that speaks DTLS 1.3 cannot tell the hello's versions from the fragment.
    const again = try hello(&buffer, .tls12, "", 0);
    try std.testing.expect(cookies.check(gpa, &options, "client:1", now, firstFragment(again, 60), &out) == .drop);
    // A fragment cut before its suites is dropped.
    const short = try hello(&buffer, .tls12, "", 0);
    try std.testing.expect(cookies.check(gpa, &only12, "client:1", now, firstFragment(short, 36), &out) == .drop);
}

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist (open code points: a cookie names only a group cloak speaks)" {
    // `check` reads the caller's options unchecked. Listing ffdhe2048 first, and a client
    // offering it (in place of P-256) without a share: the retry request asks for P-384.
    var cookies = try keyed();
    defer cookies.deinit();
    const ffdhe2048: Hello.Group = @fromBackingInt(@intCast(0x0100));
    const listing: Datagram.ServerOptions = .{ .credentials = &.{}, .groups = &.{ ffdhe2048, .p384 } };
    var first_buf: [2048]u8 = undefined;
    const first = try hello(&first_buf, .tls13, "", 0);
    const at = std.mem.find(u8, first, &.{ 0x11, 0xec, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18 }).?;
    first[at + 4 ..][0..2].* = .{ 0x01, 0x00 };
    var out: [4096]u8 = undefined;
    const response = cookies.check(gpa, &listing, "a", .fromNanoseconds(1), first, &out).respond;
    // The retry request's key_share: the selected group.
    const body = response[Record.header12 + 12 ..];
    const share = std.mem.find(u8, body, &.{ 0, 51, 0, 2 }).?;
    try std.testing.expectEqualSlices(u8, &.{ 0x00, 0x18 }, body[share + 4 ..][0..2]);
}
