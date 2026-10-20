const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");
const H = @import("Hello.zig");
const Reader = @import("../../wire/Reader.zig");
const Extensions = @import("../wire/Extensions.zig");
const x: [32]u8 = @splat(1);
const shares = [_]H.Share{.{ .group = .x25519, .bytes = &x }};
const fixture = @embedFile("testdata/server-hello.bin");
test "C2 hello codec RFC server selection and bounded client offer" {
    const parsed = (try H.server(fixture, "", &shares, .{}, .{})).tls13;
    try std.testing.expectEqual(.aes_128_gcm_sha256, parsed.suite);
    try std.testing.expectEqual(.x25519, parsed.group);
    try std.testing.expectEqual(@as(usize, 32), parsed.share.len);
    var out: [4096]u8 = undefined;
    const ch = try H.client(&out, &@as([32]u8, @splat(2)), "", "", &shares, "", .{ .sni = "example.com", .alpn = &.{ "h2", "http/1.1" }, .min_version = .tls13 }, .{});
    try std.testing.expectEqual(@as(usize, std.mem.readInt(u24, ch[1..4], .big)), ch.len - 4);
    var r: Reader = .{ .bytes = ch[4..] };
    try std.testing.expectEqual(@as(u16, 0x0303), try r.int(u16));
    _ = try r.take(32);
    _ = try r.vector(u8);
    _ = try r.vector(u16);
    _ = try r.vector(u8);
    var ext: Extensions = .{ .reader = try r.vector(u16) };
    try r.finish();
    var ids: [12]u16 = undefined;
    var count: usize = 0;
    while (try ext.next()) |item| {
        ids[count] = item.id;
        count += 1;
    }
    // record_size_limit (28) ahead of the run an ECH outer hello shares.
    try std.testing.expectEqualSlices(u16, &.{ 0, 28, 10, 13, 43, 16, 51 }, ids[0..count]);
    // With TLS 1.2 offered too: point formats, extended master secret and renegotiation_info.
    const both = try H.client(&out, &@as([32]u8, @splat(2)), "", "", &shares, "", .{ .sni = "example.com", .alpn = &.{ "h2", "http/1.1" } }, .{});
    var rb: Reader = .{ .bytes = both[4..] };
    _ = try rb.take(34);
    _ = try rb.vector(u8);
    _ = try rb.vector(u16);
    _ = try rb.vector(u8);
    var ext_both: Extensions = .{ .reader = try rb.vector(u16) };
    count = 0;
    while (try ext_both.next()) |item| {
        ids[count] = item.id;
        count += 1;
    }
    try std.testing.expectEqualSlices(u16, &.{ 0, 28, 10, 11, 13, 23, 0xff01, 43, 16, 51 }, ids[0..count]);
    try std.testing.expectError(error.BufferTooSmall, H.client(out[0..10], &@as([32]u8, @splat(2)), "", "", &shares, "", .{}, .{}));
}
test "F31 catalogue_hrr_illegal_group_ch2_and_reallocation: hello selection" {
    var hrr = fixture.*;
    @memcpy(hrr[6..38], &H.retry_random);
    // Replace the key-share body with selected_group while retaining supported_versions.
    var valid: [58]u8 = undefined;
    @memcpy(valid[0..46], hrr[0..46]);
    std.mem.writeInt(u24, valid[1..4], 54, .big);
    std.mem.writeInt(u16, valid[42..44], 12, .big);
    valid[44..].* = .{ 0, 51, 0, 2, 0, 23, 0, 43, 0, 2, 3, 4, 0, 0 };
    // Exact ServerHello prefix is 44 bytes; body here is twelve extension bytes.
    const message = valid[0..56];
    std.mem.writeInt(u24, valid[1..4], 52, .big);
    const retry = (try H.server(message, "", &shares, .{}, .{})).tls13;
    try std.testing.expect(retry.retry and retry.group == .p256);
    valid[48..50].* = .{ 0, 29 };
    try std.testing.expectError(error.InvalidHello, H.server(message, "", &shares, .{}, .{}));
    valid[48..50].* = .{ 0, 24 };
    try std.testing.expectError(error.UnofferedSelection, H.server(message, "", &shares, .{ .groups = &.{ .x25519, .p256 } }, .{}));
    var duplicate: [62]u8 = undefined;
    @memcpy(duplicate[0..56], message);
    std.mem.writeInt(u24, duplicate[1..4], 58, .big);
    std.mem.writeInt(u16, duplicate[42..44], 18, .big);
    duplicate[56..].* = .{ 0, 43, 0, 2, 3, 4 };
    try std.testing.expectError(error.DuplicateExtension, H.server(&duplicate, "", &shares, .{}, .{}));
}
test "F41 catalogue_alpaca_protocol_and_port_binding: required ALPN" {
    const ee = "\x08\x00\x00\x0b\x00\x09\x00\x10\x00\x05\x00\x03\x02h2";
    const parsed = try H.encrypted(ee, .{ .alpn = &.{"h2"}, .require_alpn = true }, false);
    try std.testing.expectEqualSlices(u8, "h2", parsed.alpn);
    try std.testing.expectError(error.UnofferedSelection, H.encrypted(ee, .{ .alpn = &.{"http/1.1"} }, false));
    try std.testing.expectError(error.NoApplicationProtocol, H.encrypted("\x08\x00\x00\x02\x00\x00", .{ .alpn = &.{"h2"}, .require_alpn = true }, false));
    try std.testing.expectError(error.InvalidOptions, H.validate(.{ .sni = "*.example.com" }));
    try std.testing.expectError(error.InvalidOptions, H.validate(.{ .alpn = &.{""} }));
    try std.testing.expectError(error.HybridRequired, H.server(fixture, "", &shares, .{ .require_hybrid = true }, .{}));
}
test "C2 hello parser truncation at every RFC byte" {
    for (0..fixture.len) |len| {
        try std.testing.expectError(error.InvalidLength, H.server(fixture[0..len], "", &shares, .{}, .{}));
    }
}
test "C2 fuzz TLS hello selections and extension placement" {
    try shakedown.check(std.testing.allocator, {}, fuzz, .{});
}
fn fuzz(_: void, case: *shakedown.Case) !void {
    var bytes: [4096]u8 = undefined;
    try parseAny(inputs.draw(case, &bytes, &.{ fixture, "\x08\x00\x00\x02\x00\x00" }, 48));
}
test "C2 TLS hello selections take the fixture and an empty encrypted extensions" {
    try parseAny(fixture);
    try parseAny("\x08\x00\x00\x02\x00\x00");
}
fn parseAny(input: []const u8) !void {
    if (H.server(input, "", &shares, .{}, .{})) |answer| switch (answer) {
        .tls13 => |parsed| try std.testing.expect(parsed.retry or parsed.share.len == parsed.group.?.serverShareLength()),
        .tls12 => |parsed| try std.testing.expect(parsed.random.len == 32),
    } else |_| {}
    if (H.encrypted(input, .{}, false)) |parsed| {
        try std.testing.expectEqual(@as(usize, 0), parsed.alpn.len);
    } else |_| {}
}

test "C2 cookie-only HRR and empty QUIC parameter presence" {
    var cookie_hrr: [58]u8 = undefined;
    @memcpy(cookie_hrr[0..44], fixture[0..44]);
    @memcpy(cookie_hrr[6..38], &H.retry_random);
    std.mem.writeInt(u24, cookie_hrr[1..4], 54, .big);
    std.mem.writeInt(u16, cookie_hrr[42..44], 14, .big);
    cookie_hrr[44..].* = .{ 0, 43, 0, 2, 3, 4, 0, 44, 0, 4, 0, 2, 'o', 'k' };
    const retry = (try H.server(&cookie_hrr, "", &shares, .{}, .{})).tls13;
    try std.testing.expect(retry.retry and retry.group == null);
    try std.testing.expectEqualSlices(u8, "ok", retry.cookie);
    const ee = "\x08\x00\x00\x0f\x00\x0d\x00\x10\x00\x05\x00\x03\x02h2\x00\x39\x00\x00";
    const parsed = try H.encrypted(ee, .{ .alpn = &.{"h2"}, .transport = .quic }, false);
    try std.testing.expectEqualSlices(u8, "h2", parsed.alpn);
    try std.testing.expectEqual(@as(usize, 0), parsed.parameters.len);
    // Acceptance belongs to the QUIC parameter service, not this opaque parser.
}
test "F68 a ServerHello selects only the one identity the client offered" {
    var message: [fixture.len + 6]u8 = undefined;
    @memcpy(message[0..fixture.len], fixture);
    std.mem.writeInt(u24, message[1..4], fixture.len + 6 - 4, .big);
    std.mem.writeInt(u16, message[42..44], std.mem.readInt(u16, fixture[42..44], .big) + 6, .big);
    message[fixture.len..].* = .{ 0, 41, 0, 2, 0, 0 };
    try std.testing.expect((try H.server(&message, "", &shares, .{}, .{ .psk = true })).tls13.psk);
    try std.testing.expectError(error.UnsolicitedExtension, H.server(&message, "", &shares, .{}, .{}));
    message[fixture.len + 5] = 1;
    try std.testing.expectError(error.InvalidHello, H.server(&message, "", &shares, .{}, .{ .psk = true }));
    try std.testing.expect(!(try H.server(fixture, "", &shares, .{}, .{ .psk = true })).tls13.psk);
}

test "F118 catalogue_tls12_only_hello_offers_classical_groups (a hello offering TLS 1.2 alone lists no post-quantum group)" {
    // Hybrid and ML-KEM groups are TLS 1.3's (designs/cloak.md section 5.8; RFC 8422 has no such
    // group): a hello that cannot negotiate TLS 1.3 names only groups TLS 1.2 can use.
    var out: [4096]u8 = undefined;
    for ([_]bool{ false, true }) |only12| {
        const ch = try H.client(&out, &@as([32]u8, @splat(2)), "", "", if (only12) &.{} else &shares, "", .{ .sni = "example.com", .max_version = if (only12) .tls12 else .tls13 }, .{});
        var r: Reader = .{ .bytes = ch[4..] };
        _ = try r.take(34);
        _ = try r.vector(u8);
        _ = try r.vector(u16);
        _ = try r.vector(u8);
        var ext: Extensions = .{ .reader = try r.vector(u16) };
        var pq: usize = 0;
        var classical: usize = 0;
        while (try ext.next()) |item| if (item.id == 10) {
            var list: Reader = .{ .bytes = item.bytes };
            var groups = try list.vector(u16);
            while (groups.bytes.len != groups.pos) {
                const group: @import("../crypto/Group.zig").Group = @fromBackingInt(@intCast(try groups.int(u16)));
                if (group.classical()) classical += 1 else pq += 1;
            }
        };
        try std.testing.expect(classical != 0);
        try std.testing.expectEqual(only12, pq == 0);
    }
}

test "F120 catalogue_unsolicited_extension_unsupported (an extension the client never sent is unsupported_extension)" {
    // RFC 8446 section 4.2: a response to an extension the client did not send ends the handshake
    // with unsupported_extension (Client maps UnsolicitedExtension to it); one the client
    // recognizes in a message it is not specified for is illegal_parameter (InvalidHello).
    const ee = struct {
        fn of(comptime id: u16, comptime body: []const u8) []const u8 {
            const ext = [_]u8{ id >> 8, id & 0xff, 0, body.len } ++ body;
            return [_]u8{ 8, 0, 0, 2 + ext.len, 0, ext.len } ++ ext;
        }
    };
    // An extension type cloak does not know, so never sent.
    try std.testing.expectError(error.UnsolicitedExtension, H.encrypted(ee.of(0x7a7a, ""), .{}, false));
    // server_name acknowledged without a name sent; ALPN answered without any offered.
    try std.testing.expectError(error.UnsolicitedExtension, H.encrypted(ee.of(0, ""), .{}, false));
    try std.testing.expectError(error.UnsolicitedExtension, H.encrypted(ee.of(16, "\x00\x03\x02h2"), .{}, false));
    // QUIC transport parameters on a stream.
    try std.testing.expectError(error.UnsolicitedExtension, H.encrypted(ee.of(57, ""), .{}, false));
    // key_share is the client's own, out of place in EncryptedExtensions.
    try std.testing.expectError(error.InvalidHello, H.encrypted(ee.of(51, ""), .{}, false));
    // A server_name acknowledgement is empty: one with data is out of its range.
    try std.testing.expectError(error.DecodeError, H.encrypted(ee.of(0, "\x00"), .{ .sni = "example.com" }, false));
}

test "F121 catalogue_field_out_of_range_decode_error (a session id echo past 32 bytes is decode_error)" {
    // RFC 8446 section 4.1.3 and RFC 5246 section 7.4.1.3: legacy_session_id_echo<0..32>; a field
    // out of its range is decode_error (RFC 8446 section 6.2).
    var message: [4 + 2 + 32 + 1 + 33 + 2 + 1 + 2]u8 = @splat(0);
    message[0] = 2;
    std.mem.writeInt(u24, message[1..4], message.len - 4, .big);
    message[4] = 3;
    message[5] = 3;
    message[4 + 34] = 33;
    message[4 + 34 + 1 + 33] = 0x13;
    message[4 + 34 + 1 + 33 + 1] = 0x01;
    try std.testing.expectError(error.DecodeError, H.server(&message, "", &shares, .{}, .{}));
}
