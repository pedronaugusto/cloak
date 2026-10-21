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
    try std.testing.expectEqual(0, (try H.server(&message, "", &shares, .{}, .{ .psk = 1 })).tls13.psk.?);
    try std.testing.expectError(error.UnsolicitedExtension, H.server(&message, "", &shares, .{}, .{}));
    message[fixture.len + 5] = 1;
    try std.testing.expectError(error.InvalidHello, H.server(&message, "", &shares, .{}, .{ .psk = 1 }));
    // An index within what was offered selects that identity.
    try std.testing.expectEqual(1, (try H.server(&message, "", &shares, .{}, .{ .psk = 2 })).tls13.psk.?);
    try std.testing.expectEqual(null, (try H.server(fixture, "", &shares, .{}, .{ .psk = 1 })).tls13.psk);
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

test "F125 catalogue_tls12_server_groups_ignored (supported_groups in a TLS 1.2 ServerHello is taken and ignored; in TLS 1.3 it stays illegal_parameter)" {
    // No TLS 1.2 text forbids a server's supported_groups (RFC 8422 section 5.2 defines
    // ec_point_formats alone for the ServerHello and refuses nothing else; RFC 5246 section
    // 7.4.1.4 refuses only extensions the client did not send). RFC 8446 section 4.2's table
    // lists it for ClientHello and EncryptedExtensions, so a TLS 1.3 ServerHello carrying it is
    // illegal_parameter (InvalidHello).
    const hello = struct {
        fn of(comptime suite: u16, comptime exts: []const u8) [4 + 2 + 32 + 1 + 2 + 1 + 2 + exts.len]u8 {
            const tail: [exts.len]u8 = exts[0..exts.len].*;
            const body = [_]u8{ 3, 3 } ++ @as([32]u8, @splat(0x11)) ++ [_]u8{ 0, suite >> 8, suite & 0xff, 0, 0, exts.len } ++ tail;
            return [_]u8{ 2, 0, 0, body.len } ++ body;
        }
    };
    const groups = "\x00\x0a\x00\x04\x00\x02\x00\x1d";
    const tls12 = hello.of(0xc02b, "\x00\x17\x00\x00" ++ "\xff\x01\x00\x01\x00" ++ groups);
    switch (try H.server(&tls12, "", &.{}, .{ .max_version = .tls12 }, .{})) {
        .tls12 => |parsed| try std.testing.expectEqual(@as(u16, 0xc02b), @backingInt(parsed.suite)),
        .tls13 => return error.TestUnexpectedResult,
    }
    const tls13 = hello.of(0x1301, "\x00\x2b\x00\x02\x03\x04" ++ "\x00\x33\x00\x24\x00\x1d\x00\x20" ++ @as([32]u8, @splat(1)) ++ groups);
    try std.testing.expectError(error.InvalidHello, H.server(&tls13, "", &shares, .{}, .{}));
    // F127: quic_transport_parameters in a ServerHello: a stream client never sent it
    // (unsupported_extension, RFC 9001 section 8.2); a QUIC one has it in EncryptedExtensions.
    const quic13 = hello.of(0x1301, "\x00\x2b\x00\x02\x03\x04" ++ "\x00\x33\x00\x24\x00\x1d\x00\x20" ++ @as([32]u8, @splat(1)) ++ "\x00\x39\x00\x00");
    try std.testing.expectError(error.UnsolicitedExtension, H.server(&quic13, "", &shares, .{}, .{}));
    try std.testing.expectError(error.InvalidHello, H.server(&quic13, "", &shares, .{ .transport = .quic, .alpn = &.{"h3"}, .parameters = "x" }, .{}));
    // Without it the same TLS 1.3 ServerHello is taken.
    const plain13 = hello.of(0x1301, "\x00\x2b\x00\x02\x03\x04" ++ "\x00\x33\x00\x24\x00\x1d\x00\x20" ++ @as([32]u8, @splat(1)));
    _ = try H.server(&plain13, "", &shares, .{}, .{});
}

const server13 = struct {
    fn of(comptime random: [32]u8, comptime exts: []const u8) [4 + 2 + 32 + 1 + 2 + 1 + 2 + exts.len]u8 {
        const tail: [exts.len]u8 = exts[0..exts.len].*;
        const body = [_]u8{ 3, 3 } ++ random ++ [_]u8{ 0, 0x13, 0x01, 0, 0, exts.len } ++ tail;
        return [_]u8{ 2, 0, 0, body.len } ++ body;
    }
};

test "F134 catalogue_empty_alpn_selection_decode_error (a selected protocol name of no bytes is decode_error)" {
    // RFC 7301 section 3.1: ProtocolName<1..2^8-1>; a name out of its range is decode_error
    // (RFC 8446 section 6.2), not a name the client did not offer.
    const ee = "\x08\x00\x00\x09\x00\x07\x00\x10\x00\x03\x00\x01\x00";
    try std.testing.expectError(error.DecodeError, H.encrypted(ee, .{ .alpn = &.{"h2"} }, false));
    // The same in a TLS 1.2 ServerHello.
    const tls12_body = [_]u8{ 3, 3 } ++ @as([32]u8, @splat(0x11)) ++ [_]u8{ 0, 0xc0, 0x2b, 0, 0, 16 } ++ "\x00\x17\x00\x00".* ++ "\xff\x01\x00\x01\x00".* ++ "\x00\x10\x00\x03\x00\x01\x00".*;
    const tls12 = [_]u8{ 2, 0, 0, tls12_body.len } ++ tls12_body;
    try std.testing.expectError(error.DecodeError, H.server(&tls12, "", &.{}, .{ .max_version = .tls12, .alpn = &.{"h2"} }, .{}));
}

test "F135 catalogue_empty_retry_cookie_decode_error (a retry request's empty cookie is decode_error)" {
    // RFC 8446 section 4.2.2: Cookie's cookie<1..2^16-1>; empty is out of its range, decode_error
    // (section 6.2).
    const empty = server13.of(H.retry_random, "\x00\x2b\x00\x02\x03\x04" ++ "\x00\x2c\x00\x02\x00\x00");
    try std.testing.expectError(error.DecodeError, H.server(&empty, "", &shares, .{}, .{}));
    const one = server13.of(H.retry_random, "\x00\x2b\x00\x02\x03\x04" ++ "\x00\x2c\x00\x03\x00\x01\x07");
    try std.testing.expect((try H.server(&one, "", &shares, .{}, .{})).tls13.retry);
}

test "F136 catalogue_server_hello_without_key_share_missing_extension (a TLS 1.3 ServerHello without the share its mode needs is missing_extension)" {
    // cloak's client offers only psk_dhe_ke (RFC 8446 section 4.2.9), so every TLS 1.3
    // ServerHello it takes carries key_share: one without it lacks an extension mandatory for the
    // negotiated parameters, missing_extension (section 6.2).
    const bare = server13.of(@splat(0x11), "\x00\x2b\x00\x02\x03\x04");
    try std.testing.expectError(error.MissingExtension, H.server(&bare, "", &shares, .{}, .{}));
    // A retry request that changes nothing stays illegal_parameter (RFC 8446 section 4.1.4).
    const retry = server13.of(H.retry_random, "\x00\x2b\x00\x02\x03\x04");
    try std.testing.expectError(error.InvalidHello, H.server(&retry, "", &shares, .{}, .{}));
}

test "C2 GREASE (RFC 8701): a reserved value leads each list, two reserved extensions frame the rest, and none is taken back" {
    const ClientHello = @import("ClientHello.zig");
    const Suite13 = @import("../crypto/Suite.zig").Suite13;
    const Group = @import("../crypto/Group.zig").Group;
    const grease = H.Grease.fromSeed(&.{ 0x10, 0x21, 0x32, 0x43, 0x54, 0x54 });
    // Each value one of RFC 8701's sixteen, the two extensions apart.
    for ([_]u16{ grease.suite, grease.group, grease.version, grease.scheme, grease.first, grease.last }) |value| try std.testing.expect(H.Grease.is(value));
    try std.testing.expect(grease.first != grease.last);
    try std.testing.expect(!H.Grease.is(0x0a0b) and !H.Grease.is(0x1a2a));
    var out: [4096]u8 = undefined;
    for ([_]bool{ true, false }) |share| {
        var values = grease;
        values.share = share;
        const ch = try H.client(&out, &@as([32]u8, @splat(2)), "", "", &shares, "", .{ .sni = "example.com", .grease = values }, .{});
        const parsed = try ClientHello.parse(ch, .stream);
        try std.testing.expectEqual(grease.suite, std.mem.readInt(u16, parsed.suites[0..2], .big));
        try std.testing.expectEqual(grease.group, std.mem.readInt(u16, parsed.groups[0..2], .big));
        try std.testing.expectEqual(grease.version, std.mem.readInt(u16, parsed.versions[0..2], .big));
        try std.testing.expectEqual(grease.scheme, std.mem.readInt(u16, parsed.schemes[0..2], .big));
        // A one-byte share for the reserved group, except in a hello answering a retry request.
        const first_share = std.mem.readInt(u16, parsed.shares[0..2], .big);
        try std.testing.expectEqual(if (share) grease.group else @backingInt(Group.x25519), first_share);
        var r: Reader = .{ .bytes = ch[4..] };
        _ = try r.take(34);
        _ = try r.vector(u8);
        _ = try r.vector(u16);
        _ = try r.vector(u8);
        var ext: Extensions = .{ .reader = try r.vector(u16) };
        var ids: [16]u16 = undefined;
        var count: usize = 0;
        while (try ext.next()) |item| {
            ids[count] = item.id;
            count += 1;
        }
        try std.testing.expectEqual(grease.first, ids[0]);
        try std.testing.expectEqual(grease.last, ids[count - 1]);
    }
    // A server that selects a reserved value is refused: the client never offered it.
    var server_hello: [512]u8 = undefined;
    const options: H.Options = .{ .grease = grease };
    const chosen = try H.buildServer(&server_hello, .stream, &@as([32]u8, @splat(3)), "", .aes_128_gcm_sha256, .x25519, &x, null, null);
    // The suite follows the type, length, legacy version, random and an empty session id.
    std.mem.writeInt(u16, chosen[39..41], grease.suite, .big);
    try std.testing.expect(if (H.server(chosen, "", &shares, options, .{})) |_| false else |_| true);
    const retry = try H.buildRetry(&server_hello, .stream, "", Suite13.aes_128_gcm_sha256, @fromBackingInt(grease.group), "", false);
    try std.testing.expect(if (H.server(retry, "", &shares, options, .{})) |_| false else |_| true);
}

/// The extensions of a written ClientHello, id and whole bytes each, in their order.
fn helloExtensions(ch: []const u8, datagram: bool, out: *[48][]const u8) ![]const []const u8 {
    var r: Reader = .{ .bytes = ch[4..] };
    _ = try r.take(34);
    _ = try r.vector(u8);
    if (datagram) _ = try r.vector(u8);
    _ = try r.vector(u16);
    _ = try r.vector(u8);
    const block = (try r.vector(u16)).bytes;
    var b: Reader = .{ .bytes = block };
    var count: usize = 0;
    while (b.pos != block.len) {
        const start = b.pos;
        _ = try b.int(u16);
        _ = try b.vector(u16);
        out[count] = block[start..b.pos];
        count += 1;
    }
    return out[0..count];
}

fn extensionId(ext: []const u8) u16 {
    return std.mem.readInt(u16, ext[0..2], .big);
}

fn lessBytes(_: void, a: []const u8, b: []const u8) bool {
    return std.mem.order(u8, a, b) == .lt;
}

test "C2 permute_extensions: the same extensions in a random order per key, the same order for one key, the ends kept" {
    const grease = H.Grease.fromSeed(&.{ 0x10, 0x21, 0x32, 0x43, 0x54, 0x65 });
    const offer = [_]H.PskOffer{.{ .identity = "ticket", .age = 7, .binder_len = 32 }};
    const base: H.Options = .{ .sni = "example.com", .alpn = &.{ "h2", "http/1.1" }, .grease = grease, .accept_delegated = true, .request_ocsp = true, .post_handshake_auth = true };
    const resumption: H.Resume = .{ .modes = true, .offers = &offer };
    var plain_buf: [4096]u8 = undefined;
    const plain = try H.client(&plain_buf, &@as([32]u8, @splat(2)), "", "", &shares, "", base, resumption);
    var plain_ext: [48][]const u8 = undefined;
    const want = try helloExtensions(plain, false, &plain_ext);
    var sorted_want: [48][]const u8 = undefined;
    @memcpy(sorted_want[0..want.len], want);
    std.sort.insertion([]const u8, sorted_want[0..want.len], {}, lessBytes);
    var moved = false;
    for (0..16) |seed| {
        var options = base;
        options.permutation = .{ .key = @splat(@intCast(seed)) };
        var buf: [4096]u8 = undefined;
        const ch = try H.client(&buf, &@as([32]u8, @splat(2)), "", "", &shares, "", options, resumption);
        try std.testing.expectEqual(plain.len, ch.len);
        var ext: [48][]const u8 = undefined;
        const got = try helloExtensions(ch, false, &ext);
        try std.testing.expectEqual(want.len, got.len);
        // GREASE's first leads; GREASE's last, then pre_shared_key, end it.
        try std.testing.expectEqual(grease.first, extensionId(got[0]));
        try std.testing.expectEqual(grease.last, extensionId(got[got.len - 2]));
        try std.testing.expectEqual(@as(u16, 41), extensionId(got[got.len - 1]));
        for (got, want) |a, b| moved = moved or !std.mem.eql(u8, a, b);
        var sorted: [48][]const u8 = undefined;
        @memcpy(sorted[0..got.len], got);
        std.sort.insertion([]const u8, sorted[0..got.len], {}, lessBytes);
        for (sorted[0..got.len], sorted_want[0..want.len]) |a, b| try std.testing.expectEqualSlices(u8, b, a);
        // One key, one order: a retry's hello keeps it.
        var again: [4096]u8 = undefined;
        try std.testing.expectEqualSlices(u8, ch, try H.client(&again, &@as([32]u8, @splat(2)), "", "", &shares, "", options, resumption));
        // A datagram hello answering a retry request still leads with its cookie.
        var dtls = options;
        dtls.transport = .datagram;
        dtls.post_handshake_auth = false;
        var dbuf: [4096]u8 = undefined;
        const dch = try H.client(&dbuf, &@as([32]u8, @splat(2)), "", "", &shares, "cookie", dtls, .{ .modes = true });
        var dext: [48][]const u8 = undefined;
        const dgot = try helloExtensions(dch, true, &dext);
        try std.testing.expectEqual(@as(u16, 44), extensionId(dgot[0]));
        try std.testing.expectEqual(grease.first, extensionId(dgot[1]));
    }
    try std.testing.expect(moved);
}

test "C6 permute_extensions under ECH: the server rebuilds the permuted inner hello from the encoded one and the outer" {
    const Ech = @import("Ech.zig");
    const gpa = std.testing.allocator;
    const grease = H.Grease.fromSeed(&.{ 0x10, 0x21, 0x32, 0x43, 0x54, 0x65 });
    const names = [_][]const u8{"\x30\x0e\x31\x0c\x30\x0a\x06\x03\x55\x04\x03\x0c\x03ca1"};
    const offer = [_]H.PskOffer{.{ .identity = "ticket", .age = 7, .binder_len = 32 }};
    const random: [32]u8 = @splat(2);
    const Transport = @import("../crypto/Suite.zig").Transport;
    // Over datagrams the cookie leads every form and is never compressed; there is no session id.
    for ([_]Transport{ .stream, .datagram }) |transport| for ([_][]const u8{ "", "cookie" }) |cookie| for (0..16) |seed| {
        const options: H.Options = .{ .transport = transport, .min_version = .tls13, .sni = "example.com", .alpn = &.{"h2"}, .grease = grease, .certificate_authorities = &names, .permutation = .{ .key = @splat(@intCast(seed)) } };
        const resumption: H.Resume = .{ .modes = true, .offers = &offer };
        const session = if (transport == .datagram) "" else "session";
        var inner_buf: [4096]u8 = undefined;
        const inner = try H.clientForm(&inner_buf, &random, session, "", &shares, cookie, options, resumption, .inner);
        var encoded_buf: [4096]u8 = undefined;
        const encoded = try H.clientForm(&encoded_buf, &random, session, "", &shares, cookie, options, resumption, .encoded);
        var outer_buf: [4096]u8 = undefined;
        const outer = try H.clientForm(&outer_buf, &@as([32]u8, @splat(9)), session, "", &shares, cookie, options, .{ .modes = true }, .{ .outer = .{ .name = "public.example.org", .ext = "payload", .psk = &.{} } });
        const rebuilt = try Ech.reconstruct(gpa, outer, encoded[4..], transport);
        defer gpa.free(rebuilt);
        try std.testing.expectEqualSlices(u8, inner, rebuilt);
    };
}
