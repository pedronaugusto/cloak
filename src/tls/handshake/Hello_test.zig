const std = @import("std");
const shakedown = @import("shakedown");
const H = @import("Hello.zig");
const Reader = @import("../wire/Reader.zig");
const Extensions = @import("../wire/Extensions.zig");
const x: [32]u8 = @splat(1);
const shares = [_]H.Share{.{ .group = .x25519, .bytes = &x }};
const fixture = @embedFile("testdata/server-hello.bin");
test "C2 hello codec RFC server selection and bounded client offer" {
    const parsed = try H.server(fixture, "", &shares, .{});
    try std.testing.expectEqual(.aes_128_gcm_sha256, parsed.suite);
    try std.testing.expectEqual(.x25519, parsed.group);
    try std.testing.expectEqual(@as(usize, 32), parsed.share.len);
    var out: [4096]u8 = undefined;
    const ch = try H.client(&out, &@as([32]u8, @splat(2)), "", &shares, "", .{ .sni = "example.com", .alpn = &.{ "h2", "http/1.1" } });
    try std.testing.expectEqual(@as(usize, std.mem.readInt(u24, ch[1..4], .big)), ch.len - 4);
    var r: Reader = .{ .bytes = ch[4..] };
    try std.testing.expectEqual(@as(u16, 0x0303), try r.int(u16));
    _ = try r.take(32);
    _ = try r.vector(u8);
    _ = try r.vector(u16);
    _ = try r.vector(u8);
    var ext: Extensions = .{ .reader = try r.vector(u16) };
    try r.finish();
    var ids: [6]u16 = undefined;
    var count: usize = 0;
    while (try ext.next()) |item| {
        ids[count] = item.id;
        count += 1;
    }
    try std.testing.expectEqualSlices(u16, &.{ 0, 10, 13, 43, 16, 51 }, ids[0..count]);
    try std.testing.expectError(error.BufferTooSmall, H.client(out[0..10], &@as([32]u8, @splat(2)), "", &shares, "", .{}));
}
test "C2 catalogue_hrr_illegal_group_ch2_and_reallocation: hello selection" {
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
    const retry = try H.server(message, "", &shares, .{});
    try std.testing.expect(retry.retry and retry.group == .p256);
    valid[48..50].* = .{ 0, 29 };
    try std.testing.expectError(error.InvalidHello, H.server(message, "", &shares, .{}));
    valid[48..50].* = .{ 0, 24 };
    try std.testing.expectError(error.UnofferedSelection, H.server(message, "", &shares, .{ .groups = &.{ .x25519, .p256 } }));
    var duplicate: [62]u8 = undefined;
    @memcpy(duplicate[0..56], message);
    std.mem.writeInt(u24, duplicate[1..4], 58, .big);
    std.mem.writeInt(u16, duplicate[42..44], 18, .big);
    duplicate[56..].* = .{ 0, 43, 0, 2, 3, 4 };
    try std.testing.expectError(error.DuplicateExtension, H.server(&duplicate, "", &shares, .{}));
}
test "C2 catalogue_alpaca_protocol_and_port_binding: required ALPN" {
    const ee = "\x08\x00\x00\x0b\x00\x09\x00\x10\x00\x05\x00\x03\x02h2";
    const parsed = try H.encrypted(ee, .{ .alpn = &.{"h2"}, .require_alpn = true });
    try std.testing.expectEqualSlices(u8, "h2", parsed.alpn);
    try std.testing.expectError(error.UnofferedSelection, H.encrypted(ee, .{ .alpn = &.{"http/1.1"} }));
    try std.testing.expectError(error.NoApplicationProtocol, H.encrypted("\x08\x00\x00\x02\x00\x00", .{ .alpn = &.{"h2"}, .require_alpn = true }));
    try std.testing.expectError(error.InvalidOptions, H.validate(.{ .sni = "*.example.com" }));
    try std.testing.expectError(error.InvalidOptions, H.validate(.{ .alpn = &.{""} }));
    try std.testing.expectError(error.HybridRequired, H.server(fixture, "", &shares, .{ .require_hybrid = true }));
}
test "C2 hello parser truncation at every RFC byte" {
    for (0..fixture.len) |len| {
        try std.testing.expectError(error.InvalidLength, H.server(fixture[0..len], "", &shares, .{}));
    }
}
test "C2 fuzz TLS hello selections and extension placement" {
    try std.testing.fuzz({}, fuzz, .{ .corpus = shakedown.corpus.entries(&.{ fixture, "\x08\x00\x00\x02\x00\x00" }) });
}
fn fuzz(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    const input = bytes[0..smith.slice(&bytes)];
    if (H.server(input, "", &shares, .{})) |parsed| {
        try std.testing.expect(parsed.retry or parsed.share.len == parsed.group.?.serverShareLength());
    } else |_| {}
    if (H.encrypted(input, .{})) |parsed| {
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
    const retry = try H.server(&cookie_hrr, "", &shares, .{});
    try std.testing.expect(retry.retry and retry.group == null);
    try std.testing.expectEqualSlices(u8, "ok", retry.cookie);
    const ee = "\x08\x00\x00\x0f\x00\x0d\x00\x10\x00\x05\x00\x03\x02h2\x00\x39\x00\x00";
    const parsed = try H.encrypted(ee, .{ .alpn = &.{"h2"}, .quic = true });
    try std.testing.expectEqualSlices(u8, "h2", parsed.alpn);
    try std.testing.expectEqual(@as(usize, 0), parsed.parameters.len);
    // Acceptance belongs to the QUIC parameter service, not this opaque parser.
}
