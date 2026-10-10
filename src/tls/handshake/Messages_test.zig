const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");
const M = @import("Messages.zig");

fn message(kind: u8, body: []const u8, out: []u8) []u8 {
    out[0] = kind;
    std.mem.writeInt(u24, out[1..4], @intCast(body.len), .big);
    @memcpy(out[4..][0..body.len], body);
    return out[0 .. 4 + body.len];
}

test "C2 messages certificate list parses entries and bounds count bytes and extensions" {
    var chain: [M.max_certificates][]const u8 = undefined;
    var buf: [256]u8 = undefined;
    const body = [_]u8{0} ++ [_]u8{ 0, 0, 14 } ++ [_]u8{ 0, 0, 3, 'a', 'b', 'c', 0, 0 } ++ [_]u8{ 0, 0, 1, 'z', 0, 0 };
    const wire = message(11, &body, &buf);
    const parsed = try M.certificate(wire, 16, 1024, &chain);
    try std.testing.expectEqual(@as(usize, 2), parsed.count);
    try std.testing.expectEqual(@as(usize, 4), parsed.total_bytes);
    try std.testing.expectEqualSlices(u8, "abc", chain[0]);
    try std.testing.expectEqualSlices(u8, "z", chain[1]);
    try std.testing.expectError(error.CertificateLimit, M.certificate(wire, 1, 1024, &chain));
    try std.testing.expectError(error.CertificateLimit, M.certificate(wire, 16, 3, &chain));
    // An entry extension is unsolicited, an empty DER is invalid, the list must fill its vector.
    const with_extension = [_]u8{ 0, 0, 0, 8, 0, 0, 1, 'a', 0, 2, 0, 0 };
    try std.testing.expectError(error.UnsolicitedExtension, M.certificate(message(11, &with_extension, &buf), 16, 1024, &chain));
    const empty_der = [_]u8{0} ++ [_]u8{ 0, 0, 5 } ++ [_]u8{ 0, 0, 0, 0, 0 };
    try std.testing.expectError(error.InvalidMessage, M.certificate(message(11, &empty_der, &buf), 16, 1024, &chain));
    try std.testing.expectError(error.InvalidLength, M.certificate(message(11, &.{ 0, 0, 0, 5, 1 }, &buf), 16, 1024, &chain));
    try std.testing.expectError(error.InvalidMessage, M.certificate(message(15, &body, &buf), 16, 1024, &chain));
    // Every truncation of a valid message fails cleanly.
    for (0..wire.len) |len| try std.testing.expect(std.meta.isError(M.certificate(wire[0..len], 16, 1024, &chain)));
    // An empty list parses to zero entries; the handshake turns that into a decode error.
    const none = try M.certificate(message(11, &.{ 0, 0, 0, 0 }, &buf), 16, 1024, &chain);
    try std.testing.expectEqual(@as(usize, 0), none.count);
}

test "C2 messages certificate request needs signature_algorithms and an even scheme list" {
    var buf: [64]u8 = undefined;
    const ok = message(13, &.{ 0, 0, 8, 0, 13, 0, 4, 0, 2, 4, 3 }, &buf);
    const parsed = try M.certificateRequest(ok);
    try std.testing.expect(parsed.accepts(0x0403));
    try std.testing.expect(!parsed.accepts(0x0807));
    try std.testing.expectEqual(@as(usize, 0), parsed.context.len);
    var other: [64]u8 = undefined;
    try std.testing.expectError(error.MissingExtension, M.certificateRequest(message(13, &.{ 0, 0, 4, 0, 47, 0, 0 }, &other)));
    try std.testing.expectError(error.InvalidMessage, M.certificateRequest(message(13, &.{ 0, 0, 7, 0, 13, 0, 3, 0, 1, 4 }, &other)));
    try std.testing.expectError(error.InvalidMessage, M.certificateRequest(message(13, &.{ 0, 0, 6, 0, 13, 0, 2, 0, 0 }, &other)));
    try std.testing.expectError(error.DuplicateExtension, M.certificateRequest(message(13, &.{ 0, 0, 16, 0, 13, 0, 4, 0, 2, 4, 3, 0, 13, 0, 4, 0, 2, 8, 7 }, &other)));
    // A nonempty context parses (post-handshake requests use it); the handshake rejects it.
    const with_context = try M.certificateRequest(message(13, &.{ 2, 'h', 'i', 0, 8, 0, 13, 0, 4, 0, 2, 4, 3 }, &other));
    try std.testing.expectEqualSlices(u8, "hi", with_context.context);
}

test "C2 messages certificate verify and finished are exact" {
    var buf: [64]u8 = undefined;
    const cv = try M.certificateVerify(message(15, &.{ 8, 7, 0, 3, 'a', 'b', 'c' }, &buf));
    try std.testing.expectEqual(@as(u16, 0x0807), cv.scheme);
    try std.testing.expectEqualSlices(u8, "abc", cv.signature);
    try std.testing.expectError(error.InvalidLength, M.certificateVerify(message(15, &.{ 8, 7, 0, 3, 'a', 'b', 'c', 0 }, &buf)));
    try std.testing.expectError(error.InvalidLength, M.certificateVerify(message(15, &.{ 8, 7, 0, 4, 'a', 'b', 'c' }, &buf)));
    try std.testing.expectEqualSlices(u8, "0123456789abcdef0123456789abcdef", try M.finished(message(20, "0123456789abcdef0123456789abcdef", &buf), 32));
    try std.testing.expectError(error.InvalidMessage, M.finished(message(20, "short", &buf), 32));
    try std.testing.expectError(error.InvalidMessage, M.finished(message(15, "0123456789abcdef0123456789abcdef", &buf), 32));
}

test "C2 messages ticket lifetime nonce and early data bounds" {
    var buf: [64]u8 = undefined;
    const body = [_]u8{ 0, 0, 0x1c, 0x20, 1, 2, 3, 4, 1, 9, 0, 2, 'o', 'k', 0, 0 };
    const ticket = try M.newSessionTicket(message(4, &body, &buf));
    try std.testing.expectEqual(@as(u32, 7200), ticket.lifetime);
    try std.testing.expectEqual(@as(u32, 0x01020304), ticket.age_add);
    try std.testing.expectEqualSlices(u8, "ok", ticket.ticket);
    var too_long = body;
    std.mem.writeInt(u32, too_long[0..4], M.max_ticket_lifetime + 1, .big);
    try std.testing.expectError(error.IllegalParameter, M.newSessionTicket(message(4, &too_long, &buf)));
    try std.testing.expectError(error.IllegalParameter, M.newSessionTicket(message(4, &.{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, &buf)));
    const early_bad = [_]u8{ 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'k', 0, 6, 0, 42, 0, 2, 0, 1 };
    try std.testing.expectError(error.InvalidMessage, M.newSessionTicket(message(4, &early_bad, &buf)));
    for (0..body.len + 4) |len| {
        const wire = message(4, &body, &buf);
        try std.testing.expect(len >= wire.len or std.meta.isError(M.newSessionTicket(wire[0..len])));
    }
}

test "C2 messages key update accepts exactly zero and one" {
    var buf: [8]u8 = undefined;
    try std.testing.expectEqual(false, try M.keyUpdate(message(24, &.{0}, &buf)));
    try std.testing.expectEqual(true, try M.keyUpdate(message(24, &.{1}, &buf)));
    try std.testing.expectError(error.IllegalParameter, M.keyUpdate(message(24, &.{2}, &buf)));
    try std.testing.expectError(error.InvalidMessage, M.keyUpdate(message(24, &.{ 0, 0 }, &buf)));
    try std.testing.expectError(error.InvalidMessage, M.keyUpdate(message(20, &.{0}, &buf)));
}

test "C2 messages builders produce the wire form the parsers read" {
    var out: [128]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &.{ 24, 0, 0, 1, 1 }, try M.buildKeyUpdate(&out, true));
    try std.testing.expectEqualSlices(u8, &.{ 20, 0, 0, 4, 1, 2, 3, 4 }, try M.buildFinished(&out, &.{ 1, 2, 3, 4 }));
    try std.testing.expectEqualSlices(u8, &.{ 15, 0, 0, 7, 8, 7, 0, 3, 'a', 'b', 'c' }, try M.buildCertificateVerify(&out, 0x0807, "abc"));
    try std.testing.expectEqualSlices(u8, &.{ 11, 0, 0, 4, 0, 0, 0, 0 }, try M.buildCertificate(&out, "", &.{}));
    const chain = [_][]const u8{ "one", "two" };
    const built = try M.buildCertificate(&out, "", &chain);
    var parsed: [M.max_certificates][]const u8 = undefined;
    const result = try M.certificate(built, 16, 1024, &parsed);
    try std.testing.expectEqual(@as(usize, 2), result.count);
    try std.testing.expectEqualSlices(u8, "two", parsed[1]);
    try std.testing.expectError(error.BufferTooSmall, M.buildCertificate(out[0..10], "", &chain));
    try std.testing.expectError(error.BufferTooSmall, M.buildFinished(out[0..5], &.{ 1, 2, 3, 4 }));
}

test "C2 messages signed content follows RFC 8446 section 4.4.3" {
    var out: [M.max_signed]u8 = undefined;
    const digest: [32]u8 = @splat(0xab);
    const server = M.signedContent(&out, true, &digest);
    try std.testing.expect(std.mem.allEqual(u8, server[0..64], 0x20));
    try std.testing.expectEqualSlices(u8, "TLS 1.3, server CertificateVerify", server[64..97]);
    try std.testing.expectEqual(@as(u8, 0), server[97]);
    try std.testing.expectEqualSlices(u8, &digest, server[98..]);
    var other: [M.max_signed]u8 = undefined;
    const client = M.signedContent(&other, false, &(@as([48]u8, @splat(1))));
    try std.testing.expectEqualSlices(u8, "TLS 1.3, client CertificateVerify", client[64..97]);
    try std.testing.expectEqual(@as(usize, 64 + 33 + 1 + 48), client.len);
}

test "C2 fuzz message parsers reject or bound every input" {
    try shakedown.check(std.testing.allocator, {}, fuzz, .{});
}

const examples = [_][]const u8{ "\x0b\x00\x00\x04\x00\x00\x00\x00", "\x0d\x00\x00\x0b\x00\x00\x08\x00\x0d\x00\x04\x00\x02\x04\x03", "\x04\x00\x00\x10\x00\x00\x1c\x20\x01\x02\x03\x04\x01\x09\x00\x02ok\x00\x00", "\x18\x00\x00\x01\x01" };

test "C2 message parsers reject or bound the odd examples" {
    for (examples) |input| try parseAll(input);
}

fn fuzz(_: void, case: *shakedown.Case) !void {
    var bytes: [2048]u8 = undefined;
    try parseAll(inputs.draw(case, &bytes, &examples, 48));
}

fn parseAll(input: []const u8) !void {
    var chain: [M.max_certificates][]const u8 = undefined;
    if (M.certificate(input, 16, 4096, &chain)) |parsed| {
        try std.testing.expect(parsed.count <= 16 and parsed.total_bytes <= 4096);
        for (chain[0..parsed.count]) |der| try std.testing.expect(der.len != 0);
    } else |_| {}
    if (M.certificateRequest(input)) |request| {
        try std.testing.expect(request.schemes.len >= 2 and request.schemes.len % 2 == 0);
    } else |_| {}
    if (M.certificateVerify(input)) |cv| try std.testing.expect(cv.signature.len <= input.len) else |_| {}
    if (M.finished(input, 32)) |verify_data| try std.testing.expectEqual(@as(usize, 32), verify_data.len) else |_| {}
    if (M.newSessionTicket(input)) |ticket| {
        try std.testing.expect(ticket.ticket.len != 0 and ticket.lifetime <= M.max_ticket_lifetime);
    } else |_| {}
    if (M.keyUpdate(input)) |request| try std.testing.expect(request or !request) else |_| {}
}
