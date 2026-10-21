const std = @import("std");
const Ech = @import("Ech.zig");
const Hpke = @import("../crypto/Hpke.zig");

fn sampleConfig(buf: []u8, id: u8, name: []const u8) ![]u8 {
    var pair = Hpke.deriveKeyPair(&(@as([32]u8, @splat(id))));
    defer pair.deinit();
    return Ech.writeConfig(buf, .{ .id = id, .public_key = pair.public, .public_name = name, .max_name_length = 32 });
}

test "C6 ECH configs: built, listed, parsed back and chosen by what a client can use" {
    var a: [128]u8 = undefined;
    var b: [128]u8 = undefined;
    const first = try sampleConfig(&a, 1, "public.example");
    const second = try sampleConfig(&b, 2, "other.example");
    var list_buf: [300]u8 = undefined;
    const list = try Ech.writeList(&list_buf, &.{ first, second });
    try Ech.checkList(list);
    const chosen = (try Ech.choose(list)).?;
    try std.testing.expectEqual(1, chosen.id);
    try std.testing.expectEqualStrings("public.example", chosen.public_name);
    try std.testing.expectEqual(32, chosen.max_name_length);
    try std.testing.expectEqual(Hpke.Aead.aes_128_gcm, chosen.suite().?.aead);
    try std.testing.expectEqualSlices(u8, first, chosen.raw);

    // A config of an unknown version is skipped by its length, and the next one is used.
    var unknown_buf: [300]u8 = undefined;
    @memcpy(unknown_buf[0..2], &[_]u8{ 0, 0 });
    @memcpy(unknown_buf[2..][0..6], &[_]u8{ 0xfe, 0x0c, 0, 2, 0xaa, 0xbb });
    @memcpy(unknown_buf[8..][0..second.len], second);
    std.mem.writeInt(u16, unknown_buf[0..2], @intCast(6 + second.len), .big);
    try std.testing.expectEqual(2, (try Ech.choose(unknown_buf[0 .. 8 + second.len])).?.id);

    // A mandatory extension the client does not know makes a config unusable.
    var mandatory: [160]u8 = undefined;
    @memcpy(mandatory[0..first.len], first);
    const ext_at = first.len - 2;
    std.mem.writeInt(u16, mandatory[ext_at..][0..2], 4, .big);
    std.mem.writeInt(u16, mandatory[ext_at + 2 ..][0..2], 0xfa0a, .big);
    std.mem.writeInt(u16, mandatory[ext_at + 4 ..][0..2], 0, .big);
    std.mem.writeInt(u16, mandatory[2..4], @intCast(first.len + 4 - 4), .big);
    const parsed = (try Ech.parseConfig(mandatory[0 .. first.len + 4])).config.?;
    try std.testing.expect(!parsed.usable());
    std.mem.writeInt(u16, mandatory[ext_at + 2 ..][0..2], 0x7a0a, .big);
    try std.testing.expect((try Ech.parseConfig(mandatory[0 .. first.len + 4])).config.?.usable());

    // Truncation and trailing bytes are syntax errors.
    try std.testing.expectError(error.InvalidLength, Ech.checkList(list[0 .. list.len - 1]));
    try std.testing.expectError(error.InvalidLength, Ech.checkList(&[_]u8{ 0, 1 }));
}

test "C6 ECH public names: DNS names only, never an IPv4 literal" {
    for ([_][]const u8{ "public.example", "a.b-c.example", "xn--bcher-kva.example", "localhost" }) |name| try std.testing.expect(Ech.publicName(name));
    for ([_][]const u8{ "", ".example", "example.", "a..b", "-a.example", "a-.example", "a_b.example", "10.0.0.1", "example.123", "example.0x1f", "example.0X" }) |name| try std.testing.expect(!Ech.publicName(name));
}

test "C6 ECH padding rounds the encoded inner hello to 32 bytes past the name bound" {
    try std.testing.expectEqual(32, Ech.paddedLength(1, 0, 0));
    // A name of 10 bytes under a bound of 32: 22 bytes of padding, then the round-up.
    try std.testing.expectEqual(224, Ech.paddedLength(200, 10, 32));
    // No name: the bound plus nine, the size of a server_name extension with such a name.
    try std.testing.expectEqual(256, Ech.paddedLength(200, 0, 32));
    // A name longer than the bound adds nothing.
    try std.testing.expectEqual(224, Ech.paddedLength(200, 40, 32));
    try std.testing.expectEqual(0, Ech.paddedLength(256, 1, 0) % 32);
}

test "C6 ECH offers: inner and outer forms parse; anything else is refused" {
    try std.testing.expectEqual(Ech.Offer.inner, try Ech.parseOffer(&.{1}));
    try std.testing.expectError(error.DecodeError, Ech.parseOffer(&.{ 1, 0 }));
    try std.testing.expectError(error.IllegalParameter, Ech.parseOffer(&.{2}));
    try std.testing.expectError(error.DecodeError, Ech.parseOffer(&.{}));
    var buf: [64]u8 = undefined;
    const body = try Ech.writeOuter(&buf, .{ .kdf = .hkdf_sha256, .aead = .chacha20_poly1305 }, 7, "enc", 20);
    const offer = (try Ech.parseOffer(body)).outer;
    try std.testing.expectEqual(7, offer.config_id);
    try std.testing.expectEqual(Hpke.Aead.chacha20_poly1305, offer.suite.aead);
    try std.testing.expectEqualStrings("enc", offer.enc);
    try std.testing.expectEqual(20, offer.payload.len);
    try std.testing.expectError(error.DecodeError, Ech.parseOffer(body[0 .. body.len - 1]));
    // An empty payload is no payload.
    const empty = try Ech.writeOuter(&buf, .{ .kdf = .hkdf_sha256, .aead = .aes_128_gcm }, 7, "", 0);
    try std.testing.expectError(error.DecodeError, Ech.parseOffer(empty));
}

/// A minimal ClientHello with the given extensions, in order.
fn hello(buf: []u8, session: []const u8, extensions: []const struct { u16, []const u8 }) []u8 {
    return helloOf(buf, session, null, extensions);
}

/// A minimal ClientHello of a stream, or of a datagram with `legacy_cookie` in its cookie field.
fn helloOf(buf: []u8, session: []const u8, legacy_cookie: ?[]const u8, extensions: []const struct { u16, []const u8 }) []u8 {
    var at: usize = 4;
    buf[at] = 3;
    buf[at + 1] = 3;
    at += 2;
    @memset(buf[at..][0..32], 0x11);
    at += 32;
    buf[at] = @intCast(session.len);
    @memcpy(buf[at + 1 ..][0..session.len], session);
    at += 1 + session.len;
    if (legacy_cookie) |field| {
        buf[at] = @intCast(field.len);
        @memcpy(buf[at + 1 ..][0..field.len], field);
        at += 1 + field.len;
    }
    @memcpy(buf[at..][0..4], &[_]u8{ 0, 2, 0x13, 0x01 });
    at += 4;
    @memcpy(buf[at..][0..2], &[_]u8{ 1, 0 });
    at += 2;
    const ext_at = at;
    at += 2;
    for (extensions) |e| {
        std.mem.writeInt(u16, buf[at..][0..2], e[0], .big);
        std.mem.writeInt(u16, buf[at + 2 ..][0..2], @intCast(e[1].len), .big);
        @memcpy(buf[at + 4 ..][0..e[1].len], e[1]);
        at += 4 + e[1].len;
    }
    std.mem.writeInt(u16, buf[ext_at..][0..2], @intCast(at - ext_at - 2), .big);
    buf[0] = 1;
    std.mem.writeInt(u24, buf[1..4], @intCast(at - 4), .big);
    return buf[0..at];
}

test "C6 ECH reconstruction copies named outer extensions once, in order, and refuses the rest" {
    const gpa = std.testing.allocator;
    var outer_buf: [256]u8 = undefined;
    const outer = hello(&outer_buf, "sess", &.{ .{ 0, "public" }, .{ 10, "groups" }, .{ 13, "schemes" }, .{ 51, "share" }, .{ 0xfe0d, "payload" } });
    var encoded_buf: [256]u8 = undefined;
    const encoded_msg = hello(&encoded_buf, "", &.{ .{ 0, "secret" }, .{ 0xfd00, &.{ 4, 0, 10, 0, 51 } }, .{ 0xfe0d, &.{1} } });
    // Padding of zeros follows the hello.
    @memset(encoded_buf[encoded_msg.len..][0..7], 0);
    const inner = try Ech.reconstruct(gpa, outer, encoded_buf[4 .. encoded_msg.len + 7], .stream);
    defer gpa.free(inner);
    var want_buf: [256]u8 = undefined;
    const want = hello(&want_buf, "sess", &.{ .{ 0, "secret" }, .{ 10, "groups" }, .{ 51, "share" }, .{ 0xfe0d, &.{1} } });
    try std.testing.expectEqualSlices(u8, want, inner);

    const refusals = [_][]const u8{
        // Out of order, repeated, missing, encrypted_client_hello itself, an odd list.
        &.{ 4, 0, 51, 0, 10 },
        &.{ 4, 0, 10, 0, 10 },
        &.{ 2, 0, 16 },
        &.{ 2, 0xfe, 0x0d },
        &.{ 1, 0 },
        &.{0},
    };
    for (refusals) |list| {
        const bad = hello(&encoded_buf, "", &.{ .{ 0xfd00, list }, .{ 0xfe0d, &.{1} } });
        try std.testing.expectError(error.IllegalParameter, Ech.reconstruct(gpa, outer, bad[4..], .stream));
    }
    // Nonzero padding, and a session id inside the encoded hello.
    const padded = hello(&encoded_buf, "", &.{.{ 0xfe0d, &.{1} }});
    encoded_buf[padded.len] = 1;
    try std.testing.expectError(error.IllegalParameter, Ech.reconstruct(gpa, outer, encoded_buf[4 .. padded.len + 1], .stream));
    const with_session = hello(&encoded_buf, "x", &.{.{ 0xfe0d, &.{1} }});
    try std.testing.expectError(error.IllegalParameter, Ech.reconstruct(gpa, outer, with_session[4..], .stream));
}

test "C8 ECH over DTLS: a datagram hello's cookie field is read past, and the inner hello keeps its own" {
    const gpa = std.testing.allocator;
    var outer_buf: [256]u8 = undefined;
    const outer = helloOf(&outer_buf, "", "", &.{ .{ 0, "public" }, .{ 10, "groups" }, .{ 0xfe0d, "payload" } });
    const span = Ech.extensionSpan(outer, .datagram).?;
    try std.testing.expectEqualSlices(u8, "payload", outer[span.start..][0..span.len]);
    // Read as a stream hello, the cookie field shifts every field after it.
    try std.testing.expect(Ech.extensionSpan(outer, .stream) == null);
    var encoded_buf: [256]u8 = undefined;
    const encoded = helloOf(&encoded_buf, "", "", &.{ .{ 0, "secret" }, .{ 0xfd00, &.{ 2, 0, 10 } }, .{ 0xfe0d, &.{1} } });
    const inner = try Ech.reconstruct(gpa, outer, encoded[4..], .datagram);
    defer gpa.free(inner);
    var want_buf: [256]u8 = undefined;
    const want = helloOf(&want_buf, "", "", &.{ .{ 0, "secret" }, .{ 10, "groups" }, .{ 0xfe0d, &.{1} } });
    try std.testing.expectEqualSlices(u8, want, inner);
    // The inner hello's cookie field is its own, whatever the outer one holds: the server refuses
    // a non-empty one as it refuses it in any DTLS 1.3 hello.
    const with_field = helloOf(&encoded_buf, "", "c", &.{.{ 0xfe0d, &.{1} }});
    const kept = try Ech.reconstruct(gpa, outer, with_field[4..], .datagram);
    defer gpa.free(kept);
    try std.testing.expectEqualSlices(u8, &.{ 1, 'c' }, kept[4 + 2 + 32 + 1 ..][0..2]);
}

test "C6 ECH server keys must match their configs" {
    var pair = Hpke.deriveKeyPair(&(@as([32]u8, @splat(1))));
    defer pair.deinit();
    var buf: [128]u8 = undefined;
    const config = try sampleConfig(&buf, 1, "public.example");
    try Ech.checkKeys(&.{.{ .config = config, .secret = pair.secret.expose() }});
    var other = Hpke.deriveKeyPair(&(@as([32]u8, @splat(2))));
    defer other.deinit();
    try std.testing.expectError(error.InvalidConfig, Ech.checkKeys(&.{.{ .config = config, .secret = other.secret.expose() }}));
    try std.testing.expectError(error.InvalidConfig, Ech.checkKeys(&.{.{ .config = config[0 .. config.len - 1], .secret = pair.secret.expose() }}));
    try std.testing.expectError(error.InvalidConfig, Ech.writeConfig(&buf, .{ .id = 1, .public_key = pair.public, .public_name = "1.2.3.4" }));
}

const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");

test "C6 fuzz ECH config lists, offers and inner hellos never misparse" {
    try shakedown.check(gpa_fuzz, {}, fuzzEchInput, .{});
}

const gpa_fuzz = std.testing.allocator;

fn fuzzEchInput(_: void, case: *shakedown.Case) !void {
    var config_buf: [128]u8 = undefined;
    const config = try sampleConfig(&config_buf, 1, "public.example");
    var list_buf: [140]u8 = undefined;
    const list = try Ech.writeList(&list_buf, &.{config});
    var offer_buf: [64]u8 = undefined;
    const offer = try Ech.writeOuter(&offer_buf, .{ .kdf = .hkdf_sha256, .aead = .aes_128_gcm }, 3, "enc", 20);
    var outer_buf: [256]u8 = undefined;
    const outer = hello(&outer_buf, "sess", &.{ .{ 10, "groups" }, .{ 51, "share" } });
    var encoded_buf: [256]u8 = undefined;
    const encoded = hello(&encoded_buf, "", &.{ .{ 0xfd00, &.{ 4, 0, 10, 0, 51 } }, .{ 0xfe0d, &.{1} } });
    var bytes: [512]u8 = undefined;
    const input = inputs.draw(case, &bytes, &.{ list, config, offer, encoded[4..] }, 48);
    if (Ech.parseConfig(input)) |parsed| {
        try std.testing.expect(parsed.len <= input.len);
        if (parsed.config) |c| {
            try std.testing.expect(c.raw.len == parsed.len and c.suites.len % 4 == 0 and c.public_name.len != 0);
            _ = c.usable();
            _ = c.suite();
        }
    } else |_| {}
    if (Ech.choose(input)) |chosen| {
        if (chosen) |c| try std.testing.expect(c.usable());
    } else |_| {}
    if (Ech.parseOffer(input)) |parsed| switch (parsed) {
        .inner => try std.testing.expectEqual(1, input.len),
        .outer => |o| try std.testing.expect(o.payload.len != 0 and o.enc.len + o.payload.len + 10 == input.len),
    } else |_| {}
    if (Ech.reconstruct(gpa_fuzz, outer, input, .stream)) |inner| {
        defer gpa_fuzz.free(inner);
        // Never larger than what both hellos hold.
        try std.testing.expect(inner.len <= outer.len + input.len + 4);
        try std.testing.expectEqual(inner.len - 4, std.mem.readInt(u24, inner[1..4], .big));
    } else |_| {}
}

test "C8 ECH over DTLS: an inner hello offering DTLS 1.2 (or 1.0) is no inner hello" {
    const Hello = @import("Hello.zig");
    const ClientHello = @import("ClientHello.zig");
    const Server = @import("Server.zig");
    const share: [32]u8 = @splat(1);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &share }};
    const random: [32]u8 = @splat(2);
    for ([_]@import("../crypto/Suite.zig").Version{ .tls12, .tls13 }) |min| {
        var buf: [1024]u8 = undefined;
        const plain = try Hello.client(&buf, &random, "", "", &shares, "", .{ .transport = .datagram, .min_version = min }, .{});
        // The inner marker appended as the last extension: the block's and the message's
        // lengths grow by its five bytes.
        @memcpy(buf[plain.len..][0..5], &[_]u8{ 0xfe, 0x0d, 0, 1, 1 });
        const message = buf[0 .. plain.len + 5];
        std.mem.writeInt(u24, message[1..4], @intCast(message.len - 4), .big);
        const block = 4 + 2 + 32 + 1 + 1 + 2 + std.mem.readInt(u16, message[4 + 2 + 32 + 2 ..][0..2], .big) + 2;
        std.mem.writeInt(u16, message[block..][0..2], std.mem.readInt(u16, message[block..][0..2], .big) + 5, .big);
        const parsed = try ClientHello.parse(message, .datagram);
        if (min == .tls13) try Server.checkInner(&parsed) else try std.testing.expectError(error.IllegalParameter, Server.checkInner(&parsed));
    }
}
