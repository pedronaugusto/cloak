//! The handshake as a datagram carrier drives it (RFC 9147, RFC 6347): wire versions and the
//! cookie field, the "dtls13" label prefix, the DTLS 1.2 transcript form and the
//! HelloVerifyRequest edge, between two machines with no record layer.
const std = @import("std");
const at = @import("../../testing/StateAt.zig").at;
const Pair = @import("../../testing/MachinePair.zig");
const Hello = @import("Hello.zig");
const ClientHello = @import("ClientHello.zig");
const Labels = @import("../crypto/Labels.zig");
const State = @import("State.zig");
const Transcript = @import("Transcript.zig");
const Transcripts = @import("Transcripts.zig");
const suites = @import("../crypto/Suite.zig");

const gpa = std.testing.allocator;

fn exportersAgree(pair: *Pair) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try pair.client.machine.exportKeyingMaterial(&a, "EXPERIMENTAL dtls", "ctx");
    try pair.server.machine.exportKeyingMaterial(&b, "EXPERIMENTAL dtls", "ctx");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "C8 a DTLS 1.3 handshake of two machines completes" {
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(suites.Version.tls13, pair.client.machine.info().?.version);
    try std.testing.expect(pair.client.machine.info().?.peer_authenticated);
    try exportersAgree(pair);
    // The hello is a DTLS one: DTLS 1.2's legacy version, an empty cookie field, DTLS 1.3 offered.
    const hello = try ClientHello.parse(pair.client.sent.items[0], .datagram);
    try std.testing.expectEqual(@as(u16, 0xfefd), hello.legacy_version);
    try std.testing.expectEqual(@as(usize, 0), hello.legacy_cookie.len);
    try std.testing.expectEqual(@as(usize, 0), hello.session.len);
    try std.testing.expect(hello.offers13() and !hello.offers12());
    // The ServerHello names DTLS 1.2 in its legacy version and DTLS 1.3 in supported_versions.
    const server_hello = pair.server.sent.items[0];
    try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0xfd }, server_hello[4..6]);
    try std.testing.expect(std.mem.find(u8, server_hello, &.{ 0, 43, 0, 2, 0xfe, 0xfc }) != null);
}

test "C8 a DTLS 1.3 handshake derives under dtls13, not under TLS's labels" {
    // The same seed gives both pairs the same draws, so only the transport differs.
    const datagram = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer datagram.deinit();
    try datagram.run();
    const stream = try Pair.init(gpa, .{ .transport = .stream, .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer stream.deinit();
    try stream.run();
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try datagram.client.machine.exportKeyingMaterial(&a, "EXPERIMENTAL dtls", "");
    try stream.client.machine.exportKeyingMaterial(&b, "EXPERIMENTAL dtls", "");
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "C8 a DTLS 1.2 handshake of two machines completes over the DTLS transcript form" {
    const only12: []const suites.Suite = &.{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_chacha20_poly1305_sha256 };
    const pair = try Pair.init(gpa, .{ .client_suites = only12, .server_suites = only12 });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(suites.Version.tls12, pair.server.machine.info().?.version);
    try exportersAgree(pair);
    const hello = try ClientHello.parse(pair.client.sent.items[0], .datagram);
    try std.testing.expect(hello.offers12() and !hello.offers13());
    try std.testing.expectEqualSlices(u8, &.{ 0xfe, 0xfd }, pair.server.sent.items[0][4..6]);
}

test "C8 a client offering both DTLS versions settles on DTLS 1.2 with a DTLS 1.2 server" {
    const only12: []const suites.Suite = &.{.ecdhe_ecdsa_aes_256_gcm_sha384};
    const pair = try Pair.init(gpa, .{ .server_suites = only12 });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(suites.Version.tls12, pair.client.machine.info().?.version);
    try exportersAgree(pair);
}

fn helloVerify(cookie: []const u8) ![]u8 {
    var buffer: [300]u8 = undefined;
    return gpa.dupe(u8, try Hello.buildHelloVerify(&buffer, cookie));
}

/// Runs the client to its first hello, answers it with a HelloVerifyRequest, and returns the
/// client's second hello.
fn verifiedHello(pair: *Pair, cookie: []const u8) ![]const u8 {
    pair.hold_client = true;
    while (pair.client.sent.items.len == 0) _ = try pair.step();
    const request = try helloVerify(cookie);
    defer gpa.free(request);
    try pair.toClient(request);
    while (pair.client.sent.items.len == 1) if (!try pair.step()) return error.Stalled;
    return pair.client.sent.items[1];
}

test "C8 a HelloVerifyRequest is answered by the same hello with its cookie, and the handshake goes on" {
    const pair = try Pair.init(gpa, .{ .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer pair.deinit();
    const second = try verifiedHello(pair, "cookie-0123456789");
    const first = try ClientHello.parse(pair.client.sent.items[0], .datagram);
    const again = try ClientHello.parse(second, .datagram);
    try std.testing.expectEqualSlices(u8, "", first.legacy_cookie);
    try std.testing.expectEqualSlices(u8, "cookie-0123456789", again.legacy_cookie);
    try std.testing.expectEqualSlices(u8, first.random, again.random);
    try std.testing.expectEqualSlices(u8, first.extensions, again.extensions);
    // The server meets the hello the cookie came back in: message_seq 1.
    pair.server.machine.firstSequence(1);
    try pair.forwardLast();
    pair.hold_client = false;
    try pair.run();
    try exportersAgree(pair);
}

test "C8 a DTLS 1.3 answer after a HelloVerifyRequest is refused" {
    const pair = try Pair.init(gpa, .{ .server_suites = suites.Suite.tls13_only });
    defer pair.deinit();
    _ = try verifiedHello(pair, "c");
    pair.server.machine.firstSequence(1);
    try pair.forwardLast();
    pair.hold_client = false;
    // The DTLS 1.3 server refuses the cookie field first: its hello must carry none.
    try std.testing.expectError(error.IllegalParameter, pair.run());
}

test "C8 a ServerHello of DTLS 1.3 after a HelloVerifyRequest is refused by the client" {
    const pair = try Pair.init(gpa, .{});
    defer pair.deinit();
    _ = try verifiedHello(pair, "c");
    // A DTLS 1.3 ServerHello, as a server that never sent the request would answer.
    var buffer: [256]u8 = undefined;
    const share: [32]u8 = @splat(9);
    const answer = try Hello.buildServer(&buffer, .datagram, &@as([32]u8, @splat(1)), "", .aes_128_gcm_sha256, .x25519, &share, null, null);
    try pair.toClient(answer);
    try std.testing.expectError(error.IllegalParameter, pair.run());
}

test "C8 HelloVerifyRequest edges: datagram only, never after a retry request, at most three" {
    var stream: State.State = at(.client, .stream, .hello, .{});
    try std.testing.expectError(error.UnexpectedMessage, stream.advance(.hello_verify, .initial, .parsed, true));
    var quic: State.State = at(.client, .quic, .hello, .{});
    try std.testing.expectError(error.UnexpectedMessage, quic.advance(.hello_verify, .initial, .parsed, true));
    var retried: State.State = at(.client, .datagram, .hello, .{ .retried = true });
    try std.testing.expectError(error.UnexpectedMessage, retried.advance(.hello_verify, .initial, .parsed, true));
    var server: State.State = at(.server, .datagram, .hello, .{});
    try std.testing.expectError(error.UnexpectedMessage, server.advance(.hello_verify, .initial, .parsed, true));
    var datagram: State.State = State.State.init(.client, .datagram);
    for (0..3) |_| {
        try datagram.advance(.client_hello, .initial, .parsed, true);
        try datagram.advance(.hello_verify, .initial, .parsed, true);
    }
    try datagram.advance(.client_hello, .initial, .parsed, true);
    try std.testing.expectError(error.UnexpectedMessage, datagram.advance(.hello_verify, .initial, .parsed, true));
    // And a retry request may not follow one.
    var verified: State.State = State.State.init(.client, .datagram);
    try verified.advance(.client_hello, .initial, .parsed, true);
    try verified.advance(.hello_verify, .initial, .parsed, true);
    try verified.advance(.client_hello, .initial, .parsed, true);
    try std.testing.expectError(error.UnexpectedMessage, verified.advance(.hello_retry, .initial, .parsed, true));
}

test "C8 the HelloVerifyRequest parser takes a cookie of DTLS 1.0 or 1.2 and nothing else" {
    const good = try helloVerify("abc");
    defer gpa.free(good);
    try std.testing.expectEqualSlices(u8, &.{ 3, 0, 0, 6, 0xfe, 0xff, 3, 'a', 'b', 'c' }, good);
    try std.testing.expectEqualSlices(u8, "abc", try Hello.helloVerify(good));
    try std.testing.expectError(error.InvalidHello, Hello.helloVerify(&.{ 3, 0, 0, 3, 0x03, 0x03, 0 }));
    try std.testing.expectError(error.InvalidHello, Hello.helloVerify(&.{ 3, 0, 0, 3, 0xfe, 0xfd, 0 }));
    try std.testing.expectError(error.InvalidLength, Hello.helloVerify(&.{ 3, 0, 0, 7, 0xfe, 0xfd, 3, 'a', 'b', 'c' }));
    try std.testing.expectError(error.InvalidLength, Hello.helloVerify(&.{ 3, 0, 0, 5, 0xfe, 0xfd, 1, 'a', 'b' }));
}

test "C8 the dtls13 prefix is HKDF-Expand-Label's, six bytes in place of tls13's" {
    const H = std.crypto.hash.sha2.Sha256;
    const secret: [32]u8 = @splat(0x42);
    var got: [16]u8 = undefined;
    try Labels.expandWith(H, .dtls13, &got, &secret, "key", "");
    // HKDF-Expand over HkdfLabel { 16, "dtls13" ++ "key", "" } with one block (RFC 9147 section 5.9).
    const info = [_]u8{ 0, 16, 9 } ++ "dtls13key".* ++ [_]u8{0};
    var expected: [16]u8 = undefined;
    std.crypto.kdf.hkdf.HkdfSha256.expand(&expected, &info, secret);
    try std.testing.expectEqualSlices(u8, &expected, &got);
    var tls: [16]u8 = undefined;
    try Labels.expand(H, &tls, &secret, "key", "");
    try std.testing.expect(!std.mem.eql(u8, &tls, &got));
}

test "C8 the DTLS 1.2 transcript hashes the twelve-byte header, as if unfragmented" {
    const H = std.crypto.hash.sha2.Sha256;
    const message = [_]u8{ 14, 0, 0, 2, 0xaa, 0xbb };
    var transcript: Transcript.Transcript(H) = .{};
    try transcript.commitDatagram(&message, 0x0102);
    var expected: [32]u8 = undefined;
    H.hash(&[_]u8{ 14, 0, 0, 2, 1, 2, 0, 0, 0, 0, 0, 2, 0xaa, 0xbb }, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &transcript.digest());
    // Numbered per side, from where the carrier started each: own 3, 4; peer 7.
    var both: Transcripts = .{};
    both.startDatagram(3, 7, false);
    try both.commitOwn(&message);
    try both.commit(&message);
    try both.commitOwn(&message);
    var whole = H.init(.{});
    for ([_]u16{ 3, 7, 4 }) |sequence| {
        var header: [12]u8 = undefined;
        Transcript.datagramHeader(&header, &message, sequence);
        whole.update(&header);
        whole.update(message[4..]);
    }
    var out: [Transcripts.max_digest]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &whole.finalResult(), both.digestOf(&out, 32));
}

test "C8 a datagram hello's cookie field is refused on a stream, and a long one anywhere" {
    var buffer: [2048]u8 = undefined;
    const share: [32]u8 = @splat(5);
    const shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &share }};
    try std.testing.expectError(error.InvalidOptions, Hello.client(&buffer, &@as([32]u8, @splat(1)), "", "c", &shares, "", .{}, .{}));
    const long: [256]u8 = @splat(1);
    try std.testing.expectError(error.InvalidOptions, Hello.client(&buffer, &@as([32]u8, @splat(1)), "", &long, &shares, "", .{ .transport = .datagram }, .{}));
    // A DTLS 1.3-only hello sends no session id.
    try std.testing.expectError(error.InvalidOptions, Hello.client(&buffer, &@as([32]u8, @splat(1)), "s", "", &shares, "", .{ .transport = .datagram, .min_version = .tls13 }, .{}));
}

/// A ServerHello with `extension` appended to its extension block; `session` is the length of its
/// legacy session id.
fn appended(out: []u8, hello: []const u8, session: usize, extension: []const u8) []u8 {
    @memcpy(out[0..hello.len], hello);
    @memcpy(out[hello.len..][0..extension.len], extension);
    const ext_at = 4 + 2 + 32 + 1 + session + 2 + 1;
    const ext_len = std.mem.readInt(u16, out[ext_at..][0..2], .big);
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(ext_len + extension.len), .big);
    std.mem.writeInt(u24, out[1..4], @intCast(hello.len + extension.len - 4), .big);
    return out[0 .. hello.len + extension.len];
}

test "C8 connection_id and use_srtp answers: only what was offered, one profile, no MKI" {
    const only12: []const suites.Suite = &.{.ecdhe_ecdsa_aes_128_gcm_sha256};
    const bare: Hello.Options = .{ .transport = .datagram, .suites = only12, .groups = &.{.x25519} };
    var offering = bare;
    offering.connection_id = "me";
    offering.srtp = &.{ .aead_aes_128_gcm, .aes128_cm_hmac_sha1_80 };
    var buffer: [512]u8 = undefined;
    const random: [32]u8 = @splat(3);
    const hello = try Hello.buildServer12(&buffer, .datagram, &random, "", .ecdhe_ecdsa_aes_128_gcm_sha256, "", .{ .server_name = false, .point_formats = false, .connection_id = "server-id", .srtp = .aes128_cm_hmac_sha1_80 });
    const answer = (try Hello.server(hello, "", &.{}, offering, .{})).tls12;
    try std.testing.expectEqualSlices(u8, "server-id", answer.connection_id.?);
    try std.testing.expectEqual(Hello.Srtp.aes128_cm_hmac_sha1_80, answer.srtp.?);
    // Neither was offered: both answers are unsolicited.
    try std.testing.expectError(error.UnsolicitedExtension, Hello.server(hello, "", &.{}, bare, .{}));
    var cid_only = bare;
    cid_only.connection_id = "";
    try std.testing.expectError(error.UnsolicitedExtension, Hello.server(hello, "", &.{}, cid_only, .{}));
    // A profile the client did not offer.
    var other = offering;
    other.srtp = &.{.aead_aes_256_gcm};
    try std.testing.expectError(error.UnofferedSelection, Hello.server(hello, "", &.{}, other, .{}));
    // A server MKI differs from the client's (none): illegal_parameter (RFC 5764 section 4.1.3).
    const plain = try Hello.buildServer12(buffer[256..], .datagram, &random, "", .ecdhe_ecdsa_aes_128_gcm_sha256, "", .{ .server_name = false, .point_formats = false });
    var spliced: [512]u8 = undefined;
    try std.testing.expectError(error.InvalidHello, Hello.server(appended(&spliced, plain, 0, &.{ 0, 14, 0, 6, 0, 2, 0, 1, 1, 7 }), "", &.{}, offering, .{}));
    // Two profiles in an answer.
    try std.testing.expectError(error.InvalidLength, Hello.server(appended(&spliced, plain, 0, &.{ 0, 14, 0, 7, 0, 4, 0, 1, 0, 7, 0 }), "", &.{}, offering, .{}));
    // DTLS 1.3 answers use_srtp in EncryptedExtensions, never in its ServerHello.
    var thirteen = offering;
    thirteen.suites = suites.Suite.tls13_only;
    var ee_buffer: [128]u8 = undefined;
    const ee = try Hello.buildEncrypted(&ee_buffer, .{ .srtp = .aead_aes_128_gcm });
    try std.testing.expectEqual(Hello.Srtp.aead_aes_128_gcm, (try Hello.encrypted(ee, thirteen, false)).srtp.?);
    var no_srtp = thirteen;
    no_srtp.srtp = &.{};
    try std.testing.expectError(error.UnsolicitedExtension, Hello.encrypted(ee, no_srtp, false));
    const share: [32]u8 = @splat(9);
    const server13 = try Hello.buildServer(&buffer, .datagram, &random, "", .aes_128_gcm_sha256, .x25519, &share, null, "s");
    var shares = [_]Hello.Share{.{ .group = .x25519, .bytes = &share }};
    try std.testing.expectEqualSlices(u8, "s", (try Hello.server(server13, "", &shares, thirteen, .{})).tls13.connection_id.?);
    try std.testing.expectError(error.InvalidHello, Hello.server(appended(&spliced, server13, 0, &.{ 0, 14, 0, 5, 0, 2, 0, 7, 0 }), "", &shares, thirteen, .{}));
    // A retry request carries no connection_id.
    const retry = try Hello.buildRetry(&buffer, .datagram, "", .aes_128_gcm_sha256, .p256, "", false);
    try std.testing.expectError(error.InvalidHello, Hello.server(appended(&spliced, retry, 0, &.{ 0, 54, 0, 2, 1, 9 }), "", &shares, thirteen, .{}));
}

test "C8 connection IDs and SRTP profiles are datagram options, bounded and distinct" {
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .connection_id = "x" }));
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .srtp = &.{.aead_aes_128_gcm} }));
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .transport = .datagram, .connection_id = &@as([256]u8, @splat(1)) }));
    try std.testing.expectError(error.InvalidOptions, Hello.validate(.{ .transport = .datagram, .srtp = &.{ .aead_aes_128_gcm, .aead_aes_128_gcm } }));
    try Hello.validate(.{ .transport = .datagram, .connection_id = &@as([255]u8, @splat(1)), .srtp = &.{ .aead_aes_128_gcm, .aes128_cm_hmac_sha1_80 } });
    // The hello carries them, and the server's parser reads them back.
    var buffer: [2048]u8 = undefined;
    const random: [32]u8 = @splat(5);
    const share: [32]u8 = @splat(9);
    const hello = try Hello.client(&buffer, &random, "", "", &.{.{ .group = .x25519, .bytes = &share }}, "", .{ .transport = .datagram, .groups = &.{.x25519}, .connection_id = "cid", .srtp = &.{ .aead_aes_256_gcm, .aes128_cm_hmac_sha1_32 } }, .{});
    const parsed = try ClientHello.parse(hello, .datagram);
    try std.testing.expectEqualSlices(u8, "cid", parsed.connection_id.?);
    try std.testing.expectEqualSlices(u8, &.{ 0, 8, 0, 2 }, parsed.srtp.?);
}
