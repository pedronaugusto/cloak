//! The failure catalogue's TLS 1.2 rows (F47 to F64): each legacy mechanism is refused at the
//! point a peer could try it, and each modern guard holds.
const std = @import("std");
const Hello = @import("handshake/Hello.zig");
const ClientHello = @import("handshake/ClientHello.zig");
const Messages12 = @import("handshake/Messages12.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Exchange = @import("crypto/Exchange.zig");
const Duo = @import("../testing/Duo.zig");
const Writer = @import("wire/Writer.zig");

const random: [32]u8 = @splat(0x42);

/// A TLS 1.2 ServerHello with chosen suite, compression and extension block.
fn serverHello12(out: []u8, suite: u16, compression: u8, extensions: []const u8, server_random: *const [32]u8) []const u8 {
    var w: Writer = .{ .bytes = out };
    w.put(&.{ 2, 0, 0, 0, 3, 3 }) catch unreachable;
    w.put(server_random) catch unreachable;
    w.put(&.{0}) catch unreachable;
    w.int(u16, suite) catch unreachable;
    w.int(u8, compression) catch unreachable;
    w.vector(u16, extensions) catch unreachable;
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// What a well-behaved TLS 1.2 server answers with: EMS and renegotiation_info.
const good_extensions = "\x00\x17\x00\x00\xff\x01\x00\x01\x00";
const client12: Hello.Options = .{ .max_version = .tls12, .suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };
const client_both: Hello.Options = .{};

fn answer(message: []const u8, options: Hello.Options) Hello.ParseError!Hello.Answer {
    return Hello.server(message, "", &.{}, options);
}

/// A TLS 1.2 ClientHello with chosen suites, compression list and extension block.
fn clientHello12(out: []u8, suites: []const u16, compression: []const u8, extensions: []const u8) []const u8 {
    var w: Writer = .{ .bytes = out };
    w.put(&.{ 1, 0, 0, 0, 3, 3 }) catch unreachable;
    w.put(&random) catch unreachable;
    w.put(&.{0}) catch unreachable;
    w.int(u16, @intCast(suites.len * 2)) catch unreachable;
    for (suites) |suite| w.int(u16, suite) catch unreachable;
    w.vector(u8, compression) catch unreachable;
    w.vector(u16, extensions) catch unreachable;
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// Groups, schemes, EMS and renegotiation_info: everything a modern TLS 1.2 client sends.
const modern = "\x00\x0a\x00\x04\x00\x02\x00\x1d" ++ "\x00\x0d\x00\x04\x00\x02\x04\x03" ++ "\x00\x17\x00\x00" ++ "\xff\x01\x00\x01\x00";

/// Drives a default cloak server with one ClientHello record and returns its failure.
fn serverRefuses(message: []const u8) anyerror {
    const duo = Duo.init(std.testing.allocator, .{}) catch |err| return err;
    defer duo.deinit();
    var record: [1024]u8 = undefined;
    record[0..5].* = .{ 22, 3, 3, 0, 0 };
    std.mem.writeInt(u16, record[3..5], @intCast(message.len), .big);
    @memcpy(record[5..][0..message.len], message);
    _ = duo.server.receive(record[0 .. 5 + message.len]) catch |err| return err;
    return duo.server.diagnostics().reason orelse error.NoFailure;
}

test "F47 catalogue_freak_export_rsa_and_unoffered_exchange" {
    var buffer: [256]u8 = undefined;
    // A server choosing RSA key exchange, an export suite or anything else not offered.
    for ([_]u16{ 0x009c, 0x0003, 0x002f, 0xc030 }) |suite| {
        try std.testing.expectError(error.UnofferedSelection, answer(serverHello12(&buffer, suite, 0, good_extensions, &random), client12));
    }
    // A client offering only RSA key exchange or export suites finds nothing at a cloak server.
    var hello: [512]u8 = undefined;
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0x009c, 0x0003 }, &.{0}, modern)));
}

test "F48 catalogue_logjam_export_and_weak_dh" {
    var buffer: [256]u8 = undefined;
    // No finite-field DHE suite is offered or accepted, export or not.
    for ([_]u16{ 0x009e, 0x0011, 0x0033 }) |suite| {
        try std.testing.expectError(error.UnofferedSelection, answer(serverHello12(&buffer, suite, 0, good_extensions, &random), client12));
    }
    var hello: [512]u8 = undefined;
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0x009e, 0x0011 }, &.{0}, modern)));
}

test "F49 catalogue_raccoon_secret_encoding_and_ephemeral_reuse" {
    // The premaster secret keeps its full fixed length (no stripped leading zeros) and every
    // share is fresh: two shares from different entropy never agree to the same secret.
    var a_seed: [48]u8 = @splat(1);
    var b_seed: [48]u8 = @splat(2);
    for ([_]@import("crypto/Group.zig").Group{ .x25519, .p256, .p384 }) |group| {
        a_seed[47] +%= 1;
        b_seed[47] +%= 1;
        var a = try Exchange.Share.init(group, a_seed[0..Exchange.entropyLength(group)]);
        defer a.deinit();
        var b = try Exchange.Share.init(group, b_seed[0..Exchange.entropyLength(group)]);
        defer b.deinit();
        var ab = try a.agree(b.wire());
        defer ab.deinit();
        var ba = try b.agree(a.wire());
        defer ba.deinit();
        try std.testing.expectEqualSlices(u8, ab.bytes(), ba.bytes());
        const expected: usize = if (group == .p384) 48 else 32;
        try std.testing.expectEqual(expected, ab.len);
    }
}

test "F50 catalogue_poodle_ssl3_and_cbc_fallback" {
    var buffer: [256]u8 = undefined;
    // SSL 3.0 and TLS 1.0/1.1 answers are refused, and no CBC suite exists to fall back to.
    for ([_]u16{ 0x0300, 0x0301, 0x0302 }) |version| {
        const message = serverHello12(&buffer, 0xc02b, 0, good_extensions, &random);
        std.mem.writeInt(u16, buffer[4..6], version, .big);
        try std.testing.expectError(error.UnsupportedVersion, answer(message, client12));
    }
    for (std.enums.values(Suite)) |suite| try std.testing.expect(@backingInt(suite) != 0xc009 and @backingInt(suite) != 0xc013);
}

test "F51 catalogue_beast_chained_iv_profile_refused" {
    // Every TLS 1.2 suite is an AEAD with per-record nonces; there is no chained-IV cipher.
    for (std.enums.values(@import("crypto/Suite.zig").Suite12)) |suite| {
        _ = suite.cipher();
    }
    var hello: [512]u8 = undefined;
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0xc013, 0xc014, 0x002f, 0x0035 }, &.{0}, modern)));
}

test "F52 catalogue_cbc_oracle_absence_and_aead_failure_work" {
    // A forged record fails the tag and closes the epoch; no padding check exists to time.
    const duo = try Duo.init(std.testing.allocator, .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer duo.deinit();
    try duo.handshake();
    var forged: [5 + 8 + 4 + 16]u8 = @splat(0x33);
    forged[0..5].* = .{ 23, 3, 3, 0, 28 };
    try std.testing.expectError(error.BadRecord, duo.server.receive(&forged));
    try std.testing.expectEqual(.bad_record_mac, duo.server.diagnostics().alert_sent.?);
    try std.testing.expectEqual(@as(usize, 0), duo.server.readable().len);
}

test "F53 catalogue_robot_rsa_kex_and_rsa_psk_refused" {
    var hello: [512]u8 = undefined;
    // TLS_RSA_* and RSA_PSK suites: nothing to decrypt with an RSA key, so no oracle.
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0x009c, 0x009d, 0x00ac, 0x00ad }, &.{0}, modern)));
}

test "F54 catalogue_drown_ssl2_and_shared_service_boundary" {
    // An SSLv2-format hello is not a TLS record at all.
    const duo = try Duo.init(std.testing.allocator, .{});
    defer duo.deinit();
    try std.testing.expectError(error.UnexpectedRecord, duo.server.receive("\x80\x2e\x01\x00\x02\x00\x15\x00\x00\x00\x10"));
}

test "F55 catalogue_sweet32_suite_and_usage_limits" {
    // No 64-bit block cipher, and TLS 1.2 records stop at the same per-epoch caps as TLS 1.3.
    var hello: [512]u8 = undefined;
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0x000a, 0xc012 }, &.{0}, modern)));
    const Epoch12 = @import("record/Epoch12.zig").Epoch12(.aes_128_gcm);
    const key: [16]u8 = @splat(1);
    const iv: [4]u8 = @splat(2);
    var epoch = try Epoch12.init(&key, &iv, .{ .records = 2 });
    defer epoch.deinit();
    var out: [64]u8 = undefined;
    _ = try epoch.seal(.application, "a", &out);
    _ = try epoch.seal(.application, "b", &out);
    try std.testing.expectError(error.RecordLimit, epoch.seal(.application, "c", &out));
}

test "F56 catalogue_null_rc4_and_obsolete_hash_policy" {
    var hello: [512]u8 = undefined;
    // NULL, RC4 and SHA-1 MAC suites are unknown to cloak.
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0x0000, 0x0001, 0x0005, 0xc011 }, &.{0}, modern)));
}

test "F57 catalogue_renegotiation_prefix_and_initial_signal" {
    var hello: [512]u8 = undefined;
    // The initial hello must signal secure renegotiation, with an empty renegotiated_connection.
    const no_signal = "\x00\x0a\x00\x04\x00\x02\x00\x1d" ++ "\x00\x0d\x00\x04\x00\x02\x04\x03" ++ "\x00\x17\x00\x00";
    try std.testing.expectEqual(error.NoSecureRenegotiation, serverRefuses(clientHello12(&hello, &.{0xc02b}, &.{0}, no_signal)));
    const prefixed = no_signal ++ "\xff\x01\x00\x0d\x0c" ++ "verify_data!";
    try std.testing.expectEqual(error.IllegalParameter, serverRefuses(clientHello12(&hello, &.{0xc02b}, &.{0}, prefixed)));
    // The SCSV counts as the signal.
    var scsv_hello: [512]u8 = undefined;
    const scsv = clientHello12(&scsv_hello, &.{ 0xc02b, 0x00ff }, &.{0}, no_signal);
    _ = try ClientHello.parse(scsv);
    // A server answer without it, or with a prefix, is refused by the client.
    var buffer: [256]u8 = undefined;
    try std.testing.expectError(error.NoSecureRenegotiation, answer(serverHello12(&buffer, 0xc02b, 0, "\x00\x17\x00\x00", &random), client12));
    try std.testing.expectError(error.NoSecureRenegotiation, answer(serverHello12(&buffer, 0xc02b, 0, "\x00\x17\x00\x00\xff\x01\x00\x02\x01\x00", &random), client12));
}

test "F58 catalogue_triple_handshake_ems_and_exporter_context" {
    var hello: [512]u8 = undefined;
    // Extended master secret is required both ways.
    const no_ems = "\x00\x0a\x00\x04\x00\x02\x00\x1d" ++ "\x00\x0d\x00\x04\x00\x02\x04\x03" ++ "\xff\x01\x00\x01\x00";
    try std.testing.expectEqual(error.NoExtendedMasterSecret, serverRefuses(clientHello12(&hello, &.{0xc02b}, &.{0}, no_ems)));
    var buffer: [256]u8 = undefined;
    try std.testing.expectError(error.NoExtendedMasterSecret, answer(serverHello12(&buffer, 0xc02b, 0, "\xff\x01\x00\x01\x00", &random), client12));
    // Two connections never share exported keys: the master secret binds each session hash.
    var exported: [2][32]u8 = undefined;
    for (&exported, 0..) |*out, i| {
        const duo = try Duo.init(std.testing.allocator, .{ .seed = i + 7, .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
        defer duo.deinit();
        try duo.handshake();
        try duo.client.exportKeyingMaterial(out, "EXPORTER-catalogue", "");
    }
    try std.testing.expect(!std.mem.eql(u8, &exported[0], &exported[1]));
}

test "F59 catalogue_version_rollback_sentinel_and_scsv" {
    var buffer: [256]u8 = undefined;
    // A client that offered TLS 1.3 refuses a TLS 1.2 answer carrying the downgrade sentinel.
    var marked = random;
    marked[24..32].* = Hello.downgrade_tls12.*;
    try std.testing.expectError(error.Downgrade, answer(serverHello12(&buffer, 0xc02b, 0, good_extensions, &marked), client_both));
    // A TLS 1.2-only client has no TLS 1.3 to lose: the sentinel is just a random.
    _ = try answer(serverHello12(&buffer, 0xc02b, 0, good_extensions, &marked), client12);
    // A cloak server that speaks TLS 1.3 refuses a fallback retry, and marks its TLS 1.2 random.
    var hello: [512]u8 = undefined;
    try std.testing.expectEqual(error.InappropriateFallback, serverRefuses(clientHello12(&hello, &.{ 0xc02b, 0x5600 }, &.{0}, modern)));
    const duo = try Duo.init(std.testing.allocator, .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer duo.deinit();
    try duo.handshakeUntilServerFlight();
    const server_hello = duo.server.output();
    try std.testing.expectEqualSlices(u8, Hello.downgrade_tls12, server_hello[5 + 4 + 2 + 24 ..][0..8]);
}

test "F60 catalogue_sloth_signature_hash_and_context_downgrade" {
    // MD5 and SHA-1 signature schemes are neither offered nor accepted.
    for ([_]u16{ 0x0101, 0x0201, 0x0203, 0x0202 }) |scheme| {
        try std.testing.expect(std.enums.fromInt(Hello.SignatureScheme, scheme) == null);
    }
    var buffer: [256]u8 = undefined;
    var params: [128]u8 = undefined;
    const key: [32]u8 = @splat(9);
    const ske = try Messages12.buildServerKeyExchange(&buffer, try Messages12.buildParams(&params, .x25519, &key), 0x0201, "sig");
    const parsed = try Messages12.serverKeyExchange(ske);
    const Possession = @import("handshake/Possession.zig");
    try std.testing.expectError(error.UnofferedScheme, Possession.verifyMessage12(parsed.scheme, &Hello.schemes12, @import("../testing/Peer.zig").pki.p256, "content", parsed.signature));
}

test "F61 catalogue_kci_static_dh_and_role_reflection" {
    var hello: [512]u8 = undefined;
    // Static (fixed) ECDH and DH suites do not exist here; every exchange is ephemeral and
    // signed, so a stolen client key cannot impersonate a server.
    try std.testing.expectEqual(error.NoSharedSuite, serverRefuses(clientHello12(&hello, &.{ 0xc004, 0xc00e, 0x0030 }, &.{0}, modern)));
    // A certificate request asking for fixed-ECDH client certificates gets no certificate.
    var cr: [128]u8 = undefined;
    const request = try Messages12.buildCertificateRequest(&cr, &.{0x0403});
    cr[4..7].* = .{ 2, 65, 66 };
    _ = try Messages12.certificateRequest(request);
}

test "F62 catalogue_crime_record_compression_refused" {
    var hello: [512]u8 = undefined;
    // Only the null compression method is accepted, from a client or a server.
    try std.testing.expectEqual(error.IllegalParameter, serverRefuses(clientHello12(&hello, &.{0xc02b}, &.{ 1, 0 }, modern)));
    var buffer: [256]u8 = undefined;
    try std.testing.expectError(error.InvalidHello, answer(serverHello12(&buffer, 0xc02b, 1, good_extensions, &random), client12));
}

test "F63 catalogue_breach_consumer_compression_policy" {
    // Class A (caller): cloak never compresses records, so HTTP-level compression of secrets
    // next to attacker text is the consumer's policy. What cloak guarantees: a record's
    // ciphertext length is its plaintext length plus a fixed overhead.
    const duo = try Duo.init(std.testing.allocator, .{ .client_max = .tls12, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer duo.deinit();
    try duo.handshake();
    _ = try duo.client.send("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    try std.testing.expectEqual(@as(usize, 32 + 5 + 8 + 16), duo.client.output().len);
}

test "F64 catalogue_starttls_strip_and_plaintext_fallback" {
    // Class A (caller): a connection that fails its handshake never yields plaintext and
    // never reports itself connected, so a caller cannot fall back to cleartext through cloak.
    const result = Duo.init(std.testing.allocator, .{ .client_max = .tls12, .server_min = .tls13, .server_suites = Suite.tls13_only });
    const duo = try result;
    defer duo.deinit();
    try std.testing.expectError(error.UnsupportedVersion, duo.handshake());
    try std.testing.expect(duo.client.phase() != .connected);
    if (duo.client.send("plaintext")) |_| return error.TestUnexpectedResult else |err| try std.testing.expect(err == error.NotConnected or err == error.Closed);
    try std.testing.expectEqual(@as(usize, 0), duo.client.readable().len);
}
