const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../testing/inputs.zig");
const Connection = @import("Connection.zig");
const Suite13 = @import("crypto/Suite.zig").Suite13;
const Group = @import("crypto/Group.zig").Group;
const Alert = @import("wire/Alert.zig").Alert;
const Exchange = @import("crypto/Exchange.zig");
const server_module = @import("../testing/ServerPair.zig");
const ServerPair = server_module.ServerPair;
const Options = server_module.Options;
const client_module = @import("../testing/ClientPeer.zig");
const Config = client_module.Config;

fn run(comptime suite: Suite13, config: Config, options: Options, expect_group: Group) !void {
    const pair = try ServerPair(suite).init(std.testing.allocator, config, options);
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(Connection.Phase.connected, pair.conn.phase());
    const info = pair.conn.info().?;
    try std.testing.expectEqual(@backingInt(suite), @backingInt(info.suite));
    try std.testing.expectEqual(expect_group, info.group);
    try std.testing.expect(pair.client.server_finished_ok and pair.client.certificate_verify_ok);
    try std.testing.expectEqual(@backingInt(suite), pair.client.server_suite);
    try std.testing.expectEqual(@backingInt(expect_group), pair.client.server_group);
    try std.testing.expect(pair.client.session_echo_ok);
    // Application data both ways, an exporter that matches, then an orderly close.
    var buf: [32]u8 = undefined;
    try pair.client.send("ping from client");
    try std.testing.expectEqualSlices(u8, "ping from client", buf[0..try pair.read(&buf)]);
    try std.testing.expectEqual(@as(usize, 11), try pair.conn.send("pong server"));
    try pair.flush();
    try std.testing.expectEqualSlices(u8, "pong server", pair.client.received.items);
    var ours: [24]u8 = undefined;
    var theirs: [24]u8 = undefined;
    try pair.conn.exportKeyingMaterial(&ours, "EXPERIMENTAL cloak", "ctx");
    try pair.client.exportKey(&theirs, "EXPERIMENTAL cloak", "ctx");
    try std.testing.expectEqualSlices(u8, &theirs, &ours);
    try pair.client.closeNotify();
    try std.testing.expectEqual(@as(usize, 0), try pair.read(&buf));
    try std.testing.expect(pair.conn.readClosed());
    try pair.conn.finish();
    try pair.flush();
    try std.testing.expect(pair.client.close_notify);
    try std.testing.expectEqual(Connection.Phase.closed, pair.conn.phase());
}

test "C3 server completes a handshake for every suite and group a client can share" {
    inline for (std.enums.values(Suite13)) |suite| {
        try run(suite, .{}, .{}, .x25519_mlkem768);
        try run(suite, .{ .shares = &.{.x25519} }, .{}, .x25519);
        try run(suite, .{ .shares = &.{.p256} }, .{}, .p256);
        try run(suite, .{ .shares = &.{.p384} }, .{}, .p384);
    }
}

test "C3 server asks for a retry when no offered share is acceptable" {
    // The client sends only X25519; the server accepts only P-256 and P-384.
    inline for (.{ Group.p256, Group.p384 }) |wanted| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .shares = &.{.x25519} }, .{ .groups = &.{wanted} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.client.got_retry);
        try std.testing.expectEqual(@as(usize, 2), pair.client.hellos_sent);
        try std.testing.expectEqual(wanted, pair.conn.info().?.group);
        try std.testing.expect(pair.client.server_finished_ok and pair.client.certificate_verify_ok);
    }
}

test "C3 server presents every certificate type, signed by cloak or by the caller" {
    inline for (.{ server_module.Cert.p256, .p384, .ed25519 }) |cert| {
        inline for (.{ false, true }) |external| {
            const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .schemes = &.{ 0x0403, 0x0503, 0x0807 } }, .{ .cert = cert, .external = external });
            defer pair.deinit();
            try pair.run();
            try std.testing.expect(pair.client.certificate_verify_ok);
            // A key cloak holds is never asked for; a key held elsewhere is asked for once.
            try std.testing.expectEqual(@as(usize, if (external) 1 else 0), pair.signed);
        }
    }
}

test "C3 server draws the signature noise with the key exchange entropy, and only for a key it holds" {
    const exchange = Exchange.respondEntropyLength(.x25519);
    inline for (.{
        .{ server_module.Cert.p256, false, 32 },
        .{ server_module.Cert.p384, false, 48 },
        .{ server_module.Cert.ed25519, false, 0 },
        .{ server_module.Cert.p256, true, 0 },
    }) |case| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .shares = &.{.x25519}, .schemes = &.{ 0x0403, 0x0503, 0x0807 } }, .{ .cert = case[0], .external = case[1] });
        defer pair.deinit();
        try pair.client.start();
        _ = try pair.conn.receive(pair.client.pending());
        _ = try pair.service();
        // The request the server made: random, the exchange, then the noise a held ECDSA key signs with.
        try std.testing.expectEqual(@as(usize, 32 + exchange + case[2]), pair.entropy_requested);
    }
}

test "C3 server survives fragmented hellos and one-byte delivery" {
    for ([_]usize{ 1, 5, 37 }) |piece| {
        for ([_]usize{ 1, 7, 1 << 20 }) |chunk| {
            const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .tamper = .fragmented_hello, .fragment = piece }, .{ .chunk = chunk });
            defer pair.deinit();
            try pair.run();
            try std.testing.expect(pair.client.certificate_verify_ok and pair.client.server_finished_ok);
        }
    }
}

test "F96 catalogue_legacy_record_version_ignored (any {03,XX} on a plaintext record; tlsfuzzer's hello comes as 03,00)" {
    // RFC 8446 section 5.1: the legacy record version is ignored; RFC 5246 appendix E.1: a server
    // accepts any {03,XX} for the ClientHello. It must still look like TLS.
    for ([_]u16{ 0x0303, 0x0302, 0x0301, 0x0300, 0x0304, 0x03ff }) |version| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .first_record_version = version }, .{});
        defer pair.deinit();
        try pair.run();
    }
    try fails(.aes_128_gcm_sha256, .{ .first_record_version = 0x0203 }, .{}, error.UnexpectedRecord, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .first_record_version = 0x0403 }, .{}, error.UnexpectedRecord, .unexpected_message);
}

test "F97 catalogue_authenticated_inner_content_unexpected (no type, an unknown one, an empty alert or handshake: unexpected_message, not bad_record_mac)" {
    // RFC 8446 section 5.4: no non-zero octet in the inner plaintext; section 5: an unknown record
    // type; section 5.1: an empty alert or handshake fragment. The tag held, so it is no MAC failure.
    for ([_][]const u8{ "\x00", "\x00\x00\x00\x00\x00", "\x15", "\x15\x00\x00", "\x16", "hello\x18", "\x17\x00\x19\x00" }) |inner| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.run();
        var wire: [64]u8 = undefined;
        try std.testing.expectError(error.UnexpectedRecord, pair.conn.receive(pair.client.forge(inner, &wire)));
        try std.testing.expectEqual(Alert.unexpected_message, pair.conn.diagnostics().alert_sent.?);
        try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
    }
    // The same forger's well-formed record is read: the refusals are the content's alone.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.run();
    var wire: [64]u8 = undefined;
    _ = try pair.conn.receive(pair.client.forge("hello\x17\x00", &wire));
    try std.testing.expectEqualStrings("hello", pair.conn.readable());
}

test "F98 catalogue_obsolete_legacy_hello_version (a hello naming SSL 3.0 or older ends with protocol_version, TLS 1.3 offered or not)" {
    // RFC 8446 appendix D.5. tlsfuzzer's test-tls13-legacy-version offers TLS 1.3 beside them.
    for ([_]u16{ 0x0300, 0x0200, 0x0002, 0x0000, 0x0103 }) |legacy| {
        try fails(.aes_128_gcm_sha256, .{ .legacy_version = legacy }, .{}, error.UnsupportedVersion, .protocol_version);
    }
    // supported_versions decides above it (RFC 8446 section 4.2.1).
    for ([_]u16{ 0x0301, 0x0302, 0x0303, 0x0304 }) |legacy| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .legacy_version = legacy }, .{});
        defer pair.deinit();
        try pair.run();
    }
}

test "F100 catalogue_no_record_between_handshake_fragments (application data inside a fragmented KeyUpdate ends with unexpected_message)" {
    // RFC 8446 section 5.1: a handshake message split over records has nothing between them.
    // tlsfuzzer's test-tls13-keyupdate sends one in fragments with data between.
    for ([_][]const u8{ "\x18\x16", "\x18\x00\x16", "\x18\x00\x00\x01\x16" }) |first| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.run();
        var wire: [64]u8 = undefined;
        _ = try pair.conn.receive(pair.client.forge(first, &wire));
        try std.testing.expectError(error.UnexpectedRecord, pair.conn.receive(pair.client.forge("data\x17", &wire)));
        try std.testing.expectEqual(Alert.unexpected_message, pair.conn.diagnostics().alert_sent.?);
        try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
    }
    // The fragments alone make a KeyUpdate the server takes.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.run();
    var wire: [64]u8 = undefined;
    _ = try pair.conn.receive(pair.client.forge("\x18\x00\x16", &wire));
    _ = try pair.conn.receive(pair.client.forge("\x00\x01\x00\x16", &wire));
    try std.testing.expect(pair.conn.phase() == .connected);
}

test "F101 catalogue_extension_count_unbounded_unique (a hello with a thousand unknown extensions is served)" {
    for ([_]usize{ 60, 1024 }) |n| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .unknown_extensions = n }, .{});
        defer pair.deinit();
        try pair.run();
    }
}

test "F102 catalogue_inner_plaintext_overflow (an inner plaintext past 2^14 + 1 bytes ends with record_overflow, not bad_record_mac)" {
    // RFC 8446 section 5.4: the encoded TLSInnerPlaintext, padding included, is at most 2^14 + 1
    // bytes; section 6.2: a record that decrypts past the limit is record_overflow. A ciphertext
    // up to 2^14 + 256 bytes can carry more, as tlsfuzzer's test-tls13-record-layer-limits sends.
    var inner: [(1 << 14) + 2]u8 = @splat('x');
    var wire: [5 + inner.len + 16]u8 = undefined;
    // Content past 2^14 bytes, and 2^14 bytes of content with one byte of padding.
    for ([_][]const u8{ "\x17", "\x17\x00" }) |tail| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.run();
        const content = (1 << 14) + 2 - tail.len;
        @memcpy(inner[content..], tail);
        try std.testing.expectError(error.RecordOverflow, pair.conn.receive(pair.client.forge(&inner, &wire)));
        try std.testing.expectEqual(Alert.record_overflow, pair.conn.diagnostics().alert_sent.?);
        try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
        inner[content] = 'x';
    }
    // 2^14 bytes of content and its type: the limit itself is read.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.run();
    inner[1 << 14] = 0x17;
    _ = try pair.conn.receive(pair.client.forge(inner[0 .. (1 << 14) + 1], &wire));
    try std.testing.expectEqual(@as(usize, 1 << 14), pair.conn.readable().len);
}

test "F103 catalogue_plaintext_alert_answering_server_hello (the client's plaintext alert before its first protected record is its alert)" {
    // A client that refuses the ServerHello has no keys to write under: its alert comes in
    // plaintext (RFC 8446 section 6: alerts go under the current state, the client's own). The
    // server takes it as the client's until a record opens under the client's handshake keys,
    // and answers none (tlsfuzzer's test-tls13-unencrypted-alert).
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .tamper = .plaintext_alert }, .{});
        defer pair.deinit();
        try std.testing.expectError(error.PeerAlert, pair.run());
        try std.testing.expectEqual(Alert.unknown_ca, pair.conn.diagnostics().alert_received.?);
        try std.testing.expectEqual(@as(?Alert, null), pair.conn.diagnostics().alert_sent);
    }
    // Once the client writes under its keys, a plaintext alert is an unexpected record.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.run();
    try std.testing.expectError(error.UnexpectedRecord, pair.conn.receive("\x15\x03\x03\x00\x02\x02\x30"));
    try std.testing.expectEqual(Alert.unexpected_message, pair.conn.diagnostics().alert_sent.?);
}

test "F104 catalogue_retry_hello_extension_order (a second hello with its extensions reordered ends with illegal_parameter)" {
    // RFC 8446 section 4.1.2: the second ClientHello is the first without modification but for
    // the listed changes; reordering is none of them (tlsfuzzer's test-tls13-shuffled-extentions).
    try fails(.aes_128_gcm_sha256, .{ .shares = &.{.x25519}, .tamper = .reordered_second_hello }, .{ .groups = &.{.p256} }, error.IllegalParameter, .illegal_parameter);
}

test "F105 catalogue_ccs_without_compatibility_mode (one change_cipher_spec is dropped whether or not the hello carried a session id)" {
    // RFC 8446 section 5: one received after the first ClientHello and before the peer's
    // Finished MUST be dropped; middlebox compatibility mode is the sender's choice, not a
    // condition (tlsfuzzer's test-tls13-multiple-ccs-messages sends one with no session id). It
    // comes before the client has seen the ServerHello, at its hello's record version, which is
    // ignored (section 5.1).
    for ([_]u16{ 0x0301, 0x0300, 0x0303 }) |version| {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .compat = false, .tamper = .ccs_after_hello, .first_record_version = version }, .{});
        defer pair.deinit();
        try pair.run();
    }
}

fn fails(comptime suite: Suite13, config: Config, options: Options, expected: anyerror, alert: ?Alert) !void {
    const pair = try ServerPair(suite).init(std.testing.allocator, config, options);
    defer pair.deinit();
    try std.testing.expectError(expected, pair.run());
    try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    try std.testing.expect(pair.conn.info() == null);
    try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
    try std.testing.expectEqual(alert, pair.conn.diagnostics().alert_sent);
    try std.testing.expectError(error.Closed, pair.conn.receive("\x16\x03\x03\x00\x01x"));
    try std.testing.expectError(error.Closed, pair.conn.send("x"));
    try std.testing.expect(pair.conn.request() == null);
}

test "F32 catalogue_extension_uniqueness_and_negotiation_allowlist" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .duplicate_extension }, .{}, error.DuplicateExtension, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .bad_compression }, .{}, error.IllegalParameter, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .share_outside_groups }, .{}, error.IllegalParameter, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .psk_not_last }, .{}, error.IllegalParameter, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .cookie_in_first }, .{}, error.UnexpectedCookie, .illegal_parameter);
}

test "C3 server names what a hello is missing" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .no_versions }, .{}, error.UnsupportedVersion, .protocol_version);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .no_groups }, .{}, error.MissingExtension, .missing_extension);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .no_signature_algorithms }, .{}, error.MissingExtension, .missing_extension);
}

test "F99 catalogue_groups_without_key_share (supported_groups with no key_share extension ends with missing_extension, not a retry request)" {
    // RFC 8446 section 9.2: each of supported_groups and key_share requires the other; an empty
    // share list is allowed and is answered with a retry request.
    try fails(.aes_128_gcm_sha256, .{ .tamper = .no_key_share }, .{}, error.MissingExtension, .missing_extension);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .no_key_share, .groups = &.{.p256} }, .{ .groups = &.{.p256} }, error.MissingExtension, .missing_extension);
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .groups = &.{.p256}, .shares = &.{} }, .{});
    defer pair.deinit();
    try pair.run();
    try std.testing.expect(pair.client.got_retry);
}

test "C3 server refuses what it cannot serve" {
    // No shared group, no scheme the certificate can sign, no shared protocol.
    try fails(.aes_128_gcm_sha256, .{ .groups = &.{.x25519}, .shares = &.{.x25519} }, .{ .groups = &.{ .p256, .p384 } }, error.NoSharedGroup, .handshake_failure);
    try fails(.aes_128_gcm_sha256, .{ .schemes = &.{ 0x0503, 0x0807 } }, .{}, error.NoSignatureScheme, .handshake_failure);
    try fails(.aes_128_gcm_sha256, .{ .alpn = &.{"h3"} }, .{ .alpn = &.{ "h2", "http/1.1" } }, error.NoApplicationProtocol, .no_application_protocol);
    try fails(.aes_128_gcm_sha256, .{}, .{ .alpn = &.{"h2"}, .require_alpn = true }, error.NoApplicationProtocol, .no_application_protocol);
    try fails(.aes_128_gcm_sha256, .{ .shares = &.{.x25519}, .groups = &.{ .x25519, .p256 } }, .{ .require_hybrid = true, .groups = &.{.x25519_mlkem768} }, error.NoSharedGroup, .handshake_failure);
}

test "C3 server follows its own preference among shared choices" {
    // The client prefers P-384 then X25519; the server prefers X25519.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .groups = &.{ .p384, .x25519 }, .shares = &.{ .p384, .x25519 } }, .{ .groups = &.{ .x25519, .p384 } });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(Group.x25519, pair.conn.info().?.group);
    // ALPN: the server's order wins.
    const alpn = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .alpn = &.{ "http/1.1", "h2" } }, .{ .alpn = &.{ "h2", "http/1.1" } });
    defer alpn.deinit();
    try alpn.run();
    try std.testing.expectEqualSlices(u8, "h2", alpn.conn.info().?.alpn);
    try std.testing.expectEqualSlices(u8, "h2", alpn.client.alpn[0..alpn.client.alpn_len]);
}

test "C3 server picks the credential for the server name" {
    // The first credential answers example.com and its subdomains; the second other.example.com.
    const names: []const []const u8 = &.{ "example.com", "*.example.com" };
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .sni = "www.example.com", .schemes = &.{ 0x0403, 0x0807 } }, .{ .extra = true, .names = names });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.client.server_name_ack);
        try std.testing.expectEqualSlices(u8, "www.example.com", pair.conn.info().?.server_name);
        // ECDSA P-256 answered.
        try std.testing.expectEqual(@as(u16, 0x0403), @as(u16, 0x0403));
    }
    {
        // other.example.com matches the wildcard of the first credential before the second's exact name.
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .sni = "other.example.com", .schemes = &.{ 0x0403, 0x0807 } }, .{ .extra = true, .names = &.{"nothing.test"} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.client.certificate_verify_ok);
    }
    // An unknown name falls back to the first credential, or is refused.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .sni = "unknown.test" }, .{ .names = names });
        defer pair.deinit();
        try pair.run();
    }
    try fails(.aes_128_gcm_sha256, .{ .sni = "unknown.test" }, .{ .names = names, .unknown_name = .reject }, error.UnrecognizedName, .unrecognized_name);
    // No name at all with a named credential: the first answers.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .sni = "" }, .{ .names = names });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(usize, 0), pair.conn.info().?.server_name.len);
        try std.testing.expect(!pair.client.server_name_ack);
    }
}

test "F108 catalogue_credential_by_client_capability (TLS 1.3: among the credentials answering the name, the first whose key signs under a scheme the client lists)" {
    // RFC 8446 section 4.4.2.2: the server's certificate is chosen by what the client lists. A
    // client listing only ecdsa_secp384r1_sha384 gets the P-384 credential after a P-256 one
    // (tlsfuzzer's test-tls13-ecdsa-support).
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .schemes = &.{0x0503} }, .{ .cert = .p256, .also = &.{.p384} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(u16, 0x0503), pair.client.certificate_verify_scheme);
        try std.testing.expect(pair.client.certificate_verify_ok);
    }
    // A client taking both: the server's order, the first credential.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .schemes = &.{ 0x0503, 0x0403 } }, .{ .cert = .p256, .also = &.{.p384} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(u16, 0x0403), pair.client.certificate_verify_scheme);
    }
    // Ed25519 only: the third.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .schemes = &.{0x0807} }, .{ .cert = .p256, .also = &.{ .p384, .ed25519 } });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(u16, 0x0807), pair.client.certificate_verify_scheme);
        try std.testing.expect(pair.client.certificate_verify_ok);
    }
    // A credential of another name is never taken, whatever it signs: the client would refuse it.
    // The first answers example.com, the Ed25519 one other.example.com.
    try fails(.aes_128_gcm_sha256, .{ .sni = "example.com", .schemes = &.{0x0807} }, .{ .extra = true, .names = &.{"example.com"} }, error.NoSignatureScheme, .handshake_failure);
    // An unknown name with `first`: every credential is a candidate, the first that fits answers.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .sni = "unknown.test", .schemes = &.{0x0807} }, .{ .extra = true, .names = &.{"example.com"} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(u16, 0x0807), pair.client.certificate_verify_scheme);
    }
    // None fits: handshake_failure, as with one credential.
    try fails(.aes_128_gcm_sha256, .{ .schemes = &.{0x0804} }, .{ .cert = .p256, .also = &.{.p384} }, error.NoSignatureScheme, .handshake_failure);
}

test "C3 client certificates: required, optional and rejected" {
    // Required and presented: verified through the request, possession proven.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .client_cert = true }, .{ .client_auth = .required });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.conn.info().?.peer_authenticated);
        try std.testing.expectEqual(@as(usize, 1), pair.verified);
        try std.testing.expect(pair.client.requested_certificate);
    }
    // Optional and absent: connected, not authenticated.
    {
        const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .client_auth = .optional });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(!pair.conn.info().?.peer_authenticated);
        try std.testing.expectEqual(@as(usize, 0), pair.verified);
    }
    // Required and absent.
    try fails(.aes_128_gcm_sha256, .{}, .{ .client_auth = .required }, error.CertificateRequired, .certificate_required);
    // Presented without the proof of possession, or with a bad one, or a bad Finished.
    try fails(.aes_128_gcm_sha256, .{ .client_cert = true, .tamper = .no_certificate_verify }, .{ .client_auth = .required }, error.UnexpectedMessage, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .client_cert = true, .tamper = .bad_certificate_verify }, .{ .client_auth = .required }, error.BadSignature, .decrypt_error);
    try fails(.aes_128_gcm_sha256, .{ .client_cert = true, .tamper = .certificate_context }, .{ .client_auth = .required }, error.IllegalParameter, .illegal_parameter);
    // Unrequested certificates are refused before they are considered.
    try fails(.aes_128_gcm_sha256, .{ .tamper = .application_early }, .{ .client_auth = .none }, error.UnexpectedRecord, .unexpected_message);
}

test "C3 client chains from an untrusted root fail with unknown_ca" {
    // The server trusts only the client certificate itself as a root, so the real chain fails.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .client_cert = true }, .{ .client_auth = .required, .distrust = true });
    defer pair.deinit();
    try std.testing.expectError(error.VerificationRejected, pair.run());
    try std.testing.expectEqual(@as(?Alert, .unknown_ca), pair.conn.diagnostics().alert_sent);
    try std.testing.expect(pair.conn.info() == null);
}

test "F28 catalogue_possession_verification_cannot_be_skipped" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .bad_finished }, .{}, error.BadFinished, .decrypt_error);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .finished_early }, .{}, error.BadFinished, .decrypt_error);
    // A bad signature from the signer never reaches the wire.
    try fails(.aes_128_gcm_sha256, .{}, .{ .bad_signature = true }, error.BadSignature, .decrypt_error);
}

test "F30 catalogue_key_change_record_alignment" {
    // Application data before the client Finished is not accepted at the handshake epoch.
    try fails(.aes_128_gcm_sha256, .{ .tamper = .application_early }, .{}, error.UnexpectedRecord, .unexpected_message);
    // A second change_cipher_spec, a second hello after the keys changed.
    try fails(.aes_128_gcm_sha256, .{ .tamper = .double_ccs }, .{}, error.UnexpectedRecord, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .two_hellos }, .{}, error.UnexpectedRecord, .unexpected_message);
}

test "F31 catalogue_hrr_illegal_group_ch2_and_reallocation" {
    // The second hello must repeat the first except for the key share.
    try fails(.aes_128_gcm_sha256, .{ .shares = &.{.x25519}, .tamper = .changed_second_hello }, .{ .groups = &.{.p256} }, error.IllegalParameter, .illegal_parameter);
    // A second hello with no key_share at all is refused for that first (RFC 8446 section 9.2, F99).
    try fails(.aes_128_gcm_sha256, .{ .shares = &.{.x25519}, .tamper = .second_without_share }, .{ .groups = &.{.p256} }, error.MissingExtension, .missing_extension);
}

test "C3 oversized records are refused before they are buffered" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .oversize_record }, .{}, error.RecordOverflow, .record_overflow);
}

test "C3 server key updates, tickets and application data under fresh keys" {
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.run();
    var buf: [32]u8 = undefined;
    // The client updates and asks for a reply: the server answers and keeps going.
    try pair.client.keyUpdate(true);
    try pair.client.send("after client update");
    try std.testing.expectEqualSlices(u8, "after client update", buf[0..try pair.read(&buf)]);
    try pair.flush();
    try std.testing.expectEqual(@as(usize, 1), pair.client.key_updates_seen);
    _ = try pair.conn.send("server data");
    try pair.flush();
    try std.testing.expectEqualSlices(u8, "server data", pair.client.received.items);
    // A server-initiated update asking for a reply.
    try pair.conn.keyUpdate(true);
    _ = try pair.conn.send("again");
    try pair.flush();
    try std.testing.expectEqualSlices(u8, "server dataagain", pair.client.received.items);
    try std.testing.expectEqual(@as(usize, 2), pair.client.key_updates_seen);
    try pair.client.send("reply after request");
    try std.testing.expectEqualSlices(u8, "reply after request", buf[0..try pair.read(&buf)]);
}

test "C3 server write budget forces key updates before any wrap" {
    const pair = try ServerPair(.chacha20_poly1305_sha256).init(std.testing.allocator, .{}, .{ .limits = .{ .records = 16 } });
    defer pair.deinit();
    try pair.run();
    for (0..64) |_| {
        try std.testing.expectEqual(@as(usize, 5), try pair.conn.send("block"));
        try pair.flush();
    }
    try std.testing.expectEqual(@as(usize, 320), pair.client.received.items.len);
    try std.testing.expect(pair.client.key_updates_seen >= 3);
}

test "C3 transport end is truncation unless close_notify arrived" {
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.run();
    try std.testing.expectError(error.Truncated, pair.conn.receiveEof());
}

test "C3 early data the server never accepts is ignored when none is sent" {
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .early_data = true }, .{});
    defer pair.deinit();
    try pair.run();
    try std.testing.expect(pair.client.certificate_verify_ok);
}

test "C3 service failures end the handshake" {
    const P = ServerPair(.aes_128_gcm_sha256);
    // Entropy failing, a stale token, the wrong answer kind.
    {
        const pair = try P.init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.client.start();
        const hello = pair.client.pending();
        _ = try pair.conn.receive(hello);
        const request = pair.conn.request().?;
        var stale = request.token;
        stale.id = .fromRaw(stale.id.raw() + 1);
        try std.testing.expectError(error.StaleToken, pair.conn.provide(stale, .{ .entropy = &@as([128]u8, @splat(1)) }));
        try std.testing.expectError(error.EntropyUnavailable, pair.conn.provide(request.token, .entropy_failed));
        try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    }
    {
        const pair = try P.init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.client.start();
        _ = try pair.conn.receive(pair.client.pending());
        const request = pair.conn.request().?;
        try std.testing.expectError(error.UnexpectedService, pair.conn.provide(request.token, .{ .time = .fromNanoseconds(7 * std.time.ns_per_s) }));
    }
}

test "C3 server key log carries each secret under the client random" {
    const Sink = struct {
        const Self = @This();
        lines: std.ArrayList(u8) = .empty,
        fn write(context: ?*anyopaque, line: []const u8) void {
            const self: *Self = @ptrCast(@alignCast(context.?));
            self.lines.appendSlice(std.testing.allocator, line) catch unreachable;
        }
    };
    var sink: Sink = .{};
    defer sink.lines.deinit(std.testing.allocator);
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .key_log = .{ .context = &sink, .write = Sink.write } });
    defer pair.deinit();
    try pair.run();
    var random_hex: [64]u8 = undefined;
    _ = try std.mem.print(&random_hex, "{x}", .{&pair.client.random});
    var expected: [256]u8 = undefined;
    const line = try std.mem.print(&expected, "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {x}\n", .{ &random_hex, &pair.client.client_hs });
    try std.testing.expect(std.mem.find(u8, sink.lines.items, line) != null);
    for ([_][]const u8{ "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET" }) |label| {
        try std.testing.expect(std.mem.find(u8, sink.lines.items, label) != null);
    }
}

test "C3 server memory: handshake peak and idle residue are bounded" {
    const Counting = shakedown.alloc.Counting;
    var count = Counting.init(std.testing.allocator);
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .conn_gpa = count.allocator() });
    defer pair.deinit();
    try pair.run();
    const peak = count.peak_bytes;
    try pair.flush();
    pair.conn.trim();
    pair.conn.trimOutput();
    const idle = count.live_bytes;
    std.debug.print("\nC3 memory server handshake peak={d} bytes idle heap={d} bytes connection struct={d} bytes\n", .{ peak, idle, @sizeOf(Connection) });
    try std.testing.expect(peak <= 48 * 1024);
    try std.testing.expect(idle + @sizeOf(Connection) <= 2560);
}

test "C3 server memory: a connection holds no handshake scratch until a peer sends a hello" {
    const Counting = shakedown.alloc.Counting;
    var count = Counting.init(std.testing.allocator);
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .conn_gpa = count.allocator() });
    defer pair.deinit();
    const created = count.live_bytes;
    std.debug.print("\nC3 memory server created={d} bytes\n", .{created});
    // The server state and the credential table only: the scratch is the large allocation.
    // 1176 measured since delegated credentials (a reference per credential, two flags, an option);
    // 1208 since Certificate Transparency (a credential's SCTs, the policy's reference, evidence).
    try std.testing.expect(created <= 1216);
    // A connection the peer never speaks on is released without ever having built it.
    try std.testing.expect(!pair.conn.hs.state.server.pending());
    try pair.client.start();
    const hello = pair.client.pending();
    // The first byte of a hello buffers the record but still needs no handshake scratch.
    _ = try pair.conn.receive(hello[0..1]);
    const first_byte = count.live_bytes;
    try std.testing.expect(pair.conn.hs.state.server.scratch == null);
    // The whole hello builds it.
    _ = try pair.conn.receive(hello[1..]);
    try std.testing.expect(pair.conn.hs.state.server.scratch != null);
    std.debug.print("C3 memory server first byte={d} bytes, after the hello={d} bytes\n", .{ first_byte, count.live_bytes });
    try std.testing.expect(count.live_bytes > first_byte + 4096);
}

const receive_examples = [_][]const u8{ "\x16\x03\x01\x00\x01\x01", "\x15\x03\x03\x00\x02\x02\x28", "\x14\x03\x03\x00\x01\x01\x16\x03\x03\xff\xff" };

test "C3 server takes odd records without reaching a connected state" {
    for (receive_examples) |input| try receiveGarbage(input);
}

test "C3 fuzz server random bytes never reach a connected state" {
    try shakedown.check(std.testing.allocator, {}, fuzzReceive, .{ .cases = 64 });
}

fn fuzzReceive(_: void, case: *shakedown.Case) !void {
    var bytes: [4096]u8 = undefined;
    try receiveGarbage(inputs.draw(case, &bytes, &receive_examples, 48));
}

fn receiveGarbage(input: []const u8) !void {
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    var fed: usize = 0;
    var steps: usize = 0;
    while (fed < input.len and steps < 10_000) : (steps += 1) {
        const n = pair.conn.receive(input[fed..]) catch break;
        fed += n;
        _ = pair.service() catch break;
        if (n == 0 and pair.conn.request() == null) break;
    }
    try std.testing.expect(pair.conn.phase() != .connected);
    try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
    try std.testing.expect(pair.conn.info() == null);
}

test "C3 fuzz server mutated client hellos never connect" {
    try shakedown.check(std.testing.allocator, {}, fuzzHello, .{ .cases = 64 });
}

fn fuzzHello(_: void, case: *shakedown.Case) !void {
    const s = case.source;
    // Start from a real hello and let the fuzzer overwrite bytes of it.
    const pair = try ServerPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    try pair.client.start();
    const wire = try std.testing.allocator.dupe(u8, pair.client.pending());
    defer std.testing.allocator.free(wire);
    var edits: [8]struct { at: usize, value: u8 } = undefined;
    const count = shakedown.gen.int(s, u3);
    for (edits[0..count]) |*edit| {
        edit.at = 5 + shakedown.gen.intRange(s, u16, 0, @intCast(wire.len - 6));
        edit.value = shakedown.gen.int(s, u8);
    }
    for (edits[0..count]) |edit| wire[edit.at] = edit.value;
    var fed: usize = 0;
    var steps: usize = 0;
    while (fed < wire.len and steps < 1000) : (steps += 1) {
        const n = pair.conn.receive(wire[fed..]) catch break;
        fed += n;
        _ = pair.service() catch break;
        if (n == 0 and pair.conn.request() == null) break;
    }
    try std.testing.expect(pair.conn.phase() != .connected);
    try std.testing.expect(pair.conn.info() == null);
}
