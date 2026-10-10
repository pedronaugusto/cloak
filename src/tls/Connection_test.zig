const std = @import("std");
const shakedown = @import("shakedown");
const certificates = @import("../certificates.zig");
const Connection = @import("Connection.zig");
const Suite13 = @import("crypto/Suite.zig").Suite13;
const Group = @import("crypto/Group.zig").Group;
const Alert = @import("wire/Alert.zig").Alert;
const pair_module = @import("../testing/Pair.zig");
const Pair = pair_module.Pair;
const Options = pair_module.Options;
const peer_module = @import("../testing/Peer.zig");
const pki = peer_module.pki;

fn run(comptime suite: Suite13, config: peer_module.Config, options: Options) !void {
    const P = Pair(suite);
    const pair = try P.init(std.testing.allocator, config, options);
    defer pair.deinit();
    try pair.handshake();
    try std.testing.expectEqual(Connection.Phase.connected, pair.conn.phase());
    const info = pair.conn.info().?;
    try std.testing.expectEqual(suite, info.suite);
    try std.testing.expectEqual(config.group, info.group);
    try std.testing.expect(info.peer_authenticated);
    try std.testing.expect(pair.peer.client_finished_ok);
    // Application data both ways, then an orderly close.
    try std.testing.expectEqual(@as(usize, 5), try pair.conn.send("hello"));
    try pair.flush();
    try std.testing.expectEqualSlices(u8, "hello", pair.peer.received.items);
    try pair.peer.send("world!");
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualSlices(u8, "world!", buf[0..try pair.read(&buf)]);
    // Exporters agree with the peer's independent derivation.
    var ours: [24]u8 = undefined;
    var theirs: [24]u8 = undefined;
    try pair.conn.exportKeyingMaterial(&ours, "EXPERIMENTAL cloak", "ctx");
    try pair.peer.exportKey(&theirs, "EXPERIMENTAL cloak", "ctx");
    try std.testing.expectEqualSlices(u8, &theirs, &ours);
    try pair.peer.closeNotify();
    try std.testing.expectEqual(@as(usize, 0), try pair.read(&buf));
    try std.testing.expect(pair.conn.readClosed());
    try pair.conn.finish();
    try pair.flush();
    try std.testing.expect(pair.peer.close_notify);
    try std.testing.expectEqual(Connection.Phase.closed, pair.conn.phase());
}

fn retrying(group: Group) ?Group {
    return if (group == .p256 or group == .p384) group else null;
}

test "C2 connection completes a full handshake for every suite and group" {
    inline for (std.enums.values(Suite13)) |suite| {
        inline for (.{ Group.x25519, Group.x25519_mlkem768, Group.p256, Group.p384 }) |group| {
            try run(suite, .{ .group = group, .retry = retrying(group) }, .{});
        }
    }
}

test "C2 connection authenticates every certificate type" {
    inline for (.{ peer_module.Cert.p256, .p384, .ed25519 }) |cert| {
        try run(.aes_128_gcm_sha256, .{ .cert = cert }, .{});
    }
}

test "C2 connection survives every record layout and one-byte delivery" {
    const layouts = [_]peer_module.Layout{ .coalesced, .separate, .{ .fragments = 1 }, .{ .fragments = 7 }, .{ .fragments = 100 } };
    for (layouts) |layout| {
        for ([_]usize{ 1, 3, 1 << 20 }) |chunk| {
            try run(.aes_128_gcm_sha256, .{ .layout = layout }, .{ .chunk = chunk });
            try run(.chacha20_poly1305_sha256, .{ .layout = layout, .group = .p256, .retry = .p256 }, .{ .chunk = chunk });
        }
    }
}

/// The handshake must fail with `expected`, send `alert`, and leave nothing authenticated.
fn fails(comptime suite: Suite13, config: peer_module.Config, options: Options, expected: anyerror, alert: ?Alert) !void {
    const pair = try Pair(suite).init(std.testing.allocator, config, options);
    defer pair.deinit();
    try std.testing.expectError(expected, pair.handshake());
    try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    try std.testing.expect(pair.conn.info() == null);
    try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
    try std.testing.expectEqual(alert, pair.conn.diagnostics().alert_sent);
    if (alert != null) {
        const sent = pair.conn.output();
        try std.testing.expect(sent.len >= 7 and (sent[0] == 21 or sent[0] == 23));
    }
    // A failed connection is terminal: no further progress, no new service work.
    try std.testing.expectError(error.Closed, pair.conn.receive("\x16\x03\x03\x00\x01x"));
    try std.testing.expectError(error.Closed, pair.conn.send("x"));
    try std.testing.expect(pair.conn.request() == null);
}

test "C2 catalogue_possession_verification_cannot_be_skipped" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .missing_certificate_verify }, .{}, error.UnexpectedMessage, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .bad_signature }, .{}, error.BadSignature, .decrypt_error);
    try fails(.aes_128_gcm_sha256, .{ .cert = .ed25519, .tamper = .bad_signature }, .{}, error.BadSignature, .decrypt_error);
    try fails(.aes_256_gcm_sha384, .{ .cert = .p384, .tamper = .bad_signature }, .{}, error.BadSignature, .decrypt_error);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .bad_finished }, .{}, error.BadFinished, .decrypt_error);
    // The chain is verified first; with verification disabled possession is still proven.
    try fails(.aes_128_gcm_sha256, .{ .tamper = .bad_signature }, .{ .verify_none = true }, error.BadSignature, .decrypt_error);
}

test "C2 catalogue_certificate_verify_scheme_restrictions" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .scheme_not_offered }, .{}, error.UnofferedScheme, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .scheme_curve_mismatch }, .{}, error.SchemeKeyMismatch, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .cert = .p384, .tamper = .scheme_curve_mismatch }, .{}, error.SchemeKeyMismatch, .illegal_parameter);
}

test "C2 catalogue_smack_authentication_skip_edges" {
    // A CertificateRequest after the Certificate, and application bytes before Finished.
    try fails(.aes_128_gcm_sha256, .{ .request_client_cert = true, .tamper = .certificate_request_late }, .{}, error.UnexpectedMessage, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .application_before_finished }, .{}, error.UnexpectedRecord, .unexpected_message);
}

test "C2 catalogue_key_change_record_alignment" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .encrypted_extensions_in_hello_record }, .{}, error.RecordAlignment, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .plaintext_encrypted_extensions }, .{}, error.UnexpectedRecord, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .finished_not_at_record_end }, .{}, error.RecordAlignment, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .finished_not_at_record_end, .layout = .{ .fragments = 5 } }, .{}, error.RecordAlignment, .unexpected_message);
}

test "C2 catalogue_extension_uniqueness_and_negotiation_allowlist" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .duplicate_extension_in_encrypted }, .{}, error.DuplicateExtension, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .alpn = "h2", .tamper = .unoffered_alpn }, .{ .alpn = &.{ "h2", "http/1.1" } }, error.UnofferedSelection, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .extension_in_certificate_entry }, .{}, error.UnsolicitedExtension, .unsupported_extension);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .unoffered_group }, .{}, error.InvalidHello, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .wrong_session_id }, .{}, error.InvalidHello, .illegal_parameter);
}

test "C2 a server choosing a suite the client did not offer is refused" {
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .offer = &.{.chacha20_poly1305_sha256} });
    defer pair.deinit();
    try std.testing.expectError(error.UnofferedSelection, pair.handshake());
    try std.testing.expectEqual(@as(?Alert, .illegal_parameter), pair.conn.diagnostics().alert_sent);
}

test "C2 a server answering with an older version is refused, and a downgrade sentinel is named" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .legacy_server_hello }, .{}, error.UnsupportedVersion, .protocol_version);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .downgrade_sentinel }, .{}, error.Downgrade, .illegal_parameter);
}

test "C2 catalogue_certificate_message_shapes" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .empty_certificate_list }, .{}, error.EmptyCertificate, .decode_error);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .nonempty_certificate_context }, .{}, error.IllegalParameter, .illegal_parameter);
}

test "C2 catalogue_ecdh_invalid_curve_and_noncontributory_share" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .zero_key_share }, .{}, error.WeakKey, .illegal_parameter);
}

test "C2 catalogue_record_outer_type_and_wire_aad" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .bad_tag }, .{}, error.BadRecord, .bad_record_mac);
}

test "C2 catalogue_hrr_illegal_group_ch2_and_reallocation" {
    // A retry for a group already shared is invalid, a second retry is illegal.
    try fails(.aes_128_gcm_sha256, .{ .retry = .x25519 }, .{}, error.InvalidHello, .illegal_parameter);
    try fails(.aes_128_gcm_sha256, .{ .retry = .p256, .group = .p256, .tamper = .second_retry }, .{}, error.UnexpectedMessage, .unexpected_message);
    // A retry for a group the client never offered.
    try fails(.aes_128_gcm_sha256, .{ .retry = .p384, .group = .p384 }, .{ .groups = &.{ .x25519, .p256 } }, error.UnofferedSelection, .illegal_parameter);
}

test "C2 hello retry request carries a cookie and the second hello repeats the first" {
    const P = Pair(.aes_128_gcm_sha256);
    // A cookie with a group change: fresh share for the requested group only.
    {
        const pair = try P.init(std.testing.allocator, .{ .group = .p256, .retry = .p256, .cookie = "opaque-cookie" }, .{});
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqual(@as(usize, 2), pair.peer.seen.hellos);
        try std.testing.expectEqual(@as(usize, "opaque-cookie".len), pair.peer.seen.cookie_len);
        try std.testing.expect(pair.peer.seen.sharedGroup(.p256) and !pair.peer.seen.sharedGroup(.x25519));
        try std.testing.expectEqual(@as(u16, 0x0303), pair.peer.seen.legacy_version);
        try std.testing.expectEqual(@as(usize, 1), pair.peer.seen.ccs);
    }
    // A cookie-only retry keeps the original shares and echoes the cookie.
    {
        const pair = try P.init(std.testing.allocator, .{ .group = .x25519, .retry = .x25519, .cookie = "opaque-cookie", .cookie_only = true }, .{});
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqual(@as(usize, 2), pair.peer.seen.hellos);
        try std.testing.expectEqual(@as(usize, "opaque-cookie".len), pair.peer.seen.cookie_len);
        try std.testing.expect(pair.peer.seen.sharedGroup(.x25519) and pair.peer.seen.sharedGroup(.x25519_mlkem768));
    }
}

test "C2 client hello offers TLS 1.3 only with hybrid and X25519 shares and no resumption or early data" {
    const P = Pair(.aes_128_gcm_sha256);
    const pair = try P.init(std.testing.allocator, .{ .alpn = "h2" }, .{ .alpn = &.{ "h2", "http/1.1" } });
    defer pair.deinit();
    try pair.handshake();
    const seen = &pair.peer.seen;
    try std.testing.expect(seen.versions_only_13);
    try std.testing.expectEqual(@as(u16, 0x0303), seen.legacy_version);
    try std.testing.expectEqual(@as(u16, 0x0301), seen.first_hello_record_version);
    try std.testing.expectEqual(@as(usize, 32), seen.session_id_len);
    try std.testing.expectEqual(@as(u16, 4588), seen.shares[0]);
    try std.testing.expect(seen.sharedGroup(.x25519_mlkem768) and seen.sharedGroup(.x25519));
    try std.testing.expectEqual(@as(usize, 2), seen.share_count);
    try std.testing.expect(seen.offeredGroup(.p256) and seen.offeredGroup(.p384));
    try std.testing.expect(!seen.has_psk and !seen.has_early_data);
    try std.testing.expectEqualSlices(u8, "example.com", seen.sni[0..seen.sni_len]);
    try std.testing.expect(seen.offeredAlpn("h2") and seen.offeredAlpn("http/1.1"));
    // One suite configured, one ChangeCipherSpec sent.
    try std.testing.expectEqual(@as(usize, 1), seen.suite_count);
    try std.testing.expectEqual(@as(usize, 1), seen.ccs);
}

test "C2 client hello without compatibility mode sends no session id and no change_cipher_spec" {
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .compat = false });
    defer pair.deinit();
    try pair.handshake();
    try std.testing.expectEqual(@as(usize, 0), pair.peer.seen.session_id_len);
    try std.testing.expectEqual(@as(usize, 0), pair.peer.seen.ccs);
}

test "C2 server name and reference identity are separate" {
    const P = Pair(.aes_128_gcm_sha256);
    // An IP reference identity sends no SNI and matches the certificate's address entry.
    {
        const pair = try P.init(std.testing.allocator, .{}, .{ .identity = .{ .ipv4 = .{ 192, 0, 2, 7 } } });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqual(@as(usize, 0), pair.peer.seen.sni_len);
    }
    // A wildcard entry does not authenticate the bare domain or a deeper name.
    try fails(.aes_128_gcm_sha256, .{}, .{ .identity = .{ .dns = "example.org" } }, error.VerificationRejected, .bad_certificate);
    try fails(.aes_128_gcm_sha256, .{}, .{ .identity = .{ .dns = "a.b.example.org" } }, error.VerificationRejected, .bad_certificate);
    {
        const pair = try P.init(std.testing.allocator, .{}, .{ .identity = .{ .dns = "www.example.org" } });
        defer pair.deinit();
        try pair.handshake();
    }
    // A different name in the certificate than the one asked for is a failure.
    try fails(.aes_128_gcm_sha256, .{}, .{ .identity = .{ .dns = "other.test" } }, error.VerificationRejected, .bad_certificate);
}

test "C2 verification failures map to alerts and never authenticate" {
    // Expired and not-yet-valid certificates.
    try fails(.aes_128_gcm_sha256, .{}, .{ .time = pki.time + 100 * 365 * 24 * 3600 }, error.VerificationRejected, .certificate_expired);
    try fails(.aes_128_gcm_sha256, .{}, .{ .time = 1_000_000_000 }, error.VerificationRejected, .certificate_expired);
    // An untrusted root.
    try fails(.aes_128_gcm_sha256, .{}, .{ .trusted_root = pki.client }, error.VerificationRejected, .unknown_ca);
}

fn spkiPin(der: []const u8) ![32]u8 {
    const cert = try certificates.certificate.parse(der, .{});
    var pin: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert.spki, &pin, .{});
    return pin;
}

test "C2 pins are additional to full verification" {
    const P = Pair(.aes_128_gcm_sha256);
    const good = try spkiPin(pki.p256);
    {
        const pair = try P.init(std.testing.allocator, .{}, .{ .pins = &.{good} });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expect(pair.conn.info().?.peer_authenticated);
    }
    const other = try spkiPin(pki.p384);
    try fails(.aes_128_gcm_sha256, .{}, .{ .pins = &.{other} }, error.VerificationRejected, .bad_certificate);
}

test "C2 explicit no-verification yields an unauthenticated connection" {
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .verify_none = true, .identity = .none });
    defer pair.deinit();
    try pair.handshake();
    try std.testing.expect(!pair.conn.info().?.peer_authenticated);
    try std.testing.expectEqual(@as(usize, 0), pair.verified);
    try std.testing.expectEqual(@as(usize, 0), pair.peer.seen.sni_len);
}

test "C2 catalogue_alpaca_protocol_and_port_binding" {
    const P = Pair(.aes_128_gcm_sha256);
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "http/1.1" }, .{ .alpn = &.{ "h2", "http/1.1" }, .require_alpn = true });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqualSlices(u8, "http/1.1", pair.conn.info().?.alpn);
    }
    // Required ALPN with no selection fails with its own alert; optional ALPN stays visible.
    try fails(.aes_128_gcm_sha256, .{}, .{ .alpn = &.{"h2"}, .require_alpn = true }, error.NoApplicationProtocol, .no_application_protocol);
    {
        const pair = try P.init(std.testing.allocator, .{}, .{ .alpn = &.{"h2"} });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqual(@as(usize, 0), pair.conn.info().?.alpn.len);
    }
}

test "C2 require_hybrid refuses a classical selection" {
    try fails(.aes_128_gcm_sha256, .{ .group = .x25519 }, .{ .require_hybrid = true }, error.HybridRequired, .insufficient_security);
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .group = .x25519_mlkem768 }, .{ .require_hybrid = true });
    defer pair.deinit();
    try pair.handshake();
}

test "C2 client certificate response: signed, empty, or refused by an unsuitable key" {
    const gpa = std.testing.allocator;
    const P = Pair(.aes_128_gcm_sha256);
    {
        const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
        defer key.deinit();
        const auth = try certificates.ClientAuth.init(gpa, &.{pki.client}, key, .{});
        defer auth.deinit();
        const pair = try P.init(gpa, .{ .request_client_cert = true }, .{ .client_auth = auth });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqual(@as(usize, 1), pair.peer.client_certificates);
        try std.testing.expect(pair.peer.client_signature_ok);
        try std.testing.expectEqualSlices(u8, pki.client, pair.peer.client_chain.items);
        try std.testing.expect(pair.peer.client_finished_ok);
    }
    {
        // The server asked and the client has no identity: an empty Certificate, no CertificateVerify.
        const pair = try P.init(gpa, .{ .request_client_cert = true }, .{});
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expect(pair.conn.certificateRequested());
        try std.testing.expectEqual(@as(usize, 0), pair.peer.client_certificates);
        try std.testing.expect(!pair.peer.client_signature_ok);
        try std.testing.expect(pair.peer.client_finished_ok);
    }
    {
        // An Ed25519 key is not among the signature algorithms the server listed: empty response.
        const key = try certificates.PrivateKey.parse(gpa, pki.client_ed25519_pem, .{});
        defer key.deinit();
        const auth = try certificates.ClientAuth.init(gpa, &.{pki.client_ed25519}, key, .{});
        defer auth.deinit();
        const pair = try P.init(gpa, .{ .request_client_cert = true }, .{ .client_auth = auth, .sign_with = .ed25519 });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectEqual(@as(usize, 0), pair.peer.client_certificates);
    }
    {
        // Without a request the identity is never sent.
        const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
        defer key.deinit();
        const auth = try certificates.ClientAuth.init(gpa, &.{pki.client}, key, .{});
        defer auth.deinit();
        const pair = try P.init(gpa, .{}, .{ .client_auth = auth });
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expect(!pair.conn.certificateRequested());
        try std.testing.expectEqual(@as(usize, 0), pair.peer.client_certificates);
    }
}

test "C2 the client draws signature noise up front for a key it holds, and asks to sign for a key held elsewhere" {
    const gpa = std.testing.allocator;
    const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
    defer key.deinit();
    const held = try certificates.ClientAuth.init(gpa, &.{pki.client}, key, .{});
    defer held.deinit();
    const elsewhere = try certificates.ClientAuth.initExternal(gpa, &.{pki.client}, .{});
    defer elsewhere.deinit();
    var lengths: [3]usize = undefined;
    for ([_]?certificates.ClientAuth{ null, held, elsewhere }, &lengths) |auth, *length| {
        var conn = try Connection.client(gpa, .{ .identity = .{ .dns = "example.com" }, .verify = .none, .auth = auth });
        defer conn.deinit();
        length.* = conn.request().?.service.entropy;
    }
    // No identity and a key held elsewhere draw the same; a held P-256 key adds its 32 noise bytes.
    try std.testing.expectEqual(lengths[0], lengths[2]);
    try std.testing.expectEqual(lengths[0] + 32, lengths[1]);
}

test "C2 a bad client signature from the signer never reaches the wire" {
    const gpa = std.testing.allocator;
    const auth = try certificates.ClientAuth.initExternal(gpa, &.{pki.client}, .{});
    defer auth.deinit();
    const pair = try Pair(.aes_128_gcm_sha256).init(gpa, .{ .request_client_cert = true }, .{ .client_auth = auth, .hold_sign = true });
    defer pair.deinit();
    // Drive until the signature is requested, then answer with garbage.
    var rounds: usize = 0;
    while (rounds < 50) : (rounds += 1) {
        if (pair.conn.request()) |request| {
            if (request.service == .sign) {
                try std.testing.expectError(error.BadSignature, pair.conn.provide(request.token, .{ .signature = "not a signature" }));
                break;
            }
        }
        _ = try pair.step();
    } else return error.NeverAskedForSignature;
    try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    try pair.flush();
    // The peer never saw a client Finished.
    try std.testing.expect(!pair.peer.client_finished_ok);
}

test "C2 key updates in both directions keep data flowing under fresh keys" {
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .tickets = 0 }, .{});
    defer pair.deinit();
    try pair.handshake();
    var buf: [32]u8 = undefined;
    // The peer updates and asks for a reply: the client updates its read keys and answers.
    try pair.peer.keyUpdate(true);
    try pair.peer.send("after peer update");
    try std.testing.expectEqualSlices(u8, "after peer update", buf[0..try pair.read(&buf)]);
    try pair.flush();
    try std.testing.expectEqual(@as(usize, 1), pair.peer.key_updates_seen);
    // The client's reply moved its write keys; data under them still opens at the peer.
    _ = try pair.conn.send("client data");
    try pair.flush();
    try std.testing.expectEqualSlices(u8, "client data", pair.peer.received.items);
    // A client-initiated update asking for a reply.
    try pair.conn.keyUpdate(true);
    _ = try pair.conn.send("again");
    try pair.flush();
    try std.testing.expectEqualSlices(u8, "client dataagain", pair.peer.received.items);
    try std.testing.expectEqual(@as(usize, 2), pair.peer.key_updates_seen);
    try pair.peer.send("reply after request");
    try std.testing.expectEqualSlices(u8, "reply after request", buf[0..try pair.read(&buf)]);
}

test "C2 catalogue_nonce_uniqueness_partial_retry_and_wrap" {
    // A tiny record budget forces the client to update its write keys before it can wrap.
    const pair = try Pair(.chacha20_poly1305_sha256).init(std.testing.allocator, .{ .tickets = 0 }, .{ .limits = .{ .records = 16 } });
    defer pair.deinit();
    try pair.handshake();
    var sent: usize = 0;
    var line: [5]u8 = undefined;
    for (0..64) |i| {
        line = .{ 'r', 'e', 'c', @intCast('0' + i / 10), @intCast('0' + i % 10) };
        try std.testing.expectEqual(@as(usize, 5), try pair.conn.send(&line));
        sent += 5;
        // Partial acknowledgement: the committed ciphertext is retained byte for byte.
        const out = pair.conn.output();
        const before = try std.testing.allocator.dupe(u8, out);
        defer std.testing.allocator.free(before);
        pair.conn.acknowledge(1);
        try std.testing.expectEqualSlices(u8, before[1..], pair.conn.output());
        try pair.peer.feed(before[0..1]);
        try pair.peer.feed(before[1..]);
        pair.conn.acknowledge(pair.conn.output().len);
    }
    try std.testing.expectEqual(sent, pair.peer.received.items.len);
    try std.testing.expect(pair.peer.key_updates_seen >= 3);
    try std.testing.expectEqualSlices(u8, "rec00rec01rec02", pair.peer.received.items[0..15]);
    try std.testing.expect(pair.conn.phase() == .connected);
}

test "C2 the peer exhausting its record budget is asked to update" {
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .tickets = 0 }, .{ .limits = .{ .records = 4096 } });
    defer pair.deinit();
    try pair.handshake();
    // A small budget makes the client ask for the peer's next write keys.
    var count: usize = 0;
    var buf: [8]u8 = undefined;
    while (count < 4200) : (count += 1) {
        try pair.peer.send("x");
        _ = try pair.read(&buf);
        if (pair.conn.output().len != 0) try pair.flush();
        if (pair.peer.key_updates_seen != 0) break;
    }
    try std.testing.expect(pair.peer.key_updates_seen >= 1);
    try std.testing.expect(count < 4096);
}

test "C2 catalogue_keyupdate_flood_and_step_budget" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .ticket_flood }, .{}, error.ControlFlood, .unexpected_message);
    try fails(.aes_128_gcm_sha256, .{ .tamper = .key_update_flood }, .{}, error.ControlFlood, .unexpected_message);
}

test "C2 compatibility change_cipher_spec is tolerated once and nowhere else" {
    try fails(.aes_128_gcm_sha256, .{ .tamper = .ccs_after_finished }, .{}, error.UnexpectedRecord, .unexpected_message);
}

test "C2 catalogue_eof_at_every_record_and_application_boundary" {
    // Truncate the server flight at many points: the client never connects and EOF is Truncated.
    const P = Pair(.aes_128_gcm_sha256);
    const probe = try P.init(std.testing.allocator, .{}, .{});
    var total: usize = 0;
    {
        defer probe.deinit();
        _ = try probe.service();
        try probe.flush();
        total = probe.peer.pending().len;
    }
    var cut: usize = 0;
    while (cut < total) : (cut += 13) {
        const pair = try P.init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        _ = try pair.service();
        try pair.flush();
        const wire = try std.testing.allocator.dupe(u8, pair.peer.pending());
        defer std.testing.allocator.free(wire);
        var fed: usize = 0;
        while (fed < cut) {
            const n = try pair.conn.receive(wire[fed..cut]);
            fed += n;
            if (try pair.service()) continue;
            if (n == 0) break;
        }
        try std.testing.expect(pair.conn.phase() != .connected);
        try std.testing.expectError(error.Truncated, pair.conn.receiveEof());
        try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    }
}

test "C2 transport end after the handshake is truncation unless close_notify arrived" {
    {
        const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.handshake();
        try std.testing.expectError(error.Truncated, pair.conn.receiveEof());
    }
    {
        const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        try pair.handshake();
        try pair.peer.closeNotify();
        var buf: [4]u8 = undefined;
        try std.testing.expectEqual(@as(usize, 0), try pair.read(&buf));
        try pair.conn.receiveEof();
        try std.testing.expectError(error.Closed, pair.conn.receive("x"));
    }
}

test "C2 catalogue_clienthello_close_notify_no_spin" {
    // A clear alert instead of a ServerHello is a failure, and repeated calls then stay inert.
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    _ = try pair.service();
    try std.testing.expectError(error.PeerAlert, pair.conn.receive("\x15\x03\x03\x00\x02\x01\x00"));
    try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    for (0..8) |_| {
        try std.testing.expectError(error.Closed, pair.conn.receive("\x15\x03\x03\x00\x02\x01\x00"));
        try std.testing.expectError(error.Closed, pair.conn.send("x"));
        try std.testing.expect(pair.conn.request() == null);
    }
    try std.testing.expectEqual(@as(?Alert, .close_notify), pair.conn.diagnostics().alert_received);
    // A fatal alert from the server is surfaced as such.
    const fatal = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer fatal.deinit();
    _ = try fatal.service();
    try std.testing.expectError(error.PeerAlert, fatal.conn.receive("\x15\x03\x03\x00\x02\x02\x28"));
    try std.testing.expectEqual(@as(?Alert, .handshake_failure), fatal.conn.diagnostics().alert_received);
    try std.testing.expectEqual(@as(?Alert, null), fatal.conn.diagnostics().alert_sent);
}

test "C2 catalogue_finished_entropy_failure_is_never_success" {
    const P = Pair(.aes_128_gcm_sha256);
    // Entropy failing at the first request ends the connection before a hello is sent.
    {
        const pair = try P.init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        const request = pair.conn.request().?;
        try std.testing.expectError(error.EntropyUnavailable, pair.conn.provide(request.token, .entropy_failed));
        try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
        try std.testing.expect(pair.conn.info() == null);
        try std.testing.expect(pair.conn.output().len == 0 or pair.conn.output()[0] == 21);
    }
    // A stale or wrong token is refused without progress.
    {
        const pair = try P.init(std.testing.allocator, .{}, .{});
        defer pair.deinit();
        const request = pair.conn.request().?;
        var stale = request.token;
        stale.id = .fromRaw(stale.id.raw() + 1);
        try std.testing.expectError(error.StaleToken, pair.conn.provide(stale, .{ .entropy = &@as([96]u8, @splat(1)) }));
        stale = request.token;
        stale.generation = .fromRaw(stale.generation.raw() + 1);
        try std.testing.expectError(error.StaleToken, pair.conn.provide(stale, .{ .entropy = &@as([96]u8, @splat(1)) }));
        try std.testing.expectEqual(@as(usize, 0), pair.conn.output().len);
        // The wrong answer kind ends the connection: the engine asked for something else.
        try std.testing.expectError(error.UnexpectedService, pair.conn.provide(request.token, .{ .time = .fromNanoseconds(5 * std.time.ns_per_s) }));
        try std.testing.expectEqual(Connection.Phase.failed, pair.conn.phase());
    }
}

test "C2 late and repeated service answers are refused" {
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    const first = pair.conn.request().?;
    var bytes: [512]u8 = undefined;
    pair.rng.random().bytes(&bytes);
    try pair.conn.provide(first.token, .{ .entropy = bytes[0..first.service.entropy] });
    // The same token cannot answer again.
    try std.testing.expectError(error.NoRequest, pair.conn.provide(first.token, .{ .entropy = bytes[0..first.service.entropy] }));
}

test "C2 key log lines carry each traffic secret" {
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
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{ .key_log = .{ .context = &sink, .write = Sink.write } });
    defer pair.deinit();
    try pair.handshake();
    const log = sink.lines.items;
    var random_hex: [64]u8 = undefined;
    _ = std.mem.print(&random_hex, "{x}", .{&pair.peer.seen.random}) catch unreachable;
    for ([_][]const u8{ "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET", "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET" }) |label| {
        try std.testing.expect(std.mem.find(u8, log, label) != null);
    }
    var expected: [256]u8 = undefined;
    const line = try std.mem.print(&expected, "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {x}\n", .{ &random_hex, &pair.peer.client_hs });
    try std.testing.expect(std.mem.find(u8, log, line) != null);
    const server_app = try std.mem.print(&expected, "SERVER_TRAFFIC_SECRET_0 {s} {x}\n", .{ &random_hex, &pair.peer.server_app });
    try std.testing.expect(std.mem.find(u8, log, server_app) != null);
}

test "C2 handshake allocation failures leave nothing behind" {
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), allocationLifetime, .{});
}

fn allocationLifetime(gpa: std.mem.Allocator) !void {
    const pair = try Pair(.aes_128_gcm_sha256).init(gpa, .{ .group = .x25519 }, .{});
    defer pair.deinit();
    try pair.handshake();
    _ = try pair.conn.send("data");
    try pair.flush();
}

test "C2 fuzz connection random bytes after a hello never connect or surface plaintext" {
    try std.testing.fuzz({}, fuzzReceive, .{ .corpus = shakedown.corpus.entries(&.{ "\x16\x03\x03\x00\x01\x00", "\x15\x03\x03\x00\x02\x02\x28", "\x17\x03\x03\x00\x20xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "\x14\x03\x03\x00\x01\x01\x16\x03\x03\xff\xff" }) });
}

fn fuzzReceive(_: void, smith: *std.testing.Smith) !void {
    var bytes: [4096]u8 = undefined;
    const input = bytes[0..smith.slice(&bytes)];
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    _ = try pair.service();
    var fed: usize = 0;
    var steps: usize = 0;
    while (fed < input.len and steps < 10_000) : (steps += 1) {
        const n = pair.conn.receive(input[fed..]) catch break;
        fed += n;
        _ = pair.service() catch break;
        if (n == 0 and pair.conn.request() == null) break;
    }
    // Unauthenticated input never yields a connection, plaintext or negotiated parameters.
    try std.testing.expect(pair.conn.phase() != .connected);
    try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
    try std.testing.expect(pair.conn.info() == null);
}

test "C2 property: any chunking of a valid server flight yields the same connection" {
    try shakedown.check(std.testing.allocator, {}, chunking, .{ .cases = 32, .seed = 0xc2c0 });
}

fn chunking(_: void, case: *shakedown.Case) !void {
    const layout: peer_module.Layout = switch (shakedown.gen.intRange(case.source, u8, 0, 3)) {
        0 => .coalesced,
        1 => .separate,
        else => .{ .fragments = shakedown.gen.intRange(case.source, usize, 1, 300) },
    };
    const chunk = shakedown.gen.intRange(case.source, usize, 1, 700);
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .layout = layout }, .{ .chunk = chunk, .seed = shakedown.gen.int(case.source, u32) });
    defer pair.deinit();
    try pair.handshake();
    try std.testing.expect(pair.conn.info().?.peer_authenticated);
    try std.testing.expect(pair.peer.client_finished_ok);
}

const Counting = shakedown.alloc.Counting;

test "C2 connection memory: handshake peak and idle residue are measured and bounded" {
    inline for (.{ Group.x25519, Group.x25519_mlkem768 }) |group| {
        var count = Counting.init(std.testing.allocator);
        const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .group = group }, .{ .client_gpa = count.allocator() });
        defer pair.deinit();
        try pair.handshake();
        const peak = count.peak_bytes;
        // Handshake scratch is freed once established; flush then trim leaves only the struct
        // allocation of the handshake core, its exporter and state.
        try pair.flush();
        pair.conn.trim();
        const idle = count.live_bytes;
        std.debug.print("\nC2 memory group={s} handshake peak={d} bytes idle heap={d} bytes connection struct={d} bytes\n", .{ @tagName(group), peak, idle, @sizeOf(Connection) });
        try std.testing.expect(peak <= 48 * 1024);
        // Idle state is the struct plus its one small heap block: two traffic directions,
        // sequences, suite and policy references, exporter state.
        try std.testing.expect(idle + @sizeOf(Connection) <= 2048);
        // Data keeps flowing after a trim: buffers come back on demand.
        try pair.peer.send("after trim");
        var buf: [16]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "after trim", buf[0..try pair.read(&buf)]);
    }
}

test "C2 fuzz connection arbitrary encrypted server flights never authenticate" {
    try std.testing.fuzz({}, fuzzFlight, .{ .corpus = shakedown.corpus.entries(&.{
        "\x08\x00\x00\x02\x00\x00",
        "\x08\x00\x00\x02\x00\x00\x0b\x00\x00\x04\x00\x00\x00\x00",
        "\x08\x00\x00\x02\x00\x00\x0d\x00\x00\x0b\x00\x00\x08\x00\x0d\x00\x04\x00\x02\x04\x03",
        "\x08\x00\x00\x02\x00\x00\x0b\x00\x00\x0c\x00\x00\x00\x08\x00\x00\x01a\x00\x00\x0f\x00\x00\x04\x04\x03\x00\x00",
    }) });
}

fn fuzzFlight(_: void, smith: *std.testing.Smith) !void {
    var bytes: [3000]u8 = undefined;
    const flight = bytes[0..smith.slice(&bytes)];
    if (flight.len == 0) return;
    const pair = try Pair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .raw_flight = flight }, .{});
    defer pair.deinit();
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const moved = pair.step() catch break;
        if (!moved) break;
    }
    try std.testing.expect(pair.conn.phase() != .connected);
    try std.testing.expect(pair.conn.info() == null);
    try std.testing.expectEqual(@as(usize, 0), pair.conn.readable().len);
}
