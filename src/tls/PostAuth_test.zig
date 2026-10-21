//! Post-handshake client authentication (RFC 8446 section 4.6.2) between a cloak client and a
//! cloak server; the scripted peers' checks of each side are in the failure catalogue (F90).
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Connection = @import("Connection.zig");

const gpa = std.testing.allocator;

/// Asks the client for a certificate and runs both ends until the answer is checked.
fn authenticate(duo: *Duo) !u64 {
    const number = try duo.server.requestCertificate();
    try duo.pump();
    return number;
}

test "C10 post-handshake auth: a client proves its certificate after the handshake, again and again" {
    const duo = try Duo.init(gpa, .{ .client_cert = true, .client_post_auth = true, .server_post_auth = true });
    defer duo.deinit();
    try duo.handshake();
    // The handshake asked for no certificate: the client is not authenticated yet.
    try std.testing.expect(!duo.server.info().?.peer_authenticated);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 0, .authenticated = false }, duo.server.postAuthentication().?);
    const first = try authenticate(duo);
    try std.testing.expectEqual(@as(u64, 1), first);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = true }, duo.server.postAuthentication().?);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = true }, duo.client.postAuthentication().?);
    // A second request, after both ends updated their keys: the Finished is under the current
    // application secret, the third of the client's.
    try duo.client.keyUpdate(true);
    try duo.pump();
    try duo.client.keyUpdate(false);
    try duo.pump();
    const second = try authenticate(duo);
    try std.testing.expectEqual(@as(u64, 2), second);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 2, .authenticated = true }, duo.server.postAuthentication().?);
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("still here", try duo.echo(&duo.client, &duo.server, "still here", &buf));
    try std.testing.expectEqualStrings("and here", try duo.echo(&duo.server, &duo.client, "and here", &buf));
}

test "C10 post-handshake auth: a client without a certificate declines with an empty one" {
    const duo = try Duo.init(gpa, .{ .client_post_auth = true, .server_post_auth = true });
    defer duo.deinit();
    try duo.handshake();
    _ = try authenticate(duo);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = false }, duo.server.postAuthentication().?);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = false }, duo.client.postAuthentication().?);
    try std.testing.expectEqual(Connection.Phase.connected, duo.server.phase());
}

test "C10 post-handshake auth: a key held elsewhere signs the answer through a request" {
    const duo = try Duo.init(gpa, .{ .client_cert = true, .client_ed25519 = true, .client_external = true, .client_post_auth = true, .server_post_auth = true });
    defer duo.deinit();
    try duo.handshake();
    _ = try authenticate(duo);
    try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = true }, duo.server.postAuthentication().?);
}

test "F152 post-handshake auth: a verified client leaf whose key may not sign proves nothing" {
    // RFC 8446 section 4.4.2.2, as for the handshake's certificates: the verifier takes the chain
    // (`accept_any`), the engine refuses it.
    const duo = try Duo.init(gpa, .{ .client_cert = true, .client_no_signature = true, .client_post_auth = true, .server_post_auth = true, .accept_any = true });
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expectError(error.KeyUsage, authenticate(duo));
    try std.testing.expectEqual(Connection.Phase.failed, duo.server.phase());
}

test "C10 post-handshake auth: none is asked of a client that did not offer it, nor by a server that does not ask" {
    {
        const duo = try Duo.init(gpa, .{ .client_cert = true, .server_post_auth = true });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectError(error.PostAuthUnavailable, duo.server.requestCertificate());
        try std.testing.expectEqual(@as(?Connection.PostAuthOutcome, null), duo.server.postAuthentication());
    }
    {
        const duo = try Duo.init(gpa, .{ .client_cert = true, .client_post_auth = true });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectError(error.PostAuthUnavailable, duo.server.requestCertificate());
        // A client cannot ask.
        try std.testing.expectError(error.PostAuthUnavailable, duo.client.requestCertificate());
    }
    {
        // TLS 1.2 has none: the option needs TLS 1.3 at either end, and a client that offered it
        // keeps nothing when the server answers in TLS 1.2.
        try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_post_auth = true, .client_max = .tls12 }));
        try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_post_auth = true, .server_max = .tls12 }));
        const duo = try Duo.init(gpa, .{ .client_cert = true, .client_post_auth = true, .server_max = .tls12 });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(@as(?Connection.PostAuthOutcome, null), duo.client.postAuthentication());
        try std.testing.expectError(error.PostAuthUnavailable, duo.server.requestCertificate());
    }
}

test "C10 post-handshake auth: one request outstanding; the answer's verification asks the clock anew" {
    const duo = try Duo.init(gpa, .{ .client_cert = true, .client_post_auth = true, .server_post_auth = true });
    defer duo.deinit();
    try duo.handshake();
    _ = try duo.server.requestCertificate();
    try std.testing.expectError(error.RequestOutstanding, duo.server.requestCertificate());
    try duo.pump();
    // Long after the handshake the client's certificate has expired: a verification at the
    // handshake's time would pass it.
    duo.options.time += 100 * 365 * 24 * 60 * 60;
    _ = try duo.server.requestCertificate();
    try std.testing.expectError(error.VerificationRejected, duo.pump());
    try std.testing.expectEqual(Connection.Phase.failed, duo.server.phase());
}

// ---------------------------------------------------------------- F90, against scripted peers

const certificates = @import("../certificates.zig");
const Alert = @import("wire/Alert.zig").Alert;
const ServerPair = @import("../testing/ServerPair.zig").ServerPair(.aes_128_gcm_sha256);
const Pair = @import("../testing/Pair.zig").Pair(.aes_128_gcm_sha256);
const pki = @import("../testing/Peer.zig").pki;

/// A cloak server that asks for certificates after the handshake, and a scripted client that
/// offered to answer, connected.
fn askingServer() !*ServerPair {
    const pair = try ServerPair.init(gpa, .{ .post_handshake_auth = true }, .{ .post_auth = true });
    errdefer pair.deinit();
    try pair.run();
    return pair;
}

/// Sends the server's request to the scripted client.
fn ask(pair: *ServerPair) !u64 {
    const number = try pair.conn.requestCertificate();
    try pair.flush();
    return number;
}

/// Feeds the server the scripted client's records one at a time, answering requests between
/// them, and returns the first failure.
fn deliver(pair: *ServerPair) !void {
    while (pair.client.pending().len != 0) {
        const bytes = pair.client.pending();
        const record = 5 + @as(usize, std.mem.readInt(u16, bytes[3..5], .big));
        const n = pair.conn.receive(bytes[0..record]) catch |err| {
            pair.client.drained(bytes.len);
            return err;
        };
        try std.testing.expectEqual(record, n);
        pair.client.drained(record);
        _ = try pair.service();
    }
}

test "F90 catalogue_post_handshake_auth_context_and_action_gate (a server takes only the answer to its outstanding request)" {
    {
        // An answer with no request outstanding is unsolicited.
        const pair = try askingServer();
        defer pair.deinit();
        try pair.client.answer(.{});
        try std.testing.expectError(error.UnexpectedMessage, deliver(pair));
        try std.testing.expectEqual(Alert.unexpected_message, pair.conn.diagnostics().alert_sent.?);
    }
    {
        // The faithful answer counts; then one that replays it for the next request does not:
        // its context, signature and Finished are the first exchange's.
        const pair = try askingServer();
        defer pair.deinit();
        try std.testing.expectEqual(@as(u64, 1), try ask(pair));
        try pair.client.answer(.{});
        try deliver(pair);
        try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = true }, pair.conn.postAuthentication().?);
        try std.testing.expectEqual(@as(u64, 2), try ask(pair));
        try pair.client.answer(.{ .request = 0 });
        try std.testing.expectError(error.IllegalParameter, deliver(pair));
        try std.testing.expectEqual(Alert.illegal_parameter, pair.conn.diagnostics().alert_sent.?);
    }
    {
        // A context the server never sent.
        const pair = try askingServer();
        defer pair.deinit();
        _ = try ask(pair);
        try pair.client.answer(.{ .context = "\x00\x00\x00\x00\x00\x00\x00\x02" });
        try std.testing.expectError(error.IllegalParameter, deliver(pair));
    }
    {
        // A server that does not ask takes no answer, offered or not.
        const pair = try ServerPair.init(gpa, .{ .post_handshake_auth = true }, .{});
        defer pair.deinit();
        try pair.run();
        try std.testing.expectError(error.PostAuthUnavailable, pair.conn.requestCertificate());
        try pair.client.answer(.{});
        try std.testing.expectError(error.UnexpectedMessage, deliver(pair));
    }
}

test "F90 catalogue_post_handshake_auth_context_and_action_gate (nothing counts until the Finished is checked under the current keys)" {
    {
        // Certificate and CertificateVerify are in, verified and proved: still nothing counts.
        const pair = try askingServer();
        defer pair.deinit();
        _ = try ask(pair);
        try pair.client.answer(.{});
        for (0..2) |_| {
            const bytes = pair.client.pending();
            const record = 5 + @as(usize, std.mem.readInt(u16, bytes[3..5], .big));
            _ = try pair.conn.receive(bytes[0..record]);
            pair.client.drained(record);
            _ = try pair.service();
        }
        try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 0, .authenticated = false }, pair.conn.postAuthentication().?);
        try deliver(pair);
        try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = 1, .authenticated = true }, pair.conn.postAuthentication().?);
    }
    const Wrong = struct { how: @import("../testing/ClientPeer.zig").Answer, err: anyerror, alert: Alert, update: bool = false };
    const cases = [_]Wrong{
        // The handshake's Finished key, and the one a key update replaced: only the current
        // application secret's counts (RFC 8446 section 4.4).
        .{ .how = .{ .finished_key = .handshake }, .err = error.BadFinished, .alert = .decrypt_error },
        .{ .how = .{ .finished_key = .previous }, .err = error.BadFinished, .alert = .decrypt_error, .update = true },
        // A signature over a transcript without this exchange's request.
        .{ .how = .{ .sign_without_request = true }, .err = error.BadSignature, .alert = .decrypt_error },
        // Nothing may come between an answer's messages (RFC 8446 section 4.6.2).
        .{ .how = .{ .between = .application }, .err = error.UnexpectedRecord, .alert = .unexpected_message },
        .{ .how = .{ .between = .key_update }, .err = error.UnexpectedMessage, .alert = .unexpected_message },
    };
    for (cases) |case| {
        const pair = try askingServer();
        defer pair.deinit();
        if (case.update) {
            try pair.client.keyUpdate(false);
            try deliver(pair);
        }
        _ = try ask(pair);
        try pair.client.answer(case.how);
        try std.testing.expectError(case.err, deliver(pair));
        try std.testing.expectEqual(case.alert, pair.conn.diagnostics().alert_sent.?);
        try std.testing.expectEqual(@as(?Connection.PostAuthOutcome, null), pair.conn.postAuthentication());
    }
}

test "F90 catalogue_post_handshake_auth_context_and_action_gate (a client answers only what it offered, one request at a time)" {
    const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
    defer key.deinit();
    const auth = try certificates.ClientAuth.init(gpa, &.{pki.client}, key, .{});
    defer auth.deinit();
    {
        // A client that did not offer post_handshake_auth refuses a request (RFC 8446 section 4.6.2).
        const pair = try Pair.init(gpa, .{}, .{ .client_auth = auth });
        defer pair.deinit();
        try pair.handshake();
        for (pair.peer.seen.extension_ids[0..pair.peer.seen.extension_count]) |id| try std.testing.expect(id != 49);
        try pair.peer.requestCertificate("ctx");
        try std.testing.expectError(error.UnexpectedMessage, pair.step());
        try std.testing.expectEqual(Alert.unexpected_message, pair.conn.diagnostics().alert_sent.?);
    }
    {
        // A second request while the first answer is still to be written is a second one
        // outstanding.
        const pair = try Pair.init(gpa, .{}, .{ .client_auth = auth, .post_auth = true });
        defer pair.deinit();
        try pair.handshake();
        try pair.peer.requestCertificate("one");
        try pair.peer.requestCertificate("two");
        // The first waits for its signature's noise; answered, it waits for the write half.
        pair.peer.drained(try pair.conn.receive(pair.peer.pending()));
        try std.testing.expect(try pair.service());
        try std.testing.expect(pair.conn.owes());
        try std.testing.expectError(error.UnexpectedMessage, pair.conn.receive(pair.peer.pending()));
    }
}

test "C10 post-handshake auth: the scripted server checks the client's answer by its own transcript and keys" {
    const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
    defer key.deinit();
    const auth = try certificates.ClientAuth.init(gpa, &.{pki.client}, key, .{});
    defer auth.deinit();
    for ([_]?certificates.ClientAuth{ auth, null }) |offered| {
        const pair = try Pair.init(gpa, .{}, .{ .client_auth = offered, .post_auth = true });
        defer pair.deinit();
        try pair.handshake();
        var offers = false;
        for (pair.peer.seen.extension_ids[0..pair.peer.seen.extension_count]) |id| offers = offers or id == 49;
        try std.testing.expect(offers);
        // After the client's key update its Finished is under its second application secret.
        try pair.conn.keyUpdate(false);
        _ = try pair.step();
        for ([_][]const u8{ "first", "second" }, 1..) |context, n| {
            try pair.peer.requestCertificate(context);
            while (try pair.step()) {}
            try std.testing.expect(pair.peer.alert == null);
            try std.testing.expect(pair.peer.post_finished_ok);
            try std.testing.expectEqual(n, pair.peer.post_answers);
            try std.testing.expectEqual(@as(usize, @intFromBool(offered != null)), pair.peer.post_certificates);
            try std.testing.expectEqual(offered != null, pair.peer.post_signature_ok);
            try std.testing.expectEqual(Connection.PostAuthOutcome{ .generation = n, .authenticated = offered != null }, pair.conn.postAuthentication().?);
        }
    }
}

test "C10 post-handshake auth memory: what each end keeps for it, and gives back after an exchange" {
    const shakedown = @import("shakedown");
    const key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
    defer key.deinit();
    const auth = try certificates.ClientAuth.init(gpa, &.{pki.client}, key, .{});
    defer auth.deinit();
    {
        var count = shakedown.alloc.Counting.init(gpa);
        const pair = try Pair.init(gpa, .{}, .{ .client_auth = auth, .post_auth = true, .client_gpa = count.allocator() });
        defer pair.deinit();
        try pair.handshake();
        try pair.flush();
        pair.conn.trim();
        pair.conn.trimOutput();
        const idle = count.live_bytes;
        try pair.peer.requestCertificate("memory");
        while (try pair.step()) {}
        try std.testing.expect(pair.peer.post_finished_ok);
        try pair.flush();
        pair.conn.trim();
        pair.conn.trimOutput();
        std.debug.print("\nC10 memory post-handshake auth client idle heap={d} bytes, after an exchange={d} bytes, struct={d} bytes\n", .{ idle, count.live_bytes, @sizeOf(Connection) });
        // The hash state through the client's Finished is all it keeps: still within the idle
        // client's 2 KiB (designs/cloak.md 7.3), and an exchange leaves nothing behind.
        try std.testing.expect(idle + @sizeOf(Connection) <= 2048);
        try std.testing.expectEqual(idle, count.live_bytes);
    }
    {
        var count = shakedown.alloc.Counting.init(gpa);
        const pair = try ServerPair.init(gpa, .{ .post_handshake_auth = true, .client_cert = true }, .{ .post_auth = true, .conn_gpa = count.allocator() });
        defer pair.deinit();
        try pair.run();
        try pair.flush();
        pair.conn.trim();
        pair.conn.trimOutput();
        const idle = count.live_bytes;
        _ = try ask(pair);
        try pair.client.answer(.{});
        try deliver(pair);
        try pair.flush();
        pair.conn.trim();
        pair.conn.trimOutput();
        std.debug.print("C10 memory post-handshake auth server idle heap={d} bytes, after an exchange={d} bytes\n", .{ idle, count.live_bytes });
        try std.testing.expect(idle + @sizeOf(Connection) <= 2560);
        try std.testing.expectEqual(idle, count.live_bytes);
    }
}
