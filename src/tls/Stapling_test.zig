//! OCSP stapling (status_request, RFC 6066 section 8; RFC 8446 section 4.4.2.1), cloak client
//! against cloak server: the server's staple reaches the client's verifier as evidence, TLS 1.3
//! in the leaf's entry and TLS 1.2 as a CertificateStatus, asked for whenever the client checks
//! revocation; a TLS 1.2 client takes a server that answered the extension and sent no status.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const MachinePair = @import("../testing/MachinePair.zig");

const gpa = std.testing.allocator;

/// The smallest OCSPResponse: responseStatus malformedRequest, no responseBytes. The verifiers
/// here take any chain, so its content is never judged.
const staple = "\x30\x03\x0a\x01\x01";

fn digest(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}

fn versions(tls12: bool, base: Duo.Options) Duo.Options {
    var options = base;
    if (tls12) {
        options.client_max = .tls12;
        options.server_max = .tls12;
    }
    return options;
}

test "C3 OCSP stapling: the server's staple reaches the client's verifier, both versions" {
    for ([_]bool{ false, true }) |tls12| {
        const duo = try Duo.init(gpa, versions(tls12, .{ .accept_any = true, .server_ocsp = staple }));
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(digest(staple), duo.peer_ocsp[0].?);
    }
}

test "C3 OCSP stapling: a client checking no revocation asks for none, and a server without a staple sends none" {
    for ([_]bool{ false, true }) |tls12| {
        {
            const duo = try Duo.init(gpa, versions(tls12, .{ .accept_any = true, .server_ocsp = staple, .client_revocation_off = true }));
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expectEqual(null, duo.peer_ocsp[0]);
        }
        {
            const duo = try Duo.init(gpa, versions(tls12, .{ .accept_any = true }));
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expectEqual(null, duo.peer_ocsp[0]);
        }
    }
}

test "C3 OCSP stapling: a TLS 1.2 client takes a ServerKeyExchange where the CertificateStatus might have come" {
    // RFC 6066 section 8: a server that answered the extension may still send no status. The
    // server's CertificateStatus is taken out before the client sees it; the client verifies the
    // chain without a staple, takes the ServerKeyExchange, and sends its flight. (The server's
    // transcript holds the status, so the client's Finished then fails there.)
    const suite = &.{.ecdhe_ecdsa_aes_128_gcm_sha256};
    const pair = try MachinePair.init(gpa, .{ .transport = .stream, .client_suites = suite, .server_suites = suite, .server_ocsp = staple });
    defer pair.deinit();
    var removed = false;
    var rounds: usize = 0;
    while (rounds < 1000) : (rounds += 1) {
        const moved = pair.step() catch break;
        for (pair.client.inbox.items, 0..) |item, i| if (!item.ccs and item.bytes.len != 0 and item.bytes[0] == 22) {
            gpa.free(pair.client.inbox.orderedRemove(i).bytes);
            removed = true;
            break;
        };
        if (!moved) break;
    }
    try std.testing.expect(removed);
    var key_exchange = false;
    for (pair.client.sent.items) |message| key_exchange = key_exchange or message[0] == 16;
    try std.testing.expect(key_exchange);
    try std.testing.expect(!pair.server.complete);
}

test "C3 OCSP stapling: a server's staple must read as an OCSPResponse" {
    try std.testing.expectError(error.InvalidOptions, MachinePair.init(gpa, .{ .transport = .stream, .server_ocsp = "\x01\x02\x03\x04" }));
}
