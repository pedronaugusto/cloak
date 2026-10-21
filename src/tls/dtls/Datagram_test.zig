//! A cloak DTLS client against a cloak DTLS server over a simulated network.
const std = @import("std");
const Pair = @import("../../testing/DatagramPair.zig");
const suites = @import("../crypto/Suite.zig");
const Record = @import("Record.zig");

const gpa = std.testing.allocator;

fn exportersAgree(pair: *Pair) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try pair.client.dtls.exportKeyingMaterial(&a, "EXTRACTOR-dtls_srtp", "");
    try pair.server.dtls.exportKeyingMaterial(&b, "EXTRACTOR-dtls_srtp", "");
    try std.testing.expectEqualSlices(u8, &a, &b);
}

fn carriesData(pair: *Pair) !void {
    try pair.exchange(&pair.client, "ping");
    try std.testing.expectEqualSlices(u8, "ping", pair.server.received.items[pair.server.received.items.len - 1]);
    try pair.exchange(&pair.server, "pong");
    try std.testing.expectEqualSlices(u8, "pong", pair.client.received.items[pair.client.received.items.len - 1]);
}

test "C8 DTLS 1.3 completes between cloak ends for every suite and carries data" {
    for ([_]suites.Suite{ .aes_128_gcm_sha256, .aes_256_gcm_sha384, .chacha20_poly1305_sha256, .aes_128_ccm_sha256 }) |suite| {
        const pair = try Pair.init(gpa, .{ .client_suites = &.{suite}, .server_suites = &.{suite} });
        defer pair.deinit();
        try pair.run();
        const info = pair.client.dtls.info().?;
        try std.testing.expectEqual(suites.Version.tls13, info.version);
        try std.testing.expectEqual(suite, info.suite);
        try std.testing.expect(info.peer_authenticated);
        try exportersAgree(pair);
        try carriesData(pair);
    }
}

test "C8 DTLS 1.2 completes between cloak ends for every ECDSA suite and carries data" {
    for ([_]suites.Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_aes_128_ccm, .ecdhe_ecdsa_aes_256_ccm, .ecdhe_ecdsa_aes_128_ccm_8 }) |suite| {
        const pair = try Pair.init(gpa, .{ .client_suites = &.{suite}, .server_suites = &.{suite} });
        defer pair.deinit();
        try pair.run();
        const info = pair.server.dtls.info().?;
        try std.testing.expectEqual(suites.Version.tls12, info.version);
        try std.testing.expectEqual(suite, info.suite);
        try exportersAgree(pair);
        try carriesData(pair);
    }
}

test "C10 raw public keys over DTLS, both versions, and CoAP's raw-key profile: DTLS 1.2, ECDHE_ECDSA_WITH_AES_128_CCM_8, P-256, both ends by their keys" {
    const cases = [_]struct { suite: suites.Suite, version: suites.Version, max: suites.Version }{
        .{ .suite = .ecdhe_ecdsa_aes_128_ccm_8, .version = .tls12, .max = .tls12 },
        .{ .suite = .ecdhe_ecdsa_aes_128_gcm_sha256, .version = .tls12, .max = .tls12 },
        .{ .suite = .aes_128_gcm_sha256, .version = .tls13, .max = .tls13 },
    };
    for (cases) |case| for ([_]bool{ false, true }) |mutual| {
        const pair = try Pair.init(gpa, .{ .client_suites = &.{case.suite}, .server_suites = &.{case.suite}, .client_max = case.max, .groups = &.{.p256}, .raw_keys = true, .mutual = mutual });
        defer pair.deinit();
        try pair.run();
        const client = pair.client.dtls.info().?;
        try std.testing.expectEqual(case.version, client.version);
        try std.testing.expectEqual(case.suite, client.suite);
        try std.testing.expect(client.peer_authenticated);
        try std.testing.expectEqual(@as(?u16, 0), client.pin);
        const server = pair.server.dtls.info().?;
        try std.testing.expectEqual(mutual, server.peer_authenticated);
        try std.testing.expectEqual(if (mutual) @as(?u16, 0) else null, server.pin);
        try exportersAgree(pair);
        try carriesData(pair);
    };
}

test "C8 a client offering both DTLS versions meets a DTLS 1.2 server" {
    const pair = try Pair.init(gpa, .{ .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(suites.Version.tls12, pair.client.dtls.info().?.version);
    try carriesData(pair);
}

test "C8 DTLS client certificates, both versions" {
    for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .mutual = true });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.server.dtls.info().?.peer_authenticated);
        try carriesData(pair);
    }
}

test "C8 a small MTU fragments every flight, and the handshake completes" {
    for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .mtu = 256 });
        defer pair.deinit();
        try pair.run();
        try carriesData(pair);
    }
}

test "C8 lost, repeated and reordered datagrams: the handshake completes by retransmission" {
    var seed: u64 = 1;
    while (seed <= 24) : (seed += 1) {
        for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
            const pair = try Pair.init(gpa, .{ .seed = seed, .client_suites = list, .server_suites = list, .mtu = 512, .loss = 150, .duplicate = 150, .reorder = 200 });
            defer pair.deinit();
            pair.run() catch |err| {
                std.debug.print("seed {d} list {d}: {s}\n", .{ seed, list.len, @errorName(err) });
                return err;
            };
            try std.testing.expect(pair.client.dtls.phase() == .connected and pair.server.dtls.phase() == .connected);
            try exportersAgree(pair);
        }
    }
}

test "C8 a stateless cookie exchange comes first, both versions, and the handshake resumes from it" {
    for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(usize, 1), pair.cookie_answers);
        try exportersAgree(pair);
        try carriesData(pair);
    }
}

test "C8 the cookie's retry request asks for the server's preferred group when the hello lacks it" {
    // The client offers an X25519 share; the server prefers P-256, which the retry request with the
    // cookie asks for.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .groups = &.{ .x25519, .p256 }, .server_groups = &.{.p256} });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(@as(usize, 1), pair.cookie_answers);
    try std.testing.expectEqual(@import("../crypto/Group.zig").Group.p256, pair.client.dtls.info().?.group);
    try carriesData(pair);
}

test "C8 a server on a validated path and one held to three times what it received both complete" {
    for ([_]@FieldType(Pair.Options, "admission"){ .validated, .unvalidated }) |admission| {
        for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
            const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .admission = admission });
            defer pair.deinit();
            try pair.run();
            try std.testing.expectEqual(@as(usize, 0), pair.cookie_answers);
            try carriesData(pair);
        }
    }
}

test "C8 DTLS 1.3 key updates, either side and both, move both ends to the next epochs" {
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer pair.deinit();
    try pair.run();
    // An update takes over when its ACK comes, which waits its timer: run until none waits.
    pair.settle = true;
    // The client updates and asks the server to: both write epochs move from 3 to 4.
    try pair.client.dtls.keyUpdate(true);
    try pair.run();
    try carriesData(pair);
    var out: [256]u8 = undefined;
    try std.testing.expectEqual(@as(u8, 0), (try pair.client.dtls.write("x", &out))[0] & 3);
    try std.testing.expectEqual(@as(u8, 0), (try pair.server.dtls.write("x", &out))[0] & 3);
    // Five more from the server alone: its epoch reaches 9, the client's stays at 4.
    for (0..5) |_| {
        try pair.server.dtls.keyUpdate(false);
        try pair.run();
        try carriesData(pair);
    }
    try std.testing.expectEqual(@as(u8, 1), (try pair.server.dtls.write("x", &out))[0] & 3);
    try std.testing.expectEqual(@as(u8, 0), (try pair.client.dtls.write("x", &out))[0] & 3);
}

test "C8 DTLS 1.2 has no key update" {
    const pair = try Pair.init(gpa, .{ .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectError(error.UnexpectedMessage, pair.client.dtls.keyUpdate(false));
}

test "C8 a DTLS 1.3 session resumes from its ticket, and a TLS ticket never resumes over DTLS" {
    const SessionCache = @import("../resumption/SessionCache.zig");
    const TicketKeys = @import("../resumption/TicketKeys.zig");
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x5c)), .fromNanoseconds(@as(i96, Pair.pki.time) * std.time.ns_per_s));
    {
        const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .cache = &cache, .tickets = &keys });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(!pair.client.dtls.info().?.resumed);
    }
    {
        const pair = try Pair.init(gpa, .{ .seed = 99, .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .cache = &cache, .tickets = &keys });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.client.dtls.info().?.resumed);
        try std.testing.expect(pair.server.dtls.info().?.resumed);
        try std.testing.expect(pair.client.dtls.info().?.peer_authenticated);
        try carriesData(pair);
    }
}

test "C8 a server without a cookie check asks for its group with a retry request of its own" {
    for ([_]@FieldType(Pair.Options, "admission"){ .validated, .unvalidated }) |admission| {
        const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .groups = &.{ .x25519, .p384 }, .server_groups = &.{.p384}, .admission = admission });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@import("../crypto/Group.zig").Group.p384, pair.server.dtls.info().?.group);
        try carriesData(pair);
    }
}

test "C8 close_notify ends both ends and erases their keys" {
    for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        pair.client.dtls.close();
        _ = try pair.step();
        try std.testing.expectEqual(@import("Datagram.zig").Phase.closed, pair.client.dtls.phase());
        try std.testing.expectEqual(@import("Datagram.zig").Phase.closed, pair.server.dtls.phase());
        for (pair.client.dtls.writers ++ pair.client.dtls.readers ++ pair.server.dtls.writers ++ pair.server.dtls.readers) |slot| try std.testing.expect(slot == null);
        var out: [64]u8 = undefined;
        try std.testing.expectError(error.Closed, pair.client.dtls.write("late", &out));
    }
}

const Datagram = @import("Datagram.zig");
const both_versions = [_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };

/// Whether `record`, a protected record, carries `cid` where its version puts it.
fn carriesCid(record: []const u8, dtls13: bool, cid: []const u8) bool {
    if (dtls13) return record[0] & 0x10 != 0 and std.mem.eql(u8, record[1..][0..cid.len], cid);
    return record[0] == 25 and std.mem.eql(u8, record[11..][0..cid.len], cid);
}

test "C8 connection IDs, both versions: each end's protected records carry the other's, of any length" {
    for (both_versions, [_]bool{ true, false }) |list, dtls13| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_cid = "c1", .server_cid = "server-cid-8" });
        defer pair.deinit();
        try pair.run();
        const client_ids = pair.client.dtls.connectionIds().?;
        try std.testing.expectEqualSlices(u8, "c1", client_ids.receive);
        try std.testing.expectEqualSlices(u8, "server-cid-8", client_ids.send);
        const server_ids = pair.server.dtls.connectionIds().?;
        try std.testing.expectEqualSlices(u8, "server-cid-8", server_ids.receive);
        try std.testing.expectEqualSlices(u8, "c1", server_ids.send);
        var out: [256]u8 = undefined;
        const from_client = try pair.client.dtls.write("x", &out);
        try std.testing.expect(carriesCid(from_client, dtls13, "server-cid-8"));
        try std.testing.expectEqualSlices(u8, "server-cid-8", Datagram.connectionIdOf(from_client, 12).?);
        const from_server = try pair.server.dtls.write("y", &out);
        try std.testing.expect(carriesCid(from_server, dtls13, "c1"));
        try exportersAgree(pair);
        try carriesData(pair);
        // Under loss and reordering too, where the handshake's protected records carry them.
        const lossy = try Pair.init(gpa, .{ .seed = 7, .client_suites = list, .server_suites = list, .client_cid = "c1", .server_cid = "server-cid-8", .mtu = 400, .loss = 150, .reorder = 200 });
        defer lossy.deinit();
        try lossy.run();
        try carriesData(lossy);
    }
}

test "C8 connection IDs: an empty one takes none, and a server that does not answer agrees on none" {
    for (both_versions, [_]bool{ true, false }) |list, dtls13| {
        {
            // The client takes none; the server's records go without, the client's with the server's.
            const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_cid = "", .server_cid = "srv" });
            defer pair.deinit();
            try pair.run();
            try std.testing.expectEqualSlices(u8, "", pair.client.dtls.connectionIds().?.receive);
            var out: [256]u8 = undefined;
            try std.testing.expect(carriesCid(try pair.client.dtls.write("x", &out), dtls13, "srv"));
            const from_server = try pair.server.dtls.write("y", &out);
            try std.testing.expect(!carriesCid(from_server, dtls13, ""));
            try std.testing.expect(Datagram.connectionIdOf(from_server, 3) == null);
            try carriesData(pair);
        }
        {
            const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_cid = "abc" });
            defer pair.deinit();
            try pair.run();
            try std.testing.expect(pair.client.dtls.connectionIds() == null);
            try std.testing.expect(pair.server.dtls.connectionIds() == null);
            try carriesData(pair);
        }
    }
}

test "C8 a protected record without the agreed connection ID is dropped, and one with an ID none agreed" {
    for (both_versions) |list| {
        {
            const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_cid = "c", .server_cid = "srv" });
            defer pair.deinit();
            try pair.run();
            // The client's keys seal a record without the server's ID: it authenticates under the
            // plain form, but the server expects its ID and drops it (RFC 9146 section 3).
            pair.client.dtls.cids_agreed = false;
            const before = pair.server.received.items.len;
            try pair.exchange(&pair.client, "no id");
            try std.testing.expectEqual(before, pair.server.received.items.len);
            try std.testing.expectEqual(Datagram.Phase.connected, pair.server.dtls.phase());
            pair.client.dtls.cids_agreed = true;
            try carriesData(pair);
        }
        {
            const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
            defer pair.deinit();
            try pair.run();
            // None agreed: a record carrying one is rejected (RFC 9147 section 9).
            pair.client.dtls.cids_agreed = true;
            pair.client.dtls.peer_cid_len = 2;
            pair.client.dtls.peer_cid[0..2].* = .{ 1, 2 };
            const before = pair.server.received.items.len;
            try pair.exchange(&pair.client, "an id");
            try std.testing.expectEqual(before, pair.server.received.items.len);
            pair.client.dtls.cids_agreed = false;
            try carriesData(pair);
        }
    }
}

test "C8 receivedNewest: only a record newer than every one before it" {
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .client_cid = "c", .server_cid = "s" });
    defer pair.deinit();
    try pair.run();
    var first: [256]u8 = undefined;
    var second: [256]u8 = undefined;
    const a = try pair.client.dtls.write("a", &first);
    const b = try pair.client.dtls.write("b", &second);
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..b.len], b);
    try pair.server.dtls.receive(copy[0..b.len], pair.now);
    try std.testing.expect(pair.server.dtls.receivedNewest());
    // Older, though fresh to the replay window: delivered, but not newest.
    @memcpy(copy[0..a.len], a);
    try pair.server.dtls.receive(copy[0..a.len], pair.now);
    try std.testing.expectEqualSlices(u8, "a", pair.server.dtls.read().?);
    try std.testing.expect(!pair.server.dtls.receivedNewest());
    // A forged one: dropped, not newest.
    @memcpy(copy[0..b.len], b);
    copy[b.len - 1] ^= 1;
    try pair.server.dtls.receive(copy[0..b.len], pair.now);
    try std.testing.expect(!pair.server.dtls.receivedNewest());
}

test "C8 use_srtp: the server's first profile the client offered, keyed alike at both ends" {
    for (both_versions) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_srtp = &.{ .aead_aes_128_gcm, .aes128_cm_hmac_sha1_80 }, .server_srtp = &.{ .aes128_cm_hmac_sha1_32, .aes128_cm_hmac_sha1_80, .aead_aes_128_gcm } });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(Datagram.Srtp.aes128_cm_hmac_sha1_80, pair.client.dtls.info().?.srtp.?);
        try std.testing.expectEqual(Datagram.Srtp.aes128_cm_hmac_sha1_80, pair.server.dtls.info().?.srtp.?);
        var client_keys = try pair.client.dtls.srtpKeys();
        defer client_keys.deinit();
        var server_keys = try pair.server.dtls.srtpKeys();
        defer server_keys.deinit();
        try std.testing.expectEqual(@as(usize, 16), client_keys.localKey().len);
        try std.testing.expectEqual(@as(usize, 14), client_keys.localSalt().len);
        try std.testing.expectEqualSlices(u8, client_keys.localKey(), server_keys.remoteKey());
        try std.testing.expectEqualSlices(u8, client_keys.localSalt(), server_keys.remoteSalt());
        try std.testing.expectEqualSlices(u8, server_keys.localKey(), client_keys.remoteKey());
        try std.testing.expect(!std.mem.eql(u8, client_keys.localKey(), client_keys.remoteKey()));
        // RFC 5764 section 4.2's layout of the exporter's output, which takes no context: in DTLS
        // 1.2 that is not an empty one (RFC 5705 section 4).
        var material: [60]u8 = undefined;
        try pair.client.dtls.exportKeyingMaterial(&material, "EXTRACTOR-dtls_srtp", null);
        var with_empty: [60]u8 = undefined;
        try pair.client.dtls.exportKeyingMaterial(&with_empty, "EXTRACTOR-dtls_srtp", "");
        try std.testing.expect(std.mem.eql(u8, &material, &with_empty) == (pair.client.dtls.info().?.version == .tls13));
        if (pair.client.dtls.info().?.version == .tls12) {
            // RFC 5705's seed without a context: the two randoms alone.
            const secrets = pair.client.dtls.hs.state.client.tls12.?;
            var expected: [60]u8 = undefined;
            @import("../crypto/Prf.zig").prf(std.crypto.hash.sha2.Sha256, &expected, secrets.master.expose(), "EXTRACTOR-dtls_srtp", &.{ secrets.clientRandom(), secrets.serverRandom() });
            try std.testing.expectEqualSlices(u8, &expected, &material);
        }
        try std.testing.expectEqualSlices(u8, material[0..16], client_keys.localKey());
        try std.testing.expectEqualSlices(u8, material[16..32], server_keys.localKey());
        try std.testing.expectEqualSlices(u8, material[32..46], client_keys.localSalt());
        try std.testing.expectEqualSlices(u8, material[46..60], server_keys.localSalt());
    }
}

test "C8 use_srtp: none agreed when none is shared, offered or accepted" {
    const cases = [_][2][]const Datagram.Srtp{
        .{ &.{.aead_aes_256_gcm}, &.{.aead_aes_128_gcm} },
        .{ &.{}, &.{.aead_aes_128_gcm} },
        .{ &.{.aead_aes_128_gcm}, &.{} },
    };
    for (both_versions) |list| for (cases) |case| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_srtp = case[0], .server_srtp = case[1] });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.client.dtls.info().?.srtp == null);
        try std.testing.expect(pair.server.dtls.info().?.srtp == null);
        try std.testing.expectError(error.NoSrtp, pair.client.dtls.srtpKeys());
    };
}

fn writeEpoch(dtls: *Datagram, number: u64) *@import("Record.zig").Epoch {
    for (&dtls.writers) |*slot| if (slot.*) |*keys| if (keys.number == number) return keys;
    unreachable;
}

fn ticketsAndKeys() !struct { cache: @import("../resumption/SessionCache.zig"), keys: @import("../resumption/TicketKeys.zig") } {
    const SessionCache = @import("../resumption/SessionCache.zig");
    const TicketKeys = @import("../resumption/TicketKeys.zig");
    var keys = try TicketKeys.init(gpa, .{});
    errdefer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x5c)), .fromNanoseconds(@as(i96, Pair.pki.time) * std.time.ns_per_s));
    return .{ .cache = try SessionCache.init(gpa, .{}), .keys = keys };
}

test "C8 a peer's key update request does not stop a NewSessionTicket waiting for its ACK" {
    var t = try ticketsAndKeys();
    defer t.cache.deinit();
    defer t.keys.deinit();
    // The server's second datagram (its tickets and its ACK of the client's Finished) is lost.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .cache = &t.cache, .tickets = &t.keys, .drop_server = &.{2} });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(@as(usize, 0), t.cache.count());
    // While the tickets wait, the client updates and asks the server to: the server's KeyUpdate
    // is a flight of its own, and the tickets still go again (RFC 9147 section 5.8.4).
    try pair.client.dtls.keyUpdate(true);
    pair.settle = true;
    try pair.run();
    try std.testing.expectEqual(@as(usize, 2), t.cache.count());
    var out: [256]u8 = undefined;
    try std.testing.expectEqual(@as(u8, 0), (try pair.client.dtls.write("x", &out))[0] & 3);
    try std.testing.expectEqual(@as(u8, 0), (try pair.server.dtls.write("x", &out))[0] & 3);
    for (pair.server.dtls.flights) |slot| try std.testing.expect(slot == null);
    try carriesData(pair);
}

test "C8 a NewConnectionId and a key update in flight together both arrive" {
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .client_cid = "cc", .server_cid = "ss" });
    defer pair.deinit();
    try pair.run();
    // The server hands out two spares; that datagram is lost.
    try pair.server.dtls.newConnectionIds(&.{ "s1", "s2" }, .spare);
    var out: [2048]u8 = undefined;
    _ = (try pair.server.dtls.send(&out, pair.now)).?;
    try std.testing.expectError(error.ConnectionIdPending, pair.server.dtls.newConnectionIds(&.{"s3"}, .spare));
    try pair.client.dtls.keyUpdate(true);
    pair.settle = true;
    try pair.run();
    try std.testing.expectEqual(@as(usize, 2), pair.client.dtls.spareConnectionIds());
    try std.testing.expectEqual(@as(u8, 0), (try pair.server.dtls.write("x", &out))[0] & 3);
    try carriesData(pair);
}

test "C8 a server's application data does not stand for the ACK of the client's final flight" {
    // The client's final flight (its third datagram) is lost.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .drop_client = &.{3} });
    defer pair.deinit();
    try pair.flush();
    try std.testing.expectEqual(Datagram.Phase.connected, pair.client.dtls.phase());
    try std.testing.expectEqual(Datagram.Phase.handshaking, pair.server.dtls.phase());
    // The server writes under its application keys before the client's Finished arrived, as RFC
    // 9147 section 5.8.1 allows a peer to.
    var out: [256]u8 = undefined;
    const early = try writeEpoch(&pair.server.dtls, 3).seal13(.application, "half", "", &out);
    try pair.client.dtls.receive(early, pair.now);
    try std.testing.expectEqualSlices(u8, "half", pair.client.dtls.read().?);
    // The client still sends its final flight again until the server ACKs it.
    pair.settle = true;
    try pair.run();
    try std.testing.expectEqual(Datagram.Phase.connected, pair.server.dtls.phase());
    try carriesData(pair);
}

test "F144 catalogue_dtls13_application_data_under_handshake_keys (application data under the DTLS 1.3 handshake keys ends the association)" {
    // BoGo's AppDataBeforeTLS13KeyChange-DTLS: RFC 9147 section 6.1, epoch 2 carries handshake
    // messages; the runner's server sends application data under it after its Finished.
    // The client's final flight is lost, so the server still holds its handshake keys.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .drop_client = &.{3} });
    defer pair.deinit();
    try pair.flush();
    try std.testing.expectEqual(Datagram.Phase.connected, pair.client.dtls.phase());
    var out: [256]u8 = undefined;
    const wrong = try writeEpoch(&pair.server.dtls, 2).seal13(.application, "early", "", &out);
    try std.testing.expectError(error.UnexpectedRecord, pair.client.dtls.receive(wrong, pair.now));
    try std.testing.expectEqual(Datagram.Phase.failed, pair.client.dtls.phase());
    try std.testing.expectEqual(null, pair.client.dtls.read());
}

test "F146 catalogue_dtls_record_without_content_type (an authenticated record whose inner plaintext names no content type ends the association)" {
    // BoGo's TLS13-OnlyPadding-DTLS: RFC 8446 section 5.4, unexpected_message. A record failing
    // its tag is still dropped (RFC 9147 section 4.5.2).
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer pair.deinit();
    try pair.run();
    var out: [256]u8 = undefined;
    const forged = try writeEpoch(&pair.server.dtls, 3).seal13(.application, "forged", "", &out);
    forged[forged.len - 1] ^= 1;
    try pair.client.dtls.receive(forged, pair.now);
    try std.testing.expectEqual(Datagram.Phase.connected, pair.client.dtls.phase());
    const padding = try writeEpoch(&pair.server.dtls, 3).seal13(@fromBackingInt(@intCast(0)), &@as([10]u8, @splat(0)), "", &out);
    try std.testing.expectError(error.UnexpectedRecord, pair.client.dtls.receive(padding, pair.now));
    try std.testing.expectEqual(Datagram.Phase.failed, pair.client.dtls.phase());
}

test "F148 catalogue_dtls_plaintext_held_past_the_keys (a forged plaintext message buffered ahead of its turn is dropped once keys are due, and the handshake completes)" {
    // BoGo's KeyChangeWithBufferedMessages-DTLS showed a plaintext Finished, held until its turn,
    // reaching the engine after the keys and ending the association. Forged, each comes before the
    // server's flight: a DTLS 1.2 Finished (message 4, after ServerHello, Certificate,
    // ServerKeyExchange and ServerHelloDone), due after the server's ChangeCipherSpec; a DTLS 1.3
    // EncryptedExtensions (message 1), due under the handshake keys.
    for ([_]struct { list: []const suites.Suite, kind: u8, sequence: u16 }{
        .{ .list = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .kind = 20, .sequence = 4 },
        .{ .list = suites.Suite.tls13_only, .kind = 8, .sequence = 1 },
    }) |case| {
        const pair = try Pair.init(gpa, .{ .client_suites = case.list, .server_suites = case.list, .admission = .validated });
        defer pair.deinit();
        var message: [12 + 12]u8 = @splat(0);
        message[0] = case.kind;
        std.mem.writeInt(u24, message[1..4], 12, .big);
        std.mem.writeInt(u16, message[4..6], case.sequence, .big);
        std.mem.writeInt(u24, message[9..12], 12, .big);
        var out: [64]u8 = undefined;
        const forged = try Record.plaintext(.handshake, 7, &message, &out);
        try pair.client.inbox.append(gpa, .{ .bytes = try gpa.dupe(u8, forged) });
        try pair.run();
        try carriesData(pair);
    }
}

test "F149 catalogue_dtls13_handshake_alert_epoch (a DTLS 1.3 handshake that fails before it completes sends its alert under the handshake keys)" {
    // BoGo's DTLS13-SendExtraFinished-Packed: the server's flight ends with a second Finished in
    // the same datagram. The client has made its application keys but sent nothing under them, so
    // the server reads none: the alert goes under the handshake epoch, which it reads.
    var sent: std.ArrayList([]u8) = .empty;
    defer {
        for (sent.items) |datagram| gpa.free(datagram);
        sent.deinit(gpa);
    }
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .admission = .validated, .drop_server = &.{ 1, 2, 3, 4, 5, 6 }, .server_sent = &sent });
    defer pair.deinit();
    try pair.flush();
    const burst = for (sent.items, 0..) |datagram, i| {
        if (datagram.len == 0) break i;
    } else return error.NoFlight;
    try std.testing.expect(burst >= 1 and burst <= 6);
    // ServerHello, EncryptedExtensions, Certificate, CertificateVerify, Finished: the extra
    // Finished is message 5.
    var extra: [12 + 32]u8 = @splat(0);
    extra[0] = 20;
    std.mem.writeInt(u24, extra[1..4], 32, .big);
    std.mem.writeInt(u16, extra[4..6], 5, .big);
    std.mem.writeInt(u24, extra[9..12], 32, .big);
    var buffer: [4096]u8 = undefined;
    for (sent.items[0 .. burst - 1]) |datagram| {
        @memcpy(buffer[0..datagram.len], datagram);
        try pair.client.dtls.receive(buffer[0..datagram.len], pair.now);
    }
    const last = sent.items[burst - 1];
    @memcpy(buffer[0..last.len], last);
    const record = try writeEpoch(&pair.server.dtls, 2).seal13(.handshake, &extra, "", buffer[last.len..]);
    try pair.client.dtls.receive(buffer[0 .. last.len + record.len], pair.now);
    // The Finished messages wait for the chain's verification.
    try std.testing.expectError(error.UnexpectedMessage, pair.serveClient());
    var out: [1500]u8 = undefined;
    const alert = (try pair.client.dtls.send(&out, pair.now)).?;
    try std.testing.expectEqual(@as(u8, 2), alert[0] & 3);
    try std.testing.expectError(error.PeerAlert, pair.server.dtls.receive(alert, pair.now));
    try std.testing.expectEqual(Datagram.Phase.failed, pair.server.dtls.phase());
    try std.testing.expectEqual(@as(?@TypeOf(pair.server.dtls.alerts().received.?), .unexpected_message), pair.server.dtls.alerts().received);

    // Once the Finished went out, the alert goes under the application keys.
    const done = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer done.deinit();
    try done.run();
    const padding = try writeEpoch(&done.server.dtls, 3).seal13(@fromBackingInt(@intCast(0)), &@as([10]u8, @splat(0)), "", &buffer);
    try std.testing.expectError(error.UnexpectedRecord, done.client.dtls.receive(padding, done.now));
    const late = (try done.client.dtls.send(&out, done.now)).?;
    try std.testing.expectEqual(@as(u8, 3), late[0] & 3);
    try std.testing.expectError(error.PeerAlert, done.server.dtls.receive(late, done.now));
}

test "C8 records under keys not held yet are answered by an ACK of nothing, and the flight goes again at once" {
    // A small MTU spreads the server's flight over datagrams; the first, with the ServerHello, is
    // lost, so what follows is under keys the client does not have.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .mtu = 300, .drop_server = &.{1} });
    defer pair.deinit();
    const start = pair.now;
    try pair.run();
    try std.testing.expect(pair.client.dtls.phase() == .connected and pair.server.dtls.phase() == .connected);
    // No timer had to fire: the client's empty ACK, in the clear, brought the flight back.
    try std.testing.expectEqual(start.nanoseconds, pair.now.nanoseconds);
    try carriesData(pair);
}

test "C8 setTiming rescales the running retransmission timer" {
    // A caller tuning the timer to its path (RFC 9147 section 5.8.2 leaves the timer values to the
    // implementation): a running wait becomes the new first wait times the doublings so far,
    // counted from when it started; a wait already past makes the flight due at once.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .admission = .validated });
    defer pair.deinit();
    const client = &pair.client.dtls;
    const ms: i96 = std.time.ns_per_ms;
    const at = struct {
        fn at(from: std.Io.Timestamp, ns: i96) std.Io.Timestamp {
            return .{ .nanoseconds = from.nanoseconds + ns };
        }
    }.at;
    var out: [2048]u8 = undefined;
    const t0 = pair.now;
    try pair.serveClient();
    while (try client.send(&out, t0)) |_| {}
    try std.testing.expectEqual(at(t0, 1000 * ms), client.timeout().?);
    try client.setTiming(.{ .initial = .fromMilliseconds(500) });
    try std.testing.expectEqual(at(t0, 500 * ms), client.timeout().?);
    // It fires there, and the next wait doubles from the new first one.
    const t1 = at(t0, 500 * ms);
    try std.testing.expect(try client.send(&out, t1) != null);
    while (try client.send(&out, t1)) |_| {}
    try std.testing.expectEqual(at(t1, 1000 * ms), client.timeout().?);
    // Back to a second with one doubling done: two seconds from the retransmission.
    try client.setTiming(.{});
    try std.testing.expectEqual(at(t1, 2000 * ms), client.timeout().?);
    // Shortened below what has passed: due at once.
    const t2 = at(t1, 1000 * ms);
    try client.setTiming(.{ .initial = .fromMilliseconds(250) });
    try std.testing.expectEqual(at(t1, 500 * ms), client.timeout().?);
    try std.testing.expect(try client.send(&out, t2) != null);
    // Values the timer cannot run on are refused, and change nothing.
    try std.testing.expectError(error.InvalidOptions, client.setTiming(.{ .initial = .fromNanoseconds(0) }));
    try std.testing.expectError(error.InvalidOptions, client.setTiming(.{ .initial = .fromSeconds(2), .max = .fromSeconds(1) }));
    try std.testing.expectEqual(std.Io.Duration.fromMilliseconds(250), client.timing.initial);
}

test "C8 setTiming rescales a waiting ACK" {
    // An ACK waits a quarter of the retransmission wait: a new first wait moves it with the rest
    // (BoGo's DTLS-Retransmit-PartialProgress-Server-SetTimeout).
    var t = try ticketsAndKeys();
    defer t.cache.deinit();
    defer t.keys.deinit();
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .cache = &t.cache, .tickets = &t.keys });
    defer pair.deinit();
    try pair.run();
    // The client's only timer is the tickets' ACK, a quarter second after they came.
    const due = pair.client.dtls.timeout().?;
    try std.testing.expectEqual(@as(i96, std.time.ns_per_s / 4), due.nanoseconds - pair.now.nanoseconds);
    try pair.client.dtls.setTiming(.{ .initial = .fromMilliseconds(200) });
    try std.testing.expectEqual(@as(i96, 50 * std.time.ns_per_ms), pair.client.dtls.timeout().?.nanoseconds - pair.now.nanoseconds);
}

test "C8 an ACK in the clear makes a flight go again at most once a timer period" {
    // The server's flight never reaches the client.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .drop_server = &.{ 1, 2 } });
    defer pair.deinit();
    // Run the server's flight out, then forge empty ACKs: one retransmission, not one each.
    try pair.flush();
    var out: [2048]u8 = undefined;
    var datagrams: [5]usize = @splat(0);
    for (&datagrams) |*count| {
        var ack = [_]u8{ 26, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 9, 0, 2, 0, 0 };
        try pair.server.dtls.receive(&ack, pair.now);
        while (try pair.server.dtls.send(&out, pair.now)) |_| count.* += 1;
    }
    try std.testing.expect(datagrams[0] != 0);
    for (datagrams[1..]) |count| try std.testing.expectEqual(@as(usize, 0), count);
}

test "C8 an ACK in the clear names plaintext records only" {
    // A retry request forces a plaintext flight of one record: the client's ACK of it in the
    // clear stops its retransmission (BoGo's DTLS-Retransmit-Server-ACK* scripts ACK a retry
    // request so).
    const retry = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .groups = &.{ .x25519, .p384 }, .server_groups = &.{.p384}, .admission = .validated, .drop_server = &.{1} });
    defer retry.deinit();
    try retry.flush();
    try std.testing.expect(retry.server.dtls.timeout() != null);
    var out: [2048]u8 = undefined;
    var plain = [_]u8{ 26, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 10, 0, 18, 0, 16 } ++ @as([16]u8, @splat(0));
    try retry.server.dtls.receive(&plain, retry.now);
    try std.testing.expectEqual(null, try retry.server.dtls.send(&out, retry.now));
    try std.testing.expectEqual(null, retry.server.dtls.timeout());

    // Before the version is settled an ACK in the clear counts for nothing: the client's hello
    // goes again on its timer.
    const early = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .admission = .validated, .drop_client = &.{1} });
    defer early.deinit();
    try early.flush();
    var hello_ack = [_]u8{ 26, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 18, 0, 16 } ++ @as([16]u8, @splat(0));
    try early.client.dtls.receive(&hello_ack, early.now);
    const hello = (try early.client.dtls.send(&out, early.client.dtls.timeout().?)).?;
    try std.testing.expectEqual(@as(u8, 1), hello[13]);

    // The server's main flight is lost: an ACK in the clear naming every record of it, those
    // under the handshake keys too, covers the ServerHello alone, and the rest goes again.
    const full = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .admission = .validated, .drop_server = &.{ 1, 2, 3, 4, 5, 6 } });
    defer full.deinit();
    try full.flush();
    var ack: [13 + 2 + 16 * 17]u8 = undefined;
    @memcpy(ack[0..11], &[_]u8{ 26, 0xfe, 0xfd, 0, 0, 0, 0, 0, 0, 0, 11 });
    std.mem.writeInt(u16, ack[11..13], 2 + 16 * 17, .big);
    std.mem.writeInt(u16, ack[13..15], 16 * 17, .big);
    for (0..17) |i| {
        const epoch: u64 = if (i == 0) 0 else 2;
        const sequence: u64 = if (i == 0) 0 else i - 1;
        std.mem.writeInt(u64, ack[15 + 16 * i ..][0..8], epoch, .big);
        std.mem.writeInt(u64, ack[15 + 16 * i + 8 ..][0..8], sequence, .big);
    }
    try full.server.dtls.receive(&ack, full.now);
    const again = (try full.server.dtls.send(&out, full.now)).?;
    // The resent records are protected ones: the ServerHello is not among them.
    try std.testing.expect(again[0] & 0xe0 == 0x20);
    try std.testing.expect(full.server.dtls.timeout() != null);
}

test "C8 a retransmission leaves out the fragments an ACK covered" {
    // RFC 9147 section 7.2. The server's flight spreads over small datagrams and its third is
    // lost; the client ACKs the rest, and what goes again is about the lost datagram's bytes, not
    // the messages it cut whole.
    var sent: std.ArrayList([]u8) = .empty;
    defer {
        for (sent.items) |datagram| gpa.free(datagram);
        sent.deinit(gpa);
    }
    // X25519 alone keeps the ServerHello in the first datagram.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .groups = &.{.x25519}, .admission = .validated, .mtu = 256, .drop_server = &.{3}, .server_sent = &sent });
    defer pair.deinit();
    try pair.run();
    const first = for (sent.items, 0..) |datagram, i| {
        if (datagram.len == 0) break i;
    } else return error.NoFlight;
    try std.testing.expect(first > 4);
    const lost = sent.items[2].len;
    var again: usize = 0;
    for (sent.items[first + 1 ..]) |datagram| {
        if (datagram.len == 0) break;
        again += datagram.len;
    }
    try std.testing.expect(again != 0);
    try std.testing.expect(again <= lost + 64);
    try carriesData(pair);
}

test "C8 part of the peer's next flight acknowledges ours in DTLS 1.3, and not in DTLS 1.2" {
    // RFC 9147 section 7.1. After a retry request DTLS 1.3 is settled: X25519MLKEM768's share
    // spreads the ServerHello over small datagrams and all but its first are lost. The client's
    // hello goes no more; at a quarter of the wait an ACK in the clear names what came.
    const settled = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .groups = &.{.x25519_mlkem768}, .admission = .validated, .mtu = 256, .drop_server = &.{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 } });
    defer settled.deinit();
    try settled.flush();
    var out: [2048]u8 = undefined;
    const ack = (try settled.client.dtls.send(&out, settled.client.dtls.timeout().?)).?;
    try std.testing.expectEqual(@as(u8, 26), ack[0]);
    try std.testing.expectEqual(@as(usize, 13 + 2 + 16), ack.len);
    try std.testing.expectEqual(null, settled.client.dtls.timeout());

    // DTLS 1.2: the ServerHello and part of the certificate came; the hello goes again on its
    // timer until the answer is whole (RFC 6347 section 4.2.4).
    const open = try Pair.init(gpa, .{ .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .admission = .validated, .mtu = 256, .drop_server = &.{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 } });
    defer open.deinit();
    try open.flush();
    try std.testing.expect(open.client.dtls.answered);
    const again = (try open.client.dtls.send(&out, open.client.dtls.timeout().?)).?;
    // A plaintext ClientHello fragment.
    try std.testing.expectEqual(@as(u8, 22), again[0]);
    try std.testing.expectEqual(@as(u8, 1), again[13]);
}

test "F150 catalogue_dtls13_message_after_key_update (a handshake message after the peer's KeyUpdate under the epoch it retired ends the association)" {
    // BoGo's KeyUpdate-ExtraMessage-DTLS and -Buffered: RFC 8446 section 5.1, handshake messages
    // do not span key changes. Each order: the extra message after the KeyUpdate, and before it.
    for ([_]bool{ false, true }) |extra_first| {
        const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
        defer pair.deinit();
        try pair.run();
        const next = pair.server.dtls.send_sequence;
        var update: [13]u8 = .{ 24, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1 };
        std.mem.writeInt(u16, update[4..6], next, .big);
        var extra = update;
        std.mem.writeInt(u16, extra[4..6], next + 1, .big);
        var buffer: [256]u8 = undefined;
        const keys = writeEpoch(&pair.server.dtls, 3);
        const first = try keys.seal13(.handshake, if (extra_first) &extra else &update, "", &buffer);
        const second = try keys.seal13(.handshake, if (extra_first) &update else &extra, "", buffer[first.len..]);
        try std.testing.expectError(error.RecordAlignment, pair.client.dtls.receive(buffer[0 .. first.len + second.len], pair.now));
        try std.testing.expectEqual(Datagram.Phase.failed, pair.client.dtls.phase());
    }
}

test "C8 after the peer's key update its old epoch is still read for four minutes" {
    // RFC 9147 section 8: records of an older epoch SHOULD still be processed; a reordering path
    // brings them after the first under the new keys.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer pair.deinit();
    try pair.run();
    var late: [256]u8 = undefined;
    const old = try writeEpoch(&pair.server.dtls, 3).seal13(.application, "late", "", &late);
    try pair.server.dtls.keyUpdate(false);
    pair.settle = true;
    try pair.run();
    try carriesData(pair);
    var copy: [256]u8 = undefined;
    @memcpy(copy[0..old.len], old);
    try pair.client.dtls.receive(copy[0..old.len], pair.now);
    try std.testing.expectEqualSlices(u8, "late", pair.client.dtls.read().?);
    // Four minutes on, the old keys are gone.
    var later: [256]u8 = undefined;
    const gone = try writeEpoch(&pair.server.dtls, 3).seal13(.application, "gone", "", &later);
    try pair.client.dtls.receive(gone, .{ .nanoseconds = pair.now.nanoseconds + 4 * 60 * std.time.ns_per_s });
    try std.testing.expectEqual(null, pair.client.dtls.read());
}

test "F151 catalogue_dtls13_ack_skips_dropped_fragments (a record with a fragment dropped is not ACKed; the ACK list outlives an ACK)" {
    // BoGo's DTLS-Retransmit-Server-DoNotACKDiscardedFragments: RFC 9147 section 7, records
    // holding fragments neither processed nor buffered MUST NOT be acknowledged (a deadlock
    // otherwise). One record carries a fragment of the next message and one too far ahead to
    // hold; another carries the first alone.
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only });
    defer pair.deinit();
    try pair.run();
    const next = pair.server.dtls.send_sequence;
    var near: [12]u8 = .{ 24, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u16, near[4..6], next, .big);
    var far = near;
    std.mem.writeInt(u16, far[4..6], next +% 1000, .big);
    const keys = writeEpoch(&pair.server.dtls, 3);
    var buffer: [256]u8 = undefined;
    const mixed_number = keys.sequence;
    const mixed = try keys.seal13(.handshake, &(near ++ far), "", &buffer);
    try pair.client.dtls.receive(mixed, pair.now);
    const alone_number = keys.sequence;
    const alone = try keys.seal13(.handshake, &near, "", &buffer);
    try pair.client.dtls.receive(alone, pair.now);
    const listed = struct {
        fn has(dtls: *const Datagram, number: u64) bool {
            for (dtls.acks.items) |held| if (held[0] == 3 and held[1] == number) return true;
            return false;
        }
    }.has;
    try std.testing.expect(!listed(&pair.client.dtls, mixed_number));
    try std.testing.expect(listed(&pair.client.dtls, alone_number));
    // The ACK goes on its timer, and the record stays listed for the next.
    var out: [2048]u8 = undefined;
    const ack = (try pair.client.dtls.send(&out, pair.client.dtls.timeout().?)).?;
    try std.testing.expect(ack[0] & 0xe0 == 0x20);
    try std.testing.expect(listed(&pair.client.dtls, alone_number));
}

test "F160 catalogue_dtls_authenticated_fragment_refused (a malformed or oversized handshake fragment under keys ends the association)" {
    // BoGo's LargeMessage-Reject-DTLS: a DTLS 1.3 Certificate past the client's message limit,
    // under the handshake keys, was dropped as a forged plaintext one is, and the handshake
    // waited out its timer. Under keys the peer sent it: refused as on a stream. Each case once
    // per version, after the handshake: a fragment header cut short, a fragment past its record,
    // a fragment past its message, a message past the limit.
    const Case = struct { body: []const u8, err: anyerror };
    const cases = [_]Case{
        .{ .body = &.{ 4, 0, 0, 12, 0 }, .err = error.DecodeError },
        .{ .body = &.{ 4, 0, 0, 12, 0, 0, 0, 0, 0, 0, 0, 50, 1, 2, 3 }, .err = error.DecodeError },
        .{ .body = &.{ 4, 0, 0, 12, 0, 0, 0, 0, 10, 0, 0, 5, 1, 2, 3, 4, 5 }, .err = error.DecodeError },
        .{ .body = &.{ 4, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3, 1, 2, 3 }, .err = error.HandshakeLimit },
    };
    for ([_]bool{ true, false }) |tls13| for (cases) |case| {
        const list = if (tls13) suites.Suite.tls13_only else &[_]suites.Suite{.ecdhe_ecdsa_aes_128_gcm_sha256};
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        var body: [32]u8 = undefined;
        @memcpy(body[0..case.body.len], case.body);
        // The message the client expects next, so no rule about order drops it first.
        if (case.body.len >= 6) std.mem.writeInt(u16, body[4..6], pair.client.dtls.receive_sequence, .big);
        var out: [256]u8 = undefined;
        const record = if (tls13)
            try writeEpoch(&pair.server.dtls, 3).seal13(.handshake, body[0..case.body.len], "", &out)
        else
            try writeEpoch(&pair.server.dtls, 1).seal12(.handshake, body[0..case.body.len], "", &out);
        try std.testing.expectError(case.err, pair.client.dtls.receive(record, pair.now));
        try std.testing.expectEqual(Datagram.Phase.failed, pair.client.dtls.phase());
    };
}

test "C8 DTLS 1.3 connection IDs on request, spare and immediate" {
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .client_cid = "client", .server_cid = "server" });
    defer pair.deinit();
    try pair.run();
    pair.settle = true;
    try pair.client.dtls.requestConnectionIds(2);
    try std.testing.expectError(error.ConnectionIdPending, pair.client.dtls.requestConnectionIds(1));
    try pair.run();
    try std.testing.expectEqual(@as(u8, 2), pair.server.dtls.connectionIdsRequested());
    try std.testing.expectError(error.ConnectionIdPending, pair.client.dtls.requestConnectionIds(1));
    // Those handed out have the length of the server's own.
    try std.testing.expectError(error.NoConnectionIds, pair.server.dtls.newConnectionIds(&.{"short"}, .spare));
    try pair.server.dtls.newConnectionIds(&.{ "spare1", "spare2" }, .spare);
    try pair.run();
    try std.testing.expectEqual(@as(u8, 0), pair.server.dtls.connectionIdsRequested());
    try std.testing.expectEqual(@as(usize, 2), pair.client.dtls.spareConnectionIds());
    var out: [256]u8 = undefined;
    try std.testing.expect(carriesCid(try pair.client.dtls.write("x", &out), true, "server"));
    // On a new path, a spare.
    try std.testing.expect(pair.client.dtls.useSpareConnectionId());
    try std.testing.expect(carriesCid(try pair.client.dtls.write("x", &out), true, "spare1"));
    try carriesData(pair);
    // Immediate: the next record carries the new one.
    try pair.server.dtls.newConnectionIds(&.{"newone"}, .immediate);
    try pair.run();
    try std.testing.expect(carriesCid(try pair.client.dtls.write("x", &out), true, "newone"));
    try std.testing.expectEqual(@as(usize, 1), pair.client.dtls.spareConnectionIds());
    try carriesData(pair);
    // The client may ask again now its request was answered.
    try pair.client.dtls.requestConnectionIds(1);
}

test "C8 connection ID messages: only after an agreement that allows them, and a request at a time" {
    {
        const pair = try Pair.init(gpa, .{ .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .client_cid = "c", .server_cid = "s" });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectError(error.UnexpectedMessage, pair.client.dtls.requestConnectionIds(1));
        try std.testing.expectError(error.UnexpectedMessage, pair.server.dtls.newConnectionIds(&.{"t"}, .spare));
    }
    {
        // The server takes no connection ID: the client sends with an empty one, so it may not ask
        // for more, and the server has none to hand out.
        const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .client_cid = "c", .server_cid = "" });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectError(error.NoConnectionIds, pair.client.dtls.requestConnectionIds(1));
        try std.testing.expectError(error.NoConnectionIds, pair.server.dtls.newConnectionIds(&.{""}, .spare));
        // A server that sends one anyway breaks the rule: unexpected_message (RFC 9147 section 9).
        pair.server.dtls.own_cid_len = 1;
        try pair.server.dtls.newConnectionIds(&.{"z"}, .spare);
        try std.testing.expectError(error.UnexpectedMessage, pair.run());
        try std.testing.expectEqual(@import("../wire/Alert.zig").Alert.unexpected_message, pair.client.dtls.fatal_due.?);
    }
    {
        // A second request while the first is unanswered ends the association.
        const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .client_cid = "c", .server_cid = "s" });
        defer pair.deinit();
        try pair.run();
        pair.settle = true;
        try pair.client.dtls.requestConnectionIds(3);
        try pair.run();
        pair.client.dtls.cid_request_open = false;
        try pair.client.dtls.requestConnectionIds(3);
        try std.testing.expectError(error.TooManyConnectionIdsRequested, pair.run());
        try std.testing.expectEqual(@import("../wire/Alert.zig").Alert.too_many_cids_requested, pair.server.dtls.fatal_due.?);
    }
}

test "C8 a flight puts each epoch's messages in one record per datagram, and fills each datagram it leaves" {
    // RFC 9147 section 5.5: a record may carry several handshake messages; one DTLS 1.3 record
    // per epoch and datagram spends one header and tag, and a datagram is left only when no byte
    // more of the next message fits (BoGo holds a shim to thirteen bytes: a fragment header and
    // one). Plaintext and DTLS 1.2 records keep one message each, as tinydtls reads them.
    // MTUs from the least an association takes (256) up, so tails of every length come up.
    var mtu: u16 = 256;
    while (mtu <= 1200) : (mtu += if (mtu < 700) 7 else 100) {
        for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |offer| {
            var sent: std.ArrayList([]u8) = .empty;
            defer {
                for (sent.items) |datagram| gpa.free(datagram);
                sent.deinit(gpa);
            }
            const pair = try Pair.init(gpa, .{ .client_suites = offer, .mtu = mtu, .server_sent = &sent });
            defer pair.deinit();
            try pair.run();
            // The server's first flight is its first burst, up to the empty mark.
            const burst = for (sent.items, 0..) |datagram, i| {
                if (datagram.len == 0) break i;
            } else return error.NoFlight;
            for (sent.items[0..burst], 0..) |datagram, i| {
                var protected: usize = 0;
                var rest = datagram;
                while (Record.split(rest, 0)) |next| : (rest = next.rest) {
                    switch (next.kind) {
                        .unified => protected += 1,
                        .classic => |header| if (header.epoch != 0) {
                            protected += 1;
                        } else if (next.record[0] == 22) {
                            // A plaintext record carries one fragment (tinydtls reads no more).
                            const body = next.record[13..];
                            try std.testing.expectEqual(body.len, 12 + @as(usize, std.mem.readInt(u24, body[9..12], .big)));
                        },
                    }
                }
                try std.testing.expect(protected <= 1);
                // Every datagram but the flight's last is full: no fragment header and byte more
                // fit its record (DTLS 1.3), or no record header, fragment header and byte more
                // (one message a record).
                const room: usize = if (offer[0].tls13() != null) 13 else 13 + 12;
                if (i + 1 < burst) try std.testing.expect(datagram.len + room >= mtu);
            }
            try std.testing.expect(burst >= 2 or mtu >= 1000);
        }
    }
}

test "C8 after the handshake the ACK goes first, then the post-handshake flights in the order they were made, the tickets in one record" {
    // Each ticket is a flight of its own, in whichever slot is free; they go in creation order,
    // and in one record, as fragments of one epoch do.
    var t = try ticketsAndKeys();
    defer t.cache.deinit();
    defer t.keys.deinit();
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .cache = &t.cache, .tickets = &t.keys });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(@as(usize, 2), t.cache.count());
    const server = &pair.server.dtls;
    var tickets: usize = 0;
    var record: ?u64 = null;
    var last_generation: ?u32 = null;
    for (server.sent_records[0..server.sent_records_len]) |sent| {
        if (sent.epoch != 3) continue;
        tickets += 1;
        if (record) |number| try std.testing.expectEqual(number, sent.sequence) else record = sent.sequence;
        if (last_generation) |before| try std.testing.expect(sent.generation > before);
        last_generation = sent.generation;
    }
    try std.testing.expectEqual(@as(usize, 2), tickets);
    // The ACK of the client's Finished went first under the application keys, record 0: a peer
    // waiting on it reads it before the tickets (BoGo's runner refused tickets ahead of it).
    try std.testing.expectEqual(@as(?u64, 1), record);
}

test "C8 post-handshake messages are ACKed a quarter of the first retransmission wait later, together" {
    // RFC 9147 section 7.1 leaves the delay to the implementation; BoringSSL's is a quarter of
    // its first retransmission wait, and its test runner refuses an ACK it is not waiting for.
    var t = try ticketsAndKeys();
    defer t.cache.deinit();
    defer t.keys.deinit();
    const pair = try Pair.init(gpa, .{ .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .cache = &t.cache, .tickets = &t.keys });
    defer pair.deinit();
    try pair.run();
    // Both tickets arrived, and the client's only timer is their ACK's.
    try std.testing.expectEqual(@as(usize, 2), t.cache.count());
    try std.testing.expectEqual(@as(i96, std.time.ns_per_s / 4), pair.client.dtls.timeout().?.nanoseconds - pair.now.nanoseconds);
    var out: [2048]u8 = undefined;
    try std.testing.expect(try pair.client.dtls.send(&out, pair.now) == null);
    // Once it passes, one ACK covers both, and the server holds no flight.
    pair.settle = true;
    try pair.run();
    for (pair.server.dtls.flights) |slot| try std.testing.expect(slot == null);
    try std.testing.expect(pair.client.dtls.timeout() == null);
}

test "C8 a repeated flight is answered once, at its last message, however its records come" {
    // A DTLS 1.2 server's final flight has no timer: it goes again when the client's final flight
    // does (RFC 6347 section 4.2.4). It went again for each repeated message, so a flight of
    // several asked for several answers (BoGo's DTLS-Retransmit-Client-Basic-TLS12 counts them).
    // The server's final flight, its second datagram, is lost.
    const pair = try Pair.init(gpa, .{ .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .server_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256}, .drop_server = &.{2} });
    defer pair.deinit();
    try pair.flush();
    try std.testing.expect(pair.server.dtls.phase() == .connected and pair.client.dtls.phase() == .handshaking);
    // The client's timer sends its final flight again; its records reach the server one per
    // datagram, as a peer may send them.
    const later = pair.client.dtls.timeout().?;
    var out: [2048]u8 = undefined;
    const again = (try pair.client.dtls.send(&out, later)).?;
    var records: usize = 0;
    var answers: usize = 0;
    var rest = again;
    while (Record.split(rest, 0)) |next| : (rest = next.rest) {
        records += 1;
        var copy: [2048]u8 = undefined;
        @memcpy(copy[0..next.record.len], next.record);
        try pair.server.dtls.receive(copy[0..next.record.len], later);
        var answer: [2048]u8 = undefined;
        while (try pair.server.dtls.send(&answer, later)) |_| answers += 1;
    }
    try std.testing.expect(records >= 3);
    try std.testing.expectEqual(@as(usize, 1), answers);
}
