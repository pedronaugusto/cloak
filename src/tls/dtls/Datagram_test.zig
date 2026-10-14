//! A cloak DTLS client against a cloak DTLS server over a simulated network.
const std = @import("std");
const Pair = @import("../../testing/DatagramPair.zig");
const suites = @import("../crypto/Suite.zig");

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
    for ([_]suites.Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256, .ecdhe_ecdsa_aes_128_ccm, .ecdhe_ecdsa_aes_256_ccm }) |suite| {
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
