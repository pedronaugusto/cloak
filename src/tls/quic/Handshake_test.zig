const std = @import("std");
const shakedown = @import("shakedown");
const Handshake = @import("Handshake.zig");
const Suite = @import("../crypto/Suite.zig").Suite;
const Group = @import("../crypto/Group.zig").Group;
const QuicPair = @import("../../testing/QuicPair.zig").QuicPair;
const peer_module = @import("../../testing/Peer.zig");
const Alert = @import("../wire/Alert.zig").Alert;

fn retrying(group: Group) ?Group {
    return if (group == .p256 or group == .p384) group else null;
}

test "C2 quic handshake completes for every suite and group and hands off matching secrets" {
    inline for (std.enums.values(Suite)) |suite| {
        inline for (.{ Group.x25519, Group.x25519_mlkem768, Group.p256 }) |group| {
            const P = QuicPair(suite);
            const pair = try P.init(std.testing.allocator, .{ .group = group, .retry = retrying(group), .alpn = "h3" }, .{});
            defer pair.deinit();
            try pair.run();
            try std.testing.expect(pair.authenticated);
            // Four traffic secrets, each once, matching the peer's independent derivation.
            try std.testing.expectEqual(@as(usize, 4), pair.secrets.items.len);
            const s = pair.secrets.items;
            try std.testing.expectEqual(Handshake.Level.handshake, s[0].level);
            try std.testing.expectEqual(Handshake.Direction.read, s[0].direction);
            try std.testing.expectEqualSlices(u8, &pair.peer.server_hs, s[0].bytes[0..s[0].len]);
            try std.testing.expectEqual(Handshake.Direction.write, s[1].direction);
            try std.testing.expectEqualSlices(u8, &pair.peer.client_hs, s[1].bytes[0..s[1].len]);
            try std.testing.expectEqual(Handshake.Level.application, s[2].level);
            try std.testing.expectEqualSlices(u8, &pair.peer.server_app, s[2].bytes[0..s[2].len]);
            try std.testing.expectEqualSlices(u8, &pair.peer.client_app, s[3].bytes[0..s[3].len]);
            // The server's transport parameters arrived before authentication completed.
            try std.testing.expectEqualSlices(u8, "server-params", pair.peer_parameters.items);
            try std.testing.expectEqualSlices(u8, "server-params", pair.hs.info().?.peer_parameters);
            // The first flight carries our parameters and no legacy session id or CCS.
            try std.testing.expectEqualSlices(u8, "client-params", pair.peer.seen.quic_parameters[0..pair.peer.seen.quic_parameters_len]);
            try std.testing.expectEqual(@as(usize, 0), pair.peer.seen.session_id_len);
            try std.testing.expect(pair.peer.seen.versions_only_13);
            try std.testing.expect(pair.peer.seen.offeredAlpn("h3"));
            // The exporter matches the peer's.
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            try pair.hs.exportKeyingMaterial(&ours, "EXPERIMENTAL quic", "");
            try pair.peer.exportKey(&theirs, "EXPERIMENTAL quic", "");
            try std.testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "C2 quic event order installs a level before data is sent at it" {
    const pair = try QuicPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .alpn = "h3" }, .{});
    defer pair.deinit();
    try pair.run();
    // d: ClientHello; r,w: handshake secrets; p: parameters; r: app read; d: Finished; w: app write; a.
    try std.testing.expectEqualSlices(u8, "drwprdwa", pair.events.items);
}

test "C2 catalogue_quic_levels_hrr_parameters_and_secret_authority" {
    const P = QuicPair(.aes_128_gcm_sha256);
    // Rejected parameters end the handshake with the chosen alert and no authentication.
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3" }, .{ .reject_parameters = true });
        defer pair.deinit();
        try std.testing.expectError(error.Closed, pair.run());
        try std.testing.expect(!pair.authenticated);
        try std.testing.expectEqual(@as(?Alert, .illegal_parameter), pair.alert);
        try std.testing.expect(pair.hs.info() == null);
        // Only the handshake secrets were ever handed out: no application secret.
        for (pair.secrets.items) |secret| try std.testing.expectEqual(Handshake.Level.handshake, secret.level);
    }
    // Missing, duplicated or unneeded extensions.
    for ([_]struct { config: peer_module.Config, err: anyerror }{
        .{ .config = .{ .alpn = "h3", .omit_quic_parameters = true }, .err = error.MissingExtension },
        .{ .config = .{ .alpn = "h3", .duplicate_quic_parameters = true }, .err = error.DuplicateExtension },
        .{ .config = .{}, .err = error.NoApplicationProtocol },
        .{ .config = .{ .alpn = "h3", .tamper = .bad_finished }, .err = error.BadFinished },
        .{ .config = .{ .alpn = "h3", .tamper = .bad_signature }, .err = error.BadSignature },
        .{ .config = .{ .alpn = "h3", .tamper = .missing_certificate_verify }, .err = error.UnexpectedMessage },
        .{ .config = .{ .alpn = "h3", .tamper = .zero_key_share }, .err = error.WeakKey },
    }) |case| {
        const pair = try P.init(std.testing.allocator, case.config, .{});
        defer pair.deinit();
        try std.testing.expectError(case.err, pair.run());
        try std.testing.expect(!pair.authenticated);
        try std.testing.expect(pair.hs.info() == null);
        try std.testing.expect(pair.alert != null or pair.hs.failure() != null);
        for (pair.secrets.items) |secret| try std.testing.expect(secret.level != .application);
    }
}

test "C2 quic data at the wrong level is refused" {
    const P = QuicPair(.aes_128_gcm_sha256);
    // The server's encrypted flight arriving at the Initial level.
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3" }, .{});
        defer pair.deinit();
        try pair.start();
        const hello = try std.testing.allocator.dupe(u8, pair.peer.level(.initial));
        defer std.testing.allocator.free(hello);
        const flight = try std.testing.allocator.dupe(u8, pair.peer.level(.handshake));
        defer std.testing.allocator.free(flight);
        // Hold the ServerHello back and offer the flight at the wrong level.
        try std.testing.expectError(error.UnexpectedMessage, pair.hs.receive(.initial, flight));
        try std.testing.expectError(error.Closed, pair.hs.receive(.initial, hello));
    }
    // A ServerHello offered at the Handshake level.
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3" }, .{});
        defer pair.deinit();
        try pair.start();
        const hello = try std.testing.allocator.dupe(u8, pair.peer.level(.initial));
        defer std.testing.allocator.free(hello);
        try std.testing.expectError(error.WrongEpoch, pair.hs.receive(.handshake, hello));
    }
}

test "C2 quic key-changing messages end their level" {
    const P = QuicPair(.aes_128_gcm_sha256);
    // Trailing bytes after the ServerHello in the same call.
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3" }, .{});
        defer pair.deinit();
        try pair.start();
        const hello = pair.peer.level(.initial);
        var longer = try std.testing.allocator.alloc(u8, hello.len + 4);
        defer std.testing.allocator.free(longer);
        @memcpy(longer[0..hello.len], hello);
        @memcpy(longer[hello.len..], &[_]u8{ 8, 0, 0, 0 });
        try std.testing.expectError(error.RecordAlignment, pair.hs.receive(.initial, longer));
    }
    // More bytes at the Initial level after the ServerHello was complete.
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3" }, .{});
        defer pair.deinit();
        try pair.start();
        const hello = try std.testing.allocator.dupe(u8, pair.peer.level(.initial));
        defer std.testing.allocator.free(hello);
        try std.testing.expectEqual(hello.len, try pair.hs.receive(.initial, hello));
        try std.testing.expectError(error.LevelClosed, pair.hs.receive(.initial, &[_]u8{1}));
    }
}

test "C2 quic handshake survives one-byte delivery and one-byte acknowledgement" {
    inline for (.{ Group.x25519, Group.p256 }) |group| {
        const pair = try QuicPair(.chacha20_poly1305_sha256).init(std.testing.allocator, .{ .group = group, .retry = retrying(group), .alpn = "h3" }, .{ .chunk = 1 });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.authenticated);
        try std.testing.expectEqualSlices(u8, &pair.peer.client_app, pair.secrets.items[pair.secrets.items.len - 1].bytes[0..32]);
    }
}

test "C2 quic post-handshake messages: tickets accepted, key updates and requests refused" {
    const P = QuicPair(.aes_128_gcm_sha256);
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3", .tickets = 2 }, .{});
        defer pair.deinit();
        try pair.run();
        const ticket = "\x04\x00\x00\x12\x00\x00\x1c\x20\x12\x34\x56\x78\x01\x07\x00\x04tkt!\x00\x00";
        try std.testing.expectEqual(ticket.len, try pair.hs.receive(.application, ticket));
        try std.testing.expect(pair.hs.next() == null);
        // KeyUpdate and CertificateRequest do not exist in QUIC.
        try std.testing.expectError(error.UnexpectedMessage, pair.hs.receive(.application, "\x18\x00\x00\x01\x00"));
    }
    {
        const pair = try P.init(std.testing.allocator, .{ .alpn = "h3" }, .{});
        defer pair.deinit();
        try pair.run();
        try std.testing.expectError(error.UnexpectedMessage, pair.hs.receive(.application, "\x0d\x00\x00\x0b\x00\x00\x08\x00\x0d\x00\x04\x00\x02\x04\x03"));
    }
}

test "C2 quic client certificate response goes out at the handshake level" {
    const gpa = std.testing.allocator;
    const certificates = @import("cloak.certificates");
    const key = try certificates.PrivateKey.parse(gpa, peer_module.pki.client_pem, .{});
    defer key.deinit();
    const auth = try certificates.ClientAuth.init(gpa, &.{peer_module.pki.client}, key, .{});
    defer auth.deinit();
    const pair = try QuicPair(.aes_128_gcm_sha256).init(gpa, .{ .alpn = "h3", .request_client_cert = true }, .{ .client_auth = auth });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(@as(usize, 1), pair.peer.client_certificates);
    try std.testing.expect(pair.peer.client_signature_ok);
    try std.testing.expect(pair.peer.client_finished_ok);
}

test "C2 quic options require application protocols" {
    try std.testing.expectError(error.InvalidOptions, Handshake.client(std.testing.allocator, .{ .identity = .{ .dns = "example.com" }, .verify = .none, .parameters = "", .alpn = &.{} }));
}

test "C2 fuzz quic handshake input at every level never authenticates" {
    try std.testing.fuzz({}, fuzz, .{ .corpus = shakedown.corpus.entries(&.{ "\x02\x00\x00\x00", "\x08\x00\x00\x02\x00\x00", "\x0b\x00\x00\x04\x00\x00\x00\x00" }) });
}

fn fuzz(_: void, smith: *std.testing.Smith) !void {
    var bytes: [2048]u8 = undefined;
    const input = bytes[0..smith.slice(&bytes)];
    const pair = try QuicPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .alpn = "h3" }, .{});
    defer pair.deinit();
    _ = try pair.step();
    var at: usize = 0;
    var level: Handshake.Level = .initial;
    while (at < input.len) {
        const n = @min(input.len - at, 1 + (input[at] % 64));
        const used = pair.hs.receive(level, input[at..][0..n]) catch break;
        at += @max(used, 1);
        level = switch (level) {
            .initial => .handshake,
            .handshake => .application,
            .application => .initial,
        };
        _ = pair.step() catch break;
    }
    try std.testing.expect(!pair.authenticated);
    try std.testing.expect(pair.hs.info() == null);
}

test "C2 fuzz quic arbitrary handshake-level flights never authenticate" {
    try std.testing.fuzz({}, fuzzFlight, .{ .corpus = shakedown.corpus.entries(&.{
        "\x08\x00\x00\x02\x00\x00",
        "\x08\x00\x00\x08\x00\x06\x00\x39\x00\x02xy",
        "\x08\x00\x00\x02\x00\x00\x0b\x00\x00\x04\x00\x00\x00\x00",
    }) });
}

fn fuzzFlight(_: void, smith: *std.testing.Smith) !void {
    var bytes: [3000]u8 = undefined;
    const flight = bytes[0..smith.slice(&bytes)];
    if (flight.len == 0) return;
    const pair = try QuicPair(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .raw_flight = flight, .alpn = "h3" }, .{});
    defer pair.deinit();
    var rounds: usize = 0;
    while (rounds < 64) : (rounds += 1) {
        const moved = pair.step() catch break;
        if (!moved) break;
    }
    try std.testing.expect(!pair.authenticated);
    try std.testing.expect(pair.hs.info() == null);
}
