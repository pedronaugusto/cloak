const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");
const Handshake = @import("Handshake.zig");
const Suite = @import("../crypto/Suite.zig").Suite;
const Group = @import("../crypto/Group.zig").Group;
const Alert = @import("../wire/Alert.zig").Alert;
const loop_module = @import("../../testing/QuicLoop.zig");
const QuicLoop = loop_module.QuicLoop;

test "C3 quic roles agree for every suite and group and hand off matching secrets" {
    inline for (std.enums.values(Suite)) |suite| {
        inline for (.{ Group.x25519, Group.x25519_mlkem768, Group.p256, Group.p384 }) |group| {
            // A single group on both sides; a P curve costs a retry because only X25519 or the
            // hybrid get a first share.
            const pair = try QuicLoop(suite).init(std.testing.allocator, .{ .client_groups = &.{group}, .server_groups = &.{group} });
            defer pair.deinit();
            try pair.run();
            const c = pair.client.secrets.items;
            const s = pair.server.secrets.items;
            try std.testing.expectEqual(@as(usize, 4), c.len);
            try std.testing.expectEqual(@as(usize, 4), s.len);
            // What one side writes at a level the other reads.
            for (c) |mine| {
                const theirs = for (s) |candidate| {
                    if (candidate.level == mine.level and candidate.direction != mine.direction) break candidate;
                } else return error.MissingSecret;
                try std.testing.expectEqualSlices(u8, mine.bytes[0..mine.len], theirs.bytes[0..theirs.len]);
            }
            try std.testing.expectEqualSlices(u8, "server-params", pair.client.peer_parameters.items);
            try std.testing.expectEqualSlices(u8, "client-params", pair.server.peer_parameters.items);
            const ci = pair.client.hs.info().?;
            const si = pair.server.hs.info().?;
            try std.testing.expectEqual(group, ci.group);
            try std.testing.expectEqual(group, si.group);
            try std.testing.expectEqualSlices(u8, "h3", si.alpn);
            try std.testing.expectEqualSlices(u8, "example.com", si.server_name);
            var ours: [16]u8 = undefined;
            var theirs: [16]u8 = undefined;
            try pair.client.hs.exportKeyingMaterial(&ours, "EXPERIMENTAL quic", "");
            try pair.server.hs.exportKeyingMaterial(&theirs, "EXPERIMENTAL quic", "");
            try std.testing.expectEqualSlices(u8, &theirs, &ours);
            // Cloak signed with the credential's key: no signing request reached the driver.
            try std.testing.expectEqual(@as(usize, 0), pair.server.signed);
        }
    }
}

test "C3 quic server events install a level before data is sent at it" {
    const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{});
    defer pair.deinit();
    try pair.run();
    // p: client parameters; w,r: handshake keys; d: ServerHello; d: server flight; w: app write;
    // r: app read once the client's Finished is expected; the client Finished completes it.
    std.debug.print("\nC3 quic server events {s} client events {s}\n", .{ pair.server.events.items, pair.client.events.items });
    try std.testing.expectEqualSlices(u8, "pdwrddddwra", pair.server.events.items);
}

test "C3 quic server accepts a client certificate and rejects what is missing or untrusted" {
    {
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .mutual = true });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.server.hs.info().?.peer_authenticated);
        try std.testing.expectEqual(@as(usize, 1), pair.server.verified);
        try std.testing.expectEqual(@as(usize, 0), pair.client.signed);
    }
    {
        // Keys held elsewhere: both roles ask the driver to sign.
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .mutual = true, .external = true });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.server.hs.info().?.peer_authenticated);
        try std.testing.expectEqual(@as(usize, 1), pair.server.signed);
        try std.testing.expectEqual(@as(usize, 1), pair.client.signed);
    }
    {
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .mutual_without_identity = true });
        defer pair.deinit();
        try std.testing.expectError(error.CertificateRequired, pair.run());
        try std.testing.expect(!pair.server.authenticated);
        try std.testing.expect(pair.server.hs.info() == null);
        try std.testing.expectEqual(@as(?Alert, .certificate_required), pair.server.hs.failure());
    }
    {
        // The client does not trust the server chain.
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .distrust = true });
        defer pair.deinit();
        try std.testing.expectError(error.VerificationRejected, pair.run());
        try std.testing.expect(!pair.client.authenticated);
        for (pair.client.secrets.items) |secret| try std.testing.expect(secret.level != .application);
    }
}

test "C3 quic rejected parameters end the handshake on either side" {
    {
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .reject_client_parameters = true });
        defer pair.deinit();
        try std.testing.expectError(error.Closed, pair.run());
        try std.testing.expectEqual(@as(?Alert, .illegal_parameter), pair.server.alert);
        try std.testing.expect(pair.server.hs.info() == null);
        // The server never wrote a flight or an application secret before accepting.
        try std.testing.expectEqual(@as(usize, 0), pair.server.secrets.items.len);
        try std.testing.expectEqual(@as(usize, 0), pair.client.inbox[1].items.len);
    }
    {
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .reject_server_parameters = true });
        defer pair.deinit();
        try std.testing.expectError(error.Closed, pair.run());
        try std.testing.expect(!pair.client.authenticated and !pair.server.authenticated);
    }
}

test "C3 quic server refuses what it cannot serve" {
    const P = QuicLoop(.aes_128_gcm_sha256);
    const cases = [_]struct { options: loop_module.Options, err: anyerror }{
        .{ .options = .{ .client_alpn = &.{"h2"} }, .err = error.NoApplicationProtocol },
        .{ .options = .{ .client_groups = &.{.x25519}, .server_groups = &.{.p384} }, .err = error.NoSharedGroup },
    };
    inline for (cases) |case| {
        const pair = try P.init(std.testing.allocator, case.options);
        defer pair.deinit();
        try std.testing.expectError(case.err, pair.run());
        try std.testing.expect(!pair.server.authenticated);
        try std.testing.expect(pair.server.hs.info() == null);
        try std.testing.expect(pair.server.hs.failure() != null);
        for (pair.server.secrets.items) |secret| try std.testing.expect(secret.level != .application);
    }
}

test "C3 quic server retries a group the client did not send a share for" {
    const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .client_groups = &.{ .x25519, .p256 }, .server_groups = &.{.p256} });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqual(Group.p256, pair.server.hs.info().?.group);
    // The client sent two hellos; the server answered each at the initial level.
    var data: usize = 0;
    for (pair.server.events.items) |tag| {
        if (tag == 'd') data += 1;
    }
    try std.testing.expect(data >= 3);
}

test "C3 quic server survives one-byte delivery" {
    inline for (.{ Group.x25519, Group.p256 }) |group| {
        const pair = try QuicLoop(.chacha20_poly1305_sha256).init(std.testing.allocator, .{ .client_groups = if (group == .x25519) &.{.x25519} else &.{ .x25519, group }, .server_groups = &.{group}, .chunk = 1, .mutual = true });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.server.hs.info().?.peer_authenticated);
    }
}

test "C3 quic server enforces levels and alignment" {
    const P = QuicLoop(.aes_128_gcm_sha256);
    // A ClientHello offered at the handshake level.
    {
        const pair = try P.init(std.testing.allocator, .{});
        defer pair.deinit();
        _ = try pair.service(&pair.client);
        _ = try pair.drain(&pair.client, &pair.server);
        const hello = try std.testing.allocator.dupe(u8, pair.server.inbox[0].items);
        defer std.testing.allocator.free(hello);
        try std.testing.expectError(error.WrongEpoch, pair.server.hs.receive(.handshake, hello));
    }
    // Trailing bytes after the ClientHello in the same call, and more at the initial level later.
    {
        const pair = try P.init(std.testing.allocator, .{});
        defer pair.deinit();
        _ = try pair.service(&pair.client);
        _ = try pair.drain(&pair.client, &pair.server);
        const hello = pair.server.inbox[0].items;
        var longer = try std.testing.allocator.alloc(u8, hello.len + 4);
        defer std.testing.allocator.free(longer);
        @memcpy(longer[0..hello.len], hello);
        @memcpy(longer[hello.len..], &[_]u8{ 20, 0, 0, 0 });
        try std.testing.expectError(error.RecordAlignment, pair.server.hs.receive(.initial, longer));
    }
    // After the handshake: no post-handshake message exists for a server in QUIC.
    {
        const pair = try P.init(std.testing.allocator, .{});
        defer pair.deinit();
        try pair.run();
        try std.testing.expectError(error.UnexpectedMessage, pair.server.hs.receive(.application, "\x18\x00\x00\x01\x00"));
        try std.testing.expectError(error.Closed, pair.server.hs.receive(.application, "x"));
    }
}

test "C3 quic server options require application protocols and credentials" {
    try std.testing.expectError(error.InvalidOptions, Handshake.server(std.testing.allocator, .{ .credentials = &.{}, .parameters = "", .alpn = &.{"h3"} }));
    const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{});
    defer pair.deinit();
    try std.testing.expectError(error.InvalidOptions, Handshake.server(std.testing.allocator, .{ .credentials = &.{.{ .identity = pair.server_identity }}, .parameters = "", .alpn = &.{} }));
}

test "C3 fuzz quic server input at every level never authenticates" {
    try shakedown.check(std.testing.allocator, {}, fuzz, .{ .cases = 64 });
}

const examples = [_][]const u8{ "\x01\x00\x00\x00", "\x0b\x00\x00\x04\x00\x00\x00\x00", "\x14\x00\x00\x20" };

test "C3 quic server takes odd messages at every level without authenticating" {
    for (examples) |input| for ([_]bool{ false, true }) |mutual| try feedLevels(input, mutual);
}

fn fuzz(_: void, case: *shakedown.Case) !void {
    var bytes: [2048]u8 = undefined;
    const mutual = shakedown.gen.boolean(case.source);
    try feedLevels(inputs.draw(case, &bytes, &examples, 48), mutual);
}

fn feedLevels(input: []const u8, mutual: bool) !void {
    const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .mutual = mutual });
    defer pair.deinit();
    var at: usize = 0;
    var level: Handshake.Level = .initial;
    while (at < input.len) {
        const n = @min(input.len - at, 1 + (input[at] % 64));
        const used = pair.server.hs.receive(level, input[at..][0..n]) catch break;
        at += @max(used, 1);
        level = switch (level) {
            .initial => .handshake,
            .handshake => .application,
            .application => .initial,
        };
        _ = pair.service(&pair.server) catch break;
        _ = pair.drain(&pair.server, &pair.client) catch break;
    }
    try std.testing.expect(!pair.server.authenticated);
    try std.testing.expect(pair.server.hs.info() == null);
}
