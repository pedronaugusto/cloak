//! F92: what cloak holds of a QUIC stack's input. The transport (datagrams and their
//! amplification, packet buffers, CRYPTO and STREAM reassembly, flow control, connection IDs)
//! is the caller's; cloak takes each level's contiguous CRYPTO bytes and holds itself to its own
//! bounds whatever the caller hands it. Both roles are cloak's here.
const std = @import("std");
const shakedown = @import("shakedown");
const Handshake = @import("Handshake.zig");
const loop_module = @import("../../testing/QuicLoop.zig");
const QuicLoop = loop_module.QuicLoop;
const Limits = @import("../handshake/Terms.zig").Limits;

const message_limit = (Limits{}).message;

test "F92 catalogue_quic_transport_admission_boundary (the caller's CRYPTO bytes are copied, never held: each slice overwritten as its call returns)" {
    const P = QuicLoop(.aes_128_gcm_sha256);
    for ([_]usize{ 1, 7, 1 << 20 }) |chunk| {
        // A first flight answered at once, and one that costs a retry; client certificates.
        for ([_]loop_module.Options{
            .{ .chunk = chunk, .poison = true, .mutual = true },
            .{ .chunk = chunk, .poison = true, .mutual = true, .client_groups = &.{ .x25519, .p256 }, .server_groups = &.{.p256} },
        }) |options| {
            const pair = try P.init(std.testing.allocator, options);
            defer pair.deinit();
            try pair.run();
            try std.testing.expect(pair.client.authenticated and pair.server.authenticated);
            try std.testing.expect(pair.server.hs.info().?.peer_authenticated);
        }
    }
}

test "F92 catalogue_quic_transport_admission_boundary (a byte at a time holds no more than whole flights: one partial message, at one level)" {
    const Counting = shakedown.alloc.Counting;
    var peaks: [2]usize = undefined;
    for ([_]usize{ 1 << 20, 1 }, &peaks) |chunk, *peak| {
        var count = Counting.init(std.testing.allocator);
        const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .chunk = chunk, .mutual = true, .handshake_gpa = count.allocator() });
        defer pair.deinit();
        try pair.run();
        peak.* = count.peak_bytes;
    }
    try std.testing.expect(peaks[1] <= peaks[0]);
}

test "F92 catalogue_quic_transport_admission_boundary (a message declared past the limit is refused at its header; one within it is held at one level only)" {
    const Counting = shakedown.alloc.Counting;
    const P = QuicLoop(.aes_128_gcm_sha256);
    const past: u24 = message_limit - 4 + 1;
    const at: u24 = message_limit - 4;
    // Each role: the server's first message is a ClientHello, the client's a ServerHello.
    inline for (.{ "server", "client" }) |role| {
        {
            var count = Counting.init(std.testing.allocator);
            const pair = try P.init(std.testing.allocator, .{ .handshake_gpa = count.allocator() });
            defer pair.deinit();
            const side = &@field(pair, role);
            if (comptime std.mem.eql(u8, role, "client")) _ = try pair.step();
            const kind: u8 = if (comptime std.mem.eql(u8, role, "client")) 2 else 1;
            var header: [4]u8 = .{ kind, 0, 0, 0 };
            std.mem.writeInt(u24, header[1..4], past, .big);
            const before = count.total_bytes;
            try std.testing.expectError(error.HandshakeLimit, side.hs.receive(.initial, &header));
            // Refused at the header: nothing of the declared body was allocated.
            try std.testing.expect(count.total_bytes - before <= 4);
            try std.testing.expect(side.hs.failure() != null);
            try std.testing.expect(side.hs.info() == null);
        }
        {
            var count = Counting.init(std.testing.allocator);
            const pair = try P.init(std.testing.allocator, .{ .handshake_gpa = count.allocator() });
            defer pair.deinit();
            const side = &@field(pair, role);
            if (comptime std.mem.eql(u8, role, "client")) _ = try pair.step();
            const kind: u8 = if (comptime std.mem.eql(u8, role, "client")) 2 else 1;
            var header: [4]u8 = .{ kind, 0, 0, 0 };
            std.mem.writeInt(u24, header[1..4], at, .big);
            const live = count.live_bytes;
            try std.testing.expectEqual(@as(usize, 4), try side.hs.receive(.initial, &header));
            // One partial message, never more than the limit.
            try std.testing.expect(count.live_bytes - live <= message_limit);
            // A message may not begin at another level while one is partial.
            try std.testing.expectError(error.UnexpectedMessage, side.hs.receive(.handshake, &.{20}));
            try std.testing.expect(side.hs.info() == null);
        }
    }
}

test "F92 catalogue_quic_transport_admission_boundary (the peer's transport parameters wait for the caller's verdict: no flight, secret or authentication past them)" {
    const pair = try QuicLoop(.aes_128_gcm_sha256).init(std.testing.allocator, .{ .hold_parameters = true });
    defer pair.deinit();
    try std.testing.expectError(error.Stalled, pair.run());
    // The server holds the client's parameters: it has written nothing and installed nothing.
    try std.testing.expectEqualSlices(u8, "client-params", pair.server.peer_parameters.items);
    try std.testing.expectEqual(@as(usize, 0), pair.server.secrets.items.len);
    for (pair.client.inbox) |list| try std.testing.expectEqual(@as(usize, 0), list.items.len);
    try pair.server.hs.acceptParameters();
    try std.testing.expectError(error.Stalled, pair.run());
    // The client holds the server's: handshake keys only, no Finished sent, neither end done.
    try std.testing.expectEqualSlices(u8, "server-params", pair.client.peer_parameters.items);
    for (pair.client.secrets.items) |secret| try std.testing.expectEqual(Handshake.Level.handshake, secret.level);
    try std.testing.expectEqual(@as(usize, 0), pair.server.inbox[@backingInt(Handshake.Level.handshake)].items.len);
    try std.testing.expect(!pair.client.authenticated and !pair.server.authenticated);
    try pair.client.hs.acceptParameters();
    try pair.run();
    try std.testing.expect(pair.client.authenticated and pair.server.authenticated);
}
