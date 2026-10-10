const std = @import("std");
const shakedown = @import("shakedown");
const Connection = @import("Connection.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Group = @import("crypto/Group.zig").Group;
const Pair = @import("../testing/Pair.zig").Pair;
const peer_module = @import("../testing/Peer.zig");

fn run(comptime suite: Suite, config: peer_module.Config, options: @import("../testing/Pair.zig").Options) !void {
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

test "C2 connection completes a full handshake for every suite and group" {
    inline for (std.enums.values(Suite)) |suite| {
        inline for (.{ Group.x25519, Group.x25519_mlkem768, Group.p256, Group.p384 }) |group| {
            try run(suite, .{ .group = group, .retry = if (group == .p256 or group == .p384) group else null }, .{});
        }
    }
}

test "C2 connection authenticates every certificate type" {
    inline for (.{ peer_module.Cert.p256, .p384, .ed25519 }) |cert| {
        try run(.aes_128_gcm_sha256, .{ .cert = cert }, .{});
    }
}

test "C2 scratch trace" {
    const P = Pair(.aes_128_gcm_sha256);
    const pair = try P.init(std.testing.allocator, .{}, .{});
    defer pair.deinit();
    _ = try pair.service();
    const out = pair.conn.output();
    try pair.peer.feed(out);
    pair.conn.acknowledge(out.len);
    const in = pair.peer.pending();
    std.debug.print("peer out {d}: {any}\n", .{ in.len, in[0..@min(in.len, 16)] });
    const n = pair.conn.receive(in) catch |err| {
        std.debug.print("receive error {s} {any}\n", .{ @errorName(err), pair.conn.diagnostics() });
        return;
    };
    std.debug.print("consumed {d} phase {s} out {d} need {any} diag {any}\n", .{ n, @tagName(pair.conn.phase()), pair.conn.output().len, pair.conn.hs.need(), pair.conn.diagnostics() });
}
