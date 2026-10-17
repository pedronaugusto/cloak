//! The failure catalogue's DTLS rows (design section 17, F77-F82): each a named failure class of
//! the DTLS registers, run against cloak's datagram carrier.
const std = @import("std");
const Pair = @import("../../testing/DatagramPair.zig");
const Datagram = @import("Datagram.zig");
const Record = @import("Record.zig");
const suites = @import("../crypto/Suite.zig");

const gpa = std.testing.allocator;
const both = [_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} };

/// The client's datagrams for its first flight, at the pair's MTU.
fn clientFlight(pair: *Pair, out: *std.ArrayList([]u8)) !void {
    try pair.serveClient();
    var buffer: [16 * 1024]u8 = undefined;
    while (try pair.client.dtls.send(&buffer, pair.now)) |datagram| try out.append(gpa, try gpa.dupe(u8, datagram));
}

fn freeAll(list: *std.ArrayList([]u8)) void {
    for (list.items) |d| gpa.free(d);
    list.deinit(gpa);
}

/// A plaintext handshake fragment: the DTLS header's fields as given, `bytes` as the fragment.
fn fragment(out: []u8, kind: u8, length: u24, sequence: u16, offset: u24, bytes: []const u8, record_sequence: u64) ![]u8 {
    var body: [2048]u8 = undefined;
    body[0] = kind;
    std.mem.writeInt(u24, body[1..4], length, .big);
    std.mem.writeInt(u16, body[4..6], sequence, .big);
    std.mem.writeInt(u24, body[6..9], offset, .big);
    std.mem.writeInt(u24, body[9..12], @intCast(bytes.len), .big);
    @memcpy(body[12..][0..bytes.len], bytes);
    return Record.plaintext(.handshake, record_sequence, body[0 .. 12 + bytes.len], out);
}

test "C8 catalogue_dtls_fragment_arithmetic_and_conflicting_total" {
    // F77: offsets past the end, totals that change between fragments, overlaps that disagree and
    // lengths past every bound are discarded before any byte is written or any buffer allocated;
    // the server's flight, in pieces and out of order, still makes whole messages.
    for (both) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .mtu = 256, .admission = .validated });
        defer pair.deinit();
        var hello: std.ArrayList([]u8) = .empty;
        defer freeAll(&hello);
        try clientFlight(pair, &hello);
        for (hello.items) |datagram| try pair.server.dtls.receive(datagram, pair.now);
        try pair.serveServer();
        var flight: std.ArrayList([]u8) = .empty;
        defer freeAll(&flight);
        var buffer: [16 * 1024]u8 = undefined;
        while (try pair.server.dtls.send(&buffer, pair.now)) |datagram| try flight.append(gpa, try gpa.dupe(u8, datagram));
        try std.testing.expect(flight.items.len >= 3);
        const client = &pair.client.dtls;
        var out: [2048]u8 = undefined;
        // Hostile pieces of the ServerHello (message 0) first.
        const hostile = [_][]u8{
            try fragment(out[0..256], 2, 100, 0, 90, &@as([20]u8, @splat(1)), 900),
            try fragment(out[256..512], 2, 0xffffff, 0, 0, "x", 901),
            try fragment(out[512..768], 2, 100, 0, 0xfffff0, "abc", 902),
            try fragment(out[768..1024], 2, 2 << 20, 0, 0, "abc", 903),
        };
        for (hostile) |datagram| try client.receive(datagram, pair.now);
        try std.testing.expectEqual(@as(usize, 0), client.partials.items.len);
        try std.testing.expectEqual(@as(usize, 0), client.partial_bytes);
        // The genuine datagrams in reverse order, each after a forged copy with its last byte
        // changed; before them a plaintext piece of message 1 that claims another total.
        try client.receive(try fragment(out[1024..1280], 11, 7, 1, 0, "zz", 904), pair.now);
        var index = flight.items.len;
        while (index > 0) {
            index -= 1;
            var copy: [2048]u8 = undefined;
            const datagram = flight.items[index];
            @memcpy(copy[0..datagram.len], datagram);
            copy[datagram.len - 1] ^= 0xff;
            try client.receive(copy[0..datagram.len], pair.now);
            @memcpy(copy[0..datagram.len], datagram);
            try client.receive(copy[0..datagram.len], pair.now);
            try std.testing.expect(client.partial_bytes <= client.limits.reassembly);
        }
        try std.testing.expect(client.failure() == null);
        // The handshake completes from there: every message reached the engine whole, once.
        try pair.run();
        try std.testing.expectEqual(Datagram.Phase.connected, client.phase());
        try std.testing.expectEqual(Datagram.Phase.connected, pair.server.dtls.phase());
    }
}

test "C8 catalogue_dtls_duplicate_replay_and_message_order" {
    // F78: a replayed record, a message already taken, one far ahead and a wrapping sequence are
    // discarded without touching the transcript or the keys; the association goes on.
    for (both) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        var out: [256]u8 = undefined;
        const record = try pair.client.dtls.write("once", &out);
        var copy: [256]u8 = undefined;
        @memcpy(copy[0..record.len], record);
        try pair.server.dtls.receive(copy[0..record.len], pair.now);
        try std.testing.expectEqualSlices(u8, "once", pair.server.dtls.read().?);
        @memcpy(copy[0..record.len], record);
        try pair.server.dtls.receive(copy[0..record.len], pair.now);
        try std.testing.expect(pair.server.dtls.read() == null);
        // Handshake messages of a finished handshake: message 0 again, the next one, one 20
        // ahead, one at the wrap. None reaches the engine (which would refuse them), none ends the
        // association.
        var hostile: [512]u8 = undefined;
        // The next expected one, in plaintext, can only be forged once keys are in: dropped, not
        // refused (a refusal would end the association).
        for ([_]u16{ 0, pair.server.dtls.receive_sequence, pair.server.dtls.receive_sequence +% 20, 0xffff }) |sequence| {
            try pair.server.dtls.receive(try fragment(&hostile, 1, 3, sequence, 0, "abc", 77), pair.now);
        }
        try std.testing.expect(pair.server.dtls.failure() == null);
        try std.testing.expectEqual(@as(usize, 0), pair.server.dtls.partials.items.len);
        try pair.exchange(&pair.client, "still");
        try std.testing.expectEqualSlices(u8, "still", pair.server.received.items[pair.server.received.items.len - 1]);
    }
}

test "C8 catalogue_dtls_timer_during_suspended_flight" {
    // F79: a flight cut short when the path's MTU drops, then its timer: what goes out is the
    // cached messages cut anew, the peer completes from it, and retransmissions stop at the limit.
    for (both) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .admission = .validated });
        defer pair.deinit();
        // The client's hello reaches the server; the server sends one datagram of its flight.
        try pair.serveClient();
        var buffer: [16 * 1024]u8 = undefined;
        while (try pair.client.dtls.send(&buffer, pair.now)) |datagram| try pair.server.dtls.receive(datagram, pair.now);
        try pair.serveServer();
        _ = try pair.server.dtls.send(&buffer, pair.now);
        // The MTU falls; the rest, and every retransmission, is cut for the new one.
        try pair.server.dtls.setMtu(256);
        try pair.client.dtls.setMtu(256);
        try pair.run();
        try std.testing.expectEqual(Datagram.Phase.connected, pair.client.dtls.phase());
        try std.testing.expectEqual(Datagram.Phase.connected, pair.server.dtls.phase());
    }
    // A peer that never answers: the client retransmits at most seven times, then gives up.
    var lonely = try Datagram.client(gpa, .{ .identity = .none, .verify = .none });
    defer lonely.deinit();
    var pair_for_entropy = try Pair.init(gpa, .{});
    defer pair_for_entropy.deinit();
    var now: std.Io.Timestamp = .fromNanoseconds(0);
    var sent: usize = 0;
    var buffer: [2048]u8 = undefined;
    while (lonely.request()) |request| try lonely.provide(request.token, .{ .entropy = (&buffer)[0..request.service.entropy] });
    for (0..40) |_| {
        while (lonely.send(&buffer, now) catch null) |_| sent += 1;
        if (lonely.phase() == .failed) break;
        now = lonely.timeout() orelse break;
    }
    try std.testing.expectEqual(Datagram.Phase.failed, lonely.phase());
    try std.testing.expectEqual(@as(?Datagram.Error, error.HandshakeTimeout), lonely.failure());
    try std.testing.expectEqual(@as(usize, 8), sent);
}

test "C8 catalogue_dtls_client_random_cookie_and_amplification at the association: an unproven server sends at most three times what it received" {
    // F80 (the cookie rows are in Cookies_test.zig): without a cookie the server's output before
    // the client's keys prove its address stays within three times its input, and two clients with
    // their own randomness against the same server draws derive their own keys.
    for (both) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .admission = .unvalidated, .mtu = 1200 });
        defer pair.deinit();
        while (pair.server.dtls.phase() == .handshaking and pair.client.dtls.failure() == null) {
            if (!pair.server.dtls.validated) try std.testing.expect(pair.server.dtls.sent_bytes <= 3 * pair.server.dtls.received_bytes);
            if (!try pair.step()) pair.now = pair.client.dtls.timeout() orelse break;
        }
        try pair.run();
        var a: [32]u8 = undefined;
        try pair.client.dtls.exportKeyingMaterial(&a, "EXTRACTOR-test", "");
        const other = try Pair.init(gpa, .{ .seed = 12, .client_suites = list, .server_suites = list });
        defer other.deinit();
        try other.run();
        var b: [32]u8 = undefined;
        try other.client.dtls.exportKeyingMaterial(&b, "EXTRACTOR-test", "");
        try std.testing.expect(!std.mem.eql(u8, &a, &b));
    }
}

test "C8 catalogue_dtls_short_aead_ccm_tag_and_survival at the association: forged datagrams change nothing" {
    // F81 (the record rows are in Record_test.zig): short, truncated, tampered and foreign
    // datagrams to an established association are dropped; the next genuine one is read.
    for ([_][]const suites.Suite{ &.{.aes_128_ccm_sha256}, &.{.ecdhe_ecdsa_aes_128_ccm}, suites.Suite.tls13_only, &.{.ecdhe_ecdsa_chacha20_poly1305_sha256} }) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        var out: [256]u8 = undefined;
        const record = try pair.client.dtls.write("genuine", &out);
        var keep: [256]u8 = undefined;
        @memcpy(keep[0..record.len], record);
        for (0..record.len) |len| {
            var copy: [256]u8 = undefined;
            @memcpy(copy[0..len], keep[0..len]);
            try pair.server.dtls.receive(copy[0..len], pair.now);
        }
        for (0..record.len * 8) |bit| {
            var copy: [256]u8 = undefined;
            @memcpy(copy[0..record.len], keep[0..record.len]);
            copy[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
            try pair.server.dtls.receive(copy[0..record.len], pair.now);
        }
        var junk: [64]u8 = @splat(0x2c);
        try pair.server.dtls.receive(&junk, pair.now);
        try std.testing.expect(pair.server.dtls.failure() == null);
        try std.testing.expect(pair.server.dtls.read() == null);
        @memcpy(out[0..record.len], keep[0..record.len]);
        try pair.server.dtls.receive(out[0..record.len], pair.now);
        try std.testing.expectEqualSlices(u8, "genuine", pair.server.dtls.read().?);
    }
}

test "C8 catalogue_dtls_short_aead_ccm_tag_and_survival: a CCM_8 key ends its association at 2^7 failed records, the margin of every other cipher" {
    // F81 for the 8-byte tag (RFC 9147 appendix B.3): 127 forgeries are dropped and the
    // association reads on; the 128th ends it with ForgeryLimit, before a 2^-57 forgery margin is
    // spent. A 16-byte-tag key takes the same 128 and lives on.
    for ([_]suites.Suite{ .ecdhe_ecdsa_aes_128_ccm_8, .ecdhe_ecdsa_aes_128_ccm }) |suite| {
        const pair = try Pair.init(gpa, .{ .client_suites = &.{suite}, .server_suites = &.{suite} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(suite, pair.server.dtls.info().?.suite);
        var out: [256]u8 = undefined;
        const record = try pair.client.dtls.write("genuine", &out);
        var keep: [256]u8 = undefined;
        @memcpy(keep[0..record.len], record);
        var forged: [256]u8 = undefined;
        for (0..127) |i| {
            @memcpy(forged[0..record.len], keep[0..record.len]);
            forged[record.len - 1 - i % 8] ^= 0x01;
            try pair.server.dtls.receive(forged[0..record.len], pair.now);
        }
        try std.testing.expect(pair.server.dtls.failure() == null);
        @memcpy(out[0..record.len], keep[0..record.len]);
        try pair.server.dtls.receive(out[0..record.len], pair.now);
        try std.testing.expectEqualSlices(u8, "genuine", pair.server.dtls.read().?);
        // The next record, forged: its sequence is fresh, so the forgery reaches the tag.
        const second = try pair.client.dtls.write("genuine", &out);
        @memcpy(forged[0..second.len], second);
        forged[second.len - 1] ^= 0x80;
        if (suite == .ecdhe_ecdsa_aes_128_ccm_8) {
            try std.testing.expectError(error.ForgeryLimit, pair.server.dtls.receive(forged[0..record.len], pair.now));
            try std.testing.expectEqual(error.ForgeryLimit, pair.server.dtls.failure().?);
        } else {
            try pair.server.dtls.receive(forged[0..record.len], pair.now);
            try std.testing.expect(pair.server.dtls.failure() == null);
        }
    }
}

test "C8 catalogue_dtls_corruption_renegotiation_and_reset" {
    // F82: a corrupted record, then a new hello on the established association: no renegotiation,
    // no reset; and a new association takes nothing of the old one's records.
    for (both) |list| {
        const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        var out: [256]u8 = undefined;
        const record = try pair.client.dtls.write("before", &out);
        var keep: [256]u8 = undefined;
        @memcpy(keep[0..record.len], record);
        out[record.len - 1] ^= 1;
        try pair.server.dtls.receive(out[0..record.len], pair.now);
        // A whole new first hello, as a client that restarted would send.
        var fresh = try Datagram.client(gpa, .{ .identity = .none, .verify = .none, .suites = list });
        defer fresh.deinit();
        var entropy: [2048]u8 = @splat(5);
        while (fresh.request()) |request| try fresh.provide(request.token, .{ .entropy = entropy[0..request.service.entropy] });
        var hello: [2048]u8 = undefined;
        const datagram = (try fresh.send(&hello, pair.now)).?;
        try pair.server.dtls.receive(datagram, pair.now);
        try std.testing.expect(pair.server.dtls.failure() == null);
        try std.testing.expectEqual(Datagram.Phase.connected, pair.server.dtls.phase());
        @memcpy(out[0..record.len], keep[0..record.len]);
        try pair.server.dtls.receive(out[0..record.len], pair.now);
        try std.testing.expectEqualSlices(u8, "before", pair.server.dtls.read().?);
        // A new server association: the old one's record opens nothing there.
        var other = try Datagram.server(gpa, pair.serverOptions(), .{});
        defer other.deinit();
        @memcpy(out[0..record.len], keep[0..record.len]);
        try other.receive(out[0..record.len], pair.now);
        try std.testing.expect(other.read() == null);
        try std.testing.expectEqual(Datagram.Phase.handshaking, other.phase());
    }
}
