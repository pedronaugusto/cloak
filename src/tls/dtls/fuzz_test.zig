//! Fuzz properties of the datagram carrier: hostile datagrams to a server, to an established
//! association and to the stateless cookie check end nothing they should not, release nothing
//! unauthenticated and stay within their bounds.
const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../../testing/inputs.zig");
const Pair = @import("../../testing/DatagramPair.zig");
const EchKeys = @import("../../testing/EchKeys.zig");
const Datagram = @import("Datagram.zig");
const Cookies = @import("Cookies.zig");
const Record = @import("Record.zig");
const suites = @import("../crypto/Suite.zig");

const gpa = std.testing.allocator;

/// Seeds: a plaintext hello fragment, a DTLS 1.3 unified header, a tls12_cid record, an ACK.
const examples = [_][]const u8{
    "\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x01\x00\x00\x04\x00\x00\x00\x00\x00\x00\x04abcd",
    "\x2f\x00\x01\x00\x20" ++ "0123456789abcdef0123456789abcdef",
    "\x19\xfe\xfd\x00\x01\x00\x00\x00\x00\x00\x00\x00\x04abcd",
    "\x1a\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x01\x00\x02\x00\x00",
};

test "C8 fuzz datagrams to a DTLS server never connect it" {
    try shakedown.check(gpa, {}, fuzzServer, .{ .cases = 64 });
}

fn fuzzServer(_: void, case: *shakedown.Case) !void {
    const pair = try Pair.init(gpa, .{ .admission = .validated });
    defer pair.deinit();
    var bytes: [2048]u8 = undefined;
    for (0..4) |_| {
        const input = inputs.draw(case, &bytes, &examples, 64);
        pair.server.dtls.receive(input, pair.now) catch break;
        pair.serveServer() catch break;
        var out: [16 * 1024]u8 = undefined;
        while (pair.server.dtls.send(&out, pair.now) catch null) |_| {}
    }
    try std.testing.expect(pair.server.dtls.phase() != .connected);
    try std.testing.expect(pair.server.dtls.info() == null);
    try std.testing.expect(pair.server.dtls.read() == null);
    try std.testing.expect(pair.server.dtls.partial_bytes <= pair.server.dtls.limits.reassembly);
}

test "C8 fuzz datagrams to an established DTLS association are dropped" {
    try shakedown.check(gpa, {}, fuzzEstablished, .{ .cases = 32 });
}

fn fuzzEstablished(_: void, case: *shakedown.Case) !void {
    const s = case.source;
    const list: []const suites.Suite = if (shakedown.gen.boolean(s)) suites.Suite.tls13_only else &.{.ecdhe_ecdsa_aes_128_gcm_sha256};
    // With connection IDs or without.
    const cids = shakedown.gen.boolean(s);
    const pair = try Pair.init(gpa, .{ .client_suites = list, .server_suites = list, .client_cid = if (cids) "c1" else null, .server_cid = if (cids) "srv-12" else null });
    defer pair.deinit();
    try pair.run();
    var out: [256]u8 = undefined;
    const genuine = try pair.client.dtls.write("genuine", &out);
    var seed: [256]u8 = undefined;
    @memcpy(seed[0..genuine.len], genuine);
    const seeds = [_][]const u8{seed[0..genuine.len]};
    var bytes: [512]u8 = undefined;
    for (0..8) |_| {
        const input = inputs.draw(case, &bytes, &seeds, 64);
        const same = std.mem.eql(u8, input, seed[0..genuine.len]);
        try pair.server.dtls.receive(input, pair.now);
        // Only the genuine record, once, is ever read.
        if (pair.server.dtls.read()) |plain| {
            try std.testing.expect(same);
            try std.testing.expectEqualSlices(u8, "genuine", plain);
        }
    }
    try std.testing.expect(pair.server.dtls.failure() == null);
    try std.testing.expectEqual(Datagram.Phase.connected, pair.server.dtls.phase());
}

test "C8 fuzz the cookie check: bounded answers, no admission without a cookie" {
    try shakedown.check(gpa, {}, fuzzCookies, .{ .cases = 64 });
}

fn fuzzCookies(_: void, case: *shakedown.Case) !void {
    var cookies: Cookies = .{};
    defer cookies.deinit();
    try cookies.rotate(@splat(9));
    // With ECH keys, half the cases: the check then opens a hello's ECH as well.
    var keys: EchKeys = undefined;
    try keys.init(6, 4, "public.example.org");
    defer keys.deinit();
    const ech = shakedown.gen.boolean(case.source);
    const pair = try Pair.init(gpa, .{ .client_suites = if (ech) suites.Suite.tls13_only else suites.Suite.default, .client_ech = if (ech) .{ .config_list = keys.list } else .off, .server_ech = if (ech) &.{keys.key()} else &.{} });
    defer pair.deinit();
    // A real first hello as a seed.
    try pair.serveClient();
    var hello_out: [2048]u8 = undefined;
    const hello = (try pair.client.dtls.send(&hello_out, pair.now)).?;
    // The hello whole, and its first fragment.
    var fragment: [2048]u8 = undefined;
    @memcpy(fragment[0..hello.len], hello);
    const keep = @min(hello.len - Record.header12 - 12, 70);
    std.mem.writeInt(u24, fragment[Record.header12 + 9 ..][0..3], @intCast(keep), .big);
    std.mem.writeInt(u16, fragment[11..13], @intCast(12 + keep), .big);
    const seeds = [_][]const u8{ hello, examples[0], fragment[0 .. Record.header12 + 12 + keep] };
    var bytes: [2048]u8 = undefined;
    const input = inputs.draw(case, &bytes, &seeds, 128);
    var out: [8192]u8 = undefined;
    // A server of both versions, or of DTLS 1.2 alone, which answers hello fragments too.
    var options = pair.serverOptions();
    if (shakedown.gen.boolean(case.source)) options.max_version = .tls12;
    switch (cookies.check(gpa, &options, "addr", pair.now, input, &out)) {
        .respond => |answer| try std.testing.expect(answer.len <= 3 * input.len),
        // No hello the client sent carries a cookie of this key: nothing is admitted.
        .admit => return error.AdmittedWithoutCookie,
        .drop => {},
    }
}
