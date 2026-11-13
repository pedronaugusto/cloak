const std = @import("std");
const shakedown = @import("shakedown");
const suites = @import("../crypto/Suite.zig");
const Ticket = @import("Ticket.zig");
const TicketKeys = @import("TicketKeys.zig");
const types = @import("../../certificates.zig").types;

fn sample() Ticket.State {
    var state: Ticket.State = .{ .suite = .aes_256_gcm_sha384, .issued = 1000, .expires = 2000, .age_add = 0x01020304, .policy = @splat(9), .client_authenticated = true, .auth_expires = 1500 };
    @memset(state.secret.exposeMut(), 0x5a);
    @memcpy(state.alpn[0..2], "h2");
    state.alpn_len = 2;
    @memcpy(state.server_name[0..11], "example.com");
    state.server_name_len = 11;
    return state;
}

test "C5 ticket seals and opens the session state under its ring key alone" {
    var keys = try TicketKeys.init(std.testing.allocator, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(3)), types.instant(1000));
    var snapshot = keys.acquire().?;
    defer snapshot.release();
    var state = sample();
    defer state.deinit();
    var buffer: [Ticket.max_length]u8 = undefined;
    const sealed = try Ticket.seal(snapshot.ring().issuing(1000).?, &@as([16]u8, @splat(4)), &state, &buffer);
    var opened: Ticket.State = undefined;
    try Ticket.open(snapshot.ring(), sealed, 1001, &opened);
    defer opened.deinit();
    try std.testing.expectEqual(state.suite, opened.suite);
    try std.testing.expectEqualSlices(u8, state.secretBytes(), opened.secretBytes());
    try std.testing.expectEqualSlices(u8, "h2", opened.alpnBytes());
    try std.testing.expectEqualSlices(u8, "example.com", opened.serverName());
    try std.testing.expect(opened.client_authenticated);
    try std.testing.expectEqual(@as(i64, 1500), opened.auth_expires);
    try std.testing.expect(!opened.server_raw);
    // The server's form is kept beside the client's authentication (F143), each pin form too.
    for ([_]?u16{ null, 7 }) |pin| {
        var raw = sample();
        defer raw.deinit();
        raw.server_raw = true;
        raw.client_pin = pin;
        var raw_buffer: [Ticket.max_length]u8 = undefined;
        const raw_sealed = try Ticket.seal(snapshot.ring().issuing(1000).?, &@as([16]u8, @splat(6)), &raw, &raw_buffer);
        var raw_opened: Ticket.State = undefined;
        try Ticket.open(snapshot.ring(), raw_sealed, 1001, &raw_opened);
        defer raw_opened.deinit();
        try std.testing.expect(raw_opened.server_raw and raw_opened.client_authenticated);
        try std.testing.expectEqual(pin, raw_opened.client_pin);
    }
    // The PSK is not in the clear.
    try std.testing.expect(std.mem.find(u8, sealed, state.secretBytes()) == null);
    // Every flipped bit, a truncation and a wrong version refuse.
    var copy: [Ticket.max_length]u8 = undefined;
    for (0..sealed.len * 8) |bit| {
        @memcpy(copy[0..sealed.len], sealed);
        copy[bit / 8] ^= @as(u8, 1) << @intCast(bit % 8);
        var ignored: Ticket.State = undefined;
        try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), copy[0..sealed.len], 1001, &ignored));
    }
    var ignored: Ticket.State = undefined;
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), sealed[0 .. sealed.len - 1], 1001, &ignored));
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), "", 1001, &ignored));
    // Another salt is another key: the same state seals to unrelated bytes.
    var other_buffer: [Ticket.max_length]u8 = undefined;
    const other = try Ticket.seal(snapshot.ring().issuing(1000).?, &@as([16]u8, @splat(5)), &state, &other_buffer);
    try std.testing.expect(!std.mem.eql(u8, sealed[25..], other[25..]));
}

test "C5 ticket property: a sealed state opens whole under its key, and any change, cut or other key is the one refusal" {
    // Ticket.open's promise: opened only by the ring key that sealed it, and every failure is the
    // same refusal (an unknown, retired, forged or malformed ticket), never a state.
    try shakedown.check(std.testing.allocator, {}, sealedState, .{ .cases = 256, .seed = 0x7c5e });
}
fn sealedState(_: void, case: *shakedown.Case) !void {
    var keys = try TicketKeys.init(std.testing.allocator, .{});
    defer keys.deinit();
    var material: [32]u8 = undefined;
    for (&material) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    try keys.rotate(&material, types.instant(1000));
    var snapshot = keys.acquire().?;
    defer snapshot.release();

    const all = std.enums.values(suites.Suite);
    const suite = all[shakedown.gen.intRange(case.source, usize, 0, all.len - 1)];
    const version: suites.Version = if (suite.tls13() != null) .tls13 else if (suite.tls12() != null) .tls12 else return;
    var state: Ticket.State = .{
        .version = version,
        .datagram = shakedown.gen.intRange(case.source, u1, 0, 1) == 1,
        .suite = suite,
        .issued = 1000,
        // A lifetime a ring issues: at most TicketKeys.max_lifetime, which open holds it to.
        .expires = 1000 + @as(i64, shakedown.gen.intRange(case.source, u32, 1, TicketKeys.max_lifetime)),
        .age_add = shakedown.gen.int(case.source, u32),
        .policy = undefined,
        .client_authenticated = shakedown.gen.intRange(case.source, u1, 0, 1) == 1,
        .auth_expires = shakedown.gen.intRange(case.source, i64, 0, 1 << 30),
        .server_raw = shakedown.gen.intRange(case.source, u1, 0, 1) == 1,
    };
    defer state.deinit();
    for (&state.policy) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    for (state.secret.exposeMut()) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    state.alpn_len = shakedown.gen.intRange(case.source, u8, 0, 32);
    for (state.alpn[0..state.alpn_len]) |*byte| byte.* = shakedown.gen.intRange(case.source, u8, 0x21, 0x7e);
    state.server_name_len = shakedown.gen.intRange(case.source, u8, 0, 64);
    for (state.server_name[0..state.server_name_len]) |*byte| byte.* = shakedown.gen.intRange(case.source, u8, 'a', 'z');
    var salt: [16]u8 = undefined;
    for (&salt) |*byte| byte.* = shakedown.gen.int(case.source, u8);

    var buffer: [Ticket.max_length]u8 = undefined;
    const sealed = try Ticket.seal(snapshot.ring().issuing(1000).?, &salt, &state, &buffer);
    var opened: Ticket.State = undefined;
    try Ticket.open(snapshot.ring(), sealed, 1001, &opened);
    defer opened.deinit();
    try std.testing.expectEqual(state.version, opened.version);
    try std.testing.expectEqual(state.datagram, opened.datagram);
    try std.testing.expectEqual(state.suite, opened.suite);
    try std.testing.expectEqualSlices(u8, state.secretBytes(), opened.secretBytes());
    try std.testing.expectEqual(state.expires, opened.expires);
    try std.testing.expectEqual(state.age_add, opened.age_add);
    try std.testing.expectEqualSlices(u8, state.alpnBytes(), opened.alpnBytes());
    try std.testing.expectEqualSlices(u8, state.serverName(), opened.serverName());
    try std.testing.expectEqual(state.client_authenticated, opened.client_authenticated);
    try std.testing.expectEqual(state.server_raw, opened.server_raw);
    try std.testing.expectEqualSlices(u8, &state.policy, &opened.policy);

    var refused: Ticket.State = undefined;
    // One byte changed anywhere: the format, the key id, the salt, the body or the tag.
    var changed: [Ticket.max_length]u8 = undefined;
    @memcpy(changed[0..sealed.len], sealed);
    changed[shakedown.gen.intRange(case.source, usize, 0, sealed.len - 1)] ^= shakedown.gen.intRange(case.source, u8, 1, 255);
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), changed[0..sealed.len], 1001, &refused));
    // Its format byte naming another version or carrier (1 and 3 a TLS 1.3 PSK over a stream and
    // over datagrams, 2 and 4 a TLS 1.2 master secret): a ticket of one is never opened as another.
    for ([_]u8{ 1, 2, 3, 4 }) |format| {
        if (format == sealed[0]) continue;
        @memcpy(changed[0..sealed.len], sealed);
        changed[0] = format;
        try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), changed[0..sealed.len], 1001, &refused));
    }
    // Cut short anywhere.
    try std.testing.expectError(error.Undecryptable, Ticket.open(snapshot.ring(), sealed[0..shakedown.gen.intRange(case.source, usize, 0, sealed.len - 1)], 1001, &refused));
    // Under another ring's key, the same bytes are no ticket of its.
    var other_keys = try TicketKeys.init(std.testing.allocator, .{});
    defer other_keys.deinit();
    material[0] ^= 1;
    try other_keys.rotate(&material, types.instant(1000));
    var other = other_keys.acquire().?;
    defer other.release();
    try std.testing.expectError(error.Undecryptable, Ticket.open(other.ring(), sealed, 1001, &refused));
}
