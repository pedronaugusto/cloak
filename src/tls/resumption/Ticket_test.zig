const std = @import("std");
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
