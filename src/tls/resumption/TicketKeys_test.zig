const std = @import("std");
const TicketKeys = @import("TicketKeys.zig");
const types = @import("../../certificates.zig").types;

fn at(s: i64) std.Io.Timestamp {
    return types.instant(s);
}

test "C5 ticket keys: rotation stops the old key issuing and keeps it opening until its tickets expire" {
    var keys = try TicketKeys.init(std.testing.allocator, .{ .lifetime = .fromSeconds(100), .rotation = .fromSeconds(10) });
    defer keys.deinit();
    try std.testing.expect(keys.acquire() == null);
    const first: [32]u8 = @splat(1);
    const second: [32]u8 = @splat(2);
    try keys.rotate(&first, at(1000));
    var snapshot = keys.acquire().?;
    const first_id = snapshot.ring().keys[0].id;
    try std.testing.expect(snapshot.ring().issuing(1000) != null);
    try std.testing.expect(snapshot.ring().issuing(1010) == null); // a forgotten rotation issues nothing
    try std.testing.expect(snapshot.ring().find(&first_id, 1109) != null);
    try std.testing.expect(snapshot.ring().find(&first_id, 1110) == null);
    snapshot.release();
    try keys.rotate(&second, at(1005));
    snapshot = keys.acquire().?;
    defer snapshot.release();
    const ring = snapshot.ring();
    try std.testing.expectEqual(@as(usize, 2), ring.count);
    try std.testing.expect(!std.mem.eql(u8, &ring.issuing(1005).?.id, &first_id));
    // The first key stopped issuing at 1005; its last ticket expires a lifetime later.
    try std.testing.expect(ring.find(&first_id, 1104) != null);
    try std.testing.expect(ring.find(&first_id, 1105) == null);
}

test "C5 ticket keys refuse missing, repeated and out-of-range material and options" {
    try std.testing.expectError(error.InvalidOptions, TicketKeys.init(std.testing.allocator, .{ .lifetime = .fromSeconds(8 * 24 * 3600) }));
    try std.testing.expectError(error.InvalidOptions, TicketKeys.init(std.testing.allocator, .{ .rotation = .fromSeconds(0) }));
    var keys = try TicketKeys.init(std.testing.allocator, .{});
    defer keys.deinit();
    try std.testing.expectError(error.InvalidKey, keys.rotate(&@as([32]u8, @splat(0)), at(1)));
    try keys.rotate(&@as([32]u8, @splat(7)), at(1));
    try std.testing.expectError(error.DuplicateKey, keys.rotate(&@as([32]u8, @splat(7)), at(2)));
}

test "C5 ticket keys drop keys past their tickets and hold at most eight" {
    var keys = try TicketKeys.init(std.testing.allocator, .{ .lifetime = .fromSeconds(1000), .rotation = .fromSeconds(10) });
    defer keys.deinit();
    var material: [32]u8 = @splat(0);
    for (0..20) |i| {
        material[0] = @intCast(i + 1);
        try keys.rotate(&material, at(@intCast(i)));
    }
    var snapshot = keys.acquire().?;
    defer snapshot.release();
    try std.testing.expectEqual(@as(usize, TicketKeys.max_keys), snapshot.ring().count);
    material[0] = 21;
    try keys.rotate(&material, at(5000));
    var later = keys.acquire().?;
    defer later.release();
    try std.testing.expectEqual(@as(usize, 1), later.ring().count);
}
