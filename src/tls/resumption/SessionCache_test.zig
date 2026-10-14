const std = @import("std");
const SessionCache = @import("SessionCache.zig");

fn fields(key: *const [32]u8, ticket: []const u8, expires: i64) SessionCache.Fields {
    return .{ .key = key, .ticket = ticket, .suite = .aes_128_gcm_sha256, .psk = &@as([32]u8, @splat(1)), .age_add = 7, .received_ms = 0, .expires = expires, .origin = 0, .auth_expires = expires, .authenticated = true };
}

test "C5 session cache: newest first, used once, expired dropped, bounded per key" {
    var cache = try SessionCache.init(std.testing.allocator, .{ .per_key = 2 });
    defer cache.deinit();
    const a: [32]u8 = @splat(1);
    const b: [32]u8 = @splat(2);
    try cache.store(fields(&a, "one", 100));
    try cache.store(fields(&a, "two", 100));
    try cache.store(fields(&a, "three", 100));
    try cache.store(fields(&b, "other", 100));
    try std.testing.expectEqual(@as(usize, 3), cache.count());
    var taken = cache.take(&a, 50).?;
    try std.testing.expectEqualSlices(u8, "three", taken.entry.ticket);
    taken.release();
    taken = cache.take(&a, 50).?;
    try std.testing.expectEqualSlices(u8, "two", taken.entry.ticket);
    taken.release();
    try std.testing.expect(cache.take(&a, 50) == null);
    try std.testing.expect(cache.take(&b, 100) == null); // expired, and dropped
    try std.testing.expectEqual(@as(usize, 0), cache.count());
}

test "C5 session cache bounds entries and bytes and clears" {
    var cache = try SessionCache.init(std.testing.allocator, .{ .max_entries = 3, .per_key = 4 });
    defer cache.deinit();
    var key: [32]u8 = @splat(0);
    for (0..10) |i| {
        key[0] = @intCast(i);
        try cache.store(fields(&key, "ticket", 100));
    }
    try std.testing.expectEqual(@as(usize, 3), cache.count());
    key[0] = 0;
    try std.testing.expect(cache.take(&key, 0) == null);
    key[0] = 9;
    var newest = cache.take(&key, 0).?;
    newest.release();
    try std.testing.expectError(error.TicketTooLong, cache.store(fields(&key, "", 100)));
    var long: [SessionCache.max_ticket + 1]u8 = @splat(1);
    try std.testing.expectError(error.TicketTooLong, cache.store(fields(&key, &long, 100)));
    cache.clear();
    try std.testing.expectEqual(@as(usize, 0), cache.count());
    var small = try SessionCache.init(std.testing.allocator, .{ .max_bytes = @sizeOf(SessionCache.Entry) + 100 });
    defer small.deinit();
    try small.store(fields(&key, &(@as([60]u8, @splat(2))), 100));
    try small.store(fields(&key, &(@as([60]u8, @splat(3))), 100));
    try std.testing.expectEqual(@as(usize, 1), small.count());
}
