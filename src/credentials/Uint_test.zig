const std = @import("std");
const shakedown = @import("shakedown");
const U = @import("Uint.zig");
test "credential fixed integer arithmetic agrees with independent u128 subtraction and addition" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, property, .{ .cases = 512 });
}
fn property(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    const pair = .{ shakedown.gen.int(case.source, u64), shakedown.gen.int(case.source, u64) };
    var encoded: [16]u8 = undefined;
    std.mem.writeInt(u128, &encoded, pair[0], .big);
    var a = U.zero;
    try U.decode(&a, &encoded);
    std.mem.writeInt(u128, &encoded, pair[1], .big);
    var b = U.zero;
    try U.decode(&b, &encoded);
    try std.testing.expectEqual(pair[0] < pair[1], a.less(&b));
    a.addSmall(pair[1]);
    U.encode(&a, &encoded);
    try std.testing.expectEqual(@as(u128, pair[0]) + pair[1], std.mem.readInt(u128, &encoded, .big));
    try std.testing.expectEqual(@as(u1, 0), a.subWithOverflow(&b));
    U.encode(&a, &encoded);
    try std.testing.expectEqual(@as(u128, pair[0]), std.mem.readInt(u128, &encoded, .big));
}

test "credential fixed integer full width decoding and borrows agree with the public arithmetic oracle" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, wide, .{ .cases = 128 });
}
fn wide(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    const widths = [_]usize{ 1, 3, 4, 7, 8, 9, 31, 63, 64, 127, 255, 256, 511, 512, 1023, 1024 };
    const length = widths[shakedown.gen.intRange(case.source, usize, 0, widths.len - 1)];
    var ax: [1024]u8 = undefined;
    var bx: [1024]u8 = undefined;
    for (ax[0..length], bx[0..length]) |*a, *b| {
        a.* = shakedown.gen.int(case.source, u8);
        b.* = shakedown.gen.int(case.source, u8);
    }
    var a = U.zero;
    var b = U.zero;
    try U.decode(&a, ax[0..length]);
    try U.decode(&b, bx[0..length]);
    var got: [1024]u8 = undefined;
    U.encode(&a, got[0..length]);
    try std.testing.expectEqualSlices(u8, ax[0..length], got[0..length]);
    const Oracle = std.crypto.ff.Uint(8192);
    var oa = try Oracle.fromBytes(ax[0..length], .big);
    const ob = try Oracle.fromBytes(bx[0..length], .big);
    try std.testing.expectEqual(oa.compare(ob) == .lt, a.less(&b));
    const borrow = a.subWithOverflow(&b);
    try std.testing.expectEqual(oa.subWithOverflow(ob), borrow);
    if (borrow == 0) {
        var expected: [1024]u8 = undefined;
        try oa.toBytes(&expected, .big);
        U.encode(&a, &got);
        try std.testing.expectEqualSlices(u8, &expected, &got);
    }
}
