const std = @import("std");
const shakedown = @import("shakedown");
const M = @import("Montgomery.zig");
test "credential Montgomery independent public integer arithmetic property" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, property, .{ .cases = 512 });
}
fn property(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    const modulus: u64 = shakedown.gen.int(case.source, u64) | 3;
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(u64, &encoded, modulus, .big);
    const leading = @clz(modulus) / 8;
    var m = try M.init(encoded[leading..]);
    defer m.deinit();
    const a = shakedown.gen.int(case.source, u64) % modulus;
    const b = shakedown.gen.int(case.source, u64) % modulus;
    var x: M.Number = @splat(0);
    x[0] = @truncate(a); // safe: split the public u64 differential input into low and high radix-2^32 words
    x[1] = @truncate(a >> 32); // safe: split the public u64 differential input into low and high radix-2^32 words
    var y: M.Number = @splat(0);
    y[0] = @truncate(b); // safe: split the public u64 differential input into low and high radix-2^32 words
    y[1] = @truncate(b >> 32); // safe: split the public u64 differential input into low and high radix-2^32 words
    var product: M.Number = undefined;
    m.convert(&x, &x);
    m.convert(&y, &y);
    m.multiply(&product, &x, &y);
    var one: M.Number = @splat(0);
    one[0] = 1;
    m.multiply(&product, &product, &one);
    const wanted: u64 = @intCast(@as(u128, a) * b % modulus); // safe: the remainder is below the u64 modulus
    try std.testing.expectEqual(wanted, @as(u64, product[1]) << 32 | product[0]);
}
