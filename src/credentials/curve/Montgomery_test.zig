//! Independent std-field oracle, canonical boundaries and in-place limb aliases.
const std = @import("std");
const Montgomery = @import("Montgomery.zig");
const shakedown = @import("shakedown");
test "credential Montgomery carry reduction and alias properties" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, differential, .{ .cases = 1024, .seed = 0xc1ca77 });
}
fn differential(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    inline for (.{ std.crypto.ecc.P256.Fe, std.crypto.ecc.P384.Fe }) |Public| {
        var bytes: [2][Public.encoded_length]u8 = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&bytes));
        for (&bytes) |*part| for (part) |*byte| {
            byte.* = shakedown.gen.int(case.source, u8);
        };
        const a = Public.fromBytes(bytes[0], .little) catch return;
        const b = Public.fromBytes(bytes[1], .little) catch return;
        try compare(Public, a, b);
    }
}
test "credential Montgomery prime and word boundary vectors" {
    @setRuntimeSafety(true);
    inline for (.{ std.crypto.ecc.P256.Fe, std.crypto.ecc.P384.Fe }) |Public| {
        inline for (.{ 0, 1, 2, 0xffffffffffffffff, 0x10000000000000000, Public.field_order / 2, Public.field_order - 2, Public.field_order - 1 }) |a| {
            inline for (.{ 0, 1, 0xffffffffffffffff, Public.field_order / 2, Public.field_order - 1 }) |b| {
                try compare(Public, try Public.fromInt(a), try Public.fromInt(b));
            }
        }
    }
}
fn compare(comptime Public: type, a: Public, b: Public) !void {
    @setRuntimeSafety(true);
    const field = Montgomery.Field(Public);
    var actual: field.MontgomeryDomainFieldElement = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
    field.add(&actual, a.limbs, b.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &a.add(b).limbs));
    field.sub(&actual, a.limbs, b.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &a.sub(b).limbs));
    field.mul(&actual, a.limbs, b.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &a.mul(b).limbs));
    field.square(&actual, a.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &a.sq().limbs));
    actual = a.limbs;
    field.mul(&actual, actual, b.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &a.mul(b).limbs));
    field.selectznz(&actual, 0, a.limbs, b.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &a.limbs));
    field.selectznz(&actual, 1, actual, b.limbs);
    try std.testing.expect(std.mem.eql(u64, &actual, &b.limbs));
}
