//! Synthetic public scalar oracle checks; failure output never prints material.
const std = @import("std");
const Curve = @import("Curve.zig");
const shakedown = @import("shakedown");
test "credential curve borrowed scalar matches independent std base multiplication" {
    try shakedown.check(std.testing.allocator, {}, differential, .{ .cases = 96, .seed = 0xc1b017 });
}
fn differential(_: void, case: *shakedown.Case) !void {
    inline for (.{ std.crypto.ecc.P256, std.crypto.ecc.P384, std.crypto.ecc.Edwards25519 }) |Point| {
        var scalar: [@sizeOf(Point.scalar.CompressedScalar)]u8 = undefined;
        defer std.crypto.secureZero(u8, &scalar);
        for (&scalar) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var actual = try Curve.base(Point, .little, &scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&actual));
        var expected = if (Point == std.crypto.ecc.Edwards25519) try Point.basePoint.mul(scalar) else try Point.basePoint.mul(scalar, .little);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&expected));
        try std.testing.expect(if (Point == std.crypto.ecc.Edwards25519) std.mem.eql(u8, &actual.toBytes(), &expected.toBytes()) else actual.equivalent(expected));
        if (Point != std.crypto.ecc.Edwards25519) {
            std.mem.reverse(u8, &scalar);
            var big = try Curve.base(Point, .big, &scalar);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&big));
            try std.testing.expect(big.equivalent(expected));
        }
    }
}
test "credential curve zero and subgroup order reject with cleanup" {
    inline for (.{ std.crypto.ecc.P256, std.crypto.ecc.P384, std.crypto.ecc.Edwards25519 }) |Point| {
        var scalar: [@sizeOf(Point.scalar.CompressedScalar)]u8 = @splat(0);
        defer std.crypto.secureZero(u8, &scalar);
        try std.testing.expectError(error.IdentityElement, Curve.base(Point, .little, &scalar));
        std.mem.writeInt(@Int(.unsigned, scalar.len * 8), &scalar, Point.scalar.field_order, .little);
        try std.testing.expectError(error.IdentityElement, Curve.base(Point, .little, &scalar));
    }
}

test "credential SEC1 rejects congruent out of range P256 and P384 scalars" {
    const Key = @import("Key.zig");
    inline for (.{ std.crypto.ecc.P256, std.crypto.ecc.P384 }, .{ "\x2a\x86\x48\xce\x3d\x03\x01\x07", "\x2b\x81\x04\x00\x22" }) |Point, oid| {
        const n = @sizeOf(Point.scalar.CompressedScalar);
        var der: [7 + n + 4 + oid.len]u8 = undefined;
        defer std.crypto.secureZero(u8, &der);
        der[0..7].* = .{ 0x30, der.len - 2, 2, 1, 1, 4, n };
        std.mem.writeInt(@Int(.unsigned, n * 8), der[7..][0..n], Point.scalar.field_order + 1, .big);
        der[7 + n ..][0..4].* = .{ 0xa0, oid.len + 2, 6, oid.len };
        @memcpy(der[11 + n ..], oid);
        const rejected = if (Key.parse(std.testing.allocator, &der, .{})) |value| blk: {
            var material = value;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&material));
            break :blk false;
        } else |err| err == error.InvalidKey;
        try std.testing.expect(rejected);
    }
}
