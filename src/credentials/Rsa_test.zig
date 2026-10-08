const std = @import("std");
const Rsa = @import("Rsa.zig");
const Entropy = @import("Entropy.zig");
const Pem = @import("Pem.zig");
test "credential complete RSA CRT fields reject tampering" {
    @setRuntimeSafety(true);
    var pem = Pem.init(@embedFile("testdata/rsa.pkcs1.pem"));
    var block = (try pem.next(std.testing.allocator, 65536)).?;
    defer block.deinit(std.testing.allocator);
    var key = try Rsa.parse(block.der, .{ .entropy = Entropy.fromIo(&std.testing.io) });
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    block.der[block.der.len - 1] ^= 2;
    try std.testing.expectError(error.InvalidKey, Rsa.parse(block.der, .{ .entropy = Entropy.fromIo(&std.testing.io) }));
}

test "credential RSA mathematical congruence does not permit out of range secret integers" {
    @setRuntimeSafety(true);
    for ([_][]const u8{ @embedFile("testdata/rsa.invalid-qinv-range.der"), @embedFile("testdata/rsa.invalid-d-range.der") }) |encoded| {
        const result = Rsa.parse(encoded, .{ .entropy = Entropy.fromIo(&std.testing.io) });
        if (result) |material| {
            var unexpected = material;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&unexpected));
            return error.TestUnexpectedResult;
        } else |err| try std.testing.expectEqual(error.InvalidKey, err);
    }
}
