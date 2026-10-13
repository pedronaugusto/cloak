const std = @import("std");
const Rsa = @import("Rsa.zig");
const Entropy = @import("Entropy.zig");
const Pem = @import("Pem.zig");
test "credential complete RSA CRT fields reject tampering" {
    @setRuntimeSafety(true);
    var pem = Pem.init(@embedFile("testdata/rsa.pkcs1.pem"));
    var block = (try pem.next(std.testing.allocator, 65536)).?;
    defer block.deinit(std.testing.allocator);
    var key: Rsa.Key = undefined;
    try Rsa.parse(block.der, .{ .entropy = Entropy.fromIo(&std.testing.io) }, &key);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    block.der[block.der.len - 1] ^= 2;
    var tampered: Rsa.Key = undefined;
    try std.testing.expectError(error.InvalidKey, Rsa.parse(block.der, .{ .entropy = Entropy.fromIo(&std.testing.io) }, &tampered));
}

test "credential RSA mathematical congruence does not permit out of range secret integers" {
    @setRuntimeSafety(true);
    for ([_][]const u8{ @embedFile("testdata/rsa.invalid-qinv-range.der"), @embedFile("testdata/rsa.invalid-d-range.der") }) |encoded| {
        var key: Rsa.Key = undefined;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        try std.testing.expectError(error.InvalidKey, Rsa.parse(encoded, .{ .entropy = Entropy.fromIo(&std.testing.io) }, &key));
    }
}
