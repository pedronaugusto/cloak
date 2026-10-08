const std = @import("std");
const Cbc = @import("Cbc.zig");
test "credential AES CBC NIST SP800-38A and PKCS7 rejection" {
    @setRuntimeSafety(true);
    const key = std.fmt.hexToBytes;
    var k: [16]u8 = undefined;
    _ = try key(&k, "2b7e151628aed2a6abf7158809cf4f3c");
    var iv: [16]u8 = undefined;
    _ = try key(&iv, "000102030405060708090a0b0c0d0e0f");
    var ciphertext: [16]u8 = undefined;
    _ = try key(&ciphertext, "7649abac8119b246cee98e9b12e9197d");
    var plain: [16]u8 = undefined;
    try std.testing.expectError(error.BadPassword, Cbc.decrypt(&k, iv, &ciphertext, &plain));
    var wanted: [16]u8 = undefined;
    _ = try key(&wanted, "6bc1bee22e409f96e93d7e117393172a");
    try std.testing.expectEqualSlices(u8, &@as([16]u8, @splat(0)), &plain);
    var padded: [32]u8 = undefined;
    @memcpy(padded[0..16], &ciphertext);
    var padding: [16]u8 = @splat(16);
    for (&padding, ciphertext) |*a, b| a.* ^= b;
    std.crypto.core.aes.Aes128.initEnc(k).encrypt(padded[16..32], &padding);
    var recovered: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, &wanted, try Cbc.decrypt(&k, iv, &padded, &recovered));
}
