//! Offline 3DES decryption, FIPS 46-3 Appendix 1. Every S-box entry is
//! visited through volatile public indices; secrets select with masks.
const std = @import("std");
pub const Error = error{ InvalidCiphertext, BadPassword };
pub fn decrypt(key: *const [24]u8, iv: [8]u8, encrypted: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (encrypted.len == 0 or encrypted.len % 8 != 0 or out.len != encrypted.len) return error.InvalidCiphertext;
    errdefer std.crypto.secureZero(u8, out);
    var keys: [3][16]u64 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
    for (0..3) |i| schedule(&keys[i], key[i * 8 ..][0..8]);
    var previous = std.mem.readInt(u64, &iv, .big);
    for (0..encrypted.len / 8) |i| {
        const encoded = std.mem.readInt(u64, encrypted[i * 8 ..][0..8], .big);
        var plain = block(block(block(encoded, &keys[2], true), &keys[1], false), &keys[0], true) ^ previous;
        std.mem.writeInt(u64, out[i * 8 ..][0..8], plain, .big);
        std.crypto.secureZero(u8, std.mem.asBytes(&plain));
        previous = encoded;
    }
    const padding: usize = out[out.len - 1];
    var bad: u8 = @intFromBool(padding == 0) | @intFromBool(padding > 8);
    for (0..8) |i| bad |= (0 -% @as(u8, @intFromBool(i < padding))) & (out[out.len - 1 - i] ^ @as(u8, @intCast(padding))); // safe: padding is one u8 from the final plaintext byte
    // safe: expose only the completed padding verdict required by the offline parser API.
    if (bad != 0) return error.BadPassword;
    return out[0 .. out.len - padding];
}
fn permutation(comptime width: usize, x: u64, table: []const u8) u64 {
    @setRuntimeSafety(true);
    var result: u64 = 0;
    for (table) |position| result = (result << 1) | ((x >> @as(u6, @intCast(width - position))) & 1); // safe: FIPS permutation positions are in 1..width, so the shift fits u6
    return result;
}
fn schedule(keys: *[16]u64, key: *const [8]u8) void {
    @setRuntimeSafety(true);
    var selected = permutation(64, std.mem.readInt(u64, key, .big), &pc1);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&selected));
    var left: u28 = @truncate(selected >> 28); // safe: split the PC1 result into two 28-bit halves
    var right: u28 = @truncate(selected); // safe: retain the low 28-bit PC1 half
    defer std.crypto.secureZero(u8, std.mem.asBytes(&left));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&right));
    for (shifts, 0..) |shift, i| {
        left = std.math.rotl(u28, left, shift);
        right = std.math.rotl(u28, right, shift);
        keys[i] = permutation(56, (@as(u64, left) << 28) | right, &pc2);
    }
}
fn block(encoded: u64, keys: *const [16]u64, reverse: bool) u64 {
    @setRuntimeSafety(true);
    var selected = permutation(64, encoded, &ip);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&selected));
    var left: u32 = @truncate(selected >> 32); // safe: split the initial permutation into 32-bit halves
    var right: u32 = @truncate(selected); // safe: retain the low 32-bit initial-permutation half
    defer std.crypto.secureZero(u8, std.mem.asBytes(&left));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&right));
    for (0..16) |i| {
        var temp = right;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&temp));
        right = left ^ feistel(right, keys[if (reverse) 15 - i else i]);
        left = temp;
    }
    return permutation(64, (@as(u64, right) << 32) | left, &fp);
}
fn feistel(right: u32, key: u64) u32 {
    @setRuntimeSafety(true);
    var expanded = permutation(32, right, &expansion) ^ key;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&expanded));
    var joined: u32 = 0;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&joined));
    for (0..8) |box| {
        var chunk: u8 = @truncate((expanded >> @as(u6, @intCast(42 - box * 6))) & 63); // safe: public box is in 0..7; retain its six expansion bits
        defer std.crypto.secureZero(u8, std.mem.asBytes(&chunk));
        var index = ((chunk & 32) >> 4) | (chunk & 1);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&index));
        var wanted = index * 16 + ((chunk >> 1) & 15);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&wanted));
        var selected: u8 = 0;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&selected));
        const table: *const volatile [64]u8 = &sboxes[box];
        for (0..64) |i| selected |= table[i] & (0 -% @as(u8, @intFromBool(i == wanted)));
        joined = (joined << 4) | selected;
    }
    return @truncate(permutation(32, joined, &p)); // safe: FIPS P permutation has exactly 32 output bits
}
const shifts = [_]u5{ 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
const ip = [_]u8{ 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7 };
const fp = [_]u8{ 40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25 };
const expansion = [_]u8{ 32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1 };
const p = [_]u8{ 16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25 };
const pc1 = [_]u8{ 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4 };
const pc2 = [_]u8{ 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32 };
const sboxes = [8][64]u8{
    .{ 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
    .{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
    .{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
    .{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
    .{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
    .{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 },
    .{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
    .{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 },
};
test "credential DES canonical block vector" {
    @setRuntimeSafety(true);
    const key = [_]u8{ 0x13, 0x34, 0x57, 0x79, 0x9b, 0xbc, 0xdf, 0xf1 };
    var keys: [16]u64 = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&keys));
    schedule(&keys, &key);
    const encoded = block(0x0123456789abcdef, &keys, false);
    try std.testing.expectEqual(@as(u64, 0x85e813540f0ab405), encoded);
    try std.testing.expectEqual(@as(u64, 0x0123456789abcdef), block(encoded, &keys, true));
}
