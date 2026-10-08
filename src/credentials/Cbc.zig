//! AES-CBC for offline key files. Fixed GF arithmetic; no secret table index
//! and no dependence on the consumer's std side-channel configuration.
const std = @import("std");
pub const Error = error{ InvalidCiphertext, BadPassword };
pub fn decrypt(key: []const u8, iv: [16]u8, encrypted: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if ((key.len != 16 and key.len != 24 and key.len != 32) or encrypted.len == 0 or encrypted.len % 16 != 0 or out.len != encrypted.len) return error.InvalidCiphertext;
    errdefer std.crypto.secureZero(u8, out);
    var schedule: [240]u8 = undefined;
    defer std.crypto.secureZero(u8, &schedule);
    const rounds = expand(key, &schedule);
    var previous = iv;
    for (0..encrypted.len / 16) |i| {
        const cipher = encrypted[i * 16 ..][0..16].*;
        var block = cipher;
        defer std.crypto.secureZero(u8, &block);
        inverse(&block, schedule[0 .. 16 * (rounds + 1)], rounds);
        for (&block, previous) |*b, p| b.* ^= p;
        @memcpy(out[i * 16 ..][0..16], &block);

        previous = cipher;
    }
    const padding: usize = out[out.len - 1];
    var bad: u8 = @intFromBool(padding == 0) | @intFromBool(padding > 16);
    for (0..16) |i| {
        const mask: u8 = 0 -% @as(u8, @intFromBool(i < padding));
        bad |= mask & (out[out.len - 1 - i] ^ @as(u8, @intCast(padding))); // safe: padding is one u8 from the final plaintext byte
    }
    // safe: expose only the completed padding verdict required by the offline parser API.
    if (bad != 0) return error.BadPassword;
    return out[0 .. out.len - padding];
}
fn multiply(a_: u8, b_: u8) u8 {
    @setRuntimeSafety(true);
    var a = a_;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&a));
    var b = b_;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&b));
    var product: u8 = 0;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
    for (0..8) |_| {
        product ^= a & (0 -% (b & 1));
        a = (a << 1) ^ (0x1b & (0 -% (a >> 7)));
        b >>= 1;
    }
    return product;
}
fn invert(x: u8) u8 {
    @setRuntimeSafety(true);
    var power = x;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&power));
    var result: u8 = 1;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
    inline for (0..8) |i| {
        if (i != 0) result = multiply(result, power);
        power = multiply(power, power);
    }
    return result;
}
fn substitute(x: u8) u8 {
    @setRuntimeSafety(true);
    const v = invert(x);
    return v ^ std.math.rotl(u8, v, 1) ^ std.math.rotl(u8, v, 2) ^ std.math.rotl(u8, v, 3) ^ std.math.rotl(u8, v, 4) ^ 0x63;
}
fn unsubstitute(x: u8) u8 {
    @setRuntimeSafety(true);
    return invert(std.math.rotl(u8, x, 1) ^ std.math.rotl(u8, x, 3) ^ std.math.rotl(u8, x, 6) ^ 0x05);
}
fn expand(key: []const u8, out: *[240]u8) usize {
    @setRuntimeSafety(true);
    const rounds = key.len / 4 + 6;
    @memcpy(out[0..key.len], key);
    var at = key.len;
    var rc: u8 = 1;
    while (at < 16 * (rounds + 1)) : (at += 4) {
        var word = out[at - 4 ..][0..4].*;
        if (at % key.len == 0) {
            var first = word[0];
            defer std.crypto.secureZero(u8, std.mem.asBytes(&first));
            word[0] = substitute(word[1]) ^ rc;
            word[1] = substitute(word[2]);
            word[2] = substitute(word[3]);
            word[3] = substitute(first);
            rc = multiply(rc, 2);
        } else if (key.len == 32 and at % key.len == 16) for (&word) |*b| {
            b.* = substitute(b.*);
        };
        for (0..4) |j| out[at + j] = out[at - key.len + j] ^ word[j];
        std.crypto.secureZero(u8, &word);
    }
    return rounds;
}
fn addKey(block: *[16]u8, key: []const u8) void {
    @setRuntimeSafety(true);
    for (block, key) |*b, k| b.* ^= k;
}
fn inverse(block: *[16]u8, schedule: []const u8, rounds: usize) void {
    @setRuntimeSafety(true);
    addKey(block, schedule[rounds * 16 ..][0..16]);
    var round = rounds;
    while (round > 0) {
        round -= 1;
        var prior = block.*;
        defer std.crypto.secureZero(u8, &prior);
        for (0..4) |column| for (0..4) |row| {
            block[column * 4 + row] = unsubstitute(prior[((column + 4 - row) % 4) * 4 + row]);
        };
        addKey(block, schedule[round * 16 ..][0..16]);
        if (round == 0) break;
        for (0..4) |column| {
            const i = column * 4;
            var a = block[i..][0..4].*;
            defer std.crypto.secureZero(u8, &a);
            block[i] = multiply(a[0], 14) ^ multiply(a[1], 11) ^ multiply(a[2], 13) ^ multiply(a[3], 9);
            block[i + 1] = multiply(a[0], 9) ^ multiply(a[1], 14) ^ multiply(a[2], 11) ^ multiply(a[3], 13);
            block[i + 2] = multiply(a[0], 13) ^ multiply(a[1], 9) ^ multiply(a[2], 14) ^ multiply(a[3], 11);
            block[i + 3] = multiply(a[0], 11) ^ multiply(a[1], 13) ^ multiply(a[2], 9) ^ multiply(a[3], 14);
        }
    }
}
test {
    @setRuntimeSafety(true);
    _ = @import("Cbc_test.zig");
}
