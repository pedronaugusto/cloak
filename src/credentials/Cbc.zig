//! AES-CBC for offline key files. Fixed GF arithmetic; no secret table index
//! and no dependence on the consumer's std side-channel configuration.
const std = @import("std");
pub const Error = error{ InvalidCiphertext, BadPassword };
pub fn decrypt(key: []const u8, iv: [16]u8, encrypted: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if ((key.len != 16 and key.len != 24 and key.len != 32) or encrypted.len == 0 or encrypted.len % 16 != 0 or out.len != encrypted.len) return error.InvalidCiphertext;
    errdefer std.crypto.secureZero(u8, out);
    // The AES instructions take no secret index whatever std's options say: where the target has
    // them, std's AES-128 and AES-256 run on them (AES-192 has no std context).
    if (comptime aes.has_hardware_support) switch (key.len) {
        16 => return unpad(hardware(aes.Aes128, key[0..16], iv, encrypted, out)),
        32 => return unpad(hardware(aes.Aes256, key[0..32], iv, encrypted, out)),
        else => {},
    };
    return software(key, iv, encrypted, out);
}
/// The fixed-arithmetic AES, for targets without the instructions and for AES-192.
fn software(key: []const u8, iv: [16]u8, encrypted: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
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
    return unpad(out);
}
const aes = std.crypto.core.aes;
/// CBC decryption on the AES instructions, eight blocks at a time; the round keys are erased.
fn hardware(comptime Aes: type, key: *const [Aes.key_bits / 8]u8, iv: [16]u8, encrypted: []const u8, out: []u8) []u8 {
    @setRuntimeSafety(true);
    var ctx = Aes.initDec(key.*);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ctx));
    const wide = 8;
    var at: usize = 0;
    while (at + 16 * wide <= encrypted.len) : (at += 16 * wide) {
        ctx.decryptWide(wide, out[at..][0 .. 16 * wide], encrypted[at..][0 .. 16 * wide]);
    }
    while (at < encrypted.len) : (at += 16) ctx.decrypt(out[at..][0..16], encrypted[at..][0..16]);
    for (out[0..16], iv) |*b, v| b.* ^= v;
    for (out[16..], encrypted[0 .. encrypted.len - 16]) |*b, c| b.* ^= c;
    return out;
}
/// The PKCS#7 padding, checked in constant time; the plaintext without it.
fn unpad(out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    errdefer std.crypto.secureZero(u8, out);
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

test "credential AES-CBC on the instructions and in fixed arithmetic agree" {
    var iv: [16]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @truncate(i * 13 + 5);
    var message: [16 * 19 - 5]u8 = undefined;
    for (&message, 0..) |*b, i| b.* = @truncate(i * 31 + 3);
    var padded: [16 * 19]u8 = undefined;
    @memcpy(padded[0..message.len], &message);
    @memset(padded[message.len..], 5);
    inline for (.{ aes.Aes128, aes.Aes256 }) |Aes| {
        var key: [Aes.key_bits / 8]u8 = undefined;
        for (&key, 0..) |*b, i| b.* = @truncate(i * 7 + 1);
        // CBC encryption through std, so neither decryptor checks itself.
        const ctx = Aes.initEnc(key);
        var cipher: [padded.len]u8 = undefined;
        var previous = iv;
        for (0..padded.len / 16) |i| {
            var block: [16]u8 = undefined;
            for (&block, padded[i * 16 ..][0..16], previous) |*o, p, v| o.* = p ^ v;
            ctx.encrypt(cipher[i * 16 ..][0..16], &block);
            previous = cipher[i * 16 ..][0..16].*;
        }
        var a: [padded.len]u8 = undefined;
        var b: [padded.len]u8 = undefined;
        try std.testing.expectEqualSlices(u8, &message, try decrypt(&key, iv, &cipher, &a));
        try std.testing.expectEqualSlices(u8, &message, try software(&key, iv, &cipher, &b));
    }
}
