//! Offline RC2-CBC decryption (RFC 2268), for the certificates and keys of PKCS#12 files that
//! Windows and OpenSSL 1.x encrypted under pbeWithSHAAnd40BitRC2-CBC or -128BitRC2-CBC. Read
//! only, never negotiated (the legacy key-file rule). The key schedule's PITABLE lookups and the
//! mash rounds' key-word lookups take secret indices, so each scans its whole table and selects
//! with masks: no secret reaches an address. Secret temporaries live in aegis `Secret` owners;
//! `out` is the caller's secret owner, which erases it when decryption fails.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
pub const Error = error{ InvalidCiphertext, BadPassword };

/// Decrypts `encrypted` under `key` with `effective` key bits (40 or 128 for PKCS#12) in CBC
/// mode, checks the PKCS#5 padding in constant time and returns the plaintext within `out`.
pub fn decrypt(key: []const u8, effective: u10, iv: [8]u8, encrypted: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (key.len == 0 or key.len > 128 or effective == 0 or effective > 1024 or encrypted.len == 0 or encrypted.len % 8 != 0 or out.len != encrypted.len) return error.InvalidCiphertext;
    var owner: Secret(struct { k: [64]u16, block: [8]u8 }) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    expand(key, effective, &s.k);
    var previous = iv;
    for (0..encrypted.len / 8) |i| {
        const cipher = encrypted[i * 8 ..][0..8].*;
        s.block = decryptBlock(&s.k, cipher);
        for (&s.block, previous) |*b, p| b.* ^= p;
        @memcpy(out[i * 8 ..][0..8], &s.block);
        previous = cipher;
    }
    const padding: usize = out[out.len - 1];
    var bad: u8 = @intFromBool(padding == 0) | @intFromBool(padding > 8);
    for (0..8) |i| bad |= (0 -% @as(u8, @intFromBool(i < padding))) & (out[out.len - 1 - i] ^ @as(u8, @intCast(padding))); // padding is one u8 from the final plaintext byte
    // Expose only the completed padding verdict required by the offline parser API.
    if (bad != 0) return error.BadPassword;
    return out[0 .. out.len - padding];
}

const pitable = [256]u8{
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d,
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2,
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32,
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82,
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc,
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26,
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03,
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7,
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a,
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec,
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39,
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31,
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9,
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9,
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e,
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad,
};

/// PITABLE[index] by a scan of every entry.
fn pi(index: u8) u8 {
    @setRuntimeSafety(true);
    var result: u8 = 0;
    for (pitable, 0..) |entry, i| {
        const mask: u8 = @truncate((@as(u16, index ^ @as(u8, @truncate(i))) -% 1) >> 8);
        result |= entry & mask;
    }
    return result;
}

/// K[index & 63] by a scan of every word.
fn word(k: *const [64]u16, index: u16) u16 {
    @setRuntimeSafety(true);
    const wanted: u8 = @truncate(index & 63);
    var result: u16 = 0;
    for (k, 0..) |entry, i| {
        const mask: u16 = 0 -% @as(u16, @truncate((@as(u16, wanted ^ @as(u8, @truncate(i))) -% 1) >> 15));
        result |= entry & mask;
    }
    return result;
}

/// RFC 2268 section 2.
fn expand(key: []const u8, effective: u10, k: *[64]u16) void {
    @setRuntimeSafety(true);
    var owner: Secret([128]u8) = .init(@splat(0));
    defer owner.deinit();
    const l = owner.exposeMut();
    @memcpy(l[0..key.len], key);
    for (key.len..128) |i| l[i] = pi(l[i - 1] +% l[i - key.len]);
    const bytes: usize = (@as(usize, effective) + 7) / 8;
    // 8 + effective - 8 * bytes is in 1..8.
    const mask: u8 = @truncate((@as(u16, 1) << @intCast(8 + @as(usize, effective) - 8 * bytes)) - 1);
    l[128 - bytes] = pi(l[128 - bytes] & mask);
    var i: usize = 128 - bytes;
    while (i > 0) {
        i -= 1;
        l[i] = pi(l[i + 1] ^ l[i + bytes]);
    }
    for (k, 0..) |*w, j| w.* = @as(u16, l[2 * j]) | (@as(u16, l[2 * j + 1]) << 8);
}

fn decryptBlock(k: *const [64]u16, block: [8]u8) [8]u8 {
    @setRuntimeSafety(true);
    var owner: Secret([4]u16) = .init(undefined);
    defer owner.deinit();
    const r = owner.exposeMut();
    for (r, 0..) |*w, i| w.* = std.mem.readInt(u16, block[2 * i ..][0..2], .little);
    var j: usize = 63;
    const rounds = [_]u8{ 5, 1, 6, 1, 5 };
    for (rounds, 0..) |count, step| {
        for (0..count) |_| {
            if (step % 2 == 1) {
                // r-mash, reversed.
                r[3] -%= word(k, r[2]);
                r[2] -%= word(k, r[1]);
                r[1] -%= word(k, r[0]);
                r[0] -%= word(k, r[3]);
            } else {
                // r-mix, reversed.
                r[3] = std.math.rotr(u16, r[3], 5);
                r[3] -%= k[j] +% (r[2] & r[1]) +% (~r[2] & r[0]);
                r[2] = std.math.rotr(u16, r[2], 3);
                r[2] -%= k[j - 1] +% (r[1] & r[0]) +% (~r[1] & r[3]);
                r[1] = std.math.rotr(u16, r[1], 2);
                r[1] -%= k[j - 2] +% (r[0] & r[3]) +% (~r[0] & r[2]);
                r[0] = std.math.rotr(u16, r[0], 1);
                r[0] -%= k[j - 3] +% (r[3] & r[2]) +% (~r[3] & r[1]);
                j -%= 4;
            }
        }
    }
    var out: [8]u8 = undefined;
    for (r, 0..) |w, i| std.mem.writeInt(u16, out[2 * i ..][0..2], w, .little);
    return out;
}

/// One block under the raw cipher, for the RFC's vectors.
pub fn blockForTest(key: []const u8, effective: u10, block: [8]u8) [8]u8 {
    var k: [64]u16 = undefined;
    expand(key, effective, &k);
    return decryptBlock(&k, block);
}

test {
    _ = @import("Rc2_test.zig");
}
