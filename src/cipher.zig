//! The symmetric constructions JOSE and its kin use beside TLS's records: AES-GCM under a
//! nonce the caller draws, AES key wrap (RFC 3394), and AES-CBC with HMAC-SHA-2 as one
//! authenticated cipher (RFC 7518 section 5.2). Each runs std's AES in a frame
//! `aegis.secret.scrubbed` erases, at the depth the record kernels use (`crypto/aes.zig`), so
//! no key schedule, block or hash state outlives the call. Tags and key-wrap checks are compared
//! in constant time, and nothing is decrypted or released before its check holds. Raw CBC is not
//! here: its padding would be an oracle (cloak's own, for key files, is private).
//!
//! AES-192 is not offered: std's AES has no 192-bit key schedule, and JOSE's A192 algorithms
//! are optional (RFC 7518 sections 4.1 and 5.1) and absent from WebCrypto.
const std = @import("std");
const aegis = @import("aegis");
const Secret = aegis.secret.Secret;
const aes = @import("crypto/aes.zig");

const Aes128 = std.crypto.core.aes.Aes128;
const Aes256 = std.crypto.core.aes.Aes256;

pub const Error = error{
    /// The tag, or the key wrap's integrity check, does not hold: nothing is released.
    AuthenticationFailed,
};

/// AES-GCM (NIST SP 800-38D) with a 96-bit nonce the caller draws fresh for every key, and any
/// associated data: JWE's content encryption (A128GCM, A256GCM) and its A*GCMKW key wrap.
pub fn AesGcm(comptime bits: u16) type {
    const A = switch (bits) {
        128 => std.crypto.aead.aes_gcm.Aes128Gcm,
        256 => std.crypto.aead.aes_gcm.Aes256Gcm,
        else => @compileError("AES-GCM is 128 or 256 bits here"),
    };
    return struct {
        pub const key_length = A.key_length;
        pub const nonce_length = A.nonce_length;
        pub const tag_length = A.tag_length;

        /// Encrypts `m` into `c` (as long as `m`) and writes the tag over `c` and `ad`.
        pub fn seal(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, nonce: *const [nonce_length]u8, key: *const [key_length]u8) void {
            aegis.assert.pre(c.len == m.len, "an AES-GCM ciphertext buffer is as long as the message");
            aegis.secret.scrubbed(aes.depth(), sealKernel, .{ c, tag, m, ad, nonce, key });
        }

        /// Checks the tag, then decrypts `c` into `m` (as long as `c`); on a refusal no plaintext is
        /// written to `m`, the tag being checked before any block is decrypted.
        pub fn open(m: []u8, c: []const u8, tag: *const [tag_length]u8, ad: []const u8, nonce: *const [nonce_length]u8, key: *const [key_length]u8) Error!void {
            aegis.assert.pre(m.len == c.len, "an AES-GCM message buffer is as long as the ciphertext");
            return aegis.secret.scrubbed(aes.depth(), openKernel, .{ m, c, tag, ad, nonce, key });
        }

        fn sealKernel(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, nonce: *const [nonce_length]u8, key: *const [key_length]u8) void {
            A.encrypt(c, tag, m, ad, nonce.*, key.*);
        }

        fn openKernel(m: []u8, c: []const u8, tag: *const [tag_length]u8, ad: []const u8, nonce: *const [nonce_length]u8, key: *const [key_length]u8) Error!void {
            A.decrypt(m, c, tag.*, ad, nonce.*, key.*) catch return error.AuthenticationFailed;
        }
    };
}

/// AES key wrap (RFC 3394 section 2.2, the default IV): a key of 16 bytes or more, a multiple
/// of 8, sealed under a 128- or 256-bit key-encryption key; JWE's A128KW and A256KW.
pub const keyWrap = struct {
    /// RFC 3394 section 2.2.3.1's default initial value.
    const iv: [8]u8 = @splat(0xa6);

    pub const LengthError = error{
        /// A key-encryption key of neither 16 nor 32 bytes, a key shorter than 16 bytes or not a
        /// multiple of 8, or an output of the wrong length.
        InvalidLength,
    };

    /// Wraps `key` under `kek` into `out`, 8 bytes longer than `key`.
    pub fn wrap(kek: []const u8, key: []const u8, out: []u8) LengthError!void {
        if ((kek.len != 16 and kek.len != 32) or key.len < 16 or key.len % 8 != 0 or out.len != key.len + 8) return error.InvalidLength;
        switch (kek.len) {
            16 => aegis.secret.scrubbed(aes.depth(), wrapKernel, .{ Aes128, kek[0..16], key, out }),
            else => aegis.secret.scrubbed(aes.depth(), wrapKernel, .{ Aes256, kek[0..32], key, out }),
        }
    }

    /// The longest key `unwrap` takes: a JOSE content key is at most 64 bytes.
    pub const max_unwrapped = 512;

    /// Unwraps `wrapped` under `kek` into `out`, 8 bytes shorter (at most `max_unwrapped`). The
    /// rounds run in an owned buffer and the integrity check is compared in constant time; `out`
    /// is written only when the check held, so a refusal leaves it as it was.
    pub fn unwrap(kek: []const u8, wrapped: []const u8, out: []u8) (LengthError || Error)!void {
        if ((kek.len != 16 and kek.len != 32) or wrapped.len < 24 or wrapped.len % 8 != 0 or out.len + 8 != wrapped.len or out.len > max_unwrapped) return error.InvalidLength;
        return switch (kek.len) {
            16 => aegis.secret.scrubbed(aes.depth(), unwrapKernel, .{ Aes128, kek[0..16], wrapped, out }),
            else => aegis.secret.scrubbed(aes.depth(), unwrapKernel, .{ Aes256, kek[0..32], wrapped, out }),
        };
    }

    fn wrapKernel(comptime Aes: type, kek: *const [Aes.key_bits / 8]u8, key: []const u8, out: []u8) void {
        const ctx = Aes.initEnc(kek.*);
        const n = key.len / 8;
        var a = iv;
        @memcpy(out[8..], key);
        var owner: Secret([16]u8) = .init(undefined);
        defer owner.deinit();
        const block = owner.exposeMut();
        for (0..6) |j| for (1..n + 1) |i| {
            @memcpy(block[0..8], &a);
            @memcpy(block[8..], out[8 * i ..][0..8]);
            ctx.encrypt(block, block);
            const t: u64 = @intCast(n * j + i);
            a = block[0..8].*;
            var tb: [8]u8 = undefined;
            std.mem.writeInt(u64, &tb, t, .big);
            for (&a, tb) |*x, y| x.* ^= y;
            @memcpy(out[8 * i ..][0..8], block[8..]);
        };
        @memcpy(out[0..8], &a);
    }

    fn unwrapKernel(comptime Aes: type, kek: *const [Aes.key_bits / 8]u8, wrapped: []const u8, out: []u8) Error!void {
        const ctx = Aes.initDec(kek.*);
        const n = wrapped.len / 8 - 1;
        var owner: Secret(struct { r: [max_unwrapped]u8, block: [16]u8 }) = .init(undefined);
        defer owner.deinit();
        const s = owner.exposeMut();
        const r = s.r[0..out.len];
        const block = &s.block;
        var a = wrapped[0..8].*;
        @memcpy(r, wrapped[8..]);
        var j: usize = 6;
        while (j > 0) {
            j -= 1;
            var i: usize = n;
            while (i > 0) : (i -= 1) {
                const t: u64 = @intCast(n * j + i);
                var tb: [8]u8 = undefined;
                std.mem.writeInt(u64, &tb, t, .big);
                for (&a, tb) |*x, y| x.* ^= y;
                @memcpy(block[0..8], &a);
                @memcpy(block[8..], r[8 * (i - 1) ..][0..8]);
                ctx.decrypt(block, block);
                a = block[0..8].*;
                @memcpy(r[8 * (i - 1) ..][0..8], block[8..]);
            }
        }
        const same = aegis.secret.equalBytes(&a, &iv) catch unreachable; // unreachable: both are 8 bytes
        if (!same.declassify("a failed unwrap releases nothing but the refusal")) return error.AuthenticationFailed;
        @memcpy(out, r);
    }
};

/// AES-CBC with HMAC-SHA-2 as one authenticated cipher (RFC 7518 section 5.2): the key's first
/// half the MAC key, its second the AES key; the tag the HMAC over the associated data, the IV,
/// the ciphertext and the associated data's length in bits, truncated to half the hash. `open`
/// checks the tag in constant time before one block is decrypted, so the padding is never an
/// oracle; it is then checked under masks.
pub fn CbcHmac(comptime which: enum { a128cbc_hs256, a256cbc_hs512 }) type {
    const Hmac, const Aes = switch (which) {
        .a128cbc_hs256 => .{ std.crypto.auth.hmac.sha2.HmacSha256, Aes128 },
        .a256cbc_hs512 => .{ std.crypto.auth.hmac.sha2.HmacSha512, Aes256 },
    };
    return struct {
        /// The MAC key and the AES key, joined.
        pub const key_length = 2 * (Aes.key_bits / 8);
        pub const iv_length = 16;
        pub const tag_length = Hmac.mac_length / 2;
        const half = Aes.key_bits / 8;

        /// The ciphertext's length for a message of `length` bytes: PKCS#7 padded to the block.
        pub fn ciphertextLength(length: usize) usize {
            return (length / 16 + 1) * 16;
        }

        /// Encrypts `m` into `c` (`ciphertextLength(m.len)` bytes) under `iv`, and writes the tag.
        pub fn seal(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, iv: *const [iv_length]u8, key: *const [key_length]u8) void {
            aegis.assert.pre(c.len == ciphertextLength(m.len), "a CBC-HMAC ciphertext buffer is ciphertextLength(message) bytes");
            aegis.secret.scrubbed(aes.depth(), sealKernel, .{ c, tag, m, ad, iv, key });
        }

        /// Checks the tag, then decrypts `c` into `m` (as long as `c`) and returns the message
        /// without its padding. Any refusal is `AuthenticationFailed`, and leaves `m` as it was.
        pub fn open(m: []u8, c: []const u8, tag: *const [tag_length]u8, ad: []const u8, iv: *const [iv_length]u8, key: *const [key_length]u8) Error![]u8 {
            aegis.assert.pre(m.len == c.len, "a CBC-HMAC message buffer is as long as the ciphertext");
            return aegis.secret.scrubbed(aes.depth(), openKernel, .{ m, c, tag, ad, iv, key });
        }

        fn mac(out: *[tag_length]u8, c: []const u8, ad: []const u8, iv: *const [iv_length]u8, key: *const [half]u8) void {
            var h = Hmac.init(key);
            h.update(ad);
            h.update(iv);
            h.update(c);
            var al: [8]u8 = undefined;
            std.mem.writeInt(u64, &al, @as(u64, ad.len) * 8, .big);
            h.update(&al);
            var full: Secret([Hmac.mac_length]u8) = .init(undefined);
            defer full.deinit();
            h.final(full.exposeMut());
            const tag = full.expose();
            out.* = tag[0..tag_length].*;
        }

        fn sealKernel(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, iv: *const [iv_length]u8, key: *const [key_length]u8) void {
            const ctx = Aes.initEnc(key[half..].*);
            var previous = iv.*;
            const blocks = c.len / 16;
            const pad: u8 = @intCast(c.len - m.len); // safe: 1..16, the PKCS#7 count
            var owner: Secret([16]u8) = .init(undefined);
            defer owner.deinit();
            const block = owner.exposeMut();
            for (0..blocks) |b| {
                for (block, 0..) |*x, k| {
                    const at = b * 16 + k;
                    x.* = (if (at < m.len) m[at] else pad) ^ previous[k];
                }
                ctx.encrypt(block, block);
                @memcpy(c[b * 16 ..][0..16], block);
                previous = block.*;
            }
            mac(tag, c, ad, iv, key[0..half]);
        }

        fn openKernel(m: []u8, c: []const u8, tag: *const [tag_length]u8, ad: []const u8, iv: *const [iv_length]u8, key: *const [key_length]u8) Error![]u8 {
            if (c.len == 0 or c.len % 16 != 0) return error.AuthenticationFailed;
            var owner: Secret(struct { expected: [tag_length]u8, block: [16]u8 }) = .init(undefined);
            defer owner.deinit();
            const s = owner.exposeMut();
            mac(&s.expected, c, ad, iv, key[0..half]);
            const same = aegis.secret.equalBytes(&s.expected, tag) catch unreachable; // unreachable: both are tag_length bytes
            if (!same.declassify("a refused tag ends the decryption before any block")) return error.AuthenticationFailed;
            const ctx = Aes.initDec(key[half..].*);
            const blocks = c.len / 16;
            // The last block first: its padding is read under masks before any plaintext is
            // written, so a refusal leaves `m` as it was. The tag held: a bad one is the sender's.
            const before: *const [16]u8 = if (blocks == 1) iv else c[(blocks - 2) * 16 ..][0..16];
            ctx.decrypt(&s.block, c[(blocks - 1) * 16 ..][0..16]);
            for (&s.block, before) |*x, p| x.* ^= p;
            const pad: usize = s.block[15];
            var bad: u8 = @intFromBool(pad == 0) | @intFromBool(pad > 16);
            for (0..16) |i| {
                const inside: u8 = 0 -% @as(u8, @intFromBool(i < pad));
                bad |= inside & (s.block[15 - i] ^ @as(u8, @truncate(pad)));
            }
            // aegis: no-danger: the verdict is the only thing released, after the tag held
            if (bad != 0) return error.AuthenticationFailed;
            var previous = iv.*;
            for (0..blocks) |b| {
                const cipher_block = c[b * 16 ..][0..16].*;
                ctx.decrypt(&s.block, &cipher_block);
                for (&s.block, previous) |*x, p| x.* ^= p;
                @memcpy(m[b * 16 ..][0..16], &s.block);
                previous = cipher_block;
            }
            return m[0 .. m.len - pad];
        }
    };
}

test "each cipher kernel reaches less stack than the depth that erases it" {
    const depth = comptime aes.depth();
    var buffer: [512]u8 = @splat(1);
    var out: [512]u8 = undefined;
    const key: [64]u8 = @splat(7);
    const iv: [16]u8 = @splat(9);
    var tag: [32]u8 = undefined;
    const G = AesGcm(256);
    try std.testing.expect(aegis.secret.stackReach(4 * depth, G.sealKernel, .{ out[0..64], tag[0..16], buffer[0..64], "ad", iv[0..12], key[0..32] }) < depth);
    const C = CbcHmac(.a256cbc_hs512);
    try std.testing.expect(aegis.secret.stackReach(4 * depth, C.sealKernel, .{ out[0..64], tag[0..32], buffer[0..63], "ad", &iv, &key }) < depth);
    try std.testing.expect(aegis.secret.stackReach(4 * depth, keyWrap.wrapKernel, .{ Aes256, key[0..32], buffer[0..32], out[0..40] }) < depth);
    try std.testing.expect(aegis.secret.stackReach(4 * depth, keyWrap.unwrapKernel, .{ Aes256, key[0..32], buffer[0..40], out[0..32] }) < depth);
}

test {
    _ = @import("cipher_test.zig");
}
