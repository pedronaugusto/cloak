//! AES-CCM with a 12-byte nonce and a 16-byte tag (NIST SP 800-38C, RFC 3610): the AEAD of
//! TLS_AES_128_CCM_SHA256 (RFC 8446) and of the ECDHE_ECDSA CCM suites (RFC 7251). std's CCM fixes a
//! 13-byte nonce, so this is cloak's: one AES key schedule for the CBC-MAC and the counter, the
//! tag compared in constant time, plaintext released only after it, and every intermediate
//! (key schedule, MAC state, keystream block) erased. It has the shape of std's AEADs, so the
//! record layer takes it as it takes AES-GCM.
const std = @import("std");
const crypto = std.crypto;

pub const Aes128Ccm = AesCcm(crypto.core.aes.Aes128);
pub const Aes256Ccm = AesCcm(crypto.core.aes.Aes256);

fn AesCcm(comptime Aes: type) type {
    return struct {
        pub const key_length = Aes.key_bits / 8;
        pub const tag_length = 16;
        pub const nonce_length = 12;
        const block_length = 16;
        /// Bytes of the counter and of the message length: 15 minus the nonce.
        const L = 15 - nonce_length;
        /// The longest message L bytes of length can state.
        pub const max_message = (1 << (8 * L)) - 1;
        const Context = @TypeOf(Aes.initEnc(@as([key_length]u8, undefined)));

        /// Seals `m` into `c` (the same length; `c` may be `m`) and writes the tag.
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            @setRuntimeSafety(true);
            std.debug.assert(c.len == m.len and m.len <= max_message);
            var ctx = Aes.initEnc(key);
            defer crypto.secureZero(u8, std.mem.asBytes(&ctx));
            var mac: [block_length]u8 = undefined;
            defer crypto.secureZero(u8, &mac);
            cbcMac(&ctx, &mac, m, ad, npub);
            var s0: [block_length]u8 = undefined;
            defer crypto.secureZero(u8, &s0);
            ctx.encrypt(&s0, &counterBlock(npub, 0));
            for (tag, mac, s0) |*t, a, b| t.* = a ^ b;
            ctr(&ctx, c, m, npub);
        }

        /// Opens `c` into `m` (the same length; `m` may be `c`). On a wrong tag `m` is erased and
        /// nothing of it is released.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) crypto.errors.AuthenticationError!void {
            @setRuntimeSafety(true);
            std.debug.assert(c.len == m.len);
            if (c.len > max_message) return error.AuthenticationFailed;
            var ctx = Aes.initEnc(key);
            defer crypto.secureZero(u8, std.mem.asBytes(&ctx));
            ctr(&ctx, m, c, npub);
            var mac: [block_length]u8 = undefined;
            defer crypto.secureZero(u8, &mac);
            cbcMac(&ctx, &mac, m, ad, npub);
            var expected: [block_length]u8 = undefined;
            defer crypto.secureZero(u8, &expected);
            ctx.encrypt(&expected, &counterBlock(npub, 0));
            for (&expected, mac) |*e, a| e.* ^= a;
            if (!crypto.timing_safe.eql([tag_length]u8, expected, tag)) {
                crypto.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
        }

        /// A counter block: flags (L - 1), the nonce, the counter in the last L bytes.
        fn counterBlock(npub: [nonce_length]u8, counter: u24) [block_length]u8 {
            var block: [block_length]u8 = undefined;
            block[0] = L - 1;
            block[1..][0..nonce_length].* = npub;
            std.mem.writeInt(u24, block[1 + nonce_length ..][0..L], counter, .big);
            return block;
        }

        /// Counter mode from counter 1 (counter 0 masks the tag).
        fn ctr(ctx: *const Context, out: []u8, in: []const u8, npub: [nonce_length]u8) void {
            var keystream: [block_length]u8 = undefined;
            defer crypto.secureZero(u8, &keystream);
            var counter: u24 = 1;
            var at: usize = 0;
            while (at < in.len) : (at += block_length) {
                ctx.encrypt(&keystream, &counterBlock(npub, counter));
                const n = @min(block_length, in.len - at);
                for (out[at..][0..n], in[at..][0..n], keystream[0..n]) |*o, i, k| o.* = i ^ k;
                // The length bound keeps the counter below 2^24 blocks.
                counter +%= 1;
            }
        }

        /// CBC-MAC over B0, the encoded additional data padded to a block, then the message
        /// padded to a block (RFC 3610 section 2.2).
        fn cbcMac(ctx: *const Context, mac: *[block_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) void {
            var state: Absorb = .{ .ctx = ctx };
            defer crypto.secureZero(u8, std.mem.asBytes(&state));
            var b0: [block_length]u8 = undefined;
            const adata: u8 = if (ad.len != 0) 0x40 else 0;
            b0[0] = adata | ((tag_length - 2) / 2) << 3 | (L - 1);
            b0[1..][0..nonce_length].* = npub;
            // safe: callers bound the message at max_message, the L-byte length's range.
            std.mem.writeInt(u24, b0[1 + nonce_length ..][0..L], @intCast(m.len), .big);
            state.update(&b0);
            if (ad.len != 0) {
                var encoded: [6]u8 = undefined;
                const prefix: []const u8 = if (ad.len < 0xff00) prefix: {
                    // safe: below 0xff00.
                    std.mem.writeInt(u16, encoded[0..2], @intCast(ad.len), .big);
                    break :prefix encoded[0..2];
                } else prefix: {
                    encoded[0..2].* = .{ 0xff, 0xfe };
                    // safe: TLS additional data is a few bytes; a 4 GiB one cannot reach here.
                    std.mem.writeInt(u32, encoded[2..6], @intCast(ad.len), .big);
                    break :prefix encoded[0..6];
                };
                state.update(prefix);
                state.update(ad);
                state.pad();
            }
            state.update(m);
            state.pad();
            mac.* = state.chain;
        }

        /// The CBC chain and the bytes of the current block absorbed so far.
        const Absorb = struct {
            ctx: *const Context,
            chain: [block_length]u8 = @splat(0),
            filled: usize = 0,

            fn update(self: *Absorb, bytes: []const u8) void {
                var rest = bytes;
                while (rest.len != 0) {
                    const n = @min(block_length - self.filled, rest.len);
                    for (self.chain[self.filled..][0..n], rest[0..n]) |*c, b| c.* ^= b;
                    self.filled += n;
                    rest = rest[n..];
                    if (self.filled == block_length) self.flush();
                }
            }

            /// Zero padding to the block boundary: the chain already holds zeros there.
            fn pad(self: *Absorb) void {
                if (self.filled != 0) self.flush();
            }

            fn flush(self: *Absorb) void {
                self.ctx.encrypt(&self.chain, &self.chain);
                self.filled = 0;
            }
        };
    };
}

test {
    _ = @import("Ccm_test.zig");
}
