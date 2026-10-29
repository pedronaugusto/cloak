//! AES-CCM with a 12-byte nonce and a 16- or 8-byte tag (NIST SP 800-38C, RFC 3610): the AEAD of
//! TLS_AES_128_CCM_SHA256 (RFC 8446), of the ECDHE_ECDSA CCM suites (RFC 7251) and, with the short
//! tag, of the CCM_8 suites the CoAP and LwM2M profiles require (RFC 6655, RFC 7925). std's CCM fixes a
//! 13-byte nonce, so this is cloak's: one AES key schedule for the CBC-MAC and the counter, the
//! tag compared in constant time, plaintext released only after it, and every intermediate
//! (key schedule, MAC state, keystream block) erased. It has the shape of std's AEADs, so the
//! record layer takes it as it takes AES-GCM.
const std = @import("std");
const aegis = @import("aegis");
const crypto = std.crypto;

pub const Aes128Ccm = AesCcm(crypto.core.aes.Aes128, 16);
pub const Aes256Ccm = AesCcm(crypto.core.aes.Aes256, 16);
/// AEAD_AES_128_CCM_8 (RFC 6655 section 3): the tag is the first eight bytes of CCM's.
pub const Aes128Ccm8 = AesCcm(crypto.core.aes.Aes128, 8);

fn AesCcm(comptime Aes: type, comptime tag_bytes: comptime_int) type {
    comptime std.debug.assert(tag_bytes == 16 or tag_bytes == 8);
    return struct {
        pub const key_length = Aes.key_bits / 8;
        pub const tag_length = tag_bytes;
        pub const nonce_length = 12;
        const block_length = 16;
        /// Bytes of the counter and of the message length (RFC 3610's L): 15 minus the nonce.
        const length_bytes = 15 - nonce_length;
        /// The longest message `length_bytes` bytes of length can state.
        pub const max_message = (1 << (8 * length_bytes)) - 1;
        const Context = @TypeOf(Aes.initEnc(@as([key_length]u8, undefined)));

        /// Seals `m` into `c` (the same length; `c` may be `m`) and writes the tag.
        pub fn encrypt(c: []u8, tag: *[tag_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            @setRuntimeSafety(true);
            aegis.assert.invariant(c.len == m.len, "CCM seals in place or into an equal buffer");
            aegis.assert.invariant(m.len <= max_message, "a CCM message is within its counter's reach");
            var owner: aegis.Secret(struct { ctx: Context, mac: [block_length]u8, s0: [block_length]u8 }) = .init(.{ .ctx = Aes.initEnc(key), .mac = undefined, .s0 = undefined });
            defer owner.deinit();
            const s = owner.exposeMut();
            cbcMac(&s.ctx, &s.mac, m, ad, npub);
            s.ctx.encrypt(&s.s0, &counterBlock(npub, 0));
            for (tag, s.mac[0..tag_length], s.s0[0..tag_length]) |*t, a, b| t.* = a ^ b;
            ctr(&s.ctx, c, m, npub);
        }

        /// Opens `c` into `m` (the same length; `m` may be `c`). On a wrong tag `m` holds `c` again:
        /// the keystream is applied a second time, so nothing derived from the key is left in it.
        pub fn decrypt(m: []u8, c: []const u8, tag: [tag_length]u8, ad: []const u8, npub: [nonce_length]u8, key: [key_length]u8) crypto.errors.AuthenticationError!void {
            @setRuntimeSafety(true);
            aegis.assert.invariant(c.len == m.len, "CCM opens in place or into an equal buffer");
            if (c.len > max_message) return error.AuthenticationFailed;
            var owner: aegis.Secret(struct { ctx: Context, mac: [block_length]u8, expected: [block_length]u8 }) = .init(.{ .ctx = Aes.initEnc(key), .mac = undefined, .expected = undefined });
            defer owner.deinit();
            const s = owner.exposeMut();
            ctr(&s.ctx, m, c, npub);
            cbcMac(&s.ctx, &s.mac, m, ad, npub);
            s.ctx.encrypt(&s.expected, &counterBlock(npub, 0));
            for (&s.expected, s.mac) |*e, a| e.* ^= a;
            if (!aegis.secret.equal(tag_length, s.expected[0..tag_length], &tag).declassify("a bad tag drops the record")) {
                // m ^ keystream is c, public: the plaintext and the keystream both leave m.
                ctr(&s.ctx, m, m, npub);
                return error.AuthenticationFailed;
            }
        }

        /// A counter block: flags (`length_bytes` - 1), the nonce, the counter in the last `length_bytes` bytes.
        fn counterBlock(npub: [nonce_length]u8, counter: u24) [block_length]u8 {
            var block: [block_length]u8 = undefined;
            block[0] = length_bytes - 1;
            block[1..][0..nonce_length].* = npub;
            std.mem.writeInt(u24, block[1 + nonce_length ..][0..length_bytes], counter, .big);
            return block;
        }

        /// Counter mode from counter 1 (counter 0 masks the tag).
        fn ctr(ctx: *const Context, out: []u8, in: []const u8, npub: [nonce_length]u8) void {
            var keystream_owner: aegis.Secret([block_length]u8) = .init(undefined);
            defer keystream_owner.deinit();
            const keystream = keystream_owner.exposeMut();
            var counter: u24 = 1;
            var at: usize = 0;
            while (at < in.len) : (at += block_length) {
                ctx.encrypt(keystream, &counterBlock(npub, counter));
                const n = @min(block_length, in.len - at);
                for (out[at..][0..n], in[at..][0..n], keystream[0..n]) |*o, i, k| o.* = i ^ k;
                // The length bound keeps the counter below 2^24 blocks.
                counter +%= 1;
            }
        }

        /// CBC-MAC over B0, the encoded additional data padded to a block, then the message
        /// padded to a block (RFC 3610 section 2.2).
        fn cbcMac(ctx: *const Context, mac: *[block_length]u8, m: []const u8, ad: []const u8, npub: [nonce_length]u8) void {
            mac.* = @splat(0);
            var state: Absorb = .{ .ctx = ctx, .chain = mac };
            var b0: [block_length]u8 = undefined;
            const adata: u8 = if (ad.len != 0) 0x40 else 0;
            b0[0] = adata | (((tag_length - 2) / 2) << 3) | (length_bytes - 1);
            b0[1..][0..nonce_length].* = npub;
            // Callers bound the message at max_message, the `length_bytes`-byte length's range.
            std.mem.writeInt(u24, b0[1 + nonce_length ..][0..length_bytes], @intCast(m.len), .big);
            state.update(&b0);
            if (ad.len != 0) {
                var encoded: [6]u8 = undefined;
                const prefix: []const u8 = if (ad.len < 0xff00) prefix: {
                    // Below 0xff00.
                    std.mem.writeInt(u16, encoded[0..2], @intCast(ad.len), .big);
                    break :prefix encoded[0..2];
                } else prefix: {
                    encoded[0..2].* = .{ 0xff, 0xfe };
                    // TLS additional data is a few bytes; a 4 GiB one cannot reach here.
                    std.mem.writeInt(u32, encoded[2..6], @intCast(ad.len), .big);
                    break :prefix encoded[0..6];
                };
                state.update(prefix);
                state.update(ad);
                state.pad();
            }
            state.update(m);
            state.pad();
        }

        /// The CBC chain, kept in the caller's MAC block, and the bytes of the current block
        /// absorbed so far.
        const Absorb = struct {
            ctx: *const Context,
            chain: *[block_length]u8,
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
                self.ctx.encrypt(self.chain, self.chain);
                self.filled = 0;
            }
        };
    };
}

test {
    _ = @import("Ccm_test.zig");
}
