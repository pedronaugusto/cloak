//! RFC 8017's mask generation and RSAES-OAEP encoding (§7.1, B.2.1): MGF1, EME-OAEP's encoding
//! of public data, and its decoding of a private operation's output in constant time.
//!
//! Decoding reads every byte of the encoded message whatever it holds. The leading zero, the
//! label hash and the separator after the zero padding fold into one mask, so the one failure,
//! `DecryptionFailed`, says nothing of which check failed: Manger's attack needs exactly that.
//! Only a decoded message's length leaves the mask, once the whole encoding has held.
const std = @import("std");
const ct = @import("p256/Montgomery.zig");

/// The hashes OAEP's label hash and MGF1 take: SHA-1 (JOSE's RSA-OAEP), SHA-256, SHA-384 and
/// SHA-512.
pub const Hash = enum {
    sha1,
    sha256,
    sha384,
    sha512,

    pub fn length(hash: Hash) usize {
        return switch (hash) {
            inline else => |tag| Type(tag).digest_length,
        };
    }

    /// The member naming std's hash type `H`.
    pub fn of(comptime H: type) Hash {
        return switch (H) {
            std.crypto.hash.Sha1 => .sha1,
            std.crypto.hash.sha2.Sha256 => .sha256,
            std.crypto.hash.sha2.Sha384 => .sha384,
            std.crypto.hash.sha2.Sha512 => .sha512,
            else => @compileError("MGF1 and OAEP hash with SHA-1, SHA-256, SHA-384 or SHA-512"),
        };
    }

    fn Type(comptime hash: Hash) type {
        return switch (hash) {
            .sha1 => std.crypto.hash.Sha1,
            .sha256 => std.crypto.hash.sha2.Sha256,
            .sha384 => std.crypto.hash.sha2.Sha384,
            .sha512 => std.crypto.hash.sha2.Sha512,
        };
    }

    /// `hash(data)` into the start of `out`.
    fn digest(hash: Hash, data: []const u8, out: *[max_digest]u8) void {
        switch (hash) {
            inline else => |tag| Type(tag).hash(data, out[0..Type(tag).digest_length], .{}),
        }
    }
};

/// The longest digest: SHA-512's.
pub const max_digest = 64;

/// XORs MGF1(seed) on `hash` into `out` (RFC 8017 B.2.1).
pub fn mgf1(hash: Hash, seed: []const u8, out: []u8) void {
    @setRuntimeSafety(true);
    switch (hash) {
        inline else => |tag| {
            const H = Hash.Type(tag);
            var counter: u32 = 0;
            var at: usize = 0;
            while (at < out.len) : (counter += 1) {
                var h = H.init(.{});
                h.update(seed);
                var count: [4]u8 = undefined;
                std.mem.writeInt(u32, &count, counter, .big);
                h.update(&count);
                var block = h.finalResult();
                defer std.crypto.secureZero(u8, &block);
                const take = @min(block.len, out.len - at);
                for (out[at..][0..take], block[0..take]) |*o, b| o.* ^= b;
                at += take;
            }
        },
    }
}

/// OAEP's parameters: the label's hash, MGF1's hash, the label.
pub const Oaep = struct { hash: Hash, mgf_hash: Hash, label: []const u8 = "" };

/// The longest message a `k`-byte modulus carries under `hash`, or null when it carries none.
pub fn maxMessage(hash: Hash, k: usize) ?usize {
    const h = hash.length();
    return if (k < 2 * h + 2) null else k - 2 * h - 2;
}

pub const EncodeError = error{ MessageTooLong, InvalidSeed };

/// EME-OAEP encoding (§7.1.1 step 2) of `message` into all of `em` (`k` bytes, the modulus's
/// length), with `seed` the hash's length of fresh bytes.
pub fn encode(scheme: Oaep, message: []const u8, seed: []const u8, em: []u8) EncodeError!void {
    @setRuntimeSafety(true);
    const h = scheme.hash.length();
    const limit = maxMessage(scheme.hash, em.len) orelse return error.MessageTooLong;
    if (message.len > limit) return error.MessageTooLong;
    if (seed.len != h) return error.InvalidSeed;
    const k = em.len;
    // EM = 0x00 || maskedSeed || maskedDB, DB = lHash || PS || 0x01 || M.
    em[0] = 0;
    const masked_seed = em[1..][0..h];
    const db = em[1 + h .. k];
    var l_hash: [max_digest]u8 = undefined;
    scheme.hash.digest(scheme.label, &l_hash);
    @memcpy(db[0..h], l_hash[0..h]);
    @memset(db[h .. db.len - message.len - 1], 0);
    db[db.len - message.len - 1] = 1;
    @memcpy(db[db.len - message.len ..], message);
    mgf1(scheme.mgf_hash, seed, db);
    @memcpy(masked_seed, seed);
    mgf1(scheme.mgf_hash, db, masked_seed);
}

pub const DecodeError = error{DecryptionFailed};

/// EME-OAEP decoding (§7.1.2 step 3) of `em`, a private operation's `k`-byte output, into `out`,
/// which holds at least `maxMessage(scheme.hash, k)` bytes. Returns the message, the start of
/// `out`; `out` is written only when the encoding holds. Constant time in `em`'s contents.
pub fn decode(scheme: Oaep, em: []const u8, out: []u8) DecodeError![]u8 {
    @setRuntimeSafety(true);
    const h = scheme.hash.length();
    const limit = maxMessage(scheme.hash, em.len) orelse return error.DecryptionFailed;
    if (out.len < limit or em.len > max_em) return error.DecryptionFailed;
    const k = em.len;
    var buffer: [max_em]u8 = undefined;
    defer std.crypto.secureZero(u8, buffer[0..k]);
    // seed = maskedSeed ^ MGF(maskedDB), DB = maskedDB ^ MGF(seed), in one owned copy.
    @memcpy(buffer[0..k], em);
    const seed = buffer[1..][0..h];
    const db = buffer[1 + h .. k];
    mgf1(scheme.mgf_hash, db, seed);
    mgf1(scheme.mgf_hash, seed, db);
    var l_hash: [max_digest]u8 = undefined;
    scheme.hash.digest(scheme.label, &l_hash);

    // Y is zero and DB's first h bytes are lHash.
    var difference: u64 = em[0];
    for (db[0..h], l_hash[0..h]) |a, b| difference |= a ^ b;
    var good = ct.zeroMask(difference);
    // Then zeros up to the first nonzero byte, which must be 0x01: scanned to the end.
    var looking: u64 = ~@as(u64, 0);
    var invalid: u64 = 0;
    var index: u64 = 0;
    for (db[h..], 0..) |byte, i| {
        const is_zero = ct.zeroMask(byte);
        const is_one = ct.zeroMask(byte ^ 1);
        index |= looking & is_one & @as(u64, i);
        invalid |= looking & ~is_zero & ~is_one;
        looking &= is_zero;
    }
    good &= ~looking & ~invalid;
    // Whether the encoding held is the decryption's one public answer.
    if (ct.barrier(good) == 0) return error.DecryptionFailed;
    const message = db[h + index + 1 ..];
    @memcpy(out[0..message.len], message);
    return out[0..message.len];
}

/// The longest encoded message: a 4096-bit modulus's.
pub const max_em = 512;

const testing = std.testing;

test "an encoding decodes to its message, and every flipped byte of it fails as one error" {
    const scheme: Oaep = .{ .hash = .sha256, .mgf_hash = .sha1, .label = "label" };
    var em: [256]u8 = undefined;
    const seed: [32]u8 = @splat(0x5a);
    try encode(scheme, "a key to carry", &seed, &em);
    var out: [256]u8 = undefined;
    try testing.expectEqualStrings("a key to carry", try decode(scheme, &em, &out));
    for (0..em.len) |at| {
        var bad = em;
        bad[at] ^= 0x80;
        try testing.expectError(error.DecryptionFailed, decode(scheme, &bad, &out));
    }
    try testing.expectError(error.DecryptionFailed, decode(.{ .hash = .sha256, .mgf_hash = .sha1, .label = "other" }, &em, &out));
    try testing.expectError(error.DecryptionFailed, decode(scheme, &em, out[0..10]));
    // The longest message, and the empty one.
    const longest: [256 - 66]u8 = @splat(0x33);
    try encode(scheme, &longest, &seed, &em);
    try testing.expectEqualSlices(u8, &longest, try decode(scheme, &em, &out));
    try testing.expectError(error.MessageTooLong, encode(scheme, longest ++ "x", &seed, &em));
    try encode(scheme, "", &seed, &em);
    try testing.expectEqual(@as(usize, 0), (try decode(scheme, &em, &out)).len);
}
