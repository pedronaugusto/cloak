//! SHA-1 for the key-file KDFs (PBKDF2 over HMAC-SHA-1, PKCS#12's appendix B), on the ARMv8
//! SHA-1 instructions where the target has them; std's portable SHA-1 elsewhere. std has no
//! accelerated SHA-1, and a legacy PKCS#12 file costs some twelve thousand compressions. The
//! streaming shape and padding are std's; only the compression differs. SHA-1's collisions do
//! not touch these uses: an HMAC and a KDF need its preimage resistance alone.
const std = @import("std");
const builtin = @import("builtin");

const accelerated = builtin.cpu.arch == .aarch64 and builtin.zig_backend != .stage2_c and builtin.cpu.has(.aarch64, .sha2);
pub const Sha1 = if (accelerated) Armv8 else std.crypto.hash.Sha1;

/// The ARMv8 compression behind std's streaming shape.
pub const Armv8 = struct {
    pub const block_length = 64;
    pub const digest_length = 20;
    pub const Options = struct {};

    s: [5]u32,
    buf: [64]u8 = undefined,
    buf_len: u8 = 0,
    total_len: u64 = 0,

    pub fn init(_: Options) Armv8 {
        return .{ .s = .{ 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 } };
    }

    pub fn hash(b: []const u8, out: *[digest_length]u8, options: Options) void {
        var d = Armv8.init(options);
        d.update(b);
        d.final(out);
    }

    pub fn update(d: *Armv8, b: []const u8) void {
        var off: usize = 0;
        if (d.buf_len != 0 and d.buf_len + b.len >= 64) {
            off += 64 - d.buf_len;
            @memcpy(d.buf[d.buf_len..][0..off], b[0..off]);
            compress(&d.s, &d.buf);
            d.buf_len = 0;
        }
        while (off + 64 <= b.len) : (off += 64) compress(&d.s, b[off..][0..64]);
        @memcpy(d.buf[d.buf_len..][0 .. b.len - off], b[off..]);
        d.buf_len += @intCast(b[off..].len); // below 64
        d.total_len += b.len;
    }

    pub fn final(d: *Armv8, out: *[digest_length]u8) void {
        @memset(d.buf[d.buf_len..], 0);
        d.buf[d.buf_len] = 0x80;
        d.buf_len += 1;
        if (64 - d.buf_len < 8) {
            compress(&d.s, &d.buf);
            @memset(d.buf[0..], 0);
        }
        std.mem.writeInt(u64, d.buf[56..64], d.total_len * 8, .big);
        compress(&d.s, &d.buf);
        for (d.s, 0..) |s, j| std.mem.writeInt(u32, out[4 * j ..][0..4], s, .big);
    }

    pub fn finalResult(d: *Armv8) [digest_length]u8 {
        var result: [digest_length]u8 = undefined;
        d.final(&result);
        return result;
    }

    const V = @Vector(4, u32);
    fn k(comptime stage: usize) V {
        return @splat(([_]u32{ 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 })[stage]);
    }

    /// One block: twenty four-round groups, the message schedule two groups ahead (Arm's ARMv8
    /// Cryptography Extensions layout: sha1c for rounds 0-19, sha1p 20-39 and 60-79, sha1m 40-59).
    fn compress(state: *[5]u32, block: *const [64]u8) void {
        var m0 = word(block[0..16]);
        var m1 = word(block[16..32]);
        var m2 = word(block[32..48]);
        var m3 = word(block[48..64]);
        var abcd: V = state[0..4].*;
        var e0 = state[4];
        var e1: u32 = undefined;
        var t0 = m0 +% k(0);
        var t1 = m1 +% k(0);
        e1 = h(abcd[0]);
        abcd = c(abcd, e0, t0);
        t0 = m2 +% k(0);
        m0 = su0(m0, m1, m2);
        e0 = h(abcd[0]);
        abcd = c(abcd, e1, t1);
        t1 = m3 +% k(0);
        m0 = su1(m0, m3);
        m1 = su0(m1, m2, m3);
        e1 = h(abcd[0]);
        abcd = c(abcd, e0, t0);
        t0 = m0 +% k(0);
        m1 = su1(m1, m0);
        m2 = su0(m2, m3, m0);
        e0 = h(abcd[0]);
        abcd = c(abcd, e1, t1);
        t1 = m1 +% k(1);
        m2 = su1(m2, m1);
        m3 = su0(m3, m0, m1);
        e1 = h(abcd[0]);
        abcd = c(abcd, e0, t0);
        t0 = m2 +% k(1);
        m3 = su1(m3, m2);
        m0 = su0(m0, m1, m2);
        e0 = h(abcd[0]);
        abcd = p(abcd, e1, t1);
        t1 = m3 +% k(1);
        m0 = su1(m0, m3);
        m1 = su0(m1, m2, m3);
        e1 = h(abcd[0]);
        abcd = p(abcd, e0, t0);
        t0 = m0 +% k(1);
        m1 = su1(m1, m0);
        m2 = su0(m2, m3, m0);
        e0 = h(abcd[0]);
        abcd = p(abcd, e1, t1);
        t1 = m1 +% k(1);
        m2 = su1(m2, m1);
        m3 = su0(m3, m0, m1);
        e1 = h(abcd[0]);
        abcd = p(abcd, e0, t0);
        t0 = m2 +% k(2);
        m3 = su1(m3, m2);
        m0 = su0(m0, m1, m2);
        e0 = h(abcd[0]);
        abcd = p(abcd, e1, t1);
        t1 = m3 +% k(2);
        m0 = su1(m0, m3);
        m1 = su0(m1, m2, m3);
        e1 = h(abcd[0]);
        abcd = m(abcd, e0, t0);
        t0 = m0 +% k(2);
        m1 = su1(m1, m0);
        m2 = su0(m2, m3, m0);
        e0 = h(abcd[0]);
        abcd = m(abcd, e1, t1);
        t1 = m1 +% k(2);
        m2 = su1(m2, m1);
        m3 = su0(m3, m0, m1);
        e1 = h(abcd[0]);
        abcd = m(abcd, e0, t0);
        t0 = m2 +% k(2);
        m3 = su1(m3, m2);
        m0 = su0(m0, m1, m2);
        e0 = h(abcd[0]);
        abcd = m(abcd, e1, t1);
        t1 = m3 +% k(3);
        m0 = su1(m0, m3);
        m1 = su0(m1, m2, m3);
        e1 = h(abcd[0]);
        abcd = m(abcd, e0, t0);
        t0 = m0 +% k(3);
        m1 = su1(m1, m0);
        m2 = su0(m2, m3, m0);
        e0 = h(abcd[0]);
        abcd = p(abcd, e1, t1);
        t1 = m1 +% k(3);
        m2 = su1(m2, m1);
        m3 = su0(m3, m0, m1);
        e1 = h(abcd[0]);
        abcd = p(abcd, e0, t0);
        t0 = m2 +% k(3);
        m3 = su1(m3, m2);
        e0 = h(abcd[0]);
        abcd = p(abcd, e1, t1);
        t1 = m3 +% k(3);
        e1 = h(abcd[0]);
        abcd = p(abcd, e0, t0);
        e0 = h(abcd[0]);
        abcd = p(abcd, e1, t1);
        const sum: V = state[0..4].* +% abcd;
        state[0..4].* = sum;
        state[4] +%= e0;
    }

    fn word(bytes: *const [16]u8) V {
        var v: V = undefined;
        inline for (0..4) |i| v[i] = std.mem.readInt(u32, bytes[4 * i ..][0..4], .big);
        return v;
    }

    fn h(e: u32) u32 {
        // aegis: boundary: an ARMv8 SHA-1 instruction on registers alone, no memory
        return asm ("sha1h %[out:s], %[in:s]"
            : [out] "=w" (-> u32),
            : [in] "w" (e),
        );
    }
    fn c(abcd: V, e: u32, wk: V) V {
        // aegis: boundary: an ARMv8 SHA-1 instruction on registers alone, no memory
        return asm ("sha1c %[x:q], %[e:s], %[w].4s"
            : [x] "=w" (-> V),
            : [_] "0" (abcd),
              [e] "w" (e),
              [w] "w" (wk),
        );
    }
    fn p(abcd: V, e: u32, wk: V) V {
        // aegis: boundary: an ARMv8 SHA-1 instruction on registers alone, no memory
        return asm ("sha1p %[x:q], %[e:s], %[w].4s"
            : [x] "=w" (-> V),
            : [_] "0" (abcd),
              [e] "w" (e),
              [w] "w" (wk),
        );
    }
    fn m(abcd: V, e: u32, wk: V) V {
        // aegis: boundary: an ARMv8 SHA-1 instruction on registers alone, no memory
        return asm ("sha1m %[x:q], %[e:s], %[w].4s"
            : [x] "=w" (-> V),
            : [_] "0" (abcd),
              [e] "w" (e),
              [w] "w" (wk),
        );
    }
    fn su0(a: V, b: V, c_: V) V {
        // aegis: boundary: an ARMv8 SHA-1 instruction on registers alone, no memory
        return asm ("sha1su0 %[a].4s, %[b].4s, %[c].4s"
            : [a] "=w" (-> V),
            : [_] "0" (a),
              [b] "w" (b),
              [c] "w" (c_),
        );
    }
    fn su1(a: V, b: V) V {
        // aegis: boundary: an ARMv8 SHA-1 instruction on registers alone, no memory
        return asm ("sha1su1 %[a].4s, %[b].4s"
            : [a] "=w" (-> V),
            : [_] "0" (a),
              [b] "w" (b),
        );
    }
};

test "SHA-1 matches std's over every length across three blocks, split and whole" {
    var input: [200]u8 = undefined;
    for (&input, 0..) |*b, i| b.* = @truncate(i *% 151 +% 7);
    for (0..input.len) |len| {
        var ours: [20]u8 = undefined;
        var theirs: [20]u8 = undefined;
        Sha1.hash(input[0..len], &ours, .{});
        std.crypto.hash.Sha1.hash(input[0..len], &theirs, .{});
        try std.testing.expectEqualSlices(u8, &theirs, &ours);
        var split = Sha1.init(.{});
        split.update(input[0 .. len / 3]);
        split.update(input[len / 3 .. len]);
        split.final(&ours);
        try std.testing.expectEqualSlices(u8, &theirs, &ours);
    }
    // FIPS 180-2's "abc".
    var abc: [20]u8 = undefined;
    Sha1.hash("abc", &abc, .{});
    try std.testing.expectEqualSlices(u8, "\xa9\x99\x3e\x36\x47\x06\x81\x6a\xba\x3e\x25\x71\x78\x50\xc2\x6c\x9c\xd0\xd8\x9d", &abc);
}
