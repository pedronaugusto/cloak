//! The RSA private operation, constant time on every secret: `m^d mod n` by the Chinese
//! remainder theorem with base blinding and a public verification of the result.
//!
//! Every number is little-endian 64-bit limbs at a public width: the modulus's limb count for
//! values mod n, the larger factor's limb count for values mod p and q. Loops run over those
//! widths only; carries move through add-with-carry chains; every conditional subtraction and
//! every table entry is chosen by a mask the optimizer cannot see through. Exponents are walked
//! in fixed four-bit windows over the full width, so the instruction sequence and the memory
//! addresses depend only on the key's size.
//!
//! One operation:
//! 1. Blinding: r is drawn by SHAKE256 from a caller seed, a secret the key derives from its
//!    factors and the message, so a weak seed alone does not make r predictable; the message
//!    becomes m * r^e mod n.
//! 2. Each half raises the blinded message reduced mod p (and q) to dp (dq), then multiplies by
//!    r^-1 mod p (q), computed as r^(p-2) by the same constant-time exponentiation (Fermat).
//! 3. Garner recombination: s = sq + q * (qinv * (sp - sq) mod p), all in constant time.
//! 4. Fault check on the exact bytes to be released: they must encode a value below n whose
//!    e-th power mod n is m. A result that fails it is never written out.
const std = @import("std");
const builtin = @import("builtin");
const ct = @import("p256/Montgomery.zig");

const addc = ct.addc;
const subb = ct.subb;
const maskOf = ct.maskOf;

/// Limbs of the largest modulus (4096 bits) and of the largest factor (2048 bits).
pub const max_limbs = 64;
pub const max_half = max_limbs / 2;
/// The largest modulus in bytes, which is also the longest result.
pub const max_bytes = max_limbs * 8;
/// Bytes of the caller's seed for the blinding value.
pub const seed_length = 32;

pub const InitError = error{InvalidKey};
pub const Error = error{SigningFailed};

const Limbs = [max_limbs]u64;

/// An odd modulus with its Montgomery constants, R = 2^(64 * len).
const Modulus = struct {
    m: Limbs = @splat(0),
    /// R^2 and R^3 mod m.
    rr: Limbs = @splat(0),
    rrr: Limbs = @splat(0),
    /// -m^-1 mod 2^64.
    inv: u64 = 0,
    len: usize = 0,

    fn init(out: *Modulus, bytes: []const u8, len: usize) InitError!void {
        @setRuntimeSafety(true);
        out.* = .{ .len = len };
        try decode(out.m[0..len], bytes);
        if (out.m[0] & 1 == 0) return error.InvalidKey;
        var v: u64 = out.m[0];
        // Newton's iteration doubles the correct low bits: 3, 6, 12, 24, 48, 96.
        for (0..5) |_| v *%= 2 -% out.m[0] *% v;
        out.inv = 0 -% v;
        // R^2 mod m by doubling 1 in 2 * 64 * len steps, each a masked conditional subtraction.
        const rr = out.rr[0..len];
        rr[0] = 1;
        for (0..2 * 64 * len) |_| {
            var carry: u64 = 0;
            for (rr) |*limb| {
                const next = limb.* >> 63;
                limb.* = (limb.* << 1) | carry;
                carry = next;
            }
            out.reduceOnce(rr, rr, carry);
        }
        out.mul(out.rrr[0..len], rr, rr);
    }

    fn slice(self: *const Modulus) []const u64 {
        return self.m[0..self.len];
    }

    /// `out = t - m` when `high:t` is at least m, else `t`; `high:t` must be below 2m.
    fn reduceOnce(self: *const Modulus, out: []u64, t: []const u64, high: u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        var d: Limbs = undefined;
        defer wipe(&d);
        var borrow: u1 = 0;
        for (0..len) |i| d[i], borrow = subb(t[i], self.m[i], borrow);
        // high:t >= m exactly when the high limb is set or the subtraction did not borrow.
        const take = maskOf(@as(u1, @truncate(high)) | (borrow ^ 1)); // safe: high is a carry, zero or one
        for (0..len) |i| out[i] = (t[i] & ~take) | (d[i] & take);
    }

    /// Montgomery product `out = a * b / R mod m` for `a, b` below m; `out` may alias either.
    fn mul(self: *const Modulus, out: []u64, a: []const u64, b: []const u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        var t: [max_limbs + 2]u64 = @splat(0);
        defer wipe(&t);
        for (0..len) |i| {
            var carry: u64 = 0;
            for (0..len) |j| {
                const p = @as(u128, a[j]) * b[i] + t[j] + carry;
                t[j] = @truncate(p); // safe: the low word; the high word carries
                carry = @truncate(p >> 64); // safe: (2^64-1)^2 + 2(2^64-1) fits 128 bits
            }
            var s = @as(u128, t[len]) + carry;
            t[len] = @truncate(s); // safe: the low word
            t[len + 1] = @truncate(s >> 64); // safe: a single carry bit
            const u = t[0] *% self.inv;
            var c: u64 = @truncate((@as(u128, u) * self.m[0] + t[0]) >> 64); // safe: the low word cancels by the choice of u
            for (1..len) |j| {
                const p = @as(u128, u) * self.m[j] + t[j] + c;
                t[j - 1] = @truncate(p); // safe: the low word, shifted down one limb
                c = @truncate(p >> 64); // safe: the high word
            }
            s = @as(u128, t[len]) + c;
            t[len - 1] = @truncate(s); // safe: the low word
            t[len] = t[len + 1] + @as(u64, @truncate(s >> 64)); // safe: the sum stays below 2m < 2R
        }
        self.reduceOnce(out, t[0..len], t[len]);
    }

    /// Montgomery reduction `out = t / R mod m` of a `t` below m * R of at most 2 * len limbs.
    fn reduce(self: *const Modulus, out: []u64, input: []const u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        std.debug.assert(input.len <= 2 * len);
        var t: [2 * max_limbs + 1]u64 = @splat(0);
        defer wipe(&t);
        @memcpy(t[0..input.len], input);
        for (0..len) |i| {
            const u = t[i] *% self.inv;
            var carry: u64 = 0;
            for (0..len) |j| {
                const p = @as(u128, u) * self.m[j] + t[i + j] + carry;
                t[i + j] = @truncate(p); // safe: the low word
                carry = @truncate(p >> 64); // safe: the high word
            }
            // The carry runs to the top on every iteration: no early stop on a zero carry.
            var c: u1 = 0;
            t[i + len], c = addc(t[i + len], carry, 0);
            for (t[i + len + 1 .. 2 * len + 1]) |*limb| limb.*, c = addc(limb.*, 0, c);
        }
        self.reduceOnce(out, t[len .. 2 * len], t[2 * len]);
    }

    /// The Montgomery form of `x`, a value below m * R of at most 2 * len limbs: x * R mod m.
    fn toMontgomery(self: *const Modulus, out: []u64, x: []const u64) void {
        @setRuntimeSafety(true);
        // reduce gives x / R; multiplying by R^3 gives x * R.
        self.reduce(out, x);
        self.mul(out, out, self.rrr[0..self.len]);
    }

    /// `out = a - b mod m` for `a, b` below m.
    fn sub(self: *const Modulus, out: []u64, a: []const u64, b: []const u64) void {
        @setRuntimeSafety(true);
        var borrow: u1 = 0;
        for (0..self.len) |i| out[i], borrow = subb(a[i], b[i], borrow);
        const add = maskOf(borrow);
        var carry: u1 = 0;
        for (0..self.len) |i| out[i], carry = addc(out[i], self.m[i] & add, carry);
    }

    /// `out = base^e` in Montgomery form for a public exponent: the schedule follows e's bits.
    fn powPublic(self: *const Modulus, out: []u64, base: []const u64, e: u64) void {
        @setRuntimeSafety(true);
        std.debug.assert(e != 0);
        var acc: Limbs = undefined;
        defer wipe(&acc);
        const len = self.len;
        @memcpy(acc[0..len], base);
        var bit: u6 = @intCast(63 - @as(u32, @clz(e))); // safe: e is nonzero, so its top bit index is below 64
        while (bit > 0) {
            bit -= 1;
            self.mul(acc[0..len], acc[0..len], acc[0..len]);
            if ((e >> bit) & 1 == 1) self.mul(acc[0..len], acc[0..len], base);
        }
        @memcpy(out, acc[0..len]);
    }

    /// `out = base^exponent` in Montgomery form for a secret `exponent` of `len` limbs: fixed
    /// four-bit windows from the top over all 64 * len bits, each window's multiple chosen by a
    /// scan of the whole table.
    fn powSecret(self: *const Modulus, out: []u64, base: []const u64, exponent: []const u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        var table: [16][max_half]u64 = undefined;
        defer wipe(&table);
        var acc: [max_half]u64 = undefined;
        defer wipe(&acc);
        var chosen: [max_half]u64 = undefined;
        defer wipe(&chosen);
        var window: u64 = 0;
        defer wipe(&window);
        std.debug.assert(len <= max_half);
        // table[i] = base^i: table[0] is R mod m, the form of one.
        var one: Limbs = @splat(0);
        one[0] = 1;
        self.mul(table[0][0..len], self.rr[0..len], one[0..len]);
        @memcpy(table[1][0..len], base);
        for (2..16) |i| self.mul(table[i][0..len], table[i - 1][0..len], base);
        @memcpy(acc[0..len], table[0][0..len]);
        var bit = 64 * len;
        while (bit > 0) {
            bit -= 4;
            for (0..4) |_| self.mul(acc[0..len], acc[0..len], acc[0..len]);
            window = (exponent[bit / 64] >> @as(u6, @intCast(bit % 64))) & 15; // safe: a public bit offset below 64
            select(chosen[0..len], &table, window);
            self.mul(acc[0..len], acc[0..len], chosen[0..len]);
        }
        @memcpy(out, acc[0..len]);
    }
};

/// Copies `table[index]` by reading every entry and keeping one through a mask.
fn select(out: []u64, table: *const [16][max_half]u64, index: u64) void {
    @setRuntimeSafety(true);
    @memset(out, 0);
    for (table, 0..) |*entry, i| {
        const x = @as(u64, i) ^ index;
        // All ones exactly when x is zero.
        const keep = maskOf(@as(u1, @truncate((x | (0 -% x)) >> 63)) ^ 1); // safe: the top bit is set exactly when x != 0
        for (out, entry[0..out.len]) |*o, v| o.* |= v & keep;
    }
}

/// A big-endian integer into `out`; it must fit.
fn decode(out: []u64, bytes: []const u8) InitError!void {
    @setRuntimeSafety(true);
    @memset(out, 0);
    if (bytes.len > out.len * 8) return error.InvalidKey;
    for (0..bytes.len) |k| {
        const byte = bytes[bytes.len - 1 - k];
        out[k / 8] |= @as(u64, byte) << @as(u6, @intCast(8 * (k % 8))); // safe: a public byte offset below 64 bits
    }
}

/// `x` big-endian into all of `out`; the value must fit.
fn encode(out: []u8, x: []const u64) void {
    @setRuntimeSafety(true);
    for (0..out.len) |k| {
        const limb = if (k / 8 < x.len) x[k / 8] else 0;
        out[out.len - 1 - k] = @truncate(limb >> @as(u6, @intCast(8 * (k % 8)))); // safe: one byte of a limb at a public offset
    }
}

fn limbsOf(bytes: []const u8) usize {
    @setRuntimeSafety(true);
    return (bytes.len + 7) / 8;
}

fn wipe(value: anytype) void {
    std.crypto.secureZero(u8, std.mem.asBytes(value));
}

/// A two-prime RSA private key, ready for the CRT operation. Holds secrets: the owner erases it.
pub const PrivateKey = struct {
    n: Modulus,
    p: Modulus,
    q: Modulus,
    dp: Limbs,
    dq: Limbs,
    qinv: Limbs,
    /// p - 2 and q - 2, the inversion exponents.
    p2: Limbs,
    q2: Limbs,
    e: u64,
    /// The modulus in bytes and bits: the result's length and the PSS encoding's width.
    size: usize,
    bits: usize,
    /// A secret hedge for the blinding draw, derived from the factors.
    hedge: [32]u8,

    /// The key from its big-endian parts. They must be a consistent, validated key: odd n
    /// up to 4096 bits with odd prime factors up to 2048 bits each, dp and dq reduced, qinv
    /// below p, e up to 64 bits.
    pub fn init(out: *PrivateKey, n: []const u8, e: []const u8, p: []const u8, q: []const u8, dp: []const u8, dq: []const u8, qinv: []const u8) InitError!void {
        @setRuntimeSafety(true);
        if (n.len == 0 or n[0] == 0 or n.len > max_bytes or e.len == 0 or e.len > 8) return error.InvalidKey;
        const half = @max(limbsOf(p), limbsOf(q));
        // n = pq fits 2 * half limbs; the reductions mod p and q rely on it.
        if (half > max_half or limbsOf(n) > 2 * half) return error.InvalidKey;
        out.* = std.mem.zeroes(PrivateKey);
        out.size = n.len;
        out.bits = 8 * n.len - @clz(n[0]);
        out.e = 0;
        for (e) |byte| out.e = (out.e << 8) | byte;
        if (out.e < 3 or out.e & 1 == 0) return error.InvalidKey;
        try out.n.init(n, limbsOf(n));
        try out.p.init(p, half);
        try out.q.init(q, half);
        try decode(out.dp[0..half], dp);
        try decode(out.dq[0..half], dq);
        try decode(out.qinv[0..half], qinv);
        var two: Limbs = @splat(0);
        two[0] = 2;
        var borrow: u1 = 0;
        for (0..half) |i| out.p2[i], borrow = subb(out.p.m[i], two[i], borrow);
        borrow = 0;
        for (0..half) |i| out.q2[i], borrow = subb(out.q.m[i], two[i], borrow);
        var xof = std.crypto.hash.sha3.Shake256.init(.{});
        defer wipe(&xof);
        xof.update("cloak rsa blinding hedge");
        xof.update(p);
        xof.update(q);
        xof.squeeze(&out.hedge);
    }

    /// `out = m^d mod n` for `m` big-endian of `size` bytes below n; `out` is `size` bytes.
    /// `seed` is fresh: the blinding value derives from it. The result is verified against the
    /// public key before it is written.
    pub fn private(key: *const PrivateKey, m: []const u8, seed: *const [seed_length]u8, out: []u8) Error!void {
        return key.privateFaulted(m, seed, out, .none);
    }

    /// Faults a test injects to prove the check catches them: into one half after its
    /// exponentiation, or into the encoded bytes after recombination.
    pub const Fault = enum { none, p_half, q_half, encoded };

    fn privateFaulted(key: *const PrivateKey, m_bytes: []const u8, seed: *const [seed_length]u8, out: []u8, comptime fault: Fault) Error!void {
        @setRuntimeSafety(true);
        if (m_bytes.len != key.size or out.len != key.size) return error.SigningFailed;
        const n = &key.n;
        const l = n.len;
        const h = key.p.len;
        var s: Scratch = undefined;
        defer wipe(&s);
        decode(s.m[0..l], m_bytes) catch return error.SigningFailed;
        // The message is public (the signature reveals it): range-checking it may branch.
        var borrow: u1 = 0;
        for (0..l) |i| _, borrow = subb(s.m[i], n.m[i], borrow);
        if (borrow == 0) return error.SigningFailed;

        // Blinding: r_mont is the Montgomery form of a uniform r (bias below 2^-64): the reduction
        // of a uniform (l + 1)-limb draw, read as Montgomery form, is uniform mod n.
        var xof = std.crypto.hash.sha3.Shake256.init(.{});
        defer wipe(&xof);
        xof.update("cloak rsa blinding");
        xof.update(&key.hedge);
        xof.update(seed);
        xof.update(m_bytes);
        var draw: [(max_limbs + 1) * 8]u8 = undefined;
        defer wipe(&draw);
        xof.squeeze(draw[0 .. (l + 1) * 8]);
        for (0..l + 1) |i| s.wide[i] = std.mem.readInt(u64, draw[i * 8 ..][0..8], .little);
        n.reduce(s.r[0..l], s.wide[0 .. l + 1]);
        // mb = m * r^e mod n, plain.
        n.mul(s.t[0..l], s.m[0..l], n.rr[0..l]);
        n.powPublic(s.u[0..l], s.r[0..l], key.e);
        n.mul(s.t[0..l], s.t[0..l], s.u[0..l]);
        n.reduce(s.mb[0..l], s.t[0..l]);
        // r plain, for its inverses mod p and q.
        n.reduce(s.r[0..l], s.r[0..l]);

        key.crtHalf(&key.p, &key.dp, &key.p2, &s, s.sp[0..h]);
        key.crtHalf(&key.q, &key.dq, &key.q2, &s, s.sq[0..h]);
        switch (fault) {
            .none => {},
            .p_half => s.sp[0] ^= 1,
            .q_half => s.sq[0] ^= 1,
            .encoded => {},
        }

        // Garner: h = qinv * (sp - sq) mod p, s = sq + q * h. sq comes out of Montgomery form
        // mod q, then into Montgomery form mod p (sq < q < R_p, so the reduction is in range).
        key.q.reduce(s.t[0..h], s.sq[0..h]);
        key.p.toMontgomery(s.u[0..h], s.t[0..h]);
        key.p.sub(s.u[0..h], s.sp[0..h], s.u[0..h]);
        key.p.mul(s.u[0..h], s.u[0..h], key.qinv[0..h]);
        // s.t (sq, plain) + q * s.u (h, plain), 2h limbs, carries through the full width.
        @memset(s.wide[0 .. 2 * h + 1], 0);
        @memcpy(s.wide[0..h], s.t[0..h]);
        for (0..h) |i| {
            var carry: u64 = 0;
            for (0..h) |j| {
                const p = @as(u128, key.q.m[j]) * s.u[i] + s.wide[i + j] + carry;
                s.wide[i + j] = @truncate(p); // safe: the low word
                carry = @truncate(p >> 64); // safe: the high word
            }
            var c: u1 = 0;
            s.wide[i + h], c = addc(s.wide[i + h], carry, 0);
            for (s.wide[i + h + 1 .. 2 * h + 1]) |*limb| limb.*, c = addc(limb.*, 0, c);
        }
        // s < n, so the limbs above l are zero when nothing faulted.
        var high: u64 = 0;
        for (s.wide[l .. 2 * h + 1]) |limb| high |= limb;

        // The bytes to release, then the fault check against the public key on exactly those
        // bytes: they must decode below n, and unblinding and recombination must give m back.
        const bytes = s.bytes[0..key.size];
        encode(bytes, s.wide[0..l]);
        if (fault == .encoded) bytes[key.size / 2] ^= 0x10;
        decode(s.t[0..l], bytes) catch return error.SigningFailed;
        borrow = 0;
        for (0..l) |i| _, borrow = subb(s.t[i], n.m[i], borrow);
        // Montgomery multiplication takes an operand below R, so a faulty value at or above n
        // still reduces correctly; the borrow above refuses it on its own.
        n.mul(s.u[0..l], s.t[0..l], n.rr[0..l]);
        n.powPublic(s.u[0..l], s.u[0..l], key.e);
        n.reduce(s.u[0..l], s.u[0..l]);
        var difference: u64 = high | (borrow ^ 1);
        for (0..l) |i| difference |= s.u[i] ^ s.m[i];
        // Whether the signature is released is public: the branch reveals only a fault.
        if (ct.barrier(difference) != 0) return error.SigningFailed;
        @memcpy(out, bytes);
    }

    /// One CRT half: `out = (mb mod m)^d * (r mod m)^-1 mod m`, in Montgomery form.
    fn crtHalf(key: *const PrivateKey, m: *const Modulus, d: *const Limbs, minus_two: *const Limbs, s: *Scratch, out: []u64) void {
        @setRuntimeSafety(true);
        const l = key.n.len;
        const h = m.len;
        // mb < n = pq and the other factor is below R_m, so mb < m * R_m.
        m.toMontgomery(s.x[0..h], s.mb[0..l]);
        m.powSecret(s.y[0..h], s.x[0..h], d[0..h]);
        m.toMontgomery(s.x[0..h], s.r[0..l]);
        m.powSecret(s.x[0..h], s.x[0..h], minus_two[0..h]);
        m.mul(out, s.y[0..h], s.x[0..h]);
    }
};

/// Every secret temporary of one operation, in one owner wiped on return.
const Scratch = struct {
    m: Limbs,
    r: Limbs,
    mb: Limbs,
    t: Limbs,
    u: Limbs,
    x: Limbs,
    y: Limbs,
    sp: Limbs,
    sq: Limbs,
    wide: [2 * max_limbs + 1]u64,
    /// The result as released, checked before it is copied out.
    bytes: [max_bytes]u8,
};

/// Test seam: the operation with a fault injected into one half after its exponentiation.
pub fn privateWithFault(key: *const PrivateKey, m: []const u8, seed: *const [seed_length]u8, out: []u8, comptime fault: PrivateKey.Fault) Error!void {
    if (!builtin.is_test) @compileError("fault injection is a test seam");
    return key.privateFaulted(m, seed, out, fault);
}

test {
    _ = @import("rsa_test.zig");
}
