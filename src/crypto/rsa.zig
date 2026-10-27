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
//! The Montgomery multiplications and squarings are s2n-bignum's verified routines where the
//! build has its assembly (`field/bignum.zig`: Karatsuba and `emontredc_8n` at multiples of 8
//! limbs, its generic routines at other widths), else the CIOS loop below, which is also the
//! reference the assembly is tested against.
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
const aegis = @import("aegis");
const builtin = @import("builtin");
const ct = @import("field/Montgomery.zig");
const bignum = @import("field/bignum.zig");
const Secret = aegis.secret.Secret;

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

/// An odd modulus with its Montgomery constants, R = 2^(64 * len). Key generation
/// (`rsa_keygen.zig`) tests its candidates and inverts with it.
pub const Modulus = struct {
    m: Limbs = @splat(0),
    /// R^2 and R^3 mod m.
    rr: Limbs = @splat(0),
    rrr: Limbs = @splat(0),
    /// -m^-1 mod 2^64.
    inv: u64 = 0,
    len: usize = 0,

    pub fn init(out: *Modulus, bytes: []const u8, len: usize) InitError!void {
        @setRuntimeSafety(true);
        out.* = .{ .len = len };
        try decode(out.m[0..len], bytes);
        if (out.m[0] & 1 == 0) return error.InvalidKey;
        var v: u64 = out.m[0];
        // Newton's iteration doubles the correct low bits: 3, 6, 12, 24, 48, 96.
        for (0..5) |_| v *%= 2 -% out.m[0] *% v;
        out.inv = 0 -% v;
        // R^2 mod m: 1 doubled 64 * len + len times, each a masked conditional subtraction, is
        // 2^len in Montgomery form; six Montgomery squarings make it 2^(64 * len) = R in that
        // form, which is R^2 mod m. Half the doublings of doubling all the way.
        // The doublings below the modulus's width only shift: begin at its top bit (the width is
        // public, as every RSA implementation takes it), which is below m.
        const rr = out.rr[0..len];
        const width = bitLength(out.m[0..len]);
        rr[(width - 1) / 64] = @as(u64, 1) << @intCast((width - 1) % 64); // safe: the remainder of a division by 64
        for (0..65 * len - (width - 1)) |_| {
            var carry: u64 = 0;
            for (rr) |*limb| {
                const next = limb.* >> 63;
                limb.* = (limb.* << 1) | carry;
                carry = next;
            }
            out.reduceOnce(rr, rr, carry);
        }
        for (0..6) |_| out.sqr(rr, rr);
        out.sqr(out.rrr[0..len], rr);
    }

    /// `out = t - m` when `high:t` is at least m, else `t`; `high:t` must be below 2m.
    fn reduceOnce(self: *const Modulus, out: []u64, t: []const u64, high: u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        // The borrow of t - m alone first, then t - (m & take): no difference is held between.
        var borrow: u1 = 0;
        for (0..len) |i| borrow = subb(t[i], self.m[i], borrow)[1];
        // high:t >= m exactly when the high limb is set or the subtraction did not borrow.
        const take = maskOf(@as(u1, @truncate(high)) | (borrow ^ 1)); // aegis: no-danger: high is a carry, zero or one
        borrow = 0;
        for (0..len) |i| {
            const step = subb(t[i], self.m[i] & take, borrow);
            out[i] = step[0];
            borrow = step[1];
        }
    }

    /// Montgomery product `out = a * b / R mod m` for `a, b` below m; `out` may alias either.
    /// s2n-bignum's where the build has it (`field/bignum.zig`), else the CIOS loop.
    fn mul(self: *const Modulus, out: []u64, a: []const u64, b: []const u64) void {
        @setRuntimeSafety(true);
        if (comptime !bignum.assembly) return self.mulPortable(out, a, b);
        switch (bignum.path(self.len)) {
            .fast => {
                var owner: Secret(bignum.Wide) = .init(undefined);
                defer owner.deinit();
                const wide = owner.exposeMut();
                bignum.mulFast(wide, self.len, a, b, &self.m, self.inv);
                self.reduceOnce(out, wide.words[self.len .. 2 * self.len], wide.carry);
            },
            .generic => bignum.mulGeneric(out[0..self.len], a, b, self.m[0..self.len]),
        }
    }

    /// Montgomery square `out = a^2 / R mod m` for `a` below m; `out` may alias it.
    fn sqr(self: *const Modulus, out: []u64, a: []const u64) void {
        @setRuntimeSafety(true);
        if (comptime !bignum.assembly) return self.mulPortable(out, a, a);
        switch (bignum.path(self.len)) {
            .fast => {
                var owner: Secret(bignum.Wide) = .init(undefined);
                defer owner.deinit();
                const wide = owner.exposeMut();
                bignum.sqrFast(wide, self.len, a, &self.m, self.inv);
                self.reduceOnce(out, wide.words[self.len .. 2 * self.len], wide.carry);
            },
            .generic => bignum.sqrGeneric(out[0..self.len], a, self.m[0..self.len]),
        }
    }

    /// The CIOS loop: the product where there is no assembly, and the reference every
    /// s2n-bignum path is tested against.
    fn mulPortable(self: *const Modulus, out: []u64, a: []const u64, b: []const u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        var owner: Secret([max_limbs + 2]u64) = .init(undefined);
        defer owner.deinit();
        const t = owner.exposeMut();
        @memset(t[0 .. len + 2], 0);
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
    pub fn reduce(self: *const Modulus, out: []u64, input: []const u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        aegis.assert.invariant(input.len <= 2 * len, "a reduction takes at most twice the modulus");
        var owner: Secret([2 * max_limbs + 1]u64) = .init(@splat(0));
        defer owner.deinit();
        const t = owner.exposeMut();
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
    pub fn toMontgomery(self: *const Modulus, out: []u64, x: []const u64) void {
        @setRuntimeSafety(true);
        // reduce gives x / R; multiplying by R^3 gives x * R.
        self.reduce(out, x);
        self.mul(out, out, self.rrr[0..self.len]);
    }

    /// `out = a - b mod m` for `a, b` below m.
    pub fn sub(self: *const Modulus, out: []u64, a: []const u64, b: []const u64) void {
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
        aegis.assert.invariant(e != 0, "a public exponent is nonzero");
        var owner: Secret(Limbs) = .init(undefined);
        defer owner.deinit();
        const acc = owner.exposeMut();
        const len = self.len;
        @memcpy(acc[0..len], base);
        var bit: u6 = @intCast(63 - @as(u32, @clz(e))); // safe: e is nonzero, so its top bit index is below 64
        while (bit > 0) {
            bit -= 1;
            self.sqr(acc[0..len], acc[0..len]);
            if ((e >> bit) & 1 == 1) self.mul(acc[0..len], acc[0..len], base);
        }
        @memcpy(out, acc[0..len]);
    }

    /// `out = base^exponent` in Montgomery form for a secret `exponent` of `len` limbs: fixed
    /// four-bit windows from the top over all 64 * len bits, each window's multiple chosen by a
    /// scan of the whole table.
    pub fn powSecret(self: *const Modulus, out: []u64, base: []const u64, exponent: []const u64) void {
        @setRuntimeSafety(true);
        const len = self.len;
        var owner: Secret(struct { table: [16][max_half]u64, acc: [max_half]u64, chosen: [max_half]u64, window: u64 }) = .init(undefined);
        defer owner.deinit();
        const work = owner.exposeMut();
        const table = &work.table;
        const acc = &work.acc;
        const chosen = &work.chosen;
        const window = &work.window;
        aegis.assert.invariant(len <= max_half, "a CRT half fits its buffers");
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
            for (0..4) |_| self.sqr(acc[0..len], acc[0..len]);
            window.* = (exponent[bit / 64] >> @as(u6, @intCast(bit % 64))) & 15; // aegis: no-danger: a public bit offset below 64
            select(chosen[0..len], table, window.*);
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

/// The bit length of a public value: the position of its top set bit, plus one.
fn bitLength(limbs: []const u64) usize {
    var i = limbs.len;
    while (i > 0) {
        i -= 1;
        if (limbs[i] != 0) return 64 * i + 64 - @clz(limbs[i]);
    }
    return 0;
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
        var xof_owner: Secret(std.crypto.hash.sha3.Shake256) = .init(.init(.{}));
        defer xof_owner.deinit();
        const xof = xof_owner.exposeMut();
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
        var owner: Secret(Scratch) = .init(undefined);
        defer owner.deinit();
        const s = owner.exposeMut();
        try key.blind(m_bytes, seed, s);

        key.crtHalf(&key.p, &key.dp, &key.p2, s, s.sp[0..h]);
        key.crtHalf(&key.q, &key.dq, &key.q2, s, s.sq[0..h]);
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
        var borrow: u1 = 0;
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

    /// Fills `s.m` with the message, `s.r` with a fresh blinding value r and `s.mb` with
    /// m * r^e mod n, all plain.
    fn blind(key: *const PrivateKey, m_bytes: []const u8, seed: *const [seed_length]u8, s: *Scratch) Error!void {
        @setRuntimeSafety(true);
        const n = &key.n;
        const l = n.len;
        decode(s.m[0..l], m_bytes) catch return error.SigningFailed;
        // The message is public (the signature reveals it): range-checking it may branch.
        var borrow: u1 = 0;
        for (0..l) |i| _, borrow = subb(s.m[i], n.m[i], borrow);
        if (borrow == 0) return error.SigningFailed;

        // r_mont is the Montgomery form of a uniform r (bias below 2^-64): the reduction of a
        // uniform (l + 1)-limb draw, read as Montgomery form, is uniform mod n.
        var xof_owner: Secret(std.crypto.hash.sha3.Shake256) = .init(.init(.{}));
        defer xof_owner.deinit();
        const xof = xof_owner.exposeMut();
        xof.update("cloak rsa blinding");
        xof.update(&key.hedge);
        xof.update(seed);
        xof.update(m_bytes);
        var draw_owner: Secret([(max_limbs + 1) * 8]u8) = .init(undefined);
        defer draw_owner.deinit();
        const draw = draw_owner.exposeMut();
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

/// Test seam: the blinding value r and the blinded message m * r^e mod n an operation on `m`
/// with `seed` would exponentiate, as little-endian limbs.
pub fn blindingForTest(key: *const PrivateKey, m: []const u8, seed: *const [seed_length]u8, r: []u64, mb: []u64) Error!void {
    if (!builtin.is_test) @compileError("the blinding values are a test seam");
    var owner: Secret(Scratch) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    try key.blind(m, seed, s);
    @memcpy(r, s.r[0..key.n.len]);
    @memcpy(mb, s.mb[0..key.n.len]);
}

test {
    _ = @import("rsa_test.zig");
}

test "F05 catalogue_kernel_carries_lengths_and_dispatch (RSA: s2n-bignum's Montgomery multiplication and squaring equal the CIOS loop, every width)" {
    if (!bignum.assembly) return error.SkipZigTest;
    var random = std.Random.DefaultPrng.init(0x125a);
    var modulus: Modulus = undefined;
    for (1..max_limbs + 1) |len| {
        for (0..if (len % 8 == 0) 24 else 3) |round| {
            var bytes: [max_bytes]u8 = undefined;
            random.fill(bytes[0 .. 8 * len]);
            bytes[8 * len - 1] |= 1;
            // The top limb with its top bit set, and in some rounds small: both edges of a width.
            bytes[0] = if (round % 3 == 2) 0 else bytes[0] | 0x80;
            if (round % 3 == 2) bytes[1] |= 1;
            try modulus.init(bytes[0 .. 8 * len], len);
            const m = modulus.m[0..len];
            var operands: [6]Limbs = undefined;
            for (operands[0..4]) |*x| {
                // Reduced to below m: a random value times R^2 / R.
                var raw: Limbs = @splat(0);
                for (raw[0 .. len - 1]) |*limb| limb.* = random.next();
                modulus.mulPortable(x[0..len], raw[0..len], modulus.rr[0..len]);
            }
            operands[4] = @splat(0);
            operands[4][0] = 1;
            var borrow: u1 = 0;
            for (0..len) |i| operands[5][i], borrow = subb(m[i], operands[4][i], borrow);
            for (&operands) |*x| for (&operands) |*y| {
                var ours: Limbs = undefined;
                var theirs: Limbs = undefined;
                modulus.mul(ours[0..len], x[0..len], y[0..len]);
                modulus.mulPortable(theirs[0..len], x[0..len], y[0..len]);
                try std.testing.expectEqualSlices(u64, theirs[0..len], ours[0..len]);
            };
            for (&operands) |*x| {
                var ours: Limbs = undefined;
                var theirs: Limbs = undefined;
                modulus.sqr(ours[0..len], x[0..len]);
                modulus.mulPortable(theirs[0..len], x[0..len], x[0..len]);
                try std.testing.expectEqualSlices(u64, theirs[0..len], ours[0..len]);
                // In place, as the walk squares.
                ours = x.*;
                modulus.sqr(ours[0..len], ours[0..len]);
                try std.testing.expectEqualSlices(u64, theirs[0..len], ours[0..len]);
            }
        }
    }
}
