//! RSA key generation, FIPS 186-5 A.1.3 (random probable primes), e = 65537, constant time on
//! every value that is kept.
//!
//! Candidates have the top two bits set (p > sqrt(2) * 2^(bits-1), and n never a bit short) and
//! are 7 mod 8, so (w - 1)/2 is odd and Miller-Rabin's power of two is 1: one exponentiation and
//! a comparison with +-1, with no loop whose length depends on the candidate. Trial division by
//! the odd primes below 2^12 and the test w mod e != 1 use a multiply-and-correct reduction (no
//! hardware division); Miller-Rabin exponentiates with the RSA modulus code's constant-time
//! window. Only "rejected" ever leaves, about a value that is thrown away.
//!
//! d = e^-1 mod lambda(n), lambda = lcm(p - 1, q - 1) = 2 a' (b' / g) for a' = (p - 1)/2,
//! b' = (q - 1)/2 and g = gcd(a', b') (a fixed-iteration binary gcd; g at or above 2^32 rejects
//! the pair, as Go does, with probability near 2^-32). With e prime, t = x mod e and
//! u = t^(e-2) mod e give e^-1 mod x = (1 + x (e - u)) / e, an exact division done by
//! multiplying by e^-1 mod 2^64 limb by limb: d from lambda, dp and dq from p - 1 and q - 1.
//! qinv = q^(p-2) mod p.
const std = @import("std");
const aegis = @import("aegis");
const Secret = aegis.secret.Secret;
const rsa = @import("../rsa.zig");
const ct = @import("../field.zig").Montgomery;

const addc = ct.addc;
const subb = ct.subb;
const maskOf = ct.maskOf;

pub const e: u32 = 65537;

/// The sizes generated: the FIPS 186-5 ones cloak's private operation holds.
pub const Size = enum(u16) {
    @"2048" = 2048,
    @"3072" = 3072,
    @"4096" = 4096,

    fn bits(size: Size) usize {
        return @backingInt(size);
    }
};

pub const Error = error{ EntropyUnavailable, GenerationFailed };

/// `io.randomSecure` as a source: what `PrivateKey.generate` draws from.
pub const IoSource = struct {
    io: std.Io,

    pub fn fill(self: *const IoSource, buffer: []u8) error{EntropyUnavailable}!void {
        self.io.randomSecure(buffer) catch return error.EntropyUnavailable;
    }
};

/// A key's numbers as `Rsa.fromIntegers` takes them: unsigned big-endian in their fewest
/// bytes, n, e, d, p, q, dp, dq and qinv. The owner wipes it.
pub const Integers = struct {
    buffers: [8][rsa.max_bytes]u8,
    lengths: [8]usize,

    pub fn slices(self: *const Integers) [8][]const u8 {
        var out: [8][]const u8 = undefined;
        for (&out, &self.buffers, self.lengths) |*slice, *buffer, length| slice.* = buffer[rsa.max_bytes - length ..];
        return out;
    }

    fn set(self: *Integers, index: usize, limbs: []const u64) void {
        const bytes = &self.buffers[index];
        @memset(bytes, 0);
        for (limbs, 0..) |limb, i| std.mem.writeInt(u64, bytes[rsa.max_bytes - 8 * (i + 1) ..][0..8], limb, .big);
        // The fewest bytes: the length of a key's number is public, as its encoding shows it.
        var length: usize = 8 * limbs.len;
        while (length > 1 and bytes[rsa.max_bytes - length] == 0) length -= 1;
        self.lengths[index] = length;
    }
};

const Limbs = [rsa.max_limbs]u64;
const Half = [rsa.max_half]u64;

/// The most candidates one prime may take before the source is presumed broken: at the density
/// of primes among 7 mod 8 values of 2048 bits (about 1 in 355), never reached by chance.
const max_candidates = 1 << 16;

/// A new key of `size` from `source`, which has `fill(buffer) error{EntropyUnavailable}!void`
/// and must be a cryptographic source (a key from a predictable one is predictable). The whole
/// runs as one secret computation, its stack scrubbed after.
pub fn generate(size: Size, source: anytype, out: *Integers) Error!void {
    return aegis.secret.scrubbed(depth, generateKernel, .{ size, source, out });
}

/// The stack `generateKernel` reaches at most, which a test holds it to: its state, the
/// window's table and the products' temporaries. Debug keeps more copies in its frames.
pub const depth = if (@import("builtin").mode == .debug) 48 * 1024 else 32 * 1024;

pub fn generateKernel(size: Size, source: anytype, out: *Integers) Error!void {
    var owner: Secret(State) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    const half = size.bits() / 2;
    const k = half / 64;
    while (true) {
        try randomPrime(half, source, s, &s.p);
        try randomPrime(half, source, s, &s.q);
        if (try derive(size, s, k)) break;
    }
    out.* = undefined;
    out.set(0, s.n[0 .. 2 * k]);
    out.set(1, &.{e});
    out.set(2, s.d[0 .. 2 * k]);
    out.set(3, s.p[0..k]);
    out.set(4, s.q[0..k]);
    out.set(5, s.dp[0..k]);
    out.set(6, s.dq[0..k]);
    out.set(7, s.qinv[0..k]);
}

/// Every secret of one generation, in one owner wiped on return.
pub const State = struct {
    p: Half,
    q: Half,
    n: Limbs,
    d: Limbs,
    dp: Half,
    dq: Half,
    qinv: Half,
    // Working values.
    draw: [rsa.max_half * 8]u8,
    a: Half,
    b: Half,
    g: Half,
    lambda: Limbs,
    wide: [rsa.max_limbs + 1]u64,
    modulus: rsa.Modulus,
    x: Half,
    y: Half,
    one: Half,
    minus_one: Half,
};

/// Builds n, lambda, d, dp, dq and qinv from p and q in `s`, or false when the pair fails a
/// check FIPS 186-5 makes (|p - q| too small, d too small) or g is too large.
fn derive(size: Size, s: *State, k: usize) Error!bool {
    const nlen = size.bits();
    // |p - q| > 2^(nlen/2 - 100).
    var borrow: u1 = 0;
    for (0..k) |i| s.a[i], borrow = subb(s.p[i], s.q[i], borrow);
    negateIf(s.a[0..k], borrow);
    if (!greaterThanPowerOfTwo(s.a[0..k], nlen / 2 - 100)) return false;
    // a' = (p - 1)/2 and b' = (q - 1)/2, both odd: p and q are 7 mod 8.
    shiftRightOne(s.a[0..k], s.p[0..k]);
    shiftRightOne(s.b[0..k], s.q[0..k]);
    gcdOdd(s.g[0..k], s.a[0..k], s.b[0..k]);
    // g below 2^32, or the pair is refused.
    var high: u64 = s.g[0] >> 32;
    for (s.g[1..k]) |limb| high |= limb;
    if (ct.barrier(high) != 0) return false;
    const g: u32 = @truncate(s.g[0]); // checked below 2^32 above
    // lambda = 2 a' (b' / g); b' is a multiple of g.
    divideSmall(s.b[0..k], s.b[0..k], g);
    multiply(s.lambda[0 .. 2 * k], s.a[0..k], s.b[0..k]);
    _ = shiftLeftOne(s.lambda[0 .. 2 * k]);
    if (!inverseOfE(s.d[0 .. 2 * k], s.lambda[0 .. 2 * k], &s.wide)) return false;
    // d > 2^(nlen/2).
    if (!greaterThanPowerOfTwo(s.d[0 .. 2 * k], nlen / 2)) return false;
    // dp and dq: e is prime to p - 1 and q - 1 (each candidate was checked).
    @memcpy(s.a[0..k], s.p[0..k]);
    s.a[0] -= 1;
    if (!inverseOfE(s.dp[0..k], s.a[0..k], &s.wide)) return error.GenerationFailed;
    @memcpy(s.a[0..k], s.q[0..k]);
    s.a[0] -= 1;
    if (!inverseOfE(s.dq[0..k], s.a[0..k], &s.wide)) return error.GenerationFailed;
    multiply(s.n[0 .. 2 * k], s.p[0..k], s.q[0..k]);
    // qinv = q^(p-2) mod p, by the window, out of Montgomery form.
    s.modulus.init(bigEndian(&s.draw, s.p[0..k]), k) catch return error.GenerationFailed;
    s.modulus.toMontgomery(s.x[0..k], s.q[0..k]);
    @memcpy(s.a[0..k], s.p[0..k]);
    s.a[0] -= 2;
    s.modulus.powSecret(s.y[0..k], s.x[0..k], s.a[0..k]);
    s.modulus.reduce(s.qinv[0..k], s.y[0..k]);
    return true;
}

// ---------------------------------------------------------------- primes

/// Rounds of Miller-Rabin for a candidate p or q of `bits`: FIPS 186-5 Table B.1 (Appendix
/// B.3), its column whose error probability matches the security strength, M-R tests only:
/// 1024 bits 5 rounds (2^-112), 1536 bits 4 (2^-128), 2048 bits 4 (2^-144). Go's counts.
/// Trial division comes first, as B.3 allows, by the primes below 2^12: a limit L within B.3's
/// 10^3 to 10^5 (2 needs no test: every candidate is odd).
fn rounds(bits: usize) usize {
    return if (bits >= 1345) 4 else 5;
}

/// A random probable prime of exactly `bits` bits (a multiple of 64), 7 mod 8, with w mod e != 1.
fn randomPrime(bits: usize, source: anytype, s: *State, out: *Half) Error!void {
    const k = bits / 64;
    const bytes = s.draw[0 .. bits / 8];
    for (0..max_candidates) |_| {
        source.fill(bytes) catch return error.EntropyUnavailable;
        bytes[0] |= 0xc0;
        bytes[bytes.len - 1] |= 0x07;
        fromBigEndian(out[0..k], bytes);
        if (try isProbablePrime(out[0..k], source, s)) return;
    }
    return error.GenerationFailed;
}

/// Whether `w` (odd, 7 mod 8, its top limb nonzero) passes trial division, the e check and
/// Miller-Rabin. Only the verdict leaves; a composite is discarded.
pub fn isProbablePrime(w: []const u64, source: anytype, s: *State) Error!bool {
    // Trial division and the e check, every remainder computed before the verdict.
    var divisible: u64 = 0;
    inline for (small_primes) |prime| divisible |= zeroMask(remainder(w, prime));
    divisible |= zeroMask(remainder(w, e) ^ 1);
    if (ct.barrier(divisible) != 0) return false;
    return millerRabin(w, source, s);
}

/// Miller-Rabin on `w` (odd, 7 mod 8, its top limb nonzero) with `rounds` random bases: for
/// w = 3 mod 4 one exponentiation by (w - 1)/2 per base, compared with +-1.
pub fn millerRabin(w: []const u64, source: anytype, s: *State) Error!bool {
    const k = w.len;
    // Bases are drawn below 2^width, the width public as a candidate's is: at least half of
    // the draws land in range.
    const width_mask = @as(u64, std.math.maxInt(u64)) >> @intCast(@clz(w[k - 1]));
    s.modulus.init(bigEndian(&s.draw, w), k) catch return error.GenerationFailed;
    // 1 and -1 in Montgomery form, and the exponent (w - 1)/2 = w >> 1 for odd w.
    @memset(s.x[0..k], 0);
    s.x[0] = 1;
    s.modulus.toMontgomery(s.one[0..k], s.x[0..k]);
    @memset(s.x[0..k], 0);
    s.modulus.sub(s.minus_one[0..k], s.x[0..k], s.one[0..k]);
    shiftRightOne(s.g[0..k], w);
    var round: usize = 0;
    var draws: usize = 0;
    while (round < rounds(64 * k)) {
        draws += 1;
        if (draws > max_candidates) return error.GenerationFailed;
        // A base uniform in [2, w - 2]: drawn below 2^width and refused outside the range.
        const base = s.draw[0 .. 8 * k];
        source.fill(base) catch return error.EntropyUnavailable;
        fromBigEndian(s.x[0..k], base);
        s.x[k - 1] &= width_mask;
        if (!inBaseRange(s.x[0..k], w)) continue;
        s.modulus.toMontgomery(s.y[0..k], s.x[0..k]);
        s.modulus.powSecret(s.y[0..k], s.y[0..k], s.g[0..k]);
        var plus: u64 = 0;
        var minus: u64 = 0;
        for (0..k) |i| {
            plus |= s.y[i] ^ s.one[i];
            minus |= s.y[i] ^ s.minus_one[i];
        }
        if (ct.barrier(zeroMask(plus) | zeroMask(minus)) == 0) return false;
        round += 1;
    }
    return true;
}

/// Whether 2 <= x <= w - 2, by a borrow chain.
pub fn inBaseRange(x: []const u64, w: []const u64) bool {
    // x - 2 does not borrow, and (w - 2) - x does not borrow.
    var borrow: u1 = 0;
    for (x, 0..) |limb, i| _, borrow = subb(limb, if (i == 0) 2 else 0, borrow);
    const below_two = borrow;
    borrow = 0;
    var c: u1 = 0;
    for (x, w, 0..) |limb, wl, i| {
        const top = subb(wl, if (i == 0) 2 else 0, c);
        c = top[1];
        _, borrow = subb(top[0], limb, borrow);
    }
    return ct.barrier(@as(u64, below_two | borrow)) == 0;
}

/// The odd primes below 2^12 (563 of them).
const small_primes = blk: {
    @setEvalBranchQuota(1_000_000);
    const limit = 1 << 12;
    var composite: [limit]bool = @splat(false);
    var list: [563]u32 = undefined;
    var count = 0;
    for (3..limit) |i| {
        if (i % 2 == 0 or composite[i]) continue;
        list[count] = i;
        count += 1;
        var j = i * i;
        while (j < limit) : (j += i) composite[j] = true;
    }
    std.debug.assert(count == list.len);
    break :blk list;
};

/// `x mod q` for q below 2^32 (comptime), over 32-bit chunks from the top: each step's value
/// is below q * 2^32, reduced by its Barrett quotient (at most one short) and one masked
/// correction. No division instruction.
pub fn remainder(x: []const u64, comptime q: u32) u32 {
    const m: u64 = comptime @intCast(@as(u128, 1 << 64) / q);
    var r: u64 = 0;
    var i = x.len;
    while (i > 0) {
        i -= 1;
        r = reduceWord((r << 32) | (x[i] >> 32), q, m);
        r = reduceWord((r << 32) | (x[i] & 0xffff_ffff), q, m);
    }
    return @intCast(r); // below q
}

fn reduceWord(x: u64, comptime q: u32, m: u64) u64 {
    const estimate: u64 = @truncate((@as(u128, x) * m) >> 64);
    const r = x - estimate * q;
    // r is below 2q: subtract q when it is at least q.
    const d = r -% q;
    return d +% (q & maskOf(@truncate(d >> 63))); // the sign bit of a value below 2^34
}

/// All ones when `x` is zero.
fn zeroMask(x: u64) u64 {
    return ct.zeroMask(x);
}

// ---------------------------------------------------------------- arithmetic on secrets

/// e^-1 mod x into `out` (as wide as x), or false when e divides x. With t = x mod e and
/// u = t^(e-2) mod e, (1 + x (e - u)) is a multiple of e below e * x.
pub fn inverseOfE(out: []u64, x: []const u64, wide: *[rsa.max_limbs + 1]u64) bool {
    const t = remainder(x, e);
    if (ct.barrier(t) == 0) return false;
    const u = powModE(t, e - 2);
    // wide = x * (e - u) + 1.
    const factor: u64 = e - u;
    var carry: u64 = 0;
    for (x, 0..) |limb, i| {
        const p = @as(u128, limb) * factor + carry;
        wide[i] = @truncate(p);
        carry = @truncate(p >> 64);
    }
    wide[x.len] = carry;
    var c: u1 = 1;
    for (wide[0 .. x.len + 1]) |*limb| limb.*, c = addc(limb.*, 0, c);
    // Exact division by e: each quotient limb is the low word times e^-1 mod 2^64.
    const inverse = comptime blk: {
        var v: u64 = 1;
        for (0..6) |_| v *%= 2 -% e *% v;
        break :blk v;
    };
    var borrow: u64 = 0;
    for (0..x.len + 1) |i| {
        const t_i, const b1 = subb(wide[i], borrow, 0);
        const q_i = t_i *% inverse;
        if (i < out.len) out[i] = q_i;
        borrow = @as(u64, @truncate((@as(u128, q_i) * e) >> 64)) + b1;
    }
    return true;
}

/// base^exponent mod e for a public exponent, by square and multiply on words.
fn powModE(base: u32, comptime exponent: u32) u32 {
    const m: u64 = comptime @intCast(@as(u128, 1 << 64) / e);
    var acc: u64 = 1;
    var bit: u5 = 31;
    while (true) : (bit -= 1) {
        acc = reduceWord(acc * acc, e, m);
        if ((exponent >> bit) & 1 == 1) acc = reduceWord(acc * base, e, m);
        if (bit == 0) break;
    }
    return @intCast(acc); // below e
}

/// gcd(a, b) of two odd values into `out`, by a binary gcd of a fixed 2 * 64 * k steps: each
/// step subtracts the smaller from the larger when both are odd, then halves the even one.
pub fn gcdOdd(out: []u64, a_in: []const u64, b_in: []const u64) void {
    const k = out.len;
    var owner: Secret(struct { a: Half, b: Half }) = .init(undefined);
    defer owner.deinit();
    const a = &owner.exposeMut().a;
    const b = &owner.exposeMut().b;
    @memcpy(a[0..k], a_in);
    @memcpy(b[0..k], b_in);
    for (0..2 * 64 * k) |_| {
        const both = maskOf(@truncate(a[0] & b[0] & 1));
        var borrow: u1 = 0;
        for (0..k) |i| _, borrow = subb(a[i], b[i], borrow);
        // Swap when both are odd and a < b, so a >= b, then a -= b when both are odd.
        const swap = both & maskOf(borrow);
        for (0..k) |i| {
            const x = (a[i] ^ b[i]) & swap;
            a[i] ^= x;
            b[i] ^= x;
        }
        borrow = 0;
        for (0..k) |i| {
            const d, borrow = subb(a[i], b[i] & both, borrow);
            a[i] = d;
        }
        // Halve a when even, else b when even.
        const a_even = maskOf(@truncate(~a[0] & 1));
        const b_even = ~a_even & maskOf(@truncate(~b[0] & 1));
        halveIf(a[0..k], a_even);
        halveIf(b[0..k], b_even);
    }
    // One of them is zero; the other is the gcd.
    for (0..k) |i| out[i] = a[i] | b[i];
}

fn halveIf(x: []u64, mask: u64) void {
    for (0..x.len) |i| {
        const next = if (i + 1 < x.len) x[i + 1] << 63 else 0;
        x[i] = (x[i] & ~mask) | (((x[i] >> 1) | next) & mask);
    }
}

/// `out = x / g` for x a multiple of g (any x: the quotient's floor), g below 2^32, bit by bit.
pub fn divideSmall(out: []u64, x: []const u64, g: u32) void {
    var r: u64 = 0;
    var i = x.len;
    while (i > 0) {
        i -= 1;
        var word: u64 = 0;
        var bit: u7 = 64;
        const limb = x[i];
        while (bit > 0) {
            bit -= 1;
            r = (r << 1) | ((limb >> @intCast(bit)) & 1); // bit below 64
            const d = r -% g;
            // r < 2g < 2^33, so the sign bit says r < g.
            const take = ~maskOf(@truncate(d >> 63));
            r = (r & ~take) | (d & take);
            word |= (take & 1) << @intCast(bit); // bit below 64
        }
        out[i] = word;
    }
}

/// `out = a * b`, out as wide as both together.
fn multiply(out: []u64, a: []const u64, b: []const u64) void {
    @memset(out, 0);
    for (b, 0..) |bl, i| {
        var carry: u64 = 0;
        for (a, 0..) |al, j| {
            const p = @as(u128, al) * bl + out[i + j] + carry;
            out[i + j] = @truncate(p);
            carry = @truncate(p >> 64);
        }
        out[i + a.len] = carry;
    }
}

/// Two's complement negation of `x` when `bit` is 1.
fn negateIf(x: []u64, bit: u1) void {
    const mask = maskOf(bit);
    var c: u1 = bit;
    for (x) |*limb| limb.*, c = addc(limb.* ^ mask, 0, c);
}

fn shiftRightOne(out: []u64, x: []const u64) void {
    for (0..out.len) |i| out[i] = (x[i] >> 1) | (if (i + 1 < x.len) x[i + 1] << 63 else 0);
}

fn shiftLeftOne(x: []u64) u64 {
    var carry: u64 = 0;
    for (x) |*limb| {
        const next = limb.* >> 63;
        limb.* = (limb.* << 1) | carry;
        carry = next;
    }
    return carry;
}

/// Whether x > 2^power, by the bits at and above the power: the verdict alone leaves.
pub fn greaterThanPowerOfTwo(x: []const u64, power: usize) bool {
    var above: u64 = 0; // bits above the power
    var at: u64 = 0; // the bit at the power
    var below: u64 = 0; // bits below it
    for (x, 0..) |limb, i| {
        const low = 64 * i;
        for (0..64) |j| {
            const bit = (limb >> @intCast(j)) & 1; // j below 64
            const position = low + j;
            if (position > power) above |= bit else if (position == power) at |= bit else below |= bit;
        }
    }
    // x > 2^power: a bit above it, or the bit at it and any below.
    const below_any = (below | (0 -% below)) >> 63;
    return ct.barrier(above | (at & below_any)) != 0;
}

fn fromBigEndian(out: []u64, bytes: []const u8) void {
    for (out, 0..) |*limb, i| limb.* = std.mem.readInt(u64, bytes[bytes.len - 8 * (i + 1) ..][0..8], .big);
}

fn bigEndian(buffer: *[rsa.max_half * 8]u8, x: []const u64) []const u8 {
    const bytes = buffer[0 .. 8 * x.len];
    for (x, 0..) |limb, i| std.mem.writeInt(u64, bytes[bytes.len - 8 * (i + 1) ..][0..8], limb, .big);
    return bytes;
}

test "Miller-Rabin's rounds are FIPS 186-5 Table B.1's for p and q at each size" {
    // p and q of 1024, 1536 and 2048 bits: 5, 4 and 4 rounds (2^-112, 2^-128, 2^-144).
    try std.testing.expectEqual(@as(usize, 5), rounds(1024));
    try std.testing.expectEqual(@as(usize, 4), rounds(1536));
    try std.testing.expectEqual(@as(usize, 4), rounds(2048));
}

test "a generation reaches less stack than the depth that scrubs it" {
    const Source = struct {
        rng: std.Random.ChaCha = .init(@splat(11)),
        pub fn fill(self: *@This(), buffer: []u8) error{EntropyUnavailable}!void {
            self.rng.fill(buffer);
        }
    };
    var source: Source = .{};
    var out: Secret(Integers) = .init(undefined);
    defer out.deinit();
    inline for (.{ Size.@"2048", .@"4096" }) |size| {
        try std.testing.expect(aegis.secret.stackReach(4 * depth, generateKernel, .{ size, &source, out.exposeMut() }) < depth);
    }
}

test {
    _ = @import("keygen_test.zig");
}
