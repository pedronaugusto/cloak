const std = @import("std");
const keygen = @import("keygen.zig");
const rsa = @import("../rsa.zig");
const Rsa = @import("../../credentials/Rsa.zig");
const Secret = @import("aegis").secret.Secret;
const Managed = std.math.big.int.Managed;

const gpa = std.testing.allocator;

/// A deterministic source for tests, ChaCha20 from a seed; it fails from its `fails_at`th call
/// on when one is given.
pub const Drbg = struct {
    rng: std.Random.ChaCha,
    fails_at: ?usize = null,
    calls: usize = 0,

    fn init(seed: u8) Drbg {
        return .{ .rng = .init(@splat(seed)) };
    }

    pub fn fill(self: *Drbg, buffer: []u8) error{EntropyUnavailable}!void {
        self.calls += 1;
        if (self.fails_at) |at| if (self.calls >= at) return error.EntropyUnavailable;
        self.rng.fill(buffer);
    }
};

fn big(x: []const u64) !Managed {
    var m = try Managed.init(gpa);
    errdefer m.deinit();
    var i = x.len;
    while (i > 0) {
        i -= 1;
        try m.shiftLeft(&m, 64);
        try m.addScalar(&m, x[i]);
    }
    return m;
}

fn expectEqualBig(expected: *const Managed, limbs: []const u64) !void {
    var actual = try big(limbs);
    defer actual.deinit();
    try std.testing.expect(expected.eql(actual));
}

fn randomLimbs(random: std.Random, out: []u64) void {
    for (out) |*limb| limb.* = random.int(u64);
}

test "a remainder by a small prime is the integer's" {
    var prng: std.Random.DefaultPrng = .init(1);
    const random = prng.random();
    var x: [32]u64 = undefined;
    for (0..20) |round| {
        randomLimbs(random, &x);
        if (round == 0) @memset(&x, std.math.maxInt(u64));
        if (round == 1) @memset(&x, 0);
        var whole = try big(&x);
        defer whole.deinit();
        inline for (.{ 3, 5, 4093, keygen.e }) |q| {
            var divisor = try Managed.initSet(gpa, q);
            defer divisor.deinit();
            var quotient = try Managed.init(gpa);
            defer quotient.deinit();
            var rest = try Managed.init(gpa);
            defer rest.deinit();
            try quotient.divTrunc(&rest, &whole, &divisor);
            try std.testing.expectEqual(try rest.toConst().toInt(u32), keygen.remainder(&x, q));
        }
    }
}

test "the fixed-step gcd of two odd values is the integers' gcd" {
    var prng: std.Random.DefaultPrng = .init(2);
    const random = prng.random();
    for (0..12) |round| {
        const k = 1 + round % 4;
        var a: [4]u64 = undefined;
        var b: [4]u64 = undefined;
        randomLimbs(random, a[0..k]);
        randomLimbs(random, b[0..k]);
        // A common odd factor of up to 32 bits in some rounds: the low limb times it, both odd.
        const common: u64 = if (round % 2 == 0) (random.int(u32) | 1) else 1;
        a[k - 1] >>= 33;
        b[k - 1] >>= 33;
        var ma = try big(a[0..k]);
        defer ma.deinit();
        var mb = try big(b[0..k]);
        defer mb.deinit();
        var factor = try Managed.initSet(gpa, common);
        defer factor.deinit();
        try ma.mul(&ma, &factor);
        try mb.mul(&mb, &factor);
        if (ma.isEven()) try ma.addScalar(&ma, common);
        if (mb.isEven()) try mb.addScalar(&mb, common);
        var la: [4]u64 = @splat(0);
        var lb: [4]u64 = @splat(0);
        try toLimbs(&ma, la[0..k]);
        try toLimbs(&mb, lb[0..k]);
        var g: [4]u64 = undefined;
        keygen.gcdOdd(g[0..k], la[0..k], lb[0..k]);
        var expected = try Managed.init(gpa);
        defer expected.deinit();
        try expected.gcd(&ma, &mb);
        try expectEqualBig(&expected, g[0..k]);
    }
}

fn toLimbs(m: *const Managed, out: []u64) !void {
    var bytes: [8 * 4]u8 = @splat(0);
    m.toConst().writeTwosComplement(bytes[0 .. 8 * out.len], .little);
    for (out, 0..) |*limb, i| limb.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
}

test "a division by a small factor of a multiple of it is exact" {
    var prng: std.Random.DefaultPrng = .init(3);
    const random = prng.random();
    var x: [16]u64 = undefined;
    for (0..10) |_| {
        randomLimbs(random, &x);
        x[15] >>= 33;
        const g: u32 = random.int(u32) | 1;
        var product = try big(&x);
        defer product.deinit();
        var factor = try Managed.initSet(gpa, g);
        defer factor.deinit();
        try product.mul(&product, &factor);
        var limbs: [16]u64 = undefined;
        try toLimbsWide(&product, &limbs);
        var out: [16]u64 = undefined;
        keygen.divideSmall(&out, &limbs, g);
        try std.testing.expectEqualSlices(u64, &x, &out);
    }
}

fn toLimbsWide(m: *const Managed, out: []u64) !void {
    var bytes: [8 * 16]u8 = @splat(0);
    m.toConst().writeTwosComplement(bytes[0 .. 8 * out.len], .little);
    for (out, 0..) |*limb, i| limb.* = std.mem.readInt(u64, bytes[8 * i ..][0..8], .little);
}

test "e's inverse modulo an even value is one, below it, and refused where e divides it" {
    var prng: std.Random.DefaultPrng = .init(4);
    const random = prng.random();
    var wide: [rsa.max_limbs + 1]u64 = undefined;
    var x: [32]u64 = undefined;
    var found: usize = 0;
    while (found < 6) {
        randomLimbs(random, &x);
        x[0] &= ~@as(u64, 1);
        if (keygen.remainder(&x, keygen.e) == 0) continue;
        found += 1;
        var d: [32]u64 = undefined;
        try std.testing.expect(keygen.inverseOfE(&d, &x, &wide));
        var modulus = try big(&x);
        defer modulus.deinit();
        var product = try big(&d);
        defer product.deinit();
        try std.testing.expect(product.order(modulus) == .lt);
        var e = try Managed.initSet(gpa, keygen.e);
        defer e.deinit();
        try product.mul(&product, &e);
        var quotient = try Managed.init(gpa);
        defer quotient.deinit();
        var rest = try Managed.init(gpa);
        defer rest.deinit();
        try quotient.divTrunc(&rest, &product, &modulus);
        try std.testing.expect(rest.toConst().orderAgainstScalar(1) == .eq);
    }
    // A multiple of e has no inverse.
    @memset(&x, 0);
    x[0] = 2 * keygen.e * 12345;
    var d: [32]u64 = undefined;
    try std.testing.expect(!keygen.inverseOfE(&d, &x, &wide));
}

test "greater than a power of two, at its edges" {
    var x: [4]u64 = @splat(0);
    for ([_]usize{ 0, 1, 63, 64, 100, 200, 255 }) |power| {
        @memset(&x, 0);
        x[power / 64] = @as(u64, 1) << @intCast(power % 64);
        try std.testing.expect(!keygen.greaterThanPowerOfTwo(&x, power));
        // One more.
        if (power > 0) {
            x[0] |= 1;
            try std.testing.expect(keygen.greaterThanPowerOfTwo(&x, power));
            x[0] &= ~@as(u64, 1);
            if (power == 0) unreachable;
        }
        // One less: every bit below it.
        @memset(&x, 0);
        for (0..power) |bit| x[bit / 64] |= @as(u64, 1) << @intCast(bit % 64);
        try std.testing.expect(!keygen.greaterThanPowerOfTwo(&x, power));
        // The next power.
        if (power + 1 < 256) {
            @memset(&x, 0);
            x[(power + 1) / 64] = @as(u64, 1) << @intCast((power + 1) % 64);
            try std.testing.expect(keygen.greaterThanPowerOfTwo(&x, power));
        }
    }
}

test "a Miller-Rabin base is between 2 and w - 2" {
    const w = [2]u64{ 0xffff_ffff_ffff_ffff, 0x7fff_ffff_ffff_ffff };
    const cases = [_]struct { x: [2]u64, in: bool }{
        .{ .x = .{ 0, 0 }, .in = false },
        .{ .x = .{ 1, 0 }, .in = false },
        .{ .x = .{ 2, 0 }, .in = true },
        .{ .x = .{ 0, 1 }, .in = true },
        .{ .x = .{ w[0] - 2, w[1] }, .in = true },
        .{ .x = .{ w[0] - 1, w[1] }, .in = false },
        .{ .x = w, .in = false },
        .{ .x = .{ 0, 0x8000_0000_0000_0000 }, .in = false },
    };
    for (cases) |case| try std.testing.expectEqual(case.in, keygen.inBaseRange(&case.x, &w));
}

test "near 2^64, 2^128, 2^256 and 2^1024, the kernel's verdicts are std's" {
    var owner: Secret(keygen.State) = .init(undefined);
    defer owner.deinit();
    var source: Drbg = .init(5);
    inline for (.{ 1, 2, 4, 16 }) |k| {
        var primes: usize = 0;
        var composites: usize = 0;
        // 2^(64k) - c for c = 1 mod 8: 7 mod 8, the top bit set, as every candidate is.
        var c: u64 = 1;
        while (c < 1600) : (c += 8) {
            var w: [k]u64 = @splat(std.math.maxInt(u64));
            w[0] -%= c - 1;
            var bytes: [8 * k]u8 = undefined;
            for (w, 0..) |limb, i| std.mem.writeInt(u64, bytes[8 * (k - 1 - i) ..][0..8], limb, .big);
            const ours = try keygen.isProbablePrime(&w, &source, owner.exposeMut());
            // The kernel also refuses w = 1 mod e, which RSA cannot use; std is not asked.
            if (keygen.remainder(&w, keygen.e) == 1) {
                try std.testing.expect(!ours);
                continue;
            }
            try std.testing.expectEqual(try stdProbablePrime(&bytes, 20), ours);
            if (ours) primes += 1 else composites += 1;
        }
        try std.testing.expect(primes > 0 and composites > 0);
    }
}

test "Miller-Rabin refuses strong pseudoprimes and a Carmichael number, and keeps primes, at any width" {
    var owner: Secret(keygen.State) = .init(undefined);
    defer owner.deinit();
    var source: Drbg = .init(12);
    // 2047 = 23 * 89, a strong pseudoprime to base 2; 3215031751 = 151 * 751 * 28351, one to
    // bases 2, 3, 5 and 7; 8911 = 7 * 19 * 67, a Carmichael number. Each is 7 mod 8, as a
    // candidate is, and each has a factor trial division would find: Miller-Rabin alone here.
    for ([_]u64{ 2047, 3215031751, 8911 }) |composite| {
        try std.testing.expect(!try keygen.millerRabin(&.{composite}, &source, owner.exposeMut()));
    }
    // 2^31 - 1, 2^61 - 1 and 2^89 - 1, below their limbs' width.
    try std.testing.expect(try keygen.millerRabin(&.{0x7fff_ffff}, &source, owner.exposeMut()));
    try std.testing.expect(try keygen.millerRabin(&.{0x1fff_ffff_ffff_ffff}, &source, owner.exposeMut()));
    try std.testing.expect(try keygen.millerRabin(&.{ std.math.maxInt(u64), 0x1ff_ffff }, &source, owner.exposeMut()));
}

/// An independent Miller-Rabin over std's constant-time modular arithmetic: `rounds` fixed
/// bases, for a prime of up to 2048 bits given big-endian.
fn stdProbablePrime(w: []const u8, rounds: usize) !bool {
    const M = std.crypto.ff.Modulus(2048);
    const m = try M.fromBytes(w, .big);
    // (w - 1)/2 for w = 7 mod 8: w shifted right once.
    var half: [256]u8 = undefined;
    const exponent = half[0..w.len];
    var carry: u8 = 0;
    for (w, exponent) |byte, *out| {
        out.* = (byte >> 1) | carry;
        carry = byte << 7;
    }
    const one = m.one();
    const minus_one = m.sub(m.zero, one);
    for (0..rounds) |i| {
        const base = try M.Fe.fromPrimitive(u64, m, 2 + i * 7919);
        const y = try m.powWithEncodedPublicExponent(base, exponent, .big);
        if (!y.eql(one) and !y.eql(minus_one)) return false;
    }
    return true;
}

fn expectKey(size: keygen.Size, seed: u8) !void {
    var integers_owner: Secret(keygen.Integers) = .init(undefined);
    defer integers_owner.deinit();
    const integers = integers_owner.exposeMut();
    var source: Drbg = .init(seed);
    try keygen.generate(size, &source, integers);
    const numbers = integers.slices();
    const n = numbers[0];
    const p = numbers[3];
    const q = numbers[4];
    const bits = @backingInt(size);
    // n has exactly the size's bits; each factor half of them, its top two set, 7 mod 8.
    try std.testing.expectEqual(bits / 8, n.len);
    try std.testing.expect(n[0] & 0x80 != 0);
    for ([_][]const u8{ p, q }) |factor| {
        try std.testing.expectEqual(bits / 16, factor.len);
        try std.testing.expect(factor[0] & 0xc0 == 0xc0);
        try std.testing.expectEqual(@as(u8, 7), factor[factor.len - 1] & 7);
        try std.testing.expect(try stdProbablePrime(factor, 20));
    }
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x00, 0x01 }, numbers[1]);
    // The numbers agree with each other as a parsed key's must.
    var key_owner: Secret(Rsa.Key) = .init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut();
    try Rsa.fromIntegers(&numbers, key);
    // The private operation is m^d mod n: the kernel checks each result against e, and std
    // computes m^d itself.
    const M = std.crypto.ff.Modulus(4096);
    const modulus = try M.fromBytes(n, .big);
    var prng: std.Random.DefaultPrng = .init(seed);
    const random = prng.random();
    var m: [rsa.max_bytes]u8 = undefined;
    random.bytes(m[0..n.len]);
    m[0] = random.uintLessThan(u8, n[0]);
    var seed_bytes: [rsa.seed_length]u8 = undefined;
    random.bytes(&seed_bytes);
    var ours: [rsa.max_bytes]u8 = undefined;
    try key.crt.private(m[0..n.len], &seed_bytes, ours[0..n.len]);
    const expected = try modulus.powWithEncodedExponent(try M.Fe.fromBytes(modulus, m[0..n.len], .big), numbers[2], .big);
    var theirs: [rsa.max_bytes]u8 = undefined;
    try expected.toBytes(theirs[0..n.len], .big);
    try std.testing.expectEqualSlices(u8, theirs[0..n.len], ours[0..n.len]);
}

test "a generated 2048-bit key is one a parsed key would be, of primes std finds prime" {
    try expectKey(.@"2048", 6);
}

test "a source gives one key: the same draws make the same numbers" {
    var a_owner: Secret(keygen.Integers) = .init(undefined);
    defer a_owner.deinit();
    var b_owner: Secret(keygen.Integers) = .init(undefined);
    defer b_owner.deinit();
    var first: Drbg = .init(7);
    var second: Drbg = .init(7);
    try keygen.generate(.@"2048", &first, a_owner.exposeMut());
    try keygen.generate(.@"2048", &second, b_owner.exposeMut());
    for (a_owner.exposeMut().slices(), b_owner.exposeMut().slices()) |a, b| try std.testing.expectEqualSlices(u8, a, b);
}

test "a source that fails is EntropyUnavailable, at its first draw and in the middle" {
    var integers_owner: Secret(keygen.Integers) = .init(undefined);
    defer integers_owner.deinit();
    var first: Drbg = .init(8);
    first.fails_at = 1;
    try std.testing.expectError(error.EntropyUnavailable, keygen.generate(.@"2048", &first, integers_owner.exposeMut()));
    var later: Drbg = .init(8);
    later.fails_at = 50;
    try std.testing.expectError(error.EntropyUnavailable, keygen.generate(.@"2048", &later, integers_owner.exposeMut()));
}

test "generated 3072- and 4096-bit keys are ones a parsed key would be" {
    try expectKey(.@"3072", 9);
    try expectKey(.@"4096", 10);
}
