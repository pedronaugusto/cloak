//! Validation of complete two-prime RSA input, kept in the CRT form the private operation of
//! `crypto/rsa.zig` uses. A key's numbers are checked to agree with each other (n = pq, the
//! exponents and the CRT values); whether p and q are prime is its generator's to ensure, as Go,
//! BoringSSL and ring hold it. No wrong signature leaves on a key whose factors are not: the
//! private operation checks each signature against the public key before releasing it.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const Der = @import("../wire/Der.zig");
const kernel = @import("../crypto/rsa.zig");
const roca = @import("../crypto/roca.zig");
/// `UnsupportedKey`: a valid key the private operation cannot hold, a factor above 2048 bits.
pub const Error = Der.Error || error{ InvalidKey, UnsupportedKey };
/// The public modulus and exponent as parsed, for matching a certificate, the private exponent
/// d as given (validated; kept so the key can be written back, `Numbers`), and the private key
/// as the CRT operation holds it: n, e, p, q, dp, dq and qinv with their Montgomery constants.
/// The owner erases the whole value.
pub const Key = struct {
    n: [512]u8 = @splat(0),
    e: [8]u8 = @splat(0),
    d: [512]u8 = @splat(0),
    size: usize,
    exponent_size: usize,
    d_size: usize,
    crt: kernel.PrivateKey,
};

/// A key's numbers back as unsigned big-endian bytes, as an RSAPrivateKey (RFC 8017) writes
/// them: n, e, d, p, q, dp, dq and qinv. Holds secrets: the owner erases it.
pub const Numbers = struct {
    buffers: [8][512]u8,
    lengths: [8]usize,

    /// `key`'s numbers into this owner.
    pub fn of(self: *Numbers, key: *const Key) void {
        @setRuntimeSafety(true);
        self.copy(0, key.n[0..key.size]);
        self.copy(1, key.e[0..key.exponent_size]);
        self.copy(2, key.d[0..key.d_size]);
        const half = key.crt.p.len;
        self.limbs(3, key.crt.p.m[0..half]);
        self.limbs(4, key.crt.q.m[0..half]);
        self.limbs(5, key.crt.dp[0..half]);
        self.limbs(6, key.crt.dq[0..half]);
        self.limbs(7, key.crt.qinv[0..half]);
    }

    pub fn slices(self: *const Numbers) [8][]const u8 {
        var out: [8][]const u8 = undefined;
        for (&out, &self.buffers, self.lengths) |*slice, *buffer, length| slice.* = buffer[0..length];
        return out;
    }

    fn copy(self: *Numbers, index: usize, bytes: []const u8) void {
        @memcpy(self.buffers[index][0..bytes.len], bytes);
        self.lengths[index] = bytes.len;
    }

    /// Little-endian limbs as big-endian bytes, leading zero bytes dropped (the DER integer's
    /// length, which the encoding shows).
    fn limbs(self: *Numbers, index: usize, value: []const u64) void {
        const bytes = self.buffers[index][0 .. 8 * value.len];
        for (value, 0..) |limb, i| std.mem.writeInt(u64, bytes[bytes.len - 8 * (i + 1) ..][0..8], limb, .big);
        var start: usize = 0;
        while (start + 1 < bytes.len and bytes[start] == 0) start += 1;
        @memmove(bytes[0 .. bytes.len - start], bytes[start..]);
        self.lengths[index] = bytes.len - start;
    }
};
const Uint = @import("Uint.zig");
const limb_bits = @bitSizeOf(usize) - 1;
/// Parses and validates an RSAPrivateKey into `out`, which holds the key on success; `out` is
/// the caller's secret owner, which erases what a failure leaves in it.
pub fn parse(encoded: []const u8, out: *Key) Error!void {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    if (try Der.number((try r.expect(2)).value) != 0) return error.InvalidKey;
    var integers: [8][]const u8 = undefined;
    for (&integers) |*n| n.* = try Der.integer((try r.expect(2)).value);
    try r.finish();
    return fromIntegers(&integers, out);
}

/// Validates a key given by its numbers, unsigned big-endian in their fewest bytes (a JWK's
/// n, e, d, p, q, dp, dq and qi; an RSAPrivateKey's after its sign bytes), into `out`: the one
/// path every RSA private key takes, parsed or built.
pub fn fromIntegers(integers: *const [8][]const u8, out: *Key) Error!void {
    @setRuntimeSafety(true);
    // Every number is positive and in its fewest bytes: one value has one encoding.
    for (integers) |bytes| if (bytes.len == 0 or bytes[0] == 0) return error.InvalidKey;
    const n = integers[0];
    const e = integers[1];
    const d = integers[2];
    if (n.len < 256 or n.len > 512 or n[0] == 0 or n[n.len - 1] & 1 == 0 or e.len > 4 or d.len > n.len) return error.InvalidKey;
    // At least 2048 bits, any length up to 4096: the bounds a public key has.
    // Clz on u8 is at most eight and widens to usize.
    if (n.len * 8 - @as(usize, @clz(n[0])) < 2048) return error.InvalidKey;
    const exponent = try Der.number(e);
    if (exponent < 3 or exponent & 1 == 0) return error.InvalidKey;
    // A modulus with the ROCA fingerprint is factorable from the public key (CVE-2017-15361):
    // whoever holds it is not the only one who can sign.
    if (roca.fingerprinted(n)) return error.InvalidKey;
    var values_owner: Secret([8]Uint) = .init(undefined);
    defer values_owner.deinit();
    const values = values_owner.exposeMut();
    for (integers, values) |bytes, *value| {
        if (bytes.len == 0 or bytes.len > 512) return error.InvalidKey;
        try Uint.decode(value, bytes);
        if (value.isZero()) return error.InvalidKey;
    }
    const p = &values[3];
    const q = &values[4];
    if (!p.isOdd() or !q.isOdd() or p.isOne() or q.isOne() or p.eql(q)) return error.InvalidKey;
    // Only the final range/validity predicate leaves the fixed-width arithmetic.
    if (!values[2].less(&values[0]) or !values[7].less(p)) return error.InvalidKey;
    var product_owner: Secret(Uint) = .init(Uint.zero);
    defer product_owner.deinit();
    const product = product_owner.exposeMut();
    if (multiply(product, p, q) != 0 or !product.eql(&values[0])) return error.InvalidKey;
    var one = Uint.zero;
    one.limbs_buffer[0] = 1;
    var pm_owner: Secret(Uint) = .init(p.*);
    defer pm_owner.deinit();
    const pm = pm_owner.exposeMut();
    _ = pm.subWithOverflow(&one);
    var qm_owner: Secret(Uint) = .init(q.*);
    defer qm_owner.deinit();
    const qm = qm_owner.exposeMut();
    _ = qm.subWithOverflow(&one);
    // e * d = 1 mod p - 1 holds exactly when e * dp does, given d = dp mod p - 1 (checked
    // below), and e * dp is half as long: the same check for half the reduction.
    var edp_owner: Secret(Uint) = .init(Uint.zero);
    defer edp_owner.deinit();
    const edp = edp_owner.exposeMut();
    if (multiply(edp, &values[1], &values[5]) != 0) return error.InvalidKey;
    var edq_owner: Secret(Uint) = .init(Uint.zero);
    defer edq_owner.deinit();
    const edq = edq_owner.exposeMut();
    if (multiply(edq, &values[1], &values[6]) != 0) return error.InvalidKey;
    // Fixed-width reduction supports the even moduli p-1 and q-1 without
    // bigint division, public-exponent private operations, or signing entropy.
    // The widths walked are the encodings' lengths, public: a product has at most the sum of
    // its factors' bytes.
    const p_bytes = integers[3].len;
    const q_bytes = integers[4].len;
    if (!congruent(edp, e.len + integers[5].len, pm, p_bytes, &one) or !congruent(edq, e.len + integers[6].len, qm, q_bytes, &one)) return error.InvalidKey;
    if (!congruent(&values[2], d.len, pm, p_bytes, &values[5]) or !congruent(&values[2], d.len, qm, q_bytes, &values[6])) return error.InvalidKey;
    product.* = Uint.zero;
    if (multiply(product, q, &values[7]) != 0 or !congruent(product, q_bytes + integers[7].len, p, p_bytes, &one)) return error.InvalidKey;
    out.* = .{ .size = n.len, .exponent_size = e.len, .d_size = d.len, .crt = undefined };
    @memcpy(out.n[0..n.len], n);
    @memcpy(out.e[0..e.len], e);
    @memcpy(out.d[0..d.len], d);
    // Validated above; the kernel refuses only shapes it cannot hold, such as unbalanced factors.
    out.crt.init(n, e, integers[3], integers[4], integers[5], integers[6], integers[7]) catch return error.UnsupportedKey;
}
/// `x mod modulus`, walking only the bits `x` can have (`x_bytes`) and the limbs a value below
/// twice the modulus fills (`modulus_bytes`): both public, the lengths of the DER integers.
fn remainder(x: *const Uint, x_bytes: usize, modulus: *const Uint, modulus_bytes: usize) Uint {
    @setRuntimeSafety(true);
    var owner: Secret(struct { result: Uint, subtracted: [Uint.zero.limbs_buffer.len]usize }) = .init(.{ .result = Uint.zero, .subtracted = undefined });
    defer owner.deinit();
    const result = &owner.exposeMut().result;
    const subtracted = &owner.exposeMut().subtracted;
    const limbs = @min(result.limbs_buffer.len, (8 * modulus_bytes + 1) / limb_bits + 1);
    var bit: usize = @min(Uint.capacity_bits, 8 * x_bytes);
    // x's top bits below the modulus's width are already reduced: load them whole and walk the
    // rest. The modulus's width is public, as its encoding's length is.
    const width = bitLength(modulus);
    if (width > 1 and bit > width - 1) {
        const start = bit - (width - 1);
        for (0..width - 1) |i| {
            const from = start + i;
            const value: usize = (x.limbs_buffer[from / limb_bits] >> @as(std.math.Log2Int(usize), @intCast(from % limb_bits))) & 1; // public bit offsets modulo the radix
            result.limbs_buffer[i / limb_bits] |= value << @as(std.math.Log2Int(usize), @intCast(i % limb_bits)); // as above
        }
        bit = start;
    }
    while (bit > 0) {
        bit -= 1;
        const input: usize = (x.limbs_buffer[bit / limb_bits] >> @as(std.math.Log2Int(usize), @intCast(bit % limb_bits))) & 1; // public bit offset modulo machine radix fits Log2Int(usize)
        var carry = input;
        for (result.limbs_buffer[0..limbs]) |*limb| {
            const next = limb.* >> (limb_bits - 1);
            limb.* = ((limb.* << 1) | carry) & (std.math.maxInt(usize) >> 1);
            carry = next;
        }
        // result - modulus over the live limbs, kept when it does not borrow.
        var borrow: usize = 0;
        for (result.limbs_buffer[0..limbs], modulus.limbs_buffer[0..limbs], subtracted[0..limbs]) |a, b, *d| {
            const difference = a -% b -% borrow;
            d.* = difference & (std.math.maxInt(usize) >> 1);
            borrow = difference >> limb_bits;
        }
        const mask: usize = 0 -% (1 - borrow);
        for (result.limbs_buffer[0..limbs], subtracted[0..limbs]) |*a, b| a.* = (a.* & ~mask) | (b & mask);
    }
    return result.*;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Rsa_test.zig");
    _ = @import("Uint.zig");
}

/// The bit length of a public value.
fn bitLength(value: *const Uint) usize {
    var i = value.limbs_buffer.len;
    while (i > 0) {
        i -= 1;
        if (value.limbs_buffer[i] != 0) return limb_bits * i + @bitSizeOf(usize) - @clz(value.limbs_buffer[i]);
    }
    return 0;
}
fn congruent(x: *const Uint, x_bytes: usize, modulus: *const Uint, modulus_bytes: usize, expected: *const Uint) bool {
    @setRuntimeSafety(true);
    var reduced_owner: Secret(Uint) = .init(remainder(x, x_bytes, modulus, modulus_bytes));
    defer reduced_owner.deinit();
    const reduced = reduced_owner.exposeMut();
    return reduced.eql(expected);
}
fn multiply(out: *Uint, x: *const Uint, y: *const Uint) u1 {
    @setRuntimeSafety(true);
    const len = Uint.zero.limbs_buffer.len;
    var owner: Secret(struct { wide: [2 * len]usize, carry: u128, sum: u128 }) = .init(.{ .wide = @splat(0), .carry = 0, .sum = 0 });
    defer owner.deinit();
    const s = owner.exposeMut();
    const wide = &s.wide;
    const mask = std.math.maxInt(usize) >> 1;
    for (0..len) |i| {
        s.carry = 0;
        for (0..len) |j| {
            s.sum = @as(u128, x.limbs_buffer[i]) * y.limbs_buffer[j] + wide[i + j] + s.carry;
            wide[i + j] = @as(usize, @truncate(s.sum)) & mask; // retain low multiplication radix bits and propagate high carry separately
            s.carry = s.sum >> limb_bits;
        }
        wide[i + len] = @intCast(s.carry); // carry is bounded by the machine radix after the preceding shift
    }
    @memcpy(&out.limbs_buffer, wide[0..len]);
    var overflow: usize = 0;
    for (wide[len..]) |limb| overflow |= limb;
    return @intFromBool(overflow != 0);
}
