//! Mathematical validation of complete two-prime RSA input, kept in the CRT form the private
//! operation of `crypto/rsa.zig` uses.
const std = @import("std");
const Entropy = @import("Entropy.zig");
const Primality = @import("Primality.zig");
const Der = @import("../wire/Der.zig");
const kernel = @import("../crypto/rsa.zig");
/// `UnsupportedKey`: a valid key the private operation cannot hold, a factor above 2048 bits.
pub const Error = Der.Error || Primality.CheckError || error{ InvalidKey, EntropyRequired, UnsupportedKey };
pub const Options = struct { entropy: ?Entropy = null };
/// The public modulus and exponent as parsed, for matching a certificate, and the private key
/// as the CRT operation holds it: n, e, p, q, dp, dq and qinv with their Montgomery constants.
/// The private exponent d is validated and not kept. The owner erases the whole value.
pub const Key = struct {
    n: [512]u8 = @splat(0),
    e: [8]u8 = @splat(0),
    size: usize,
    exponent_size: usize,
    crt: kernel.PrivateKey,
};
const Uint = @import("Uint.zig");
const limb_bits = @bitSizeOf(usize) - 1;
pub fn parse(encoded: []const u8, options: Options) Error!Key {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    if (try Der.number((try r.expect(2)).value) != 0) return error.InvalidKey;
    var integers: [8][]const u8 = undefined;
    for (&integers) |*n| n.* = try Der.integer((try r.expect(2)).value);
    try r.finish();
    const n = integers[0];
    const e = integers[1];
    const d = integers[2];
    if (n.len < 256 or n.len > 512 or n[0] & 0x80 == 0 or n[n.len - 1] & 1 == 0 or e.len > 4 or d.len > n.len) return error.InvalidKey;
    const exponent = try Der.number(e);
    if (exponent < 3 or exponent & 1 == 0) return error.InvalidKey;
    var values: [8]Uint = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&values));
    for (integers, &values) |bytes, *value| {
        if (bytes.len == 0 or bytes.len > 512) return error.InvalidKey;
        try Uint.decode(value, bytes);
        if (value.isZero()) return error.InvalidKey;
    }
    const p = &values[3];
    const q = &values[4];
    if (!p.isOdd() or !q.isOdd() or p.isOne() or q.isOne() or p.eql(q)) return error.InvalidKey;
    // Only the final range/validity predicate leaves the fixed-width arithmetic.
    if (!values[2].less(&values[0]) or !values[7].less(p)) return error.InvalidKey;
    var product = Uint.zero;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
    if (multiply(&product, p, q) != 0 or !product.eql(&values[0])) return error.InvalidKey;
    var one = Uint.zero;
    one.limbs_buffer[0] = 1;
    var pm = p.*;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pm));
    _ = pm.subWithOverflow(&one);
    var qm = q.*;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&qm));
    _ = qm.subWithOverflow(&one);
    var ed = Uint.zero;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ed));
    if (multiply(&ed, &values[1], &values[2]) != 0) return error.InvalidKey;
    // Fixed-width reduction supports the even moduli p-1 and q-1 without
    // bigint division, public-exponent private operations, or signing entropy.
    if (!congruent(&ed, &pm, &one) or !congruent(&ed, &qm, &one)) return error.InvalidKey;
    if (!congruent(&values[2], &pm, &values[5]) or !congruent(&values[2], &qm, &values[6])) return error.InvalidKey;
    product = Uint.zero;
    if (multiply(&product, q, &values[7]) != 0 or !congruent(&product, p, &one)) return error.InvalidKey;
    // Small composites are rejected before an entropy request, then both factors
    // receive independent full-strength strong probable-prime validation.
    for (integers[3..5]) |factor| {
        inline for (.{ 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47 }) |prime| {
            var residue: u32 = 0;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&residue));
            for (factor) |byte| residue = (residue * 256 + byte) % prime;
            if (residue == 0) return error.InvalidKey;
        }
    }
    const entropy = options.entropy orelse return error.EntropyRequired;
    try Primality.check(integers[3], entropy);
    try Primality.check(integers[4], entropy);
    var key: Key = .{ .size = n.len, .exponent_size = e.len, .crt = undefined };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    @memcpy(key.n[0..n.len], n);
    @memcpy(key.e[0..e.len], e);
    // Validated above; the kernel refuses only shapes it cannot hold, such as unbalanced factors.
    key.crt.init(n, e, integers[3], integers[4], integers[5], integers[6], integers[7]) catch return error.UnsupportedKey;
    return key;
}
fn remainder(x: *const Uint, modulus: *const Uint) Uint {
    @setRuntimeSafety(true);
    var result = Uint.zero;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&result));
    var bit = Uint.capacity_bits;
    while (bit > 0) {
        bit -= 1;
        const input: usize = (x.limbs_buffer[bit / limb_bits] >> @as(std.math.Log2Int(usize), @intCast(bit % limb_bits))) & 1; // safe: public bit offset modulo machine radix fits Log2Int(usize)
        var carry = input;
        for (&result.limbs_buffer) |*limb| {
            const next = limb.* >> (limb_bits - 1);
            limb.* = ((limb.* << 1) | carry) & (std.math.maxInt(usize) >> 1);
            carry = next;
        }
        var subtracted = result;
        const borrow = subtracted.subWithOverflow(modulus);
        const mask: usize = 0 -% @as(usize, 1 - borrow);
        for (&result.limbs_buffer, subtracted.limbs_buffer) |*a, b| a.* = (a.* & ~mask) | (b & mask);
        std.crypto.secureZero(u8, std.mem.asBytes(&subtracted));
    }
    return result;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Rsa_test.zig");
    _ = @import("Uint.zig");
}

fn congruent(x: *const Uint, modulus: *const Uint, expected: *const Uint) bool {
    @setRuntimeSafety(true);
    var reduced = remainder(x, modulus);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&reduced));
    return reduced.eql(expected);
}
fn multiply(out: *Uint, x: *const Uint, y: *const Uint) u1 {
    @setRuntimeSafety(true);
    const len = Uint.zero.limbs_buffer.len;
    var wide: [2 * len]usize = @splat(0);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&wide));
    const mask = std.math.maxInt(usize) >> 1;
    for (0..len) |i| {
        var carry: u128 = 0;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&carry));
        for (0..len) |j| {
            var sum = @as(u128, x.limbs_buffer[i]) * y.limbs_buffer[j] + wide[i + j] + carry;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&sum));
            wide[i + j] = @as(usize, @truncate(sum)) & mask; // safe: retain low multiplication radix bits and propagate high carry separately
            carry = sum >> limb_bits;
        }
        wide[i + len] = @intCast(carry); // safe: carry is bounded by the machine radix after the preceding shift
    }
    @memcpy(&out.limbs_buffer, wide[0..len]);
    var overflow: usize = 0;
    for (wide[len..]) |limb| overflow |= limb;
    return @intFromBool(overflow != 0);
}
