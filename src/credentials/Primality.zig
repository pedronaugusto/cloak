//! Bounded 64-round strong probable-prime validation of secret RSA factors.
//! Independent CSPRNG witnesses; extra 256 bits bound reduction bias.
const std = @import("std");
const Entropy = @import("Entropy.zig");
const U = @import("Uint.zig");
const M = @import("Montgomery.zig");
pub const CheckError = Entropy.FillError || error{InvalidKey};
pub fn check(encoded: []const u8, entropy: Entropy) CheckError!void {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    var modulus = try M.init(encoded);
    defer wipe(&modulus);
    var minus_one = U.zero;
    try U.decode(&minus_one, encoded);
    defer wipe(&minus_one);
    var one = modulus.one;
    defer wipe(&one);
    var integer_one = U.zero;
    integer_one.limbs_buffer[0] = 1;
    _ = minus_one.subWithOverflow(&integer_one);
    var span = U.zero;
    try U.decode(&span, encoded);
    defer wipe(&span);
    var three = U.zero;
    three.limbs_buffer[0] = 3;
    _ = span.subWithOverflow(&three);
    var exponent: [512]u8 = @splat(0);
    defer wipe(&exponent);
    U.encode(&minus_one, &exponent);
    var s: usize = 0;
    var zero_prefix: usize = 1;
    // Fixed scan and barrel shifts: no loop bound or address depends on p-1.
    for (0..4096) |bit| {
        const b = (exponent[511 - bit / 8] >> @as(u3, @intCast(bit % 8))) & 1; // safe: public bit offset modulo eight fits u3
        zero_prefix &= 1 - b;
        s += zero_prefix;
    }
    for (0..12) |power| {
        var shifted: [512]u8 = @splat(0);
        defer wipe(&shifted);
        const shift = @as(usize, 1) << @as(u4, @intCast(power)); // safe: public barrel stage is in 0..11 and fits u4
        for (0..4096) |bit| {
            const value = if (bit + shift < 4096) (exponent[511 - (bit + shift) / 8] >> @as(u3, @intCast((bit + shift) % 8))) & 1 else 0; // safe: public bit offset modulo eight fits u3
            shifted[511 - bit / 8] |= @as(u8, value) << @as(u3, @intCast(bit % 8)); // safe: public bit offset modulo eight fits u3
        }
        const mask: u8 = 0 -% @as(u8, @intCast((s >> @as(u4, @intCast(power))) & 1)); // safe: masked selector is exactly zero or one; public stage fits u4
        for (&exponent, shifted) |*a, b| a.* = (a.* & ~mask) | (b & mask);
    }
    var plain_minus_one: [512]u8 = undefined;
    defer wipe(&plain_minus_one);
    U.encode(&minus_one, &plain_minus_one);
    var minus_one_field = M.decode(&plain_minus_one);
    defer wipe(&minus_one_field);
    modulus.convert(&minus_one_field, &minus_one_field);
    var all_rounds: u8 = 1;
    for (0..64) |_| {
        var random: [544]u8 = undefined;
        defer wipe(&random);
        try entropy.fill(entropy.context, random[0 .. encoded.len + 32]);
        var raw = U.zero;
        try U.decode(&raw, random[0 .. encoded.len + 32]);
        defer wipe(&raw);
        var reduced = reduce(&raw, &span);
        defer wipe(&reduced);
        reduced.addSmall(2);
        var buffer: [512]u8 = undefined;
        defer wipe(&buffer);
        U.encode(&reduced, &buffer);
        var base = M.decode(&buffer);
        defer wipe(&base);
        modulus.convert(&base, &base);
        var x = one;
        defer wipe(&x);
        for (exponent[512 - encoded.len ..]) |byte| for (0..8) |i| {
            var square: M.Number = undefined;
            modulus.multiply(&square, &x, &x);
            defer wipe(&square);
            var product: M.Number = undefined;
            modulus.multiply(&product, &square, &base);
            defer wipe(&product);
            x = square;
            M.select(&x, &product, @truncate(byte >> @as(u3, @intCast(7 - i)))); // safe: retain the selected exponent bit; public shift is in 0..7
        };
        var passed: u8 = M.equal(&x, &one) | M.equal(&x, &minus_one_field);
        // Fixed maximum chain; only results before s count as witnesses.
        for (1..encoded.len * 8) |j| {
            var square: M.Number = undefined;
            modulus.multiply(&square, &x, &x);
            defer wipe(&square);
            x = square;
            passed |= @as(u8, @intFromBool(j < s)) & M.equal(&x, &minus_one_field);
        }
        all_rounds &= passed;
    }
    if (all_rounds == 0) return error.InvalidKey;
}
fn reduce(x: *const U, divisor: *const U) U {
    @setRuntimeSafety(true);
    var result = U.zero;
    defer wipe(&result);
    var bit = U.capacity_bits;
    const width = @bitSizeOf(usize) - 1;
    while (bit > 0) {
        bit -= 1;
        var carry: usize = (x.limbs_buffer[bit / width] >> @as(std.math.Log2Int(usize), @intCast(bit % width))) & 1; // safe: public bit offset modulo machine radix fits Log2Int(usize)
        for (&result.limbs_buffer) |*limb| {
            const next = limb.* >> (width - 1);
            limb.* = ((limb.* << 1) | carry) & (std.math.maxInt(usize) >> 1);
            carry = next;
        }
        var difference = result;
        defer wipe(&difference);
        const borrow = difference.subWithOverflow(divisor);
        select(U, &result, &difference, borrow == 0);
    }
    return result;
}
fn wipe(value: anytype) void {
    @setRuntimeSafety(true);
    std.crypto.secureZero(u8, std.mem.asBytes(value));
}
test {
    @setRuntimeSafety(true);
    _ = @import("Primality_test.zig");
    _ = @import("Uint.zig");
}

fn select(comptime T: type, destination: *T, source: *const T, on: bool) void {
    @setRuntimeSafety(true);
    const mask: usize = 0 -% @as(usize, @intFromBool(on));
    for (&destination.limbs_buffer, source.limbs_buffer) |*a, b| a.* = (a.* & ~mask) | (b & mask);
}
