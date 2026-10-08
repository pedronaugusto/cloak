//! Fixed public-width Montgomery arithmetic for RSA factor validation.
const std = @import("std");
const Montgomery = @This();
pub const Number = [128]u32;
modulus: Number,
rr: Number,
one: Number,
words: usize,
inverse: u32,
pub const InitError = error{InvalidKey};
pub fn init(encoded: []const u8) InitError!Montgomery {
    @setRuntimeSafety(true);
    if (encoded.len == 0 or encoded.len > 512 or encoded[0] == 0 or encoded[encoded.len - 1] & 1 == 0) return error.InvalidKey;
    var m: Montgomery = .{ .modulus = decode(encoded), .rr = @splat(0), .one = @splat(0), .words = (encoded.len + 3) / 4, .inverse = undefined };
    defer wipe(&m);
    var inverse: u32 = m.modulus[0];
    defer wipe(&inverse);
    for (0..5) |_| inverse *%= 2 -% m.modulus[0] *% inverse;
    m.inverse = 0 -% inverse;
    m.rr[0] = 1;
    for (0..2 * m.words * 32) |_| m.double(&m.rr);
    var plain_one: Number = @splat(0);
    defer wipe(&plain_one);
    plain_one[0] = 1;
    m.multiply(&m.one, &plain_one, &m.rr);
    return m;
}
pub fn decode(encoded: []const u8) Number {
    @setRuntimeSafety(true);
    var number: Number = @splat(0);
    defer wipe(&number);
    for (encoded, 0..) |byte, i| {
        const j = encoded.len - 1 - i;
        number[j / 4] |= @as(u32, byte) << @as(u5, @intCast((j % 4) * 8)); // safe: public byte offset modulo four gives a shift in 0..24
    }
    return number;
}
pub fn convert(m: *const Montgomery, out: *Number, input: *const Number) void {
    @setRuntimeSafety(true);
    m.multiply(out, input, &m.rr);
}
pub fn multiply(m: *const Montgomery, out: *Number, a: *const Number, b: *const Number) void {
    @setRuntimeSafety(true);
    var t: [130]u32 = @splat(0);
    defer wipe(&t);
    var carry: u64 = 0;
    defer wipe(&carry);
    var sum: u64 = 0;
    defer wipe(&sum);
    var top: u64 = 0;
    defer wipe(&top);
    var factor: u32 = 0;
    defer wipe(&factor);
    for (0..m.words) |i| {
        carry = 0;
        for (0..m.words) |j| {
            sum = @as(u64, a[j]) * b[i] + t[j] + carry;
            t[j] = @truncate(sum); // safe: retain low radix-2^32 word and propagate carry separately
            carry = sum >> 32;
        }
        top = @as(u64, t[m.words]) + carry;
        t[m.words] = @truncate(top); // safe: retain low radix-2^32 accumulator word
        t[m.words + 1] = @truncate(top >> 32); // safe: retain high radix-2^32 carry word
        factor = t[0] *% m.inverse;
        carry = 0;
        for (0..m.words) |j| {
            sum = @as(u64, factor) * m.modulus[j] + t[j] + carry;
            if (j > 0) t[j - 1] = @truncate(sum); // safe: retain low word after a public radix shift
            carry = sum >> 32;
        }
        top = @as(u64, t[m.words]) + carry;
        t[m.words - 1] = @truncate(top); // safe: retain low word after the Montgomery radix shift
        t[m.words] = t[m.words + 1] + @as(u32, @truncate(top >> 32)); // safe: retain high radix-2^32 carry word
    }
    m.canonical(out, t[0..128], t[m.words]);
}
fn double(m: *const Montgomery, number: *Number) void {
    @setRuntimeSafety(true);
    var carry: u32 = 0;
    defer wipe(&carry);
    for (number[0..m.words]) |*word| {
        const next = word.* >> 31;
        word.* = (word.* << 1) | carry;
        carry = next;
    }
    m.canonical(number, number, carry);
}
fn canonical(m: *const Montgomery, out: *Number, input: *const Number, high: u32) void {
    @setRuntimeSafety(true);
    var difference: Number = @splat(0);
    defer wipe(&difference);
    var borrow: u64 = 0;
    defer wipe(&borrow);
    var sub: u64 = 0;
    defer wipe(&sub);
    for (0..m.words) |i| {
        sub = @as(u64, input[i]) -% m.modulus[i] -% borrow;
        difference[i] = @truncate(sub); // safe: wrapping subtraction retains low radix word and records borrow separately
        borrow = sub >> 63;
    }
    const choose: u32 = @as(u32, @intFromBool(high != 0)) | @as(u32, @intCast(1 - borrow)); // safe: subtraction borrow is exactly zero or one
    const mask: u32 = 0 -% choose;
    for (out, input, difference) |*dst, a, b| dst.* = (a & ~mask) | (b & mask);
}
pub fn select(out: *Number, other: *const Number, bit: u1) void {
    @setRuntimeSafety(true);
    const mask: u32 = 0 -% @as(u32, bit);
    for (out, other) |*a, b| a.* = (a.* & ~mask) | (b & mask);
}
pub fn equal(a: *const Number, b: *const Number) u8 {
    @setRuntimeSafety(true);
    var difference: u32 = 0;
    defer wipe(&difference);
    // Volatile reads prevent an optimizer from introducing early-exit comparison.
    const x: *const volatile Number = a;
    const y: *const volatile Number = b;
    for (0..128) |i| difference |= x[i] ^ y[i];
    return @intFromBool(difference == 0);
}
pub fn deinit(m: *Montgomery) void {
    @setRuntimeSafety(true);
    wipe(m);
    m.* = undefined;
}
fn wipe(value: anytype) void {
    @setRuntimeSafety(true);
    std.crypto.secureZero(u8, std.mem.asBytes(value));
}
test {
    @setRuntimeSafety(true);
    _ = @import("Montgomery_test.zig");
}
