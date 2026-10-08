//! Fixed-width borrowed arithmetic for RSA preparation. No secret-dependent
//! active width, bigint copies in callees, or secret-indexed addressing.
const std = @import("std");
const Uint = @This();
const width = @bitSizeOf(usize) - 1;
const mask = std.math.maxInt(usize) >> 1;
pub const capacity_bits: usize = 8192;
limbs_buffer: [(capacity_bits + width - 1) / width]usize = @splat(0),
pub const zero: Uint = .{};
pub fn decode(out: *Uint, bytes: []const u8) error{InvalidKey}!void {
    @setRuntimeSafety(true);
    if (bytes.len > capacity_bits / 8) return error.InvalidKey;
    out.* = zero;
    for (0..bytes.len * 8) |bit| {
        out.limbs_buffer[bit / width] |= @as(usize, (bytes[bytes.len - 1 - bit / 8] >> @as(u3, @intCast(bit % 8))) & 1) << @as(std.math.Log2Int(usize), @intCast(bit % width)); // safe: public bit offsets modulo byte/machine radix fit their shift types
    }
}
pub fn encode(input: *const Uint, bytes: []u8) void {
    @setRuntimeSafety(true);
    if (bytes.len > capacity_bits / 8) @panic("cloak integer output exceeds fixed capacity");
    @memset(bytes, 0);
    for (0..bytes.len * 8) |bit| {
        bytes[bytes.len - 1 - bit / 8] |= @as(u8, @intCast((input.limbs_buffer[bit / width] >> @as(std.math.Log2Int(usize), @intCast(bit % width))) & 1)) << @as(u3, @intCast(bit % 8)); // safe: masked value is one bit; public bit offsets fit shift types
    }
}
pub fn eql(a: *const Uint, b: *const Uint) bool {
    @setRuntimeSafety(true);
    var difference: usize = 0;
    defer wipe(&difference);
    const x: *const volatile Uint = a;
    const y: *const volatile Uint = b;
    for (0..a.limbs_buffer.len) |i| difference |= x.limbs_buffer[i] ^ y.limbs_buffer[i];
    return difference == 0;
}
pub fn isZero(a: *const Uint) bool {
    @setRuntimeSafety(true);
    return a.eql(&zero);
}
pub fn isOne(a: *const Uint) bool {
    @setRuntimeSafety(true);
    var one = zero;
    one.limbs_buffer[0] = 1;
    return a.eql(&one);
}
pub fn isOdd(a: *const Uint) bool {
    @setRuntimeSafety(true);
    return a.limbs_buffer[0] & 1 != 0;
}
pub fn subWithOverflow(out: *Uint, other: *const Uint) u1 {
    @setRuntimeSafety(true);
    var difference: usize = 0;
    defer wipe(&difference);
    var borrow: usize = 0;
    defer wipe(&borrow);
    for (0..out.limbs_buffer.len) |i| {
        difference = out.limbs_buffer[i] -% other.limbs_buffer[i] -% borrow;
        out.limbs_buffer[i] = difference & mask;
        // Radix reserves one machine bit: positive differences fit the low
        // radix; underflow alone sets the high bit. No wider arithmetic needed.
        borrow = difference >> width;
    }
    return @intCast(borrow); // safe: wrapping unsigned subtraction produces exactly a zero/one borrow
}
pub fn addSmall(out: *Uint, amount: usize) void {
    @setRuntimeSafety(true);
    var sum: u128 = 0;
    defer wipe(&sum);
    var carry: u128 = amount;
    defer wipe(&carry);
    for (0..out.limbs_buffer.len) |i| {
        sum = @as(u128, out.limbs_buffer[i]) + carry;
        out.limbs_buffer[i] = @as(usize, @truncate(sum)) & mask; // safe: retain low radix bits and propagate carry in the next fixed-width iteration
        carry = sum >> width;
    }
}
pub fn less(a: *const Uint, b: *const Uint) bool {
    @setRuntimeSafety(true);
    var difference = a.*;
    defer wipe(&difference);
    return difference.subWithOverflow(b) != 0;
}
fn wipe(value: anytype) void {
    @setRuntimeSafety(true);
    std.crypto.secureZero(u8, std.mem.asBytes(value));
}
test {
    @setRuntimeSafety(true);
    _ = @import("Uint_test.zig");
}
