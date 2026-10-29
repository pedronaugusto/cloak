//! Fixed-width borrowed arithmetic for RSA preparation. No secret-dependent
//! active width, bigint copies in callees, or secret-indexed addressing.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
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
        out.limbs_buffer[bit / width] |= @as(usize, (bytes[bytes.len - 1 - bit / 8] >> @as(u3, @intCast(bit % 8))) & 1) << @as(std.math.Log2Int(usize), @intCast(bit % width)); // public bit offsets modulo byte/machine radix fit their shift types
    }
}
pub fn encode(input: *const Uint, bytes: []u8) void {
    @setRuntimeSafety(true);
    if (bytes.len > capacity_bits / 8) @panic("cloak integer output exceeds fixed capacity");
    @memset(bytes, 0);
    for (0..bytes.len * 8) |bit| {
        bytes[bytes.len - 1 - bit / 8] |= @as(u8, @intCast((input.limbs_buffer[bit / width] >> @as(std.math.Log2Int(usize), @intCast(bit % width))) & 1)) << @as(u3, @intCast(bit % 8)); // masked value is one bit; public bit offsets fit shift types
    }
}
pub fn eql(a: *const Uint, b: *const Uint) bool {
    @setRuntimeSafety(true);
    var owner: Secret(usize) = .init(0);
    defer owner.deinit();
    const difference = owner.exposeMut();
    const x: *const volatile Uint = a;
    const y: *const volatile Uint = b;
    for (0..a.limbs_buffer.len) |i| difference.* |= x.limbs_buffer[i] ^ y.limbs_buffer[i];
    return difference.* == 0;
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
    var owner: Secret(struct { difference: usize, borrow: usize }) = .init(.{ .difference = 0, .borrow = 0 });
    defer owner.deinit();
    const s = owner.exposeMut();
    for (0..out.limbs_buffer.len) |i| {
        s.difference = out.limbs_buffer[i] -% other.limbs_buffer[i] -% s.borrow;
        out.limbs_buffer[i] = s.difference & mask;
        // Radix reserves one machine bit: positive differences fit the low
        // radix; underflow alone sets the high bit. No wider arithmetic needed.
        s.borrow = s.difference >> width;
    }
    return @intCast(s.borrow); // wrapping unsigned subtraction produces exactly a zero/one borrow
}
pub fn addSmall(out: *Uint, amount: usize) void {
    @setRuntimeSafety(true);
    var owner: Secret(struct { sum: u128, carry: u128 }) = .init(.{ .sum = 0, .carry = amount });
    defer owner.deinit();
    const s = owner.exposeMut();
    for (0..out.limbs_buffer.len) |i| {
        s.sum = @as(u128, out.limbs_buffer[i]) + s.carry;
        out.limbs_buffer[i] = @as(usize, @truncate(s.sum)) & mask; // retain low radix bits and propagate carry in the next fixed-width iteration
        s.carry = s.sum >> width;
    }
}
pub fn less(a: *const Uint, b: *const Uint) bool {
    @setRuntimeSafety(true);
    var owner: Secret(Uint) = .init(a.*);
    defer owner.deinit();
    return owner.exposeMut().subWithOverflow(b) != 0;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Uint_test.zig");
}
