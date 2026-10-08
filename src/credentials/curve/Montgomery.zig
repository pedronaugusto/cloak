//! Fixed-width Montgomery arithmetic over the P-256/P-384 prime fields.
//! Schoolbook product and REDC use public limb counts; only masked reduction selects.
const std = @import("std");
const Select = @import("Select.zig");
pub fn Field(comptime Public: type) type {
    const n = Public.encoded_length / 8;
    const prime: [n]u64 = comptime blk: {
        var limbs: [n]u64 = undefined;
        for (&limbs, 0..) |*limb, i| limb.* = @truncate(Public.field_order >> (64 * i)); // safe: each modulus limb retains its low 64 bits
        break :blk limbs;
    };
    const inverse: u64 = comptime blk: {
        var value: u64 = 1;
        for (0..6) |_| value *%= 2 -% prime[0] *% value;
        break :blk 0 -% value;
    };
    comptime {
        std.debug.assert(n == 4 or n == 6);
        std.debug.assert(Public.field_bits == n * 64);
        std.debug.assert(prime[0] *% inverse == std.math.maxInt(u64));
    }
    return struct {
        pub const MontgomeryDomainFieldElement = [n]u64;
        pub fn selectznz(out: *[n]u64, choice: u1, a: [n]u64, b: [n]u64) void {
            @setRuntimeSafety(true);
            const mask = Select.mask(choice);
            for (0..n) |i| out[i] = (mask & b[i]) | (~mask & a[i]);
        }
        pub fn mul(out: *[n]u64, a: [n]u64, b: [n]u64) void {
            @setRuntimeSafety(true);
            var scratch: struct { product: [2 * n + 1]u64, carry: u64, wide: u128 } = .{ .product = @splat(0), .carry = 0, .wide = 0 };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            for (0..n) |i| {
                scratch.carry = 0;
                for (0..n) |j| {
                    // Max: (2^64-1)^2 + 2*(2^64-1) = 2^128-1.
                    scratch.wide = @as(u128, a[i]) *% b[j] +% scratch.product[i + j] +% scratch.carry;
                    scratch.product[i + j] = @truncate(scratch.wide); // safe: low product word
                    scratch.carry = @truncate(scratch.wide >> 64); // safe: high product word
                }
                scratch.product[i + n] = scratch.carry;
            }
            reduce(out, &scratch.product);
        }
        pub fn square(out: *[n]u64, a: [n]u64) void {
            @setRuntimeSafety(true);
            mul(out, a, a);
        }
        fn reduce(out: *[n]u64, product: *[2 * n + 1]u64) void {
            @setRuntimeSafety(true);
            var scratch: struct { factor: u64, carry: u64, wide: u128 } = .{ .factor = 0, .carry = 0, .wide = 0 };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            for (0..n) |i| {
                scratch.factor = product[i] *% inverse;
                scratch.carry = 0;
                for (0..n) |j| {
                    // Same double-word bound as the product; low limb cancels modulo 2^64.
                    scratch.wide = @as(u128, scratch.factor) *% prime[j] +% product[i + j] +% scratch.carry;
                    product[i + j] = @truncate(scratch.wide); // safe: low reduction word
                    scratch.carry = @truncate(scratch.wide >> 64); // safe: high reduction word
                }
                for (i + n..2 * n + 1) |j| {
                    scratch.wide = @as(u128, product[j]) +% scratch.carry;
                    product[j] = @truncate(scratch.wide); // safe: low sum word
                    scratch.carry = @truncate(scratch.wide >> 64); // safe: high sum word, at most one
                }
            }
            // For a,b < p, REDC is below 2p and needs exactly one conditional subtraction.
            canonical(out, product[n..][0 .. n + 1]);
        }
        fn canonical(out: *[n]u64, candidate: *const [n + 1]u64) void {
            @setRuntimeSafety(true);
            var scratch: struct { difference: [n]u64, borrow: u64, wide: u128, mask: u64 } = .{ .difference = @splat(0), .borrow = 0, .wide = 0, .mask = 0 };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            for (0..n) |i| {
                scratch.wide = @as(u128, candidate[i]) -% prime[i] -% scratch.borrow;
                scratch.difference[i] = @truncate(scratch.wide); // safe: low subtraction word
                scratch.borrow = @truncate(scratch.wide >> 127); // safe: unsigned wrapped subtraction's borrow bit
            }
            scratch.wide = @as(u128, candidate[n]) -% scratch.borrow;
            scratch.mask = Select.mask(@truncate(scratch.wide >> 127)); // safe: final borrow is one bit
            for (0..n) |i| out[i] = (scratch.mask & candidate[i]) | (~scratch.mask & scratch.difference[i]);
        }
        pub fn add(out: *[n]u64, a: [n]u64, b: [n]u64) void {
            @setRuntimeSafety(true);
            var scratch: struct { candidate: [n + 1]u64, wide: u128, carry: u64 } = .{ .candidate = @splat(0), .wide = 0, .carry = 0 };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            for (0..n) |i| {
                scratch.wide = @as(u128, a[i]) +% b[i] +% scratch.carry;
                scratch.candidate[i] = @truncate(scratch.wide); // safe: low sum word
                scratch.carry = @truncate(scratch.wide >> 64); // safe: high sum word, at most one
            }
            scratch.candidate[n] = scratch.carry;
            canonical(out, &scratch.candidate);
        }
        pub fn sub(out: *[n]u64, a: [n]u64, b: [n]u64) void {
            @setRuntimeSafety(true);
            var scratch: struct { difference: [n]u64, borrow: u64, wide: u128, carry: u64, mask: u64 } = .{ .difference = @splat(0), .borrow = 0, .wide = 0, .carry = 0, .mask = 0 };
            defer if (!@inComptime()) std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
            for (0..n) |i| {
                scratch.wide = @as(u128, a[i]) -% b[i] -% scratch.borrow;
                scratch.difference[i] = @truncate(scratch.wide); // safe: low subtraction word
                scratch.borrow = @truncate(scratch.wide >> 127); // safe: unsigned wrapped subtraction's borrow bit
            }
            scratch.mask = Select.mask(@truncate(scratch.borrow)); // safe: borrow remains zero or one
            for (0..n) |i| {
                scratch.wide = @as(u128, scratch.difference[i]) +% (prime[i] & scratch.mask) +% scratch.carry;
                out[i] = @truncate(scratch.wide); // safe: low correction word; canonical a-b modulo p
                scratch.carry = @truncate(scratch.wide >> 64); // safe: high correction word
            }
        }
    };
}
