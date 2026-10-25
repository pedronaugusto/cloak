//! Owned RFC8032 seed expansion; every orchestration temporary is erased.
const std = @import("std");
const edwards25519 = @import("../crypto/edwards25519.zig");
const Ed25519 = std.crypto.sign.Ed25519;
pub const CreateError = error{InvalidKey};
pub fn create(seed: *const [32]u8) CreateError!Ed25519.KeyPair {
    @setRuntimeSafety(true);
    var expanded: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &expanded);
    var hash = std.crypto.hash.sha2.Sha512.init(.{});
    defer std.crypto.secureZero(u8, std.mem.asBytes(&hash));
    hash.update(seed);
    hash.final(&expanded);
    var scalar = expanded[0..32].*;
    defer std.crypto.secureZero(u8, &scalar);
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    // The clamped scalar is a multiple of 8 below 2^255 and at least 2^254, so never 0 mod L.
    var public: [32]u8 = undefined;
    edwards25519.base(&public, &scalar);
    var encoded: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    @memcpy(encoded[0..32], seed);
    @memcpy(encoded[32..64], &public);
    return .{
        .public_key = Ed25519.PublicKey.fromBytes(public) catch return error.InvalidKey,
        .secret_key = .{ .bytes = encoded },
    };
}
