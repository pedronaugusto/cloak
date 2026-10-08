//! Owned RFC8032 seed expansion; every orchestration temporary is erased.
const std = @import("std");
const Curve = @import("Curve.zig");
const Ed25519 = std.crypto.sign.Ed25519;
pub const CreateError = error{InvalidKey};
pub fn create(seed: *const [32]u8) CreateError!Ed25519.KeyPair {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
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
    var point = Curve.base(Ed25519.Curve, .little, &scalar) catch return error.InvalidKey;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
    const public = point.toBytes();
    var encoded: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &encoded);
    @memcpy(encoded[0..32], seed);
    @memcpy(encoded[32..64], &public);
    return .{
        .public_key = Ed25519.PublicKey.fromBytes(public) catch return error.InvalidKey,
        .secret_key = .{ .bytes = encoded },
    };
}
