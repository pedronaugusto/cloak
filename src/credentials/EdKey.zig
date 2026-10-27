//! Owned RFC8032 seed expansion; every orchestration temporary is erased.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const Curve = @import("Curve.zig");
const Ed25519 = std.crypto.sign.Ed25519;
pub const CreateError = error{InvalidKey};
/// RFC 8032 5.1.5: the key `out` holds, the seed then the public key it derives.
pub fn create(seed: *const [32]u8, out: *[64]u8) CreateError!void {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    var owner: Secret(struct { expanded: [64]u8, hash: std.crypto.hash.sha2.Sha512, point: Ed25519.Curve }) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    s.hash = .init(.{});
    s.hash.update(seed);
    s.hash.final(&s.expanded);
    const scalar = s.expanded[0..32];
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    s.point = Curve.base(Ed25519.Curve, .little, scalar) catch return error.InvalidKey;
    out[0..32].* = seed.*;
    out[32..64].* = s.point.toBytes();
}
