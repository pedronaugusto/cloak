//! Owned RFC8032 seed expansion; every orchestration temporary is erased.
const std = @import("std");
const Secret = @import("aegis").secret.Secret;
const edwards25519 = @import("../crypto/edwards25519.zig");
/// RFC 8032 5.1.5: the key `out` holds, the seed then the public key it derives. The clamped
/// scalar is a multiple of 8 below 2^255 and at least 2^254, so never 0 mod L: every seed is a
/// key.
pub fn create(seed: *const [32]u8, out: *[64]u8) void {
    @setRuntimeSafety(true);
    var owner: Secret(struct { expanded: [64]u8, hash: std.crypto.hash.sha2.Sha512 }) = .init(undefined);
    defer owner.deinit();
    const s = owner.exposeMut();
    s.hash = .init(.{});
    s.hash.update(seed);
    s.hash.final(&s.expanded);
    const scalar = s.expanded[0..32];
    scalar[0] &= 248;
    scalar[31] = (scalar[31] & 127) | 64;
    out[0..32].* = seed.*;
    edwards25519.base(out[32..64], scalar);
}
