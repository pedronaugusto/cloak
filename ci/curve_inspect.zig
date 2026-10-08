//! Freestanding optimized inspection entry points; no hosted timing/runtime root.
const std = @import("std");
const Curve = @import("credentials").Curve;
export fn cloakP256(out: *std.crypto.ecc.P256, scalar: *const [32]u8) u8 {
    @setRuntimeSafety(true);
    out.* = @call(.never_inline, Curve.base, .{ std.crypto.ecc.P256, .big, scalar }) catch return 1;
    return 0;
}
export fn cloakP384(out: *std.crypto.ecc.P384, scalar: *const [48]u8) u8 {
    @setRuntimeSafety(true);
    out.* = @call(.never_inline, Curve.base, .{ std.crypto.ecc.P384, .big, scalar }) catch return 1;
    return 0;
}
export fn cloakEdwards(out: *std.crypto.ecc.Edwards25519, scalar: *const [32]u8) u8 {
    @setRuntimeSafety(true);
    out.* = @call(.never_inline, Curve.base, .{ std.crypto.ecc.Edwards25519, .little, scalar }) catch return 1;
    return 0;
}
