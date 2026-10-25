//! ECDH on P-256, P-384 and P-521 with a private scalar, and X25519. Generation and agreement on the
//! curves run cloak's constant-time multiplications: neither a carry nor a table index depends
//! on the scalar. The shared secret is the affine x coordinate.
//! X25519 is std's Montgomery ladder, its shared secret the 32 bytes RFC 7748 names.
const std = @import("std");
const p256 = @import("../crypto/p256.zig");
const p384 = @import("../crypto/p384.zig");
const p521 = @import("../crypto/p521.zig");
const aegis = @import("aegis");

/// Stack a derivation or an agreement reaches below its entry, erased when it returns; a test
/// measures both curves against it in each build mode.
const secret_stack: usize = if (@import("builtin").mode == .debug) 32 * 1024 else 24 * 1024;

/// ECDH on one of cloak's curves (`crypto/weierstrass.zig`): the base point's comb or walk for a
/// public key, the signed-window walk over the peer's multiples for an agreement.
fn Nist(comptime curve: type) type {
    return struct {
        pub const scalar_length = curve.scalar_length;
        pub const public_length = curve.public_length;

        /// A scalar is acceptable when 0 < scalar < group order; only the verdict is released.
        pub fn check(scalar: *const [scalar_length]u8) Error!void {
            @setRuntimeSafety(true);
            if (!curve.scalarInRange(scalar)) return error.InvalidScalar;
        }

        /// Writes the SEC1 public key of a big-endian scalar.
        pub fn publicKey(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
            return aegis.secret.scrubbed(secret_stack, derive, .{ scalar, out });
        }

        fn derive(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
            @setRuntimeSafety(true);
            try check(scalar);
            var point = curve.baseMul(scalar);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
            if (point.z.isZero()) return error.IdentityElement;
            out.* = point.affine().toSec1();
        }

        /// Writes the x coordinate of scalar * peer; the peer must be an uncompressed point on
        /// the curve.
        pub fn agree(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
            return aegis.secret.scrubbed(secret_stack, multiply, .{ scalar, peer, out });
        }

        fn multiply(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
            @setRuntimeSafety(true);
            try check(scalar);
            if (peer.len != public_length or peer[0] != 4) return error.InvalidPublicKey;
            const point = curve.Affine.fromSec1(peer) catch return error.InvalidPublicKey;
            var product = curve.mul(&point, scalar);
            defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
            if (product.z.isZero()) return error.IdentityElement;
            // The shared point is secret, both coordinates.
            var shared = product.affine();
            defer std.crypto.secureZero(u8, std.mem.asBytes(&shared));
            out.* = shared.x.toBytes();
        }
    };
}

pub const P256 = Nist(p256);
pub const P384 = Nist(p384);
pub const P521 = Nist(p521);

pub const X25519 = struct {
    pub const length = 32;

    /// Writes X25519(scalar, peer) (RFC 7748 5). A peer of small order, whose result is all
    /// zeros, is refused (6.1): it would fix the secret whatever the scalar.
    pub fn agree(scalar: *const [length]u8, peer: []const u8, out: *[length]u8) Error!void {
        return aegis.secret.scrubbed(secret_stack, ladder, .{ scalar, peer, out });
    }

    fn ladder(scalar: *const [length]u8, peer: []const u8, out: *[length]u8) Error!void {
        @setRuntimeSafety(true);
        if (peer.len != length) return error.InvalidPublicKey;
        out.* = std.crypto.dh.X25519.scalarmult(scalar.*, peer[0..length].*) catch return error.IdentityElement;
    }
};

pub const Error = error{ InvalidScalar, InvalidPublicKey, IdentityElement };

test {
    _ = @import("Ecdh_test.zig");
}

test "a derivation or an agreement reaches less stack than the depth that erases it" {
    var deepest: usize = 0;
    inline for (.{ P256, P384, P521 }) |Kind| {
        var scalar: [Kind.scalar_length]u8 = @splat(0x35);
        scalar[0] = 0;
        var public: [Kind.public_length]u8 = undefined;
        deepest = @max(deepest, aegis.secret.stackReach(4 * secret_stack, Kind.derive, .{ &scalar, &public }));
        try Kind.publicKey(&scalar, &public);
        var shared: [Kind.scalar_length]u8 = undefined;
        deepest = @max(deepest, aegis.secret.stackReach(4 * secret_stack, Kind.multiply, .{ &scalar, &public, &shared }));
    }
    const scalar: [X25519.length]u8 = @splat(0x35);
    const peer: [X25519.length]u8 = @splat(0x09);
    var shared: [X25519.length]u8 = undefined;
    deepest = @max(deepest, aegis.secret.stackReach(4 * secret_stack, X25519.ladder, .{ &scalar, &peer, &shared }));
    try std.testing.expect(deepest < secret_stack);
}
