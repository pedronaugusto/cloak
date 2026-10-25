//! ECDH on P-256, P-384 and P-521 with a private scalar, and X25519. Generation and agreement on the
//! curves run the same masked fixed-window walk as credential construction: neither a carry
//! nor a table index depends on the scalar. The shared secret is the affine x coordinate.
//! X25519 is std's Montgomery ladder, its shared secret the 32 bytes RFC 7748 names.
const std = @import("std");
const Curve = @import("Curve.zig");
const p256 = @import("../crypto/p256.zig");
const p521 = @import("../crypto/p521.zig");
const aegis = @import("aegis");

/// Stack a derivation or an agreement reaches below its entry, erased when it returns; a test
/// measures both curves against it in each build mode.
const secret_stack: usize = if (@import("builtin").mode == .debug) 32 * 1024 else 24 * 1024;

pub const P256 = struct {
    pub const scalar_length = p256.scalar_length;
    pub const public_length = p256.public_length;

    /// A scalar is acceptable when 0 < scalar < group order; only the verdict is released.
    pub fn check(scalar: *const [scalar_length]u8) Error!void {
        @setRuntimeSafety(true);
        if (!p256.scalarInRange(scalar)) return error.InvalidScalar;
    }

    /// Writes the SEC1 public key of a big-endian scalar: the comb walk of cloak's kernel.
    pub fn publicKey(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
        return aegis.secret.scrubbed(secret_stack, derive, .{ scalar, out });
    }

    fn derive(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
        @setRuntimeSafety(true);
        try check(scalar);
        var point = p256.baseMul(scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        if (point.z.isZero()) return error.IdentityElement;
        out.* = point.affine().toSec1();
    }

    /// Writes the x coordinate of scalar * peer; the peer must be an uncompressed point on the
    /// curve.
    pub fn agree(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
        return aegis.secret.scrubbed(secret_stack, multiply, .{ scalar, peer, out });
    }

    fn multiply(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
        @setRuntimeSafety(true);
        try check(scalar);
        if (peer.len != public_length or peer[0] != 4) return error.InvalidPublicKey;
        const point = p256.Affine.fromSec1(peer) catch return error.InvalidPublicKey;
        var product = p256.mul(&point, scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
        if (product.z.isZero()) return error.IdentityElement;
        // The shared point is secret, both coordinates.
        var shared = product.affine();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&shared));
        out.* = shared.x.toBytes();
    }
};
pub const P384 = Group(std.crypto.ecc.P384, std.crypto.sign.ecdsa.EcdsaP384Sha384);

/// P-521 through cloak's curve (`crypto/p521.zig`): the signed-window walk over the field seam.
pub const P521 = struct {
    pub const scalar_length = p521.scalar_length;
    pub const public_length = p521.public_length;

    /// A scalar is acceptable when 0 < scalar < group order; only the verdict is released.
    pub fn check(scalar: *const [scalar_length]u8) Error!void {
        @setRuntimeSafety(true);
        if (!p521.scalarInRange(scalar)) return error.InvalidScalar;
    }

    /// Writes the SEC1 public key of a big-endian scalar.
    pub fn publicKey(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
        return aegis.secret.scrubbed(secret_stack, derive, .{ scalar, out });
    }

    fn derive(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
        @setRuntimeSafety(true);
        try check(scalar);
        var point = p521.baseMul(scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        if (point.z.isZero()) return error.IdentityElement;
        out.* = point.affine().toSec1();
    }

    /// Writes the x coordinate of scalar * peer; the peer must be an uncompressed point on the
    /// curve.
    pub fn agree(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
        return aegis.secret.scrubbed(secret_stack, multiply, .{ scalar, peer, out });
    }

    fn multiply(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
        @setRuntimeSafety(true);
        try check(scalar);
        if (peer.len != public_length or peer[0] != 4) return error.InvalidPublicKey;
        const point = p521.Affine.fromSec1(peer) catch return error.InvalidPublicKey;
        var product = p521.mul(&point, scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
        if (product.z.isZero()) return error.IdentityElement;
        // The shared point is secret, both coordinates.
        var shared = product.affine();
        defer std.crypto.secureZero(u8, std.mem.asBytes(&shared));
        out.* = shared.x.toBytes();
    }
};

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

fn Group(comptime Point: type, comptime Ecdsa: type) type {
    return struct {
        /// Scalar and shared-secret length in bytes.
        pub const scalar_length = @sizeOf(Point.scalar.CompressedScalar);
        /// Uncompressed SEC1 point: 0x04, x, y.
        pub const public_length = 1 + 2 * scalar_length;

        /// A scalar is acceptable when 0 < scalar < group order. The verdict says only
        /// whether fresh entropy fell outside the range, which is public.
        pub fn check(scalar: *const [scalar_length]u8) Error!void {
            @setRuntimeSafety(true);
            Curve.validate(Point, scalar) catch return error.InvalidScalar;
            if (std.mem.allEqual(u8, scalar, 0)) return error.InvalidScalar;
        }

        /// Writes the SEC1 public key of a big-endian scalar.
        pub fn publicKey(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
            return aegis.secret.scrubbed(secret_stack, derive, .{ scalar, out });
        }

        fn derive(scalar: *const [scalar_length]u8, out: *[public_length]u8) Error!void {
            @setRuntimeSafety(true);
            try check(scalar);
            var point = Curve.base(Point, .big, scalar) catch return error.IdentityElement;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
            out.* = point.toUncompressedSec1();
        }

        /// Writes the x coordinate of scalar * peer. The peer encoding must be a valid
        /// uncompressed point on the curve, never the identity.
        pub fn agree(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
            return aegis.secret.scrubbed(secret_stack, multiply, .{ scalar, peer, out });
        }

        fn multiply(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
            @setRuntimeSafety(true);
            try check(scalar);
            if (peer.len != public_length or peer[0] != 4) return error.InvalidPublicKey;
            const key = Ecdsa.PublicKey.fromSec1(peer) catch return error.InvalidPublicKey;
            var product = Curve.mul(Point, .big, key.p, scalar) catch return error.IdentityElement;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
            out.* = product.affineCoordinates().x.toBytes(.big);
        }
    };
}

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
