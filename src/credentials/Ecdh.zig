//! Ephemeral ECDH on P-256 and P-384 with a private scalar. Generation and agreement
//! run the same masked fixed-window walk as credential construction: neither a carry
//! nor a table index depends on the scalar. The shared secret is the affine x coordinate.
const std = @import("std");
const Curve = @import("Curve.zig");
const p256 = @import("../crypto/p256.zig");

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
        @setRuntimeSafety(true);
        try check(scalar);
        if (peer.len != public_length or peer[0] != 4) return error.InvalidPublicKey;
        const point = p256.Affine.fromSec1(peer) catch return error.InvalidPublicKey;
        var product = p256.mul(point, scalar);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&product));
        if (product.z.isZero()) return error.IdentityElement;
        out.* = product.affine().x.toBytes();
    }
};
pub const P384 = Group(std.crypto.ecc.P384, std.crypto.sign.ecdsa.EcdsaP384Sha384);

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
            @setRuntimeSafety(true);
            try check(scalar);
            var point = Curve.base(Point, .big, scalar) catch return error.IdentityElement;
            defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
            out.* = point.toUncompressedSec1();
        }

        /// Writes the x coordinate of scalar * peer. The peer encoding must be a valid
        /// uncompressed point on the curve, never the identity.
        pub fn agree(scalar: *const [scalar_length]u8, peer: []const u8, out: *[scalar_length]u8) Error!void {
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
