//! Ephemeral ECDH on P-256 and P-384 with a private scalar. Generation and agreement
//! run the same masked fixed-window walk as credential construction: neither a carry
//! nor a table index depends on the scalar. The shared secret is the affine x coordinate.
const std = @import("std");
const Curve = @import("Curve.zig");

pub const P256 = Group(std.crypto.ecc.P256, std.crypto.sign.ecdsa.EcdsaP256Sha256);
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
