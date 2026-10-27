//! P-521 (secp521r1): key generation, ECDH and ECDSA arithmetic, `weierstrass.zig`'s curve over
//! `field/p521.zig`'s field. The base point takes the variable-point walk (no comb).
const weierstrass = @import("weierstrass.zig");

const C = weierstrass.Curve(.{
    .Fe = @import("field.zig").p521.Fe,
    .order = 0x01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386409,
    .b = 0x0051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00,
    .gx = 0x00c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3dbaa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd66,
    .gy = 0x011839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e662c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16650,
});

pub const Fe = C.Fe;
pub const Scalar = C.Scalar;
pub const Limbs = C.Limbs;
pub const order = C.order;
pub const generator = C.generator;
pub const Affine = C.Affine;
pub const Jacobian = C.Jacobian;
pub const Digit = C.Digit;
pub const scalar_length = C.scalar_length;
pub const field_length = C.field_length;
pub const public_length = C.public_length;
pub const windows = C.windows;
pub const scalarInRange = C.scalarInRange;
pub const mul = C.mul;
pub const baseMul = C.baseMul;
pub const mulDoubleBasePublic = C.mulDoubleBasePublic;
pub const digestScalar = C.digestScalar;
pub const signR = C.signR;
pub const verify = C.verify;

/// Five-bit signed windows over the whole scalar, as the walk takes them.
pub fn recode(scalar: *const Limbs, out: *[windows]Digit) void {
    C.recode(C.window_bits, scalar, windows, out);
}

test {
    _ = @import("p521_test.zig");
}
