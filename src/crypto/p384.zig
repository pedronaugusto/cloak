//! P-384 (secp384r1): key generation, ECDH and ECDSA arithmetic, `weierstrass.zig`'s curve over
//! `field/nist.zig`'s field. The base point takes the variable-point walk (no comb).
const weierstrass = @import("weierstrass.zig");

const C = weierstrass.Curve(.{
    .Fe = @import("field.zig").nist.Fe(.p384),
    .order = 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973,
    .b = 0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef,
    .gx = 0xaa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7,
    .gy = 0x3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f,
});

pub const Fe = C.Fe;
pub const Scalar = C.Scalar;
pub const Limbs = C.Limbs;
pub const order = C.order;
pub const generator = C.generator;
pub const Affine = C.Affine;
pub const Jacobian = C.Jacobian;
pub const scalar_length = C.scalar_length;
pub const field_length = C.field_length;
pub const public_length = C.public_length;
pub const scalarInRange = C.scalarInRange;
pub const mul = C.mul;
pub const baseMul = C.baseMul;
pub const mulDoubleBasePublic = C.mulDoubleBasePublic;
pub const digestScalar = C.digestScalar;
pub const signR = C.signR;
pub const verify = C.verify;

test {
    _ = @import("p384_test.zig");
}
