const std = @import("std");
const A = @import("Algorithm.zig");
const Certificate = @import("Certificate.zig");

test "F24 catalogue_algorithm_identifier_and_empty_point (keys and signature identifiers take exactly their legal parameters; empty and unknown keys are refused)" {
    const p256 = "\x30\x13\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07";
    // A zero-byte EC point, a lone point-format byte, and a valid point.
    try std.testing.expectError(error.InvalidPublicKey, A.publicKey("\x30\x18" ++ p256 ++ "\x03\x01\x00"));
    try std.testing.expectError(error.InvalidPublicKey, A.publicKey("\x30\x19" ++ p256 ++ "\x03\x02\x00\x04"));
    const g = std.crypto.ecc.P256.basePoint.toUncompressedSec1();
    _ = try A.publicKey("\x30\x59" ++ p256 ++ "\x03\x42\x00" ++ g);
    // An EC key without its curve, or with an unknown one.
    try std.testing.expect(std.meta.isError(A.publicKey("\x30\x4f\x30\x09\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x03\x42\x00" ++ g)));
    // secp256k1 (1.3.132.0.10), a curve cloak does not take.
    try std.testing.expectError(error.UnsupportedAlgorithm, A.publicKey("\x30\x56\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x0a\x03\x42\x00" ++ g));
    // P-521's OID with a P-256-sized point.
    try std.testing.expectError(error.InvalidPublicKey, A.publicKey("\x30\x56\x30\x10\x06\x07\x2a\x86\x48\xce\x3d\x02\x01\x06\x05\x2b\x81\x04\x00\x23\x03\x42\x00" ++ g));
    // Ed25519: parameters are absent (RFC 8410), so a NULL is refused.
    const ed = (try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(3))).public_key.toBytes();
    _ = try A.publicKey("\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00" ++ ed);
    try std.testing.expectError(error.InvalidPublicKey, A.publicKey("\x30\x2c\x30\x07\x06\x03\x2b\x65\x70\x05\x00\x03\x21\x00" ++ ed));
    // An unknown key type.
    try std.testing.expectError(error.UnsupportedAlgorithm, A.publicKey("\x30\x2a\x30\x05\x06\x03\x2b\x65\x71\x03\x21\x00" ++ ed));
    // Signature identifiers: ECDSA and Ed25519 take no parameters, PKCS#1 v1.5 takes NULL or
    // nothing, and RSASSA-PSS needs its parameters.
    try std.testing.expectEqual(A.Signature{ .ecdsa = .sha256 }, try A.signature("\x30\x0a\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02"));
    try std.testing.expectError(error.InvalidDer, A.signature("\x30\x0c\x06\x08\x2a\x86\x48\xce\x3d\x04\x03\x02\x05\x00"));
    try std.testing.expectError(error.InvalidDer, A.signature("\x30\x07\x06\x03\x2b\x65\x70\x05\x00"));
    try std.testing.expectEqual(A.Signature{ .rsa = .sha256 }, try A.signature("\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x05\x00"));
    try std.testing.expectError(error.InvalidDer, A.signature("\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0b\x04\x00"));
    try std.testing.expectError(error.InvalidDer, A.signature("\x30\x0b\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a"));
    // The certificate's outer algorithm must equal the one its signed body names.
    const der = @embedFile("../verify/fixtures/vectors/p256.der");
    _ = try Certificate.parse(der, .{});
    var altered = der.*;
    const ecdsa_sha256 = "\x2a\x86\x48\xce\x3d\x04\x03\x02";
    const outer = std.mem.findLast(u8, &altered, ecdsa_sha256).?;
    try std.testing.expect(outer != std.mem.find(u8, &altered, ecdsa_sha256).?);
    altered[outer + ecdsa_sha256.len - 1] = 3; // ecdsa-with-SHA384
    try std.testing.expectError(error.InvalidCertificate, Certificate.parse(&altered, .{}));
}
