const std = @import("std");
const S = @import("signature.zig");
test "public Ed25519 signature verifies possession and rejects changed messages" {
    const E = std.crypto.sign.Ed25519;
    const key = try E.KeyPair.generateDeterministic(@splat(19));
    const pk = key.public_key.toBytes();
    const sig = try key.sign("certificate", null);
    const bytes = sig.toBytes();
    try S.verify(.{ .ed25519 = &pk }, .ed25519, "certificate", &bytes);
    try std.testing.expectError(error.InvalidSignature, S.verify(.{ .ed25519 = &pk }, .ed25519, "other", &bytes));
}

test "modern public certificate signature vectors including full PSS padding" {
    const C = @import("../certificate.zig");
    inline for (.{ "p256", "p384", "ed25519", "rsa2048", "rsa3072", "rsa4096", "rsa2048-pss0", "rsa2048-pss32", "rsa2048-pss48", "rsa3072-pss0", "rsa3072-pss32", "rsa3072-pss48", "rsa4096-pss0", "rsa4096-pss32", "rsa4096-pss48" }) |name| {
        const cert = try C.parse(@embedFile("fixtures/vectors/" ++ name ++ ".der"), .{});
        try S.verify(cert.public_key, cert.signature_algorithm, cert.tbs, cert.signature);
        try std.testing.expectError(error.InvalidSignature, S.verify(cert.public_key, cert.signature_algorithm, "altered", cert.signature));
    }
}
