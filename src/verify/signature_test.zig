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

test "F09 catalogue_rsa_signature_full_encoding (modern public certificate signature vectors including full PSS padding)" {
    const C = @import("../certificate.zig");
    inline for (.{ "p256", "p384", "ed25519", "rsa2048", "rsa3072", "rsa4096", "rsa2048-pss0", "rsa2048-pss32", "rsa2048-pss48", "rsa3072-pss0", "rsa3072-pss32", "rsa3072-pss48", "rsa4096-pss0", "rsa4096-pss32", "rsa4096-pss48" }) |name| {
        const cert = try C.parse(@embedFile("fixtures/vectors/" ++ name ++ ".der"), .{});
        try S.verify(cert.public_key, cert.signature_algorithm, cert.tbs, cert.signature);
        try std.testing.expectError(error.InvalidSignature, S.verify(cert.public_key, cert.signature_algorithm, "altered", cert.signature));
    }
}

test "F08 catalogue_signature_workspace_and_rsa_size (oversized and resized signatures fail before any workspace; the largest supported keys verify)" {
    const C = @import("../certificate.zig");
    var huge: [65536]u8 = @splat(0xff);
    inline for (.{ "rsa4096", "rsa4096-pss32" }) |name| {
        const cert = try C.parse(@embedFile("fixtures/vectors/" ++ name ++ ".der"), .{});
        try S.verify(cert.public_key, cert.signature_algorithm, cert.tbs, cert.signature);
        // The same integer one byte longer: RSA signatures are exactly the modulus's length.
        var longer: [513]u8 = undefined;
        longer[0] = 0;
        @memcpy(longer[1..], cert.signature);
        try std.testing.expectError(error.InvalidSignature, S.verify(cert.public_key, cert.signature_algorithm, cert.tbs, &longer));
        try std.testing.expectError(error.InvalidSignature, S.verify(cert.public_key, cert.signature_algorithm, cert.tbs, cert.signature[1..]));
        try std.testing.expectError(error.InvalidSignature, S.verify(cert.public_key, cert.signature_algorithm, cert.tbs, &huge));
    }
    // An ECDSA signature far larger than any curve's, well formed as DER.
    const p256 = try C.parse(@embedFile("fixtures/vectors/p256.der"), .{});
    try S.verify(p256.public_key, p256.signature_algorithm, p256.tbs, p256.signature);
    const half = (huge.len - 16) / 2;
    huge[0..4].* = .{ 0x30, 0x82, @truncate((2 * (half + 4)) >> 8), @truncate(2 * (half + 4)) };
    for (0..2) |i| {
        const at = 4 + i * (half + 4);
        huge[at..][0..4].* = .{ 0x02, 0x82, @truncate(half >> 8), @truncate(half) };
        huge[at + 4] = 0x01;
    }
    try std.testing.expectError(error.InvalidSignature, S.verify(p256.public_key, p256.signature_algorithm, p256.tbs, huge[0 .. 4 + 2 * (half + 4)]));
}
