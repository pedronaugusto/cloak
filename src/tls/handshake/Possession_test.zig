const std = @import("std");
const certificates = @import("../../certificates.zig");
const P = @import("Possession.zig");
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const peer = @import("../../testing/Peer.zig");

const pki = peer.pki;
const content = "cloak possession test content";

fn key(der: []const u8) !certificates.certificate.PublicKey {
    return (try certificates.certificate.parse(der, .{})).public_key;
}

test "C2 possession binds each scheme to the key type and curve it may use" {
    const p256 = try key(pki.p256);
    const p384 = try key(pki.p384);
    const ed = try key(pki.ed25519);
    const rsa = try key(pki.rsa);
    try std.testing.expect((try P.bind(.ecdsa_p256_sha256, p256)) == .ecdsa);
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.ecdsa_p256_sha256, p384));
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.ecdsa_p384_sha384, p256));
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.ecdsa_p256_sha256, ed));
    try std.testing.expect((try P.bind(.ecdsa_p384_sha384, p384)).ecdsa == .sha384);
    try std.testing.expect((try P.bind(.ed25519, ed)) == .ed25519);
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.ed25519, p256));
    inline for (.{ Hello.SignatureScheme.rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512 }) |scheme| {
        const algorithm = try P.bind(scheme, rsa);
        try std.testing.expect(algorithm.pss.hash == algorithm.pss.mgf_hash);
        try std.testing.expectError(error.SchemeKeyMismatch, P.bind(scheme, p256));
    }
    // rsa_pss_pss schemes need a key whose algorithm identifier is RSASSA-PSS.
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.rsa_pss_pss_sha256, rsa));
    const pss_only: certificates.certificate.PublicKey = .{ .rsa = .{ .modulus = rsa.rsa.modulus, .exponent = rsa.rsa.exponent, .pss_only = true } };
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.rsa_pss_rsae_sha256, pss_only));
    try std.testing.expect((try P.bind(.rsa_pss_pss_sha256, pss_only)).pss.salt_length == 32);
}

test "C2 possession verifies RSA-PSS and rejects PKCS#1 and unoffered schemes" {
    const signature = @embedFile("../../testing/pki/rsa-pss-sha256.sig");
    try P.verify(0x0804, &Hello.schemes, pki.rsa, content, signature);
    var damaged: [256]u8 = undefined;
    @memcpy(&damaged, signature);
    damaged[100] ^= 1;
    try std.testing.expectError(error.BadSignature, P.verify(0x0804, &Hello.schemes, pki.rsa, content, &damaged));
    try std.testing.expectError(error.BadSignature, P.verify(0x0804, &Hello.schemes, pki.rsa, "other content", signature));
    // SHA-384 PSS parameters do not accept a SHA-256 signature.
    try std.testing.expectError(error.BadSignature, P.verify(0x0805, &Hello.schemes, pki.rsa, content, signature));
    // PKCS#1 v1.5 (0x0401) is not a TLS 1.3 scheme: not in the table, never accepted.
    try std.testing.expectError(error.UnofferedScheme, P.verify(0x0401, &Hello.schemes, pki.rsa, content, @embedFile("../../testing/pki/rsa-pkcs1-sha256.sig")));
    // A scheme the caller did not offer is refused even when the signature is good.
    try std.testing.expectError(error.UnofferedScheme, P.verify(0x0804, &.{.ed25519}, pki.rsa, content, signature));
    try std.testing.expectError(error.UnofferedScheme, P.verify(0xdead, &Hello.schemes, pki.rsa, content, signature));
}

test "C2 possession verifies ECDSA and Ed25519 signatures made independently" {
    const Ecdsa = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    const kp = try Ecdsa.KeyPair.fromSecretKey(try Ecdsa.SecretKey.fromBytes(pki.p256_secret[0..32].*));
    var der: [Ecdsa.Signature.der_encoded_length_max]u8 = undefined;
    const sig = (try kp.sign(content, null)).toDer(&der);
    try P.verify(0x0403, &Hello.schemes, pki.p256, content, sig);
    try std.testing.expectError(error.BadSignature, P.verify(0x0403, &Hello.schemes, pki.p256, "tampered", sig));
    try std.testing.expectError(error.SchemeKeyMismatch, P.verify(0x0503, &Hello.schemes, pki.p256, content, sig));
    const ed = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.ed25519_secret[0..32].*);
    const ed_sig = (try ed.sign(content, null)).toBytes();
    try P.verify(0x0807, &Hello.schemes, pki.ed25519, content, &ed_sig);
    var bad = ed_sig;
    bad[3] ^= 0x80;
    try std.testing.expectError(error.BadSignature, P.verify(0x0807, &Hello.schemes, pki.ed25519, content, &bad));
    try std.testing.expectError(error.BadSignature, P.verify(0x0807, &Hello.schemes, pki.ed25519, content, ed_sig[0..63]));
}

test "C2 possession chooses the client scheme from the key and the server's list" {
    var buf: [64]u8 = undefined;
    const request = try Messages.certificateRequest(blk: {
        const body = [_]u8{ 0, 0, 12, 0, 13, 0, 8, 0, 6, 4, 3, 8, 4, 8, 7 };
        buf[0] = 13;
        std.mem.writeInt(u24, buf[1..4], body.len, .big);
        @memcpy(buf[4..][0..body.len], &body);
        break :blk buf[0 .. 4 + body.len];
    });
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p256_sha256, P.choose(try key(pki.p256), request).?);
    try std.testing.expect(P.choose(try key(pki.p384), request) == null);
    try std.testing.expectEqual(Hello.SignatureScheme.ed25519, P.choose(try key(pki.ed25519), request).?);
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha256, P.choose(try key(pki.rsa), request).?);
}
