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
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p256_sha256, P.choose(try key(pki.p256), &.{}, request).?);
    try std.testing.expect(P.choose(try key(pki.p384), &.{}, request) == null);
    try std.testing.expectEqual(Hello.SignatureScheme.ed25519, P.choose(try key(pki.ed25519), &.{}, request).?);
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha256, P.choose(try key(pki.rsa), &.{}, request).?);
}

test "C4 a key restricted to PSS parameters signs only under the schemes they name" {
    const rsa = try key(pki.rsa);
    // RSASSA-PSS with SHA-384, MGF1-SHA-384 and a 48-byte salt.
    const sha384: certificates.certificate.PublicKey = .{ .rsa = .{ .modulus = rsa.rsa.modulus, .exponent = rsa.rsa.exponent, .pss_only = true, .pss = .{ .hash = .sha384, .mgf_hash = .sha384, .salt_length = 48 } } };
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.rsa_pss_pss_sha256, sha384));
    try std.testing.expect((try P.bind(.rsa_pss_pss_sha384, sha384)).pss.salt_length == 48);
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.rsa_pss_pss_sha512, sha384));
    // A salt minimum longer than a hash rules that hash's scheme out.
    const long_salt: certificates.certificate.PublicKey = .{ .rsa = .{ .modulus = rsa.rsa.modulus, .exponent = rsa.rsa.exponent, .pss_only = true, .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 48 } } };
    try std.testing.expectError(error.SchemeKeyMismatch, P.bind(.rsa_pss_pss_sha256, long_salt));
    const Accepts = struct {
        pub fn accepts(_: @This(), scheme: u16) bool {
            return scheme == 0x0809 or scheme == 0x080a or scheme == 0x080b;
        }
    };
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_pss_sha384, P.choose(sha384, &.{}, Accepts{}).?);
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_pss_sha384, P.chooseServer12(sha384, &.{}, Accepts{}).?);
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_pss_sha384, P.chooseClient12(sha384, &.{}, Accepts{}).?);
    try std.testing.expect(P.choose(long_salt, &.{}, Accepts{}) == null);
}

test "F142 catalogue_tls12_ecdsa_scheme_names_hash_not_curve (every TLS 1.2 scheme a chooser takes for a key, the key signs and the peer accepts)" {
    // RFC 8446 section 4.2.3: TLS 1.2's ECDSA pairs name a hash, not a curve, so a P-384 key may
    // sign under ecdsa_secp256r1_sha256 and a P-256 key under ecdsa_secp384r1_sha384, as Go and
    // BoringSSL do. The server's chooser took such a scheme and the signer refused it; the
    // client's never offered one.
    const gpa = std.testing.allocator;
    const Case = struct { cert: []const u8, pem: []const u8 };
    for ([_]Case{ .{ .cert = pki.p256, .pem = pki.p256_pem }, .{ .cert = pki.p384, .pem = pki.p384_pem }, .{ .cert = pki.ed25519, .pem = pki.ed25519_pem }, .{ .cert = pki.rsa, .pem = pki.rsa_pem } }) |case| {
        const private = try certificates.PrivateKey.parse(gpa, case.pem, .{});
        defer private.deinit();
        const identity = try certificates.Identity.init(gpa, &.{case.cert}, private, .{});
        defer identity.deinit();
        const public = identity.publicKey();
        var noise: [certificates.PrivateKey.max_noise]u8 = @splat(0x5a);
        const fresh = noise[0 .. identity.noiseLength() orelse 0];
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        for (Hello.schemes12) |scheme| {
            const only: Only = .{ .id = @backingInt(scheme) };
            if (P.chooseServer12(public, &.{}, only)) |chosen| {
                try std.testing.expectEqual(scheme, chosen);
                const signature = try P.sign12(identity, chosen, content, fresh, &out);
                try P.verifyMessage12(@backingInt(chosen), &.{chosen}, public, content, signature);
            }
            if (P.chooseClient12(public, &.{}, only)) |chosen| {
                try std.testing.expectEqual(scheme, chosen);
                if (chosen == .ed25519) {
                    // Ed25519 signs the handshake messages themselves (RFC 8422 section 5.10).
                    const signature = try P.sign12(identity, chosen, content, fresh, &out);
                    try P.verifyMessage12(@backingInt(chosen), &.{chosen}, public, content, signature);
                    continue;
                }
                var digest: [64]u8 = undefined;
                const length = P.transcriptHash12(chosen).?;
                std.crypto.hash.sha2.Sha512.hash(content, &digest, .{});
                const signature = try P.signDigest12(identity, chosen, digest[0..length], fresh, &out);
                try P.verifyDigest12(@backingInt(chosen), &.{chosen}, public, digest[0..length], signature);
            }
        }
    }
    // The pairs that were missing, by name: each curve under the other's hash, both roles.
    const p256 = try key(pki.p256);
    const p384 = try key(pki.p384);
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p256_sha256, P.chooseClient12(p384, &.{}, Only{ .id = 0x0403 }).?);
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p384_sha384, P.chooseClient12(p256, &.{}, Only{ .id = 0x0503 }).?);
    try std.testing.expectEqual(Hello.SignatureScheme.ecdsa_p256_sha256, P.chooseServer12(p384, &.{}, Only{ .id = 0x0403 }).?);
    // TLS 1.3 binds the curve (RFC 8446 section 4.2.3): no such pair.
    try std.testing.expect(P.choose(p384, &.{}, Only{ .id = 0x0403 }) == null);
    try std.testing.expect(P.choose(p256, &.{}, Only{ .id = 0x0503 }) == null);
}

test "C2 a credential's own schemes restrict and reorder cloak's, and never add one" {
    const rsa = try key(pki.rsa);
    const p256 = try key(pki.p256);
    const All = struct {
        pub fn accepts(_: @This(), _: u16) bool {
            return true;
        }
    };
    const own = [_]Hello.SignatureScheme{ .rsa_pkcs1_sha256, .ecdsa_p256_sha256, .rsa_pss_rsae_sha512, .rsa_pss_rsae_sha384 };
    // TLS 1.3 never signs PKCS#1 v1.5, so the first of the list it can make; cloak's own order
    // would take SHA-256.
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha512, P.choose(rsa, &own, All{}).?);
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha256, P.choose(rsa, &.{}, All{}).?);
    // TLS 1.2 takes the list's first; a client's CertificateVerify hashes with SHA-256 or
    // SHA-384 only, so it passes over SHA-512.
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pkcs1_sha256, P.chooseServer12(rsa, &own, All{}).?);
    const pss = [_]Hello.SignatureScheme{ .rsa_pss_rsae_sha512, .rsa_pss_rsae_sha384 };
    try std.testing.expectEqual(Hello.SignatureScheme.rsa_pss_rsae_sha384, P.chooseClient12(rsa, &pss, All{}).?);
    // A list the key cannot make leaves it no scheme, as does one the peer does not take.
    try std.testing.expect(P.choose(p256, &.{ .rsa_pss_rsae_sha256, .ecdsa_p384_sha384 }, All{}) == null);
    try std.testing.expect(P.choose(rsa, &.{.rsa_pss_rsae_sha384}, Only{ .id = 0x0804 }) == null);
}

/// A peer listing one scheme.
const Only = struct {
    id: u16,
    pub fn accepts(self: @This(), scheme: u16) bool {
        return scheme == self.id;
    }
};
