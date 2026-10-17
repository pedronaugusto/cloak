//! ROCA (CVE-2017-15361) at every place cloak takes an RSA key: a certificate, a raw key, a key a
//! caller builds for `signature.verify`, and a private key, parsed or from its numbers. The keys
//! are the published detector's (crypto/testdata/roca, provenance.md).
const std = @import("std");
const certificate = @import("certificate.zig");
const signature = @import("verify/signature.zig");
const PrivateKey = @import("PrivateKey.zig");
const Pem = @import("credentials/Pem.zig");
const gpa = std.testing.allocator;

fn der(text: []const u8) !Pem.Block {
    var pem = Pem.init(text);
    return (try pem.next(gpa, 65536)).?;
}

test "F94 catalogue_roca_fingerprinted_rsa_key_refused" {
    // Certificates whose key has the fingerprint (2050 and 2049 bits) are refused at parse;
    // the detector's negatives parse.
    for ([_][]const u8{ @embedFile("crypto/testdata/roca/cert04.pem"), @embedFile("crypto/testdata/roca/cert05.pem") }) |text| {
        var block = try der(text);
        defer block.deinit(gpa);
        try std.testing.expectError(error.InvalidPublicKey, certificate.parse(block.der, .{}));
    }
    for ([_][]const u8{ @embedFile("crypto/testdata/roca/cert01.pem"), @embedFile("crypto/testdata/roca/cert06.pem") }) |text| {
        var block = try der(text);
        defer block.deinit(gpa);
        _ = try certificate.parse(block.der, .{});
    }
    // A SubjectPublicKeyInfo alone (a raw public key) the same.
    {
        var block = try der(@embedFile("crypto/testdata/roca/pubkey03.pem"));
        defer block.deinit(gpa);
        try std.testing.expectError(error.InvalidPublicKey, certificate.Algorithm.publicKey(block.der));
        var good = try der(@embedFile("crypto/testdata/roca/pubkey01.pem"));
        defer good.deinit(gpa);
        _ = try certificate.Algorithm.publicKey(good.der);
    }
    // A key a caller builds from its numbers (a JWK's n and e) verifies nothing: the check is in
    // the verifier, not only the parsers. Its modulus is pubkey03's.
    {
        var block = try der(@embedFile("crypto/testdata/roca/pubkey03.pem"));
        defer block.deinit(gpa);
        const Der = @import("wire/Der.zig");
        var outer = (try Der.single(block.der, 0x30)).reader();
        _ = try outer.expect(0x30);
        const bits = try Der.octetBits((try outer.expect(3)).value);
        var numbers = (try Der.single(bits, 0x30)).reader();
        const n = try Der.integer((try numbers.expect(2)).value);
        const e = try Der.integer((try numbers.expect(2)).value);
        const built: certificate.PublicKey = .{ .rsa = .{ .modulus = n, .exponent = e } };
        var sig: [257]u8 = @splat(1);
        try std.testing.expectError(error.InvalidPublicKey, signature.verify(built, .{ .rsa = .sha256 }, "message", sig[0..n.len]));
    }
    // Its private keys are refused too: whoever holds one is not alone.
    try std.testing.expectError(error.InvalidKey, PrivateKey.parse(gpa, @embedFile("crypto/testdata/roca/privkey05.pem"), .{}));
    const fine = try PrivateKey.parse(gpa, @embedFile("crypto/testdata/roca/privkey03.pem"), .{});
    fine.deinit();
}
