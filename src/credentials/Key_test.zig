const std = @import("std");
const shakedown = @import("shakedown");
const PrivateKey = @import("../PrivateKey.zig");
const Pem = @import("Pem.zig");
test "credential key formats match modern certificate public keys" {
    @setRuntimeSafety(true);
    const Case = struct { key: []const u8, cert: []const u8, passphrase: ?[]const u8 = null };
    const cases = [_]Case{
        .{ .key = @embedFile("testdata/rsa.pkcs8.pem"), .cert = @embedFile("testdata/rsa.cert.pem") },
        .{ .key = @embedFile("testdata/rsa.pkcs1.pem"), .cert = @embedFile("testdata/rsa.cert.pem") },
        .{ .key = @embedFile("testdata/rsa.enc-aes256-sha256.pem"), .cert = @embedFile("testdata/rsa.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/rsa.legacy-aes256.pem"), .cert = @embedFile("testdata/rsa.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p256.pkcs8.pem"), .cert = @embedFile("testdata/p256.cert.pem") },
        .{ .key = @embedFile("testdata/p256.sec1.pem"), .cert = @embedFile("testdata/p256.cert.pem") },
        .{ .key = @embedFile("testdata/p256.pkcs8.der"), .cert = @embedFile("testdata/p256.cert.der") },
        .{ .key = @embedFile("testdata/p256.enc-aes128-sha1.pem"), .cert = @embedFile("testdata/p256.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p256.legacy-aes128.pem"), .cert = @embedFile("testdata/p256.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p384.pkcs8.pem"), .cert = @embedFile("testdata/p384.cert.pem") },
        .{ .key = @embedFile("testdata/p384.enc-des3.pem"), .cert = @embedFile("testdata/p384.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/rsa.legacy-des3.pem"), .cert = @embedFile("testdata/rsa.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/p384.enc-aes192.pem"), .cert = @embedFile("testdata/p384.cert.pem"), .passphrase = "correct-horse" },
        .{ .key = @embedFile("testdata/ed25519.pkcs8.pem"), .cert = @embedFile("testdata/ed25519.cert.pem") },
        .{ .key = @embedFile("testdata/ed25519.enc-aes256-sha512.pem"), .cert = @embedFile("testdata/ed25519.cert.pem"), .passphrase = "correct-horse" },
    };
    for (cases) |case| {
        const key = try PrivateKey.parse(std.testing.allocator, case.key, .{ .passphrase = case.passphrase });
        defer key.deinit();
        var cert_pem = Pem.init(case.cert);
        var block: ?Pem.Block = if (std.mem.startsWith(u8, case.cert, "-----")) (try cert_pem.next(std.testing.allocator, 65536)).? else null;
        defer if (block) |*b| b.deinit(std.testing.allocator);
        try std.testing.expect(key.matches(if (block) |b| b.der else case.cert));
        try std.testing.expectEqual(case.passphrase != null, PrivateKey.isEncrypted(case.key));
    }
}
test "F06 catalogue_key_import_failure_and_kdf_budget (input and KDF bounds precede allocation and expensive work)" {
    @setRuntimeSafety(true);
    try rejectKey(error.InputLimit, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/rsa.pkcs1.pem"), .{ .bytes = 8 }));
    try rejectKey(error.KdfLimit, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/p256.enc-aes128-sha1.pem"), .{ .passphrase = "correct-horse", .iterations = 1 }));
    try rejectKey(error.PasswordRequired, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/p256.enc-aes128-sha1.pem"), .{}));
    try rejectKey(error.BadPassword, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/p256.enc-aes128-sha1.pem"), .{ .passphrase = "wrong" }));
}
test "F06 catalogue_key_import_failure_and_kdf_budget (final ownership survives the original owner's release and allocation faults)" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), allocation, .{});
}
fn allocation(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    const held = key.retain();
    key.deinit();
    held.deinit();
}

test "credential PEM complete input and declared key format are strict" {
    @setRuntimeSafety(true);
    const pem = @embedFile("testdata/ed25519.pkcs8.pem");
    try rejectKey(error.InvalidKey, PrivateKey.parse(std.testing.allocator, pem ++ pem, .{}));
    try rejectKey(error.InvalidPem, PrivateKey.parse(std.testing.allocator, pem ++ "junk", .{}));
    const rsa_label = "-----BEGIN RSA PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n-----END RSA PRIVATE KEY-----";
    try rejectKey(error.InvalidKey, PrivateKey.parse(std.testing.allocator, rsa_label, .{}));
}

test "credential PEM key after the attributes a PKCS #12 export writes" {
    @setRuntimeSafety(true);
    const key = try PrivateKey.parse(std.testing.allocator, "Bag Attributes\n    localKeyID: 01\nKey Attributes: <No Attributes>\n" ++ @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer key.deinit();
    try std.testing.expectEqual(@as(?usize, 0), key.noiseLength());
}

// The unencrypted RFC 8410 seed is a public dummy fixture, not a deployed key.
test "credential PKCS8 attributes require Attribute grammar and implicit SET order" {
    @setRuntimeSafety(true);
    var pem = Pem.init(@embedFile("testdata/ed25519.pkcs8.pem"));
    var block = (try pem.next(std.testing.allocator, 65536)).?;
    defer block.deinit(std.testing.allocator);
    const invalid = [_][]const u8{
        "\xa0\x02\x05\x00",
        "\xa0\x08\x30\x06\x06\x02\x2a\x03\x05\x00",
        "\xa0\x08\x30\x06\x06\x02\x2a\x03\x31\x00",
        "\xa0\x16\x30\x09\x06\x02\x2a\x04\x31\x03\x0c\x01b\x30\x09\x06\x02\x2a\x03\x31\x03\x0c\x01a",
    };
    for (invalid) |attributes| {
        const encoded = try std.testing.allocator.alloc(u8, block.der.len + attributes.len);
        defer std.testing.allocator.free(encoded);
        @memcpy(encoded[0..block.der.len], block.der);
        @memcpy(encoded[block.der.len..], attributes);
        encoded[1] += @intCast(attributes.len); // safe: this fixed dummy sequence and each short attribute fit one DER length octet
        try rejectKey(error.InvalidKey, PrivateKey.parse(std.testing.allocator, encoded, .{}));
    }
}

fn rejectKey(expected: anyerror, result: anyerror!PrivateKey) !void {
    @setRuntimeSafety(true);
    if (result) |unexpected| {
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(expected, err);
}

test "credential RSA keys sign PSS and PKCS#1 v1.5 for every hash, from a message or its digest" {
    @setRuntimeSafety(true);
    const signature = @import("../verify/signature.zig");
    const certificate = @import("../certificate.zig");
    const gpa = std.testing.allocator;
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/rsa.pkcs1.pem"), .{});
    defer key.deinit();
    var cert_pem = Pem.init(@embedFile("testdata/rsa.cert.pem"));
    var block = (try cert_pem.next(gpa, 65536)).?;
    defer block.deinit(gpa);
    const leaf = try certificate.parse(block.der, .{});
    try std.testing.expectEqual(@as(usize, 96), key.noiseLength());
    const noise: [PrivateKey.max_noise + 1]u8 = @splat(0x6b);
    var out: [PrivateKey.max_signature]u8 = undefined;
    inline for (.{ .{ certificate.Algorithm.Hash.sha256, std.crypto.hash.sha2.Sha256 }, .{ .sha384, std.crypto.hash.sha2.Sha384 }, .{ .sha512, std.crypto.hash.sha2.Sha512 } }) |pair| {
        const hash, const Hash = pair;
        var digest: [Hash.digest_length]u8 = undefined;
        Hash.hash("content", &digest, .{});
        const algorithms = [_]certificate.Algorithm.Signature{ .{ .pss = .{ .hash = hash, .mgf_hash = hash, .salt_length = Hash.digest_length } }, .{ .rsa = hash } };
        for (algorithms) |algorithm| {
            const made = try key.sign(algorithm, "content", noise[0..96], &out);
            try signature.verify(leaf.public_key, algorithm, "content", made);
            var again: [PrivateKey.max_signature]u8 = undefined;
            // The digest form signs the same message: equal for PKCS#1 v1.5 and for PSS with one salt.
            try std.testing.expectEqualSlices(u8, made, try key.signDigest(algorithm, &digest, noise[0..96], &again));
            try std.testing.expectError(error.InvalidDigest, key.signDigest(algorithm, digest[1..], noise[0..96], &again));
            try std.testing.expectError(error.InvalidNoise, key.sign(algorithm, "content", noise[0..95], &out));
            try std.testing.expectError(error.InvalidNoise, key.sign(algorithm, "content", noise[0..97], &out));
            try std.testing.expectError(error.InvalidNoise, key.signDigest(algorithm, &digest, noise[0..32], &out));
        }
        // PSS other than TLS's: another MGF hash, another salt length.
        const other: certificate.Algorithm.Hash = if (hash == .sha256) .sha384 else .sha256;
        try std.testing.expectError(error.UnsupportedAlgorithm, key.sign(.{ .pss = .{ .hash = hash, .mgf_hash = other, .salt_length = Hash.digest_length } }, "content", noise[0..96], &out));
        try std.testing.expectError(error.UnsupportedAlgorithm, key.sign(.{ .pss = .{ .hash = hash, .mgf_hash = hash, .salt_length = 20 } }, "content", noise[0..96], &out));
    }
    try std.testing.expectError(error.UnsupportedAlgorithm, key.sign(.{ .ecdsa = .sha256 }, "content", noise[0..96], &out));
    try std.testing.expectError(error.UnsupportedAlgorithm, key.sign(.ed25519, "content", noise[0..96], &out));
    // The digest form is RSA's alone until ECDSA gains one; Ed25519 never has it.
    const ed = try PrivateKey.parse(gpa, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer ed.deinit();
    try std.testing.expectError(error.UnsupportedAlgorithm, ed.signDigest(.ed25519, &@as([64]u8, @splat(0)), "", &out));
}

test "F142 catalogue_tls12_ecdsa_scheme_names_hash_not_curve (ECDSA keys sign as DER or as r || s (P1363), each verified in its own form only, under every hash on either curve)" {
    @setRuntimeSafety(true);
    const signature = @import("../verify/signature.zig");
    const certificate = @import("../certificate.zig");
    const gpa = std.testing.allocator;
    inline for (.{ .{ "testdata/p256.pkcs8.pem", certificate.Algorithm.Hash.sha256, certificate.Algorithm.Curve.p256, 32 }, .{ "testdata/p384.pkcs8.pem", .sha384, .p384, 48 }, .{ "testdata/p521.pkcs8.pem", .sha512, .p521, 66 } }) |row| {
        const file, const hash, const curve, const width = row;
        const key = try PrivateKey.parse(gpa, @embedFile(file), .{});
        defer key.deinit();
        const pair = key.state.material.expose().*;
        const encoded: []const u8 = switch (pair) {
            inline .p256, .p384, .p521 => |*p| p.public[0..],
            else => unreachable,
        };
        const public: certificate.Algorithm.PublicKey = .{ .ec = .{ .curve = curve, .bytes = encoded } };
        const noise: [PrivateKey.max_noise]u8 = @splat(0x5a);
        var der: [PrivateKey.max_signature]u8 = undefined;
        var fixed: [PrivateKey.max_signature]u8 = undefined;
        const made_der = try key.sign(.{ .ecdsa = hash }, "content", noise[0..key.noiseLength()], &der);
        const made_fixed = try key.sign(.{ .ecdsa_p1363 = hash }, "content", noise[0..key.noiseLength()], &fixed);
        try std.testing.expectEqual(@as(usize, 2 * width), made_fixed.len);
        try signature.verify(public, .{ .ecdsa = hash }, "content", made_der);
        try signature.verify(public, .{ .ecdsa_p1363 = hash }, "content", made_fixed);
        // One signature, one encoding: neither form is read as the other.
        try std.testing.expectError(error.InvalidSignature, signature.verify(public, .{ .ecdsa_p1363 = hash }, "content", made_der));
        try std.testing.expectError(error.InvalidSignature, signature.verify(public, .{ .ecdsa = hash }, "content", made_fixed));
        try std.testing.expectError(error.InvalidSignature, signature.verify(public, .{ .ecdsa_p1363 = hash }, "other", made_fixed));
        try std.testing.expectError(error.InvalidSignature, signature.verify(public, .{ .ecdsa_p1363 = hash }, "content", made_fixed[0 .. made_fixed.len - 1]));
        // The same nonce draw gives the same r and s in both forms.
        var digest_out: [PrivateKey.max_signature]u8 = undefined;
        const Own = switch (@as(certificate.Algorithm.Hash, hash)) {
            .sha256 => std.crypto.hash.sha2.Sha256,
            .sha384 => std.crypto.hash.sha2.Sha384,
            .sha512 => std.crypto.hash.sha2.Sha512,
        };
        var digest: [Own.digest_length]u8 = undefined;
        Own.hash("content", &digest, .{});
        try std.testing.expectEqualSlices(u8, made_fixed, try key.signDigest(.{ .ecdsa_p1363 = hash }, &digest, noise[0..key.noiseLength()], &digest_out));
        // F142: every hash on either curve, from the message or its digest, as RFC 6979's
        // bits2int takes a hash not the curve's own; the verifier, which already took them,
        // accepts each, and a digest of another length is InvalidDigest.
        inline for (comptime std.enums.values(certificate.Algorithm.Hash)) |other| {
            const Hash = switch (other) {
                .sha256 => std.crypto.hash.sha2.Sha256,
                .sha384 => std.crypto.hash.sha2.Sha384,
                .sha512 => std.crypto.hash.sha2.Sha512,
            };
            inline for (.{ certificate.Algorithm.Signature{ .ecdsa = other }, certificate.Algorithm.Signature{ .ecdsa_p1363 = other } }) |algorithm| {
                const made = try key.sign(algorithm, "content", noise[0..key.noiseLength()], &der);
                try signature.verify(public, algorithm, "content", made);
                try std.testing.expectError(error.InvalidSignature, signature.verify(public, algorithm, "other", made));
                var other_digest: [Hash.digest_length]u8 = undefined;
                Hash.hash("content", &other_digest, .{});
                try std.testing.expectEqualSlices(u8, made, try key.signDigest(algorithm, &other_digest, noise[0..key.noiseLength()], &digest_out));
                try std.testing.expectError(error.InvalidDigest, key.signDigest(algorithm, other_digest[1..], noise[0..key.noiseLength()], &digest_out));
            }
        }
    }
}

/// The DER of a PEM file's first block, owned by the caller.
fn pemDer(text: []const u8) !Pem.Block {
    var pem = Pem.init(text);
    return (try pem.next(std.testing.allocator, 65536)).?;
}

fn certKey(text: []const u8) !@import("../certificate.zig").PublicKey {
    var block = try pemDer(text);
    defer block.deinit(std.testing.allocator);
    // The parsed key borrows the DER: keep a copy alive for the test's length.
    const der = try std.testing.allocator.dupe(u8, block.der);
    kept_ders.append(std.testing.allocator, der) catch unreachable; // unreachable: tests allocate little
    return (try @import("../certificate.zig").parse(der, .{})).public_key;
}
var kept_ders: std.ArrayList([]u8) = .empty;
fn freeKept() void {
    for (kept_ders.items) |der| std.testing.allocator.free(der);
    kept_ders.deinit(std.testing.allocator);
    kept_ders = .empty;
}

test "C10 private keys from their components: the same key as parsed, and every check a parse makes" {
    @setRuntimeSafety(true);
    const gpa = std.testing.allocator;
    const Der = @import("../wire/Der.zig");
    defer freeKept();
    // RSA: the eight numbers of an RSAPrivateKey, as a JWK carries them.
    var rsa_block = try pemDer(@embedFile("testdata/rsa.pkcs1.pem"));
    defer rsa_block.deinit(gpa);
    var r = (try Der.single(rsa_block.der, 0x30)).reader();
    _ = try r.expect(2);
    var numbers: [8][]const u8 = undefined;
    for (&numbers) |*n| n.* = try Der.integer((try r.expect(2)).value);
    const rsa = try PrivateKey.fromComponents(gpa, .{ .rsa = .{ .n = numbers[0], .e = numbers[1], .d = numbers[2], .p = numbers[3], .q = numbers[4], .dp = numbers[5], .dq = numbers[6], .qi = numbers[7] } });
    defer rsa.deinit();
    try std.testing.expect(rsa.matchesKey(try certKey(@embedFile("testdata/rsa.cert.pem"))));
    const parsed = try PrivateKey.parse(gpa, @embedFile("testdata/rsa.pkcs1.pem"), .{});
    defer parsed.deinit();
    var noise: [PrivateKey.max_noise]u8 = @splat(7);
    var a: [PrivateKey.max_signature]u8 = undefined;
    var b: [PrivateKey.max_signature]u8 = undefined;
    // PKCS#1 v1.5 is deterministic: the same key signs the same bytes.
    try std.testing.expectEqualSlices(u8, try parsed.sign(.{ .rsa = .sha256 }, "jwk", noise[0..parsed.noiseLength()], &a), try rsa.sign(.{ .rsa = .sha256 }, "jwk", noise[0..rsa.noiseLength()], &b));
    // Numbers that disagree, a leading zero, a missing one: refused as a parse refuses them.
    var dq = try gpa.dupe(u8, numbers[6]);
    defer gpa.free(dq);
    dq[dq.len - 1] ^= 2;
    const zero_led = try std.mem.concat(gpa, u8, &.{ "\x00", numbers[1] });
    defer gpa.free(zero_led);
    for ([_][8][]const u8{
        .{ numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5], dq, numbers[7] },
        .{ numbers[0], zero_led, numbers[2], numbers[3], numbers[4], numbers[5], numbers[6], numbers[7] },
        .{ numbers[0], numbers[1], numbers[2], numbers[4], numbers[3], numbers[5], numbers[6], numbers[7] },
        .{ numbers[0], numbers[1], numbers[2], numbers[3], numbers[4], numbers[5], numbers[6], "" },
    }) |bad| try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .rsa = .{ .n = bad[0], .e = bad[1], .d = bad[2], .p = bad[3], .q = bad[4], .dp = bad[5], .dq = bad[6], .qi = bad[7] } }));
    // EC: the scalar and the public point of an ECPrivateKey.
    var ec_block = try pemDer(@embedFile("testdata/p256.sec1.pem"));
    defer ec_block.deinit(gpa);
    var e = (try Der.single(ec_block.der, 0x30)).reader();
    _ = try e.expect(2);
    const d = (try e.expect(4)).value;
    _ = try e.expect(0xa0);
    const point = try Der.octetBits((try Der.single((try e.expect(0xa1)).value, 3)).value);
    const p256_cert = try certKey(@embedFile("testdata/p256.cert.pem"));
    for ([_]?[]const u8{ null, point }) |public| {
        const ec = try PrivateKey.fromComponents(gpa, .{ .ec = .{ .curve = .p256, .d = d, .public = public } });
        defer ec.deinit();
        try std.testing.expect(ec.matchesKey(p256_cert));
    }
    var other_point = try gpa.dupe(u8, point);
    defer gpa.free(other_point);
    other_point[64] ^= 1;
    const order = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51 };
    for ([_]struct { d: []const u8, public: ?[]const u8 = null }{
        .{ .d = d, .public = other_point },
        .{ .d = &@as([32]u8, @splat(0)) },
        .{ .d = &order },
        .{ .d = d[1..] },
        .{ .d = &(@as([1]u8, .{0}) ++ @as([32]u8, @splat(1))) },
    }) |bad| try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .ec = .{ .curve = .p256, .d = bad.d, .public = bad.public } }));
    // A P-256 scalar is not a P-384 key.
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .ec = .{ .curve = .p384, .d = d } }));
    // Ed25519: the seed (a JWK's d) and the public key (its x).
    var ed_block = try pemDer(@embedFile("testdata/ed25519.pkcs8.pem"));
    defer ed_block.deinit(gpa);
    const seed = ed_block.der[ed_block.der.len - 32 ..];
    const ed_cert = try certKey(@embedFile("testdata/ed25519.cert.pem"));
    const ed = try PrivateKey.fromComponents(gpa, .{ .ed25519 = .{ .seed = seed, .public = ed_cert.ed25519 } });
    defer ed.deinit();
    try std.testing.expect(ed.matchesKey(ed_cert));
    var other_x: [32]u8 = ed_cert.ed25519[0..32].*;
    other_x[0] ^= 1;
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .ed25519 = .{ .seed = seed, .public = &other_x } }));
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .ed25519 = .{ .seed = seed[1..] } }));
}

test "P-521 private keys: SEC 1 and PKCS#8 read to one key, its SubjectPublicKeyInfo OpenSSL's, its components checked" {
    @setRuntimeSafety(true);
    const certificate = @import("../certificate.zig");
    const Der = @import("../wire/Der.zig");
    const gpa = std.testing.allocator;
    const pkcs8 = try PrivateKey.parse(gpa, @embedFile("testdata/p521.pkcs8.pem"), .{});
    defer pkcs8.deinit();
    const sec1 = try PrivateKey.parse(gpa, @embedFile("testdata/p521.sec1.pem"), .{});
    defer sec1.deinit();
    var out: [PrivateKey.max_public_key_info]u8 = undefined;
    const spki = pkcs8.publicKeyInfo(&out);
    try std.testing.expectEqualSlices(u8, @embedFile("testdata/p521.pub.der"), spki);
    const public = try certificate.Algorithm.publicKey(spki);
    try std.testing.expect(sec1.matchesKey(public));
    // The components: d and the point, from the SEC 1 form.
    var block = try pemDer(@embedFile("testdata/p521.sec1.pem"));
    defer block.deinit(gpa);
    var e = (try Der.single(block.der, 0x30)).reader();
    _ = try e.expect(2);
    const d = (try e.expect(4)).value;
    try std.testing.expectEqual(@as(usize, 66), d.len);
    _ = try e.expect(0xa0);
    const point = try Der.octetBits((try Der.single((try e.expect(0xa1)).value, 3)).value);
    for ([_]?[]const u8{ null, point }) |given| {
        const key = try PrivateKey.fromComponents(gpa, .{ .ec = .{ .curve = .p521, .d = d, .public = given } });
        defer key.deinit();
        try std.testing.expect(key.matchesKey(public));
    }
    var other_point = try gpa.dupe(u8, point);
    defer gpa.free(other_point);
    other_point[132] ^= 1;
    var order: [66]u8 = undefined;
    std.mem.writeInt(u528, &order, @import("../crypto/p521.zig").order, .big);
    for ([_]struct { d: []const u8, public: ?[]const u8 = null }{
        .{ .d = d, .public = other_point },
        .{ .d = &@as([66]u8, @splat(0)) },
        .{ .d = &order },
        .{ .d = &@as([66]u8, @splat(0xff)) },
        .{ .d = d[1..] },
        .{ .d = &(@as([1]u8, .{0}) ++ @as([66]u8, @splat(1))) },
    }) |bad| try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .ec = .{ .curve = .p521, .d = bad.d, .public = bad.public } }));
    // A P-521 scalar is not a P-384 key.
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .ec = .{ .curve = .p384, .d = d } }));
}

test "C10 a private key writes its public half as the SubjectPublicKeyInfo its certificate carries" {
    const certificate = @import("../certificate.zig");
    const pki = @import("../testing/Peer.zig").pki;
    const gpa = std.testing.allocator;
    const Case = struct { cert: []const u8, pem: []const u8 };
    // OpenSSL made each certificate: RSA (a modulus with its high bit set, so a leading zero),
    // both curves, Ed25519 and the three ML-DSA sets.
    for ([_]Case{
        .{ .cert = pki.rsa, .pem = pki.rsa_pem },
        .{ .cert = pki.p256, .pem = pki.p256_pem },
        .{ .cert = pki.p384, .pem = pki.p384_pem },
        .{ .cert = pki.ed25519, .pem = pki.ed25519_pem },
        .{ .cert = pki.mldsa44, .pem = pki.mldsa44_pem },
        .{ .cert = pki.mldsa65, .pem = pki.mldsa65_pem },
        .{ .cert = pki.mldsa87, .pem = pki.mldsa87_pem },
    }) |case| {
        const key = try PrivateKey.parse(gpa, case.pem, .{});
        defer key.deinit();
        var out: [PrivateKey.max_public_key_info]u8 = undefined;
        const spki = key.publicKeyInfo(&out);
        try std.testing.expectEqualSlices(u8, (try certificate.parse(case.cert, .{})).spki, spki);
        try std.testing.expect(key.matchesKey(try certificate.Algorithm.publicKey(spki)));
    }
    // ML-DSA-87's is the longest.
    const key = try PrivateKey.parse(gpa, pki.mldsa87_pem, .{});
    defer key.deinit();
    var out: [PrivateKey.max_public_key_info]u8 = undefined;
    try std.testing.expectEqual(out.len, key.publicKeyInfo(&out).len);
    // A key restricted to RSASSA-PSS carries its parameters in its certificate: not written.
    const rsa = try certificate.Algorithm.publicKey((try certificate.parse(pki.rsa, .{})).spki);
    try std.testing.expectError(error.UnsupportedAlgorithm, certificate.Algorithm.encodePublicKey(.{ .rsa = .{ .modulus = rsa.rsa.modulus, .exponent = rsa.rsa.exponent, .pss_only = true } }, &out));
}
