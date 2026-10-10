//! Signing against std's independent implementations and RFC 8032; failure output never prints keys.
const std = @import("std");
const shakedown = @import("shakedown");
const Sign = @import("Sign.zig");

test "ecdsa signatures equal std's for the same key, message and noise" {
    try shakedown.check(std.testing.allocator, {}, ecdsaDifferential, .{ .cases = 64, .seed = 0x51a9e });
}

fn ecdsaDifferential(_: void, case: *shakedown.Case) !void {
    inline for (.{
        .{ Sign.P256, std.crypto.sign.ecdsa.EcdsaP256Sha256 },
        .{ Sign.P384, std.crypto.sign.ecdsa.EcdsaP384Sha384 },
    }) |pair| {
        const Ours, const Std = pair;
        var seed: [Std.KeyPair.seed_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        for (&seed) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var key = Std.KeyPair.generateDeterministic(seed) catch return;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        var message: [200]u8 = undefined;
        const length = shakedown.gen.int(case.source, u8) % message.len;
        for (message[0..length]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var noise: [Ours.noise_length]u8 = undefined;
        for (&noise) |*byte| byte.* = shakedown.gen.int(case.source, u8);
        var out: [Sign.max_signature]u8 = undefined;
        for ([_]?*const [Ours.noise_length]u8{ null, &noise }) |hedge| {
            const ours = try Ours.sign(&key.secret_key.bytes, message[0..length], hedge, &out);
            var expected_der: [Std.Signature.der_encoded_length_max]u8 = undefined;
            const expected = (try key.sign(message[0..length], if (hedge) |bytes| bytes.* else null)).toDer(&expected_der);
            try std.testing.expectEqualSlices(u8, expected, ours);
            const parsed = try Std.Signature.fromDer(ours);
            try parsed.verify(message[0..length], key.public_key);
        }
    }
}

test "ecdsa hedged signatures differ with the noise and both verify" {
    const Std = std.crypto.sign.ecdsa.EcdsaP256Sha256;
    var key = try Std.KeyPair.generateDeterministic(@splat(7));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    var first: [Sign.max_signature]u8 = undefined;
    var second: [Sign.max_signature]u8 = undefined;
    const a = try Sign.P256.sign(&key.secret_key.bytes, "hello", &@as([32]u8, @splat(1)), &first);
    const b = try Sign.P256.sign(&key.secret_key.bytes, "hello", &@as([32]u8, @splat(2)), &second);
    try std.testing.expect(!std.mem.eql(u8, a, b));
    try (try Std.Signature.fromDer(a)).verify("hello", key.public_key);
    try (try Std.Signature.fromDer(b)).verify("hello", key.public_key);
}

test "ecdsa rejects a secret scalar outside the group order" {
    var out: [Sign.max_signature]u8 = undefined;
    const too_big: [32]u8 = @splat(0xff);
    try std.testing.expectError(error.SigningFailed, Sign.P256.sign(&too_big, "x", null, &out));
    const zero: [48]u8 = @splat(0);
    try std.testing.expectError(error.SigningFailed, Sign.P384.sign(&zero, "x", null, &out));
}

const Vector = struct { seed: []const u8, message: []const u8, signature: []const u8 };

test "ed25519 matches the RFC 8032 vectors" {
    const vectors = [_]Vector{
        .{
            .seed = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            .message = "",
            .signature = "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        .{
            .seed = "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            .message = "72",
            .signature = "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        .{
            .seed = "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            .message = "af82",
            .signature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
    };
    for (vectors) |vector| {
        var key: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(key[0..32], vector.seed);
        const std_pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(key[0..32].*);
        key[32..64].* = std_pair.public_key.toBytes();
        var message: [8]u8 = undefined;
        const message_bytes = try std.fmt.hexToBytes(&message, vector.message);
        var expected: [64]u8 = undefined;
        _ = try std.fmt.hexToBytes(&expected, vector.signature);
        var out: [64]u8 = undefined;
        try Sign.ed25519.sign(&key, message_bytes, &out);
        try std.testing.expectEqualSlices(u8, &expected, &out);
    }
}

test "ed25519 signatures equal std's deterministic signatures and verify" {
    try shakedown.check(std.testing.allocator, {}, edDifferential, .{ .cases = 64, .seed = 0xed25519 });
}

fn edDifferential(_: void, case: *shakedown.Case) !void {
    const Std = std.crypto.sign.Ed25519;
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    for (&seed) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    var pair = try Std.KeyPair.generateDeterministic(seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
    var message: [200]u8 = undefined;
    const length = shakedown.gen.int(case.source, u8) % message.len;
    for (message[0..length]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    var out: [64]u8 = undefined;
    try Sign.ed25519.sign(&pair.secret_key.bytes, message[0..length], &out);
    const expected = try pair.sign(message[0..length], null);
    try std.testing.expectEqualSlices(u8, &expected.toBytes(), &out);
    try Std.Signature.fromBytes(out).verifyStrict(message[0..length], pair.public_key);
}

const Rsa = @import("Rsa.zig");
const Entropy = @import("Entropy.zig");
const signature = @import("../verify/signature.zig");
const certificate = @import("../certificate.zig");
const StdRsa = std.crypto.Certificate.rsa;
const sha2 = std.crypto.hash.sha2;

/// The OpenSSL keys of the private-operation tests: every modulus size the parser accepts has
/// the same shape, and 2056 bits is a width that is not a multiple of a limb.
const rsa_keys = .{ @embedFile("../crypto/testdata/rsa2048.der"), @embedFile("../crypto/testdata/rsa2056.der"), @embedFile("../crypto/testdata/rsa3072.der"), @embedFile("../crypto/testdata/rsa4096.der") };

fn rsaKey(der: []const u8) !Rsa.Key {
    return Rsa.parse(der, .{ .entropy = Entropy.fromIo(&std.testing.io) });
}

fn rsaPublic(key: *const Rsa.Key) StdRsa.PublicKey {
    return StdRsa.PublicKey.fromBytes(key.e[0..key.exponent_size], key.n[0..key.size]) catch unreachable;
}

fn noiseFrom(random: std.Random) [Sign.rsa.noise_length]u8 {
    var noise: [Sign.rsa.noise_length]u8 = undefined;
    random.bytes(&noise);
    return noise;
}

test "rsa pss signatures verify under std's and cloak's verifiers for every key size and hash" {
    var prng: std.Random.DefaultPrng = .init(0x9055);
    const random = prng.random();
    inline for (rsa_keys) |der| {
        var key = try rsaKey(der);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        const public: @FieldType(certificate.PublicKey, "rsa") = .{ .modulus = key.n[0..key.size], .exponent = key.e[0..key.exponent_size] };
        inline for (.{ .{ sha2.Sha256, .sha256 }, .{ sha2.Sha384, .sha384 }, .{ sha2.Sha512, .sha512 } }) |pair| {
            const Hash, const name = pair;
            var message: [100]u8 = undefined;
            random.bytes(&message);
            const noise = noiseFrom(random);
            var out: [Sign.max_signature]u8 = undefined;
            const made = try Sign.rsa.pss(Hash, &key.crt, &message, &noise, &out);
            try std.testing.expectEqual(key.size, made.len);
            try signature.verify(.{ .rsa = public }, .{ .pss = .{ .hash = name, .mgf_hash = name, .salt_length = Hash.digest_length } }, &message, made);
            try stdVerify(StdRsa.PSSSignature, Hash, &key, &message, made);
            // A different message does not verify.
            try std.testing.expectError(error.InvalidSignature, signature.verify(.{ .rsa = public }, .{ .pss = .{ .hash = name, .mgf_hash = name, .salt_length = Hash.digest_length } }, "other", made));
        }
    }
}

/// std's verification takes the modulus length at compile time: dispatch on the four sizes.
fn stdVerify(comptime Scheme: type, comptime Hash: type, key: *const Rsa.Key, message: []const u8, made: []const u8) !void {
    inline for (.{ 256, 257, 384, 512 }) |len| if (made.len == len) {
        return Scheme.verify(len, made[0..len], message, rsaPublic(key), Hash);
    };
    return error.TestUnexpectedResult;
}

test "rsa pkcs1 signatures equal OpenSSL's known answers and std's encoding" {
    const message = "cloak rsa known answer";
    const answers = .{
        .{ rsa_keys[1], sha2.Sha256, @embedFile("../crypto/testdata/rsa2056-pkcs1-sha256.sig") },
        .{ rsa_keys[2], sha2.Sha384, @embedFile("../crypto/testdata/rsa3072-pkcs1-sha384.sig") },
        .{ rsa_keys[3], sha2.Sha512, @embedFile("../crypto/testdata/rsa4096-pkcs1-sha512.sig") },
    };
    var prng: std.Random.DefaultPrng = .init(0x9c51);
    inline for (answers) |answer| {
        const der, const Hash, const expected = answer;
        var key = try rsaKey(der);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        var out: [Sign.max_signature]u8 = undefined;
        const noise = noiseFrom(prng.random());
        try std.testing.expectEqualSlices(u8, expected, try Sign.rsa.pkcs1(Hash, &key.crt, message, &noise, &out));
    }
    // Every size and hash: std re-encodes EMSA-PKCS1-v1_5 and compares it whole, so passing is
    // equality with the one valid signature.
    inline for (rsa_keys) |der| {
        var key = try rsaKey(der);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
        inline for (.{ sha2.Sha256, sha2.Sha384, sha2.Sha512 }) |Hash| {
            var out: [Sign.max_signature]u8 = undefined;
            const noise = noiseFrom(prng.random());
            try stdVerify(StdRsa.PKCS1v1_5Signature, Hash, &key, message, try Sign.rsa.pkcs1(Hash, &key.crt, message, &noise, &out));
        }
    }
}

test "rsa pkcs1 equals the TLS fixture signature made by OpenSSL" {
    const pem = @embedFile("../testing/pki/rsa.key.pem");
    var reader = @import("Pem.zig").init(pem);
    var block = (try reader.next(std.testing.allocator, 65536)).?;
    defer block.deinit(std.testing.allocator);
    // The fixture is PKCS#8: the RSAPrivateKey is the OCTET STRING after the algorithm.
    const Der = @import("../wire/Der.zig");
    var r = (try Der.single(block.der, 0x30)).reader();
    _ = try r.expect(2);
    _ = try r.expect(0x30);
    var key = try rsaKey((try r.expect(4)).value);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    var out: [Sign.max_signature]u8 = undefined;
    const made = try Sign.rsa.pkcs1(sha2.Sha256, &key.crt, "cloak possession test content", &@as([Sign.rsa.noise_length]u8, @splat(3)), &out);
    try std.testing.expectEqualSlices(u8, @embedFile("../testing/pki/rsa-pkcs1-sha256.sig"), made);
}

test "rsa blinding never changes a signature: the seed is invisible, the salt is not" {
    var key = try rsaKey(rsa_keys[0]);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&key));
    var noise: [Sign.rsa.noise_length]u8 = @splat(0x11);
    var pss_first: [Sign.max_signature]u8 = undefined;
    var pkcs_first: [Sign.max_signature]u8 = undefined;
    var again: [Sign.max_signature]u8 = undefined;
    const pss = try Sign.rsa.pss(sha2.Sha256, &key.crt, "message", &noise, &pss_first);
    const pkcs = try Sign.rsa.pkcs1(sha2.Sha256, &key.crt, "message", &noise, &pkcs_first);
    for (1..6) |i| {
        // Another blinding seed, the same salt.
        @memset(noise[0..Sign.rsa.seed_length], @intCast(i));
        try std.testing.expectEqualSlices(u8, pss, try Sign.rsa.pss(sha2.Sha256, &key.crt, "message", &noise, &again));
        try std.testing.expectEqualSlices(u8, pkcs, try Sign.rsa.pkcs1(sha2.Sha256, &key.crt, "message", &noise, &again));
    }
    // Another salt: another PSS signature, still valid.
    noise[Sign.rsa.seed_length] ^= 1;
    const other = try Sign.rsa.pss(sha2.Sha256, &key.crt, "message", &noise, &again);
    try std.testing.expect(!std.mem.eql(u8, pss, other));
    try stdVerify(StdRsa.PSSSignature, sha2.Sha256, &key, "message", other);
}

test "rsa keys with a factor the private operation cannot hold are refused by type" {
    // A valid key whose larger factor has 2112 bits: more than half of the largest modulus.
    try std.testing.expectError(error.UnsupportedKey, rsaKey(@embedFile("../crypto/testdata/rsa-unbalanced.der")));
}
