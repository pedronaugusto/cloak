//! RSAES-OAEP against Wycheproof's rsa_oaep files (C2SP testvectors_v1, the commit
//! `fixtures/wycheproof/provenance.txt` names): every valid ciphertext decrypted to its message
//! by `PrivateKey.decrypt`, every invalid one refused with the one error, and every message
//! encrypted again by `encryption.encrypt` and decrypted back. Keys outside 2048 to 4096 bits
//! and SHA-224 are counted as not offered.
const std = @import("std");
const C = @import("../certificate.zig");
const encryption = @import("encryption.zig");
const PrivateKey = @import("../PrivateKey.zig");

const gpa = std.testing.allocator;

const Case = struct { tcId: u32, msg: []const u8, ct: []const u8, label: []const u8, result: []const u8 };
const Group = struct { keySize: u32, sha: []const u8, mgfSha: []const u8, privateKeyPkcs8: []const u8, tests: []const Case };
const File = struct { numberOfTests: u32, testGroups: []const Group };

fn hex(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try arena.alloc(u8, text.len / 2);
    _ = try std.fmt.hexToBytes(out, text);
    return out;
}

fn hashOf(name: []const u8) ?@FieldType(C.Algorithm.Oaep, "hash") {
    const names = .{ .{ "SHA-1", .sha1 }, .{ "SHA-256", .sha256 }, .{ "SHA-384", .sha384 }, .{ "SHA-512", .sha512 } };
    inline for (names) |pair| if (std.mem.eql(u8, name, pair[0])) return pair[1];
    return null;
}

/// Runs one file; returns how many cases ran.
fn campaign(comptime name: []const u8) !usize {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const file = try std.json.parseFromSliceLeaky(File, arena, @embedFile("fixtures/wycheproof/" ++ name), .{ .ignore_unknown_fields = true });
    var ran: usize = 0;
    var not_offered: usize = 0;
    for (file.testGroups) |g| {
        const hash = hashOf(g.sha);
        const mgf_hash = hashOf(g.mgfSha);
        const der = try hex(arena, g.privateKeyPkcs8);
        if (g.keySize < 2048 or g.keySize > 4096 or hash == null or mgf_hash == null) {
            // A key of another size is refused where it is read.
            if (g.keySize < 2048 or g.keySize > 4096) if (PrivateKey.parse(gpa, der, .{})) |key| {
                key.deinit();
                return error.TestUnexpectedResult;
            } else |_| {};
            not_offered += g.tests.len;
            continue;
        }
        const key = try PrivateKey.parse(gpa, der, .{});
        defer key.deinit();
        var info: [PrivateKey.max_public_key_info]u8 = undefined;
        const public = try C.parsePublicKey(key.publicKeyInfo(&info));
        var noise: [PrivateKey.max_noise]u8 = @splat(0x6e);
        for (g.tests) |t| {
            ran += 1;
            const scheme: C.Algorithm.Encryption = .{ .oaep = .{ .hash = hash.?, .mgf_hash = mgf_hash.?, .label = try hex(arena, t.label) } };
            const ct = try hex(arena, t.ct);
            const msg = try hex(arena, t.msg);
            var out: [PrivateKey.max_plaintext]u8 = undefined;
            const opened = key.decrypt(scheme, ct, noise[0..key.noiseLength()], &out);
            if (std.mem.eql(u8, t.result, "invalid")) {
                std.testing.expectError(error.DecryptionFailed, opened) catch |err| {
                    std.debug.print("{s} tcId {d} decrypted\n", .{ name, t.tcId });
                    return err;
                };
                continue;
            }
            // "acceptable": an encoding whose integer is small, which decrypts as any other.
            try std.testing.expectEqualSlices(u8, msg, try opened);
            var seed: [64]u8 = @splat(0x53);
            var sealed: [encryption.max_ciphertext]u8 = undefined;
            const again = try encryption.encrypt(public, scheme, msg, seed[0..encryption.seedLength(scheme)], &sealed);
            try std.testing.expectEqualSlices(u8, msg, try key.decrypt(scheme, again, noise[0..key.noiseLength()], &out));
        }
    }
    try std.testing.expectEqual(@as(usize, file.numberOfTests), ran + not_offered);
    return ran;
}

test "Wycheproof rsa_oaep: valid ciphertexts decrypt, invalid ones fail as one error, messages encrypt back" {
    var ran: usize = 0;
    inline for (.{
        "rsa_oaep_2048_sha1_mgf1sha1_test.json",
        "rsa_oaep_2048_sha256_mgf1sha1_test.json",
        "rsa_oaep_2048_sha256_mgf1sha256_test.json",
        "rsa_oaep_2048_sha384_mgf1sha384_test.json",
        "rsa_oaep_2048_sha512_mgf1sha512_test.json",
        "rsa_oaep_3072_sha256_mgf1sha256_test.json",
        "rsa_oaep_3072_sha512_mgf1sha512_test.json",
        "rsa_oaep_4096_sha256_mgf1sha256_test.json",
        "rsa_oaep_4096_sha512_mgf1sha512_test.json",
        "rsa_oaep_misc_test.json",
    }) |name| ran += try campaign(name);
    try std.testing.expect(ran > 400);
}

test "encryption refuses what is not an RSA encryption key, and messages longer than the key carries" {
    const key = try PrivateKey.parse(gpa, @embedFile("../crypto/testdata/rsa2048.der"), .{});
    defer key.deinit();
    var info: [PrivateKey.max_public_key_info]u8 = undefined;
    var public = try C.parsePublicKey(key.publicKeyInfo(&info));
    const scheme: C.Algorithm.Encryption = .{ .oaep = .{ .hash = .sha256, .mgf_hash = .sha256 } };
    var out: [encryption.max_ciphertext]u8 = undefined;
    const seed: [32]u8 = @splat(1);
    const longest: [256 - 66]u8 = @splat(7);
    _ = try encryption.encrypt(public, scheme, &longest, &seed, &out);
    try std.testing.expectError(error.MessageTooLong, encryption.encrypt(public, scheme, longest ++ "x", &seed, &out));
    try std.testing.expectError(error.InvalidSeed, encryption.encrypt(public, scheme, "m", seed[0..20], &out));
    public.rsa.pss_only = true;
    try std.testing.expectError(error.UnsupportedAlgorithm, encryption.encrypt(public, scheme, "m", &seed, &out));
    try std.testing.expectError(error.UnsupportedAlgorithm, encryption.encrypt(.{ .ed25519 = &@as([32]u8, @splat(9)) }, scheme, "m", &seed, &out));
    // A ciphertext of the wrong length, or at the modulus, is the same one failure.
    var noise: [PrivateKey.max_noise]u8 = @splat(0x6e);
    var plain: [PrivateKey.max_plaintext]u8 = undefined;
    try std.testing.expectError(error.DecryptionFailed, key.decrypt(scheme, out[0..255], noise[0..key.noiseLength()], &plain));
    try std.testing.expectError(error.DecryptionFailed, key.decrypt(scheme, public.rsa.modulus, noise[0..key.noiseLength()], &plain));
    const ed = try PrivateKey.parse(gpa, @embedFile("../credentials/testdata/ed25519.pkcs8.pem"), .{});
    defer ed.deinit();
    try std.testing.expectError(error.UnsupportedAlgorithm, ed.decrypt(scheme, out[0..256], "", &plain));
}
