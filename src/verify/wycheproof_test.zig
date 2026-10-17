const std = @import("std");
const C = @import("../certificate.zig");
const S = @import("signature.zig");
const PrivateKey = @import("../PrivateKey.zig");
const Test = struct { tcId: usize, flags: []const []const u8, msg: []const u8, sig: []const u8, result: []const u8 };
const Group = struct { publicKeyDer: []const u8, tests: []Test };
fn hex(gpa: std.mem.Allocator, value: []const u8) ![]const u8 {
    const bytes = try gpa.alloc(u8, value.len / 2);
    _ = try std.fmt.hexToBytes(bytes, value);
    return bytes;
}
fn campaign(comptime file: []const u8, algorithm: C.Algorithm.Signature) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const parsed = try std.json.parseFromSlice(struct { numberOfTests: usize, testGroups: []Group }, gpa, @embedFile("fixtures/wycheproof/" ++ file), .{ .ignore_unknown_fields = true });
    var passed: usize = 0;
    var mismatch: usize = 0;
    for (parsed.value.testGroups) |group| {
        const key_der = try hex(gpa, group.publicKeyDer);
        const key = C.parsePublicKey(key_der);
        // Every group's key is one the policy takes: a parse regression must not hide behind
        // a group whose vectors are all invalid.
        _ = key catch |err| {
            std.debug.print("WYCHEPROOF {s} key refused: {t}\n", .{ file, err });
            return err;
        };
        for (group.tests) |vector| {
            const message = try hex(gpa, vector.msg);
            const sig = try hex(gpa, vector.sig);
            const accepted = if (key) |pk| blk: {
                S.verify(pk, algorithm, message, sig) catch break :blk false;
                break :blk true;
            } else |_| false;
            // "acceptable" encodings are outside strict DER/canonical Ed25519.
            const expected = std.mem.eql(u8, vector.result, "valid");
            if (accepted != expected) {
                mismatch += 1;
                std.debug.print("WYCHEPROOF {s} tcId={d} expected={s} accepted={} flags={any}\n", .{ file, vector.tcId, vector.result, accepted, vector.flags });
            } else passed += 1;
        }
    }
    std.debug.print("WYCHEPROOF {s}: {d}/{d}, mismatch {d}\n", .{ file, passed, parsed.value.numberOfTests, mismatch });
    try std.testing.expectEqual(@as(usize, 0), mismatch);
}
test "Wycheproof P256 SHA256 public signature campaign" {
    try campaign("ecdsa_secp256r1_sha256_test.json", .{ .ecdsa = .sha256 });
}
test "Wycheproof P384 SHA384 public signature campaign" {
    try campaign("ecdsa_secp384r1_sha384_test.json", .{ .ecdsa = .sha384 });
}
test "Wycheproof P256 SHA256 signatures as r || s (P1363)" {
    try campaign("ecdsa_secp256r1_sha256_p1363_test.json", .{ .ecdsa_p1363 = .sha256 });
}
test "Wycheproof P256 SHA512 signatures as r || s (P1363)" {
    try campaign("ecdsa_secp256r1_sha512_p1363_test.json", .{ .ecdsa_p1363 = .sha512 });
}
test "Wycheproof P384 SHA384 signatures as r || s (P1363)" {
    try campaign("ecdsa_secp384r1_sha384_p1363_test.json", .{ .ecdsa_p1363 = .sha384 });
}
test "Wycheproof P384 SHA512 signatures as r || s (P1363)" {
    try campaign("ecdsa_secp384r1_sha512_p1363_test.json", .{ .ecdsa_p1363 = .sha512 });
}
test "Wycheproof Ed25519 strict public signature campaign" {
    try campaign("ed25519_test.json", .ed25519);
}
test "F09 catalogue_rsa_signature_full_encoding (Wycheproof RSA PKCS#1 v1.5 SHA-256 public signature campaign)" {
    try campaign("rsa_signature_2048_sha256_test.json", .{ .rsa = .sha256 });
}
test "F09 catalogue_rsa_signature_full_encoding (Wycheproof RSA-PSS SHA-256 public signature campaign)" {
    try campaign("rsa_pss_2048_sha256_mgf1_32_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } });
}

test "Wycheproof ecdsa_secp256r1_sha512_test" {
    try campaign("ecdsa_secp256r1_sha512_test.json", .{ .ecdsa = .sha512 });
}

test "Wycheproof ecdsa_secp384r1_sha256_test" {
    try campaign("ecdsa_secp384r1_sha256_test.json", .{ .ecdsa = .sha256 });
}

test "Wycheproof ecdsa_secp384r1_sha512_test" {
    try campaign("ecdsa_secp384r1_sha512_test.json", .{ .ecdsa = .sha512 });
}

test "Wycheproof rsa_pss_2048_sha256_mgf1_0_params_test" {
    try campaign("rsa_pss_2048_sha256_mgf1_0_params_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 0 } });
}

test "Wycheproof rsa_pss_2048_sha256_mgf1_0_test" {
    try campaign("rsa_pss_2048_sha256_mgf1_0_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 0 } });
}

test "Wycheproof rsa_pss_2048_sha256_mgf1_32_params_test" {
    try campaign("rsa_pss_2048_sha256_mgf1_32_params_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_2048_sha384_mgf1_48_test" {
    try campaign("rsa_pss_2048_sha384_mgf1_48_test.json", .{ .pss = .{ .hash = .sha384, .mgf_hash = .sha384, .salt_length = 48 } });
}

test "Wycheproof rsa_pss_2048_sha512_mgf1sha256_32_params_test" {
    try campaign("rsa_pss_2048_sha512_mgf1sha256_32_params_test.json", .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha256, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_3072_sha256_mgf1_32_params_test" {
    try campaign("rsa_pss_3072_sha256_mgf1_32_params_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_3072_sha256_mgf1_32_test" {
    try campaign("rsa_pss_3072_sha256_mgf1_32_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_4096_sha256_mgf1_32_test" {
    try campaign("rsa_pss_4096_sha256_mgf1_32_test.json", .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_4096_sha384_mgf1_48_test" {
    try campaign("rsa_pss_4096_sha384_mgf1_48_test.json", .{ .pss = .{ .hash = .sha384, .mgf_hash = .sha384, .salt_length = 48 } });
}

test "Wycheproof rsa_pss_4096_sha512_mgf1_32_params_test" {
    try campaign("rsa_pss_4096_sha512_mgf1_32_params_test.json", .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha512, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_4096_sha512_mgf1_32_test" {
    try campaign("rsa_pss_4096_sha512_mgf1_32_test.json", .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha512, .salt_length = 32 } });
}

test "Wycheproof rsa_pss_4096_sha512_mgf1_64_params_test" {
    try campaign("rsa_pss_4096_sha512_mgf1_64_params_test.json", .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha512, .salt_length = 64 } });
}

test "Wycheproof rsa_pss_4096_sha512_mgf1_64_test" {
    try campaign("rsa_pss_4096_sha512_mgf1_64_test.json", .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha512, .salt_length = 64 } });
}

test "Wycheproof rsa_signature_2048_sha384_test" {
    try campaign("rsa_signature_2048_sha384_test.json", .{ .rsa = .sha384 });
}

test "Wycheproof rsa_signature_2048_sha512_test" {
    try campaign("rsa_signature_2048_sha512_test.json", .{ .rsa = .sha512 });
}

test "Wycheproof rsa_signature_3072_sha256_test" {
    try campaign("rsa_signature_3072_sha256_test.json", .{ .rsa = .sha256 });
}

test "Wycheproof rsa_signature_3072_sha384_test" {
    try campaign("rsa_signature_3072_sha384_test.json", .{ .rsa = .sha384 });
}

test "Wycheproof rsa_signature_3072_sha512_test" {
    try campaign("rsa_signature_3072_sha512_test.json", .{ .rsa = .sha512 });
}

test "Wycheproof rsa_signature_4096_sha256_test" {
    try campaign("rsa_signature_4096_sha256_test.json", .{ .rsa = .sha256 });
}

test "Wycheproof rsa_signature_4096_sha384_test" {
    try campaign("rsa_signature_4096_sha384_test.json", .{ .rsa = .sha384 });
}

test "Wycheproof rsa_signature_4096_sha512_test" {
    try campaign("rsa_signature_4096_sha512_test.json", .{ .rsa = .sha512 });
}

/// A Wycheproof hash name, or null for one cloak does not sign or verify with (SHA-1, SHA-224,
/// the truncated SHA-512 forms and SHA-3).
fn hashNamed(name: []const u8) ?C.Algorithm.Hash {
    if (std.mem.eql(u8, name, "SHA-256")) return .sha256;
    if (std.mem.eql(u8, name, "SHA-384")) return .sha384;
    if (std.mem.eql(u8, name, "SHA-512")) return .sha512;
    return null;
}

test "Wycheproof rsa_pss_misc_test: every salt length from 0 to 64 under every hash pair cloak verifies" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const PssGroup = struct { publicKeyDer: []const u8, sha: []const u8, mgfSha: []const u8, sLen: usize, tests: []Test };
    const parsed = try std.json.parseFromSliceLeaky(struct { testGroups: []PssGroup }, gpa, @embedFile("fixtures/wycheproof/rsa_pss_misc_test.json"), .{ .ignore_unknown_fields = true });
    var checked: usize = 0;
    for (parsed.testGroups) |group| {
        const hash = hashNamed(group.sha) orelse continue;
        const mgf = hashNamed(group.mgfSha) orelse continue;
        const key = try C.parsePublicKey(try hex(gpa, group.publicKeyDer));
        for (group.tests) |vector| {
            try std.testing.expectEqualStrings("valid", vector.result);
            try S.verify(key, .{ .pss = .{ .hash = hash, .mgf_hash = mgf, .salt_length = group.sLen } }, try hex(gpa, vector.msg), try hex(gpa, vector.sig));
            checked += 1;
        }
    }
    // Three hashes for the message and three for the mask, six salt lengths each.
    try std.testing.expectEqual(@as(usize, 3 * 3 * 6), checked);
}

/// Wycheproof's PKCS#1 v1.5 signing known answers: cloak signs each message with the group's
/// private key and must produce the published signature exactly (the encoding is deterministic).
fn signatureGeneration(comptime file: []const u8, expected: usize) !void {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const GenTest = struct { tcId: usize, msg: []const u8, sig: []const u8, result: []const u8 };
    const GenGroup = struct { privateKeyPkcs8: []const u8, sha: []const u8, tests: []GenTest };
    const parsed = try std.json.parseFromSliceLeaky(struct { testGroups: []GenGroup }, gpa, @embedFile("fixtures/wycheproof/" ++ file), .{ .ignore_unknown_fields = true });
    var checked: usize = 0;
    for (parsed.testGroups) |group| {
        const hash = hashNamed(group.sha) orelse continue;
        const key = try PrivateKey.parse(std.testing.allocator, try hex(gpa, group.privateKeyPkcs8), .{});
        defer key.deinit();
        var noise: [PrivateKey.max_noise]u8 = @splat(0x6e);
        for (group.tests) |vector| {
            // "acceptable" marks a small public exponent (3), which cloak takes: the signature
            // is as deterministic as any other.
            try std.testing.expect(std.mem.eql(u8, vector.result, "valid") or std.mem.eql(u8, vector.result, "acceptable"));
            var out: [PrivateKey.max_signature]u8 = undefined;
            const made = try key.sign(.{ .rsa = hash }, try hex(gpa, vector.msg), noise[0..key.noiseLength()], &out);
            try std.testing.expectEqualSlices(u8, try hex(gpa, vector.sig), made);
            checked += 1;
        }
    }
    try std.testing.expectEqual(expected, checked);
}

test "Wycheproof rsa_pkcs1_2048_sig_gen_test: signatures equal the known answers" {
    try signatureGeneration("rsa_pkcs1_2048_sig_gen_test.json", 27);
}

test "Wycheproof rsa_pkcs1_3072_sig_gen_test: signatures equal the known answers" {
    try signatureGeneration("rsa_pkcs1_3072_sig_gen_test.json", 26);
}

test "Wycheproof rsa_pkcs1_4096_sig_gen_test: signatures equal the known answers" {
    try signatureGeneration("rsa_pkcs1_4096_sig_gen_test.json", 24);
}

test "F08 catalogue_signature_workspace_and_rsa_size (Wycheproof rsa_signature_8192: an 8192-bit key is refused by policy)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    // The first group's key of rsa_signature_8192_sha256_test.json.
    const der = try hex(arena.allocator(), "30820422300d06092a864886f70d01010105000382040f003082040a0282040100dced8ed038581210fe2ccadbaa0728450b2bbb2066ca51ad97c2c1e53839dfd9870aa9b82c5029c1864ed48c019e408029b73603c605617be2e823c6f1bee4154ac7900d7bfd7a8c05bbacd4807a0a1855066ebf7f04225a3d7dfd3d16d546746c738a311d0fba6a32f00febf968d619bbe275eac61b80dec34927aef1b29b96ba42967002c33f406bf47209d005b5d2c6d4ffaf63011bf415c3cab548faefbe855754cc885c64e3c74a3f11d1dd2ef3ca88de746cc245cba25c2ab1b6280276265afaedfa24d21ac49e5101290f3a5330e362e6b2897e400839768f67d6adc443e1b51b19403925efa575f030e28668406fa52440ec9965c73fbd89374964058f7acf354decbf6c79d23a7f35d1a296ba0f6ae36117e26ccfb56c453b859a7ba12accb706559c146b245f9d222b5b7c2e158090c0946484c3893365e9bc818a265be8664f53ec6e779b5d73709f082bd943c2fc97731afd44609fc2bd37fab7e92b1715a52aa25115f2af31207aefd497c3bd061eb1a2b0559b9c6b1b2861ad565e9be71091895abb94956f5d862f3a60e0cb9fd37dcb7c218e3a82ebc288edaf3b64c1d8b80e71867b60465c0455d69d3bfadb9b8e4d1241c79f2ea8e6a3b12af6877c1a06b051c8b12b023611a1b0e8e0823632bc16d1698133895df698301f5472b4cbbe4dadbc4fab4617e825d829837f0dc6257dfb370486fe79078145d616a34925d12031e67971e91fcadc302b7a6bea614b7c68d93c54a0692c7ba6080a3522a052fc161b77305e8140d19196c4fd69d35e2cf72438804330411bc8597c52ac834e914156ebaa65ffd71123946d195a0348fe61644e6dd0bc13c89ffb8400832312e0949f7cfa12bf7802d1eda352b34bc3c34edea995548590ad59b249c4674ce1063de9e84cd1d1c4cc9b31def87b39010a1ab344319a630cbbdb74896758138cd8506730f34228798dcba116c01c204353353ceca3ee59491744d04336e5218e6d43361d5c9ac619340599884f82634a64101713c1f2368a7c0ee8d9af80e539caec7cc07545d91c8b03c8aac7556ea169675e5aed7efb71a236710e570b48b7bc922c1b619acd8aecd9c9a991216d67bc324697d8a190c75aa23b5fe032aedae8cb90af0692f061a69346c9b9684cb77209886745d55bde8253bde37821f68364a25e706092962ee1c57adf45af7efc93bc8b5e61524c058968f69e81d901bd63630de3b1856d77878ecf845efde3d0ac3ed39a9570d228c1924c01b72c2b46d0b4c84e0af1f2e9f894a3ad4a0a7845f7f71224d4f14bafdbf4b0b854a70e873a8a1e18ed25eb7e0af22d3e9346174aa03fdf73f5c9a3f7b3526bd42d9fb59734f344aacc910c127d30890279de5e54974805d8870374b47b95bb6bde71ab5c41e9596ec2ec20e588dcd81240452c9614ade0f7c4c35e9e8ca90203010001");
    try std.testing.expectError(error.InvalidPublicKey, C.parsePublicKey(der));
}
