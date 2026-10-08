const std = @import("std");
const C = @import("../certificate.zig");
const S = @import("signature.zig");
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
test "Wycheproof Ed25519 strict public signature campaign" {
    try campaign("ed25519_test.json", .ed25519);
}
test "Wycheproof RSA PKCS1 SHA256 public signature campaign" {
    try campaign("rsa_signature_2048_sha256_test.json", .{ .rsa = .sha256 });
}
test "Wycheproof RSA PSS SHA256 public signature campaign" {
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
