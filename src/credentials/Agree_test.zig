//! `PrivateKey.agree` against Wycheproof's ecdh_secp256r1_ecpoint, ecdh_secp384r1_ecpoint and
//! x25519 files (C2SP testvectors_v1, the commit `verify/fixtures/wycheproof/provenance.txt`
//! names), held keys made by `fromComponents`, and X25519 keys read from PKCS#8 (RFC 8410).
const std = @import("std");
const PrivateKey = @import("../PrivateKey.zig");
const certificate = @import("../certificate.zig");

const gpa = std.testing.allocator;

const Case = struct { tcId: u32, flags: []const []const u8, public: []const u8, private: []const u8, shared: []const u8, result: []const u8 };
const Group = struct { tests: []const Case };
const File = struct { numberOfTests: u32, testGroups: []const Group };

fn hex(arena: std.mem.Allocator, text: []const u8) ![]u8 {
    const out = try arena.alloc(u8, text.len / 2);
    _ = try std.fmt.hexToBytes(out, text);
    return out;
}

fn flagged(case: Case, flag: []const u8) bool {
    for (case.flags) |f| if (std.mem.eql(u8, f, flag)) return true;
    return false;
}

const Kind = enum { p256, p384, x25519 };

fn campaign(comptime name: []const u8, comptime kind: Kind) !void {
    var arena_state: std.heap.ArenaAllocator = .init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const file = try std.json.parseFromSliceLeaky(File, arena, @embedFile("../verify/fixtures/wycheproof/" ++ name), .{ .ignore_unknown_fields = true });
    const width: usize = switch (kind) {
        .p256, .x25519 => 32,
        .p384 => 48,
    };
    var ran: usize = 0;
    for (file.testGroups) |g| for (g.tests) |t| {
        ran += 1;
        // The scalar as an integer at the curve's width: Wycheproof writes it signed, so with a
        // leading zero, or short.
        const raw = try hex(arena, t.private);
        const d = try arena.alloc(u8, width);
        @memset(d, 0);
        const significant = std.mem.trimStart(u8, raw, "\x00");
        if (kind == .x25519) @memcpy(d, raw) else @memcpy(d[width - significant.len ..], significant);
        const key = try PrivateKey.fromComponents(gpa, switch (kind) {
            .p256 => .{ .ec = .{ .curve = .p256, .d = d } },
            .p384 => .{ .ec = .{ .curve = .p384, .d = d } },
            .x25519 => .{ .x25519 = .{ .d = d } },
        });
        defer key.deinit();
        var out: [PrivateKey.max_shared]u8 = undefined;
        const made = key.agree(try hex(arena, t.public), &out);
        const valid = std.mem.eql(u8, t.result, "valid");
        // Acceptable: compressed points, which cloak does not read (no SEC 1 point a JWK or
        // a certificate carries is compressed); X25519 results of all zeros, refused as RFC
        // 7748 6.1 allows; twist and non-canonical X25519 inputs, which RFC 7748 5 computes.
        const refused = !valid and (std.mem.eql(u8, t.result, "invalid") or flagged(t, "CompressedPoint") or flagged(t, "ZeroSharedSecret"));
        if (refused) {
            if (made) |_| {
                std.debug.print("{s} tcId {d} agreed\n", .{ name, t.tcId });
                return error.TestUnexpectedResult;
            } else |_| {}
        } else {
            const shared = made catch |err| {
                std.debug.print("{s} tcId {d}: {t}\n", .{ name, t.tcId, err });
                return err;
            };
            try std.testing.expectEqualSlices(u8, try hex(arena, t.shared), shared);
        }
    };
    try std.testing.expectEqual(@as(usize, file.numberOfTests), ran);
}

test "Wycheproof ECDH P-256, P-384 and X25519: a held key agrees on the file's secret, refuses bad peers" {
    try campaign("ecdh_secp256r1_ecpoint_test.json", .p256);
    try campaign("ecdh_secp384r1_ecpoint_test.json", .p384);
    try campaign("x25519_test.json", .x25519);
}

test "an X25519 key from PKCS#8 (RFC 8410) agrees, signs nothing, and has its RFC 8410 public key" {
    // RFC 7748 6.1's Alice and Bob.
    var alice_d: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&alice_d, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    var alice_public: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&alice_public, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    var bob_d: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bob_d, "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    var bob_public: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&bob_public, "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");
    const alice = try PrivateKey.parse(gpa, "\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x6e\x04\x22\x04\x20" ++ alice_d, .{});
    defer alice.deinit();
    const bob = try PrivateKey.fromComponents(gpa, .{ .x25519 = .{ .d = &bob_d, .public = &bob_public } });
    defer bob.deinit();
    var info: [PrivateKey.max_public_key_info]u8 = undefined;
    const spki = alice.publicKeyInfo(&info);
    try std.testing.expectEqualSlices(u8, "\x30\x2a\x30\x05\x06\x03\x2b\x65\x6e\x03\x21\x00" ++ alice_public, spki);
    const public = try certificate.parsePublicKey(spki);
    try std.testing.expect(alice.matchesKey(public));
    try std.testing.expect(!bob.matchesKey(public));
    var a: [PrivateKey.max_shared]u8 = undefined;
    var b: [PrivateKey.max_shared]u8 = undefined;
    try std.testing.expectEqualSlices(u8, try alice.agree(&bob_public, &a), try bob.agree(&alice_public, &b));
    var out: [PrivateKey.max_signature]u8 = undefined;
    try std.testing.expectError(error.UnsupportedAlgorithm, alice.sign(.ed25519, "m", "", &out));
    try std.testing.expectError(error.InvalidPublicKey, alice.agree(bob_public[0..31], &a));
    try std.testing.expectError(error.IdentityElement, alice.agree(&@as([32]u8, @splat(0)), &a));
    // A public key given that is not the private key's is refused.
    try std.testing.expectError(error.InvalidKey, PrivateKey.fromComponents(gpa, .{ .x25519 = .{ .d = &bob_d, .public = &alice_public } }));
}

test "an RSA or Ed25519 key agrees on nothing; an EC key refuses a peer off its curve" {
    const rsa = try PrivateKey.parse(gpa, @embedFile("../crypto/testdata/rsa2048.der"), .{});
    defer rsa.deinit();
    var out: [PrivateKey.max_shared]u8 = undefined;
    try std.testing.expectError(error.UnsupportedAlgorithm, rsa.agree(&@as([65]u8, @splat(4)), &out));
    const p384 = try PrivateKey.parse(gpa, @embedFile("testdata/p384.pkcs8.pem"), .{});
    defer p384.deinit();
    const p256 = try PrivateKey.parse(gpa, @embedFile("testdata/p256.pkcs8.pem"), .{});
    defer p256.deinit();
    var info: [PrivateKey.max_public_key_info]u8 = undefined;
    const p256_public = (try certificate.parsePublicKey(p256.publicKeyInfo(&info))).ec.bytes;
    try std.testing.expectError(error.InvalidPublicKey, p384.agree(p256_public, &out));
    try std.testing.expectEqual(@as(usize, 32), (try p256.agree(p256_public, &out)).len);
}
