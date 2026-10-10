const std = @import("std");
const shakedown = @import("shakedown");
const Identity = @import("../Identity.zig");
const ClientAuth = @import("../ClientAuth.zig");
const PrivateKey = @import("../PrivateKey.zig");
const Pem = @import("Pem.zig");
test "credential identity owns chain and shares retained private owner" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), lifetime, .{});
}
fn lifetime(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var pem = Pem.init(@embedFile("testdata/ed25519.cert.pem"));
    var block = (try pem.next(gpa, 65536)).?;
    defer block.deinit(gpa);
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer key.deinit();
    const identity = try Identity.init(gpa, &.{block.der}, key, .{ .generation = .fromRaw(7) });
    const held = identity.retain();
    identity.deinit();
    defer held.deinit();
    const auth = try ClientAuth.init(gpa, held.chain(), key, .{});
    defer auth.deinit();
    @memset(block.der, 0);
    try std.testing.expectEqual(@as(u64, 7), held.generation().raw());
    try std.testing.expectEqual(@as(usize, 1), held.chain().len);
    try std.testing.expectEqualSlices(u8, held.chain()[0], held.certificateList()[3..]);
    try std.testing.expect(key.matches(auth.chain()[0]));
}
test "credential identity rejects mismatched leaf and empty chain" {
    @setRuntimeSafety(true);
    const key = try PrivateKey.parse(std.testing.allocator, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer key.deinit();
    try rejectIdentity(error.EmptyChain, Identity.init(std.testing.allocator, &.{}, key, .{}));
    var pem = Pem.init(@embedFile("testdata/p256.cert.pem"));
    var block = (try pem.next(std.testing.allocator, 65536)).?;
    defer block.deinit(std.testing.allocator);
    try rejectIdentity(error.KeyMismatch, Identity.init(std.testing.allocator, &.{block.der}, key, .{}));
    try rejectIdentity(error.IdentityLimit, Identity.init(std.testing.allocator, &.{block.der}, key, .{ .chain_bytes = 1 }));
}

fn rejectIdentity(expected: anyerror, result: anyerror!Identity) !void {
    @setRuntimeSafety(true);
    if (result) |unexpected| {
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(expected, err);
}

const certificate = @import("../certificate.zig");
const signature = @import("../verify/signature.zig");

const Held = struct { cert: []const u8, key: []const u8, noise: ?usize, algorithm: certificate.Algorithm.Signature };

test "credential identity signs for the keys cloak holds and says so for the rest" {
    @setRuntimeSafety(true);
    const gpa = std.testing.allocator;
    const cases = [_]Held{
        .{ .cert = @embedFile("testdata/ed25519.cert.pem"), .key = @embedFile("testdata/ed25519.pkcs8.pem"), .noise = 0, .algorithm = .ed25519 },
        .{ .cert = @embedFile("testdata/p256.cert.pem"), .key = @embedFile("testdata/p256.pkcs8.pem"), .noise = 32, .algorithm = .{ .ecdsa = .sha256 } },
        .{ .cert = @embedFile("testdata/p384.cert.pem"), .key = @embedFile("testdata/p384.pkcs8.pem"), .noise = 48, .algorithm = .{ .ecdsa = .sha384 } },
        .{ .cert = @embedFile("testdata/rsa.cert.pem"), .key = @embedFile("testdata/rsa.pkcs8.pem"), .noise = null, .algorithm = .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } } },
    };
    for (cases) |case| {
        var pem = Pem.init(case.cert);
        var block = (try pem.next(gpa, 65536)).?;
        defer block.deinit(gpa);
        const io = std.testing.io;
        const key = try PrivateKey.parse(gpa, case.key, .{ .entropy = PrivateKey.Entropy.fromIo(&io) });
        defer key.deinit();
        const identity = try Identity.init(gpa, &.{block.der}, key, .{});
        defer identity.deinit();
        try std.testing.expectEqual(case.noise, identity.noiseLength());
        var out: [PrivateKey.max_signature]u8 = undefined;
        const noise: [PrivateKey.max_noise + 1]u8 = @splat(0x5a);
        const leaf = try certificate.parse(block.der, .{});
        if (case.noise) |length| {
            const made = try identity.sign(case.algorithm, "content", noise[0..length], &out);
            try signature.verify(leaf.public_key, case.algorithm, "content", made);
            // The algorithm must be the one the key fixes, and the noise the length it draws.
            const other: certificate.Algorithm.Signature = if (case.algorithm == .ed25519) .{ .ecdsa = .sha256 } else if (case.algorithm.ecdsa == .sha256) .{ .ecdsa = .sha384 } else .{ .ecdsa = .sha256 };
            try std.testing.expectError(error.UnsupportedAlgorithm, identity.sign(other, "content", noise[0..length], &out));
            try std.testing.expectError(error.SigningFailed, identity.sign(case.algorithm, "content", noise[0 .. length + 1], &out));
        } else try std.testing.expectError(error.UnsupportedAlgorithm, identity.sign(case.algorithm, "content", "", &out));
    }
}

test "credential identity without a key holds the chain and never signs" {
    @setRuntimeSafety(true);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, externalLifetime, .{});
    const gpa = std.testing.allocator;
    var pem = Pem.init(@embedFile("testdata/p256.cert.pem"));
    var block = (try pem.next(gpa, 65536)).?;
    defer block.deinit(gpa);
    const identity = try Identity.initExternal(gpa, &.{block.der}, .{});
    defer identity.deinit();
    try std.testing.expectEqual(@as(?usize, null), identity.noiseLength());
    var out: [PrivateKey.max_signature]u8 = undefined;
    try std.testing.expectError(error.UnsupportedAlgorithm, identity.sign(.{ .ecdsa = .sha256 }, "content", "", &out));
    try rejectIdentity(error.EmptyChain, Identity.initExternal(gpa, &.{}, .{}));
    try rejectIdentity(error.IdentityLimit, Identity.initExternal(gpa, &.{block.der}, .{ .chain_bytes = 1 }));
    // A leaf that is not a certificate cannot name the schemes a peer may be offered.
    try std.testing.expect(if (Identity.initExternal(gpa, &.{"not a certificate"}, .{})) |unexpected| blk: {
        unexpected.deinit();
        break :blk false;
    } else |_| true);
}

fn externalLifetime(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var pem = Pem.init(@embedFile("testdata/ed25519.cert.pem"));
    var block = (try pem.next(gpa, 65536)).?;
    defer block.deinit(gpa);
    const auth = try ClientAuth.initExternal(gpa, &.{block.der}, .{});
    defer auth.deinit();
    const held = auth.retain();
    defer held.deinit();
    try std.testing.expectEqual(@as(usize, 1), held.chain().len);
}

test "credential identity reads its chain from PEM, the leaf first, and refuses anything else" {
    @setRuntimeSafety(true);
    try std.testing.checkAllAllocationFailures(std.testing.allocator, pemLifetime, .{});
    const gpa = std.testing.allocator;
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/p256.pkcs8.pem"), .{});
    defer key.deinit();
    const chain = @embedFile("testdata/p256.cert.pem") ++ @embedFile("testdata/rsa.cert.pem");
    const identity = try Identity.initPem(gpa, chain, key, .{});
    defer identity.deinit();
    try std.testing.expectEqual(@as(usize, 2), identity.chain().len);
    try std.testing.expect(key.matches(identity.chain()[0]));
    // A key in the chain file is not a certificate, an empty file is no chain, and the leaf must match.
    try rejectPem(error.NotCertificate, Identity.initPem(gpa, chain ++ @embedFile("testdata/p256.pkcs8.pem"), key, .{}));
    try rejectPem(error.EmptyChain, Identity.initPem(gpa, " \n", key, .{}));
    try rejectPem(error.InvalidPem, Identity.initPem(gpa, "not pem", key, .{}));
    try rejectPem(error.IdentityLimit, Identity.initPem(gpa, chain, key, .{ .certificates = 1 }));
    try rejectPem(error.KeyMismatch, Identity.initPem(gpa, @embedFile("testdata/rsa.cert.pem"), key, .{}));
    const auth = try ClientAuth.initPem(gpa, chain, key, .{});
    defer auth.deinit();
    try std.testing.expectEqual(@as(usize, 2), auth.chain().len);
}

test "credential identity skips a key in its chain file when asked" {
    @setRuntimeSafety(true);
    const gpa = std.testing.allocator;
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/p256.pkcs8.pem"), .{});
    defer key.deinit();
    const both = @embedFile("testdata/p256.cert.pem") ++ @embedFile("testdata/p256.pkcs8.pem") ++ @embedFile("testdata/rsa.cert.pem");
    const auth = try ClientAuth.initPem(gpa, both, key, .{ .other_blocks = .skip });
    defer auth.deinit();
    try std.testing.expectEqual(@as(usize, 2), auth.chain().len);
    try std.testing.expect(key.matches(auth.chain()[0]));
    try rejectPem(error.EmptyChain, Identity.initPem(gpa, @embedFile("testdata/p256.pkcs8.pem"), key, .{ .other_blocks = .skip }));
}

fn pemLifetime(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    const key = try PrivateKey.parse(gpa, @embedFile("testdata/ed25519.pkcs8.pem"), .{});
    defer key.deinit();
    const identity = try Identity.initPem(gpa, @embedFile("testdata/ed25519.cert.pem"), key, .{});
    identity.deinit();
}

fn rejectPem(expected: anyerror, result: anyerror!Identity) !void {
    @setRuntimeSafety(true);
    if (result) |unexpected| {
        unexpected.deinit();
        return error.TestUnexpectedResult;
    } else |err| try std.testing.expectEqual(expected, err);
}
