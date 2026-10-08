const std = @import("std");
const shakedown = @import("shakedown");
const PrivateKey = @import("../PrivateKey.zig");
const Entropy = @import("Entropy.zig");
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
        const key = try PrivateKey.parse(std.testing.allocator, case.key, .{ .passphrase = case.passphrase, .entropy = Entropy.fromIo(&std.testing.io) });
        defer key.deinit();
        var cert_pem = Pem.init(case.cert);
        var block: ?Pem.Block = if (std.mem.startsWith(u8, case.cert, "-----")) (try cert_pem.next(std.testing.allocator, 65536)).? else null;
        defer if (block) |*b| b.deinit(std.testing.allocator);
        try std.testing.expect(key.matches(if (block) |b| b.der else case.cert));
        try std.testing.expectEqual(case.passphrase != null, PrivateKey.isEncrypted(case.key));
    }
}
test "credential input and KDF bounds precede allocation and expensive work" {
    @setRuntimeSafety(true);
    try rejectKey(error.InputLimit, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/rsa.pkcs1.pem"), .{ .bytes = 8 }));
    try rejectKey(error.KdfLimit, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/p256.enc-aes128-sha1.pem"), .{ .passphrase = "correct-horse", .iterations = 1 }));
    try rejectKey(error.PasswordRequired, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/p256.enc-aes128-sha1.pem"), .{}));
    try rejectKey(error.BadPassword, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/p256.enc-aes128-sha1.pem"), .{ .passphrase = "wrong" }));
}
test "credential final ownership survives original owner release and allocation faults" {
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
    try rejectKey(error.EntropyRequired, PrivateKey.parse(std.testing.allocator, @embedFile("testdata/rsa.pkcs1.pem"), .{}));
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
