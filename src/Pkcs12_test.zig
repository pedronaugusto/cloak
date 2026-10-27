const std = @import("std");
const cloak = @import("root.zig");
const Pkcs12 = @import("Pkcs12.zig");
const PrivateKey = @import("PrivateKey.zig");
const certificate = @import("certificate.zig");

const dir = "credentials/testdata/pkcs12/";
const root = @embedFile(dir ++ "root.der");
const inter = @embedFile(dir ++ "inter.der");
const password = "correct-horse";

const Kind = enum { p256, p384, rsa, ed25519 };
fn leafOf(kind: Kind) []const u8 {
    return switch (kind) {
        .p256 => @embedFile(dir ++ "p256.der"),
        .p384 => @embedFile(dir ++ "p384.der"),
        .rsa => @embedFile(dir ++ "rsa.der"),
        .ed25519 => @embedFile(dir ++ "ed25519.der"),
    };
}
fn keyOf(kind: Kind) []const u8 {
    return switch (kind) {
        .p256 => @embedFile(dir ++ "p256.key.der"),
        .p384 => @embedFile(dir ++ "p384.key.der"),
        .rsa => @embedFile(dir ++ "rsa.key.der"),
        .ed25519 => @embedFile(dir ++ "ed25519.key.der"),
    };
}

/// A file every writer made from the same PKI, and what reading it gives.
const Fixture = struct { name: []const u8, bytes: []const u8, kind: Kind = .p256, passphrase: ?[]const u8 = password, chain: enum { full, leaf } = .full, require_mac: bool = true };
const fixtures = [_]Fixture{
    // OpenSSL 4.0.3
    .{ .name = "p256.default", .bytes = @embedFile(dir ++ "p256.default.p12") },
    .{ .name = "p384.default", .bytes = @embedFile(dir ++ "p384.default.p12"), .kind = .p384 },
    .{ .name = "rsa.default", .bytes = @embedFile(dir ++ "rsa.default.p12"), .kind = .rsa },
    .{ .name = "ed25519.default", .bytes = @embedFile(dir ++ "ed25519.default.p12"), .kind = .ed25519 },
    .{ .name = "p256.legacy", .bytes = @embedFile(dir ++ "p256.legacy.p12") },
    .{ .name = "rsa.legacy", .bytes = @embedFile(dir ++ "rsa.legacy.p12"), .kind = .rsa },
    .{ .name = "p256.pbmac1", .bytes = @embedFile(dir ++ "p256.pbmac1.p12") },
    .{ .name = "p256.pbmac1-sha512", .bytes = @embedFile(dir ++ "p256.pbmac1-sha512.p12") },
    .{ .name = "p256.mixed", .bytes = @embedFile(dir ++ "p256.mixed.p12") },
    .{ .name = "p256.pbe-2des-rc2-128", .bytes = @embedFile(dir ++ "p256.pbe-2des-rc2-128.p12") },
    .{ .name = "p256.noenc", .bytes = @embedFile(dir ++ "p256.noenc.p12") },
    .{ .name = "p256.nomac", .bytes = @embedFile(dir ++ "p256.nomac.p12"), .require_mac = false },
    .{ .name = "p256.iter1", .bytes = @embedFile(dir ++ "p256.iter1.p12") },
    .{ .name = "p256.iter2048", .bytes = @embedFile(dir ++ "p256.iter2048.p12") },
    .{ .name = "p256.empty-password", .bytes = @embedFile(dir ++ "p256.empty-password.p12"), .passphrase = "" },
    .{ .name = "p256.empty-password null", .bytes = @embedFile(dir ++ "p256.empty-password.p12"), .passphrase = null },
    .{ .name = "p256.empty-password.legacy", .bytes = @embedFile(dir ++ "p256.empty-password.legacy.p12"), .passphrase = "" },
    .{ .name = "p256.unicode", .bytes = @embedFile(dir ++ "p256.unicode.p12"), .passphrase = "pässwörd😀" },
    .{ .name = "p256.unicode.legacy", .bytes = @embedFile(dir ++ "p256.unicode.legacy.p12"), .passphrase = "pässwörd😀" },
    // NSS pk12util 3.128: BER with indefinite lengths and chunked strings
    .{ .name = "nss", .bytes = @embedFile(dir ++ "nss.p12") },
    .{ .name = "nss.legacy", .bytes = @embedFile(dir ++ "nss.legacy.p12") },
    // go-pkcs12 v0.7.4
    .{ .name = "go.modern", .bytes = @embedFile(dir ++ "go.modern.p12") },
    .{ .name = "go.modern2023", .bytes = @embedFile(dir ++ "go.modern2023.p12") },
    .{ .name = "go.legacy", .bytes = @embedFile(dir ++ "go.legacy.p12") },
    .{ .name = "go.legacydes", .bytes = @embedFile(dir ++ "go.legacydes.p12") },
    .{ .name = "go.passwordless", .bytes = @embedFile(dir ++ "go.passwordless.p12"), .passphrase = null, .require_mac = false },
    // Python cryptography 46.0.5
    .{ .name = "python.aes", .bytes = @embedFile(dir ++ "python.aes.p12") },
    .{ .name = "python.3des", .bytes = @embedFile(dir ++ "python.3des.p12") },
    .{ .name = "python.unencrypted", .bytes = @embedFile(dir ++ "python.unencrypted.p12"), .passphrase = null },
    // macOS security export: the identity alone
    .{ .name = "macos", .bytes = @embedFile(dir ++ "macos.p12"), .chain = .leaf },
};

/// The same key: one public half, and one signature under the same noise.
fn expectSameKey(a: PrivateKey, b: PrivateKey, kind: Kind) !void {
    var ka: [PrivateKey.max_public_key_info]u8 = undefined;
    var kb: [PrivateKey.max_public_key_info]u8 = undefined;
    try std.testing.expectEqualSlices(u8, b.publicKeyInfo(&kb), a.publicKeyInfo(&ka));
    const algorithm: certificate.Algorithm.Signature = switch (kind) {
        .p256 => .{ .ecdsa = .sha256 },
        .p384 => .{ .ecdsa = .sha384 },
        .rsa => .{ .rsa = .sha256 },
        .ed25519 => .ed25519,
    };
    var noise: [PrivateKey.max_noise]u8 = @splat(7);
    var sa: [PrivateKey.max_signature]u8 = undefined;
    var sb: [PrivateKey.max_signature]u8 = undefined;
    try std.testing.expectEqualSlices(u8, try b.sign(algorithm, "m", noise[0..b.noiseLength()], &sb), try a.sign(algorithm, "m", noise[0..a.noiseLength()], &sa));
}

test "credential PKCS#12 reads every writer's file into the key and its chain, leaf first" {
    const gpa = std.testing.allocator;
    for (fixtures) |f| {
        errdefer std.debug.print("fixture {s}\n", .{f.name});
        const p12 = try Pkcs12.parse(gpa, f.bytes, .{ .passphrase = f.passphrase, .require_mac = f.require_mac });
        defer p12.deinit();
        const expected: []const []const u8 = switch (f.chain) {
            .full => &.{ leafOf(f.kind), inter, root },
            .leaf => &.{leafOf(f.kind)},
        };
        try std.testing.expectEqual(expected.len, p12.chain().len);
        try std.testing.expectEqual(expected.len, p12.certificates.len);
        for (expected, p12.chain()) |want, got| try std.testing.expectEqualSlices(u8, want, got);
        const reference = try PrivateKey.parse(gpa, keyOf(f.kind), .{});
        defer reference.deinit();
        try expectSameKey(p12.key.?, reference, f.kind);
        // What it reads is what an Identity takes.
        const identity = try cloak.Identity.init(gpa, p12.chain(), p12.key.?, .{});
        identity.deinit();
    }
}

test "credential PKCS#12 trust stores give their certificates in file order and no key" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ @embedFile(dir ++ "truststore.p12"), @embedFile(dir ++ "go.truststore.p12") }) |bytes| {
        const p12 = try Pkcs12.parse(gpa, bytes, .{ .passphrase = password });
        defer p12.deinit();
        try std.testing.expect(p12.key == null);
        try std.testing.expectEqual(0, p12.chain().len);
        try std.testing.expectEqual(2, p12.certificates.len);
        try std.testing.expectEqualSlices(u8, root, p12.certificates[0]);
        try std.testing.expectEqualSlices(u8, inter, p12.certificates[1]);
    }
}

test "credential PKCS#12 refuses a wrong, missing or tampered password before decrypting" {
    const gpa = std.testing.allocator;
    const bytes = @embedFile(dir ++ "p256.iter1.p12");
    try std.testing.expectError(error.BadPassword, Pkcs12.parse(gpa, bytes, .{ .passphrase = "wrong" }));
    try std.testing.expectError(error.PasswordRequired, Pkcs12.parse(gpa, bytes, .{}));
    try std.testing.expectError(error.BadPassword, Pkcs12.parse(gpa, @embedFile(dir ++ "p256.unicode.legacy.p12"), .{ .passphrase = "passwrd" }));
    // Any byte of the authenticated safe changed fails the MAC, whatever it was.
    var tampered = bytes.*;
    for ([_]usize{ 64, tampered.len / 2, tampered.len - 120 }) |at| {
        tampered = bytes.*;
        tampered[at] ^= 0x01;
        if (Pkcs12.parse(gpa, &tampered, .{ .passphrase = password })) |p12| {
            p12.deinit();
            return error.TestUnexpectedResult;
        } else |_| {}
    }
}

test "credential PKCS#12 refuses a file without a MAC unless the caller takes it unauthenticated" {
    const gpa = std.testing.allocator;
    try std.testing.expectError(error.Unauthenticated, Pkcs12.parse(gpa, @embedFile(dir ++ "p256.nomac.p12"), .{ .passphrase = password }));
    try std.testing.expectError(error.Unauthenticated, Pkcs12.parse(gpa, @embedFile(dir ++ "go.passwordless.p12"), .{}));
}

test "credential PKCS#12 bounds hostile files before the work" {
    const gpa = std.testing.allocator;
    const bytes = @embedFile(dir ++ "p256.iter2048.p12");
    try std.testing.expectError(error.KdfLimit, Pkcs12.parse(gpa, bytes, .{ .passphrase = password, .limits = .{ .iterations = 2047 } }));
    try std.testing.expectError(error.InputLimit, Pkcs12.parse(gpa, bytes, .{ .passphrase = password, .limits = .{ .bytes = 1000 } }));
    try std.testing.expectError(error.CertificateLimit, Pkcs12.parse(gpa, bytes, .{ .passphrase = password, .certificates = 2 }));
    try std.testing.expectError(error.BagLimit, Pkcs12.parse(gpa, bytes, .{ .passphrase = password, .limits = .{ .bags = 3 } }));
}

test "credential PKCS#12 keys under PKCS#12 PBE read as encrypted PKCS#8 too" {
    const gpa = std.testing.allocator;
    const reference = try PrivateKey.parse(gpa, keyOf(.p256), .{});
    defer reference.deinit();
    for ([_][]const u8{ @embedFile(dir ++ "p256.pbe-sha1-3des.pk8.pem"), @embedFile(dir ++ "p256.pbe-sha1-rc2-40.pk8.pem") }) |pem| {
        const key = try PrivateKey.parse(gpa, pem, .{ .passphrase = password });
        defer key.deinit();
        try expectSameKey(key, reference, .p256);
        try std.testing.expectError(error.BadPassword, PrivateKey.parse(gpa, pem, .{ .passphrase = "wrong" }));
    }
}

test "fuzz PKCS#12 container parsing" {
    const shakedown = @import("shakedown");
    try shakedown.check(std.testing.allocator, {}, struct {
        fn run(_: void, case: *shakedown.Case) !void {
            const inputs = @import("testing/inputs.zig");
            var buffer: [8192]u8 = undefined;
            // Unauthenticated, one-iteration files: the mutations reach the decryptors and bags.
            const seeds = [_][]const u8{ @embedFile(dir ++ "p256.iter1.p12"), @embedFile(dir ++ "p256.nomac.p12"), @embedFile(dir ++ "go.passwordless.p12"), @embedFile(dir ++ "nss.legacy.p12")[0..64] };
            const input = inputs.draw(case, &buffer, &seeds, 64);
            const p12 = Pkcs12.parse(std.testing.allocator, input, .{ .passphrase = password, .require_mac = false, .limits = .{ .iterations = 4096 } }) catch return;
            defer p12.deinit();
            try std.testing.expect(p12.chain_length <= p12.certificates.len);
            if (p12.key) |key| if (p12.chain_length != 0) try std.testing.expect(key.matches(p12.certificates[0]));
        }
    }.run, .{ .cases = 128 });
}

test "fuzz PKCS#12 key bags, plain and shrouded" {
    const shakedown = @import("shakedown");
    try shakedown.check(std.testing.allocator, {}, struct {
        fn run(_: void, case: *shakedown.Case) !void {
            const inputs = @import("testing/inputs.zig");
            const Pbe = @import("credentials/Pbe.zig");
            const Key = @import("credentials/Key.zig");
            var buffer: [4096]u8 = undefined;
            const seeds = [_][]const u8{ keyOf(.p256), keyOf(.ed25519), shrouded_iter1 };
            const input = inputs.draw(case, &buffer, &seeds, 64);
            var bag_password = try Pbe.Password.init(std.testing.allocator, password, false, .{});
            defer bag_password.deinit(std.testing.allocator);
            for ([_]bool{ false, true }) |shrouded| {
                if (PrivateKey.parseBag(std.testing.allocator, input, shrouded, &bag_password, .{ .iterations = 4 })) |key| key.deinit() else |_| {}
            }
            var material: Key.Material = undefined;
            if (Key.parsePlain(input, .{}, &material)) |_| std.crypto.secureZero(u8, std.mem.asBytes(&material)) else |_| {}
        }
    }.run, .{ .cases = 128 });
}

/// The P-256 key under PBES2 with one PBKDF2 round, as a shrouded bag holds it.
const shrouded_iter1 = @embedFile(dir ++ "p256.pbes2-iter1.pk8.der");
