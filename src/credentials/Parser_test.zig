//! Independent bounded PEM, key and encrypted-key fuzz targets.
const std = @import("std");
const shakedown = @import("shakedown");
const inputs = @import("../testing/inputs.zig");
const PrivateKey = @import("../PrivateKey.zig");
const Pem = @import("Pem.zig");

const key_examples = [_][]const u8{ @embedFile("testdata/ed25519.pkcs8.pem"), @embedFile("testdata/p256.pkcs8.der"), "", "\x30\x80" };
const encrypted_examples = [_][]const u8{ @embedFile("testdata/ed25519.enc-low-work.pem"), @embedFile("testdata/p256.enc-aes128-sha1.pem"), @embedFile("testdata/ed25519.enc-aes256-sha512.pem"), "\x30\x00" };
const pem_examples = [_][]const u8{ @embedFile("testdata/ed25519.pkcs8.pem"), "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----", "" };

fn parseKey(bytes: []const u8) void {
    if (PrivateKey.parse(std.testing.allocator, bytes, .{ .iterations = 4 })) |key| key.deinit() else |_| {}
}
fn parseEncrypted(bytes: []const u8) void {
    if (PrivateKey.parse(std.testing.allocator, bytes, .{ .passphrase = "correct-horse", .iterations = 4 })) |key| key.deinit() else |_| {}
}
fn walkPem(bytes: []const u8) void {
    var pem = Pem.init(bytes);
    for (0..32) |_| {
        var block = (pem.next(std.testing.allocator, 65536) catch return) orelse return;
        block.deinit(std.testing.allocator);
    }
}

test "credential parsers take their fixtures and hostile examples without leaking" {
    @setRuntimeSafety(true);
    for (key_examples) |bytes| parseKey(bytes);
    for (encrypted_examples) |bytes| parseEncrypted(bytes);
    for (pem_examples) |bytes| walkPem(bytes);
}

test "credential key parser fuzz bounded DER and armor" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, keyInput, .{ .cases = 64 });
}
fn keyInput(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    var storage: [65536]u8 = undefined;
    parseKey(inputs.draw(case, &storage, &key_examples, 48));
}
test "credential KDF parser fuzz rejects hostile work before decrypt" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, encryptedInput, .{ .cases = 64 });
}
fn encryptedInput(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    var storage: [65536]u8 = undefined;
    parseEncrypted(inputs.draw(case, &storage, &encrypted_examples, 48));
}
test "credential PEM parser fuzz owns bounded decoded blocks" {
    @setRuntimeSafety(true);
    try shakedown.check(std.testing.allocator, {}, pemInput, .{ .cases = 64 });
}
fn pemInput(_: void, case: *shakedown.Case) !void {
    @setRuntimeSafety(true);
    var storage: [65536]u8 = undefined;
    walkPem(inputs.draw(case, &storage, &pem_examples, 48));
}
