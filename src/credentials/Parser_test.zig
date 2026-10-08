//! Independent bounded PEM, key and encrypted-key fuzz targets.
const std = @import("std");
const shakedown = @import("shakedown");
const PrivateKey = @import("../PrivateKey.zig");
const Pem = @import("Pem.zig");
test "credential key parser fuzz bounded DER and armor" {
    @setRuntimeSafety(true);
    try std.testing.fuzz({}, keyInput, .{ .corpus = shakedown.corpus.entries(&.{ @embedFile("testdata/ed25519.pkcs8.pem"), @embedFile("testdata/p256.pkcs8.der"), "", "\x30\x80" }) });
}
fn keyInput(_: void, smith: *std.testing.Smith) !void {
    @setRuntimeSafety(true);
    var storage: [65536]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    if (PrivateKey.parse(std.testing.allocator, bytes, .{ .iterations = 4 })) |key| key.deinit() else |_| {}
}
test "credential KDF parser fuzz rejects hostile work before decrypt" {
    @setRuntimeSafety(true);
    try std.testing.fuzz({}, encryptedInput, .{ .corpus = shakedown.corpus.entries(&.{ @embedFile("testdata/ed25519.enc-low-work.pem"), @embedFile("testdata/p256.enc-aes128-sha1.pem"), @embedFile("testdata/ed25519.enc-aes256-sha512.pem"), "\x30\x00" }) });
}
fn encryptedInput(_: void, smith: *std.testing.Smith) !void {
    @setRuntimeSafety(true);
    var storage: [65536]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    if (PrivateKey.parse(std.testing.allocator, bytes, .{ .passphrase = "correct-horse", .iterations = 4 })) |key| key.deinit() else |_| {}
}
test "credential PEM parser fuzz owns bounded decoded blocks" {
    @setRuntimeSafety(true);
    try std.testing.fuzz({}, pemInput, .{ .corpus = shakedown.corpus.entries(&.{ @embedFile("testdata/ed25519.pkcs8.pem"), "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----", "" }) });
}
fn pemInput(_: void, smith: *std.testing.Smith) !void {
    @setRuntimeSafety(true);
    var storage: [65536]u8 = undefined;
    const bytes = storage[0..smith.slice(&storage)];
    var pem = Pem.init(bytes);
    for (0..32) |_| {
        var block = (pem.next(std.testing.allocator, 65536) catch return) orelse return;
        block.deinit(std.testing.allocator);
    }
}
