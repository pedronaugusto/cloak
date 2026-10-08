//! A retained immutable private key. Final release wipes all owned material.
const std = @import("std");
const Der = @import("wire/Der.zig");
const parser = @import("credentials/Key.zig");
const certificate = @import("certificate.zig");
const Secret = @import("credentials/Secret.zig").Secret;
const PrivateKey = @This();
/// Private: shares one immutable owner, never a caller's passphrase or DER.
state: *State,
const State = struct { gpa: std.mem.Allocator, refs: std.atomic.Value(usize) = .init(1), material: Secret(parser.Material) };
pub const ParseError = parser.ParseError;
pub const ParseOptions = parser.Options;
/// Caller-provided fresh CSPRNG witnesses for RSA material validation.
pub const Entropy = @import("credentials/Entropy.zig");
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!PrivateKey {
    @setRuntimeSafety(true);
    var material: Secret(parser.Material) = .{ .value = try parser.parse(gpa, bytes, options) };
    defer material.deinit();
    const state = try gpa.create(State);
    errdefer gpa.destroy(state);
    state.* = .{ .gpa = gpa, .material = material };
    return .{ .state = state };
}
pub fn isEncrypted(bytes: []const u8) bool {
    @setRuntimeSafety(true);
    if (std.mem.find(u8, bytes, "-----BEGIN ENCRYPTED PRIVATE KEY-----") != null or std.mem.find(u8, bytes, "Proc-Type: 4,ENCRYPTED") != null) return true;
    var r = (Der.single(bytes, 0x30) catch return false).reader();
    return r.peek() == 0x30;
}
pub fn matches(key: PrivateKey, der: []const u8) bool {
    @setRuntimeSafety(true);
    const cert = certificate.parse(der, .{}) catch return false;
    return switch (key.state.material.value) {
        .rsa => |*k| switch (cert.public_key) {
            .rsa => |p| std.mem.eql(u8, k.n[0..k.size], p.modulus) and std.mem.eql(u8, k.e[0..k.exponent_size], p.exponent),
            else => false,
        },
        .p256 => |*k| switch (cert.public_key) {
            .ec => |p| p.curve == .p256 and std.mem.eql(u8, p.bytes, &k.public_key.toUncompressedSec1()),
            else => false,
        },
        .p384 => |*k| switch (cert.public_key) {
            .ec => |p| p.curve == .p384 and std.mem.eql(u8, p.bytes, &k.public_key.toUncompressedSec1()),
            else => false,
        },
        .ed25519 => |*k| switch (cert.public_key) {
            .ed25519 => |p| std.mem.eql(u8, p, &k.public_key.toBytes()),
            else => false,
        },
    };
}
pub fn retain(key: PrivateKey) PrivateKey {
    @setRuntimeSafety(true);
    var count = key.state.refs.load(.monotonic);
    while (true) {
        if (count == 0 or count == std.math.maxInt(usize)) @panic("cloak retained owner exhausted");
        if (key.state.refs.cmpxchgWeak(count, count + 1, .monotonic, .monotonic)) |actual| count = actual else break;
    }
    return key;
}
pub fn deinit(key: PrivateKey) void {
    @setRuntimeSafety(true);
    if (key.state.refs.fetchSub(1, .acq_rel) != 1) return;
    const gpa = key.state.gpa;
    key.state.material.deinit();
    gpa.destroy(key.state);
}
test {
    @setRuntimeSafety(true);
    _ = @import("credentials/Key_test.zig");
    _ = @import("credentials/Secret.zig");
}
