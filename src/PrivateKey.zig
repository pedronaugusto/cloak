//! A retained immutable private key. Final release wipes all owned material.
const std = @import("std");
const Der = @import("wire/Der.zig");
const parser = @import("credentials/Key.zig");
const certificate = @import("certificate.zig");
const Sign = @import("credentials/Sign.zig");
const Secret = @import("aegis").Secret;
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
    var material = Secret(parser.Material).init(try parser.parse(gpa, bytes, options));
    errdefer material.deinit();
    const state = try gpa.create(State);
    errdefer gpa.destroy(state);
    state.gpa = gpa;
    state.refs = .init(1);
    material.moveInto(&state.material);
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
    return switch (key.state.material.expose().*) {
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
/// The most noise bytes one signature draws.
pub const max_noise = Sign.P384.noise_length;
/// The longest signature `sign` writes.
pub const max_signature = Sign.max_signature;

pub const SignError = error{ UnsupportedAlgorithm, SigningFailed };

/// How many bytes of fresh noise one signature draws, or null when this key does not sign in
/// this package: ECDSA on P-256 and P-384 hedge their nonces with noise, Ed25519 is
/// deterministic (zero), and RSA keys are signed by the caller until RSA-PSS signing lands.
pub fn noiseLength(key: PrivateKey) ?usize {
    @setRuntimeSafety(true);
    return switch (key.state.material.expose().*) {
        .rsa => null,
        .p256 => Sign.P256.noise_length,
        .p384 => Sign.P384.noise_length,
        .ed25519 => 0,
    };
}

/// Signs `message` under `algorithm`, which must be the one this key's type and curve fix
/// (ECDSA with SHA-256 on P-256, with SHA-384 on P-384, or Ed25519). `noise` is exactly
/// `noiseLength` fresh bytes. Returns the DER ECDSA-Sig-Value or the 64 Ed25519 bytes in `out`.
pub fn sign(key: PrivateKey, algorithm: certificate.Algorithm.Signature, message: []const u8, noise: []const u8, out: *[max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    const expected = key.noiseLength() orelse return error.UnsupportedAlgorithm;
    if (noise.len != expected) return error.SigningFailed;
    switch (key.state.material.expose().*) {
        .rsa => unreachable,
        .p256 => |*pair| {
            if (algorithm != .ecdsa or algorithm.ecdsa != .sha256) return error.UnsupportedAlgorithm;
            return Sign.P256.sign(&pair.secret_key.bytes, message, noise[0..Sign.P256.noise_length], out) catch error.SigningFailed;
        },
        .p384 => |*pair| {
            if (algorithm != .ecdsa or algorithm.ecdsa != .sha384) return error.UnsupportedAlgorithm;
            return Sign.P384.sign(&pair.secret_key.bytes, message, noise[0..Sign.P384.noise_length], out) catch error.SigningFailed;
        },
        .ed25519 => |*pair| {
            if (algorithm != .ed25519) return error.UnsupportedAlgorithm;
            Sign.ed25519.sign(&pair.secret_key.bytes, message, out[0..Sign.ed25519.signature_length]) catch return error.SigningFailed;
            return out[0..Sign.ed25519.signature_length];
        },
    }
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
}
