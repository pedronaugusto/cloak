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
/// The most noise bytes one signature draws: RSA's blinding seed and salt.
pub const max_noise = @max(Sign.P384.noise_length, Sign.rsa.noise_length);
/// The longest signature `sign` writes: RSA's, 512 bytes for a 4096-bit key.
pub const max_signature = Sign.max_signature;

pub const SignError = error{ UnsupportedAlgorithm, InvalidNoise, SigningFailed };

/// How many bytes of fresh noise one signature draws: ECDSA on P-256 and P-384 hedges its
/// nonces with 32 or 48, Ed25519 is deterministic (zero), and RSA draws 96 for every scheme,
/// a 32-byte blinding seed and room for the longest PSS salt.
pub fn noiseLength(key: PrivateKey) usize {
    @setRuntimeSafety(true);
    return switch (key.state.material.expose().*) {
        .rsa => Sign.rsa.noise_length,
        .p256 => Sign.P256.noise_length,
        .p384 => Sign.P384.noise_length,
        .ed25519 => 0,
    };
}

/// Signs `message` under `algorithm`, which must be one this key's type and curve can make:
/// ECDSA with SHA-256 on P-256, with SHA-384 on P-384, Ed25519, and for RSA `.pss` (MGF1 on
/// the same hash, a salt as long as the hash, as TLS requires) or `.rsa` (PKCS#1 v1.5, for
/// TLS 1.2) on SHA-256, SHA-384 or SHA-512. `noise` is exactly `noiseLength` fresh bytes.
/// Returns the DER ECDSA-Sig-Value, the 64 Ed25519 bytes, or the modulus-sized RSA signature
/// in `out`; an RSA signature is checked against the public key before it is returned.
pub fn sign(key: PrivateKey, algorithm: certificate.Algorithm.Signature, message: []const u8, noise: []const u8, out: *[max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    if (noise.len != key.noiseLength()) return error.InvalidNoise;
    switch (key.state.material.expose().*) {
        .rsa => |*rsa| return rsaSign(SignError, &rsa.crt, algorithm, message, false, noise[0..Sign.rsa.noise_length], out),
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

pub const SignDigestError = SignError || error{InvalidDigest};

/// `sign` over a digest the caller already computed with `algorithm`'s hash, as TLS 1.2 keeps
/// its transcript: 32, 48 or 64 bytes for SHA-256, SHA-384 or SHA-512, `InvalidDigest`
/// otherwise. ECDSA on the key's own curve hash, or RSA (PSS or PKCS#1 v1.5, with the same
/// public check); Ed25519 signs the message itself and has no digest form.
pub fn signDigest(key: PrivateKey, algorithm: certificate.Algorithm.Signature, digest: []const u8, noise: []const u8, out: *[max_signature]u8) SignDigestError![]const u8 {
    @setRuntimeSafety(true);
    if (noise.len != key.noiseLength()) return error.InvalidNoise;
    return switch (key.state.material.expose().*) {
        .rsa => |*rsa| rsaSign(SignDigestError, &rsa.crt, algorithm, digest, true, noise[0..Sign.rsa.noise_length], out),
        .p256 => |*pair| {
            if (algorithm != .ecdsa or algorithm.ecdsa != .sha256) return error.UnsupportedAlgorithm;
            if (digest.len != 32) return error.InvalidDigest;
            return Sign.P256.signDigest(&pair.secret_key.bytes, digest[0..32], noise[0..Sign.P256.noise_length], out) catch error.SigningFailed;
        },
        .p384 => |*pair| {
            if (algorithm != .ecdsa or algorithm.ecdsa != .sha384) return error.UnsupportedAlgorithm;
            if (digest.len != 48) return error.InvalidDigest;
            return Sign.P384.signDigest(&pair.secret_key.bytes, digest[0..48], noise[0..Sign.P384.noise_length], out) catch error.SigningFailed;
        },
        .ed25519 => error.UnsupportedAlgorithm,
    };
}

/// An RSA signature under `algorithm` over `input`, a message or, when `prehashed`, its digest.
fn rsaSign(comptime E: type, key: *const Sign.rsa.Key, algorithm: certificate.Algorithm.Signature, input: []const u8, comptime prehashed: bool, noise: *const [Sign.rsa.noise_length]u8, out: *[max_signature]u8) E![]const u8 {
    @setRuntimeSafety(true);
    const hash: certificate.Algorithm.Hash, const pss = switch (algorithm) {
        // TLS's PSS schemes: MGF1 on the signing hash, a salt as long as the hash.
        .pss => |p| if (p.mgf_hash == p.hash and p.trailer == 1) .{ p.hash, true } else return error.UnsupportedAlgorithm,
        .rsa => |h| .{ h, false },
        else => return error.UnsupportedAlgorithm,
    };
    switch (hash) {
        inline else => |tag| {
            const Hash = HashOf(tag);
            if (pss and algorithm.pss.salt_length != Hash.digest_length) return error.UnsupportedAlgorithm;
            var digest: [Hash.digest_length]u8 = undefined;
            if (prehashed) {
                if (input.len != Hash.digest_length) return error.InvalidDigest;
                @memcpy(&digest, input);
            } else Hash.hash(input, &digest, .{});
            const made = if (pss) Sign.rsa.pssDigest(Hash, key, &digest, noise, out) else Sign.rsa.pkcs1Digest(Hash, key, &digest, noise, out);
            return made catch error.SigningFailed;
        },
    }
}

fn HashOf(comptime hash: certificate.Algorithm.Hash) type {
    return switch (hash) {
        .sha256 => std.crypto.hash.sha2.Sha256,
        .sha384 => std.crypto.hash.sha2.Sha384,
        .sha512 => std.crypto.hash.sha2.Sha512,
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
}
