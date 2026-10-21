//! A retained immutable private key. Final release wipes all owned material.
const std = @import("std");
const builtin = @import("builtin");
const Der = @import("wire/Der.zig");
const parser = @import("credentials/Key.zig");
const certificate = @import("certificate.zig");
const Sign = @import("credentials/Sign.zig");
const mldsa = @import("crypto/mldsa.zig");
const aegis = @import("aegis");
const Secret = aegis.Secret;
const PrivateKey = @This();
/// Private: shares one immutable owner, never a caller's passphrase or DER.
state: *State,
const State = struct { gpa: std.mem.Allocator, refs: std.atomic.Value(usize) = .init(1), material: Secret(parser.Material) };
pub const ParseError = parser.ParseError;
pub const ParseOptions = parser.Options;
/// Stack a parse and a signature reach below their entry, erased when they return: the frames
/// of the parser and the kernels, whose spills and copies of key material no owner can name.
/// A test measures every key type and scheme against them in each build mode.
const parse_stack: usize = if (builtin.mode == .debug) 96 * 1024 else 64 * 1024;
const sign_stack: usize = if (builtin.mode == .debug) 48 * 1024 else 24 * 1024;

pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!PrivateKey {
    return aegis.secret.scrubbed(parse_stack, parseKey, .{ gpa, bytes, options });
}

fn parseKey(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!PrivateKey {
    @setRuntimeSafety(true);
    // The owner first: the parser writes the key where it lives.
    const state = try gpa.create(State);
    errdefer gpa.destroy(state);
    state.gpa = gpa;
    state.refs = .init(1);
    state.material = .init(undefined);
    errdefer state.material.deinit();
    try parser.parse(gpa, bytes, options, state.material.exposeMut());
    return .{ .state = state };
}
/// A private key by its numbers, as a JWK (RFC 7518 section 6, RFC 8037) or another format
/// carries them, never in DER. Each goes through the checks a parsed key of its kind gets, by the
/// same code: an RSA key's numbers agreeing, an EC scalar in range, and the public half derived
/// and compared when it is given. Borrowed for the call only.
pub const Components = union(enum) {
    /// The private scalar d, exactly the curve's width, and optionally the public point as
    /// SEC 1 uncompressed bytes (0x04 || x || y), the form a certificate's key takes.
    ec: struct { curve: parser.EcCurve, d: []const u8, public: ?[]const u8 = null },
    /// The 32-byte seed (a JWK's d) and optionally the 32-byte public key (its x).
    ed25519: struct { seed: []const u8, public: ?[]const u8 = null },
    /// A two-prime key's numbers, unsigned big-endian in their fewest bytes. All eight are
    /// needed: the private operation is CRT's.
    rsa: struct { n: []const u8, e: []const u8, d: []const u8, p: []const u8, q: []const u8, dp: []const u8, dq: []const u8, qi: []const u8 },
};

pub const ComponentsError = std.mem.Allocator.Error || error{ InvalidKey, UnsupportedKey };

pub fn fromComponents(gpa: std.mem.Allocator, components: Components) ComponentsError!PrivateKey {
    return aegis.secret.scrubbed(parse_stack, buildKey, .{ gpa, components });
}

fn buildKey(gpa: std.mem.Allocator, components: Components) ComponentsError!PrivateKey {
    @setRuntimeSafety(true);
    const state = try gpa.create(State);
    errdefer gpa.destroy(state);
    state.gpa = gpa;
    state.refs = .init(1);
    state.material = .init(undefined);
    errdefer state.material.deinit();
    const out = state.material.exposeMut();
    (switch (components) {
        .ec => |ec| parser.ecKey(ec.curve, ec.d, ec.public, out),
        .ed25519 => |ed| parser.ed25519Key(ed.seed, ed.public, out),
        .rsa => |rsa| parser.rsaFromIntegers(&.{ rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qi }, out),
    }) catch |err| return switch (err) {
        error.UnsupportedKey => error.UnsupportedKey,
        else => error.InvalidKey,
    };
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
    return key.matchesKey(cert.public_key);
}
/// Whether `public_key` is this key's public half.
pub fn matchesKey(key: PrivateKey, public_key: certificate.PublicKey) bool {
    @setRuntimeSafety(true);
    return switch (key.state.material.expose().*) {
        .rsa => |*k| switch (public_key) {
            .rsa => |p| std.mem.eql(u8, k.n[0..k.size], p.modulus) and std.mem.eql(u8, k.e[0..k.exponent_size], p.exponent),
            else => false,
        },
        .p256 => |*k| switch (public_key) {
            .ec => |p| p.curve == .p256 and std.mem.eql(u8, p.bytes, &k.public_key.toUncompressedSec1()),
            else => false,
        },
        .p384 => |*k| switch (public_key) {
            .ec => |p| p.curve == .p384 and std.mem.eql(u8, p.bytes, &k.public_key.toUncompressedSec1()),
            else => false,
        },
        .ed25519 => |*k| switch (public_key) {
            .ed25519 => |p| std.mem.eql(u8, p, &k.public_key.toBytes()),
            else => false,
        },
        .mldsa => |*k| switch (public_key) {
            .mldsa => |p| p.level == k.level and std.mem.eql(u8, p.bytes, k.publicKey()),
            else => false,
        },
    };
}
/// The longest SubjectPublicKeyInfo `publicKeyInfo` writes: ML-DSA-87's.
pub const max_public_key_info = certificate.Algorithm.max_public_key_info;

/// This key's public half as the DER SubjectPublicKeyInfo its certificate would carry, in `out`:
/// what a raw public key (RFC 7250, `Identity.initRawKey`) or a pin is made of.
pub fn publicKeyInfo(key: PrivateKey, out: *[max_public_key_info]u8) []const u8 {
    @setRuntimeSafety(true);
    var point: [97]u8 = undefined;
    const public: certificate.PublicKey = switch (key.state.material.expose().*) {
        .rsa => |*k| .{ .rsa = .{ .modulus = k.n[0..k.size], .exponent = k.e[0..k.exponent_size] } },
        .p256 => |*k| blk: {
            point[0..65].* = k.public_key.toUncompressedSec1();
            break :blk .{ .ec = .{ .curve = .p256, .bytes = point[0..65] } };
        },
        .p384 => |*k| blk: {
            point = k.public_key.toUncompressedSec1();
            break :blk .{ .ec = .{ .curve = .p384, .bytes = &point } };
        },
        .ed25519 => |*k| blk: {
            point[0..32].* = k.public_key.toBytes();
            break :blk .{ .ed25519 = point[0..32] };
        },
        .mldsa => |*k| .{ .mldsa = .{ .level = k.level, .bytes = k.publicKey() } },
    };
    // unreachable: a private key is never restricted to RSASSA-PSS.
    return certificate.Algorithm.encodePublicKey(public, out) catch unreachable;
}
/// The most noise bytes one signature draws: RSA's blinding seed and salt.
pub const max_noise = @max(Sign.P384.noise_length, Sign.rsa.noise_length);
/// The longest signature `sign` writes: ML-DSA-87's, 4627 bytes.
pub const max_signature = @max(Sign.max_signature, mldsa.Scheme(.mldsa87).signature_length);

pub const SignError = error{ UnsupportedAlgorithm, InvalidNoise, SigningFailed };

/// How many bytes of fresh noise one signature draws: ECDSA on P-256 and P-384 hedges its
/// nonces with 32 or 48, Ed25519 is deterministic (zero), ML-DSA hedges with 32, and RSA draws
/// 96 for every scheme, a 32-byte blinding seed and room for the longest PSS salt.
pub fn noiseLength(key: PrivateKey) usize {
    @setRuntimeSafety(true);
    return switch (key.state.material.expose().*) {
        .rsa => Sign.rsa.noise_length,
        .p256 => Sign.P256.noise_length,
        .p384 => Sign.P384.noise_length,
        .ed25519 => 0,
        .mldsa => 32,
    };
}

/// Signs `message` under `algorithm`, which must be one this key's type and curve can make:
/// ECDSA with SHA-256, SHA-384 or SHA-512 on P-256 or P-384 (a hash other than the curve's own
/// as RFC 6979's bits2int takes it: TLS 1.2 and X.509 bind the hash, not the curve), Ed25519,
/// and for RSA `.pss` (MGF1 on
/// the same hash, a salt as long as the hash, as TLS requires) or `.rsa` (PKCS#1 v1.5, for
/// TLS 1.2) on SHA-256, SHA-384 or SHA-512, and ML-DSA of the key's parameter set (pure, an
/// empty context, hedged). `noise` is exactly `noiseLength` fresh bytes. Returns the DER
/// ECDSA-Sig-Value, the 64 Ed25519 bytes, the ML-DSA signature, or the modulus-sized RSA
/// signature in `out`; an RSA signature is checked against the public key before it is returned.
pub fn sign(key: PrivateKey, algorithm: certificate.Algorithm.Signature, message: []const u8, noise: []const u8, out: *[max_signature]u8) SignError![]const u8 {
    return aegis.secret.scrubbed(sign_stack, signMessage, .{ key, algorithm, message, noise, out });
}

fn signMessage(key: PrivateKey, algorithm: certificate.Algorithm.Signature, message: []const u8, noise: []const u8, out: *[max_signature]u8) SignError![]const u8 {
    @setRuntimeSafety(true);
    if (noise.len != key.noiseLength()) return error.InvalidNoise;
    switch (key.state.material.expose().*) {
        .rsa => |*rsa| return rsaSign(SignError, &rsa.crt, algorithm, message, false, noise[0..Sign.rsa.noise_length], out),
        .p256 => |*pair| {
            return ecdsaSign(SignError, Sign.P256, &pair.secret_key.bytes, algorithm, message, false, noise[0..Sign.P256.noise_length], out);
        },
        .p384 => |*pair| {
            return ecdsaSign(SignError, Sign.P384, &pair.secret_key.bytes, algorithm, message, false, noise[0..Sign.P384.noise_length], out);
        },
        .ed25519 => |*pair| {
            if (algorithm != .ed25519) return error.UnsupportedAlgorithm;
            Sign.ed25519.sign(&pair.secret_key.bytes, message, out[0..Sign.ed25519.signature_length]) catch return error.SigningFailed;
            return out[0..Sign.ed25519.signature_length];
        },
        .mldsa => |*k| {
            if (algorithm != .mldsa or algorithm.mldsa != k.level) return error.UnsupportedAlgorithm;
            switch (k.level) {
                inline else => |tag| {
                    const M = mldsa.Scheme(tag);
                    M.sign(k.secret[0..M.secret_key_length], message, "", noise[0..M.noise_length], out[0..M.signature_length]);
                    return out[0..M.signature_length];
                },
            }
        },
    }
}

pub const SignDigestError = SignError || error{InvalidDigest};

/// `sign` over a digest the caller already computed with `algorithm`'s hash, as TLS 1.2 keeps
/// its transcript: 32, 48 or 64 bytes for SHA-256, SHA-384 or SHA-512, `InvalidDigest`
/// otherwise. ECDSA under any of them (as `sign`), or RSA (PSS or PKCS#1 v1.5, with the same
/// public check); Ed25519 signs the message itself and has no digest form.
pub fn signDigest(key: PrivateKey, algorithm: certificate.Algorithm.Signature, digest: []const u8, noise: []const u8, out: *[max_signature]u8) SignDigestError![]const u8 {
    return aegis.secret.scrubbed(sign_stack, signPrehashed, .{ key, algorithm, digest, noise, out });
}

fn signPrehashed(key: PrivateKey, algorithm: certificate.Algorithm.Signature, digest: []const u8, noise: []const u8, out: *[max_signature]u8) SignDigestError![]const u8 {
    @setRuntimeSafety(true);
    if (noise.len != key.noiseLength()) return error.InvalidNoise;
    return switch (key.state.material.expose().*) {
        .rsa => |*rsa| rsaSign(SignDigestError, &rsa.crt, algorithm, digest, true, noise[0..Sign.rsa.noise_length], out),
        .p256 => |*pair| {
            return ecdsaSign(SignDigestError, Sign.P256, &pair.secret_key.bytes, algorithm, digest, true, noise[0..Sign.P256.noise_length], out);
        },
        .p384 => |*pair| {
            return ecdsaSign(SignDigestError, Sign.P384, &pair.secret_key.bytes, algorithm, digest, true, noise[0..Sign.P384.noise_length], out);
        },
        .ed25519, .mldsa => error.UnsupportedAlgorithm,
    };
}

/// An ECDSA signature under `algorithm` over `input`, a message or, when `prehashed`, its digest:
/// any of the three hashes on either curve, a hash not the curve's own taken as RFC 6979's
/// bits2int (`Sign.Ecdsa.signAnyDigest`), in DER or P1363 form as `algorithm` names.
fn ecdsaSign(comptime E: type, comptime S: type, secret: *const [S.secret_length]u8, algorithm: certificate.Algorithm.Signature, input: []const u8, comptime prehashed: bool, noise: *const [S.noise_length]u8, out: *[max_signature]u8) E![]const u8 {
    @setRuntimeSafety(true);
    const hash: certificate.Algorithm.Hash, const form: Sign.Form = switch (algorithm) {
        .ecdsa => |h| .{ h, .der },
        .ecdsa_p1363 => |h| .{ h, .p1363 },
        else => return error.UnsupportedAlgorithm,
    };
    switch (hash) {
        inline else => |tag| {
            const Hash = HashOf(tag);
            var digest: [Hash.digest_length]u8 = undefined;
            if (prehashed) {
                if (input.len != Hash.digest_length) return error.InvalidDigest;
                @memcpy(&digest, input);
            } else Hash.hash(input, &digest, .{});
            return S.signAnyDigest(secret, &digest, noise, form, out[0..Sign.max_signature]) catch error.SigningFailed;
        },
    }
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
            const made = if (pss) Sign.rsa.pssDigest(Hash, key, &digest, noise, out[0..Sign.max_signature]) else Sign.rsa.pkcs1Digest(Hash, key, &digest, noise, out[0..Sign.max_signature]);
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

fn parseReleased(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!void {
    const key = try parseKey(gpa, bytes, options);
    key.deinit();
}

test "a parse and a signature reach less stack than the depths that erase it" {
    const gpa = std.testing.allocator;
    const keys = [_][]const u8{
        @embedFile("crypto/testdata/rsa4096.der"),
        @embedFile("crypto/testdata/rsa2049.der"),
        @embedFile("credentials/testdata/p384.pkcs8.pem"),
        @embedFile("credentials/testdata/p256.pkcs8.pem"),
        @embedFile("credentials/testdata/ed25519.pkcs8.pem"),
        @embedFile("credentials/testdata/mldsa44.seed.pem"),
        @embedFile("credentials/testdata/mldsa65.both.pem"),
        @embedFile("credentials/testdata/mldsa87.expanded.pem"),
        @embedFile("credentials/testdata/rsa.enc-aes256-sha256.pem"),
        @embedFile("credentials/testdata/p384.enc-des3.pem"),
    };
    var parsing: usize = 0;
    var signing: usize = 0;
    for (keys) |bytes| {
        const options: ParseOptions = .{ .passphrase = if (isEncrypted(bytes)) "correct-horse" else null };
        parsing = @max(parsing, aegis.secret.stackReach(4 * parse_stack, parseReleased, .{ gpa, bytes, options }));
        const key = try parse(gpa, bytes, options);
        defer key.deinit();
        var noise: [max_noise]u8 = @splat(0x4e);
        var out: [max_signature]u8 = undefined;
        const algorithms: []const certificate.Algorithm.Signature = switch (key.state.material.expose().*) {
            .rsa => &.{ .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha512, .salt_length = 64 } }, .{ .rsa = .sha256 } },
            .p256 => &.{ .{ .ecdsa = .sha256 }, .{ .ecdsa_p1363 = .sha256 } },
            .p384 => &.{ .{ .ecdsa = .sha384 }, .{ .ecdsa_p1363 = .sha384 } },
            .ed25519 => &.{.ed25519},
            .mldsa => |*k| &.{.{ .mldsa = k.level }},
        };
        for (algorithms) |algorithm| {
            signing = @max(signing, aegis.secret.stackReach(4 * sign_stack, signMessage, .{ key, algorithm, "message", noise[0..key.noiseLength()], &out }));
            if (algorithm == .ed25519 or algorithm == .mldsa) continue;
            const digest: [64]u8 = @splat(0x44);
            const length: usize = switch (algorithm) {
                .pss => 64,
                .rsa => 32,
                .ecdsa, .ecdsa_p1363 => |hash| if (hash == .sha256) 32 else 48,
                else => unreachable,
            };
            signing = @max(signing, aegis.secret.stackReach(4 * sign_stack, signPrehashed, .{ key, algorithm, digest[0..length], noise[0..key.noiseLength()], &out }));
        }
    }
    if (parsing >= parse_stack or signing >= sign_stack) {
        std.debug.print("stack reached: parsing {d} of {d}, signing {d} of {d}\n", .{ parsing, parse_stack, signing, sign_stack });
        return error.TestUnexpectedResult;
    }
}
