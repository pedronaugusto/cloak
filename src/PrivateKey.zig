//! A retained immutable private key. Final release wipes all owned material.
const std = @import("std");
const builtin = @import("builtin");
const Der = @import("wire/Der.zig");
const parser = @import("credentials/Key.zig");
const certificate = @import("certificate.zig");
const Sign = @import("credentials/Sign.zig");
const mldsa = @import("crypto/mldsa.zig");
const Pbe = @import("credentials/Pbe.zig");
const pkcs1 = @import("crypto/pkcs1.zig");
const Ecdh = @import("credentials/Ecdh.zig");
const Rsa = @import("credentials/Rsa.zig");
const rsa_keygen = @import("crypto/rsa.zig").keygen;
const aegis = @import("aegis");
const Secret = aegis.Secret;
const PrivateKey = @This();
/// Private: shares one immutable owner, never a caller's passphrase or DER.
state: Handle,
const Handle = aegis.Shared(State, release);
const State = struct {
    gpa: std.mem.Allocator,
    material: Secret(parser.Material),
};
pub const ParseError = parser.ParseError;
pub const ParseOptions = parser.Options;
/// Stack a parse and a signature reach below their entry, erased when they return: the frames
/// of the parser and the kernels, whose spills and copies of key material no owner can name.
/// A test measures every key type and scheme against them in each build mode. A key is built
/// straight into its shared block (aegis `Shared.createWith`), never in a frame first.
/// Debug's parsing depth is Zig's own x86_64 backend's, the one a Debug build for x86_64 Linux
/// compiles with: its frames are larger than LLVM's (an encrypted RSA key's parse reaches 108 KiB
/// there, 90 KiB under LLVM).
const parse_stack: usize = if (builtin.mode == .debug) 128 * 1024 else 64 * 1024;
/// Debug's signing depth is P-521's: its nine-limb scalar arithmetic unrolls without
/// optimization into a frame per step (91 KiB measured); the optimized builds stay below 24 KiB.
const sign_stack: usize = if (builtin.mode == .debug) 128 * 1024 else 24 * 1024;

pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!PrivateKey {
    return aegis.secret.scrubbed(parse_stack, parseKey, .{ gpa, bytes, options });
}

fn parseKey(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!PrivateKey {
    @setRuntimeSafety(true);
    const Build = struct {
        fn run(c: struct { std.mem.Allocator, []const u8, ParseOptions }, state: *State) ParseError!void {
            state.* = .{ .gpa = c[0], .material = .init(undefined) };
            errdefer state.material.deinit();
            try parser.parse(c[0], c[1], c[2], state.material.exposeMut());
        }
    };
    return .{ .state = try .createWith(gpa, .{ gpa, bytes, options }, Build.run) };
}
/// Package-internal (`Pkcs12`): a key bag's key, a PrivateKeyInfo or, when `shrouded`, an
/// EncryptedPrivateKeyInfo opened with `password` in the form the file's MAC verified.
pub fn parseBag(gpa: std.mem.Allocator, bag: []const u8, shrouded: bool, password: *const Pbe.Password, options: ParseOptions) ParseError!PrivateKey {
    return aegis.secret.scrubbed(parse_stack, parseBagKey, .{ gpa, bag, shrouded, password, options });
}

fn parseBagKey(gpa: std.mem.Allocator, bag: []const u8, shrouded: bool, password: *const Pbe.Password, options: ParseOptions) ParseError!PrivateKey {
    @setRuntimeSafety(true);
    const Build = struct {
        fn run(c: struct { std.mem.Allocator, []const u8, bool, *const Pbe.Password, ParseOptions }, state: *State) ParseError!void {
            state.* = .{ .gpa = c[0], .material = .init(undefined) };
            errdefer state.material.deinit();
            const out = state.material.exposeMut();
            if (c[2]) try parser.encryptedWith(c[0], c[1], c[3], c[4], out) else try parser.parsePlain(c[1], c[4], out);
        }
    };
    return .{ .state = try .createWith(gpa, .{ gpa, bag, shrouded, password, options }, Build.run) };
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
    /// An X25519 key (RFC 7748, a JWK's OKP `d` and `x`, RFC 8037): the 32-byte private key and
    /// optionally the 32-byte public key. It agrees (`agree`) and signs nothing.
    x25519: struct { d: []const u8, public: ?[]const u8 = null },
    /// An ML-DSA key by its 32-byte seed (RFC 9964's AKP `priv`, the only private form it
    /// defines) and optionally its encoded public key (the AKP's `pub`).
    mldsa: struct { level: certificate.Algorithm.MlDsa, seed: []const u8, public: ?[]const u8 = null },
};

pub const ComponentsError = std.mem.Allocator.Error || error{ InvalidKey, UnsupportedKey };

pub fn fromComponents(gpa: std.mem.Allocator, components: Components) ComponentsError!PrivateKey {
    return aegis.secret.scrubbed(parse_stack, buildKey, .{ gpa, components });
}

fn buildKey(gpa: std.mem.Allocator, components: Components) ComponentsError!PrivateKey {
    @setRuntimeSafety(true);
    const Build = struct {
        fn run(c: struct { std.mem.Allocator, Components }, state: *State) error{ InvalidKey, UnsupportedKey }!void {
            state.* = .{ .gpa = c[0], .material = .init(undefined) };
            errdefer state.material.deinit();
            const out = state.material.exposeMut();
            (switch (c[1]) {
                .ec => |ec| parser.ecKey(ec.curve, ec.d, ec.public, out),
                .ed25519 => |ed| parser.ed25519Key(ed.seed, ed.public, out),
                .rsa => |rsa| parser.rsaFromIntegers(&.{ rsa.n, rsa.e, rsa.d, rsa.p, rsa.q, rsa.dp, rsa.dq, rsa.qi }, out),
                .x25519 => |x| parser.x25519Key(x.d, x.public, out),
                .mldsa => |m| parser.mldsaFromSeed(m.level, m.seed, m.public, out),
            }) catch |err| return switch (err) {
                error.UnsupportedKey => error.UnsupportedKey,
                else => error.InvalidKey,
            };
        }
    };
    return .{ .state = try .createWith(gpa, .{ gpa, components }, Build.run) };
}

/// The kinds of key `generate` makes. An X25519 key only agrees (`agree`): an ephemeral key for
/// ECDH, as JWE's ECDH-ES draws one per message.
pub const Kind = union(enum) { p256, p384, p521, ed25519, x25519, mldsa44, mldsa65, mldsa87, rsa: RsaSize };
/// An RSA key's modulus, in bits: FIPS 186-5's sizes, e = 65537.
pub const RsaSize = rsa_keygen.Size;
/// `GenerationFailed`: the source gave no prime in 2^16 candidates, which a working one never does.
pub const GenerateError = std.mem.Allocator.Error || error{ EntropyUnavailable, GenerationFailed };

/// A new key of `kind` from `io.randomSecure`, built by the constructor a parsed key of its kind
/// goes through: an EC scalar drawn until it is in range, an Ed25519 or ML-DSA seed, an X25519
/// private key (clamped where it is used, RFC 7748), an RSA
/// key's numbers (FIPS 186-5 A.1.3, `crypto/rsa/keygen.zig`) checked as a parsed key's are.
pub fn generate(gpa: std.mem.Allocator, io: std.Io, kind: Kind) GenerateError!PrivateKey {
    return aegis.secret.scrubbed(parse_stack, generateKey, .{ gpa, io, kind });
}

fn generateKey(gpa: std.mem.Allocator, io: std.Io, kind: Kind) GenerateError!PrivateKey {
    @setRuntimeSafety(true);
    const Build = struct {
        fn run(c: struct { std.mem.Allocator, std.Io, Kind }, state: *State) GenerateError!void {
            state.* = .{ .gpa = c[0], .material = .init(undefined) };
            errdefer state.material.deinit();
            try generateInto(c[1], c[2], state.material.exposeMut());
        }
    };
    return .{ .state = try .createWith(gpa, .{ gpa, io, kind }, Build.run) };
}

/// A new key of `kind` into `out`: the draws and the RSA integers in this frame, which `scrubbed`
/// erases, the key in its shared block.
fn generateInto(io: std.Io, kind: Kind, out: *parser.Material) GenerateError!void {
    @setRuntimeSafety(true);
    var draw_owner: Secret([66]u8) = .init(undefined);
    defer draw_owner.deinit();
    const draw = draw_owner.exposeMut();
    switch (kind) {
        .p256, .p384, .p521 => {
            const curve: parser.EcCurve, const width: usize = switch (kind) {
                .p256 => .{ .p256, 32 },
                .p384 => .{ .p384, 48 },
                else => .{ .p521, 66 },
            };
            // A draw as wide as the order (P-521's top seven bits cleared), out of range one
            // time in 2^32 (P-256) or far less: a retry, never a bias.
            var attempts: usize = 0;
            while (true) : (attempts += 1) {
                if (attempts == 64) return error.EntropyUnavailable;
                io.randomSecure(draw[0..width]) catch return error.EntropyUnavailable;
                if (curve == .p521) draw[0] &= 0x01;
                if (parser.ecKey(curve, draw[0..width], null, out)) break else |_| {}
            }
        },
        .ed25519 => {
            io.randomSecure(draw[0..32]) catch return error.EntropyUnavailable;
            // unreachable: every 32-byte seed is a key.
            parser.ed25519Key(draw[0..32], null, out) catch unreachable;
        },
        .x25519 => {
            io.randomSecure(draw[0..32]) catch return error.EntropyUnavailable;
            // unreachable: every 32 bytes are an X25519 private key.
            parser.x25519Key(draw[0..32], null, out) catch unreachable;
        },
        .mldsa44, .mldsa65, .mldsa87 => {
            io.randomSecure(draw[0..32]) catch return error.EntropyUnavailable;
            const level: mldsa.Level = switch (kind) {
                .mldsa44 => .mldsa44,
                .mldsa65 => .mldsa65,
                else => .mldsa87,
            };
            // unreachable: every 32-byte seed is a key.
            parser.mldsaFromSeed(level, draw[0..32], null, out) catch unreachable;
        },
        .rsa => |size| {
            var integers_owner: Secret(rsa_keygen.Integers) = .init(undefined);
            defer integers_owner.deinit();
            const integers = integers_owner.exposeMut();
            const entropy: rsa_keygen.IoSource = .{ .io = io };
            try rsa_keygen.generate(size, &entropy, integers);
            // The validator a parsed key's numbers take; a generated key it refuses is the
            // generator's fault, never the caller's.
            parser.rsaFromIntegers(&integers.slices(), out) catch return error.GenerationFailed;
        },
    }
}

pub const Pkcs8Error = std.mem.Allocator.Error;

/// The key as a DER PrivateKeyInfo (RFC 5958), what `parse` reads back, in a secret owner the
/// caller releases (`deinit(gpa)`): RSA's RSAPrivateKey (RFC 8017), an EC key with its public
/// point (RFC 5915), Ed25519's and X25519's private key (RFC 8410), ML-DSA's seed, or its
/// expanded key when the seed is not known (RFC 9881).
pub fn pkcs8(key: PrivateKey, gpa: std.mem.Allocator) Pkcs8Error!aegis.SecretBytes {
    return aegis.secret.scrubbed(sign_stack, writePkcs8, .{ key, gpa });
}

fn writePkcs8(key: PrivateKey, gpa: std.mem.Allocator) Pkcs8Error!aegis.SecretBytes {
    @setRuntimeSafety(true);
    const Builder = @import("wire/Builder.zig");
    var b = Builder.init(gpa);
    defer b.deinit();
    const outer = try b.open(0x30);
    try b.small(0);
    switch (key.state.get().material.expose().*) {
        .rsa => |*rsa| {
            try b.raw("\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00");
            const wrapped = try b.open(0x04);
            const sequence = try b.open(0x30);
            try b.small(0);
            var numbers_owner: Secret(Rsa.Numbers) = .init(undefined);
            defer numbers_owner.deinit();
            const numbers = numbers_owner.exposeMut();
            numbers.of(rsa);
            for (numbers.slices()) |number| try b.unsigned(number);
            try b.close(sequence);
            try b.close(wrapped);
        },
        inline .p256, .p384, .p521 => |*pair, tag| {
            const algorithm = try b.open(0x30);
            try b.element(0x06, "\x2a\x86\x48\xce\x3d\x02\x01");
            try b.element(0x06, switch (tag) {
                .p256 => "\x2a\x86\x48\xce\x3d\x03\x01\x07",
                .p384 => "\x2b\x81\x04\x00\x22",
                else => "\x2b\x81\x04\x00\x23",
            });
            try b.close(algorithm);
            const wrapped = try b.open(0x04);
            const ec = try b.open(0x30);
            try b.small(1);
            try b.element(0x04, &pair.secret);
            const point = try b.open(0xa1);
            try b.bits(&pair.public);
            try b.close(point);
            try b.close(ec);
            try b.close(wrapped);
        },
        .ed25519 => |*pair| {
            try b.raw("\x30\x05\x06\x03\x2b\x65\x70");
            const wrapped = try b.open(0x04);
            try b.element(0x04, pair.secret[0..32]);
            try b.close(wrapped);
        },
        .x25519 => |*pair| {
            try b.raw("\x30\x05\x06\x03\x2b\x65\x6e");
            const wrapped = try b.open(0x04);
            try b.element(0x04, &pair.secret);
            try b.close(wrapped);
        },
        .mldsa => |*k| {
            const algorithm = try b.open(0x30);
            try b.element(0x06, "\x60\x86\x48\x01\x65\x03\x04\x03" ++ switch (k.level) {
                .mldsa44 => "\x11",
                .mldsa65 => "\x12",
                .mldsa87 => "\x13",
            });
            try b.close(algorithm);
            // RFC 9881's seed form when the seed is known, the expanded key when it is not.
            const wrapped = try b.open(0x04);
            if (k.seed) |*seed| {
                try b.element(0x80, seed);
            } else switch (k.level) {
                inline else => |level| try b.element(0x04, k.secret[0..mldsa.Scheme(level).secret_key_length]),
            }
            try b.close(wrapped);
        },
    }
    try b.close(outer);
    return b.take();
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
    return switch (key.state.get().material.expose().*) {
        .rsa => |*k| switch (public_key) {
            .rsa => |p| std.mem.eql(u8, k.n[0..k.size], p.modulus) and std.mem.eql(u8, k.e[0..k.exponent_size], p.exponent),
            else => false,
        },
        inline .p256, .p384, .p521 => |*k, tag| switch (public_key) {
            .ec => |p| p.curve == @field(certificate.Algorithm.Curve, @tagName(tag)) and std.mem.eql(u8, p.bytes, &k.public),
            else => false,
        },
        .ed25519 => |*k| switch (public_key) {
            .ed25519 => |p| std.mem.eql(u8, p, k.public()),
            else => false,
        },
        .mldsa => |*k| switch (public_key) {
            .mldsa => |p| p.level == k.level and std.mem.eql(u8, p.bytes, k.publicKey()),
            else => false,
        },
        .x25519 => |*k| switch (public_key) {
            .x25519 => |p| std.mem.eql(u8, p, &k.public),
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
    const material = key.state.get().material.expose();
    const public: certificate.PublicKey = switch (material.*) {
        .rsa => |*k| .{ .rsa = .{ .modulus = k.n[0..k.size], .exponent = k.e[0..k.exponent_size] } },
        inline .p256, .p384, .p521 => |*k, tag| .{ .ec = .{ .curve = @field(certificate.Algorithm.Curve, @tagName(tag)), .bytes = &k.public } },
        .ed25519 => |*k| .{ .ed25519 = k.public() },
        .mldsa => |*k| .{ .mldsa = .{ .level = k.level, .bytes = k.publicKey() } },
        .x25519 => |*k| .{ .x25519 = &k.public },
    };
    // unreachable: a private key is never restricted to RSASSA-PSS, and its parts are its
    // material's fixed arrays, each within the longest key `out` holds.
    return certificate.Algorithm.encodePublicKey(public, out) catch unreachable;
}
/// The most noise bytes one signature draws: RSA's blinding seed and salt.
pub const max_noise = @max(Sign.P384.noise_length, Sign.rsa.noise_length);
/// The longest signature `sign` writes: ML-DSA-87's, 4627 bytes.
pub const max_signature = @max(Sign.max_signature, mldsa.Scheme(.mldsa87).signature_length);

pub const SignError = error{ UnsupportedAlgorithm, InvalidNoise, SigningFailed };

/// How many bytes of fresh noise one signature draws: ECDSA on P-256, P-384 and P-521 hedges
/// its nonces with 32, 48 or 66, Ed25519 is deterministic (zero), ML-DSA hedges with 32, and RSA draws
/// 96 for every scheme, a 32-byte blinding seed and room for the longest PSS salt.
pub fn noiseLength(key: PrivateKey) usize {
    @setRuntimeSafety(true);
    return switch (key.state.get().material.expose().*) {
        .rsa => Sign.rsa.noise_length,
        .p256 => Sign.P256.noise_length,
        .p384 => Sign.P384.noise_length,
        .p521 => Sign.P521.noise_length,
        .ed25519, .x25519 => 0,
        .mldsa => 32,
    };
}

/// Signs `message` under `algorithm`, which must be one this key's type and curve can make:
/// ECDSA with SHA-256, SHA-384 or SHA-512 on P-256, P-384 or P-521 (a hash other than the curve's own
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
    switch (key.state.get().material.expose().*) {
        .rsa => |*rsa| return rsaSign(SignError, &rsa.crt, algorithm, message, false, noise[0..Sign.rsa.noise_length], out),
        .p256 => |*k| {
            return ecdsaSign(SignError, Sign.P256, &k.secret, algorithm, message, false, noise[0..Sign.P256.noise_length], out);
        },
        .p384 => |*k| {
            return ecdsaSign(SignError, Sign.P384, &k.secret, algorithm, message, false, noise[0..Sign.P384.noise_length], out);
        },
        .p521 => |*k| {
            return ecdsaSign(SignError, Sign.P521, &k.secret, algorithm, message, false, noise[0..Sign.P521.noise_length], out);
        },
        .ed25519 => |*k| {
            if (algorithm != .ed25519) return error.UnsupportedAlgorithm;
            Sign.ed25519.sign(&k.secret, message, out[0..Sign.ed25519.signature_length]) catch return error.SigningFailed;
            return out[0..Sign.ed25519.signature_length];
        },
        .x25519 => return error.UnsupportedAlgorithm,
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
    return switch (key.state.get().material.expose().*) {
        .rsa => |*rsa| rsaSign(SignDigestError, &rsa.crt, algorithm, digest, true, noise[0..Sign.rsa.noise_length], out),
        .p256 => |*k| {
            return ecdsaSign(SignDigestError, Sign.P256, &k.secret, algorithm, digest, true, noise[0..Sign.P256.noise_length], out);
        },
        .p384 => |*k| {
            return ecdsaSign(SignDigestError, Sign.P384, &k.secret, algorithm, digest, true, noise[0..Sign.P384.noise_length], out);
        },
        .p521 => |*k| {
            return ecdsaSign(SignDigestError, Sign.P521, &k.secret, algorithm, digest, true, noise[0..Sign.P521.noise_length], out);
        },
        .ed25519, .mldsa, .x25519 => error.UnsupportedAlgorithm,
    };
}

/// The longest shared secret `agree` writes: P-521's x coordinate.
pub const max_shared = Ecdh.P521.scalar_length;

pub const AgreeError = error{
    /// An RSA, Ed25519 or ML-DSA key: they agree on nothing.
    UnsupportedAlgorithm,
    /// Not a public key of this key's curve: for P-256, P-384 and P-521 an uncompressed SEC 1
    /// point on the curve, for X25519 32 bytes.
    InvalidPublicKey,
    /// The shared point is the identity, or X25519's result all zeros (a peer of small order).
    IdentityElement,
};

/// The shared secret of this key and `peer`'s public key: ECDH's x coordinate (SEC 1 3.3.1) on
/// P-256, P-384 and P-521, X25519's 32 bytes (RFC 7748 6.1), in `out`, a secret the caller
/// erases. The peer is checked first (on the curve, not the identity; for X25519 a result of
/// all zeros is refused), and the scalar walk is the constant-time one of the key's
/// construction.
pub fn agree(key: PrivateKey, peer: []const u8, out: *[max_shared]u8) AgreeError![]const u8 {
    @setRuntimeSafety(true);
    // Each agreement erases its own frame (`Ecdh`), reading the scalar where the key holds it.
    const length: usize, const made = switch (key.state.get().material.expose().*) {
        .p256 => |*k| .{ Ecdh.P256.scalar_length, Ecdh.P256.agree(&k.secret, peer, out[0..Ecdh.P256.scalar_length]) },
        .p384 => |*k| .{ Ecdh.P384.scalar_length, Ecdh.P384.agree(&k.secret, peer, out[0..Ecdh.P384.scalar_length]) },
        .p521 => |*k| .{ Ecdh.P521.scalar_length, Ecdh.P521.agree(&k.secret, peer, out[0..Ecdh.P521.scalar_length]) },
        .x25519 => |*k| .{ Ecdh.X25519.length, Ecdh.X25519.agree(&k.secret, peer, out[0..Ecdh.X25519.length]) },
        .rsa, .ed25519, .mldsa => return error.UnsupportedAlgorithm,
    };
    made catch |err| return switch (err) {
        error.InvalidPublicKey => error.InvalidPublicKey,
        error.IdentityElement => error.IdentityElement,
        // unreachable: a held key's scalar was checked in range when the key was made.
        error.InvalidScalar => unreachable,
    };
    return out[0..length];
}

/// The longest message `decrypt` writes: a 4096-bit key's, under OAEP's shortest hash.
pub const max_plaintext = pkcs1.max_em;

pub const DecryptError = error{
    /// Not an RSA key: only RSA decrypts.
    UnsupportedAlgorithm,
    InvalidNoise,
    /// The one answer to every ciphertext that does not decrypt: of the wrong length, at or
    /// above the modulus, or whose encoding does not hold. Which, nothing says.
    DecryptionFailed,
};

/// Decrypts an RSAES-OAEP `ciphertext` (RFC 8017 7.1.2) made to this key under `scheme`: the
/// blinded private operation, checked against the public key, then the encoding decoded in
/// constant time. `noise` is exactly `noiseLength` fresh bytes (the blinding seed draws on
/// the first 32). Returns the message in `out`, a secret the caller erases.
pub fn decrypt(key: PrivateKey, scheme: certificate.Algorithm.Encryption, ciphertext: []const u8, noise: []const u8, out: *[max_plaintext]u8) DecryptError![]const u8 {
    return aegis.secret.scrubbed(sign_stack, decryptMessage, .{ key, scheme, ciphertext, noise, out });
}

fn decryptMessage(key: PrivateKey, scheme: certificate.Algorithm.Encryption, ciphertext: []const u8, noise: []const u8, out: *[max_plaintext]u8) DecryptError![]const u8 {
    @setRuntimeSafety(true);
    if (noise.len != key.noiseLength()) return error.InvalidNoise;
    const rsa = switch (key.state.get().material.expose().*) {
        .rsa => |*k| &k.crt,
        else => return error.UnsupportedAlgorithm,
    };
    // The length and the range are public: the ciphertext is.
    if (ciphertext.len != rsa.size) return error.DecryptionFailed;
    var em_owner: Secret([pkcs1.max_em]u8) = .init(undefined);
    defer em_owner.deinit();
    const em = em_owner.exposeMut();
    rsa.private(ciphertext, noise[0..Sign.rsa.seed_length], em[0..rsa.size]) catch return error.DecryptionFailed;
    return switch (scheme) {
        .oaep => |oaep| pkcs1.decode(oaep, em[0..rsa.size], out),
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
    return .{ .state = key.state.retain() };
}
pub fn deinit(key: PrivateKey) void {
    var handle = key.state;
    handle.release();
}
/// The last handle's cleanup.
fn release(state: *State) void {
    state.material.deinit();
}
test {
    @setRuntimeSafety(true);
    _ = @import("credentials/Key_test.zig");
    _ = @import("credentials/Generate_test.zig");
    _ = @import("credentials/Agree_test.zig");
}

fn parseReleased(gpa: std.mem.Allocator, bytes: []const u8, options: ParseOptions) ParseError!void {
    const key = try parseKey(gpa, bytes, options);
    key.deinit();
}

fn generateReleased(gpa: std.mem.Allocator, io: std.Io, kind: Kind) GenerateError!void {
    const key = try generateKey(gpa, io, kind);
    key.deinit();
}

fn pkcs8Released(key: PrivateKey, gpa: std.mem.Allocator) Pkcs8Error!void {
    var der = try writePkcs8(key, gpa);
    der.deinit(gpa);
}

test "a parse, a generation, a signature, a decryption and a PKCS#8 reach less stack than the depths that erase it" {
    const gpa = std.testing.allocator;
    const keys = [_][]const u8{
        @embedFile("crypto/testdata/rsa4096.der"),
        @embedFile("crypto/testdata/rsa2049.der"),
        @embedFile("credentials/testdata/p384.pkcs8.pem"),
        @embedFile("credentials/testdata/p521.pkcs8.pem"),
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
    var decrypting: usize = 0;
    for (keys) |bytes| {
        const options: ParseOptions = .{ .passphrase = if (isEncrypted(bytes)) "correct-horse" else null };
        parsing = @max(parsing, aegis.secret.stackReach(4 * parse_stack, parseReleased, .{ gpa, bytes, options }));
        const key = try parse(gpa, bytes, options);
        defer key.deinit();
        var noise: [max_noise]u8 = @splat(0x4e);
        var out: [max_signature]u8 = undefined;
        const algorithms: []const certificate.Algorithm.Signature = switch (key.state.get().material.expose().*) {
            .rsa => &.{ .{ .pss = .{ .hash = .sha512, .mgf_hash = .sha512, .salt_length = 64 } }, .{ .rsa = .sha256 } },
            .p256 => &.{ .{ .ecdsa = .sha256 }, .{ .ecdsa_p1363 = .sha256 } },
            .p384 => &.{ .{ .ecdsa = .sha384 }, .{ .ecdsa_p1363 = .sha384 } },
            .p521 => &.{ .{ .ecdsa = .sha512 }, .{ .ecdsa_p1363 = .sha512 } },
            .ed25519 => &.{.ed25519},
            .mldsa => |*k| &.{.{ .mldsa = k.level }},
            .x25519 => &.{},
        };
        if (key.state.get().material.expose().* == .rsa) {
            // Below the modulus, an encoding that fails: the whole private operation and the
            // whole decoding run all the same.
            var ciphertext: [512]u8 = @splat(1);
            var plain: [max_plaintext]u8 = undefined;
            const size = key.state.get().material.expose().rsa.crt.size;
            const scheme: certificate.Algorithm.Encryption = .{ .oaep = .{ .hash = .sha1, .mgf_hash = .sha1 } };
            decrypting = @max(decrypting, aegis.secret.stackReach(4 * sign_stack, decryptMessage, .{ key, scheme, ciphertext[0..size], noise[0..key.noiseLength()], &plain }));
        }
        for (algorithms) |algorithm| {
            signing = @max(signing, aegis.secret.stackReach(4 * sign_stack, signMessage, .{ key, algorithm, "message", noise[0..key.noiseLength()], &out }));
            if (algorithm == .ed25519 or algorithm == .mldsa) continue;
            const digest: [64]u8 = @splat(0x44);
            const length: usize = switch (algorithm) {
                .pss => 64,
                .rsa => 32,
                .ecdsa, .ecdsa_p1363 => |hash| switch (hash) {
                    .sha256 => 32,
                    .sha384 => 48,
                    .sha512 => 64,
                },
                else => unreachable,
            };
            signing = @max(signing, aegis.secret.stackReach(4 * sign_stack, signPrehashed, .{ key, algorithm, digest[0..length], noise[0..key.noiseLength()], &out }));
        }
        signing = @max(signing, aegis.secret.stackReach(4 * sign_stack, pkcs8Released, .{ key, gpa }));
    }
    // A generation of each kind, RSA's at its widest, builds its key in the parse's depth.
    const kinds = [_]Kind{ .p256, .p384, .p521, .ed25519, .mldsa44, .mldsa87, .{ .rsa = .@"4096" } };
    for (kinds) |kind| parsing = @max(parsing, aegis.secret.stackReach(4 * parse_stack, generateReleased, .{ gpa, std.testing.io, kind }));
    if (parsing >= parse_stack or signing >= sign_stack or decrypting >= sign_stack or decrypting == 0) {
        std.debug.print("stack reached: parsing {d} of {d}, signing {d} and decrypting {d} of {d}\n", .{ parsing, parse_stack, signing, decrypting, sign_stack });
        return error.TestUnexpectedResult;
    }
}
