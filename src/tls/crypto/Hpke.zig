//! HPKE base mode (RFC 9180) for Encrypted Client Hello: DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
//! and AES-128-GCM, AES-256-GCM or ChaCha20-Poly1305. std has no HPKE; this is its smallest form,
//! built on std's X25519, HMAC and AEADs. Single-shot sender and recipient contexts with the
//! sequence counter RFC 9180 section 5.2 defines; no PSK or authenticated modes, no exporter.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("Suite.zig");

const X25519 = std.crypto.dh.X25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac = std.crypto.auth.hmac.Hmac(Sha256);

pub const Kem = enum(u16) { x25519_sha256 = 0x0020, _ };
pub const Kdf = enum(u16) { hkdf_sha256 = 0x0001, _ };
pub const Aead = enum(u16) {
    aes_128_gcm = 0x0001,
    aes_256_gcm = 0x0002,
    chacha20_poly1305 = 0x0003,
    _,

    pub fn supported(aead: Aead) bool {
        return switch (aead) {
            .aes_128_gcm, .aes_256_gcm, .chacha20_poly1305 => true,
            _ => false,
        };
    }

    fn keyLength(aead: Aead) usize {
        return if (aead == .aes_128_gcm) 16 else 32;
    }

    fn cipher(aead: Aead) suites.Cipher {
        return switch (aead) {
            .aes_128_gcm => .aes_128_gcm,
            .aes_256_gcm => .aes_256_gcm,
            .chacha20_poly1305 => .chacha20_poly1305,
            _ => unreachable, // unreachable: contexts are made only for supported AEADs
        };
    }
};

/// The KDF and AEAD of a context; the KEM is DHKEM(X25519, HKDF-SHA256).
pub const Suite = struct { kdf: Kdf, aead: Aead };

/// An encapsulated key: an X25519 public key.
pub const enc_length = 32;
pub const public_length = 32;
pub const secret_length = 32;
/// Every supported AEAD's tag.
pub const tag_length = 16;
const nonce_length = 12;

pub const Error = error{
    /// A KDF or AEAD outside the supported set.
    UnsupportedSuite,
    /// The encapsulated key is not 32 bytes, or the agreement is the all-zero point.
    InvalidKey,
};
pub const OpenError = error{ AuthenticationFailed, MessageLimit };
pub const SealError = error{MessageLimit};

pub const KeyPair = struct {
    secret: aegis.Secret([secret_length]u8),
    public: [public_length]u8,

    pub fn deinit(self: *KeyPair) void {
        self.secret.deinit();
    }
};

/// DeriveKeyPair (RFC 9180 section 7.1.3) for X25519: the secret key from `ikm`, which must hold
/// at least 32 bytes of entropy.
pub fn deriveKeyPair(ikm: []const u8) KeyPair {
    return aegis.secret.scrubbed(secret_stack, derivePair, .{ikm});
}

fn derivePair(ikm: []const u8) KeyPair {
    @setRuntimeSafety(true);
    var prk = aegis.Secret([32]u8).init(undefined);
    defer prk.deinit();
    labeledExtract(prk.exposeMut(), kem_suite, "", "dkp_prk", &.{ikm});
    var pair: KeyPair = .{ .secret = .init(undefined), .public = undefined };
    labeledExpand(pair.secret.exposeMut(), prk.expose(), kem_suite, "sk", &.{});
    pair.public = X25519.recoverPublicKey(pair.secret.expose().*);
    return pair;
}

/// The public key of an X25519 secret key.
pub fn publicKey(secret: *const [secret_length]u8) [public_length]u8 {
    return aegis.secret.scrubbed(secret_stack, recoverPublic, .{secret});
}

fn recoverPublic(secret: *const [secret_length]u8) [public_length]u8 {
    return X25519.recoverPublicKey(secret.*);
}

/// The stack the key derivations and encapsulations reach (X25519 and the labeled HKDF), which
/// `aegis.secret.scrubbed` erases after each and runs under data-independent timing. A test holds it.
const secret_stack: usize = if (@import("builtin").mode == .debug) 32 * 1024 else 16 * 1024;

/// One direction of an HPKE context: the AEAD key, the base nonce and the sequence number.
pub const Context = struct {
    aead: Aead,
    key: aegis.Secret([32]u8),
    base_nonce: aegis.Secret([nonce_length]u8),
    seq: u64 = 0,

    pub fn deinit(self: *Context) void {
        self.key.deinit();
        self.base_nonce.deinit();
        self.seq = std.math.maxInt(u64);
    }

    fn nonce(self: *const Context) [nonce_length]u8 {
        var out = self.base_nonce.expose().*;
        var counter: [8]u8 = undefined;
        std.mem.writeInt(u64, &counter, self.seq, .big);
        for (out[nonce_length - 8 ..], counter) |*b, c| b.* ^= c;
        return out;
    }

    /// Seals `plaintext` into `out` (ciphertext then tag, `plaintext.len + tag_length` bytes).
    pub fn seal(self: *Context, out: []u8, aad: []const u8, plaintext: []const u8) SealError!void {
        @setRuntimeSafety(true);
        aegis.assert.invariant(out.len == plaintext.len + tag_length, "the sealed output is the plaintext and its tag");
        if (self.seq == std.math.maxInt(u64)) return error.MessageLimit;
        var n = self.nonce();
        defer std.crypto.secureZero(u8, &n);
        switch (self.aead.cipher()) {
            inline else => |c| {
                const A = suites.AeadOf(c);
                A.encrypt(out[0..plaintext.len], out[plaintext.len..][0..tag_length], plaintext, aad, n, self.key.expose()[0..A.key_length].*);
            },
        }
        self.seq += 1;
    }

    /// Opens `ciphertext` (with its tag) into `out` (`ciphertext.len - tag_length` bytes). A
    /// failure leaves the sequence number unchanged and writes nothing usable.
    pub fn open(self: *Context, out: []u8, aad: []const u8, ciphertext: []const u8) OpenError!void {
        @setRuntimeSafety(true);
        if (ciphertext.len < tag_length) return error.AuthenticationFailed;
        aegis.assert.invariant(out.len == ciphertext.len - tag_length, "the opened output is the ciphertext without its tag");
        if (self.seq == std.math.maxInt(u64)) return error.MessageLimit;
        var n = self.nonce();
        defer std.crypto.secureZero(u8, &n);
        const body = ciphertext[0 .. ciphertext.len - tag_length];
        const tag = ciphertext[body.len..][0..tag_length].*;
        switch (self.aead.cipher()) {
            inline else => |c| {
                const A = suites.AeadOf(c);
                A.decrypt(out, body, tag, aad, n, self.key.expose()[0..A.key_length].*) catch {
                    std.crypto.secureZero(u8, out);
                    return error.AuthenticationFailed;
                };
            },
        }
        self.seq += 1;
    }
};

/// SetupBaseS: encapsulates to `public` with the ephemeral key derived from `ikm_e`, writing the
/// encapsulated key to `enc`.
pub fn setupSender(suite: Suite, public: *const [public_length]u8, info: []const u8, ikm_e: []const u8, enc: *[enc_length]u8) Error!Context {
    return aegis.secret.scrubbed(secret_stack, encapsulate, .{ suite, public, info, ikm_e, enc });
}

fn encapsulate(suite: Suite, public: *const [public_length]u8, info: []const u8, ikm_e: []const u8, enc: *[enc_length]u8) Error!Context {
    @setRuntimeSafety(true);
    try check(suite);
    var ephemeral = derivePair(ikm_e);
    defer ephemeral.deinit();
    var dh = aegis.Secret([32]u8).init(X25519.scalarmult(ephemeral.secret.expose().*, public.*) catch return error.InvalidKey);
    defer dh.deinit();
    enc.* = ephemeral.public;
    var shared = aegis.Secret([32]u8).init(undefined);
    defer shared.deinit();
    extractAndExpand(shared.exposeMut(), dh.expose(), enc, public);
    return keySchedule(suite, shared.expose(), info);
}

/// SetupBaseR: decapsulates `enc` with the recipient's secret key.
pub fn setupRecipient(suite: Suite, enc: []const u8, secret: *const [secret_length]u8, info: []const u8) Error!Context {
    return aegis.secret.scrubbed(secret_stack, decapsulate, .{ suite, enc, secret, info });
}

fn decapsulate(suite: Suite, enc: []const u8, secret: *const [secret_length]u8, info: []const u8) Error!Context {
    @setRuntimeSafety(true);
    try check(suite);
    if (enc.len != enc_length) return error.InvalidKey;
    const public = recoverPublic(secret);
    var dh = aegis.Secret([32]u8).init(X25519.scalarmult(secret.*, enc[0..32].*) catch return error.InvalidKey);
    defer dh.deinit();
    var shared = aegis.Secret([32]u8).init(undefined);
    defer shared.deinit();
    extractAndExpand(shared.exposeMut(), dh.expose(), enc[0..32], &public);
    return keySchedule(suite, shared.expose(), info);
}

fn check(suite: Suite) Error!void {
    if (suite.kdf != .hkdf_sha256 or !suite.aead.supported()) return error.UnsupportedSuite;
}

const kem_suite = "KEM\x00\x20";

fn hpkeSuite(suite: Suite) [10]u8 {
    var id: [10]u8 = "HPKE\x00\x20\x00\x00\x00\x00".*;
    std.mem.writeInt(u16, id[6..8], @backingInt(suite.kdf), .big);
    std.mem.writeInt(u16, id[8..10], @backingInt(suite.aead), .big);
    return id;
}

fn extractAndExpand(out: *[32]u8, dh: *const [32]u8, enc: *const [32]u8, public: *const [32]u8) void {
    var prk = aegis.Secret([32]u8).init(undefined);
    defer prk.deinit();
    labeledExtract(prk.exposeMut(), kem_suite, "", "eae_prk", &.{dh});
    labeledExpand(out, prk.expose(), kem_suite, "shared_secret", &.{ enc, public });
}

fn keySchedule(suite: Suite, shared: *const [32]u8, info: []const u8) Context {
    @setRuntimeSafety(true);
    const id = hpkeSuite(suite);
    // mode_base, psk_id_hash, info_hash (RFC 9180 section 5.1).
    var context: [65]u8 = undefined;
    context[0] = 0;
    labeledExtract(context[1..33], &id, "", "psk_id_hash", &.{});
    labeledExtract(context[33..65], &id, "", "info_hash", &.{info});
    var secret = aegis.Secret([32]u8).init(undefined);
    defer secret.deinit();
    labeledExtract(secret.exposeMut(), &id, shared, "secret", &.{});
    var self: Context = .{ .aead = suite.aead, .key = .init(@splat(0)), .base_nonce = .init(undefined) };
    labeledExpand(self.key.exposeMut()[0..suite.aead.keyLength()], secret.expose(), &id, "key", &.{&context});
    labeledExpand(self.base_nonce.exposeMut(), secret.expose(), &id, "base_nonce", &.{&context});
    return self;
}

/// LabeledExtract(salt, label, ikm) = HKDF-Extract(salt, "HPKE-v1" || suite_id || label || ikm).
fn labeledExtract(out: *[32]u8, suite_id: []const u8, salt: []const u8, label: []const u8, ikm: []const []const u8) void {
    var h = Hmac.init(salt);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update("HPKE-v1");
    h.update(suite_id);
    h.update(label);
    for (ikm) |part| h.update(part);
    h.final(out);
}

/// LabeledExpand(prk, label, info, L) for L of at most one SHA-256 block: HKDF-Expand's first
/// block over I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info.
fn labeledExpand(out: []u8, prk: *const [32]u8, suite_id: []const u8, label: []const u8, info: []const []const u8) void {
    @setRuntimeSafety(true);
    aegis.assert.invariant(out.len <= 32, "a labeled expansion is one block");
    var length: [2]u8 = undefined;
    std.mem.writeInt(u16, &length, @intCast(out.len), .big); // safe: at most 32
    var h = Hmac.init(prk);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(&length);
    h.update("HPKE-v1");
    h.update(suite_id);
    h.update(label);
    for (info) |part| h.update(part);
    h.update(&.{1});
    var block: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &block);
    h.final(&block);
    @memcpy(out, block[0..out.len]);
}

test {
    _ = @import("Hpke_test.zig");
}

test "the HPKE key derivations and encapsulations reach less stack than the depth that erases them" {
    const suite: Suite = .{ .kdf = .hkdf_sha256, .aead = .aes_256_gcm };
    const ikm: [32]u8 = @splat(0x35);
    var pair = derivePair(&ikm);
    defer pair.deinit();
    var enc: [enc_length]u8 = undefined;
    const reach = [4]usize{
        aegis.secret.stackReach(4 * secret_stack, derivePair, .{&ikm}),
        aegis.secret.stackReach(4 * secret_stack, recoverPublic, .{pair.secret.expose()}),
        aegis.secret.stackReach(4 * secret_stack, encapsulate, .{ suite, &pair.public, "info", &ikm, &enc }),
        aegis.secret.stackReach(4 * secret_stack, decapsulate, .{ suite, &pair.public, pair.secret.expose(), "info" }),
    };
    std.testing.expect(@max(@max(reach[0], reach[1]), @max(reach[2], reach[3])) < secret_stack) catch |err| {
        std.debug.print("HPKE stack: derive {d}, public {d}, encapsulate {d}, decapsulate {d} of {d}\n", .{ reach[0], reach[1], reach[2], reach[3], secret_stack });
        return err;
    };
}
