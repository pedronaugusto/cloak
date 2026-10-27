//! JOSE's primitives (JWE, RFC 7516 and 7518): RSA-OAEP with a held key and to a public key,
//! ECDH on P-256 and X25519 with a held key, AES key wrap, the A128CBC-HS256 composite and
//! AES-GCM under a caller's nonce, beside std's where std has the operation. BoringSSL's rows
//! are taken by its own `bssl speed` on the same machine.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");

const certificates = cloak.certificates;
const cipher = cloak.cipher;
const oaep: certificates.certificate.Algorithm.Encryption = .{ .oaep = .{ .hash = .sha256, .mgf_hash = .sha256 } };

const Context = struct {
    rsa: cloak.PrivateKey,
    rsa_public: certificates.certificate.PublicKey,
    p256: cloak.PrivateKey,
    p256_peer: [65]u8,
    x25519: cloak.PrivateKey,
    x25519_peer: [32]u8,
    noise: [cloak.PrivateKey.max_noise]u8,
    ciphertext: [certificates.encryption.max_ciphertext]u8,
    ciphertext_len: usize,
    kek: [16]u8 = @splat(0x4b),
    cek: [16]u8 = @splat(0x43),
    wrapped: [24]u8 = undefined,
    composite_key: [32]u8 = @splat(0x6b),
    gcm_key: [32]u8 = @splat(0x67),
    iv: [16]u8 = @splat(0x69),
    message: [1024]u8 = @splat(0x6d),
    sealed: [1040]u8 = undefined,
    tag: [16]u8 = undefined,

    fn decrypt(c: *Context, units: u64) !void {
        for (0..units) |_| {
            var out: [cloak.PrivateKey.max_plaintext]u8 = undefined;
            const plain = try c.rsa.decrypt(oaep, c.ciphertext[0..c.ciphertext_len], c.noise[0..c.rsa.noiseLength()], &out);
            std.mem.doNotOptimizeAway(plain);
        }
    }
    fn encrypt(c: *Context, units: u64) !void {
        for (0..units) |_| {
            var out: [certificates.encryption.max_ciphertext]u8 = undefined;
            const sealed = try certificates.encryption.encrypt(c.rsa_public, oaep, &c.cek, c.noise[0..32], &out);
            std.mem.doNotOptimizeAway(sealed);
        }
    }
    fn agreeP256(c: *Context, units: u64) !void {
        for (0..units) |_| {
            var out: [cloak.PrivateKey.max_shared]u8 = undefined;
            std.mem.doNotOptimizeAway(try c.p256.agree(&c.p256_peer, &out));
        }
    }
    fn agreeX25519(c: *Context, units: u64) !void {
        for (0..units) |_| {
            var out: [cloak.PrivateKey.max_shared]u8 = undefined;
            std.mem.doNotOptimizeAway(try c.x25519.agree(&c.x25519_peer, &out));
        }
    }
    fn stdX25519(c: *Context, units: u64) !void {
        const secret: [32]u8 = @splat(0x58);
        for (0..units) |_| std.mem.doNotOptimizeAway(try std.crypto.dh.X25519.scalarmult(secret, c.x25519_peer));
    }
    fn wrap(c: *Context, units: u64) !void {
        for (0..units) |_| {
            try cipher.keyWrap.wrap(&c.kek, &c.cek, &c.wrapped);
            std.mem.doNotOptimizeAway(&c.wrapped);
        }
    }
    fn unwrap(c: *Context, units: u64) !void {
        for (0..units) |_| {
            var key: [16]u8 = undefined;
            try cipher.keyWrap.unwrap(&c.kek, &c.wrapped, &key);
            std.mem.doNotOptimizeAway(&key);
        }
    }
    fn compositeSeal(c: *Context, units: u64) !void {
        const C = cipher.CbcHmac(.a128cbc_hs256);
        for (0..units) |_| {
            C.seal(c.sealed[0..C.ciphertextLength(c.message.len)], &c.tag, &c.message, "aad", &c.iv, &c.composite_key);
            std.mem.doNotOptimizeAway(&c.sealed);
        }
    }
    fn compositeOpen(c: *Context, units: u64) !void {
        const C = cipher.CbcHmac(.a128cbc_hs256);
        for (0..units) |_| {
            var out: [1040]u8 = undefined;
            std.mem.doNotOptimizeAway(try C.open(&out, c.sealed[0..C.ciphertextLength(c.message.len)], &c.tag, "aad", &c.iv, &c.composite_key));
        }
    }
    fn gcmSeal(c: *Context, units: u64) !void {
        const G = cipher.AesGcm(256);
        for (0..units) |_| {
            G.seal(c.sealed[0..c.message.len], &c.tag, &c.message, "aad", c.iv[0..12], &c.gcm_key);
            std.mem.doNotOptimizeAway(&c.sealed);
        }
    }
    fn stdGcmSeal(c: *Context, units: u64) !void {
        const G = std.crypto.aead.aes_gcm.Aes256Gcm;
        for (0..units) |_| {
            G.encrypt(c.sealed[0..c.message.len], &c.tag, &c.message, "aad", c.iv[0..12].*, c.gcm_key);
            std.mem.doNotOptimizeAway(&c.sealed);
        }
    }
};

pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    const io = init.io;
    const gpa = init.gpa;
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &buffer);

    const rsa = try cloak.PrivateKey.parse(gpa, @embedFile("data/rsa.pem"), .{});
    defer rsa.deinit();
    const p256 = try cloak.PrivateKey.parse(gpa, @embedFile("data/p256.pem"), .{});
    defer p256.deinit();
    const x25519_d: [32]u8 = @splat(0x58);
    const x25519 = try cloak.PrivateKey.fromComponents(gpa, .{ .x25519 = .{ .d = &x25519_d } });
    defer x25519.deinit();
    var rsa_info: [cloak.PrivateKey.max_public_key_info]u8 = undefined;
    var p256_info: [cloak.PrivateKey.max_public_key_info]u8 = undefined;
    var context: Context = .{
        .rsa = rsa,
        .rsa_public = try certificates.certificate.parsePublicKey(rsa.publicKeyInfo(&rsa_info)),
        .p256 = p256,
        .p256_peer = (try certificates.certificate.parsePublicKey(p256.publicKeyInfo(&p256_info))).ec.bytes[0..65].*,
        .x25519 = x25519,
        .x25519_peer = std.crypto.dh.X25519.recoverPublicKey(@splat(0x59)),
        .noise = @splat(0x6e),
        .ciphertext = undefined,
        .ciphertext_len = 0,
    };
    context.ciphertext_len = (try certificates.encryption.encrypt(context.rsa_public, oaep, &context.cek, context.noise[0..32], &context.ciphertext)).len;
    try cipher.keyWrap.wrap(&context.kek, &context.cek, &context.wrapped);
    const C = cipher.CbcHmac(.a128cbc_hs256);
    C.seal(context.sealed[0..C.ciphertextLength(context.message.len)], &context.tag, &context.message, "aad", &context.iv, &context.composite_key);

    const Error = anyerror;
    try shakedown.bench.run(Error, gpa, io, &out.interface, &context, &.{
        .{ .name = "RSA-2048 OAEP-256 decrypt (cloak, held key)", .unit = "op", .run = Context.decrypt },
        .{ .name = "RSA-2048 OAEP-256 encrypt (cloak)", .unit = "op", .run = Context.encrypt },
        .{ .name = "P-256 ECDH agree (cloak, held key)", .unit = "op", .run = Context.agreeP256 },
        .{ .name = "X25519 agree (cloak, held key)", .unit = "op", .run = Context.agreeX25519 },
        .{ .name = "X25519 scalarmult (std)", .unit = "op", .run = Context.stdX25519 },
        .{ .name = "AES-128 key wrap, 16-byte key (cloak)", .unit = "op", .run = Context.wrap },
        .{ .name = "AES-128 key unwrap, 16-byte key (cloak)", .unit = "op", .run = Context.unwrap },
        .{ .name = "A128CBC-HS256 seal 1 KiB (cloak)", .unit = "op", .run = Context.compositeSeal },
        .{ .name = "A128CBC-HS256 open 1 KiB (cloak)", .unit = "op", .run = Context.compositeOpen },
        .{ .name = "AES-256-GCM seal 1 KiB (cloak)", .unit = "op", .run = Context.gcmSeal },
        .{ .name = "AES-256-GCM seal 1 KiB (std)", .unit = "op", .run = Context.stdGcmSeal },
    }, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    try out.interface.flush();
}
