//! Bounded key parsing. Private RSA operations are supplied in a later phase.
const std = @import("std");
const Der = @import("../wire/Der.zig");
const Pem = @import("Pem.zig");
const Entropy = @import("Entropy.zig");
const Rsa = @import("Rsa.zig");
const Kdf = @import("Kdf.zig");
const Cbc = @import("Cbc.zig");
const Des3 = @import("Des3.zig");
const oid_des3 = "\x2a\x86\x48\x86\xf7\x0d\x03\x07";
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const Curve = @import("Curve.zig");
const EdKey = @import("EdKey.zig");
pub const Material = union(enum) { rsa: Rsa.Key, p256: P256.KeyPair, p384: P384.KeyPair, ed25519: Ed25519.KeyPair };
pub const Options = struct { entropy: ?Entropy = null, passphrase: ?[]const u8 = null, bytes: usize = 65536, depth: usize = 24, elements: usize = 4096, iterations: usize = 1_000_000, salt_bytes: usize = 1024, password_bytes: usize = 4096 };
pub const ParseError = Der.Error || Pem.Error || Rsa.Error || Cbc.Error || error{ UnsupportedKey, UnsupportedEncryption, PasswordRequired, KdfLimit };
const oid_rsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const oid_ec = "\x2a\x86\x48\xce\x3d\x02\x01";
const oid_ed = "\x2b\x65\x70";
const oid_p256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const oid_p384 = "\x2b\x81\x04\x00\x22";
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, options: Options) ParseError!Material {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    if (bytes.len > options.bytes) return error.InputLimit;
    if (options.passphrase) |password| if (password.len > options.password_bytes) return error.KdfLimit;
    if (std.mem.startsWith(u8, std.mem.trim(u8, bytes, " \t\r\n"), "-----BEGIN ")) {
        var pem = Pem.init(bytes);
        var found: ?Material = null;
        defer if (found != null) std.crypto.secureZero(u8, std.mem.asBytes(&found));
        while (try pem.next(gpa, options.bytes)) |decoded| {
            var block = decoded;
            defer block.deinit(gpa);
            if (std.mem.eql(u8, block.label, "CERTIFICATE")) {
                try validate(block.der, options);
                continue;
            }
            if (found != null) return error.InvalidKey;
            const rsa_label = std.mem.eql(u8, block.label, "RSA PRIVATE KEY");
            const ec_label = std.mem.eql(u8, block.label, "EC PRIVATE KEY");
            const pkcs8_label = std.mem.eql(u8, block.label, "PRIVATE KEY");
            const encrypted_label = std.mem.eql(u8, block.label, "ENCRYPTED PRIVATE KEY");
            if (!rsa_label and !ec_label and !pkcs8_label and !encrypted_label) return error.UnsupportedKey;
            if (block.legacy) {
                if (!rsa_label and !ec_label) return error.InvalidKey;
                const plain = try legacy(gpa, block, options);
                defer wipeFree(gpa, plain);
                try labelShape(plain, rsa_label, ec_label);
                found = try parseDer(plain, options);
            } else if (encrypted_label) {
                found = try encrypted(gpa, block.der, options);
            } else {
                try labelShape(block.der, rsa_label, ec_label);
                found = try parseDer(block.der, options);
            }
        }
        return found orelse error.InvalidKey;
    }
    try validate(bytes, options);
    var probe = (try Der.single(bytes, 0x30)).reader();
    if (probe.peek() == 0x30) return encrypted(gpa, bytes, options);
    return parseDer(bytes, options);
}
fn labelShape(bytes: []const u8, rsa: bool, ec: bool) ParseError!void {
    @setRuntimeSafety(true);
    var r = (try Der.single(bytes, 0x30)).reader();
    _ = try r.expect(2);
    const expected: u8 = if (rsa) 2 else if (ec) 4 else 0x30;
    if (r.peek() != expected) return error.InvalidKey;
}
fn validate(bytes: []const u8, options: Options) ParseError!void {
    @setRuntimeSafety(true);
    try Der.validate(bytes, .{ .bytes = options.bytes, .elements = options.elements, .depth = options.depth });
}
fn parseDer(bytes: []const u8, options: Options) ParseError!Material {
    @setRuntimeSafety(true);
    try validate(bytes, options);
    var r = (try Der.single(bytes, 0x30)).reader();
    const version = try Der.number((try r.expect(2)).value);
    return switch (r.peek() orelse return error.InvalidKey) {
        0x30 => if (version == 0) pkcs8(&r, options) else error.InvalidKey,
        2 => if (version == 0) .{ .rsa = try Rsa.parse(bytes, .{ .entropy = options.entropy }) } else error.InvalidKey,
        4 => if (version == 1) sec1(bytes, null) else error.InvalidKey,
        else => error.InvalidKey,
    };
}
fn pkcs8(r: *Der.Reader, options: Options) ParseError!Material {
    @setRuntimeSafety(true);
    var algorithm = (try r.expect(0x30)).reader();
    const id = (try algorithm.expect(6)).value;
    const parameter = if (!algorithm.empty()) try algorithm.next() else null;
    try algorithm.finish();
    const key = (try r.expect(4)).value;
    // Attributes are SET OF Attribute in an implicit context wrapper.
    if (r.peek() == 0xa0) {
        try attributes((try r.next()).value);
    }
    try r.finish();
    try validate(key, options);
    if (std.mem.eql(u8, id, oid_rsa)) {
        if (parameter) |p| if (p.tag != 5 or p.value.len != 0) return error.InvalidKey;
        return .{ .rsa = try Rsa.parse(key, .{ .entropy = options.entropy }) };
    }
    if (std.mem.eql(u8, id, oid_ec)) {
        const p = parameter orelse return error.InvalidKey;
        if (p.tag != 6) return error.InvalidKey;
        return sec1(key, p.value);
    }
    if (std.mem.eql(u8, id, oid_ed)) {
        if (parameter != null) return error.InvalidKey;
        const seed = (try Der.single(key, 4)).value;
        if (seed.len != 32) return error.InvalidKey;
        var owned_seed = seed[0..32].*;
        defer std.crypto.secureZero(u8, &owned_seed);
        var pair = EdKey.create(&owned_seed) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
        return .{ .ed25519 = pair };
    }
    return error.UnsupportedKey;
}
fn attributes(bytes: []const u8) ParseError!void {
    @setRuntimeSafety(true);
    var set: Der.Reader = .{ .bytes = bytes };
    var previous: ?[]const u8 = null;
    while (!set.empty()) {
        const element = set.expect(0x30) catch return error.InvalidKey;
        if (previous) |prior| if (std.mem.order(u8, prior, element.encoded) == .gt) return error.InvalidKey;
        previous = element.encoded;
        var attribute = element.reader();
        const oid = attribute.expect(6) catch return error.InvalidKey;
        Der.oid(oid.value) catch return error.InvalidKey;
        const values = attribute.expect(0x31) catch return error.InvalidKey;
        if (values.value.len == 0) return error.InvalidKey;
        attribute.finish() catch return error.InvalidKey;
    }
}
fn sec1(bytes: []const u8, outside: ?[]const u8) ParseError!Material {
    @setRuntimeSafety(true);
    var r = (try Der.single(bytes, 0x30)).reader();
    if (try Der.number((try r.expect(2)).value) != 1) return error.InvalidKey;
    const scalar = (try r.expect(4)).value;
    var curve = outside;
    if (r.peek() == 0xa0) {
        const named = (try Der.single((try r.next()).value, 6)).value;
        if (curve) |c| if (!std.mem.eql(u8, c, named)) return error.InvalidKey;
        curve = named;
    }
    const public = if (r.peek() == 0xa1) try Der.octetBits((try Der.single((try r.next()).value, 3)).value) else null;
    try r.finish();
    const named = curve orelse return error.InvalidKey;
    if (std.mem.eql(u8, named, oid_p256)) {
        if (scalar.len != 32) return error.InvalidKey;
        var sk = P256.SecretKey.fromBytes(scalar[0..32].*) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        Curve.validate(P256.Curve, &sk.bytes) catch return error.InvalidKey;
        var point = Curve.base(P256.Curve, .big, &sk.bytes) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        var kp: P256.KeyPair = .{ .secret_key = sk, .public_key = .{ .p = point } };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
        if (public) |p| if (!std.mem.eql(u8, p, &kp.public_key.toUncompressedSec1())) return error.InvalidKey;
        return .{ .p256 = kp };
    }
    if (std.mem.eql(u8, named, oid_p384)) {
        if (scalar.len != 48) return error.InvalidKey;
        var sk = P384.SecretKey.fromBytes(scalar[0..48].*) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        Curve.validate(P384.Curve, &sk.bytes) catch return error.InvalidKey;
        var point = Curve.base(P384.Curve, .big, &sk.bytes) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        var kp: P384.KeyPair = .{ .secret_key = sk, .public_key = .{ .p = point } };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
        if (public) |p| if (!std.mem.eql(u8, p, &kp.public_key.toUncompressedSec1())) return error.InvalidKey;
        return .{ .p384 = kp };
    }
    return error.UnsupportedKey;
}
fn encrypted(gpa: std.mem.Allocator, bytes: []const u8, options: Options) ParseError!Material {
    @setRuntimeSafety(true);
    try validate(bytes, options);
    const password = options.passphrase orelse return error.PasswordRequired;
    var info = (try Der.single(bytes, 0x30)).reader();
    var algorithm = (try info.expect(0x30)).reader();
    if (!std.mem.eql(u8, (try algorithm.expect(6)).value, "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d")) return error.UnsupportedEncryption;
    var parameters = (try algorithm.expect(0x30)).reader();
    try algorithm.finish();
    var kdf = (try parameters.expect(0x30)).reader();
    if (!std.mem.eql(u8, (try kdf.expect(6)).value, "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c")) return error.UnsupportedEncryption;
    var kp = (try kdf.expect(0x30)).reader();
    try kdf.finish();
    const salt = (try kp.expect(4)).value;
    const iterations = try Der.number((try kp.expect(2)).value);
    if (salt.len > options.salt_bytes or iterations == 0 or iterations > options.iterations or iterations > std.math.maxInt(u32)) return error.KdfLimit;
    const key_length = if (kp.peek() == 2) try Der.number((try kp.next()).value) else null;
    var hash: u8 = 7;
    if (kp.peek() == 0x30) {
        var prf = (try kp.next()).reader();
        const id = (try prf.expect(6)).value;
        const prefix = "\x2a\x86\x48\x86\xf7\x0d\x02";
        if (id.len != 8 or !std.mem.eql(u8, id[0..7], prefix)) return error.UnsupportedEncryption;
        hash = id[7];
        if (!prf.empty()) {
            const n = try prf.expect(5);
            if (n.value.len != 0) return error.InvalidKey;
        }
        try prf.finish();
    }
    try kp.finish();
    var scheme = (try parameters.expect(0x30)).reader();
    try parameters.finish();
    const cipher = (try scheme.expect(6)).value;
    const key_len = try cipherLength(cipher);
    if (key_length) |len| if (len != key_len) return error.InvalidKey;
    const iv = (try scheme.expect(4)).value;
    try scheme.finish();
    const des3 = std.mem.eql(u8, cipher, oid_des3);
    if (iv.len != (if (des3) @as(usize, 8) else 16)) return error.InvalidKey;
    const data = (try info.expect(4)).value;
    try info.finish();
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    const rounds: u32 = @intCast(iterations); // safe: the explicit iteration limit above fits u32
    switch (hash) {
        7 => Kdf.derive(std.crypto.hash.Sha1, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        9 => Kdf.derive(std.crypto.hash.sha2.Sha256, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        10 => Kdf.derive(std.crypto.hash.sha2.Sha384, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        11 => Kdf.derive(std.crypto.hash.sha2.Sha512, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        else => return error.UnsupportedEncryption,
    }
    const plain = try gpa.alloc(u8, data.len);
    defer wipeFree(gpa, plain);
    const decoded = if (des3) try Des3.decrypt(key[0..24], iv[0..8].*, data, plain) else try Cbc.decrypt(key[0..key_len], iv[0..16].*, data, plain);
    return parseDer(decoded, options) catch |err| switch (err) {
        error.OutOfMemory, error.EntropyRequired, error.EntropyUnavailable => err,
        else => error.BadPassword,
    };
}
fn cipherLength(id: []const u8) ParseError!usize {
    @setRuntimeSafety(true);
    if (std.mem.eql(u8, id, oid_des3)) return 24;
    const prefix = "\x60\x86\x48\x01\x65\x03\x04\x01";
    if (id.len == 9 and std.mem.eql(u8, id[0..8], prefix)) return switch (id[8]) {
        2 => 16,
        22 => 24,
        42 => 32,
        else => error.UnsupportedEncryption,
    };
    return error.UnsupportedEncryption;
}
fn legacy(gpa: std.mem.Allocator, block: Pem.Block, options: Options) ParseError![]u8 {
    @setRuntimeSafety(true);
    const password = options.passphrase orelse return error.PasswordRequired;
    const info = block.dek orelse return error.InvalidPem;
    const comma = std.mem.findScalar(u8, info, ',') orelse return error.InvalidPem;
    const name = info[0..comma];
    const des3 = std.mem.eql(u8, name, "DES-EDE3-CBC");
    const key_len: usize = if (des3) 24 else if (std.mem.eql(u8, name, "AES-128-CBC")) 16 else if (std.mem.eql(u8, name, "AES-192-CBC")) 24 else if (std.mem.eql(u8, name, "AES-256-CBC")) 32 else return error.UnsupportedEncryption;
    var iv: [16]u8 = undefined;
    const iv_len: usize = if (des3) 8 else 16;
    if (info[comma + 1 ..].len != iv_len * 2) return error.InvalidPem;
    _ = std.fmt.hexToBytes(iv[0..iv_len], info[comma + 1 ..]) catch return error.InvalidPem;
    var key: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    var previous: [16]u8 = undefined;
    defer std.crypto.secureZero(u8, &previous);
    var filled: usize = 0;
    while (filled < key_len) {
        var h = std.crypto.hash.Md5.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        if (filled != 0) h.update(&previous);
        h.update(password);
        h.update(iv[0..8]);
        h.final(&previous);
        const n = @min(previous.len, key_len - filled);
        @memcpy(key[filled..][0..n], previous[0..n]);
        filled += n;
    }
    const plain = try gpa.alloc(u8, block.der.len);
    errdefer wipeFree(gpa, plain);
    const decoded = if (des3) try Des3.decrypt(key[0..24], iv[0..8].*, block.der, plain) else try Cbc.decrypt(key[0..key_len], iv, block.der, plain);
    // The owned output keeps its full allocation size for erasure and free.
    // Make the returned DER owned; wipe padding and the staging block now.
    const result = try gpa.dupe(u8, decoded);
    wipeFree(gpa, plain);
    return result;
}
fn wipeFree(gpa: std.mem.Allocator, bytes: []u8) void {
    @setRuntimeSafety(true);
    std.crypto.secureZero(u8, bytes);
    gpa.free(bytes);
}
test {
    @setRuntimeSafety(true);
    _ = @import("Key_test.zig");
    _ = @import("Rsa.zig");
    _ = @import("Kdf.zig");
    _ = @import("EdKey.zig");
    _ = Curve;
    _ = Des3;
}
