//! Bounded key parsing into the material `PrivateKey` signs with.
const std = @import("std");
const aegis = @import("aegis");
const SecretBytes = aegis.SecretBytes;
const Der = @import("../wire/Der.zig");
const Pem = @import("Pem.zig");
const Rsa = @import("Rsa.zig");
const p256 = @import("../crypto/p256.zig");
const Kdf = @import("Kdf.zig");
const Cbc = @import("Cbc.zig");
const Des3 = @import("Des3.zig");
const oid_des3 = "\x2a\x86\x48\x86\xf7\x0d\x03\x07";
const P256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P384 = std.crypto.sign.ecdsa.EcdsaP384Sha384;
const Ed25519 = std.crypto.sign.Ed25519;
const Curve = @import("Curve.zig");
const EdKey = @import("EdKey.zig");
const mldsa = @import("../crypto/mldsa.zig");
pub const Material = union(enum) { rsa: Rsa.Key, p256: P256.KeyPair, p384: P384.KeyPair, ed25519: Ed25519.KeyPair, mldsa: MlDsa };
/// An ML-DSA key: the expanded private key (FIPS 204 skEncode), checked against itself, and
/// the public key it belongs to. The first `secretLength`/`publicLength` bytes are the key's.
pub const MlDsa = struct {
    level: mldsa.Level,
    secret: [mldsa.Scheme(.mldsa87).secret_key_length]u8,
    public: [mldsa.Scheme(.mldsa87).public_key_length]u8,

    pub fn publicKey(self: *const MlDsa) []const u8 {
        return switch (self.level) {
            inline else => |tag| self.public[0..mldsa.Scheme(tag).public_key_length],
        };
    }
};
pub const Options = struct { passphrase: ?[]const u8 = null, bytes: usize = 65536, depth: usize = 24, elements: usize = 4096, iterations: usize = 1_000_000, salt_bytes: usize = 1024, password_bytes: usize = 4096 };
pub const ParseError = Der.Error || Pem.Error || Rsa.Error || Cbc.Error || error{ UnsupportedKey, UnsupportedEncryption, PasswordRequired, KdfLimit };
const oid_rsa = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
const oid_ec = "\x2a\x86\x48\xce\x3d\x02\x01";
const oid_ed = "\x2b\x65\x70";
const oid_p256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const oid_p384 = "\x2b\x81\x04\x00\x22";
/// id-ml-dsa-44, -65 and -87 (RFC 9881), the last byte apart.
const oid_mldsa_prefix = "\x60\x86\x48\x01\x65\x03\x04\x03";
/// Parses one private key into `out`, which holds it on success and nothing on failure: key
/// material is written where it will live, never returned by value through the frames between.
pub fn parse(gpa: std.mem.Allocator, bytes: []const u8, options: Options, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    comptime {
        if (std.options.side_channels_mitigations == .none) @compileError("cloak private-key construction requires std side-channel mitigations");
    }
    if (bytes.len > options.bytes) return error.InputLimit;
    if (options.passphrase) |password| if (password.len > options.password_bytes) return error.KdfLimit;
    // Armor may follow explanatory text, as `openssl pkcs12` writes it; a DER key starts with
    // its SEQUENCE tag, which no text before armor does.
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    const armored = std.mem.startsWith(u8, trimmed, "-----BEGIN ") or (trimmed.len != 0 and trimmed[0] != 0x30 and Pem.boundary(bytes, 0) != null);
    if (armored) {
        var pem = Pem.init(bytes);
        var found = false;
        errdefer if (found) std.crypto.secureZero(u8, std.mem.asBytes(out));
        while (try pem.next(gpa, options.bytes)) |decoded| {
            var block = decoded;
            defer block.deinit(gpa);
            if (std.mem.eql(u8, block.label, "CERTIFICATE")) {
                try validate(block.der, options);
                continue;
            }
            if (found) return error.InvalidKey;
            const rsa_label = std.mem.eql(u8, block.label, "RSA PRIVATE KEY");
            const ec_label = std.mem.eql(u8, block.label, "EC PRIVATE KEY");
            const pkcs8_label = std.mem.eql(u8, block.label, "PRIVATE KEY");
            const encrypted_label = std.mem.eql(u8, block.label, "ENCRYPTED PRIVATE KEY");
            if (!rsa_label and !ec_label and !pkcs8_label and !encrypted_label) return error.UnsupportedKey;
            if (block.legacy) {
                if (!rsa_label and !ec_label) return error.InvalidKey;
                var plain = try legacy(gpa, block, options);
                defer plain.deinit();
                try labelShape(plain.expose(), rsa_label, ec_label);
                try parseDer(plain.expose(), options, out);
            } else if (encrypted_label) {
                try encrypted(gpa, block.der, options, out);
            } else {
                try labelShape(block.der, rsa_label, ec_label);
                try parseDer(block.der, options, out);
            }
            found = true;
        }
        if (!found) return error.InvalidKey;
        return;
    }
    try validate(bytes, options);
    var probe = (try Der.single(bytes, 0x30)).reader();
    if (probe.peek() == 0x30) return encrypted(gpa, bytes, options, out);
    return parseDer(bytes, options, out);
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
fn parseDer(bytes: []const u8, options: Options, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    try validate(bytes, options);
    var r = (try Der.single(bytes, 0x30)).reader();
    const version = try Der.number((try r.expect(2)).value);
    return switch (r.peek() orelse return error.InvalidKey) {
        0x30 => if (version == 0) pkcs8(&r, options, out) else error.InvalidKey,
        2 => if (version == 0) rsaKey(bytes, out) else error.InvalidKey,
        4 => if (version == 1) sec1(bytes, null, out) else error.InvalidKey,
        else => error.InvalidKey,
    };
}
/// An RSAPrivateKey, parsed straight into `out`'s RSA arm.
fn rsaKey(bytes: []const u8, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    out.* = .{ .rsa = undefined };
    Rsa.parse(bytes, &out.rsa) catch |err| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return err;
    };
}
fn pkcs8(r: *Der.Reader, options: Options, out: *Material) ParseError!void {
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
        return rsaKey(key, out);
    }
    if (std.mem.eql(u8, id, oid_ec)) {
        const p = parameter orelse return error.InvalidKey;
        if (p.tag != 6) return error.InvalidKey;
        return sec1(key, p.value, out);
    }
    if (id.len == 9 and std.mem.eql(u8, id[0..8], oid_mldsa_prefix)) {
        if (parameter != null) return error.InvalidKey;
        const level: mldsa.Level = switch (id[8]) {
            0x11 => .mldsa44,
            0x12 => .mldsa65,
            0x13 => .mldsa87,
            else => return error.UnsupportedKey,
        };
        return switch (level) {
            inline else => |tag| mldsaKey(tag, key, out),
        };
    }
    if (std.mem.eql(u8, id, oid_ed)) {
        if (parameter != null) return error.InvalidKey;
        return ed25519Key((try Der.single(key, 4)).value, null, out);
    }
    return error.UnsupportedKey;
}
/// An ML-DSA private key (RFC 9881 section 6): the seed ([0], 32 bytes), the expanded key, or
/// both, whose expanded key must be the seed's. An expanded key without its seed is checked
/// against itself (`Scheme.publicKey`). The key is written into `out` in place.
fn mldsaKey(comptime level: mldsa.Level, encoded: []const u8, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    const M = mldsa.Scheme(level);
    out.* = .{ .mldsa = .{ .level = level, .secret = @splat(0), .public = @splat(0) } };
    errdefer std.crypto.secureZero(u8, std.mem.asBytes(out));
    const key = &out.mldsa;
    const sk = key.secret[0..M.secret_key_length];
    const pk = key.public[0..M.public_key_length];
    if (encoded.len == 0) return error.InvalidKey;
    const element = try Der.single(encoded, encoded[0]);
    switch (element.tag) {
        0x80 => {
            if (element.value.len != M.seed_length) return error.InvalidKey;
            M.keyFromSeed(element.value[0..M.seed_length], pk, sk);
        },
        0x04 => {
            if (element.value.len != M.secret_key_length) return error.InvalidKey;
            sk.* = element.value[0..M.secret_key_length].*;
            M.publicKey(sk, pk) catch return error.InvalidKey;
        },
        0x30 => {
            var r = element.reader();
            const seed = (try r.expect(4)).value;
            const expanded = (try r.expect(4)).value;
            try r.finish();
            if (seed.len != M.seed_length or expanded.len != M.secret_key_length) return error.InvalidKey;
            M.keyFromSeed(seed[0..M.seed_length], pk, sk);
            if (!aegis.secret.equal(M.secret_key_length, sk, expanded[0..M.secret_key_length]).declassify("a seed whose key differs from the one beside it is refused")) return error.InvalidKey;
        },
        else => return error.InvalidKey,
    }
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
fn sec1(bytes: []const u8, outside: ?[]const u8, out: *Material) ParseError!void {
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
    if (std.mem.eql(u8, named, oid_p256)) return ecKey(.p256, scalar, public, out);
    if (std.mem.eql(u8, named, oid_p384)) return ecKey(.p384, scalar, public, out);
    return error.UnsupportedKey;
}

pub const EcCurve = enum { p256, p384 };

/// An EC key from its scalar, exactly the curve's width (SEC 1, RFC 7518 section 6.2.2.1), into
/// `out`: 0 < d < n, and the public point derived from it, compared with `public` (SEC 1
/// uncompressed, 0x04 || x || y) when one is given. The one path every EC private key takes.
pub fn ecKey(named: EcCurve, scalar: []const u8, public: ?[]const u8, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    if (named == .p256) {
        if (scalar.len != 32) return error.InvalidKey;
        var sk = P256.SecretKey.fromBytes(scalar[0..32].*) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        // 0 < d < n, checked in constant time; the comb of cloak's kernel derives the point.
        if (!p256.scalarInRange(&sk.bytes)) return error.InvalidKey;
        var point = p256.baseMul(&sk.bytes);
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        // The derived public key is public; only its verdict and coordinates leave.
        const encoded = point.affine().toSec1();
        var kp: P256.KeyPair = .{ .secret_key = sk, .public_key = P256.PublicKey.fromSec1(&encoded) catch return error.InvalidKey };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
        if (public) |p| if (!std.mem.eql(u8, p, &kp.public_key.toUncompressedSec1())) return error.InvalidKey;
        out.* = .{ .p256 = kp };
        return;
    }
    {
        if (scalar.len != 48) return error.InvalidKey;
        var sk = P384.SecretKey.fromBytes(scalar[0..48].*) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&sk));
        Curve.validate(P384.Curve, &sk.bytes) catch return error.InvalidKey;
        var point = Curve.base(P384.Curve, .big, &sk.bytes) catch return error.InvalidKey;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&point));
        var kp: P384.KeyPair = .{ .secret_key = sk, .public_key = .{ .p = point } };
        defer std.crypto.secureZero(u8, std.mem.asBytes(&kp));
        if (public) |p| if (!std.mem.eql(u8, p, &kp.public_key.toUncompressedSec1())) return error.InvalidKey;
        out.* = .{ .p384 = kp };
        return;
    }
}

/// An Ed25519 key from its 32-byte seed (RFC 8032, RFC 8410, RFC 8037's d), into `out`, its
/// public key compared with `public` when one is given. The one path every Ed25519 key takes.
pub fn ed25519Key(seed: []const u8, public: ?[]const u8, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    if (seed.len != 32) return error.InvalidKey;
    var owned_seed = seed[0..32].*;
    defer std.crypto.secureZero(u8, &owned_seed);
    var pair = EdKey.create(&owned_seed) catch return error.InvalidKey;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
    if (public) |p| if (!std.mem.eql(u8, p, &pair.public_key.toBytes())) return error.InvalidKey;
    out.* = .{ .ed25519 = pair };
}

/// An RSA key from its numbers (`Rsa.fromIntegers`), into `out`.
pub fn rsaFromIntegers(integers: *const [8][]const u8, out: *Material) ParseError!void {
    @setRuntimeSafety(true);
    out.* = .{ .rsa = undefined };
    Rsa.fromIntegers(integers, &out.rsa) catch |err| {
        std.crypto.secureZero(u8, std.mem.asBytes(out));
        return err;
    };
}
fn encrypted(gpa: std.mem.Allocator, bytes: []const u8, options: Options, out: *Material) ParseError!void {
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
    var key_owner = aegis.Secret([32]u8).init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut();
    const rounds = aegis.int.cast(u32, iterations) catch return error.KdfLimit; // safe: checked narrowing at the KDF boundary
    switch (hash) {
        7 => Kdf.derive(std.crypto.hash.Sha1, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        9 => Kdf.derive(std.crypto.hash.sha2.Sha256, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        10 => Kdf.derive(std.crypto.hash.sha2.Sha384, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        11 => Kdf.derive(std.crypto.hash.sha2.Sha512, key[0..key_len], password, salt, rounds) catch return error.KdfLimit,
        else => return error.UnsupportedEncryption,
    }
    var plain_owner = try SecretBytes.init(gpa, data.len);
    defer plain_owner.deinit();
    plain_owner.resizeWithinCapacity(data.len) catch return error.InputLimit;
    const plain = plain_owner.exposeMut();
    const decoded = if (des3) try Des3.decrypt(key[0..24], iv[0..8].*, data, plain) else try Cbc.decrypt(key[0..key_len], iv[0..16].*, data, plain);
    return parseDer(decoded, options, out) catch |err| switch (err) {
        error.OutOfMemory => err,
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
fn legacy(gpa: std.mem.Allocator, block: Pem.Block, options: Options) ParseError!SecretBytes {
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
    var key_owner = aegis.Secret([32]u8).init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut();
    var previous_owner = aegis.Secret([16]u8).init(undefined);
    defer previous_owner.deinit();
    const previous = previous_owner.exposeMut();
    var filled: usize = 0;
    while (filled < key_len) {
        var h = std.crypto.hash.Md5.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        if (filled != 0) h.update(previous);
        h.update(password);
        h.update(iv[0..8]);
        h.final(previous);
        const n = @min(previous.len, key_len - filled);
        @memcpy(key[filled..][0..n], previous[0..n]);
        filled += n;
    }
    var plain_owner = try SecretBytes.init(gpa, block.der.len);
    errdefer plain_owner.deinit();
    plain_owner.resizeWithinCapacity(block.der.len) catch return error.InputLimit;
    const plain = plain_owner.exposeMut();
    const decoded = if (des3) try Des3.decrypt(key[0..24], iv[0..8].*, block.der, plain) else try Cbc.decrypt(key[0..key_len], iv, block.der, plain);
    // Preserve the complete ciphertext-sized allocation; shrink wipes padding.
    plain_owner.resizeWithinCapacity(decoded.len) catch return error.InputLimit;
    var result: SecretBytes = undefined;
    plain_owner.moveInto(&result);
    return result;
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
