//! Password-based decryption of an (AlgorithmIdentifier, ciphertext) pair, the one decryptor
//! for encrypted PKCS#8 keys and PKCS#12's encrypted contents and shrouded keys: PBES2 (RFC
//! 8018: PBKDF2 with AES-CBC or DES-EDE3-CBC) and PKCS#12's own PBE (RFC 7292 appendix B's KDF
//! with SHA-1, under 3DES or RC2). Every derived key is a secret owner; the plaintext is a
//! `SecretBytes` the caller releases.
const std = @import("std");
const aegis = @import("aegis");
const SecretBytes = aegis.SecretBytes;
const Der = @import("../wire/Der.zig");
const Kdf = @import("Kdf.zig");
const Sha1 = @import("../crypto/sha1.zig").Sha1;
const Cbc = @import("Cbc.zig");
const Des3 = @import("Des3.zig");
const Rc2 = @import("Rc2.zig");

pub const Error = Der.Error || Cbc.Error || std.mem.Allocator.Error || error{ UnsupportedEncryption, KdfLimit, InvalidKey, InputLimit, InvalidPassword };

/// The bounds a hostile file meets before any work is done for it.
pub const Limits = struct { iterations: usize = 1_000_000, salt_bytes: usize = 1024, password_bytes: usize = 4096 };

/// A password in both forms the algorithms take: the caller's UTF-8 bytes (PBES2, PBMAC1) and
/// the BMPString of RFC 7292 appendix B.1 (the PKCS#12 KDF): UTF-16BE with a NUL, or nothing at
/// all for an absent password; null when the bytes are not UTF-8, which only PBES2 can take.
/// Owned; `deinit` erases the BMP form.
pub const Password = struct {
    utf8: []const u8,
    bmp: ?SecretBytes,

    /// `utf8`, borrowed for the owner's life, and its BMP form (`absent`: none at all, as some
    /// writers encode an empty password).
    pub fn init(gpa: std.mem.Allocator, utf8: []const u8, absent: bool, limits: Limits) Error!Password {
        @setRuntimeSafety(true);
        if (utf8.len > limits.password_bytes) return error.KdfLimit;
        if (absent and utf8.len != 0) return error.InvalidPassword;
        if (!std.unicode.utf8ValidateSlice(utf8)) return .{ .utf8 = utf8, .bmp = null };
        // At most two UTF-16 bytes per UTF-8 byte, and the NUL.
        var bmp = try SecretBytes.init(gpa, 2 * utf8.len + 2);
        errdefer bmp.deinit();
        bmp.resizeWithinCapacity(2 * utf8.len + 2) catch return error.InputLimit;
        const out = bmp.exposeMut();
        var at: usize = 0;
        if (!absent) {
            var view = std.unicode.Utf8View.initUnchecked(utf8).iterator();
            while (view.nextCodepoint()) |point| {
                if (point >= 0x10000) {
                    const v = point - 0x10000;
                    std.mem.writeInt(u16, out[at..][0..2], @intCast(0xd800 + (v >> 10)), .big); // safe: v < 2^20
                    std.mem.writeInt(u16, out[at + 2 ..][0..2], @intCast(0xdc00 + (v & 0x3ff)), .big); // safe: masked to ten bits
                    at += 4;
                } else {
                    std.mem.writeInt(u16, out[at..][0..2], @intCast(point), .big); // safe: below 0x10000
                    at += 2;
                }
            }
            out[at] = 0;
            out[at + 1] = 0;
            at += 2;
        }
        bmp.resizeWithinCapacity(at) catch return error.InputLimit;
        return .{ .utf8 = utf8, .bmp = bmp };
    }

    pub fn deinit(self: *Password) void {
        if (self.bmp) |*bmp| bmp.deinit();
    }

    /// The BMP form, or `InvalidPassword` when the password is not UTF-8.
    pub fn bmpForm(self: *const Password) Error![]const u8 {
        return if (self.bmp) |*bmp| bmp.expose() else error.InvalidPassword;
    }
};

const oid_pbes2 = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0d";
const oid_pbkdf2 = "\x2a\x86\x48\x86\xf7\x0d\x01\x05\x0c";
const oid_des3 = "\x2a\x86\x48\x86\xf7\x0d\x03\x07";
/// pkcs-12PbeIds (RFC 7292 appendix C), the last byte apart: 1 and 2 are RC4 (refused), 3 and 4
/// 3-key and 2-key 3DES, 5 and 6 RC2 with a 128-bit and a 40-bit key.
const oid_pkcs12_pbe = "\x2a\x86\x48\x86\xf7\x0d\x01\x0c\x01";

/// Decrypts `data` under `algorithm` (a DER AlgorithmIdentifier) with `password`, and returns the
/// unpadded plaintext in a secret owner.
pub fn decrypt(gpa: std.mem.Allocator, algorithm: []const u8, data: []const u8, password: *const Password, limits: Limits) Error!SecretBytes {
    @setRuntimeSafety(true);
    var r = (try Der.single(algorithm, 0x30)).reader();
    const id = (try r.expect(6)).value;
    const parameters = try r.expect(0x30);
    try r.finish();
    if (std.mem.eql(u8, id, oid_pbes2)) return pbes2(gpa, parameters, data, password.utf8, limits);
    if (id.len == oid_pkcs12_pbe.len + 1 and std.mem.eql(u8, id[0..oid_pkcs12_pbe.len], oid_pkcs12_pbe)) return pkcs12Pbe(gpa, id[oid_pkcs12_pbe.len], parameters, data, try password.bmpForm(), limits);
    return error.UnsupportedEncryption;
}

/// PBES2 (RFC 8018 section 6.2): PBKDF2 with HMAC-SHA-1 or SHA-2, then AES-CBC or DES-EDE3-CBC.
fn pbes2(gpa: std.mem.Allocator, parameters: Der.Element, data: []const u8, password: []const u8, limits: Limits) Error!SecretBytes {
    @setRuntimeSafety(true);
    var p = parameters.reader();
    var kdf = (try p.expect(0x30)).reader();
    if (!std.mem.eql(u8, (try kdf.expect(6)).value, oid_pbkdf2)) return error.UnsupportedEncryption;
    var kp = (try kdf.expect(0x30)).reader();
    try kdf.finish();
    const salt = (try kp.expect(4)).value;
    const iterations = try Der.number((try kp.expect(2)).value);
    if (salt.len > limits.salt_bytes or iterations == 0 or iterations > limits.iterations or iterations > std.math.maxInt(u32)) return error.KdfLimit;
    const key_length = if (kp.peek() == 2) try Der.number((try kp.next()).value) else null;
    const hash = if (kp.peek() == 0x30) try prf((try kp.next()).encoded) else Prf.sha1;
    try kp.finish();
    var scheme = (try p.expect(0x30)).reader();
    try p.finish();
    const cipher = (try scheme.expect(6)).value;
    const key_len = try cipherLength(cipher);
    if (key_length) |len| if (len != key_len) return error.InvalidKey;
    const iv = (try scheme.expect(4)).value;
    try scheme.finish();
    const des3 = std.mem.eql(u8, cipher, oid_des3);
    if (iv.len != (if (des3) @as(usize, 8) else 16)) return error.InvalidKey;
    var key_owner = aegis.Secret([32]u8).init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut();
    const rounds = aegis.int.cast(u32, iterations) catch return error.KdfLimit; // safe: checked narrowing at the KDF boundary
    try pbkdf2(hash, key[0..key_len], password, salt, rounds);
    var plain = try SecretBytes.init(gpa, data.len);
    errdefer plain.deinit();
    plain.resizeWithinCapacity(data.len) catch return error.InputLimit;
    const decoded = if (des3) try Des3.decrypt(key[0..24], iv[0..8].*, data, plain.exposeMut()) else try Cbc.decrypt(key[0..key_len], iv[0..16].*, data, plain.exposeMut());
    // The ciphertext-sized allocation is kept; the shrink wipes the padding.
    plain.resizeWithinCapacity(decoded.len) catch return error.InputLimit;
    return plain;
}

/// The HMAC hashes PBKDF2 and PBMAC1 take.
pub const Prf = enum { sha1, sha256, sha384, sha512 };

/// An HMAC AlgorithmIdentifier (RFC 8018 appendix B.1), its NULL parameters optional.
pub fn prf(encoded: []const u8) Error!Prf {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    const id = (try r.expect(6)).value;
    if (!r.empty()) {
        const n = try r.expect(5);
        if (n.value.len != 0) return error.InvalidKey;
    }
    try r.finish();
    const prefix = "\x2a\x86\x48\x86\xf7\x0d\x02";
    if (id.len != 8 or !std.mem.eql(u8, id[0..7], prefix)) return error.UnsupportedEncryption;
    return switch (id[7]) {
        7 => .sha1,
        9 => .sha256,
        10 => .sha384,
        11 => .sha512,
        else => error.UnsupportedEncryption,
    };
}

pub fn pbkdf2(hash: Prf, out: []u8, password: []const u8, salt: []const u8, rounds: u32) Error!void {
    @setRuntimeSafety(true);
    (switch (hash) {
        .sha1 => Kdf.derive(Sha1, out, password, salt, rounds),
        .sha256 => Kdf.derive(std.crypto.hash.sha2.Sha256, out, password, salt, rounds),
        .sha384 => Kdf.derive(std.crypto.hash.sha2.Sha384, out, password, salt, rounds),
        .sha512 => Kdf.derive(std.crypto.hash.sha2.Sha512, out, password, salt, rounds),
    }) catch return error.KdfLimit;
}

fn cipherLength(id: []const u8) Error!usize {
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

/// PKCS#12 PBE (RFC 7292 appendix C): pkcs-12PbeParams { salt, iterations }, the key and IV from
/// the appendix B KDF over SHA-1 (IDs 1 and 2).
fn pkcs12Pbe(gpa: std.mem.Allocator, which: u8, parameters: Der.Element, data: []const u8, bmp: []const u8, limits: Limits) Error!SecretBytes {
    @setRuntimeSafety(true);
    const Cipher = enum { des3, des2, rc2_128, rc2_40 };
    const cipher: Cipher = switch (which) {
        3 => .des3,
        4 => .des2,
        5 => .rc2_128,
        6 => .rc2_40,
        else => return error.UnsupportedEncryption,
    };
    var p = parameters.reader();
    const salt = (try p.expect(4)).value;
    const iterations = try Der.number((try p.expect(2)).value);
    try p.finish();
    if (salt.len > limits.salt_bytes or iterations == 0 or iterations > limits.iterations or iterations > std.math.maxInt(u32)) return error.KdfLimit;
    const rounds = aegis.int.cast(u32, iterations) catch return error.KdfLimit; // safe: checked narrowing at the KDF boundary
    const key_len: usize = switch (cipher) {
        .des3 => 24,
        .des2, .rc2_128 => 16,
        .rc2_40 => 5,
    };
    var key_owner = aegis.Secret([24]u8).init(undefined);
    defer key_owner.deinit();
    const key = key_owner.exposeMut();
    try pkcs12Kdf(Sha1, gpa, 1, bmp, salt, rounds, key[0..key_len]);
    // Two-key 3DES is K1, K2, K1.
    if (cipher == .des2) @memcpy(key[16..24], key[0..8]);
    var iv: [8]u8 = undefined;
    try pkcs12Kdf(Sha1, gpa, 2, bmp, salt, rounds, &iv);
    var plain = try SecretBytes.init(gpa, data.len);
    errdefer plain.deinit();
    plain.resizeWithinCapacity(data.len) catch return error.InputLimit;
    const decoded = switch (cipher) {
        .des3, .des2 => try Des3.decrypt(key, iv, data, plain.exposeMut()),
        .rc2_128 => try Rc2.decrypt(key[0..16], 128, iv, data, plain.exposeMut()),
        .rc2_40 => try Rc2.decrypt(key[0..5], 40, iv, data, plain.exposeMut()),
    };
    plain.resizeWithinCapacity(decoded.len) catch return error.InputLimit;
    return plain;
}

/// RFC 7292 appendix B.2: `out.len` bytes for purpose `id` (1 key, 2 IV, 3 MAC key) from the
/// BMP password and salt, `rounds` iterations of `Hash`.
pub fn pkcs12Kdf(comptime Hash: type, gpa: std.mem.Allocator, id: u8, bmp: []const u8, salt: []const u8, rounds: u32, out: []u8) Error!void {
    @setRuntimeSafety(true);
    const v = Hash.block_length;
    const u = Hash.digest_length;
    if (rounds == 0) return error.KdfLimit;
    const s_len = v * ((salt.len + v - 1) / v);
    const p_len = v * ((bmp.len + v - 1) / v);
    // I = S || P, each the input repeated to whole blocks.
    var i_owner = try SecretBytes.init(gpa, s_len + p_len);
    defer i_owner.deinit();
    i_owner.resizeWithinCapacity(s_len + p_len) catch return error.InputLimit;
    const big_i = i_owner.exposeMut();
    for (0..s_len) |k| big_i[k] = salt[k % salt.len];
    for (0..p_len) |k| big_i[s_len + k] = bmp[k % bmp.len];
    const diversifier: [v]u8 = @splat(id);
    var a_owner = aegis.Secret([u]u8).init(undefined);
    defer a_owner.deinit();
    const a = a_owner.exposeMut();
    var b_owner = aegis.Secret([v]u8).init(undefined);
    defer b_owner.deinit();
    const b = b_owner.exposeMut();
    var offset: usize = 0;
    while (true) {
        var h = Hash.init(.{});
        defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
        h.update(&diversifier);
        h.update(big_i);
        h.final(a);
        for (1..rounds) |_| {
            h = Hash.init(.{});
            h.update(a);
            h.final(a);
        }
        const n = @min(u, out.len - offset);
        @memcpy(out[offset..][0..n], a[0..n]);
        offset += n;
        if (offset == out.len) return;
        for (0..v) |k| b[k] = a[k % u];
        // Each v-byte block of I becomes (I_j + B + 1) mod 2^(8v).
        var j: usize = 0;
        while (j < big_i.len) : (j += v) {
            var carry: u16 = 1;
            var k: usize = v;
            while (k > 0) {
                k -= 1;
                const sum = @as(u16, big_i[j + k]) + b[k] + carry;
                big_i[j + k] = @truncate(sum);
                carry = sum >> 8;
            }
        }
    }
}

test {
    _ = @import("Pbe_test.zig");
}
