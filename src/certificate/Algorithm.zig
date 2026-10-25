const std = @import("std");
const Der = @import("../wire/Der.zig");
const mldsa = @import("../crypto/mldsa.zig");
const roca = @import("../crypto/roca.zig");
const p521 = @import("../crypto/p521.zig");
const pkcs1 = @import("../crypto/pkcs1.zig");
pub const Error = Der.Error || error{ UnsupportedAlgorithm, InvalidPublicKey };
pub const Hash = enum { sha256, sha384, sha512 };
pub const Pss = struct { hash: Hash, mgf_hash: Hash, salt_length: usize, trailer: usize = 1 };
/// ML-DSA's parameter sets (FIPS 204): pure ML-DSA, an empty context, for keys and signatures.
pub const MlDsa = mldsa.Level;
/// A signature algorithm. `ecdsa` signatures are DER, as X.509 and TLS write them; `ecdsa_p1363` is the
/// same algorithm with the signature as r || s, each at the curve's width (IEEE P1363), as JOSE
/// (RFC 7518 3.4), COSE and WebAuthn write them. Certificates never carry it.
pub const Signature = union(enum) { rsa: Hash, pss: Pss, ecdsa: Hash, ecdsa_p1363: Hash, ed25519, mldsa: MlDsa, unsupported: []const u8 };
/// RSAES-OAEP's parameters (RFC 8017 7.1): the label's hash, MGF1's hash and the label. JOSE's
/// RSA-OAEP takes SHA-1 for both, RSA-OAEP-256 SHA-256 for both (RFC 7518 4.3).
pub const Oaep = pkcs1.Oaep;
/// A public-key encryption scheme. RSAES-PKCS1-v1_5 is not one: its decryption is the padding
/// oracle Bleichenbacher's attack reads.
pub const Encryption = union(enum) { oaep: Oaep };
pub const Curve = enum { p256, p384, p521 };
pub const PublicKey = union(enum) {
    rsa: struct { modulus: []const u8, exponent: []const u8, pss: ?Pss = null, pss_only: bool = false },
    ec: struct { curve: Curve, bytes: []const u8 },
    ed25519: []const u8,
    mldsa: struct { level: MlDsa, bytes: []const u8 },
    /// An X25519 public key (RFC 7748, RFC 8410): 32 bytes, for key agreement alone. No
    /// signature verifies under it and TLS authenticates with none.
    x25519: []const u8,
};
pub const rsa_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
pub const pss_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";
const ed_oid = "\x2b\x65\x70";
const x25519_oid = "\x2b\x65\x6e";
const ec_oid = "\x2a\x86\x48\xce\x3d\x02\x01";
const p256_oid = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const p384_oid = "\x2b\x81\x04\x00\x22";
const p521_oid = "\x2b\x81\x04\x00\x23";
/// id-ml-dsa-44, -65 and -87: 2.16.840.1.101.3.4.3.17 to .19 (RFC 9881), the last byte apart.
const mldsa_prefix = "\x60\x86\x48\x01\x65\x03\x04\x03";

/// The ML-DSA parameter set an algorithm identifier names, if it names one.
fn mldsaOf(id: []const u8) ?MlDsa {
    if (id.len != 9 or !eql(id[0..8], mldsa_prefix)) return null;
    return switch (id[8]) {
        0x11 => .mldsa44,
        0x12 => .mldsa65,
        0x13 => .mldsa87,
        else => null,
    };
}

/// The length of a public key or signature of each ML-DSA parameter set.
pub fn mldsaPublicKeyLength(level: MlDsa) usize {
    return switch (level) {
        inline else => |tag| mldsa.Scheme(tag).public_key_length,
    };
}

pub fn mldsaSignatureLength(level: MlDsa) usize {
    return switch (level) {
        inline else => |tag| mldsa.Scheme(tag).signature_length,
    };
}
pub fn eql(a: []const u8, b: []const u8) bool {
    @setRuntimeSafety(true);
    return std.mem.eql(u8, a, b);
}
pub fn signature(encoded: []const u8) Error!Signature {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    const id = (try r.expect(6)).value;
    const param = if (!r.empty()) try r.next() else null;
    try r.finish();
    if (eql(id, ed_oid)) {
        if (param != null) return error.InvalidDer;
        return .ed25519;
    }
    if (eql(id, pss_oid)) return .{ .pss = try pssParameters(param orelse return error.InvalidDer) };
    if (mldsaOf(id)) |level| {
        // The parameters are absent (RFC 9881 section 2).
        if (param != null) return error.InvalidDer;
        return .{ .mldsa = level };
    }
    const rsa_prefix = "\x2a\x86\x48\x86\xf7\x0d\x01\x01";
    if (id.len == 9 and eql(id[0..8], rsa_prefix)) {
        if (param) |p| if (p.tag != 5 or p.value.len != 0) return error.InvalidDer;
        return .{ .rsa = switch (id[8]) {
            11 => .sha256,
            12 => .sha384,
            13 => .sha512,
            else => return .{ .unsupported = id },
        } };
    }
    const ecdsa_prefix = "\x2a\x86\x48\xce\x3d\x04\x03";
    if (id.len == 8 and eql(id[0..7], ecdsa_prefix)) {
        if (param != null) return error.InvalidDer;
        return .{ .ecdsa = switch (id[7]) {
            2 => .sha256,
            3 => .sha384,
            4 => .sha512,
            else => return .{ .unsupported = id },
        } };
    }
    return .{ .unsupported = id };
}
fn hashAlgorithm(encoded: []const u8) Error!Hash {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    const id = (try r.expect(6)).value;
    if (!r.empty()) {
        const n = try r.expect(5);
        if (n.value.len != 0) return error.InvalidDer;
    }
    try r.finish();
    const prefix = "\x60\x86\x48\x01\x65\x03\x04\x02";
    if (id.len != 9 or !eql(id[0..8], prefix)) return error.UnsupportedAlgorithm;
    return switch (id[8]) {
        1 => .sha256,
        2 => .sha384,
        3 => .sha512,
        else => error.UnsupportedAlgorithm,
    };
}
/// Defaults are SHA-1, which this policy does not permit. Modern hashes must be explicit.
pub fn pssParameters(e: Der.Element) Error!Pss {
    @setRuntimeSafety(true);
    if (e.tag != 0x30) return error.InvalidDer;
    var r = e.reader();
    const h = try r.expect(0xa0);
    const hash = try hashAlgorithm(h.value);
    var mgf = (try Der.single((try r.expect(0xa1)).value, 0x30)).reader();
    if (!eql((try mgf.expect(6)).value, "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x08")) return error.UnsupportedAlgorithm;
    const mgf_hash = try hashAlgorithm((try mgf.expect(0x30)).encoded);
    try mgf.finish();
    var salt: usize = 20;
    if (r.peek() == 0xa2) {
        salt = try Der.number((try Der.single((try r.next()).value, 2)).value);
        if (salt == 20) return error.InvalidDer; // DEFAULT must be absent in DER.
    }
    // trailerField DEFAULT 1: an explicitly encoded default is not DER.
    if (!r.empty()) return error.InvalidDer;
    if (salt > 512) return error.DerLimit;
    return .{ .hash = hash, .mgf_hash = mgf_hash, .salt_length = salt };
}
/// The checks every RSA public key gets, from a certificate, a raw key or built by a caller (a
/// JWK's n and e), before it verifies anything: 2048 to 4096 bits, odd, minimal encodings, an odd
/// exponent of 3 to 2^32-1, and no ROCA fingerprint (CVE-2017-15361: a modulus anyone can factor
/// from the key alone is no one's key).
pub fn checkRsa(n: []const u8, exponent: []const u8) error{InvalidPublicKey}!void {
    @setRuntimeSafety(true);
    if (n.len < 256 or n.len > 512 or n[0] == 0 or n[n.len - 1] & 1 == 0) return error.InvalidPublicKey;
    // safe: clz on u8 is at most eight and widens to usize.
    const bits = n.len * 8 - @as(usize, @clz(n[0]));
    if (bits < 2048 or exponent.len == 0 or exponent.len > 4 or exponent[0] == 0) return error.InvalidPublicKey;
    var ev: u32 = 0;
    for (exponent) |byte| ev = (ev << 8) | byte;
    if (ev < 3 or ev & 1 == 0) return error.InvalidPublicKey;
    if (roca.fingerprinted(n)) return error.InvalidPublicKey;
}

pub fn publicKey(encoded: []const u8) Error!PublicKey {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    var a = (try r.expect(0x30)).reader();
    const id = (try a.expect(6)).value;
    const param = if (!a.empty()) try a.next() else null;
    try a.finish();
    const bytes = try Der.octetBits((try r.expect(3)).value);
    try r.finish();
    if (eql(id, rsa_oid) or eql(id, pss_oid)) {
        var pss: ?Pss = null;
        if (eql(id, pss_oid)) {
            if (param) |p| pss = try pssParameters(p);
        } else if (param) |p| {
            if (p.tag != 5 or p.value.len != 0) return error.InvalidDer;
        }
        var k = (try Der.single(bytes, 0x30)).reader();
        const n = try Der.integer((try k.expect(2)).value);
        const exponent = try Der.integer((try k.expect(2)).value);
        try k.finish();
        try checkRsa(n, exponent);
        return .{ .rsa = .{ .modulus = n, .exponent = exponent, .pss = pss, .pss_only = eql(id, pss_oid) } };
    }
    if (eql(id, ec_oid)) {
        const p = param orelse return error.InvalidDer;
        if (p.tag != 6) return error.InvalidDer;
        const curve: Curve = if (eql(p.value, p256_oid)) .p256 else if (eql(p.value, p384_oid)) .p384 else if (eql(p.value, p521_oid)) .p521 else return error.UnsupportedAlgorithm;
        const point_length: usize = switch (curve) {
            .p256 => 65,
            .p384 => 97,
            .p521 => p521.public_length,
        };
        if (bytes.len != point_length or bytes[0] != 4) return error.InvalidPublicKey;
        switch (curve) {
            .p256 => {
                _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(bytes) catch return error.InvalidPublicKey;
            },
            .p384 => {
                _ = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(bytes) catch return error.InvalidPublicKey;
            },
            .p521 => {
                _ = p521.Affine.fromSec1(bytes) catch return error.InvalidPublicKey;
            },
        }
        return .{ .ec = .{ .curve = curve, .bytes = bytes } };
    }
    if (mldsaOf(id)) |level| {
        if (param != null or bytes.len != mldsaPublicKeyLength(level)) return error.InvalidPublicKey;
        return .{ .mldsa = .{ .level = level, .bytes = bytes } };
    }
    if (eql(id, ed_oid)) {
        if (param != null or bytes.len != 32) return error.InvalidPublicKey;
        _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(bytes[0..32].*) catch return error.InvalidPublicKey;
        const point = std.crypto.ecc.Edwards25519.fromBytes(bytes[0..32].*) catch return error.InvalidPublicKey;
        point.rejectLowOrder() catch return error.InvalidPublicKey;
        point.rejectUnexpectedSubgroup() catch return error.InvalidPublicKey;
        return .{ .ed25519 = bytes };
    }
    if (eql(id, x25519_oid)) {
        // Every 32 bytes are an X25519 public key (RFC 7748 5); the agreement refuses the ones
        // of small order.
        if (param != null or bytes.len != 32) return error.InvalidPublicKey;
        return .{ .x25519 = bytes };
    }
    return error.UnsupportedAlgorithm;
}

/// The longest SubjectPublicKeyInfo `encodePublicKey` writes: ML-DSA-87's, 2,614 bytes (a
/// 4096-bit RSA key's is 556).
pub const max_public_key_info = 22 + mldsa.Scheme(.mldsa87).public_key_length;

/// `key` as the DER SubjectPublicKeyInfo `publicKey` reads, in `out` (RFC 5280 section 4.1.2.7):
/// rsaEncryption with NULL parameters (RFC 3279), id-ecPublicKey with the named curve and the
/// uncompressed point (RFC 5480), id-Ed25519 (RFC 8410) and id-ML-DSA-* (RFC 9881), with no
/// parameters. A key restricted to RSASSA-PSS is UnsupportedAlgorithm: its parameters are its
/// certificate's to carry.
pub fn encodePublicKey(key: PublicKey, out: *[max_public_key_info]u8) error{UnsupportedAlgorithm}![]const u8 {
    @setRuntimeSafety(true);
    // The AlgorithmIdentifier, and the subjectPublicKey's bytes (for RSA, their length).
    const identifier: []const u8, const raw: []const u8 = switch (key) {
        .rsa => |rsa| if (rsa.pss_only) return error.UnsupportedAlgorithm else .{ "\x30\x0d\x06\x09" ++ rsa_oid ++ "\x05\x00", "" },
        .ec => |ec| .{ switch (ec.curve) {
            .p256 => "\x30\x13\x06\x07" ++ ec_oid ++ "\x06\x08" ++ p256_oid,
            .p384 => "\x30\x10\x06\x07" ++ ec_oid ++ "\x06\x05" ++ p384_oid,
            .p521 => "\x30\x10\x06\x07" ++ ec_oid ++ "\x06\x05" ++ p521_oid,
        }, ec.bytes },
        .ed25519 => |bytes| .{ "\x30\x05\x06\x03" ++ ed_oid, bytes },
        .x25519 => |bytes| .{ "\x30\x05\x06\x03" ++ x25519_oid, bytes },
        .mldsa => |m| .{ switch (m.level) {
            .mldsa44 => "\x30\x0b\x06\x09" ++ mldsa_prefix ++ "\x11",
            .mldsa65 => "\x30\x0b\x06\x09" ++ mldsa_prefix ++ "\x12",
            .mldsa87 => "\x30\x0b\x06\x09" ++ mldsa_prefix ++ "\x13",
        }, m.bytes },
    };
    const rsa_body = if (key == .rsa) integerLength(key.rsa.modulus) + integerLength(key.rsa.exponent) else 0;
    const subject = if (key == .rsa) Der.headerLength(rsa_body) + rsa_body else raw.len;
    const bit_string = 1 + subject;
    const body = identifier.len + Der.headerLength(bit_string) + bit_string;
    std.debug.assert(Der.headerLength(body) + body <= out.len);
    var at = Der.header(out, 0, 0x30, body);
    @memcpy(out[at..][0..identifier.len], identifier);
    at += identifier.len;
    at = Der.header(out, at, 0x03, bit_string);
    out[at] = 0;
    at += 1;
    if (key == .rsa) {
        at = Der.header(out, at, 0x30, rsa_body);
        at = putInteger(out, at, key.rsa.modulus);
        at = putInteger(out, at, key.rsa.exponent);
    } else {
        @memcpy(out[at..][0..raw.len], raw);
        at += raw.len;
    }
    return out[0..at];
}

/// The encoded size of a positive INTEGER of `magnitude` (big-endian, no leading zero byte).
fn integerLength(magnitude: []const u8) usize {
    const len = magnitude.len + @intFromBool(magnitude[0] & 0x80 != 0);
    return Der.headerLength(len) + len;
}

fn putInteger(out: []u8, at: usize, magnitude: []const u8) usize {
    @setRuntimeSafety(true);
    const pad = magnitude[0] & 0x80 != 0;
    var next = Der.header(out, at, 0x02, magnitude.len + @intFromBool(pad));
    if (pad) {
        out[next] = 0;
        next += 1;
    }
    @memcpy(out[next..][0..magnitude.len], magnitude);
    return next + magnitude.len;
}
