const std = @import("std");
const Der = @import("../wire/Der.zig");
pub const Error = Der.Error || error{ UnsupportedAlgorithm, InvalidPublicKey };
pub const Hash = enum { sha256, sha384, sha512 };
pub const Pss = struct { hash: Hash, mgf_hash: Hash, salt_length: usize, trailer: usize = 1 };
pub const Signature = union(enum) { rsa: Hash, pss: Pss, ecdsa: Hash, ed25519, unsupported: []const u8 };
pub const Curve = enum { p256, p384 };
pub const PublicKey = union(enum) {
    rsa: struct { modulus: []const u8, exponent: []const u8, pss: ?Pss = null, pss_only: bool = false },
    ec: struct { curve: Curve, bytes: []const u8 },
    ed25519: []const u8,
};
pub const rsa_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";
pub const pss_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x0a";
const ed_oid = "\x2b\x65\x70";
const ec_oid = "\x2a\x86\x48\xce\x3d\x02\x01";
const p256_oid = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const p384_oid = "\x2b\x81\x04\x00\x22";
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
        if (n.len < 256 or n.len > 512 or n[0] == 0 or n[n.len - 1] & 1 == 0) return error.InvalidPublicKey;
        // safe: clz on u8 is at most eight and widens to usize.
        const bits = n.len * 8 - @as(usize, @clz(n[0]));
        if (bits < 2048 or exponent.len > 4) return error.InvalidPublicKey;
        const ev = try Der.number(exponent);
        if (ev < 3 or ev & 1 == 0) return error.InvalidPublicKey;
        return .{ .rsa = .{ .modulus = n, .exponent = exponent, .pss = pss, .pss_only = eql(id, pss_oid) } };
    }
    if (eql(id, ec_oid)) {
        const p = param orelse return error.InvalidDer;
        if (p.tag != 6) return error.InvalidDer;
        const curve: Curve = if (eql(p.value, p256_oid)) .p256 else if (eql(p.value, p384_oid)) .p384 else return error.UnsupportedAlgorithm;
        const point_length: usize = if (curve == .p256) 65 else 97;
        if (bytes.len != point_length or bytes[0] != 4) return error.InvalidPublicKey;
        switch (curve) {
            .p256 => {
                _ = std.crypto.sign.ecdsa.EcdsaP256Sha256.PublicKey.fromSec1(bytes) catch return error.InvalidPublicKey;
            },
            .p384 => {
                _ = std.crypto.sign.ecdsa.EcdsaP384Sha384.PublicKey.fromSec1(bytes) catch return error.InvalidPublicKey;
            },
        }
        return .{ .ec = .{ .curve = curve, .bytes = bytes } };
    }
    if (eql(id, ed_oid)) {
        if (param != null or bytes.len != 32) return error.InvalidPublicKey;
        _ = std.crypto.sign.Ed25519.PublicKey.fromBytes(bytes[0..32].*) catch return error.InvalidPublicKey;
        const point = std.crypto.ecc.Edwards25519.fromBytes(bytes[0..32].*) catch return error.InvalidPublicKey;
        point.rejectLowOrder() catch return error.InvalidPublicKey;
        point.rejectUnexpectedSubgroup() catch return error.InvalidPublicKey;
        return .{ .ed25519 = bytes };
    }
    return error.UnsupportedAlgorithm;
}
