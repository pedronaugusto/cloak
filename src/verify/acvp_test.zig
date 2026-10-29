//! NIST's ACVP vectors (fixtures/acvp, provenance.md there): ECDSA signature and key
//! verification on P-256, P-384 and P-521; Ed25519 signatures verified and made (byte for byte:
//! Ed25519 is deterministic); X25519 shared secrets; RSA PKCS#1 v1.5 and PSS verification. Each campaign runs every vector of a curve, hash and form cloak has and counts
//! the rest as skipped; a campaign that checks nothing fails.
const std = @import("std");
const C = @import("../certificate.zig");
const S = @import("signature.zig");
const PrivateKey = @import("../PrivateKey.zig");
const Builder = @import("../wire/Builder.zig");

const Value = std.json.Value;
const Tally = struct {
    checked: usize = 0,
    skipped: usize = 0,
    mismatch: usize = 0,
    /// Keys outside cloak's key policy, checked to be refused there.
    refused_keys: usize = 0,
};

fn load(gpa: std.mem.Allocator, comptime file: []const u8) ![]Value {
    const parsed = try std.json.parseFromSliceLeaky(Value, gpa, @embedFile("fixtures/acvp/" ++ file), .{});
    return parsed.object.get("testGroups").?.array.items;
}

fn text(object: Value, name: []const u8) []const u8 {
    return object.object.get(name).?.string;
}

/// The hex field `name` as bytes, left-padded with zeros to `width` when it is shorter.
fn bytes(gpa: std.mem.Allocator, object: Value, name: []const u8, width: usize) ![]u8 {
    const digits = text(object, name);
    const out = try gpa.alloc(u8, @max(width, digits.len / 2));
    @memset(out, 0);
    _ = try std.fmt.hexToBytes(out[out.len - digits.len / 2 ..], digits);
    return out;
}

const Curve = struct { curve: C.Algorithm.Curve, oid: []const u8, width: usize };

fn curveOf(name: []const u8) ?Curve {
    if (std.mem.eql(u8, name, "P-256")) return .{ .curve = .p256, .oid = "\x2a\x86\x48\xce\x3d\x03\x01\x07", .width = 32 };
    if (std.mem.eql(u8, name, "P-384")) return .{ .curve = .p384, .oid = "\x2b\x81\x04\x00\x22", .width = 48 };
    if (std.mem.eql(u8, name, "P-521")) return .{ .curve = .p521, .oid = "\x2b\x81\x04\x00\x23", .width = 66 };
    return null;
}

fn hashOf(name: []const u8) ?C.Algorithm.Hash {
    if (std.mem.eql(u8, name, "SHA2-256")) return .sha256;
    if (std.mem.eql(u8, name, "SHA2-384")) return .sha384;
    if (std.mem.eql(u8, name, "SHA2-512")) return .sha512;
    return null;
}

/// 04 || x || y, each at the curve's width.
fn point(gpa: std.mem.Allocator, object: Value, x: []const u8, y: []const u8, width: usize) ![]u8 {
    return std.mem.concat(gpa, u8, &.{ "\x04", try bytes(gpa, object, x, width), try bytes(gpa, object, y, width) });
}

/// A SubjectPublicKeyInfo of `algorithm` (its AlgorithmIdentifier's DER) over `key`.
fn spki(gpa: std.mem.Allocator, algorithm: []const u8, key: []const u8) ![]u8 {
    var b = Builder.init(gpa);
    const outer = try b.open(0x30);
    try b.raw(algorithm);
    try b.bits(key);
    try b.close(outer);
    return b.toOwnedSlice();
}

fn ecKey(gpa: std.mem.Allocator, curve: Curve, sec1: []const u8) ![]u8 {
    var b = Builder.init(gpa);
    const id = try b.open(0x30);
    try b.element(0x06, "\x2a\x86\x48\xce\x3d\x02\x01");
    try b.element(0x06, curve.oid);
    try b.close(id);
    return spki(gpa, b.written(), sec1);
}

fn expected(vector: Value) bool {
    return vector.object.get("testPassed").?.bool;
}

fn finish(comptime what: []const u8, tally: Tally) !void {
    std.debug.print("ACVP " ++ what ++ ": {d} checked, {d} skipped, {d} keys refused by policy, {d} mismatched\n", .{ tally.checked, tally.skipped, tally.refused_keys, tally.mismatch });
    try std.testing.expectEqual(@as(usize, 0), tally.mismatch);
    try std.testing.expect(tally.checked != 0);
}

fn verdict(tally: *Tally, comptime what: []const u8, vector: Value, got: bool) void {
    tally.checked += 1;
    if (got == expected(vector)) return;
    tally.mismatch += 1;
    std.debug.print("ACVP " ++ what ++ " tcId={d} expected {} got {}\n", .{ vector.object.get("tcId").?.integer, expected(vector), got });
}

test "ACVP ECDSA SigVer (FIPS 186-5) on P-256, P-384 and P-521" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tally: Tally = .{};
    for (try load(gpa, "ECDSA-SigVer-FIPS186-5.json")) |group| {
        const tests = group.object.get("tests").?.array.items;
        const curve = curveOf(text(group, "curve")) orelse {
            tally.skipped += tests.len;
            continue;
        };
        const hash = hashOf(text(group, "hashAlg")) orelse {
            tally.skipped += tests.len;
            continue;
        };
        for (tests) |vector| {
            const key = C.parsePublicKey(try ecKey(gpa, curve, try point(gpa, vector, "qx", "qy", curve.width)));
            const signature = try std.mem.concat(gpa, u8, &.{ try bytes(gpa, vector, "r", curve.width), try bytes(gpa, vector, "s", curve.width) });
            const accepted = if (key) |pk| blk: {
                S.verify(pk, .{ .ecdsa_p1363 = hash }, try bytes(gpa, vector, "message", 0), signature) catch break :blk false;
                break :blk true;
            } else |_| false;
            verdict(&tally, "ECDSA SigVer", vector, accepted);
        }
    }
    try finish("ECDSA SigVer", tally);
}

test "ACVP ECDSA KeyVer (FIPS 186-5): the public key checks on P-256, P-384 and P-521" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tally: Tally = .{};
    for (try load(gpa, "ECDSA-KeyVer-FIPS186-5.json")) |group| {
        const tests = group.object.get("tests").?.array.items;
        const curve = curveOf(text(group, "curve")) orelse {
            tally.skipped += tests.len;
            continue;
        };
        for (tests) |vector| {
            const sec1 = try point(gpa, vector, "qx", "qy", curve.width);
            const checked = if (C.Algorithm.checkEc(curve.curve, sec1)) |_| true else |_| false;
            // A certificate's key is read through the same check.
            const parsed = if (C.parsePublicKey(try ecKey(gpa, curve, sec1))) |_| true else |_| false;
            verdict(&tally, "ECDSA KeyVer", vector, checked);
            verdict(&tally, "ECDSA KeyVer (SubjectPublicKeyInfo)", vector, parsed);
        }
    }
    try finish("ECDSA KeyVer", tally);
}

test "ACVP EdDSA SigVer: Ed25519" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tally: Tally = .{};
    for (try load(gpa, "EDDSA-SigVer-1.0.json")) |group| {
        const tests = group.object.get("tests").?.array.items;
        if (!std.mem.eql(u8, text(group, "curve"), "ED-25519") or group.object.get("preHash").?.bool) {
            tally.skipped += tests.len;
            continue;
        }
        for (tests) |vector| {
            const key = C.parsePublicKey(try spki(gpa, "\x30\x05\x06\x03\x2b\x65\x70", try bytes(gpa, vector, "q", 32)));
            const accepted = if (key) |pk| blk: {
                S.verify(pk, .ed25519, try bytes(gpa, vector, "message", 0), try bytes(gpa, vector, "signature", 0)) catch break :blk false;
                break :blk true;
            } else |_| false;
            verdict(&tally, "EdDSA SigVer", vector, accepted);
        }
    }
    try finish("EdDSA SigVer", tally);
}

test "ACVP EdDSA SigGen: Ed25519 signatures byte for byte" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tally: Tally = .{};
    for (try load(gpa, "EDDSA-SigGen-1.0.json")) |group| {
        const tests = group.object.get("tests").?.array.items;
        if (!std.mem.eql(u8, text(group, "curve"), "ED-25519") or group.object.get("preHash").?.bool) {
            tally.skipped += tests.len;
            continue;
        }
        const key = try PrivateKey.fromComponents(std.testing.allocator, .{ .ed25519 = .{ .seed = try bytes(gpa, group, "d", 32), .public = try bytes(gpa, group, "q", 32) } });
        defer key.deinit();
        for (tests) |vector| {
            // Ed25519 alone: Ed25519ctx's context is another algorithm.
            if (text(vector, "context").len != 0) {
                tally.skipped += 1;
                continue;
            }
            var out: [PrivateKey.max_signature]u8 = undefined;
            const made = try key.sign(.ed25519, try bytes(gpa, vector, "message", 0), "", &out);
            tally.checked += 1;
            if (!std.mem.eql(u8, made, try bytes(gpa, vector, "signature", 0))) {
                tally.mismatch += 1;
                std.debug.print("ACVP EdDSA SigGen tcId={d}: another signature\n", .{vector.object.get("tcId").?.integer});
            }
        }
    }
    try finish("EdDSA SigGen", tally);
}

test "ACVP XECDH SSC (RFC 7748): X25519 shared secrets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tally: Tally = .{};
    for (try load(gpa, "XECDH-SSC-RFC7748.json")) |group| {
        const tests = group.object.get("tests").?.array.items;
        if (!std.mem.eql(u8, text(group, "curve"), "Curve25519")) {
            tally.skipped += tests.len;
            continue;
        }
        for (tests) |vector| {
            const key = try PrivateKey.fromComponents(std.testing.allocator, .{ .x25519 = .{ .d = try bytes(gpa, vector, "privateIut", 32) } });
            defer key.deinit();
            var out: [PrivateKey.max_shared]u8 = undefined;
            const same = if (key.agree(try bytes(gpa, vector, "publicServer", 32), &out)) |z|
                std.mem.eql(u8, z, try bytes(gpa, vector, "z", 32))
            else |_|
                false;
            verdict(&tally, "XECDH SSC", vector, same);
        }
    }
    try finish("XECDH SSC", tally);
}

test "ACVP RSA SigVer (FIPS 186-5): PKCS#1 v1.5 and PSS with MGF1" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    var tally: Tally = .{};
    for (try load(gpa, "RSA-SigVer-FIPS186-5.json")) |group| {
        const tests = group.object.get("tests").?.array.items;
        const kind = text(group, "sigType");
        const hash = hashOf(text(group, "hashAlg"));
        const pss = std.mem.eql(u8, kind, "pss");
        if (hash == null or !(pss or std.mem.eql(u8, kind, "pkcs1v1.5")) or (pss and !std.mem.eql(u8, text(group, "maskFunction"), "mgf1"))) {
            tally.skipped += tests.len;
            continue;
        }
        const algorithm: C.Algorithm.Signature = if (pss)
            .{ .pss = .{ .hash = hash.?, .mgf_hash = hash.?, .salt_length = @intCast(group.object.get("saltLen").?.integer) } }
        else
            .{ .rsa = hash.? };
        var numbers = Builder.init(gpa);
        const seq = try numbers.open(0x30);
        const modulus = try bytes(gpa, group, "n", 0);
        try numbers.unsigned(modulus);
        const exponent = try bytes(gpa, group, "e", 0);
        try numbers.unsigned(exponent);
        try numbers.close(seq);
        const key = C.parsePublicKey(try spki(gpa, "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00", numbers.written()));
        // FIPS 186-5 allows exponents to 2^256; cloak's key policy stops at 2^32 - 1
        // (`Algorithm.checkRsa`), so such a key is refused before any signature is read.
        if (exponent.len > 4) {
            try std.testing.expectError(error.InvalidPublicKey, key);
            tally.refused_keys += tests.len;
            continue;
        }
        for (tests) |vector| {
            const accepted = if (key) |pk| blk: {
                S.verify(pk, algorithm, try bytes(gpa, vector, "message", 0), try bytes(gpa, vector, "signature", modulus.len)) catch break :blk false;
                break :blk true;
            } else |_| false;
            verdict(&tally, "RSA SigVer", vector, accepted);
        }
    }
    try finish("RSA SigVer", tally);
}
