//! Certificate Transparency's checks (F88): RFC 6962's reference vectors, a public certificate
//! from two production logs, and the policy over certificate-transparency-go's test PKI.
const std = @import("std");
const C = @import("../certificate.zig");
const T = @import("../types.zig");
const Der = @import("../wire/Der.zig");
const ct = @import("transparency.zig");
const signatures = @import("signature.zig");
const gpa = std.testing.allocator;

const vectors = struct {
    const log = @embedFile("fixtures/ct/ct-server-key-public.der");
    const ca = @embedFile("fixtures/ct/ca-cert.der");
    const intermediate = @embedFile("fixtures/ct/intermediate-cert.der");
    const cert = @embedFile("fixtures/ct/test-cert.der");
    const proof = @embedFile("fixtures/ct/test-cert.proof");
    const invalid = @embedFile("fixtures/ct/test-invalid-embedded-cert.der");
};

const pki = struct {
    const ca = @embedFile("../testing/pki/ct_ca.der");
    const leaf = @embedFile("../testing/pki/ct_leaf.der");
    const one_operator = @embedFile("../testing/pki/ct_leaf_one_operator.der");
    const long = @embedFile("../testing/pki/ct_leaf_long.der");
    const long_three = @embedFile("../testing/pki/ct_leaf_long_three.der");
    const wrong_entry = @embedFile("../testing/pki/ct_leaf_wrong_entry.der");
    const plain = @embedFile("../testing/pki/ct_plain.der");
    const plain_scts = @embedFile("../testing/pki/ct_plain.scts");
    const log_a = @embedFile("../testing/pki/ct_log_a.spki.der");
    const log_b = @embedFile("../testing/pki/ct_log_b.spki.der");
    const log_c = @embedFile("../testing/pki/ct_log_c.spki.der");
    const log_d = @embedFile("../testing/pki/ct_log_d.spki.der");
    /// The SCTs were issued an hour after 2026-12-01T00:00:00Z, when the certificates start.
    const issued_ms: i64 = 1_796_086_800_000;
    const now_ms: i64 = 1_800_000_000_000;
};

const logs = [_]T.TransparencyLog{
    .{ .key = pki.log_a, .operator = "alpha" },
    .{ .key = pki.log_b, .operator = "beta" },
    .{ .key = pki.log_c, .operator = "alpha" },
    .{ .key = pki.log_d, .operator = "gamma" },
};

/// A certificate's TBS, issuer key and extensions by DER alone: the reference vectors' RSA-1024
/// and SHA-1 keep them out of the certificate parser.
const Raw = struct {
    tbs: []const u8,
    spki: []const u8,
    scts: ?[]const u8,

    fn of(der: []const u8) !Raw {
        var outer = (try Der.single(der, 0x30)).reader();
        const tbs = try outer.expect(0x30);
        var r = tbs.reader();
        if (r.peek() == 0xa0) _ = try r.next();
        for (0..5) |_| _ = try r.next();
        const spki = (try r.expect(0x30)).encoded;
        var scts: ?[]const u8 = null;
        while (!r.empty()) {
            const field = try r.next();
            if (field.tag != 0xa3) continue;
            var list = (try Der.single(field.value, 0x30)).reader();
            while (!list.empty()) {
                var ext = (try list.expect(0x30)).reader();
                if (std.mem.eql(u8, (try ext.expect(6)).value, ct.sct_list_oid)) scts = (try Der.single((try ext.expect(4)).value, 4)).value;
            }
        }
        return .{ .tbs = tbs.encoded, .spki = spki, .scts = scts };
    }
};

fn verifyOne(sct: ct.Sct, entry: ct.Entry, log: []const u8) !void {
    const input = try ct.signedInput(gpa, sct, entry);
    defer gpa.free(input);
    try signatures.verify(try C.Algorithm.publicKey(log), .{ .ecdsa = .sha256 }, input, sct.signature);
}

/// Checks every SCT embedded in `leaf` over its precertificate under `issuer`'s key.
fn embeddedVector(leaf: []const u8, issuer: []const u8) !void {
    const raw = try Raw.of(leaf);
    var list = try ct.List.init(raw.scts.?);
    const tbs = try ct.precertificate(gpa, raw.tbs);
    defer gpa.free(tbs);
    var key_hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash((try Raw.of(issuer)).spki, &key_hash, .{});
    var n: usize = 0;
    while (list.next()) |sct| : (n += 1) try verifyOne(sct, .{ .precert = .{ .issuer_key_hash = &key_hash, .tbs = tbs } }, vectors.log);
    try std.testing.expectEqual(1, n);
}

test "F88 RFC 6962 reference vectors: embedded SCTs over the precertificate, also through a precertificate signing certificate" {
    try embeddedVector(@embedFile("fixtures/ct/test-embedded-cert.der"), vectors.ca);
    try embeddedVector(@embedFile("fixtures/ct/test-embedded-with-preca-cert.der"), vectors.ca);
    try embeddedVector(@embedFile("fixtures/ct/test-embedded-with-intermediate-cert.der"), vectors.intermediate);
    try embeddedVector(@embedFile("fixtures/ct/test-embedded-with-intermediate-preca-cert.der"), vectors.intermediate);
    // An SCT for another precertificate, and a right one checked under the wrong issuer.
    try std.testing.expectError(error.InvalidSignature, embeddedVector(vectors.invalid, vectors.ca));
    try std.testing.expectError(error.InvalidSignature, embeddedVector(@embedFile("fixtures/ct/test-embedded-cert.der"), vectors.intermediate));
}

test "F88 RFC 6962 reference vectors: an SCT over the certificate itself" {
    // test-cert.proof is one serialized SCT: frame it as a list.
    var list_bytes: [4 + vectors.proof.len]u8 = undefined;
    std.mem.writeInt(u16, list_bytes[0..2], vectors.proof.len + 2, .big);
    std.mem.writeInt(u16, list_bytes[2..4], vectors.proof.len, .big);
    @memcpy(list_bytes[4..], vectors.proof);
    var list = try ct.List.init(&list_bytes);
    const sct = list.next().?;
    try std.testing.expect(list.next() == null);
    try verifyOne(sct, .{ .x509 = vectors.cert }, vectors.log);
    try std.testing.expectError(error.InvalidSignature, verifyOne(sct, .{ .x509 = vectors.invalid }, vectors.log));
}

test "F88 a public certificate's SCTs from two production logs meet the default policy" {
    const leaf = try C.parse(@embedFile("fixtures/ct/www-google-com.der"), .{});
    const issuer = try C.parse(@embedFile("fixtures/ct/google-we2.der"), .{});
    const production = [_]T.TransparencyLog{
        .{ .key = @embedFile("fixtures/ct/argon2026h2.spki.der"), .operator = "Google" },
        .{ .key = @embedFile("fixtures/ct/wyvern2026h2.spki.der"), .operator = "DigiCert" },
    };
    // 2026-10-17T00:00:00Z, within the certificate's validity.
    const now_ms: i64 = 1_792_195_200_000;
    var budget: usize = 16;
    const result = try ct.check(gpa, &.{ leaf, issuer }, now_ms, &.{ .logs = &production }, &.{}, &budget);
    try std.testing.expectEqual(.compliant, result.status);
    try std.testing.expectEqual(14, budget);
    // One operator is not two.
    budget = 16;
    try std.testing.expectError(error.MissingTransparency, ct.check(gpa, &.{ leaf, issuer }, now_ms, &.{ .logs = production[0..1], .operators = 2 }, &.{}, &budget));
}

fn checkLeaf(der: []const u8, policy: T.TransparencyPolicy, scts: []const []const u8, now_ms: i64) ct.Error!ct.Result {
    const path = [_]C.Certificate{ C.parse(der, .{}) catch unreachable, C.parse(pki.ca, .{}) catch unreachable };
    var budget: usize = 64;
    return ct.check(gpa, &path, now_ms, &policy, scts, &budget);
}

const required: T.TransparencyPolicy = .{ .logs = &logs };

test "F88 catalogue_ct_sct_lengths_wrong_entry_and_log_generation (the policy over embedded and delivered SCTs)" {
    const expectMissing = struct {
        fn run(der: []const u8, policy: T.TransparencyPolicy, scts: []const []const u8, now_ms: i64) !void {
            try std.testing.expectError(error.MissingTransparency, checkLeaf(der, policy, scts, now_ms));
        }
    }.run;
    // Two logs of two operators embedded: compliant; one SCT short of the long-lived count is not,
    // a third (an RSA log's) is.
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.leaf, required, &.{}, pki.now_ms)).status);
    try expectMissing(pki.long, required, &.{}, pki.now_ms);
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.long_three, required, &.{}, pki.now_ms)).status);
    // Two logs of one operator meet the count, not the diversity.
    try expectMissing(pki.one_operator, required, &.{}, pki.now_ms);
    var lenient = required;
    lenient.operators = 1;
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.one_operator, lenient, &.{}, pki.now_ms)).status);
    // An SCT for another precertificate counts for nothing: one valid log is left.
    try expectMissing(pki.wrong_entry, required, &.{}, pki.now_ms);
    lenient.embedded = 1;
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.wrong_entry, lenient, &.{}, pki.now_ms)).status);
    // Logs not listed count for nothing.
    try expectMissing(pki.leaf, .{ .logs = logs[2..] }, &.{}, pki.now_ms);
    // An SCT timestamped after now is no evidence yet.
    try expectMissing(pki.leaf, required, &.{}, pki.issued_ms - 1);

    // Delivered SCTs sign the certificate itself; those for another certificate do not count.
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.plain, required, &.{pki.plain_scts}, pki.now_ms)).status);
    try expectMissing(pki.plain, required, &.{}, pki.now_ms);
    try expectMissing(pki.one_operator, required, &.{pki.plain_scts}, pki.now_ms);
    // One log's SCT twice is one log.
    const first_len = std.mem.readInt(u16, pki.plain_scts[2..4], .big);
    const first = pki.plain_scts[2..][0 .. 2 + first_len];
    var twice: [2 + 2 * (2 + 120)]u8 = undefined;
    std.debug.assert(first.len <= 122);
    std.mem.writeInt(u16, twice[0..2], @intCast(2 * first.len), .big);
    @memcpy(twice[2..][0..first.len], first);
    @memcpy(twice[2 + first.len ..][0..first.len], first);
    const doubled = twice[0 .. 2 + 2 * first.len];
    lenient = required;
    lenient.operators = 1;
    try expectMissing(pki.plain, lenient, &.{doubled}, pki.now_ms);
    // Nor does the same list delivered twice (a TLS extension and an OCSP response).
    try expectMissing(pki.plain, lenient, &.{ doubled, doubled }, pki.now_ms);
}

test "F88 catalogue_ct_sct_lengths_wrong_entry_and_log_generation (retired logs and the log list's generation)" {
    const at = struct {
        fn ms(value: i64) std.Io.Timestamp {
            return .fromNanoseconds(@as(i96, value) * std.time.ns_per_ms);
        }
    }.ms;
    var retired = logs;
    // Retired before it signed: the SCT counts for nothing.
    retired[0].retired = at(pki.issued_ms);
    try std.testing.expectError(error.MissingTransparency, checkLeaf(pki.leaf, .{ .logs = &retired }, &.{}, pki.now_ms));
    // Retired after it signed: an embedded SCT still counts beside one from a log not retired.
    retired[0].retired = at(pki.issued_ms + 1);
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.leaf, .{ .logs = &retired }, &.{}, pki.now_ms)).status);
    // A retirement still to come leaves the log current.
    retired[1].retired = at(pki.now_ms + 1);
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.leaf, .{ .logs = &retired }, &.{}, pki.now_ms)).status);
    // Both retired: none is current.
    retired[1].retired = at(pki.issued_ms + 1);
    try std.testing.expectError(error.MissingTransparency, checkLeaf(pki.leaf, .{ .logs = &retired }, &.{}, pki.now_ms));
    // A delivered SCT counts only from a log not retired.
    retired = logs;
    retired[0].retired = at(pki.issued_ms + 1);
    try std.testing.expectError(error.MissingTransparency, checkLeaf(pki.plain, .{ .logs = &retired }, &.{pki.plain_scts}, pki.now_ms));

    // A log list past its expiry decides nothing; before it, the verdict holds until then.
    var policy = required;
    policy.expires = at(pki.now_ms);
    try std.testing.expectError(error.StaleTransparency, checkLeaf(pki.leaf, policy, &.{}, pki.now_ms));
    policy.expires = at(pki.now_ms + 5000);
    const result = try checkLeaf(pki.leaf, policy, &.{}, pki.now_ms);
    // The last second it holds starts one before the list's expiry, on a second boundary or not.
    try std.testing.expectEqual(@divFloor(pki.now_ms, 1000) + 4, result.expires.?);
    policy.expires = at(pki.now_ms + 5500);
    try std.testing.expectEqual(@divFloor(pki.now_ms, 1000) + 5, (try checkLeaf(pki.leaf, policy, &.{}, pki.now_ms)).expires.?);

    // A policy that cannot decide is refused; off decides nothing.
    try std.testing.expectError(error.InvalidTransparencyPolicy, checkLeaf(pki.leaf, .{}, &.{}, pki.now_ms));
    policy = required;
    policy.operators = 0;
    try std.testing.expectError(error.InvalidTransparencyPolicy, checkLeaf(pki.leaf, policy, &.{}, pki.now_ms));
    policy = required;
    policy.embedded = T.TransparencyPolicy.max_count + 1;
    try std.testing.expectError(error.InvalidTransparencyPolicy, checkLeaf(pki.leaf, policy, &.{}, pki.now_ms));
    var bad_key = logs;
    bad_key[0].key = pki.ca;
    try std.testing.expectError(error.InvalidTransparencyPolicy, checkLeaf(pki.leaf, .{ .logs = &bad_key }, &.{}, pki.now_ms));
    var budget: usize = 1;
    const path = [_]C.Certificate{ try C.parse(pki.leaf, .{}), try C.parse(pki.ca, .{}) };
    try std.testing.expectEqual(.unchecked, (try ct.check(gpa, &path, pki.now_ms, null, &.{"garbage"}, &budget)).status);
}

test "F88 catalogue_ct_sct_lengths_wrong_entry_and_log_generation (lengths: truncated lists, empty SCTs, other versions, no read past the end)" {
    const list = pki.plain_scts;
    try std.testing.expectError(error.InvalidTransparency, checkLeaf(pki.plain, required, &.{list[0 .. list.len - 1]}, pki.now_ms));
    try std.testing.expectError(error.InvalidTransparency, checkLeaf(pki.plain, required, &.{list[1..]}, pki.now_ms));
    for ([_][]const u8{ "", "\x00\x00", "\x00\x02\x00\x00", "\x00\x03\x00\x01\x00", "\x00\x01\x00" }) |bad| try std.testing.expectError(error.InvalidTransparency, ct.List.init(bad));
    // Trailing bytes after the list.
    var long: [list.len + 1]u8 = undefined;
    @memcpy(long[0..list.len], list);
    long[list.len] = 0;
    try std.testing.expectError(error.InvalidTransparency, ct.List.init(&long));
    // A version this end does not know is skipped, framed; the rest still count.
    var mixed: [list.len + 5]u8 = undefined;
    std.mem.writeInt(u16, mixed[0..2], list.len - 2 + 5, .big);
    @memcpy(mixed[2..7], "\x00\x03\x01\xaa\xbb");
    @memcpy(mixed[7..], list[2..]);
    try std.testing.expectEqual(.compliant, (try checkLeaf(pki.plain, required, &.{&mixed}, pki.now_ms)).status);
    // Every truncation and every flipped byte of a list and of a certificate's SCT extension is
    // refused or counts for nothing: never compliant, never read past.
    const refused = struct {
        fn check(result: ct.Error!ct.Result) !void {
            if (result) |_| return error.TestUnexpectedResult else |err| switch (err) {
                error.InvalidTransparency, error.MissingTransparency => {},
                else => return err,
            }
        }
    }.check;
    var copy: [list.len]u8 = undefined;
    for (0..list.len) |i| {
        try refused(checkLeaf(pki.plain, required, &.{list[0..i]}, pki.now_ms));
        @memcpy(&copy, list);
        copy[i] ^= 0x80;
        try refused(checkLeaf(pki.plain, required, &.{&copy}, pki.now_ms));
    }
    const raw = try Raw.of(pki.leaf);
    var leaf: [pki.leaf.len]u8 = pki.leaf.*;
    const at = std.mem.find(u8, pki.leaf, raw.scts.?).?;
    for (0..raw.scts.?.len) |i| {
        leaf[at + i] ^= 0x80;
        try refused(checkLeaf(&leaf, required, &.{}, pki.now_ms));
        leaf[at + i] ^= 0x80;
    }
    // Lists beyond the bound, and signatures beyond the budget, are work refused.
    const too_many: [T.TransparencyPolicy.max_lists + 1][]const u8 = @splat(list);
    try std.testing.expectError(error.VerificationLimit, checkLeaf(pki.plain, required, &too_many, pki.now_ms));
    const path = [_]C.Certificate{ try C.parse(pki.plain, .{}), try C.parse(pki.ca, .{}) };
    var budget: usize = 1;
    try std.testing.expectError(error.VerificationLimit, ct.check(gpa, &path, pki.now_ms, &required, &.{list}, &budget));
}

test "the precertificate is the certificate's TBS without the SCT list, re-encoded" {
    const leaf = try C.parse(pki.leaf, .{});
    const tbs = try ct.precertificate(gpa, leaf.tbs);
    defer gpa.free(tbs);
    try std.testing.expect(tbs.len < leaf.tbs.len);
    try std.testing.expect(std.mem.find(u8, tbs, ct.sct_list_oid) == null);
    try Der.validate(tbs, .{});
    // A certificate without the extension has no precertificate.
    try std.testing.expectError(error.InvalidTransparency, ct.precertificate(gpa, (try C.parse(pki.plain, .{})).tbs));
}

test "F88 catalogue_ct_sct_lengths_wrong_entry_and_log_generation (the verifier: typed verdicts, the receipt bound to the SCTs and held no longer than the log list)" {
    const Verifier = @import("Verifier.zig");
    const now: std.Io.Timestamp = .fromNanoseconds(@as(i96, pki.now_ms) * std.time.ns_per_ms);
    var policy = required;
    policy.expires = .fromNanoseconds(@as(i96, pki.now_ms + 3_600_000) * std.time.ns_per_ms);
    const base: T.Request = .{ .chain = &.{pki.leaf}, .identity = .{ .dns = "example.com" }, .time = now, .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1), .policy = .{ .transparency = &policy } };
    var receipt = try Verifier.verify(gpa, base, &.{pki.ca});
    defer receipt.deinit();
    try std.testing.expectEqual(.compliant, receipt.transparency);
    try std.testing.expectEqual(@divFloor(pki.now_ms, 1000) + 3599, T.seconds(receipt.expires));
    try receipt.check(base);
    // A certificate without SCTs: the verdict says why, not only that no path was found.
    var plain = base;
    plain.chain = &.{pki.plain};
    try std.testing.expectError(error.MissingTransparency, Verifier.verify(gpa, plain, &.{pki.ca}));
    plain.evidence = .{ .scts = &.{pki.plain_scts} };
    var delivered = try Verifier.verify(gpa, plain, &.{pki.ca});
    defer delivered.deinit();
    try std.testing.expectEqual(.compliant, delivered.transparency);
    // The receipt answers exactly the request whose SCTs it checked, and only under its log list.
    var other = plain;
    other.evidence = .{};
    try std.testing.expectError(error.WrongVerificationRequest, delivered.check(other));
    other = plain;
    var retired = logs;
    retired[3].retired = now;
    var retired_policy = required;
    retired_policy.logs = &retired;
    other.policy.transparency = &retired_policy;
    try std.testing.expectError(error.WrongVerificationRequest, delivered.check(other));
    // A stale log list decides nothing; off checks nothing.
    var stale = base;
    var stale_policy = policy;
    stale_policy.expires = now;
    stale.policy.transparency = &stale_policy;
    try std.testing.expectError(error.StaleTransparency, Verifier.verify(gpa, stale, &.{pki.ca}));
    var off = plain;
    off.policy = .{};
    off.evidence = .{};
    var unchecked = try Verifier.verify(gpa, off, &.{pki.ca});
    defer unchecked.deinit();
    try std.testing.expectEqual(.unchecked, unchecked.transparency);
}
