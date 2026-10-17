const std = @import("std");
const C = @import("../certificate.zig");
const V = @import("Verifier.zig");
const profiles = @import("limbo_profiles.zig");
const T = @import("../types.zig");
const Case = struct {
    id: []const u8,
    features: []const []const u8,
    validation_kind: []const u8,
    validation_time: ?[]const u8,
    trusted_certs: []const []const u8,
    untrusted_intermediates: []const []const u8,
    peer_certificate: []const u8,
    expected_result: []const u8,
    expected_peer_name: ?struct { kind: []const u8, value: []const u8 },
    expected_peer_names: []const std.json.Value,
    max_chain_depth: ?usize,
    crls: []const []const u8,
};
fn der(gpa: std.mem.Allocator, pem: []const u8) ![]const u8 {
    const start = (std.mem.findScalar(u8, pem, '\n') orelse return error.InvalidPem) + 1;
    const end = std.mem.find(u8, pem[start..], "-----END") orelse return error.InvalidPem;
    const encoded = try gpa.alloc(u8, end);
    var len: usize = 0;
    for (pem[start..][0..end]) |c| if (!std.ascii.isWhitespace(c)) {
        encoded[len] = c;
        len += 1;
    };
    const decoded = try gpa.alloc(u8, try std.base64.standard.Decoder.calcSizeForSlice(encoded[0..len]));
    try std.base64.standard.Decoder.decode(decoded, encoded[0..len]);
    return decoded;
}
fn ders(gpa: std.mem.Allocator, pems: []const []const u8) ![]const []const u8 {
    const out = try gpa.alloc([]const u8, pems.len);
    for (pems, out) |pem, *bytes| bytes.* = try der(gpa, pem);
    return out;
}
fn timestamp(input: ?[]const u8) !i64 {
    // Fixed test time when the vector leaves clock choice to the harness.
    const s = input orelse "2024-01-01T00:00:00+00:00";
    var compact: [15]u8 = undefined;
    var cursor: usize = 0;
    for (s[0..19]) |c| if (std.ascii.isDigit(c)) {
        compact[cursor] = c;
        cursor += 1;
    };
    compact[14] = 'Z';
    return C.Certificate.evidenceTime(.{ .tag = 0x18, .encoded = &.{}, .value = &compact });
}
fn reference(case: Case) !T.Identity {
    const peer = case.expected_peer_name orelse return .none;
    if (std.mem.eql(u8, peer.kind, "DNS")) return .{ .dns = peer.value };
    const address = try std.Io.net.IpAddress.parse(peer.value, 0);
    return switch (address) {
        .ip4 => |v| .{ .ipv4 = v.bytes },
        .ip6 => |v| .{ .ipv6 = v.bytes },
    };
}
test "x509-limbo portable complete corpus profile mapping batch 1 of 8" {
    try corpus(0);
}

test "x509-limbo portable complete corpus profile mapping batch 2 of 8" {
    try corpus(1);
}

test "x509-limbo portable complete corpus profile mapping batch 3 of 8" {
    try corpus(2);
}

test "x509-limbo portable complete corpus profile mapping batch 4 of 8" {
    try corpus(3);
}

test "x509-limbo portable complete corpus profile mapping batch 5 of 8" {
    try corpus(4);
}

test "x509-limbo portable complete corpus profile mapping batch 6 of 8" {
    try corpus(5);
}

test "x509-limbo portable complete corpus profile mapping batch 7 of 8" {
    try corpus(6);
}

test "x509-limbo portable complete corpus profile mapping batch 8 of 8" {
    try corpus(7);
}

// The failure catalogue's rows the corpus guards, each over the cases that exercise it; the
// batches above run every case, these name what each row rests on.

test "F10 catalogue_ca_bit_usage_and_pathlen (x509-limbo: the CA bit, key usage, extended key usage and path length)" {
    try family(&.{ "pathlen::*", "rfc5280::intermediate-ca-without-ca-bit", "rfc5280::intermediate-ca-missing-basic-constraints", "rfc5280::root-inconsistent-ca-extensions", "rfc5280::ica-ku-keycertsign", "rfc5280::leaf-ku-keycertsign", "rfc5280::no-keyusage", "rfc5280::no-basicconstraints", "rfc5280::ca-as-leaf", "rfc5280::ca-as-leaf-wrong-san", "rfc5280::eku::*", "webpki::eku::*", "webpki::ee-basicconstraints-ca", "webpki::ca-as-leaf", "rfc9881::ml-dsa-44-key-encipherment", "rfc9881::ml-dsa-44-key-agreement" });
}

test "F11 catalogue_untrusted_self_signed_and_verifier_error (x509-limbo: an untrusted root, swapped roots and a missing intermediate)" {
    try family(&.{ "rfc5280::chain-untrusted-root", "rfc5280::root-and-intermediate-swapped", "webpki::cryptographydotio-chain-missing-intermediate", "webpki::cryptographydotio-chain" });
}

test "F12 catalogue_alternate_chain_rechecks_constraints (x509-limbo: bettertls path building and alternate chains)" {
    try family(&.{ "bettertls::pathbuilding::*", "rfc5280::nc::nc-forbids-alternate-chain-ica", "rfc5280::nc::nc-forbids-same-chain-ica", "pathological::multiple-chains-expired-intermediate" });
}

test "F13 catalogue_cross_signed_cycles_and_chain_depth (x509-limbo: cycles, pathological chains and depth limits)" {
    try family(&.{ "pathological::intermediate-cycle-*", "pathological::pathological-chain-*", "cve::cve-2024-0567", "pathlen::max-chain-depth-*" });
}

test "F16 catalogue_wildcard_constraint_intersection_and_case (x509-limbo: wildcard names and wildcard constraints)" {
    try family(&.{ "cve::cve-2025-61727", "cve::cve-2025-61727-nc-permits-variant", "rfc5280::nc::nc-forbids-dnsname-wildcard-san", "rfc5280::nc::invalid-dnsname-wildcard", "webpki::san::public-suffix-wildcard-san", "webpki::san::leftmost-wildcard-san", "webpki::san::wildcard-*", "webpki::san::san-wildcard-only*", "webpki::san::mismatch-*" });
}

test "F17 catalogue_nul_san_and_no_cn_fallback (x509-limbo: no common-name fallback, malformed and absent SANs)" {
    try family(&.{ "webpki::cn::*", "webpki::san::no-san", "webpki::san::exact-*", "webpki::san::unicode-emoji-san", "rfc5280::san::malformed", "rfc5280::san::noncritical-with-empty-subject" });
}

test "F19 catalogue_general_name_syntax_and_constraint_forms (x509-limbo: name forms in SANs and in constraints)" {
    try family(&.{ "rfc5280::nc::invalid-*", "rfc5280::nc::nc-permits-invalid-*", "rfc5280::nc::nc-permits-email-*", "rfc5280::nc::nc-permits-uri-*", "rfc5280::nc::nc-forbids-othername*", "rfc5280::nc::permitted-dn-*", "rfc5280::nc::excluded-dn-*", "rfc5280::nc::permitted-ip*", "rfc5280::nc::excluded-ipv*", "rfc5280::nc::permitted-different-constraint-type", "rfc5280::nc::excluded-different-constraint-type", "rfc5280::san::ip-in-dns", "rfc5280::san::underscore-dns", "webpki::nc::nc-permits-dns-san-pattern" });
}

test "F20 catalogue_crldp_generalname_and_expansion_budget (x509-limbo: CRLs of unsupported scope or unknown critical extensions fail closed)" {
    try family(&.{"crl::*"});
}

test "F24 catalogue_algorithm_identifier_and_empty_point (x509-limbo: mismatched and weak algorithms, explicit curves, invalid keys)" {
    try family(&.{ "rfc5280::mismatching-signature-algorithm", "webpki::explicit-curve", "webpki::forbidden-*", "invalid::invalid-issuer-key", "webpki::v1-cert", "rfc9881::ml-dsa-44", "rfc9881::ml-dsa-65", "rfc9881::ml-dsa-87", "rfc9881::ml-dsa-44-bad-signature" });
}

fn corpus(comptime batch: usize) !void {
    @setRuntimeSafety(true);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try std.json.parseFromSlice(struct { version: usize, testcases: []Case }, arena.allocator(), @embedFile("fixtures/limbo.json"), .{ .ignore_unknown_fields = true });
    // Fixed fixture cardinality and disjoint residues preserve complete coverage.
    try std.testing.expectEqual(@as(usize, 9802), parsed.value.testcases.len);
    const selected = (parsed.value.testcases.len + 7 - batch) / 8;
    var tally: Tally = .{};
    for (parsed.value.testcases, 0..) |case, case_index| {
        if (case_index % 8 != batch) continue;
        try check(case, &tally);
    }
    std.debug.print("LIMBO batch {d}/8 matched {d} flat and {d} indexed, mismatches {d}\n", .{ batch + 1, tally.passed, tally.indexed_passed, tally.mismatches });
    try std.testing.expectEqual(selected, tally.passed);
    try std.testing.expectEqual(selected, tally.indexed_passed);
    try std.testing.expectEqual(@as(usize, 0), tally.mismatches);
}

/// The corpus cases a failure-catalogue row names: every id equal to an entry, or under an
/// entry ending in "*". Each entry must select at least one case, so a renamed corpus family
/// cannot leave a row guarding nothing.
pub fn family(names: []const []const u8) !void {
    @setRuntimeSafety(true);
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try std.json.parseFromSlice(struct { version: usize, testcases: []Case }, arena.allocator(), @embedFile("fixtures/limbo.json"), .{ .ignore_unknown_fields = true });
    var tally: Tally = .{};
    for (names) |name| {
        var selected: usize = 0;
        for (parsed.value.testcases) |case| {
            const hit = if (std.mem.endsWith(u8, name, "*")) std.mem.startsWith(u8, case.id, name[0 .. name.len - 1]) else std.mem.eql(u8, case.id, name);
            if (!hit) continue;
            selected += 1;
            try check(case, &tally);
        }
        if (selected == 0) {
            std.debug.print("LIMBO family entry {s} selects no case\n", .{name});
            return error.EmptyFamily;
        }
    }
    try std.testing.expectEqual(@as(usize, 0), tally.mismatches);
    try std.testing.expectEqual(tally.passed, tally.indexed_passed);
}

const Tally = struct { passed: usize = 0, indexed_passed: usize = 0, mismatches: usize = 0 };

/// Verifies one case flat and through the issuer index, each against its expected verdict.
fn check(case: Case, tally: *Tally) !void {
    @setRuntimeSafety(true);
    var item = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer item.deinit();
    const alloc = item.allocator();
    const described = try requestOf(alloc, case);
    const anchors = described.anchors;
    const chain = described.request.chain;
    var configured = described.request;
    if (std.mem.startsWith(u8, case.id, "bettertls::pathbuilding::")) {
        configured.limits.certificates = @max(16, chain.len);
        configured.limits.chain_bytes = 262144;
        configured.limits.candidates = 16384;
        configured.limits.parses = 16384;
        configured.limits.signatures = 4096;
        configured.limits.rejected = 16384;
        configured.limits.parsed_bytes = 32 * 1024 * 1024;
    }
    var result = V.verify(std.testing.allocator, configured, anchors);
    const success = if (result) |*receipt| blk: {
        receipt.deinit();
        break :blk true;
    } else |_| false;
    const mapped = profiles.expected(case.id);
    const expected = mapped orelse std.mem.eql(u8, case.expected_result, "SUCCESS");
    var indexed_result: V.VerifyError!T.Verification = if (C.Issuers.init(std.testing.allocator, anchors, .{})) |prepared| blk: {
        var index = prepared;
        defer index.deinit();
        break :blk V.indexed(std.testing.allocator, configured, &index);
    } else |err| err;
    const indexed_success = if (indexed_result) |*receipt| blk: {
        receipt.deinit();
        break :blk true;
    } else |_| false;
    if (indexed_success != expected) {
        tally.mismatches += 1;
        std.debug.print("LIMBO INDEXED {s}: expected {s} got {s}\n", .{ case.id, case.expected_result, if (indexed_success) "SUCCESS" else @errorName(if (indexed_result) |_| unreachable else |err| err) });
    } else tally.indexed_passed += 1;
    if (success != expected) {
        tally.mismatches += 1;
        std.debug.print("LIMBO {s}: expected {s} got {s}\n", .{ case.id, case.expected_result, if (success) "SUCCESS" else @errorName(if (result) |_| unreachable else |err| err) });
    } else tally.passed += 1;
}

/// The verification request a case describes, and its trust anchors.
fn requestOf(alloc: std.mem.Allocator, case: Case) !struct { request: T.Request, anchors: []const []const u8 } {
    const anchors = try ders(alloc, case.trusted_certs);
    const others = try ders(alloc, case.untrusted_intermediates);
    const chain = try alloc.alloc([]const u8, others.len + 1);
    chain[0] = try der(alloc, case.peer_certificate);
    @memcpy(chain[1..], others);
    return .{ .anchors = anchors, .request = .{ .chain = chain, .identity = try reference(case), .purpose = if (std.mem.eql(u8, case.validation_kind, "CLIENT")) .client else .server, .time = .fromNanoseconds(@as(i96, try timestamp(case.validation_time)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1), .evidence = .{ .crls = try ders(alloc, case.crls) }, .limits = .{ .depth = if (case.max_chain_depth != null) 16 else 8, .intermediates = case.max_chain_depth orelse 16 } } };
}

test "F13 catalogue_cross_signed_cycles_and_chain_depth (a cycle is never walked twice: its verdict comes within one signature check per certificate presented)" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const parsed = try std.json.parseFromSlice(struct { version: usize, testcases: []Case }, arena.allocator(), @embedFile("fixtures/limbo.json"), .{ .ignore_unknown_fields = true });
    var seen: usize = 0;
    for (parsed.value.testcases) |case| {
        if (!std.mem.eql(u8, case.id, "cve::cve-2024-0567") and !std.mem.startsWith(u8, case.id, "pathological::intermediate-cycle")) continue;
        seen += 1;
        const r = try requestOf(arena.allocator(), case);
        var request = r.request;
        request.limits.signatures = request.chain.len;
        const expected = std.mem.eql(u8, case.expected_result, "SUCCESS");
        if (V.verify(std.testing.allocator, request, r.anchors)) |receipt| {
            var owned = receipt;
            owned.deinit();
            try std.testing.expect(expected);
        } else |err| {
            if (err == error.VerificationLimit) std.debug.print("LIMBO {s}: the cycle ran past {d} signature checks\n", .{ case.id, request.chain.len });
            try std.testing.expect(!expected and err != error.VerificationLimit);
        }
    }
    try std.testing.expectEqual(@as(usize, 4), seen);
}
