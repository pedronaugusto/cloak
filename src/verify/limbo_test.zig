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
test "x509-limbo portable complete corpus profile mapping" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const gpa = arena.allocator();
    const parsed = try std.json.parseFromSlice(struct { version: usize, testcases: []Case }, gpa, @embedFile("fixtures/limbo.json"), .{ .ignore_unknown_fields = true });
    var mismatches: usize = 0;
    var passed: usize = 0;
    var indexed_passed: usize = 0;
    for (parsed.value.testcases) |case| {
        var item = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer item.deinit();
        const alloc = item.allocator();
        const anchors = try ders(alloc, case.trusted_certs);
        const others = try ders(alloc, case.untrusted_intermediates);
        const chain = try alloc.alloc([]const u8, others.len + 1);
        chain[0] = try der(alloc, case.peer_certificate);
        @memcpy(chain[1..], others);
        const request: T.Request = .{ .chain = chain, .identity = try reference(case), .purpose = if (std.mem.eql(u8, case.validation_kind, "CLIENT")) .client else .server, .time = try timestamp(case.validation_time), .trust_generation = 1, .policy_generation = 1, .evidence = .{ .crls = try ders(alloc, case.crls) }, .limits = .{ .depth = if (case.max_chain_depth != null) 16 else 8, .intermediates = case.max_chain_depth orelse 16 } };
        var configured = request;
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
            mismatches += 1;
            std.debug.print("LIMBO INDEXED {s}: expected {s} got {s}\n", .{ case.id, case.expected_result, if (indexed_success) "SUCCESS" else @errorName(if (indexed_result) |_| unreachable else |err| err) });
        } else indexed_passed += 1;
        if (success != expected) {
            mismatches += 1;
            std.debug.print("LIMBO {s}: expected {s} got {s}\n", .{ case.id, case.expected_result, if (success) "SUCCESS" else @errorName(if (result) |_| unreachable else |err| err) });
        } else passed += 1;
    }
    std.debug.print("LIMBO matched {d} flat and {d} indexed, mismatches {d}\n", .{ passed, indexed_passed, mismatches });
    try std.testing.expectEqual(@as(usize, 0), mismatches);
}
