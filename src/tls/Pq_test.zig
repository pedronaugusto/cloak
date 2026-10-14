//! The NIST-curve ML-KEM hybrids (SecP256r1MLKEM768, SecP384r1MLKEM1024) end to end: cloak's
//! client against the scripted server (its own exchange code, from std's primitives), and cloak
//! against cloak; the hybrid-only policy accepts them.
const std = @import("std");
const Group = @import("crypto/Group.zig").Group;
const Suite13 = @import("crypto/Suite.zig").Suite13;
const Pair = @import("../testing/Pair.zig").Pair;
const Duo = @import("../testing/Duo.zig");
const gpa = std.testing.allocator;

fn againstPeer(comptime suite: Suite13, group: Group, require_hybrid: bool) !void {
    const P = Pair(suite);
    // The client sends no share for these groups by default: the server asks for one.
    const pair = try P.init(gpa, .{ .group = group, .retry = group }, .{ .groups = &.{ .x25519_mlkem768, .x25519, .secp256r1_mlkem768, .secp384r1_mlkem1024, .p256 }, .require_hybrid = require_hybrid });
    defer pair.deinit();
    try pair.handshake();
    const info = pair.conn.info().?;
    try std.testing.expectEqual(group, info.group);
    try std.testing.expect(info.peer_authenticated and pair.peer.client_finished_ok);
    var ours: [24]u8 = undefined;
    var theirs: [24]u8 = undefined;
    try pair.conn.exportKeyingMaterial(&ours, "EXPERIMENTAL cloak", "pq");
    try pair.peer.exportKey(&theirs, "EXPERIMENTAL cloak", "pq");
    try std.testing.expectEqualSlices(u8, &theirs, &ours);
}

test "C10 the NIST hybrids against an independent server, over a retry request, hybrid-only too" {
    inline for (.{ Suite13.aes_128_gcm_sha256, Suite13.aes_256_gcm_sha384 }) |suite| {
        for ([_]Group{ .secp256r1_mlkem768, .secp384r1_mlkem1024 }) |group| {
            try againstPeer(suite, group, false);
            try againstPeer(suite, group, true);
        }
    }
}

test "C10 cloak to cloak: a client sharing a NIST hybrid first, and a server preferring one" {
    for ([_]Group{ .secp256r1_mlkem768, .secp384r1_mlkem1024 }) |group| {
        // The client offers only this hybrid: its share goes in the first hello.
        {
            const duo = try Duo.init(gpa, .{ .client_groups = &.{group}, .server_groups = &.{ group, .x25519 } });
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expectEqual(group, duo.client.info().?.group);
            try std.testing.expectEqual(group, duo.server.info().?.group);
        }
        // The server wants it, the client offered it without a share: one retry request.
        {
            const duo = try Duo.init(gpa, .{ .server_groups = &.{group}, .client_groups = &.{ .x25519_mlkem768, .x25519, group } });
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expectEqual(group, duo.client.info().?.group);
        }
    }
}

test "F91 catalogue_pq_group_specific_layout_and_auth_policy (no hybrid in TLS 1.2)" {
    // A TLS 1.2 client with only a hybrid group has nothing to agree on.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_max = .tls12, .client_groups = &.{.secp256r1_mlkem768}, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }));
    // A TLS 1.2 server never picks a hybrid: the client's P-256 is chosen.
    const duo = try Duo.init(gpa, .{ .client_max = .tls12, .client_groups = &.{ .secp384r1_mlkem1024, .p256 }, .server_groups = &.{ .secp384r1_mlkem1024, .p256 } });
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expectEqual(.p256, duo.client.info().?.group);
}
