//! The post-quantum groups beyond the default offer end to end: the NIST-curve ML-KEM hybrids
//! (SecP256r1MLKEM768, SecP384r1MLKEM1024) and pure ML-KEM (MLKEM768, MLKEM1024). cloak's client
//! against the scripted server (its own exchange code, from std's primitives), cloak against
//! cloak, over DTLS, and the policies: hybrid-only, TLS 1.2, the default offer.
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

// Pure ML-KEM (MLKEM768, MLKEM1024; draft-ietf-tls-mlkem): opt-in groups for a policy that wants
// no elliptic curve in its key exchange (CNSA 2.0), never offered unless listed.

test "C10 pure ML-KEM against an independent server: shared first, and over a retry request" {
    inline for (.{ Suite13.aes_128_gcm_sha256, Suite13.aes_256_gcm_sha384 }) |suite| {
        for ([_]Group{ .mlkem768, .mlkem1024 }) |group| {
            const P = Pair(suite);
            // Listed alone, the group's share goes in the first hello.
            {
                const pair = try P.init(gpa, .{ .group = group }, .{ .groups = &.{group} });
                defer pair.deinit();
                try pair.handshake();
                try std.testing.expect(pair.peer.seen.sharedGroup(group) and !pair.peer.sent_retry);
                try std.testing.expectEqual(group, pair.conn.info().?.group);
                var ours: [24]u8 = undefined;
                var theirs: [24]u8 = undefined;
                try pair.conn.exportKeyingMaterial(&ours, "EXPERIMENTAL cloak", "mlkem");
                try pair.peer.exportKey(&theirs, "EXPERIMENTAL cloak", "mlkem");
                try std.testing.expectEqualSlices(u8, &theirs, &ours);
            }
            // Listed after the default groups, it is asked for.
            {
                const pair = try P.init(gpa, .{ .group = group, .retry = group }, .{ .groups = &.{ .x25519_mlkem768, .x25519, group } });
                defer pair.deinit();
                try pair.handshake();
                try std.testing.expect(pair.peer.sent_retry);
                try std.testing.expectEqual(group, pair.conn.info().?.group);
            }
        }
    }
}

test "C10 pure ML-KEM cloak to cloak: a client listing only it, and a server preferring it" {
    for ([_]Group{ .mlkem768, .mlkem1024 }) |group| {
        {
            const duo = try Duo.init(gpa, .{ .client_groups = &.{group}, .server_groups = &.{ .x25519_mlkem768, group } });
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expectEqual(group, duo.client.info().?.group);
            try std.testing.expectEqual(group, duo.server.info().?.group);
        }
        {
            const duo = try Duo.init(gpa, .{ .server_groups = &.{group}, .client_groups = &.{ .x25519_mlkem768, .x25519, group } });
            defer duo.deinit();
            try duo.handshake();
            try std.testing.expectEqual(group, duo.client.info().?.group);
        }
    }
}

test "C10 every post-quantum group over DTLS 1.3, listed alone or after X25519, asked for with the cookie" {
    const DatagramPair = @import("../testing/DatagramPair.zig");
    const tls13 = @import("crypto/Suite.zig").Suite.tls13_only;
    // A list without a classical group once put its large shares in the first hello, which a
    // stateless cookie server cannot check, and the handshake timed out; the first hello now
    // carries no share and the cookie's retry request asks for the group.
    for ([_]Group{ .x25519_mlkem768, .mlkem768, .mlkem1024, .secp256r1_mlkem768, .secp384r1_mlkem1024 }) |group| {
        {
            const pair = try DatagramPair.init(gpa, .{ .client_suites = tls13, .server_suites = tls13, .groups = &.{group} });
            defer pair.deinit();
            try pair.run();
            try std.testing.expectEqual(group, pair.client.dtls.info().?.group);
            try std.testing.expectEqual(group, pair.server.dtls.info().?.group);
        }
        {
            const pair = try DatagramPair.init(gpa, .{ .client_suites = tls13, .server_suites = tls13, .groups = &.{ .x25519, group }, .server_groups = &.{group} });
            defer pair.deinit();
            try pair.run();
            try std.testing.expectEqual(group, pair.client.dtls.info().?.group);
        }
        {
            // A server on a validated path, without cookies, asks for the group by its own retry request.
            const pair = try DatagramPair.init(gpa, .{ .client_suites = tls13, .server_suites = tls13, .groups = &.{group}, .admission = .validated });
            defer pair.deinit();
            try pair.run();
            try std.testing.expectEqual(group, pair.client.dtls.info().?.group);
        }
    }
}

test "F91 catalogue_pq_group_specific_layout_and_auth_policy (pure ML-KEM: opt-in, not a hybrid, TLS 1.3 only)" {
    const Hello = @import("handshake/Hello.zig");
    // Never a default: the one default offer holds no pure ML-KEM group, and every carrier's
    // options take it.
    for (Group.default) |group| try std.testing.expect(group.classical() or group.hybrid());
    inline for (.{
        @import("Connection.zig").ClientOptions, @import("Connection.zig").ServerOptions,
        @import("Session.zig").Options,          @import("Session.zig").ServerOptions,
        @import("quic.zig").Handshake.Options,   @import("quic.zig").Handshake.ServerOptions,
        @import("dtls/Datagram.zig").Options,    @import("dtls/Datagram.zig").ServerOptions,
        Hello.Options,                           @import("handshake/Server.zig").Options,
    }) |T| try std.testing.expectEqual(Group.default, defaultGroups(T));
    // `require_hybrid` means a hybrid: a list of only pure groups cannot meet it.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_groups = &.{.mlkem1024}, .client_require_hybrid = true }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_groups = &.{.mlkem1024}, .server_require_hybrid = true }));
    // A hybrid-only server whose preferred group is pure refuses to select it.
    {
        const duo = try Duo.init(gpa, .{ .client_groups = &.{.mlkem1024}, .server_groups = &.{ .mlkem1024, .x25519_mlkem768 }, .server_require_hybrid = true });
        defer duo.deinit();
        try std.testing.expectError(error.HybridRequired, duo.handshake());
    }
    // A hybrid-only client refuses a server that asks for a pure group it also listed.
    {
        const P = Pair(.aes_128_gcm_sha256);
        const pair = try P.init(gpa, .{ .group = .mlkem1024, .retry = .mlkem1024 }, .{ .groups = &.{ .x25519_mlkem768, .mlkem1024 }, .require_hybrid = true });
        defer pair.deinit();
        try std.testing.expectError(error.HybridRequired, pair.handshake());
    }
    // TLS 1.2 has no ML-KEM: an offer with no classical group does not offer TLS 1.2 at all, and a
    // TLS 1.2-only one is refused.
    try std.testing.expect(!(Hello.Options{ .groups = &.{ .mlkem768, .x25519_mlkem768 } }).allows12());
    try std.testing.expect((Hello.Options{ .groups = &.{ .mlkem768, .p256 } }).allows12());
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_max = .tls12, .client_groups = &.{.mlkem768}, .client_suites = &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }));
    {
        const duo = try Duo.init(gpa, .{ .client_max = .tls12, .client_groups = &.{ .mlkem1024, .p256 }, .server_groups = &.{ .mlkem1024, .p256 } });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expectEqual(.p256, duo.client.info().?.group);
    }
    // A server listing only pure groups does not speak TLS 1.2: a TLS 1.2 client meets no version.
    {
        const duo = try Duo.init(gpa, .{ .client_max = .tls12, .client_groups = &.{.p256}, .server_groups = &.{.mlkem1024} });
        defer duo.deinit();
        try std.testing.expectError(error.UnsupportedVersion, duo.handshake());
    }
}

fn defaultGroups(comptime T: type) []const Group {
    const info = @typeInfo(T).@"struct";
    inline for (info.field_names, info.field_types, info.field_attrs) |name, Field, attrs| {
        if (comptime std.mem.eql(u8, name, "groups")) return attrs.defaultValue(Field).?;
    }
    unreachable;
}

test "F131 catalogue_key_shares_in_group_order (the hello's key shares follow supported_groups' order)" {
    // RFC 8446 section 4.2.8: each KeyShareEntry MUST appear in the same order as its group in
    // supported_groups. cloak's two initial shares go in the order the groups are listed.
    const ClientHello = @import("handshake/ClientHello.zig");
    for ([_][]const Group{ &.{ .x25519, .x25519_mlkem768 }, &.{ .x25519_mlkem768, .x25519 }, &.{ .p256, .x25519, .x25519_mlkem768 } }) |groups| {
        const duo = try Duo.init(gpa, .{ .client_groups = groups });
        defer duo.deinit();
        try duo.serveClient();
        const hello = try ClientHello.parse(duo.client.output()[5..], .stream);
        var shares = hello.shares;
        var last: usize = 0;
        var count: usize = 0;
        while (shares.len != 0) : (count += 1) {
            const id = std.mem.readInt(u16, shares[0..2], .big);
            const len = std.mem.readInt(u16, shares[2..4], .big);
            shares = shares[4 + len ..];
            var at: usize = 0;
            while (at < hello.groups.len and std.mem.readInt(u16, hello.groups[at..][0..2], .big) != id) at += 2;
            try std.testing.expect(at < hello.groups.len);
            if (count != 0) try std.testing.expect(at > last);
            last = at;
        }
        try std.testing.expectEqual(@as(usize, 2), count);
    }
}
