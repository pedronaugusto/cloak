//! TLS 1.2 plain PSK (RFC 4279 with RFC 6655's CCM suites), CoAP's and LwM2M's PSK mode: cloak
//! against cloak over a stream and over datagrams, and the guards around it.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Pair = @import("../testing/DatagramPair.zig");
const Psk = @import("handshake/Psk.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const types = @import("../certificates.zig").types;
const gpa = std.testing.allocator;

const key16: [16]u8 = .{ 0x10, 0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98, 0xa9, 0xba, 0xcb, 0xdc, 0xed, 0xfe, 0x0f };
const key64: [64]u8 = @splat(0x5a);
const psk_suites: []const Suite = &.{ .psk_aes_128_ccm_8, .psk_aes_128_ccm };

/// A server's table of keys by exact identity, counting its lookups and keeping the last query.
const Table = struct {
    entries: []const Psk.External,
    queries: usize = 0,
    last: ?Psk.Query = null,

    fn find(context: ?*anyopaque, query: Psk.Query) ?Psk.External {
        const self: *Table = @ptrCast(@alignCast(context.?));
        self.queries += 1;
        self.last = query;
        for (self.entries) |entry| if (std.mem.eql(u8, entry.identity, query.identity)) return entry;
        return null;
    }

    fn lookup(self: *Table) Psk.Lookup {
        return .{ .context = self, .find = find };
    }
};

fn key12(identity: []const u8, secret: []const u8) Psk.External {
    return .{ .identity = identity, .secret = secret, .version = .tls12 };
}

/// A TLS 1.2 PSK client listing `suites` against a server with keys alone (or `credentials`).
fn options(suites: []const Suite, psk: *const Psk.External, table: *Table) Duo.Options {
    return .{ .client_suites = suites, .client_max = .tls12, .client_verify_none = true, .client_psks = psk[0..1], .server_suites = Suite.default ++ psk_suites, .server_psk = table.lookup(), .server_psk_only = true };
}

fn exportsMatch(duo: *Duo) !void {
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try duo.client.exportKeyingMaterial(&a, "cloak psk12", null);
    try duo.server.exportKeyingMaterial(&b, "cloak psk12", null);
    try std.testing.expectEqualSlices(u8, &a, &b);
}

test "C10 TLS 1.2 PSK: CCM_8 and CCM authenticate both ends by the key alone, with no group" {
    for ([_]Suite{ .psk_aes_128_ccm_8, .psk_aes_128_ccm }) |suite| for ([_][]const u8{ &key16, &key64 }) |secret| {
        const psk = key12("coap-device", secret);
        var table: Table = .{ .entries = &.{psk} };
        const duo = try Duo.init(gpa, options(&.{suite}, &psk, &table));
        defer duo.deinit();
        try duo.handshake();
        for ([_]@TypeOf(duo.client.info().?){ duo.client.info().?, duo.server.info().? }) |info| {
            try std.testing.expectEqual(.tls12, info.version);
            try std.testing.expectEqual(suite, info.suite);
            try std.testing.expect((info.external_psk != null) and info.peer_authenticated and !info.resumed);
            // Plain PSK has no key exchange.
            try std.testing.expectEqual(null, info.group);
        }
        // The server looked the identity up once, for TLS 1.2.
        try std.testing.expectEqual(1, table.queries);
        try std.testing.expectEqual(.tls12, table.last.?.version);
        try std.testing.expect(!duo.client.certificateRequested());
        try exportsMatch(duo);
        var out: [8]u8 = undefined;
        try std.testing.expectEqualSlices(u8, "coap", try duo.echo(&duo.client, &duo.server, "coap", &out));
        try std.testing.expectEqualSlices(u8, "ack", try duo.echo(&duo.server, &duo.client, "ack", &out));
    };
}

test "C10 TLS 1.2 PSK: the server's order decides between a key and a certificate" {
    const psk = key12("dual", &key16);
    var table: Table = .{ .entries = &.{psk} };
    // The client offers both kinds; a server with a credential and keys picks by its own list.
    const both: []const Suite = &.{ .ecdhe_ecdsa_aes_128_ccm_8, .psk_aes_128_ccm_8 };
    {
        const duo = try Duo.init(gpa, .{ .client_suites = both, .client_max = .tls12, .client_psks = &.{psk}, .server_suites = &.{ .psk_aes_128_ccm_8, .ecdhe_ecdsa_aes_128_ccm_8 }, .server_psk = table.lookup() });
        defer duo.deinit();
        try duo.handshake();
        try std.testing.expect(duo.client.info().?.external_psk != null);
        // The key authenticated the server: its credential, weighed for the suite, went nowhere.
        try std.testing.expectEqual(@as(?u8, null), duo.server.info().?.credential);
    }
    {
        const duo = try Duo.init(gpa, .{ .client_suites = both, .client_max = .tls12, .client_psks = &.{psk}, .server_suites = &.{ .ecdhe_ecdsa_aes_128_ccm_8, .psk_aes_128_ccm_8 }, .server_psk = table.lookup() });
        defer duo.deinit();
        try duo.handshake();
        const info = duo.client.info().?;
        try std.testing.expect((info.external_psk == null) and info.peer_authenticated and info.group != null);
        try std.testing.expectEqual(@as(?u8, 0), duo.server.info().?.credential);
    }
    // A client of PSK suites alone meets a server with certificates alone: nothing shared.
    {
        const duo = try Duo.init(gpa, .{ .client_suites = psk_suites, .client_max = .tls12, .client_verify_none = true, .client_psks = &.{psk} });
        defer duo.deinit();
        try std.testing.expectError(error.NoSharedSuite, duo.handshake());
    }
    // A client allowing TLS 1.3 too negotiates it with a server that has it: the TLS 1.2 key is
    // never offered there (RFC 8446 appendix E.7).
    {
        const duo = try Duo.init(gpa, .{ .client_suites = Suite.default ++ psk_suites, .client_psks = &.{psk}, .server_suites = Suite.default ++ psk_suites, .server_psk = table.lookup() });
        defer duo.deinit();
        try duo.handshake();
        const info = duo.client.info().?;
        try std.testing.expect(info.version == .tls13 and (info.external_psk == null));
    }
}

test "F95 catalogue_psk12_identity_probe_and_offline_guess: a wrong key and an unknown identity fail alike, at the client's Finished" {
    const other: [16]u8 = @splat(0x33);
    // A wrong key, a name nobody holds, a key of the other version, and a lookup that answers
    // for another identity: each the same refusal, the client's Finished record failing to open
    // (bad_record_mac), so a prober cannot tell which identities exist.
    const Lying = struct {
        fn find(_: ?*anyopaque, _: Psk.Query) ?Psk.External {
            return key12("someone-else", &key16);
        }
    };
    const cases = [_]struct { offered: Psk.External, held: []const Psk.External, lying: bool = false }{
        .{ .offered = key12("dev", &key16), .held = &.{key12("dev", &other)} },
        .{ .offered = key12("stranger", &key16), .held = &.{key12("dev", &key16)} },
        .{ .offered = key12("dev", &(key16 ++ key16)), .held = &.{.{ .identity = "dev", .secret = &(key16 ++ key16) }} },
        .{ .offered = key12("dev", &key16), .held = &.{}, .lying = true },
    };
    for (cases) |case| {
        var table: Table = .{ .entries = case.held };
        var opts = options(psk_suites, &case.offered, &table);
        if (case.lying) opts.server_psk = .{ .find = Lying.find };
        const duo = try Duo.init(gpa, opts);
        defer duo.deinit();
        try std.testing.expectError(error.BadRecord, duo.handshake());
        try std.testing.expectEqual(.bad_record_mac, duo.server.diagnostics().alert_sent.?);
    }
}

test "F95 catalogue_psk12_identity_probe_and_offline_guess: a key's version, length (no password-like key) and suites are checked before anything is sent" {
    var table: Table = .{ .entries = &.{} };
    // TLS 1.2 keys are 16 to 64 bytes, SHA-256's.
    for ([_]Psk.External{
        key12("x", key16[0..15]),
        key12("x", &(key64 ++ [1]u8{1})),
        .{ .identity = "x", .secret = &key16, .version = .tls12, .hash = .sha384 },
        key12("x", &@as([16]u8, @splat(0))),
    }) |bad| try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, options(psk_suites, &bad, &table)));
    const psk = key12("x", &key16);
    // A TLS 1.2 key needs its suites listed and TLS 1.2 allowed; PSK suites need a TLS 1.2 key.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_suites = Suite.default, .client_psks = &.{psk} }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_suites = Suite.default ++ psk_suites, .client_min = .tls13, .client_psks = &.{psk} }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_suites = Suite.default ++ psk_suites }));
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_suites = Suite.default ++ psk_suites, .client_psks = &.{.{ .identity = "x", .secret = &(key16 ++ key16) }} }));
    // A server listing them needs keys to look up.
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .server_suites = Suite.default ++ psk_suites }));
    // A TLS 1.3 lookup answered with a TLS 1.2 key passes it over: a full handshake.
    var held: Table = .{ .entries = &.{.{ .identity = "dev", .secret = &(key16 ++ key16), .version = .tls12 }} };
    const duo = try Duo.init(gpa, .{ .client_psks = &.{.{ .identity = "dev", .secret = &(key16 ++ key16) }}, .server_psk = held.lookup() });
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expect((duo.server.info().?.external_psk == null) and held.queries == 1 and held.last.?.version == .tls13);
}

test "C10 TLS 1.2 PSK: a session on a key keeps no ticket at either end" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x55)), types.instant(Duo.pki.time));
    const psk = key12("dev", &key16);
    var table: Table = .{ .entries = &.{psk} };
    var opts = options(psk_suites, &psk, &table);
    opts.cache = &cache;
    opts.client_tls12_tickets = true;
    opts.tickets = &keys;
    opts.server_tls12_tickets = true;
    const duo = try Duo.init(gpa, opts);
    defer duo.deinit();
    try duo.handshake();
    try std.testing.expect(duo.client.info().?.external_psk != null);
    try std.testing.expectEqual(0, cache.count());
}

test "C10 DTLS 1.2 PSK: CoAP's PSK profile, over a cookie exchange, with loss" {
    const psk = key12("coap-node", &key16);
    var table: Table = .{ .entries = &.{psk} };
    for ([_]Suite{ .psk_aes_128_ccm_8, .psk_aes_128_ccm }) |suite| for ([_]u16{ 0, 200 }) |loss| {
        const pair = try Pair.init(gpa, .{ .client_suites = &.{suite}, .client_max = .tls12, .server_suites = &.{ .aes_128_gcm_sha256, .ecdhe_ecdsa_aes_128_ccm_8, suite }, .client_psks = &.{psk}, .server_psk = table.lookup(), .psk_only = true, .loss = loss, .seed = 5 + loss });
        defer pair.deinit();
        try pair.run();
        for ([_]@TypeOf(pair.client.dtls.info().?){ pair.client.dtls.info().?, pair.server.dtls.info().? }) |info| {
            try std.testing.expectEqual(.tls12, info.version);
            try std.testing.expectEqual(suite, info.suite);
            try std.testing.expect((info.external_psk != null) and info.peer_authenticated);
        }
        try std.testing.expectEqual(.datagram, table.last.?.transport);
        try pair.exchange(&pair.client, "GET /temp");
        try std.testing.expectEqualSlices(u8, "GET /temp", pair.server.received.items[pair.server.received.items.len - 1]);
    };
}

test "C10 DTLS 1.3 PSK-DHE through the datagram carrier, with a server holding keys alone" {
    const psk: Psk.External = .{ .identity = "node-13", .secret = &(key16 ++ key16) };
    var table: Table = .{ .entries = &.{psk} };
    const pair = try Pair.init(gpa, .{ .client_suites = &.{.aes_128_ccm_sha256}, .server_suites = &.{.aes_128_ccm_sha256}, .client_psks = &.{psk}, .server_psk = table.lookup(), .psk_only = true });
    defer pair.deinit();
    try pair.run();
    const info = pair.server.dtls.info().?;
    try std.testing.expect(info.version == .tls13 and (info.external_psk != null) and info.peer_authenticated);
}
