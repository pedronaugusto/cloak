//! Imported provisioned keys (RFC 9258) and clients offering several keys, cloak client against
//! cloak server: an imported key serves both hashes under derived keys, is never taken as a plain
//! key nor a plain key as imported, binds its context and target protocol; a retry keeps the
//! offers of the chosen hash alone; `Info.external_psk` names the key that authenticated.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const DatagramPair = @import("../testing/DatagramPair.zig");
const Psk = @import("handshake/Psk.zig");
const gpa = std.testing.allocator;

const key: [32]u8 = @splat(0x5a);
const other: [32]u8 = @splat(0x6b);

/// A server's keys, matched by exact identity; counts the queries and the imported ones.
const Table = struct {
    entries: []const Psk.External,
    queries: usize = 0,
    imported_queries: usize = 0,

    fn find(context: ?*anyopaque, query: Psk.Query) ?Psk.External {
        const self: *Table = @ptrCast(@alignCast(context.?));
        self.queries += 1;
        if (query.imported != null) self.imported_queries += 1;
        for (self.entries) |entry| if (std.mem.eql(u8, entry.identity, query.identity)) return entry;
        return null;
    }

    fn lookup(self: *Table) Psk.Lookup {
        return .{ .context = self, .find = find };
    }
};

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C10 an imported key authenticates both ends under either hash, whatever the hash it is imported with" {
    for ([_]Psk.Hash{ .sha256, .sha384 }) |import_hash| {
        for ([_][]const @import("crypto/Suite.zig").Suite{ &.{.aes_128_gcm_sha256}, &.{.aes_256_gcm_sha384} }) |server_suites| {
            const psk: Psk.External = .{ .identity = "device-7", .secret = &key, .hash = import_hash, .imported = .{ .context = "app" } };
            var table: Table = .{ .entries = &.{psk} };
            const duo = try connect(.{ .client_psks = &.{psk}, .server_suites = server_suites, .server_psk = table.lookup() });
            defer duo.deinit();
            const client = duo.client.info().?;
            const server = duo.server.info().?;
            try std.testing.expectEqualStrings("device-7", client.external_psk.?);
            try std.testing.expectEqualStrings("device-7", server.external_psk.?);
            try std.testing.expect(client.peer_authenticated and server.peer_authenticated);
            // The client offered an ImportedIdentity for each hash; the server read one as imported.
            try std.testing.expect(table.imported_queries >= 1);
        }
    }
}

test "C10 an imported key is never taken as a plain one, a plain key never as imported, and the context binds" {
    const imported: Psk.External = .{ .identity = "device-7", .secret = &key, .imported = .{ .context = "app" } };
    const plain: Psk.External = .{ .identity = "device-7", .secret = &key };
    const elsewhere: Psk.External = .{ .identity = "device-7", .secret = &key, .imported = .{ .context = "other app" } };
    const Case = struct { client: Psk.External, server: Psk.External };
    for ([_]Case{
        .{ .client = imported, .server = plain },
        .{ .client = plain, .server = imported },
        .{ .client = imported, .server = elsewhere },
    }) |case| {
        var table: Table = .{ .entries = &.{case.server} };
        const duo = try connect(.{ .client_psks = &.{case.client}, .server_psk = table.lookup() });
        defer duo.deinit();
        // The certificate authenticates instead.
        try std.testing.expectEqual(null, duo.client.info().?.external_psk);
        try std.testing.expectEqual(null, duo.server.info().?.external_psk);
        try std.testing.expect(duo.client.info().?.peer_authenticated);
    }
}

test "C10 a client offers its keys in order and the server takes the first it knows" {
    const first: Psk.External = .{ .identity = "old", .secret = &key };
    const second: Psk.External = .{ .identity = "new", .secret = &other, .imported = .{} };
    var table: Table = .{ .entries = &.{second} };
    const duo = try connect(.{ .client_psks = &.{ first, second }, .server_psk = table.lookup() });
    defer duo.deinit();
    try std.testing.expectEqualStrings("new", duo.client.info().?.external_psk.?);
    try std.testing.expectEqualStrings("new", duo.server.info().?.external_psk.?);
}

test "C10 after a retry the client offers the chosen hash's identities alone" {
    // The server's one group is none the client shares a key for, and its one suite is
    // SHA-384's: the second hello keeps the imported key's SHA-384 offer and drops the plain
    // SHA-256 key, so the server's index counts the second hello's list.
    const plain: Psk.External = .{ .identity = "plain", .secret = &key };
    const imported: Psk.External = .{ .identity = "imported", .secret = &other, .imported = .{} };
    var table: Table = .{ .entries = &.{ plain, imported } };
    const duo = try connect(.{ .client_psks = &.{ plain, imported }, .server_groups = &.{.p384}, .server_suites = &.{.aes_256_gcm_sha384}, .server_psk = table.lookup() });
    defer duo.deinit();
    try std.testing.expectEqualStrings("imported", duo.client.info().?.external_psk.?);
    try std.testing.expectEqualStrings("imported", duo.server.info().?.external_psk.?);
    // The server looked at one identity, as a plain one and then as imported: the SHA-384 offer.
    try std.testing.expectEqual(2, table.queries);
    try std.testing.expectEqual(1, table.imported_queries);
}

test "C10 an imported key over DTLS 1.3 is derived for DTLS 1.3" {
    const psk: Psk.External = .{ .identity = "sensor", .secret = &key, .imported = .{} };
    var table: Table = .{ .entries = &.{psk} };
    const pair = try DatagramPair.init(gpa, .{ .client_psks = &.{psk}, .server_psk = table.lookup(), .client_min = .tls13 });
    defer pair.deinit();
    try pair.run();
    try std.testing.expectEqualStrings("sensor", pair.client.dtls.info().?.external_psk.?);
    try std.testing.expectEqualStrings("sensor", pair.server.dtls.info().?.external_psk.?);
    // The identity names DTLS 1.3 as its target protocol (RFC 9258 section 5.1).
    var wire: [64]u8 = undefined;
    const identity = Psk.importedIdentity(psk, .datagram, .sha256).write(&wire);
    try std.testing.expectEqual(0xfefc, Psk.ImportedIdentity.parse(identity).?.protocol);
}

test "C10 an ImportedIdentity reads back exactly, and other bytes read as a plain identity" {
    var wire: [64]u8 = undefined;
    const written = (Psk.ImportedIdentity{ .identity = "id", .context = "ctx", .protocol = 0x0304, .kdf = 2 }).write(&wire);
    try std.testing.expectEqualSlices(u8, "\x00\x02id\x00\x03ctx\x03\x04\x00\x02", written);
    const read = Psk.ImportedIdentity.parse(written).?;
    try std.testing.expectEqualStrings("id", read.identity);
    try std.testing.expectEqualStrings("ctx", read.context);
    try std.testing.expectEqual(2, read.kdf);
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse(wire[0 .. written.len - 1]));
    var longer: [64]u8 = undefined;
    @memcpy(longer[0..written.len], written);
    longer[written.len] = 0;
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse(longer[0 .. written.len + 1]));
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse("\x00\x00\x00\x00\x03\x04\x00\x01"));
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse("device-7"));
}

test "C10 an offered identity whose lengths are near their maximum reads as a plain identity" {
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse("\xff\xff\x00\x00"));
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse("\xff\xfe\x00\x00"));
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse("\x00\x01i\xff\xff\x00\x00"));
    try std.testing.expectEqual(null, Psk.ImportedIdentity.parse("\x00\x01i\xff\xfa\x00\x00"));
}

test "C10 the client's keys are checked: an imported key is TLS 1.3's and not a password, at most four keys, one TLS 1.2 key" {
    const bad = [_]Psk.External{
        .{ .identity = "x", .secret = &key, .version = .tls12, .imported = .{} },
        .{ .identity = "x", .secret = key[0..15], .imported = .{} },
    };
    for (bad) |psk| try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_psks = &.{psk} }));
    const five: [5]Psk.External = @splat(.{ .identity = "x", .secret = &key });
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_psks = &five }));
    const key12: Psk.External = .{ .identity = "x", .secret = key[0..16], .version = .tls12 };
    try std.testing.expectError(error.InvalidOptions, Duo.init(gpa, .{ .client_psks = &.{ key12, key12 } }));
}

test "C10 an imported key's derivation and binder match values computed apart (RFC 9258 section 5)" {
    // Computed with Python's hmac and hashlib from RFC 9258 section 5 and RFC 8446 section 7.1,
    // not with cloak: an EPSK of 32 bytes 0x5a, identity "device-7", context "app".
    const epsk: [32]u8 = @splat(0x5a);
    const Case = struct { hash: Psk.Hash, target: Psk.Hash, transport: @import("crypto/Suite.zig").Transport, expected: []const u8 };
    for ([_]Case{
        .{ .hash = .sha256, .target = .sha256, .transport = .stream, .expected = "63122f9f44279abf688eb9f0201665a0b2372776fce3427ac742563751e58e65" },
        .{ .hash = .sha256, .target = .sha384, .transport = .stream, .expected = "338fb2bd050939f28bb97c497d06987782f5809c4f30ded5dbf3c8564983f1d9af09c8a9d5ae5c6adbbf9f672b0b3106" },
        .{ .hash = .sha384, .target = .sha256, .transport = .datagram, .expected = "5433c490bc36de1d1f97c820630dc9bdd8ac90e3274682722c8d763ada27b6e3" },
    }) |case| {
        const psk: Psk.External = .{ .identity = "device-7", .secret = &epsk, .hash = case.hash, .imported = .{ .context = "app" } };
        var wire: [64]u8 = undefined;
        const identity = Psk.importedIdentity(psk, case.transport, case.target).write(&wire);
        var out: [48]u8 = undefined;
        Psk.derive(psk, case.transport.prefix(), identity, out[0..case.target.length()]);
        var expected: [48]u8 = undefined;
        try std.testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&expected, case.expected), out[0..case.target.length()]);
    }
    // The binder of an imported key is under "imp binder": a PSK of 32 bytes 0x42 over the
    // SHA-256 of "hello".
    const K = @import("handshake/Schedule.zig").Schedule(.aes_128_gcm_sha256);
    var truncated: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("hello", &truncated, .{});
    var binder: [32]u8 = undefined;
    K.binderOf(.tls13, .imported, &@as([32]u8, @splat(0x42)), &truncated, &binder);
    var expected: [32]u8 = undefined;
    try std.testing.expectEqualSlices(u8, try std.fmt.hexToBytes(&expected, "e674edb90ffa8e2d1d2286059d0dffed7364d1c1bc5e6a71b25acc3b084de986"), &binder);
}
