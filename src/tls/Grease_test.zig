//! GREASE (RFC 8701) end to end: a client whose hello carries reserved values completes against
//! cloak's server in each shape a hello takes, a second hello after a retry request and an ECH
//! pair included; the codec's half is in handshake/Hello_test.zig.
const std = @import("std");
const types = @import("../certificates.zig").types;
const Duo = @import("../testing/Duo.zig");
const Ech = @import("handshake/Ech.zig");
const Hpke = @import("crypto/Hpke.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const gpa = std.testing.allocator;

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C2 GREASE: a client offering reserved values completes in TLS 1.3, TLS 1.2, over a retry request and with ECH" {
    // TLS 1.3, and TLS 1.2 chosen by the server: the reserved suite, group, version and scheme are
    // never picked.
    for ([_]@import("crypto/Suite.zig").Version{ .tls13, .tls12 }) |version| {
        const duo = try connect(.{ .client_grease = true, .server_max = version });
        defer duo.deinit();
        try std.testing.expectEqual(version, duo.client.info().?.version);
    }
    // A retry request: the second hello keeps the values, drops the reserved share, and the
    // server's check that it matches the first holds.
    {
        const duo = try connect(.{ .client_grease = true, .server_groups = &.{.p384} });
        defer duo.deinit();
        try std.testing.expectEqual(.p384, duo.client.info().?.group);
    }
    // ECH GREASE and real ECH: the inner and outer hellos carry the same values, so the server
    // rebuilds the inner hello the client hashed.
    {
        const duo = try connect(.{ .client_grease = true, .client_ech = .grease });
        defer duo.deinit();
        try std.testing.expect(!duo.client.info().?.ech_accepted);
    }
    {
        var pair = Hpke.deriveKeyPair(&(@as([32]u8, @splat(5))));
        defer pair.deinit();
        var config_buf: [128]u8 = undefined;
        const config = try Ech.writeConfig(&config_buf, .{ .id = 3, .public_key = pair.public, .public_name = "public.example.org", .max_name_length = 24 });
        var list_buf: [140]u8 = undefined;
        const list = try Ech.writeList(&list_buf, &.{config});
        const duo = try connect(.{ .client_grease = true, .client_ech = .{ .config_list = list }, .server_ech = &.{.{ .config = config, .secret = pair.secret.expose() }} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.ech_accepted);
    }
}

test "C2 GREASE: a resumption offer keeps pre_shared_key last" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x11)), types.instant(Duo.pki.time));
    const first = try connect(.{ .client_grease = true, .cache = &cache, .tickets = &keys });
    first.deinit();
    const duo = try connect(.{ .seed = 2, .client_grease = true, .cache = &cache, .tickets = &keys });
    defer duo.deinit();
    try std.testing.expect(duo.client.info().?.resumed);
}
