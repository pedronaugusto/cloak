//! permute_extensions end to end: a client whose hello's extensions come in a random order
//! completes against cloak's server in each shape a hello takes, a second hello after a retry
//! request, an ECH pair and resumption included; the codec's half is in handshake/Hello_test.zig.
const std = @import("std");
const certificates = @import("../certificates.zig");
const types = certificates.types;
const Duo = @import("../testing/Duo.zig");
const DatagramPair = @import("../testing/DatagramPair.zig");
const Ech = @import("handshake/Ech.zig");
const Hpke = @import("crypto/Hpke.zig");
const SessionCache = @import("resumption/SessionCache.zig");
const TicketKeys = @import("resumption/TicketKeys.zig");
const suites = @import("crypto/Suite.zig");
const gpa = std.testing.allocator;

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(gpa, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C2 permute_extensions: a permuted hello completes in TLS 1.3, TLS 1.2 and over a retry request, with GREASE or without" {
    for (0..8) |seed| for ([_]bool{ false, true }) |grease| {
        for ([_]suites.Version{ .tls13, .tls12 }) |version| {
            const duo = try connect(.{ .seed = seed, .client_permute = true, .client_grease = grease, .server_max = version });
            defer duo.deinit();
            try std.testing.expectEqual(version, duo.client.info().?.version);
        }
        // The second hello keeps the first's order, so the server's check that it matches holds.
        const duo = try connect(.{ .seed = seed, .client_permute = true, .client_grease = grease, .server_groups = &.{.p384} });
        defer duo.deinit();
        try std.testing.expectEqual(.p384, duo.client.info().?.group);
    };
}

test "C6 permute_extensions with ECH: the server rebuilds the permuted inner hello, over a retry request and naming authorities" {
    var pair = Hpke.deriveKeyPair(&(@as([32]u8, @splat(5))));
    defer pair.deinit();
    var config_buf: [128]u8 = undefined;
    const config = try Ech.writeConfig(&config_buf, .{ .id = 3, .public_key = pair.public, .public_name = "public.example.org", .max_name_length = 24 });
    var list_buf: [140]u8 = undefined;
    const list = try Ech.writeList(&list_buf, &.{config});
    const root = (try certificates.certificate.parse(Duo.pki.ca, .{})).subject;
    for (0..8) |seed| for ([_][]const @import("crypto/Group.zig").Group{ &.{ .x25519_mlkem768, .x25519 }, &.{.p384} }) |server_groups| {
        const duo = try connect(.{ .seed = seed, .client_permute = true, .client_grease = true, .server_groups = server_groups, .client_authorities = &.{root}, .client_ech = .{ .config_list = list }, .server_ech = &.{.{ .config = config, .secret = pair.secret.expose() }} });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.ech_accepted and duo.server.info().?.ech_accepted);
    };
    // ECH GREASE: the permuted plain hello with a GREASE encrypted_client_hello.
    const duo = try connect(.{ .client_permute = true, .client_ech = .grease });
    defer duo.deinit();
    try std.testing.expect(!duo.client.info().?.ech_accepted);
}

test "C2 permute_extensions: a resumption offer keeps pre_shared_key last" {
    var cache = try SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x11)), types.instant(Duo.pki.time));
    const first = try connect(.{ .client_permute = true, .cache = &cache, .tickets = &keys });
    first.deinit();
    for (2..6) |seed| {
        const duo = try connect(.{ .seed = seed, .client_permute = true, .client_grease = true, .cache = &cache, .tickets = &keys });
        defer duo.deinit();
        try std.testing.expect(duo.client.info().?.resumed);
    }
}

test "C8 permute_extensions over DTLS: the cookie still leads the hello a stateless server reads, both versions" {
    for (0..8) |seed| for ([_][]const suites.Suite{ suites.Suite.tls13_only, &.{.ecdhe_ecdsa_aes_128_gcm_sha256} }) |list| {
        const pair = try DatagramPair.init(gpa, .{ .seed = seed, .client_permute = true, .client_suites = list, .server_suites = list });
        defer pair.deinit();
        try pair.run();
        try std.testing.expectEqual(@as(usize, 1), pair.cookie_answers);
    };
}

test "C8 permute_extensions with ECH over DTLS 1.3: a stateless check opens the permuted hello, across a retry request too" {
    const EchKeys = @import("../testing/EchKeys.zig");
    var keys: EchKeys = undefined;
    try keys.init(2, 9, "public.example.org");
    defer keys.deinit();
    for (0..8) |seed| for ([_][]const @import("crypto/Group.zig").Group{ &.{ .x25519, .p256 }, &.{.p256} }) |server_groups| {
        const pair = try DatagramPair.init(gpa, .{ .seed = seed, .client_permute = true, .client_suites = suites.Suite.tls13_only, .server_suites = suites.Suite.tls13_only, .groups = &.{ .x25519, .p256 }, .server_groups = server_groups, .client_ech = .{ .config_list = keys.list }, .server_ech = &.{keys.key()} });
        defer pair.deinit();
        try pair.run();
        try std.testing.expect(pair.client.dtls.info().?.ech_accepted and pair.server.dtls.info().?.ech_accepted);
    };
}
