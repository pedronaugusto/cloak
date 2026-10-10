//! TLS 1.2, both roles, a cloak client against a cloak server.
const std = @import("std");
const Duo = @import("../testing/Duo.zig");
const Suite = @import("crypto/Suite.zig").Suite;

const ecdsa_suites = [_]Suite{ .ecdhe_ecdsa_aes_128_gcm_sha256, .ecdhe_ecdsa_aes_256_gcm_sha384, .ecdhe_ecdsa_chacha20_poly1305_sha256 };

fn connect(options: Duo.Options) !*Duo {
    const duo = try Duo.init(std.testing.allocator, options);
    errdefer duo.deinit();
    try duo.handshake();
    return duo;
}

test "C4 TLS 1.2 completes for every ECDSA suite, group and certificate key, both ways" {
    for (ecdsa_suites) |suite| {
        for ([_]Duo.Cert{ .p256, .p384, .ed25519 }) |cert| {
            for ([_]@import("crypto/Group.zig").Group{ .x25519, .p256, .p384 }) |group| {
                // A TLS 1.2-only client against the default server.
                const duo = try connect(.{ .cert = cert, .client_suites = &.{suite}, .client_max = .tls12, .client_groups = &.{group} });
                defer duo.deinit();
                const info = duo.client.info().?;
                try std.testing.expectEqual(.tls12, info.version);
                try std.testing.expectEqual(suite, info.suite);
                try std.testing.expectEqual(group, info.group);
                try std.testing.expect(info.peer_authenticated);
                try std.testing.expectEqual(info.suite, duo.server.info().?.suite);
                var out: [64]u8 = undefined;
                try std.testing.expectEqualSlices(u8, "ping", try duo.echo(&duo.client, &duo.server, "ping", &out));
                try std.testing.expectEqualSlices(u8, "pong", try duo.echo(&duo.server, &duo.client, "pong", &out));
                var a: [32]u8 = undefined;
                var b: [32]u8 = undefined;
                try duo.client.exportKeyingMaterial(&a, "EXPORTER-test", "ctx");
                try duo.server.exportKeyingMaterial(&b, "EXPORTER-test", "ctx");
                try std.testing.expectEqualSlices(u8, &a, &b);
            }
        }
    }
}
