const std = @import("std");
const S = @import("Schedule.zig");
const suites = @import("../crypto/Suite.zig");
fn hex(comptime value: []const u8) [value.len / 2]u8 {
    var bytes: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, value) catch unreachable;
    return bytes;
}
test "C2 RFC8448 master application and exporter root schedule" {
    const K = S.Schedule(.aes_128_gcm_sha256);
    var hs: K.Traffic = .{};
    defer hs.deinit();
    const shared = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    const hello = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    var schedule = try K.init(null, &shared, &hello, &hs);
    defer schedule.deinit();
    try std.testing.expectEqualSlices(u8, &hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), hs.client.expose());
    try std.testing.expectEqualSlices(u8, &hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), hs.server.expose());
    const finished = hex("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13");
    var app: K.Traffic = .{};
    defer app.deinit();
    var out: [32]u8 = @splat(0xa5);
    try std.testing.expectError(error.WrongPhase, schedule.exportBytes(&out, "test", ""));
    try schedule.application(&finished, &app);
    try std.testing.expectEqualSlices(u8, &hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919"), schedule.root.expose());
    try std.testing.expectEqualSlices(u8, &hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5"), app.client.expose());
    try std.testing.expectEqualSlices(u8, &hex("a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643"), app.server.expose());
    try std.testing.expectEqualSlices(u8, &hex("fe22f881176eda18eb8f44529e6792c50c9a3f89452f68d8ae311b4309d3cf50"), schedule.exporter.expose());
    try std.testing.expectError(error.WrongPhase, schedule.application(&finished, &app));
    try std.testing.expectError(error.WrongPhase, schedule.exportBytes(&out, "test", ""));
    var ticket: [32]u8 = undefined;
    try std.testing.expectError(error.WrongPhase, schedule.ticketSecret("\x00\x00", &ticket));
    // RFC 8448 section 3: the transcript through the client Finished, then "res master".
    try schedule.complete(&hex("209145a96ee8e2a122ff810047cc952684658d6049e86429426db87c54ad143d"));
    try std.testing.expect(std.mem.allEqual(u8, schedule.root.expose(), 0));
    try std.testing.expectEqualSlices(u8, &hex("7df235f2031d2a051287d02b0241b0bfdaf86cc856231f2d5aba46c434ec196c"), schedule.resumption.expose());
    try schedule.ticketSecret("\x00\x00", &ticket);
    try std.testing.expectEqualSlices(u8, &hex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3"), &ticket);
    try schedule.exportBytes(&out, "purpose", "one");
    var other: [32]u8 = undefined;
    try schedule.exportBytes(&other, "purpose", "two");
    try std.testing.expect(!std.mem.eql(u8, &out, &other));
}
test "C2 schedule invalid phases never expose prior output" {
    inline for (std.enums.values(suites.Suite13)) |suite| {
        const K = S.Schedule(suite);
        const H = suites.Hash(suite);
        var traffic: K.Traffic = .{};
        defer traffic.deinit();
        var schedule = try K.init(null, &@as([64]u8, @splat(1)), &@as([H.digest_length]u8, @splat(2)), &traffic);
        defer schedule.deinit();
        var out: [H.digest_length]u8 = @splat(0xa5);
        try std.testing.expectError(error.WrongPhase, schedule.complete(&@as([H.digest_length]u8, @splat(4))));
        try std.testing.expectError(error.WrongPhase, schedule.exportBytes(&out, "purpose", "context"));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
        try schedule.application(&@as([H.digest_length]u8, @splat(3)), &traffic);
        try schedule.complete(&@as([H.digest_length]u8, @splat(4)));
        try std.testing.expectError(error.InvalidLabel, schedule.exportBytes(&out, "", "context"));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
    }
}

test "C5 RFC8448 resumed handshake: binder, PSK-DHE handshake secrets and resumption master" {
    const K = S.Schedule(.aes_128_gcm_sha256);
    const psk = hex("4ecd0eb6ec3b4d87f5d6028f922ca4c5851a277fd41311c9e62d2c9492e1c4f3");
    // Section 4: the binder over the hash of the ClientHello up to its binders.
    const truncated = hex("63224b2e4573f2d3454ca84b9d009a04f6be9e05711a8396473aefa01e924a14");
    var binder: [32]u8 = undefined;
    K.binder(&psk, &truncated, &binder);
    const expected = hex("3add4fb2d8fdf822a0ca3cf7678ef5e88dae990141c5924d57bb6fa31b9e5f9d");
    try std.testing.expectEqualSlices(u8, &expected, &binder);
    try K.checkBinder(&psk, &truncated, &expected);
    var flipped = expected;
    flipped[31] ^= 1;
    try std.testing.expectError(error.BadBinder, K.checkBinder(&psk, &truncated, &flipped));
    try std.testing.expectError(error.BadBinder, K.checkBinder(&psk, &truncated, expected[0..31]));
    // The handshake secrets: early secret from the PSK, then the X25519 secret.
    const shared = hex("f44194756ff9ec9d25180635d66ea6824c6ab3bf179977be37f723570e7ccb2e");
    const hello = hex("f736cb34fe25e701551bee6fd24c1cc7102a7daf9405cb15d97aafe16f757d03");
    var hs: K.Traffic = .{};
    defer hs.deinit();
    var schedule = try K.init(&psk, &shared, &hello, &hs);
    errdefer schedule.deinit();
    try std.testing.expectEqualSlices(u8, &hex("2faac08f851d35fea3604fcb4de82dc62c9b164a70974d0462e27f1ab278700f"), hs.client.expose());
    try std.testing.expectEqualSlices(u8, &hex("fe927ae271312e8bf0275b581c54eef020450dc4ecffaa05a1a35d27518e7803"), hs.server.expose());
    var app: K.Traffic = .{};
    defer app.deinit();
    try schedule.application(&hex("b0aeffc46a2cfe33114e6fd7d51f9f04b1ca3c497dab08934a774a9d9ad7dbf3"), &app);
    try std.testing.expectEqualSlices(u8, &hex("2abbf2b8e381d23dbebe1dd2a7d16a8bf484cb4950d23fb7fb7fa8547062d9a1"), app.client.expose());
    try std.testing.expectEqualSlices(u8, &hex("cc21f1bf8feb7dd5fa505bd9c4b468a9984d554a993dc49e6d285598fb672691"), app.server.expose());
    try std.testing.expectEqualSlices(u8, &hex("3fd93d4ffddc98e64b14dd107aedf8ee4add23f4510f58a4592d0b201bee56b4"), schedule.exporter.expose());
    try schedule.complete(&hex("c3c122e0bd907a4a3ff6112d8fd53dbf89c773d9552e8b6b9d56d361b3a97bf6"));
    try std.testing.expectEqualSlices(u8, &hex("5e95bdf1f89005ea2e9aa0ba85e728e3c19c5fe0c699e3f5bee59faebd0b5406"), schedule.resumption.expose());
    schedule.deinit();
    try std.testing.expect(std.mem.allEqual(u8, schedule.resumption.expose(), 0));
}
