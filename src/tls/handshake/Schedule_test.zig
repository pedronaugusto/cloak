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
    var schedule = try K.init(&shared, &hello, &hs);
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
    try schedule.complete();
    try std.testing.expect(std.mem.allEqual(u8, schedule.root.expose(), 0));
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
        var schedule = try K.init(&@as([64]u8, @splat(1)), &@as([H.digest_length]u8, @splat(2)), &traffic);
        defer schedule.deinit();
        var out: [H.digest_length]u8 = @splat(0xa5);
        try std.testing.expectError(error.WrongPhase, schedule.complete());
        try std.testing.expectError(error.WrongPhase, schedule.exportBytes(&out, "purpose", "context"));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
        try schedule.application(&@as([H.digest_length]u8, @splat(3)), &traffic);
        try schedule.complete();
        try std.testing.expectError(error.InvalidLabel, schedule.exportBytes(&out, "", "context"));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
    }
}
