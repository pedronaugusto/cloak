//! Execute record and handshake kernels without hosted Io or an allocator.
const std = @import("std");
const record = @import("../tls/record.zig");
const handshake = @import("../tls/handshake.zig");
pub fn vectors() u32 {
    @setRuntimeSafety(true);
    inline for (std.enums.values(record.Suite13)) |suite| {
        var tx = record.Epoch.Epoch(suite).init(@splat(1), @splat(2), .{}) catch return 1;
        defer tx.deinit();
        var rx = record.Epoch.Epoch(suite).init(@splat(1), @splat(2), .{}) catch return 2;
        defer rx.deinit();
        var wire: [64]u8 = undefined;
        var out: [64]u8 = undefined;
        const plain = rx.open(tx.seal(.application, "portable", 7, &wire) catch return 3, &out) catch return 4;
        if (!std.mem.eql(u8, plain.bytes, "portable")) return 5;
    }
    const Hash = std.crypto.hash.sha2.Sha256;
    var transcript: handshake.Transcript.Transcript(Hash) = .{};
    transcript.commit(@embedFile("../tls/handshake/testdata/client-hello.bin")) catch return 6;
    transcript.commit(@embedFile("../tls/handshake/testdata/server-hello.bin")) catch return 7;
    const shared = [_]u8{ 0x8b, 0xd4, 0x05, 0x4f, 0xb5, 0x5b, 0x9d, 0x63, 0xfd, 0xfb, 0xac, 0xf9, 0xf0, 0x4b, 0x9f, 0x0d, 0x35, 0xe6, 0xd6, 0x3f, 0x53, 0x75, 0x63, 0xef, 0xd4, 0x62, 0x72, 0x90, 0x0f, 0x89, 0x49, 0x2d };
    const K = handshake.Schedule.Schedule(.aes_128_gcm_sha256);
    var traffic: K.Traffic = .{};
    defer traffic.deinit();
    var schedule = K.init(&shared, &transcript.digest(), &traffic) catch return 8;
    defer schedule.deinit();
    const expected = [_]u8{ 0xb6, 0x7b, 0x7d, 0x69, 0x0c, 0xc1, 0x6c, 0x4e, 0x75, 0xe5, 0x42, 0x13, 0xcb, 0x2d, 0x37, 0xb4, 0xe9, 0xc9, 0x12, 0xbc, 0xde, 0xd9, 0x10, 0x5d, 0x42, 0xbe, 0xfd, 0x59, 0xd3, 0x91, 0xad, 0x38 };
    if (!std.mem.eql(u8, traffic.server.expose(), &expected)) return 9;
    return 0;
}
