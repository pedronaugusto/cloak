const std = @import("std");
const shakedown = @import("shakedown");
const aegis = @import("aegis");
const R = @import("Epoch.zig");
const S = @import("../crypto/Suite.zig");

test "C2 catalogue_record_outer_type_and_wire_aad" {
    inline for (std.enums.values(S.Suite)) |suite| {
        const E = R.Epoch(suite);
        var tx = try E.init(@splat(7), @splat(9), .{});
        defer tx.deinit();
        var wire: [128]u8 = undefined;
        const sealed = try tx.seal(.application, "record payload", 7, &wire);
        for (0..sealed.len) |i| {
            var rx = try E.init(@splat(7), @splat(9), .{});
            defer rx.deinit();
            var changed = wire;
            changed[i] ^= 1;
            var out: [128]u8 = @splat(0xa5);
            try std.testing.expectError(error.BadRecord, rx.open(changed[0..sealed.len], &out));
            try std.testing.expectError(error.Closed, rx.open(sealed, &out));
            if (i >= 5) try std.testing.expect(std.mem.allEqual(u8, out[0 .. sealed.len - 21], 0));
        }
    }
}
test "C2 catalogue_bad_tag_no_plaintext_or_alias_damage" {
    const E = R.Epoch(.aes_128_gcm_sha256);
    var tx = try E.init(@splat(1), @splat(2), .{});
    defer tx.deinit();
    var rx = try E.init(@splat(1), @splat(2), .{});
    defer rx.deinit();
    var wire: [128]u8 = @splat(0x55);
    @memcpy(wire[5..10], "hello");
    const before = wire;
    try std.testing.expectError(error.PartialOverlap, tx.seal(.application, wire[4..9], 0, &wire));
    try std.testing.expectEqualSlices(u8, &before, &wire);
    const sealed = try tx.seal(.application, wire[5..10], 0, &wire);
    const committed = wire;
    try std.testing.expectError(error.PartialOverlap, rx.open(sealed, wire[6..]));
    try std.testing.expectEqualSlices(u8, &committed, &wire);
    const plain = try rx.open(sealed, wire[5..]);
    try std.testing.expectEqualSlices(u8, "hello", plain.bytes);
}
test "C2 catalogue_nonce_uniqueness_partial_retry_and_wrap" {
    inline for (std.enums.values(S.Suite)) |suite| {
        const E = R.Epoch(suite);
        var tx = try E.init(@splat(1), @splat(2), .{ .records = 2, .bytes = 30 });
        defer tx.deinit();
        var wire: [64]u8 = @splat(0xa5);
        try std.testing.expectError(error.BufferTooSmall, tx.seal(.application, "same", 0, wire[0..20]));
        try std.testing.expectEqual(@as(u64, 0), tx.sequence.raw());
        const first = (try tx.seal(.application, "same", 0, &wire)).len;
        const committed = wire;
        _ = try tx.seal(.application, "same", 0, &wire);
        try std.testing.expect(!std.mem.eql(u8, committed[0..first], wire[0..first]));
        try std.testing.expectError(error.RecordLimit, tx.seal(.application, "same", 0, &wire));
        try std.testing.expectError(error.Closed, tx.seal(.application, "same", 0, &wire));
        try std.testing.expectEqualSlices(u8, &@as([S.Aead(suite).key_length]u8, @splat(0)), tx.key.expose());
        var bytes = try E.init(@splat(1), @splat(2), .{ .bytes = 5 });
        defer bytes.deinit();
        _ = try bytes.seal(.application, "same", 0, &wire);
        try std.testing.expectError(error.RecordLimit, bytes.seal(.application, "", 0, &wire));
        try std.testing.expectError(error.InvalidLimits, E.init(@splat(0), @splat(0), .{ .records = (1 << 24) + 1 }));
    }
}
test "C2 record padding empty application and authenticated inner rejection" {
    inline for (std.enums.values(S.Suite)) |suite| {
        const E = R.Epoch(suite);
        var tx = try E.init(@splat(1), @splat(2), .{});
        defer tx.deinit();
        var rx = try E.init(@splat(1), @splat(2), .{});
        defer rx.deinit();
        var wire: [64]u8 = undefined;
        var out: [64]u8 = undefined;
        const plain = try rx.open(try tx.seal(.application, "", 9, &wire), &out);
        try std.testing.expectEqual(.application, plain.content);
        try std.testing.expectEqual(@as(usize, 0), plain.bytes.len);
        const A = S.Aead(suite);
        var invalid: [22]u8 = .{ 23, 3, 3, 0, 17 } ++ @as([17]u8, @splat(0));
        A.encrypt(invalid[5..6], invalid[6..][0..16], &.{24}, invalid[0..5], rx.iv.expose().*, rx.key.expose().*);
        var bad = try E.init(@splat(1), @splat(2), .{});
        defer bad.deinit();
        try std.testing.expectError(error.BadRecord, bad.open(&invalid, &out));
    }
}
test "C2 record property roundtrip all suite boundaries" {
    try shakedown.check(std.testing.allocator, {}, roundtrip, .{ .cases = 1024, .seed = 0xc2ae });
}
fn roundtrip(_: void, case: *shakedown.Case) !void {
    var payload: [R.max_content]u8 = undefined;
    const len = shakedown.gen.intRange(case.source, usize, 0, payload.len);
    for (payload[0..len]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    const padding = shakedown.gen.intRange(case.source, usize, 0, payload.len - len);
    inline for (std.enums.values(S.Suite)) |suite| {
        const E = R.Epoch(suite);
        var tx = try E.init(@splat(1), @splat(2), .{});
        defer tx.deinit();
        var rx = try E.init(@splat(1), @splat(2), .{});
        defer rx.deinit();
        var wire: [R.max_ciphertext + 7]u8 = @splat(0xa5);
        var out: [R.max_inner + 2]u8 = @splat(0xa5);
        const sealed = try tx.seal(.application, payload[0..len], padding, wire[1 .. wire.len - 1]);
        const plain = try rx.open(sealed, out[1 .. out.len - 1]);
        try std.testing.expectEqualSlices(u8, payload[0..len], plain.bytes);
        try std.testing.expect(wire[0] == 0xa5 and wire[wire.len - 1] == 0xa5 and out[0] == 0xa5 and out[out.len - 1] == 0xa5);
    }
}

test "C2 KeyUpdate old-key commitment then directional reset" {
    inline for (std.enums.values(S.Suite)) |suite| {
        const Hash = S.Hash(suite);
        var write_secret = aegis.Secret([Hash.digest_length]u8).init(@splat(7));
        errdefer write_secret.deinit();
        var read_secret = aegis.Secret([Hash.digest_length]u8).init(@splat(7));
        errdefer read_secret.deinit();
        var tx = try R.Epoch(suite).initTraffic(&write_secret, .{ .records = 2 });
        defer tx.deinit();
        var rx = try R.Epoch(suite).initTraffic(&read_secret, .{ .records = 2 });
        defer rx.deinit();
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&write_secret), 0));
        try std.testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&read_secret), 0));
        var wire: [128]u8 = undefined;
        var out: [128]u8 = undefined;
        _ = try rx.open(try tx.seal(.application, "before", 0, &wire), &out);
        const old_key = tx.key.expose().*;
        const update = try tx.seal(.handshake, "\x18\x00\x00\x01\x00", 0, &wire);
        // Receiver must still authenticate this with the old directional key.
        try std.testing.expectEqualSlices(u8, "\x18\x00\x00\x01\x00", (try rx.open(update, &out)).bytes);
        try tx.update();
        try rx.update();
        try std.testing.expectEqual(@as(u64, 0), tx.sequence.raw());
        try std.testing.expectEqual(@as(u64, 0), rx.sequence.raw());
        try std.testing.expect(!std.mem.eql(u8, &old_key, tx.key.expose()));
        try std.testing.expectEqualSlices(u8, "after", (try rx.open(try tx.seal(.application, "after", 0, &wire), &out)).bytes);
    }
}
