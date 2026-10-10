const std = @import("std");
const suites = @import("../crypto/Suite.zig");
const Epoch12 = @import("Epoch12.zig").Epoch12;

test "C4 TLS 1.2 records round-trip under every cipher and fail closed on damage" {
    inline for (std.enums.values(suites.Cipher)) |cipher| {
        const E = Epoch12(cipher);
        const key: [E.key_length]u8 = @splat(3);
        const iv: [E.iv_length]u8 = @splat(5);
        var tx = try E.init(&key, &iv, .{});
        defer tx.deinit();
        var rx = try E.init(&key, &iv, .{});
        defer rx.deinit();
        var wire: [2048]u8 = undefined;
        var plain: [2048]u8 = undefined;
        for (0..3) |round| {
            const message = "a TLS 1.2 record";
            const sealed = try tx.seal(.application, message[0 .. round * 5], &wire);
            try std.testing.expectEqual(E.overhead + round * 5, sealed.len);
            try std.testing.expectEqual(@as(u8, 23), sealed[0]);
            const opened = try rx.open(sealed, &plain);
            try std.testing.expectEqualSlices(u8, message[0 .. round * 5], opened.bytes);
        }
        // Handshake records carry their type in the header and the additional data.
        const sealed = try tx.seal(.handshake, "\x14\x00\x00\x0cverify_data!", &wire);
        var damaged_buffer: [2048]u8 = undefined;
        const damaged = damaged_buffer[0..sealed.len];
        @memcpy(damaged, sealed);
        damaged[0] = 23;
        var victim = try E.init(&key, &iv, .{});
        defer victim.deinit();
        // Skip the victim to the same sequence number.
        var scratch: [2048]u8 = undefined;
        var other = try E.init(&key, &iv, .{});
        defer other.deinit();
        for (0..3) |_| _ = try victim.open(try other.seal(.application, "", &scratch), &plain);
        try std.testing.expectError(error.BadRecord, victim.open(damaged, &plain));
        // A failed open closes the epoch.
        try std.testing.expectError(error.Closed, victim.open(sealed, &plain));
        const opened = try rx.open(sealed, &plain);
        try std.testing.expectEqual(.handshake, opened.content);
        // Out of order: the next record under sequence 5 does not open as sequence 4.
        const later = try tx.seal(.application, "x", &wire);
        var reordered = try E.init(&key, &iv, .{});
        defer reordered.deinit();
        try std.testing.expectError(error.BadRecord, reordered.open(later, &plain));
        // Empty handshake records are refused on both sides.
        try std.testing.expectError(error.InvalidLength, tx.seal(.handshake, "", &wire));
    }
}

test "C4 TLS 1.2 GCM nonce is the salt and the explicit sequence; ChaCha XORs the sequence" {
    const Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
    const E = Epoch12(.aes_128_gcm);
    const key: [16]u8 = @splat(1);
    const salt: [4]u8 = .{ 9, 8, 7, 6 };
    var tx = try E.init(&key, &salt, .{});
    defer tx.deinit();
    var wire: [64]u8 = undefined;
    _ = try tx.seal(.application, "a", &wire);
    const sealed = try tx.seal(.application, "hi", &wire);
    // Explicit nonce: sequence 1.
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0, 0, 1 }, sealed[5..13]);
    var expected: [2]u8 = undefined;
    var tag: [16]u8 = undefined;
    const nonce = salt ++ [8]u8{ 0, 0, 0, 0, 0, 0, 0, 1 };
    const ad = [8]u8{ 0, 0, 0, 0, 0, 0, 0, 1 } ++ [5]u8{ 23, 3, 3, 0, 2 };
    Gcm.encrypt(&expected, &tag, "hi", &ad, nonce, key);
    try std.testing.expectEqualSlices(u8, &expected, sealed[13..15]);
    try std.testing.expectEqualSlices(u8, &tag, sealed[15..31]);

    const Chacha = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
    const C = Epoch12(.chacha20_poly1305);
    const ckey: [32]u8 = @splat(2);
    const civ: [12]u8 = @splat(0x55);
    var ctx = try C.init(&ckey, &civ, .{});
    defer ctx.deinit();
    _ = try ctx.seal(.application, "a", &wire);
    const csealed = try ctx.seal(.application, "hi", &wire);
    var cnonce = civ;
    cnonce[11] ^= 1;
    Chacha.encrypt(&expected, &tag, "hi", &ad, cnonce, ckey);
    try std.testing.expectEqualSlices(u8, &expected, csealed[5..7]);
    try std.testing.expectEqualSlices(u8, &tag, csealed[7..23]);
}
