//! FreeBSD's kernel record layer (design C9.1): the `struct tls_enable` a direction's keys
//! become and the write direction's count from bytes, on every OS; on FreeBSD the running
//! kernel's probe and installs, over a loopback TCP connection. A kernel without ktls skips
//! these.
const std = @import("std");
const builtin = @import("builtin");
const Keys = @import("Keys.zig");
const ktls = @import("freebsd.zig");

fn keysOf(version: Keys.Version, cipher: Keys.Cipher, sequence: u64) Keys {
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast(i + 1);
    var iv: [12]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @intCast(0xa0 + i);
    return .{ .version = version, .cipher = cipher, .key = .init(key), .iv = .init(iv), .sequence = sequence };
}

test "C9.1 a tls_enable carries the cipher's key, the IV its version takes and the next record's number" {
    const cases = [_]struct { version: Keys.Version, cipher: Keys.Cipher, algorithm: c_int, key_len: c_int, iv_len: c_int, minor: u8 }{
        .{ .version = .tls13, .cipher = .aes_128_gcm, .algorithm = 25, .key_len = 16, .iv_len = 12, .minor = 4 },
        .{ .version = .tls13, .cipher = .aes_256_gcm, .algorithm = 25, .key_len = 32, .iv_len = 12, .minor = 4 },
        .{ .version = .tls13, .cipher = .chacha20_poly1305, .algorithm = 41, .key_len = 32, .iv_len = 12, .minor = 4 },
        // TLS 1.2 GCM: the salt alone; FreeBSD makes the explicit nonce.
        .{ .version = .tls12, .cipher = .aes_128_gcm, .algorithm = 25, .key_len = 16, .iv_len = 4, .minor = 3 },
        .{ .version = .tls12, .cipher = .aes_256_gcm, .algorithm = 25, .key_len = 32, .iv_len = 4, .minor = 3 },
        .{ .version = .tls12, .cipher = .chacha20_poly1305, .algorithm = 41, .key_len = 32, .iv_len = 12, .minor = 3 },
    };
    for (cases) |case| {
        var keys = keysOf(case.version, case.cipher, 0x0102030405060708);
        defer keys.deinit();
        const enable = ktls.TlsEnable.of(&keys).?;
        try std.testing.expectEqual(case.algorithm, enable.cipher_algorithm);
        try std.testing.expectEqual(case.key_len, enable.cipher_key_len);
        try std.testing.expectEqual(case.iv_len, enable.iv_len);
        try std.testing.expectEqual(@as(c_int, 0), enable.auth_algorithm);
        try std.testing.expectEqual(@as(c_int, 0), enable.auth_key_len);
        try std.testing.expectEqual(@as(c_int, 0), enable.flags);
        try std.testing.expectEqual(@as(u8, 3), enable.tls_vmajor);
        try std.testing.expectEqual(case.minor, enable.tls_vminor);
        try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4, 5, 6, 7, 8 }, &enable.rec_seq);
        try std.testing.expectEqualSlices(u8, keys.keyBytes(), enable.cipher_key[0..@intCast(enable.cipher_key_len)]);
        try std.testing.expectEqualSlices(u8, keys.iv.expose()[0..@intCast(enable.iv_len)], enable.iv[0..@intCast(enable.iv_len)]);
    }
    // FreeBSD has no CCM.
    var ccm = keysOf(.tls13, .aes_128_ccm, 0);
    defer ccm.deinit();
    try std.testing.expect(ktls.TlsEnable.of(&ccm) == null);
}

test "C9.1 the write direction's count from bytes: ceil(2n / 1025) full-size records" {
    try std.testing.expectEqual(@as(u64, 0), Keys.equivalentRecords(0));
    // A one-byte record costs 2 of σ + q, under one full record's 1025.
    try std.testing.expectEqual(@as(u64, 1), Keys.equivalentRecords(1));
    try std.testing.expectEqual(@as(u64, 1), Keys.equivalentRecords(512));
    try std.testing.expectEqual(@as(u64, 2), Keys.equivalentRecords(513));
    // A full-size record's bytes count as 32 records: the bound is sound for any framing.
    try std.testing.expectEqual(@as(u64, 32), Keys.equivalentRecords(1 << 14));
    // About 6.4 GB reach three quarters of 2^24.
    try std.testing.expectEqual(@as(u64, 3 << 22), Keys.equivalentRecords((3 << 22) * 1025 / 2));
    try std.testing.expectEqual(@as(u64, (2 * @as(u128, std.math.maxInt(u64)) + 1024) / 1025), Keys.equivalentRecords(std.math.maxInt(u64)));
}

test "C9.1 the kernel probe: what this FreeBSD kernel's record layer takes, keys once a direction" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    const caps = ktls.probe();
    var any = false;
    for ([_]Keys.Version{ .tls12, .tls13 }) |version| for (std.enums.values(Keys.Cipher)) |cipher| for ([_]Keys.Direction{ .read, .write }) |direction| {
        const takes = caps.supports(version, cipher, direction);
        any = any or takes;
        std.debug.print("ktls {s} {s} {s}: {}\n", .{ @tagName(version), @tagName(cipher), @tagName(direction), takes });
        // No CCM in FreeBSD's kernel.
        if (cipher == .aes_128_ccm) try std.testing.expect(!takes);
    };
    if (!any) return error.SkipZigTest;
    // Keys go in once: no TLS 1.3 key update.
    try std.testing.expect(!caps.rekeys(.read));
    try std.testing.expect(!caps.rekeys(.write));
}

test "C9.1 a record size limit keeps FreeBSD's write direction in software" {
    if (comptime builtin.os.tag != .freebsd) return error.SkipZigTest;
    var keys = keysOf(.tls13, .aes_128_gcm, 0);
    defer keys.deinit();
    keys.max_payload = 1024;
    // Refused before any socket call: the descriptor is never used.
    const socket: ktls.Socket = .{ .fd = -1 };
    try std.testing.expectError(error.Unsupported, socket.install(.write, &keys));
}
