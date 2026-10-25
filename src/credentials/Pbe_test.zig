const std = @import("std");
const Pbe = @import("Pbe.zig");
const Sha1 = @import("../crypto/sha1.zig").Sha1;

test "credential PBE PKCS#12 KDF matches RFC 7292 appendix B's known answers" {
    const gpa = std.testing.allocator;
    var password = try Pbe.Password.init(gpa, "sesame", false, .{});
    defer password.deinit();
    // golang.org/x/crypto/pkcs12's vectors: a 24-byte key over two hash outputs, and an I_j
    // whose sum leaves a leading zero byte.
    var key: [24]u8 = undefined;
    try Pbe.pkcs12Kdf(Sha1, gpa, 1, try password.bmpForm(), "\xff\xff\xff\xff\xff\xff\xff\xff", 2048, &key);
    try std.testing.expectEqualSlices(u8, "\x7c\xd9\xfd\x3e\x2b\x3b\xe7\x69\x1a\x44\xe3\xbe\xf0\xf9\xea\x0f\xb9\xb8\x97\xd4\xe3\x25\xd9\xd1", &key);
    try Pbe.pkcs12Kdf(Sha1, gpa, 1, "\x00\x00", "\xf3\x7e\x05\xb5\x18\x32\x4b\x4b", 2048, &key);
    try std.testing.expectEqualSlices(u8, "\x00\xf7\x59\xff\x47\xd1\x4d\xd0\x36\x65\xd5\x94\x3c\xb3\xc4\xa3\x9a\x25\x55\xc0\x2a\xed\x66\xe1", &key);
}

test "credential PBE passwords become NUL-terminated UTF-16BE with surrogate pairs" {
    const gpa = std.testing.allocator;
    const cases = [_]struct { utf8: []const u8, absent: bool = false, bmp: ?[]const u8 }{
        .{ .utf8 = "", .bmp = "\x00\x00" },
        .{ .utf8 = "", .absent = true, .bmp = "" },
        .{ .utf8 = "Beavis", .bmp = "\x00B\x00e\x00a\x00v\x00i\x00s\x00\x00" },
        .{ .utf8 = "ä😀", .bmp = "\x00\xe4\xd8\x3d\xde\x00\x00\x00" },
        .{ .utf8 = "\xff", .bmp = null },
    };
    for (cases) |c| {
        var password = try Pbe.Password.init(gpa, c.utf8, c.absent, .{});
        defer password.deinit();
        if (c.bmp) |bmp| try std.testing.expectEqualSlices(u8, bmp, try password.bmpForm()) else try std.testing.expectError(error.InvalidPassword, password.bmpForm());
    }
    try std.testing.expectError(error.KdfLimit, Pbe.Password.init(gpa, "xxxxx", false, .{ .password_bytes = 4 }));
}
