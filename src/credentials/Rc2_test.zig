const std = @import("std");
const Rc2 = @import("Rc2.zig");

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "credential RC2 decrypts RFC 2268 section 5's vectors" {
    const Vector = struct { key: []const u8, bits: u10, plain: [8]u8, cipher: [8]u8 };
    const vectors = [_]Vector{
        .{ .key = &hex("0000000000000000"), .bits = 63, .plain = hex("0000000000000000"), .cipher = hex("ebb773f993278eff") },
        .{ .key = &hex("ffffffffffffffff"), .bits = 64, .plain = hex("ffffffffffffffff"), .cipher = hex("278b27e42e2f0d49") },
        .{ .key = &hex("3000000000000000"), .bits = 64, .plain = hex("1000000000000001"), .cipher = hex("30649edf9be7d2c2") },
        .{ .key = &hex("88"), .bits = 64, .plain = hex("0000000000000000"), .cipher = hex("61a8a244adacccf0") },
        .{ .key = &hex("88bca90e90875a"), .bits = 64, .plain = hex("0000000000000000"), .cipher = hex("6ccf4308974c267f") },
        .{ .key = &hex("88bca90e90875a7f0f79c384627bafb2"), .bits = 64, .plain = hex("0000000000000000"), .cipher = hex("1a807d272bbe5db1") },
        .{ .key = &hex("88bca90e90875a7f0f79c384627bafb2"), .bits = 128, .plain = hex("0000000000000000"), .cipher = hex("2269552ab0f85ca6") },
        .{ .key = &hex("88bca90e90875a7f0f79c384627bafb216f80a6f85920584c42fceb0be255daf1e"), .bits = 129, .plain = hex("0000000000000000"), .cipher = hex("5b78d3a43dfff1f1") },
    };
    for (vectors) |v| try std.testing.expectEqualSlices(u8, &v.plain, &Rc2.blockForTest(v.key, v.bits, v.cipher));
}

test "credential RC2-40-CBC decrypts OpenSSL's output and refuses bad padding" {
    // openssl enc -rc2-40-cbc -K 0102030405 -iv 0001020304050607 -provider legacy -provider default
    // over "cloak rc2 test\n" (15 bytes, one padding byte).
    const cipher = hex(rc2_40_cbc_cipher);
    var out: [cipher.len]u8 = undefined;
    const plain = try Rc2.decrypt(&hex("0102030405"), 40, hex("0001020304050607"), &cipher, &out);
    try std.testing.expectEqualStrings("cloak rc2 test\n", plain);
    var tampered = cipher;
    tampered[tampered.len - 1] ^= 1;
    try std.testing.expectError(error.BadPassword, Rc2.decrypt(&hex("0102030405"), 40, hex("0001020304050607"), &tampered, &out));
    try std.testing.expectError(error.InvalidCiphertext, Rc2.decrypt(&hex("0102030405"), 40, hex("0001020304050607"), cipher[0..7], out[0..7]));
}

const rc2_40_cbc_cipher = "ba42a16327ca32fe440006fe7e2e4a42";
