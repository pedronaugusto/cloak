const std = @import("std");
const Kdf = @import("Kdf.zig");
const Sha1 = @import("../crypto/sha1.zig").Sha1;
test "credential KDF RFC6070 multiblock embedded NUL and bound vectors" {
    @setRuntimeSafety(true);
    var out: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &out);
    try Kdf.derive(Sha1, out[0..20], "password", "salt", 1);
    var expected: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected[0..20], "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    try std.testing.expectEqualSlices(u8, expected[0..20], out[0..20]);
    try Kdf.derive(Sha1, out[0..25], "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096);
    _ = try std.fmt.hexToBytes(&expected, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    try std.testing.expectEqualSlices(u8, &expected, out[0..25]);
    try Kdf.derive(Sha1, out[0..16], "pass\x00word", "sa\x00lt", 4096);
    _ = try std.fmt.hexToBytes(expected[0..16], "56fa6aa75548099dcc37d7f03425e0c3");
    try std.testing.expectEqualSlices(u8, expected[0..16], out[0..16]);
    try std.testing.expectError(error.KdfLimit, Kdf.derive(Sha1, &out, "p", "s", 0));
}

test "credential KDF keyed HMAC matches std's over long and short keys" {
    @setRuntimeSafety(true);
    inline for (.{ std.crypto.hash.Sha1, std.crypto.hash.sha2.Sha256, std.crypto.hash.sha2.Sha512 }) |Hash| {
        const Std = std.crypto.auth.hmac.Hmac(Hash);
        for ([_][]const u8{ "", "key", &@as([200]u8, @splat('k')) }) |key| {
            var keyed: Kdf.Keyed(Hash) = undefined;
            keyed.init(key);
            var ours: [Hash.digest_length]u8 = undefined;
            keyed.mac(&ours, "the message ", "in two parts");
            var theirs: [Std.mac_length]u8 = undefined;
            Std.create(&theirs, "the message in two parts", key);
            try std.testing.expectEqualSlices(u8, &theirs, &ours);
        }
    }
}

test "credential KDF PBKDF2-HMAC-SHA512 to 64 bytes matches std's" {
    @setRuntimeSafety(true);
    var ours: [64]u8 = undefined;
    try Kdf.derive(std.crypto.hash.sha2.Sha512, &ours, "passphrase", "NaCl salt", 1000);
    var theirs: [64]u8 = undefined;
    try std.crypto.pwhash.pbkdf2(&theirs, "passphrase", "NaCl salt", 1000, std.crypto.auth.hmac.sha2.HmacSha512);
    try std.testing.expectEqualSlices(u8, &theirs, &ours);
    var too_long: [65]u8 = undefined;
    try std.testing.expectError(error.KdfLimit, Kdf.derive(std.crypto.hash.sha2.Sha512, &too_long, "p", "s", 1));
}
