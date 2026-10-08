const std = @import("std");
const Kdf = @import("Kdf.zig");
test "credential KDF RFC6070 multiblock embedded NUL and bound vectors" {
    @setRuntimeSafety(true);
    var out: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &out);
    try Kdf.derive(std.crypto.hash.Sha1, out[0..20], "password", "salt", 1);
    var expected: [25]u8 = undefined;
    _ = try std.fmt.hexToBytes(expected[0..20], "0c60c80f961f0e71f3a9b524af6012062fe037a6");
    try std.testing.expectEqualSlices(u8, expected[0..20], out[0..20]);
    try Kdf.derive(std.crypto.hash.Sha1, out[0..25], "passwordPASSWORDpassword", "saltSALTsaltSALTsaltSALTsaltSALTsalt", 4096);
    _ = try std.fmt.hexToBytes(&expected, "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038");
    try std.testing.expectEqualSlices(u8, &expected, out[0..25]);
    try Kdf.derive(std.crypto.hash.Sha1, out[0..16], "pass\x00word", "sa\x00lt", 4096);
    _ = try std.fmt.hexToBytes(expected[0..16], "56fa6aa75548099dcc37d7f03425e0c3");
    try std.testing.expectEqualSlices(u8, expected[0..16], out[0..16]);
    try std.testing.expectError(error.KdfLimit, Kdf.derive(std.crypto.hash.Sha1, &out, "p", "s", 0));
}
