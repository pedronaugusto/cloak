const std = @import("std");
const L = @import("Labels.zig");
const H = std.crypto.hash.sha2.Sha256;
fn hex(comptime value: []const u8) [value.len / 2]u8 {
    var out: [value.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, value) catch unreachable;
    return out;
}
test "C2 RFC8448 handshake secrets keys and IV" {
    const early = hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
    var secret: [32]u8 = undefined;
    L.extract(H, &secret, &@as([32]u8, @splat(0)), &@as([32]u8, @splat(0)));
    try std.testing.expectEqualSlices(u8, &early, &secret);
    const empty = hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    try L.expand(H, &secret, &early, "derived", &empty);
    try std.testing.expectEqualSlices(u8, &hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"), &secret);
    const share = hex("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    var handshake: [32]u8 = undefined;
    L.extract(H, &handshake, &secret, &share);
    try std.testing.expectEqualSlices(u8, &hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"), &handshake);
    const transcript = hex("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
    try L.expand(H, &secret, &handshake, "c hs traffic", &transcript);
    try std.testing.expectEqualSlices(u8, &hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21"), &secret);
    try L.expand(H, &secret, &handshake, "s hs traffic", &transcript);
    try std.testing.expectEqualSlices(u8, &hex("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38"), &secret);
    var key: [16]u8 = undefined;
    var iv: [12]u8 = undefined;
    try L.expand(H, &key, &secret, "key", "");
    try L.expand(H, &iv, &secret, "iv", "");
    try std.testing.expectEqualSlices(u8, &hex("3fce516009c21727d0f2e4e86ee403bc"), &key);
    try std.testing.expectEqualSlices(u8, &hex("5d313eb2671276ee13000b30"), &iv);
}
test "C2 catalogue_finished_entropy_failure_is_never_success" {
    inline for (.{ std.crypto.hash.sha2.Sha256, std.crypto.hash.sha2.Sha384 }) |Hash| {
        const traffic: [Hash.digest_length]u8 = @splat(1);
        const transcript: [Hash.digest_length]u8 = @splat(2);
        var valid: [Hash.digest_length]u8 = undefined;
        L.finished(Hash, &valid, &traffic, &transcript);
        try L.checkFinished(Hash, &traffic, &transcript, &valid);
        for (0..valid.len) |i| {
            valid[i] ^= 1;
            try std.testing.expectError(error.BadFinished, L.checkFinished(Hash, &traffic, &transcript, &valid));
            valid[i] ^= 1;
        }
        try std.testing.expectError(error.BadFinished, L.checkFinished(Hash, &traffic, &transcript, valid[1..]));
        var out: [256]u8 = @splat(0xa5);
        try std.testing.expectError(error.InvalidLabel, L.expand(Hash, &out, &traffic, "", ""));
        try std.testing.expect(std.mem.allEqual(u8, &out, 0xa5));
        try L.expand(Hash, &out, &traffic, "exporter", &transcript);
        var info: [9 + 8 + 1 + Hash.digest_length]u8 = undefined;
        std.mem.writeInt(u16, info[0..2], 256, .big);
        info[2] = 14;
        @memcpy(info[3..17], "tls13 exporter");
        info[17] = Hash.digest_length;
        @memcpy(info[18..], &transcript);
        var oracle: [256]u8 = undefined;
        std.crypto.kdf.hkdf.Hkdf(std.crypto.auth.hmac.Hmac(Hash)).expand(&oracle, &info, traffic);
        try std.testing.expectEqualSlices(u8, &oracle, &out);
    }
}
