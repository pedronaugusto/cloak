//! Independent C1 credential review regression. The verifier ship owns only this test.
const std = @import("std");
const Entropy = @import("../credentials/Entropy.zig");
const Primality = @import("../credentials/Primality.zig");
const shakedown = @import("shakedown");
const Montgomery = @import("../credentials/Montgomery.zig");
const Rsa = @import("../credentials/Rsa.zig");
const Kdf = @import("../credentials/Kdf.zig");
const EdKey = @import("../credentials/EdKey.zig");
test "credential review composite factors cannot become prepared RSA material" {
    const rejected = if (Rsa.parse(@embedFile("fixtures/rsa-composite.der"), .{})) |value| blk: {
        var material = value;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&material));
        break :blk false;
    } else |err| err == error.InvalidKey;
    // A failed rejection prints only a boolean, never prepared private material.
    try std.testing.expect(rejected);
}

test "credential review full primality rejects a strong pseudoprime and accepts a prime" {
    const entropy = Entropy.fromIo(&std.testing.io);
    var composite: [8]u8 = undefined;
    std.mem.writeInt(u64, &composite, 341550071728321, .big);
    try std.testing.expectError(error.InvalidKey, Primality.check(&composite, entropy));
    try Primality.check("\x01\x01", entropy);
}

test "credential review Montgomery full-width differential arithmetic and carries" {
    try shakedown.check(std.testing.allocator, {}, montgomery, .{ .cases = 128, .seed = 0xc1a017 });
}
fn montgomery(_: void, case: *shakedown.Case) !void {
    const widths = [_]usize{ 1, 3, 4, 5, 7, 8, 16, 31, 32, 63, 64, 127, 128, 255, 256, 511, 512 };
    const width = widths[shakedown.gen.intRange(case.source, usize, 0, widths.len - 1)];
    var encoded: [512]u8 = @splat(255);
    for (encoded[0..width]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    encoded[0] |= 128;
    encoded[width - 1] |= 3;
    const F = std.crypto.ff.Modulus(4096);
    const U = std.crypto.ff.Uint(4096);
    const reference = try F.fromBytes(encoded[0..width], .big);
    var m = try Montgomery.init(encoded[0..width]);
    defer m.deinit();
    var ax: [512]u8 = @splat(0);
    var bx: [512]u8 = @splat(0);
    for (ax[0..width], bx[0..width]) |*a, *b| {
        a.* = shakedown.gen.int(case.source, u8);
        b.* = shakedown.gen.int(case.source, u8);
    }
    const a = reference.reduce(try U.fromBytes(ax[0..width], .big));
    const b = reference.reduce(try U.fromBytes(bx[0..width], .big));
    try a.toBytes(&ax, .big);
    try b.toBytes(&bx, .big);
    var x = Montgomery.decode(&ax);
    var y = Montgomery.decode(&bx);
    m.convert(&x, &x);
    m.convert(&y, &y);
    var result: Montgomery.Number = undefined;
    m.multiply(&result, &x, &y);
    var one: Montgomery.Number = @splat(0);
    one[0] = 1;
    m.multiply(&result, &result, &one);
    var expected: [512]u8 = undefined;
    try reference.mul(a, b).toBytes(&expected, .big);
    var got: [512]u8 = undefined;
    for (result, 0..) |word, i| std.mem.writeInt(u32, got[508 - i * 4 ..][0..4], word, .big);
    try std.testing.expectEqualSlices(u8, &expected, &got);
}

test "credential review owned Ed expansion matches RFC8032 public key" {
    var seed: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &seed);
    _ = try std.fmt.hexToBytes(&seed, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    var pair = try EdKey.create(&seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&pair));
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    try std.testing.expect(std.mem.eql(u8, &expected, &pair.public_key.toBytes()));
}

test "credential review owned PBKDF2 long password all hashes and partial blocks" {
    // Synthetic public inputs only: the std oracle does not promise scratch erasure.
    const password: [200]u8 = @splat(0x61);
    inline for (.{ std.crypto.hash.Sha1, std.crypto.hash.sha2.Sha256, std.crypto.hash.sha2.Sha384, std.crypto.hash.sha2.Sha512 }, .{ std.crypto.auth.hmac.HmacSha1, std.crypto.auth.hmac.sha2.HmacSha256, std.crypto.auth.hmac.sha2.HmacSha384, std.crypto.auth.hmac.sha2.HmacSha512 }) |Hash, Hmac| {
        for ([_]usize{ 1, 19, 20, 21, 31, 32 }) |length| {
            var owned: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &owned);
            var reference: [32]u8 = undefined;
            defer std.crypto.secureZero(u8, &reference);
            try Kdf.derive(Hash, owned[0..length], &password, "salt\x00bound", 17);
            try std.crypto.pwhash.pbkdf2(reference[0..length], &password, "salt\x00bound", 17, Hmac);
            try std.testing.expect(std.mem.eql(u8, owned[0..length], reference[0..length]));
        }
    }
}
