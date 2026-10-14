//! Independent C1 credential review regression. The verifier ship owns only this test.
const std = @import("std");
const shakedown = @import("shakedown");
const Montgomery = @import("../credentials/Montgomery.zig");
const Rsa = @import("../credentials/Rsa.zig");
const Sign = @import("../credentials/Sign.zig");
const signature = @import("signature.zig");
const Algorithm = @import("../certificate/Algorithm.zig");
const Kdf = @import("../credentials/Kdf.zig");
const EdKey = @import("../credentials/EdKey.zig");
test "credential review a key with composite factors releases no wrong signature" {
    // Its numbers agree (n = pq, the CRT congruences) but p and q are not prime: the parse
    // checks agreement, and the private operation refuses any signature the public key rejects.
    var material: Rsa.Key = undefined;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&material));
    Rsa.parse(@embedFile("fixtures/rsa-composite.der"), &material) catch |err| {
        // The kernel may refuse the shape outright; that releases nothing either.
        return std.testing.expectEqual(error.UnsupportedKey, err);
    };
    const public: Algorithm.PublicKey = .{ .rsa = .{ .modulus = material.n[0..material.size], .exponent = material.e[0..material.exponent_size] } };
    var released: usize = 0;
    for (0..32) |i| {
        var message: [8]u8 = undefined;
        std.mem.writeInt(u64, &message, i, .big);
        var noise: [Sign.rsa.noise_length]u8 = @splat(@truncate(i));
        var out: [Sign.max_signature]u8 = undefined;
        const made = Sign.rsa.pkcs1(std.crypto.hash.sha2.Sha256, &material.crt, &message, &noise, &out) catch |err| {
            try std.testing.expectEqual(error.SigningFailed, err);
            continue;
        };
        released += 1;
        try signature.verify(public, .{ .rsa = .sha256 }, &message, made);
    }
    // A failed check prints counts only, never prepared private material.
    try std.testing.expect(released <= 32);
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
