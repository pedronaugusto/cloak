//! HPKE against RFC 9180 appendix A.1.1 (every intermediate the RFC prints for DHKEM(X25519,
//! HKDF-SHA256), HKDF-SHA256, AES-128-GCM) and the base-mode vectors of the three AEADs in Go
//! 1.27.1's crypto/hpke testdata (rfc9180.json), whose ciphertexts are checked through 1,000
//! sealed messages accumulated into SHAKE128, as Go's own test does.
const std = @import("std");
const Hpke = @import("Hpke.zig");

fn hex(comptime text: []const u8) [text.len / 2]u8 {
    var out: [text.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable;
    return out;
}

test "C6 HPKE matches RFC 9180 A.1.1: key derivation, encapsulation, key schedule and sealing" {
    const info = hex("4f6465206f6e2061204772656369616e2055726e");
    var e = Hpke.deriveKeyPair(&hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"));
    defer e.deinit();
    try std.testing.expectEqualSlices(u8, &hex("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"), e.secret.expose());
    try std.testing.expectEqualSlices(u8, &hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"), &e.public);
    var r = Hpke.deriveKeyPair(&hex("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"));
    defer r.deinit();
    try std.testing.expectEqualSlices(u8, &hex("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"), r.secret.expose());
    try std.testing.expectEqualSlices(u8, &hex("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"), &r.public);

    const suite: Hpke.Suite = .{ .kdf = .hkdf_sha256, .aead = .aes_128_gcm };
    var enc: [Hpke.enc_length]u8 = undefined;
    var sender = try Hpke.setupSender(suite, &r.public, &info, &hex("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"), &enc);
    defer sender.deinit();
    try std.testing.expectEqualSlices(u8, &hex("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"), &enc);
    try std.testing.expectEqualSlices(u8, &hex("4531685d41d65f03dc48f6b8302c05b0"), sender.key.expose()[0..16]);
    try std.testing.expectEqualSlices(u8, &hex("56d890e5accaaf011cff4b7d"), sender.base_nonce.expose());
    var recipient = try Hpke.setupRecipient(suite, &enc, r.secret.expose(), &info);
    defer recipient.deinit();

    const pt = hex("4265617574792069732074727574682c20747275746820626561757479");
    const cases = [_]struct { seq: u64, aad: []const u8, ct: []const u8 }{
        .{ .seq = 0, .aad = "Count-0", .ct = &hex("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a") },
        .{ .seq = 1, .aad = "Count-1", .ct = &hex("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84") },
        .{ .seq = 2, .aad = "Count-2", .ct = &hex("498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180") },
        .{ .seq = 4, .aad = "Count-4", .ct = &hex("583bd32bc67a5994bb8ceaca813d369bca7b2a42408cddef5e22f880b631215a09fc0012bc69fccaa251c0246d") },
        .{ .seq = 255, .aad = "Count-255", .ct = &hex("7175db9717964058640a3a11fb9007941a5d1757fda1a6935c805c21af32505bf106deefec4a49ac38d71c9e0a") },
        .{ .seq = 256, .aad = "Count-256", .ct = &hex("957f9800542b0b8891badb026d79cc54597cb2d225b54c00c5238c25d05c30e3fbeda97d2e0e1aba483a2df9f2") },
    };
    for (cases) |case| {
        sender.seq = case.seq;
        recipient.seq = case.seq;
        var ct: [pt.len + Hpke.tag_length]u8 = undefined;
        try sender.seal(&ct, case.aad, &pt);
        try std.testing.expectEqualSlices(u8, case.ct, &ct);
        var back: [pt.len]u8 = undefined;
        try recipient.open(&back, case.aad, &ct);
        try std.testing.expectEqualSlices(u8, &pt, &back);
        try std.testing.expectEqual(case.seq + 1, recipient.seq);
    }
}

const Vector = struct { aead: Hpke.Aead, info: []const u8, ikm_e: []const u8, ikm_r: []const u8, sk_r: []const u8, pk_r: []const u8, enc: []const u8, accumulated: []const u8 };
const vectors = [_]Vector{
    .{ .aead = .aes_128_gcm, .info = "4f6465206f6e2061204772656369616e2055726e", .ikm_e = "7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234", .ikm_r = "6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037", .sk_r = "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8", .pk_r = "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d", .enc = "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431", .accumulated = "dcabb32ad8e8acea785275323395abd0" },
    .{ .aead = .aes_256_gcm, .info = "4f6465206f6e2061204772656369616e2055726e", .ikm_e = "2cd7c601cefb3d42a62b04b7a9041494c06c7843818e0ce28a8f704ae7ab20f9", .ikm_r = "dac33b0e9db1b59dbbea58d59a14e7b5896e9bdf98fad6891e99d1686492b9ee", .sk_r = "497b4502664cfea5d5af0b39934dac72242a74f8480451e1aee7d6a53320333d", .pk_r = "430f4b9859665145a6b1ba274024487bd66f03a2dd577d7753c68d7d7d00c00c", .enc = "6c93e09869df3402d7bf231bf540fadd35cd56be14f97178f0954db94b7fc256", .accumulated = "1702e73e1e71705faa8241022af1deea" },
    .{ .aead = .chacha20_poly1305, .info = "4f6465206f6e2061204772656369616e2055726e", .ikm_e = "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b", .ikm_r = "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df", .sk_r = "8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb", .pk_r = "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a", .enc = "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a", .accumulated = "225fb3d35da3bb25e4371bcee4273502" },
};

fn unhex(buf: []u8, text: []const u8) []u8 {
    return std.fmt.hexToBytes(buf, text) catch unreachable;
}

fn draw(source: *std.crypto.hash.sha3.Shake128, buf: *[255]u8) []u8 {
    var length: [1]u8 = undefined;
    source.squeeze(&length);
    source.squeeze(buf[0..length[0]]);
    return buf[0..length[0]];
}

test "C6 HPKE matches the base-mode vectors of every supported AEAD over 1,000 messages" {
    for (vectors) |v| {
        var b: [6][64]u8 = undefined;
        const info = unhex(&b[0], v.info);
        var r = Hpke.deriveKeyPair(unhex(&b[1], v.ikm_r));
        defer r.deinit();
        try std.testing.expectEqualSlices(u8, unhex(&b[2], v.pk_r), &r.public);
        // X25519 keys are clamped when used; the derived bytes are the vector's as printed.
        try std.testing.expectEqualSlices(u8, unhex(&b[3], v.sk_r), r.secret.expose());
        const suite: Hpke.Suite = .{ .kdf = .hkdf_sha256, .aead = v.aead };
        var enc: [Hpke.enc_length]u8 = undefined;
        var sender = try Hpke.setupSender(suite, &r.public, info, unhex(&b[4], v.ikm_e), &enc);
        defer sender.deinit();
        try std.testing.expectEqualSlices(u8, unhex(&b[5], v.enc), &enc);
        var recipient = try Hpke.setupRecipient(suite, &enc, r.secret.expose(), info);
        defer recipient.deinit();
        var source = std.crypto.hash.sha3.Shake128.init(.{});
        var sink = std.crypto.hash.sha3.Shake128.init(.{});
        for (0..1000) |_| {
            var aad_buf: [255]u8 = undefined;
            var pt_buf: [255]u8 = undefined;
            const aad = draw(&source, &aad_buf);
            const pt = draw(&source, &pt_buf);
            var ct: [255 + Hpke.tag_length]u8 = undefined;
            try sender.seal(ct[0 .. pt.len + Hpke.tag_length], aad, pt);
            sink.update(ct[0 .. pt.len + Hpke.tag_length]);
            var back: [255]u8 = undefined;
            try recipient.open(back[0..pt.len], aad, ct[0 .. pt.len + Hpke.tag_length]);
            try std.testing.expectEqualSlices(u8, pt, back[0..pt.len]);
        }
        var accumulated: [16]u8 = undefined;
        sink.squeeze(&accumulated);
        var want: [16]u8 = undefined;
        try std.testing.expectEqualSlices(u8, unhex(&want, v.accumulated), &accumulated);
    }
}

test "C6 HPKE refuses what it must: a forged ciphertext, a wrong AAD, an odd suite, the zero point" {
    var r = Hpke.deriveKeyPair(&(@as([32]u8, @splat(7))));
    defer r.deinit();
    const suite: Hpke.Suite = .{ .kdf = .hkdf_sha256, .aead = .chacha20_poly1305 };
    var enc: [Hpke.enc_length]u8 = undefined;
    var sender = try Hpke.setupSender(suite, &r.public, "info", &(@as([32]u8, @splat(9))), &enc);
    defer sender.deinit();
    var recipient = try Hpke.setupRecipient(suite, &enc, r.secret.expose(), "info");
    defer recipient.deinit();
    var ct: [5 + Hpke.tag_length]u8 = undefined;
    try sender.seal(&ct, "aad", "hello");
    var out: [5]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, recipient.open(&out, "aaD", &ct));
    // A failed open leaves the sequence number where it was: the genuine message still opens.
    try std.testing.expectEqual(0, recipient.seq);
    ct[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, recipient.open(&out, "aad", &ct));
    ct[0] ^= 1;
    try recipient.open(&out, "aad", &ct);
    try std.testing.expectEqualStrings("hello", &out);
    // The next message needs the next nonce: a replay of the first fails.
    try std.testing.expectError(error.AuthenticationFailed, recipient.open(&out, "aad", &ct));
    // Another info is another key.
    var other = try Hpke.setupRecipient(suite, &enc, r.secret.expose(), "inf0");
    defer other.deinit();
    try std.testing.expectError(error.AuthenticationFailed, other.open(&out, "aad", &ct));
    try std.testing.expectError(error.UnsupportedSuite, Hpke.setupRecipient(.{ .kdf = @fromBackingInt(@intCast(2)), .aead = .aes_128_gcm }, &enc, r.secret.expose(), ""));
    try std.testing.expectError(error.UnsupportedSuite, Hpke.setupRecipient(.{ .kdf = .hkdf_sha256, .aead = @fromBackingInt(@intCast(0xffff)) }, &enc, r.secret.expose(), ""));
    try std.testing.expectError(error.InvalidKey, Hpke.setupRecipient(suite, &(@as([32]u8, @splat(0))), r.secret.expose(), ""));
    try std.testing.expectError(error.InvalidKey, Hpke.setupRecipient(suite, enc[0..31], r.secret.expose(), ""));
    try std.testing.expectError(error.InvalidKey, Hpke.setupSender(suite, &(@as([32]u8, @splat(0))), "", &(@as([32]u8, @splat(9))), &enc));
    // An erased context seals and opens nothing.
    var spent = try Hpke.setupSender(suite, &r.public, "", &(@as([32]u8, @splat(3))), &enc);
    spent.deinit();
    try std.testing.expectError(error.MessageLimit, spent.seal(&ct, "", "hello"));
}
