const std = @import("std");
const shakedown = @import("shakedown");
const Exchange = @import("Exchange.zig");
const Group = @import("Group.zig").Group;
const ecdh = @import("../../credentials/Ecdh.zig");

const X25519 = std.crypto.dh.X25519;
const MlKem = std.crypto.kem.ml_kem.MLKem768;

fn fill(buffer: []u8, seed: u8) void {
    for (buffer, 0..) |*byte, i| byte.* = seed +% @as(u8, @truncate(i *% 7));
}

test "C2 exchange X25519 agrees with an independent peer and rejects a low-order share" {
    var entropy: [32]u8 = undefined;
    fill(&entropy, 3);
    var share = try Exchange.Share.init(.x25519, &entropy);
    defer share.deinit();
    const server = X25519.KeyPair.generateDeterministic(@splat(9));
    var agreed = try share.agree(&server.public_key);
    defer agreed.deinit();
    const expected = try X25519.scalarmult(server.secret_key, share.wire()[0..32].*);
    try std.testing.expectEqualSlices(u8, &expected, agreed.bytes());
    try std.testing.expectError(error.WeakKey, share.agree(&@as([32]u8, @splat(0))));
    try std.testing.expectError(error.InvalidShare, share.agree(server.public_key[0..31]));
}

test "C2 exchange hybrid share order and secret order follow the ML-KEM first layout" {
    var entropy: [Exchange.entropyLength(.x25519_mlkem768)]u8 = undefined;
    fill(&entropy, 5);
    var share = try Exchange.Share.init(.x25519_mlkem768, &entropy);
    defer share.deinit();
    try std.testing.expectEqual(@as(usize, 1216), share.wire().len);
    const ek = try MlKem.PublicKey.fromBytes(share.wire()[0..MlKem.PublicKey.encoded_length]);
    const encapsulated = ek.encapsDeterministic(&@as([MlKem.encaps_seed_length]u8, @splat(7)));
    const server = X25519.KeyPair.generateDeterministic(@splat(11));
    var reply: [1120]u8 = undefined;
    reply[0..1088].* = encapsulated.ciphertext;
    reply[1088..].* = server.public_key;
    var agreed = try share.agree(&reply);
    defer agreed.deinit();
    try std.testing.expectEqual(@as(usize, 64), agreed.bytes().len);
    try std.testing.expectEqualSlices(u8, &encapsulated.shared_secret, agreed.bytes()[0..32]);
    const x = try X25519.scalarmult(server.secret_key, share.wire()[1184..][0..32].*);
    try std.testing.expectEqualSlices(u8, &x, agreed.bytes()[32..]);
    // A damaged ciphertext is implicitly rejected: success with an unrelated key.
    var damaged = reply;
    damaged[17] ^= 0x40;
    var other = try share.agree(&damaged);
    defer other.deinit();
    try std.testing.expect(!std.mem.eql(u8, agreed.bytes()[0..32], other.bytes()[0..32]));
    // Swapped component order is a length-correct but invalid share for the X25519 half.
    var swapped: [1120]u8 = undefined;
    swapped[0..32].* = server.public_key;
    swapped[32..].* = reply[0..1088].*;
    var swapped_agreed = share.agree(&swapped);
    if (swapped_agreed) |*value| {
        defer value.deinit();
        try std.testing.expect(!std.mem.eql(u8, value.bytes()[0..32], agreed.bytes()[0..32]));
    } else |err| try std.testing.expectEqual(error.WeakKey, err);
}

test "C2 exchange P-256 and P-384 agree with std and reject invalid points" {
    inline for (.{ .{ Group.p256, ecdh.P256 }, .{ Group.p384, ecdh.P384 } }) |pair| {
        var entropy: [pair[1].scalar_length]u8 = undefined;
        fill(&entropy, 21);
        var share = try Exchange.Share.init(pair[0], &entropy);
        defer share.deinit();
        var peer_scalar: [pair[1].scalar_length]u8 = undefined;
        fill(&peer_scalar, 77);
        var peer_public: [pair[1].public_length]u8 = undefined;
        try pair[1].publicKey(&peer_scalar, &peer_public);
        var agreed = try share.agree(&peer_public);
        defer agreed.deinit();
        var expected: [pair[1].scalar_length]u8 = undefined;
        try pair[1].agree(&peer_scalar, share.wire(), &expected);
        try std.testing.expectEqualSlices(u8, &expected, agreed.bytes());
        var off_curve = peer_public;
        off_curve[off_curve.len - 1] ^= 4;
        try std.testing.expectError(error.InvalidShare, share.agree(&off_curve));
        try std.testing.expectError(error.InvalidShare, share.agree(peer_public[0 .. peer_public.len - 1]));
    }
}

test "C2 exchange entropy length and scalar range are checked" {
    try std.testing.expectError(error.InvalidEntropy, Exchange.Share.init(.x25519, &@as([31]u8, @splat(1))));
    try std.testing.expectError(error.InvalidEntropy, Exchange.Share.init(.p256, &@as([32]u8, @splat(0))));
    try std.testing.expectError(error.InvalidEntropy, Exchange.Share.init(.p256, &@as([32]u8, @splat(0xff))));
    try std.testing.expectError(error.InvalidEntropy, Exchange.Share.init(.p384, &@as([48]u8, @splat(0xff))));
}

test "C2 exchange erases the private half" {
    var entropy: [32]u8 = undefined;
    fill(&entropy, 1);
    var share = try Exchange.Share.init(.x25519, &entropy);
    const secret = share.private.x25519.expose().*;
    const public = share.public;
    try std.testing.expect(std.mem.find(u8, std.mem.asBytes(&share), &secret) != null);
    share.deinit();
    try std.testing.expect(std.mem.find(u8, std.mem.asBytes(&share), &secret) == null);
    try std.testing.expect(std.mem.find(u8, std.mem.asBytes(&share), public[0..32]) == null);
}

test "C2 exchange agreement matches a symmetric peer for random entropy" {
    try shakedown.check(std.testing.allocator, {}, symmetric, .{ .cases = 24, .seed = 0xec11 });
}
fn symmetric(_: void, case: *shakedown.Case) !void {
    var entropy: [32]u8 = undefined;
    for (&entropy) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    var share = try Exchange.Share.init(.x25519, &entropy);
    defer share.deinit();
    const server = X25519.KeyPair.generateDeterministic(entropy);
    var agreed = try share.agree(&server.public_key);
    defer agreed.deinit();
    const expected = try X25519.scalarmult(server.secret_key, share.wire()[0..32].*);
    try std.testing.expectEqualSlices(u8, &expected, agreed.bytes());
}

test "C2 exchange server response agrees with the client share for every group" {
    inline for (.{ Group.x25519, Group.x25519_mlkem768, Group.p256, Group.p384 }) |group| {
        var client_entropy: [Exchange.entropyLength(group)]u8 = undefined;
        fill(&client_entropy, 11);
        var client = try Exchange.Share.init(group, &client_entropy);
        defer client.deinit();
        var server_entropy: [Exchange.respondEntropyLength(group)]u8 = undefined;
        fill(&server_entropy, 91);
        var response = try Exchange.respond(group, client.wire(), &server_entropy);
        defer response.deinit();
        var agreed = try client.agree(response.wire());
        defer agreed.deinit();
        try std.testing.expectEqualSlices(u8, response.agreed.bytes(), agreed.bytes());
        // A share of the wrong length, or off the curve, never yields a secret.
        try std.testing.expectError(error.InvalidShare, Exchange.respond(group, client.wire()[1..], &server_entropy));
        try std.testing.expectError(error.InvalidEntropy, Exchange.respond(group, client.wire(), server_entropy[1..]));
    }
}

test "C2 exchange server response refuses small-order and invalid client shares" {
    var entropy: [32]u8 = undefined;
    fill(&entropy, 5);
    try std.testing.expectError(error.WeakKey, Exchange.respond(.x25519, &@as([32]u8, @splat(0)), &entropy));
    var curve_entropy: [32]u8 = undefined;
    fill(&curve_entropy, 6);
    var off_curve: [65]u8 = @splat(1);
    off_curve[0] = 4;
    try std.testing.expectError(error.InvalidShare, Exchange.respond(.p256, &off_curve, &curve_entropy));
    var zero_scalar: [32]u8 = @splat(0);
    var good_share: [65]u8 = undefined;
    try ecdh.P256.publicKey(&curve_entropy, &good_share);
    try std.testing.expectError(error.InvalidEntropy, Exchange.respond(.p256, &good_share, &zero_scalar));
    // A hybrid share whose ML-KEM key is not canonical.
    var kem_entropy: [64]u8 = undefined;
    fill(&kem_entropy, 7);
    var bad_hybrid: [1216]u8 = @splat(0xff);
    try std.testing.expectError(error.InvalidShare, Exchange.respond(.x25519_mlkem768, &bad_hybrid, &kem_entropy));
}
