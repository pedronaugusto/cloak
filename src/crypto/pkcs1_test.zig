//! EME-OAEP decoding's contract as properties (pkcs1.zig): an encoding decodes to its message;
//! any one changed byte of it, or another label, is the one refusal (`DecryptionFailed`, which
//! says nothing of which check failed); and `out` is written only when the encoding holds.
const std = @import("std");
const shakedown = @import("shakedown");
const pkcs1 = @import("pkcs1.zig");

const Drawn = struct {
    scheme: pkcs1.Oaep,
    k: usize,
    message: []const u8,
    seed: []const u8,
};

fn draw(case: *shakedown.Case, label: []u8, message: []u8, seed: []u8) Drawn {
    const hashes = std.enums.values(pkcs1.Hash);
    const hash = hashes[shakedown.gen.intRange(case.source, usize, 0, hashes.len - 1)];
    const mgf_hash = hashes[shakedown.gen.intRange(case.source, usize, 0, hashes.len - 1)];
    const h = hash.length();
    const label_len = shakedown.gen.intRange(case.source, usize, 0, label.len);
    for (label[0..label_len]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    // Any modulus width the scheme leaves room in, to a 4096-bit key's.
    const k = shakedown.gen.intRange(case.source, usize, 2 * h + 2, pkcs1.max_em);
    const limit = pkcs1.maxMessage(hash, k).?;
    const len = shakedown.gen.intRange(case.source, usize, 0, limit);
    for (message[0..len]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    for (seed[0..h]) |*byte| byte.* = shakedown.gen.int(case.source, u8);
    return .{ .scheme = .{ .hash = hash, .mgf_hash = mgf_hash, .label = label[0..label_len] }, .k = k, .message = message[0..len], .seed = seed[0..h] };
}

test "OAEP property: an encoding decodes to its message under its scheme and label" {
    try shakedown.check(std.testing.allocator, {}, roundTrip, .{ .cases = 512, .seed = 0x0ae9 });
}
fn roundTrip(_: void, case: *shakedown.Case) !void {
    var label: [32]u8 = undefined;
    var message: [pkcs1.max_em]u8 = undefined;
    var seed: [pkcs1.max_digest]u8 = undefined;
    const d = draw(case, &label, &message, &seed);
    var em: [pkcs1.max_em]u8 = undefined;
    try pkcs1.encode(d.scheme, d.message, d.seed, em[0..d.k]);
    var out: [pkcs1.max_em]u8 = undefined;
    try std.testing.expectEqualSlices(u8, d.message, try pkcs1.decode(d.scheme, em[0..d.k], &out));
}

test "OAEP property: one changed byte anywhere is the one refusal, and out is untouched" {
    try shakedown.check(std.testing.allocator, {}, changedByte, .{ .cases = 1024, .seed = 0x0aea });
}
fn changedByte(_: void, case: *shakedown.Case) !void {
    var label: [32]u8 = undefined;
    var message: [pkcs1.max_em]u8 = undefined;
    var seed: [pkcs1.max_digest]u8 = undefined;
    const d = draw(case, &label, &message, &seed);
    var em: [pkcs1.max_em]u8 = undefined;
    try pkcs1.encode(d.scheme, d.message, d.seed, em[0..d.k]);
    // The leading byte (Manger's oracle), the masked seed, the label hash, the padding, the
    // separator and the message alike.
    const at = shakedown.gen.intRange(case.source, usize, 0, d.k - 1);
    em[at] ^= shakedown.gen.intRange(case.source, u8, 1, 255);
    var out: [pkcs1.max_em]u8 = @splat(0xc5);
    try std.testing.expectError(error.DecryptionFailed, pkcs1.decode(d.scheme, em[0..d.k], &out));
    for (out) |byte| try std.testing.expectEqual(@as(u8, 0xc5), byte);
}

test "OAEP property: an encoding under another label is the one refusal" {
    try shakedown.check(std.testing.allocator, {}, otherLabel, .{ .cases = 256, .seed = 0x0aeb });
}
fn otherLabel(_: void, case: *shakedown.Case) !void {
    var label: [32]u8 = undefined;
    var message: [pkcs1.max_em]u8 = undefined;
    var seed: [pkcs1.max_digest]u8 = undefined;
    const d = draw(case, &label, &message, &seed);
    var em: [pkcs1.max_em]u8 = undefined;
    try pkcs1.encode(d.scheme, d.message, d.seed, em[0..d.k]);
    var other_label: [33]u8 = undefined;
    @memcpy(other_label[0..d.scheme.label.len], d.scheme.label);
    other_label[d.scheme.label.len] = shakedown.gen.int(case.source, u8);
    var other = d.scheme;
    other.label = other_label[0 .. d.scheme.label.len + 1];
    var out: [pkcs1.max_em]u8 = @splat(0xc5);
    try std.testing.expectError(error.DecryptionFailed, pkcs1.decode(other, em[0..d.k], &out));
    for (out) |byte| try std.testing.expectEqual(@as(u8, 0xc5), byte);
}
