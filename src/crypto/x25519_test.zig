const std = @import("std");
const x25519 = @import("x25519.zig");
const s2n = @import("field.zig").s2n;
const Fiat = x25519.With(.fiat, null);

fn hex(comptime text: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, text) catch unreachable; // unreachable: the vectors are 64 hex digits
    return out;
}

/// RFC 7748 5.2's two vectors, its iterated vector to 1000, and 6.1's Diffie-Hellman.
fn rfc7748(comptime X: type) !void {
    var out: [32]u8 = undefined;
    X.scalarmult(&out, &hex("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"), &hex("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"));
    try std.testing.expectEqualSlices(u8, &hex("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"), &out);
    X.scalarmult(&out, &hex("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"), &hex("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"));
    try std.testing.expectEqualSlices(u8, &hex("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"), &out);
    var k = x25519_nine;
    var u = x25519_nine;
    for (1..1001) |i| {
        X.scalarmult(&out, &k, &u);
        u = k;
        k = out;
        if (i == 1) try std.testing.expectEqualSlices(u8, &hex("422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"), &k);
    }
    try std.testing.expectEqualSlices(u8, &hex("684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"), &k);
    const alice = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    const bob = hex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    var alice_public: [32]u8 = undefined;
    var bob_public: [32]u8 = undefined;
    X.base(&alice_public, &alice);
    X.base(&bob_public, &bob);
    try std.testing.expectEqualSlices(u8, &hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"), &alice_public);
    try std.testing.expectEqualSlices(u8, &hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"), &bob_public);
    var shared: [32]u8 = undefined;
    X.scalarmult(&shared, &alice, &bob_public);
    try std.testing.expectEqualSlices(u8, &hex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"), &shared);
}

const x25519_nine: [32]u8 = .{9} ++ @as([31]u8, @splat(0));

test "X25519: the portable ladder over fiat-crypto's field gives RFC 7748's vectors" {
    try rfc7748(Fiat);
}

test "X25519: s2n-bignum's ladders, every variant this processor runs, give RFC 7748's vectors" {
    if (!s2n.assembly) return error.SkipZigTest;
    try rfc7748(x25519.With(.s2n, .alt));
    if (s2n.plainRuns()) try rfc7748(x25519.With(.s2n, .plain));
}

/// Another implementation's outputs equal the portable ladder's, on random scalars and
/// u-coordinates: canonical, non-canonical (2^255 - 19 and above) and with the top bit set.
fn agree(comptime X: type, random: std.Random) !void {
    for (0..2000) |i| {
        var k: [32]u8 = undefined;
        var u: [32]u8 = undefined;
        random.bytes(&k);
        random.bytes(&u);
        if (i % 7 == 0) {
            // At or just above p: 2^255 - 19 + small.
            @memset(&u, 0xff);
            u[0] = 0xed + @as(u8, @truncate(i % 18)); // safe: any low byte will do
            u[31] = 0x7f;
        }
        if (i % 5 == 0) u[31] |= 0x80;
        var expected: [32]u8 = undefined;
        var actual: [32]u8 = undefined;
        Fiat.scalarmult(&expected, &k, &u);
        X.scalarmult(&actual, &k, &u);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
        Fiat.base(&expected, &k);
        X.base(&actual, &k);
        try std.testing.expectEqualSlices(u8, &expected, &actual);
    }
}

test "F05 catalogue_kernel_carries_lengths_and_dispatch (X25519: s2n-bignum's ladders, every variant this processor runs, equal the portable ladder)" {
    if (!s2n.assembly) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x25519);
    try agree(x25519.With(.s2n, .alt), prng.random());
    if (s2n.plainRuns()) try agree(x25519.With(.s2n, .plain), prng.random());
}

test "X25519: the portable ladder equals std's on random inputs" {
    var prng = std.Random.DefaultPrng.init(0x7748);
    for (0..500) |_| {
        var k: [32]u8 = undefined;
        var u: [32]u8 = undefined;
        prng.random().bytes(&k);
        prng.random().bytes(&u);
        var ours: [32]u8 = undefined;
        Fiat.scalarmult(&ours, &k, &u);
        const theirs = std.crypto.dh.X25519.scalarmult(k, u) catch @as([32]u8, @splat(0));
        try std.testing.expectEqualSlices(u8, &theirs, &ours);
    }
}
