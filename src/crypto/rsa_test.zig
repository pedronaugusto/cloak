const std = @import("std");
const rsa = @import("rsa.zig");
const Modulus = std.crypto.ff.Modulus(4096);

/// openssl-generated two-prime keys (PKCS#1 DER). 2056 bits gives an n of 33 limbs and factors
/// of 17: widths that are not a multiple of the 2048-bit shapes.
const keys = .{ @embedFile("testdata/rsa2048.der"), @embedFile("testdata/rsa2056.der"), @embedFile("testdata/rsa3072.der"), @embedFile("testdata/rsa4096.der") };

/// The nine INTEGERs of an RSAPrivateKey, minimal magnitudes.
const Parts = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    qinv: []const u8,
};

fn parts(der: []const u8) !Parts {
    var at: usize = 0;
    const outer = try element(der, &at, 0x30);
    var inner: usize = 0;
    var values: [9][]const u8 = undefined;
    for (&values) |*v| {
        v.* = try element(outer, &inner, 0x02);
        while (v.len > 1 and v.*[0] == 0) v.* = v.*[1..];
    }
    return .{ .n = values[1], .e = values[2], .d = values[3], .p = values[4], .q = values[5], .dp = values[6], .dq = values[7], .qinv = values[8] };
}

fn element(bytes: []const u8, at: *usize, tag: u8) ![]const u8 {
    if (bytes[at.*] != tag) return error.BadDer;
    var len: usize = bytes[at.* + 1];
    at.* += 2;
    if (len & 0x80 != 0) {
        const count = len & 0x7f;
        len = 0;
        for (bytes[at.*..][0..count]) |b| len = (len << 8) | b;
        at.* += count;
    }
    defer at.* += len;
    return bytes[at.*..][0..len];
}

fn load(der: []const u8, key: *rsa.PrivateKey) !Parts {
    const k = try parts(der);
    try key.init(k.n, k.e, k.p, k.q, k.dp, k.dq, k.qinv);
    return k;
}

/// A uniform message below n: the top byte drawn below n's.
fn message(random: std.Random, n: []const u8, out: []u8) void {
    random.bytes(out);
    out[0] = random.uintLessThan(u8, n[0]);
}

test "RSA private operation equals the standard library's m^d mod n" {
    var prng: std.Random.DefaultPrng = .init(0x5eed);
    const random = prng.random();
    inline for (keys) |der| {
        var key: rsa.PrivateKey = undefined;
        const k = try load(der, &key);
        const n = try Modulus.fromBytes(k.n, .big);
        for (0..6) |round| {
            var m: [rsa.max_bytes]u8 = undefined;
            message(random, k.n, m[0..k.n.len]);
            if (round == 0) @memset(m[0..k.n.len], 0);
            if (round == 1) {
                @memset(m[0..k.n.len], 0);
                m[k.n.len - 1] = 1;
            }
            var seed: [rsa.seed_length]u8 = undefined;
            random.bytes(&seed);
            var ours: [rsa.max_bytes]u8 = undefined;
            try key.private(m[0..k.n.len], &seed, ours[0..k.n.len]);
            const expected = try n.powWithEncodedExponent(try Modulus.Fe.fromBytes(n, m[0..k.n.len], .big), k.d, .big);
            var theirs: [rsa.max_bytes]u8 = undefined;
            try expected.toBytes(theirs[0..k.n.len], .big);
            try std.testing.expectEqualSlices(u8, theirs[0..k.n.len], ours[0..k.n.len]);
        }
    }
}

test "RSA blinding never changes the result" {
    var key: rsa.PrivateKey = undefined;
    const k = try load(keys[0], &key);
    var m: [256]u8 = undefined;
    @memcpy(&m, k.n);
    m[0] -= 1;
    var first: [256]u8 = undefined;
    try key.private(&m, &@as([32]u8, @splat(0)), &first);
    for (1..8) |i| {
        var again: [256]u8 = undefined;
        try key.private(&m, &@as([32]u8, @splat(@intCast(i))), &again);
        try std.testing.expectEqualSlices(u8, &first, &again);
    }
    // The largest message, n - 1, signs to (n - 1)^d = n - 1 for odd d.
    @memcpy(&m, k.n);
    m[255] -= 1;
    try key.private(&m, &@as([32]u8, @splat(9)), &first);
    try std.testing.expectEqualSlices(u8, &m, &first);
}

test "RSA private operation rejects a message at or above n and a wrong length" {
    var key: rsa.PrivateKey = undefined;
    const k = try load(keys[0], &key);
    var out: [256]u8 = undefined;
    const seed: [32]u8 = @splat(1);
    try std.testing.expectError(error.SigningFailed, key.private(k.n, &seed, &out));
    try std.testing.expectError(error.SigningFailed, key.private(&@as([256]u8, @splat(0xff)), &seed, &out));
    try std.testing.expectError(error.SigningFailed, key.private(k.n[1..], &seed, out[1..]));
}

test "RSA fault check withholds a result whose CRT half or encoding was corrupted" {
    inline for (keys) |der| {
        var key: rsa.PrivateKey = undefined;
        const k = try load(der, &key);
        var m: [rsa.max_bytes]u8 = @splat(0x42);
        m[0] = 1;
        const seed: [32]u8 = @splat(3);
        var out: [rsa.max_bytes]u8 = @splat(0xaa);
        inline for (.{ rsa.PrivateKey.Fault.p_half, .q_half, .encoded }) |fault| {
            try std.testing.expectError(error.SigningFailed, rsa.privateWithFault(&key, m[0..k.n.len], &seed, out[0..k.n.len], fault));
            // Nothing of the faulty result reached the output.
            for (out[0..k.n.len]) |b| try std.testing.expectEqual(@as(u8, 0xaa), b);
        }
        try rsa.privateWithFault(&key, m[0..k.n.len], &seed, out[0..k.n.len], .none);
    }
}

test "RSA key shapes outside the kernel are refused" {
    const k = try parts(keys[0]);
    var key: rsa.PrivateKey = undefined;
    // Even modulus, even exponent, exponent above 64 bits.
    var even: [256]u8 = undefined;
    @memcpy(&even, k.n);
    even[255] &= 0xfe;
    try std.testing.expectError(error.InvalidKey, key.init(&even, k.e, k.p, k.q, k.dp, k.dq, k.qinv));
    try std.testing.expectError(error.InvalidKey, key.init(k.n, "\x01\x00\x00", k.p, k.q, k.dp, k.dq, k.qinv));
    try std.testing.expectError(error.InvalidKey, key.init(k.n, &@as([9]u8, @splat(1)), k.p, k.q, k.dp, k.dq, k.qinv));
    // A factor wider than half of the largest modulus.
    try std.testing.expectError(error.InvalidKey, key.init(k.n, k.e, &@as([257]u8, @splat(0xff)), k.q, k.dp, k.dq, k.qinv));
}

test "RSA blinding is real: r is fresh per seed and key, and the exponentiated value is m * r^e" {
    var key_a: rsa.PrivateKey = undefined;
    const a = try load(keys[0], &key_a);
    var key_b: rsa.PrivateKey = undefined;
    _ = try load(keys[1], &key_b);
    var m: [256]u8 = undefined;
    var prng: std.Random.DefaultPrng = .init(0xb11d);
    message(prng.random(), a.n, &m);
    const N = std.crypto.ff.Modulus(2048);
    const n = try N.fromBytes(a.n, .big);
    var seen: [4][32]u64 = undefined;
    for (0..4) |i| {
        var r: [32]u64 = undefined;
        var mb: [32]u64 = undefined;
        try rsa.blindingForTest(&key_a, &m, &@as([32]u8, @splat(@intCast(i))), &r, &mb);
        // Never the identity, never the message itself, never a value seen before.
        try std.testing.expect(!(r[0] == 1 and std.mem.allEqual(u64, r[1..], 0)));
        for (seen[0..i]) |earlier| try std.testing.expect(!std.mem.eql(u64, &earlier, &r));
        seen[i] = r;
        var r_bytes: [256]u8 = undefined;
        var mb_bytes: [256]u8 = undefined;
        for (0..32) |j| {
            std.mem.writeInt(u64, r_bytes[256 - 8 * (j + 1) ..][0..8], r[j], .big);
            std.mem.writeInt(u64, mb_bytes[256 - 8 * (j + 1) ..][0..8], mb[j], .big);
        }
        try std.testing.expect(!std.mem.eql(u8, &mb_bytes, &m));
        // mb = m * r^e mod n, by std's arithmetic.
        const re = try n.powPublic(try N.Fe.fromBytes(n, &r_bytes, .big), try N.Fe.fromBytes(n, a.e, .big));
        const want = n.mul(try N.Fe.fromBytes(n, &m, .big), re);
        var want_bytes: [256]u8 = undefined;
        try want.toBytes(&want_bytes, .big);
        try std.testing.expectEqualSlices(u8, &want_bytes, &mb_bytes);
    }
    // The same seed and message under another key: another r.
    var m_b: [257]u8 = @splat(0);
    @memcpy(m_b[1..], &m);
    var r_b: [33]u64 = undefined;
    var mb_b: [33]u64 = undefined;
    try rsa.blindingForTest(&key_b, &m_b, &@as([32]u8, @splat(0)), &r_b, &mb_b);
    try std.testing.expect(!std.mem.eql(u64, &seen[0], r_b[0..32]));
}
