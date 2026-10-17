//! cloak's ML-DSA against std's (which keeps the whole matrix and is the oracle here: same keys,
//! same signatures byte for byte, each verifying the other's) and against Wycheproof's vectors,
//! which include malformed hints, norm violations, wrong lengths and out-of-range private keys.
const std = @import("std");
const mldsa = @import("mldsa.zig");

const gpa = std.testing.allocator;

fn StdOf(comptime level: mldsa.Level) type {
    return switch (level) {
        .mldsa44 => std.crypto.sign.mldsa.MLDSA44,
        .mldsa65 => std.crypto.sign.mldsa.MLDSA65,
        .mldsa87 => std.crypto.sign.mldsa.MLDSA87,
    };
}

fn differential(comptime level: mldsa.Level) !void {
    const M = mldsa.Scheme(level);
    const S = StdOf(level);
    var rng = std.Random.DefaultPrng.init(@as(u64, @backingInt(level)) + 7);
    const random = rng.random();
    // std's types are large: they live on the heap here.
    const pair = try gpa.create(S.KeyPair);
    defer gpa.destroy(pair);
    for (0..4) |round| {
        var seed: [32]u8 = undefined;
        random.bytes(&seed);
        var pk: [M.public_key_length]u8 = undefined;
        var sk: [M.secret_key_length]u8 = undefined;
        M.keyFromSeed(&seed, &pk, &sk);
        pair.* = try S.KeyPair.generateDeterministic(seed);
        try std.testing.expectEqualSlices(u8, &pair.public_key.toBytes(), &pk);
        try std.testing.expectEqualSlices(u8, &pair.secret_key.toBytes(), &sk);
        var derived: [M.public_key_length]u8 = undefined;
        try M.publicKey(&sk, &derived);
        try std.testing.expectEqualSlices(u8, &pk, &derived);
        var message: [100]u8 = undefined;
        random.bytes(&message);
        const msg = message[0 .. round * 30];
        const context: []const u8 = if (round % 2 == 0) "" else "cloak context";
        var noise: [32]u8 = @splat(0);
        if (round >= 2) random.bytes(&noise);
        var ours: [M.signature_length]u8 = undefined;
        M.sign(&sk, msg, context, &noise, &ours);
        var signer = try pair.signerWithContext(if (round >= 2) noise else null, context);
        signer.update(msg);
        const theirs = signer.finalize();
        try std.testing.expectEqualSlices(u8, &theirs.toBytes(), &ours);
        try M.verify(&pk, msg, context, &ours);
        // Any change to the message, context, signature or key fails.
        try std.testing.expectError(error.InvalidSignature, M.verify(&pk, message[0 .. msg.len + 1], context, &ours));
        try std.testing.expectError(error.InvalidSignature, M.verify(&pk, msg, "other", &ours));
        for ([_]usize{ 0, M.signature_length / 2, M.signature_length - 1 }) |at| {
            var bad = ours;
            bad[at] ^= 1;
            try std.testing.expectError(error.InvalidSignature, M.verify(&pk, msg, context, &bad));
        }
        var other_pk = pk;
        other_pk[40] ^= 1;
        try std.testing.expectError(error.InvalidSignature, M.verify(&other_pk, msg, context, &ours));
    }
}

test "C10 ML-DSA-44 matches std: keys, deterministic and hedged signatures, verification" {
    try differential(.mldsa44);
}

test "C10 ML-DSA-65 matches std: keys, deterministic and hedged signatures, verification" {
    try differential(.mldsa65);
}

test "C10 ML-DSA-87 matches std: keys, deterministic and hedged signatures, verification" {
    try differential(.mldsa87);
}

test "C10 ML-DSA expanded private keys are checked against themselves" {
    const M = mldsa.Scheme(.mldsa65);
    var seed: [32]u8 = @splat(9);
    var pk: [M.public_key_length]u8 = undefined;
    var sk: [M.secret_key_length]u8 = undefined;
    M.keyFromSeed(&seed, &pk, &sk);
    var out: [M.public_key_length]u8 = undefined;
    // An s1 coefficient past eta (a nibble of 15 where 8 is the most), t0 off by one bit, tr
    // of another key, rho of another key (so t0 is wrong): each refused.
    const flips = [_]struct { at: usize, xor: u8 }{
        .{ .at = 128, .xor = 0xf0 },
        .{ .at = M.secret_key_length - 5, .xor = 1 },
        .{ .at = 64, .xor = 1 },
        .{ .at = 0, .xor = 1 },
    };
    for (flips) |flip| {
        var bad = sk;
        bad[flip.at] ^= flip.xor;
        try std.testing.expectError(error.InvalidKey, M.publicKey(&bad, &out));
    }
    try M.publicKey(&sk, &out);
    try std.testing.expectEqualSlices(u8, &pk, &out);
}

fn hex(arena: std.mem.Allocator, value: []const u8) ![]u8 {
    const bytes = try arena.alloc(u8, value.len / 2);
    _ = try std.fmt.hexToBytes(bytes, value);
    return bytes;
}

const VerifyTest = struct { tcId: usize, flags: []const []const u8, msg: []const u8, ctx: ?[]const u8 = null, sig: []const u8, result: []const u8 };

fn verifyCampaign(comptime level: mldsa.Level, comptime file: []const u8) !void {
    const M = mldsa.Scheme(level);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const parsed = try std.json.parseFromSliceLeaky(struct { numberOfTests: usize, testGroups: []struct { publicKey: []const u8, tests: []VerifyTest } }, arena, @embedFile("testdata/wycheproof/" ++ file), .{ .ignore_unknown_fields = true });
    var mismatch: usize = 0;
    var count: usize = 0;
    for (parsed.testGroups) |group| {
        const pk = try hex(arena, group.publicKey);
        for (group.tests) |vector| {
            count += 1;
            const msg = try hex(arena, vector.msg);
            const ctx = if (vector.ctx) |c| try hex(arena, c) else &.{};
            const sig = try hex(arena, vector.sig);
            const accepted = pk.len == M.public_key_length and sig.len == M.signature_length and
                if (M.verify(pk[0..M.public_key_length], msg, ctx, sig[0..M.signature_length])) |_| true else |_| false;
            if (accepted != std.mem.eql(u8, vector.result, "valid")) {
                mismatch += 1;
                std.debug.print("WYCHEPROOF {s} tcId={d} expected={s} flags={any}\n", .{ file, vector.tcId, vector.result, vector.flags });
            }
        }
    }
    try std.testing.expectEqual(parsed.numberOfTests, count);
    try std.testing.expectEqual(@as(usize, 0), mismatch);
}

const SignTest = struct { tcId: usize, flags: []const []const u8, msg: ?[]const u8 = null, ctx: ?[]const u8 = null, rnd: ?[]const u8 = null, sig: []const u8, result: []const u8 };

/// Signing vectors: a seed's key (or an expanded key) signs each message, deterministically or
/// with the vector's randomness, and must produce Wycheproof's bytes; a malformed key or context
/// must be refused.
fn signCampaign(comptime level: mldsa.Level, comptime file: []const u8, comptime seeded: bool) !void {
    const M = mldsa.Scheme(level);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const Group = if (seeded) struct { privateSeed: []const u8, publicKey: ?[]const u8 = null, tests: []SignTest } else struct { privateKey: []const u8, publicKey: ?[]const u8 = null, tests: []SignTest };
    const parsed = try std.json.parseFromSliceLeaky(struct { numberOfTests: usize, testGroups: []Group }, arena, @embedFile("testdata/wycheproof/" ++ file), .{ .ignore_unknown_fields = true });
    var mismatch: usize = 0;
    var count: usize = 0;
    for (parsed.testGroups) |group| {
        var sk: [M.secret_key_length]u8 = undefined;
        var pk: [M.public_key_length]u8 = undefined;
        const key_ok = if (seeded) blk: {
            const seed = try hex(arena, group.privateSeed);
            if (seed.len != 32) break :blk false;
            M.keyFromSeed(seed[0..32], &pk, &sk);
            break :blk true;
        } else blk: {
            const bytes = try hex(arena, group.privateKey);
            if (bytes.len != M.secret_key_length) break :blk false;
            sk = bytes[0..M.secret_key_length].*;
            M.publicKey(&sk, &pk) catch break :blk false;
            break :blk true;
        };
        if (key_ok) if (group.publicKey) |text| try std.testing.expectEqualSlices(u8, try hex(arena, text), &pk);
        for (group.tests) |vector| {
            count += 1;
            const valid = std.mem.eql(u8, vector.result, "valid");
            // The "Internal" vectors sign a given mu, which this API never takes.
            const text = vector.msg orelse continue;
            const msg = try hex(arena, text);
            const ctx = if (vector.ctx) |c| try hex(arena, c) else &.{};
            const expected = try hex(arena, vector.sig);
            var noise: [32]u8 = @splat(0);
            if (vector.rnd) |r| _ = try std.fmt.hexToBytes(&noise, r);
            const ok = key_ok and ctx.len <= 255 and blk: {
                var sig: [M.signature_length]u8 = undefined;
                M.sign(&sk, msg, ctx, &noise, &sig);
                break :blk std.mem.eql(u8, &sig, expected);
            };
            if (ok != valid) {
                mismatch += 1;
                std.debug.print("WYCHEPROOF {s} tcId={d} expected={s} flags={any}\n", .{ file, vector.tcId, vector.result, vector.flags });
            }
        }
    }
    try std.testing.expectEqual(parsed.numberOfTests, count);
    try std.testing.expectEqual(@as(usize, 0), mismatch);
}

test "C10 Wycheproof ML-DSA-44 verification" {
    try verifyCampaign(.mldsa44, "mldsa_44_verify_test.json");
}

test "C10 Wycheproof ML-DSA-65 verification" {
    try verifyCampaign(.mldsa65, "mldsa_65_verify_test.json");
}

test "C10 Wycheproof ML-DSA-87 verification" {
    try verifyCampaign(.mldsa87, "mldsa_87_verify_test.json");
}

test "C10 Wycheproof ML-DSA-44 signing from seeds" {
    try signCampaign(.mldsa44, "mldsa_44_sign_seed_test.json", true);
}

test "C10 Wycheproof ML-DSA-65 signing from seeds" {
    try signCampaign(.mldsa65, "mldsa_65_sign_seed_test.json", true);
}

test "C10 Wycheproof ML-DSA-87 signing from seeds" {
    try signCampaign(.mldsa87, "mldsa_87_sign_seed_test.json", true);
}

test "C10 Wycheproof ML-DSA-44 signing from expanded keys, malformed ones refused" {
    try signCampaign(.mldsa44, "mldsa_44_sign_noseed_test.json", false);
}
