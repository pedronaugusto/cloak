const std = @import("std");
const nist = @import("nist.zig");
const s2n = @import("s2n.zig");

fn Check(comptime curve: nist.Curve) type {
    return struct {
        const Fiat = nist.Field(curve, .fiat);
        const p: comptime_int = Fiat.modulus;
        const length = Fiat.encoded_length;
        const V = @Int(.unsigned, 8 * length);
        const W = @Int(.unsigned, 16 * length + 8);

        fn encode(v: V) [length]u8 {
            var out: [length]u8 = undefined;
            std.mem.writeInt(V, &out, v, .big);
            return out;
        }

        fn decode(bytes: [length]u8) V {
            return std.mem.readInt(V, &bytes, .big);
        }

        /// Values every routine must get right: zero, one, two, p - 1, p - 2, the halves of p,
        /// powers of two at limb boundaries and all-ones below them.
        fn edges() [20]V {
            const top = 8 * length - 1;
            return .{ 0, 1, 2, 3, p - 1, p - 2, p - 3, p >> 1, (p >> 1) + 1, 1 << top, (1 << top) - 1, 1 << 64, (1 << 64) - 1, 1 << 128, (1 << 128) - 1, 1 << 192, (1 << 192) - 1, (1 << 32) - 1, p / 3, (p / 3) * 2 };
        }

        /// Each operation of `F` against wide-integer arithmetic on random and edge operands.
        fn againstIntegers(comptime F: type, random: std.Random) !void {
            const e = edges();
            for (0..3000 + e.len * e.len) |i| {
                const pair = i < e.len * e.len;
                const a: V = if (pair) e[i / e.len] else random.int(V) % p;
                const b: V = if (pair) e[i % e.len] else random.int(V) % p;
                const x = try F.fromBytes(&encode(a));
                const y = try F.fromBytes(&encode(b));
                try std.testing.expectEqual(a, decode(x.toBytes()));
                try std.testing.expectEqual(@as(V, @intCast((@as(W, a) * b) % p)), decode(x.mul(&y).toBytes()));
                try std.testing.expectEqual(@as(V, @intCast((@as(W, a) * a) % p)), decode(x.sqr().toBytes()));
                try std.testing.expectEqual(@as(V, @intCast((@as(W, a) + b) % p)), decode(x.add(&y).toBytes()));
                try std.testing.expectEqual(@as(V, @intCast((@as(W, a) + p - b) % p)), decode(x.sub(&y).toBytes()));
                try std.testing.expectEqual(@as(V, @intCast((p - @as(W, a)) % p)), decode(x.neg().toBytes()));
                try std.testing.expectEqual(a == 0, x.isZero());
                try std.testing.expectEqual(a == b, x.eql(&y));
                if (i % 16 == 0 or pair) {
                    const inverse = x.invert();
                    if (a == 0) {
                        try std.testing.expect(inverse.isZero());
                    } else {
                        try std.testing.expectEqual(@as(V, 1), decode(x.mul(&inverse).toBytes()));
                    }
                }
            }
        }

        fn encodings(comptime F: type) !void {
            try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(p)));
            try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(p + 1)));
            try std.testing.expectError(error.NonCanonical, F.fromBytes(&encode(std.math.maxInt(V))));
            _ = try F.fromBytes(&encode(p - 1));
            try std.testing.expect(F.one.mul(&F.one).eql(&F.one));
            try std.testing.expectEqual(@as(V, 1), decode(F.one.toBytes()));
            try std.testing.expect(F.zero.isZero());
            try std.testing.expect(F.select(0, &F.one, &F.zero).eql(&F.one));
            try std.testing.expect(F.select(std.math.maxInt(u64), &F.one, &F.zero).isZero());
        }

        /// Another backend's limbs equal fiat's, operation by operation: the two hold the same
        /// Montgomery form, so the limbs themselves are compared.
        fn agree(comptime S: type, random: std.Random) !void {
            const e = edges();
            for (0..20000 + e.len * e.len) |i| {
                const pair = i < e.len * e.len;
                const a: V = if (pair) e[i / e.len] else random.int(V) % p;
                const b: V = if (pair) e[i % e.len] else random.int(V) % p;
                const fa = try Fiat.fromBytes(&encode(a));
                const fb = try Fiat.fromBytes(&encode(b));
                const x = try S.fromBytes(&encode(a));
                const y = try S.fromBytes(&encode(b));
                try std.testing.expectEqualSlices(u64, &fa.limbs, &x.limbs);
                try std.testing.expectEqualSlices(u64, &fa.mul(&fb).limbs, &x.mul(&y).limbs);
                try std.testing.expectEqualSlices(u64, &fa.sqr().limbs, &x.sqr().limbs);
                try std.testing.expectEqualSlices(u64, &fa.add(&fb).limbs, &x.add(&y).limbs);
                try std.testing.expectEqualSlices(u64, &fa.sub(&fb).limbs, &x.sub(&y).limbs);
                try std.testing.expectEqualSlices(u64, &fa.neg().limbs, &x.neg().limbs);
                if (i % 16 == 0 or pair) try std.testing.expectEqualSlices(u64, &fa.invert().limbs, &x.invert().limbs);
            }
        }
    };
}

test "P-256 and P-384 fields: fiat-crypto's Zig matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x256f);
    inline for (.{ .p256, .p384 }) |curve| {
        const C = Check(curve);
        try C.againstIntegers(C.Fiat, prng.random());
        try C.encodings(C.Fiat);
    }
}

test "P-256 and P-384 fields: the build's field matches big-integer arithmetic" {
    var prng = std.Random.DefaultPrng.init(0x256e);
    inline for (.{ .p256, .p384 }) |curve| {
        const C = Check(curve);
        try C.againstIntegers(nist.Fe(curve), prng.random());
        try C.encodings(nist.Fe(curve));
    }
}

test "F05 catalogue_kernel_carries_lengths_and_dispatch (P-256 and P-384 fields: s2n-bignum's routines, every variant this processor runs, equal fiat-crypto's limb for limb)" {
    if (!s2n.assembly) return error.SkipZigTest;
    var prng = std.Random.DefaultPrng.init(0x5e2c);
    inline for (.{ .p256, .p384 }) |curve| {
        const C = Check(curve);
        try C.agree(nist.FieldWith(curve, .s2n, .alt), prng.random());
        if (s2n.plainRuns()) try C.agree(nist.FieldWith(curve, .s2n, .plain), prng.random());
    }
}
