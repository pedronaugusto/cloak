//! Private-scalar ECDH on P-256 and P-384 and signing with a private key: the masked
//! fixed-window walk against std's multiplication of a secret scalar. Measurements run by hand
//! in ReleaseFast.
const std = @import("std");
const cloak = @import("cloak");
const ecdh = cloak.certificates.ecdh;

fn time(io: std.Io, comptime body: anytype, args: anytype, iterations: usize) u64 {
    const start = std.Io.Clock.awake.now(io).nanoseconds;
    for (0..iterations) |_| @call(.auto, body, args);
    // safe: elapsed monotonic nanoseconds are positive and far below 2^64.
    return @intCast(@divTrunc(std.Io.Clock.awake.now(io).nanoseconds - start, @as(i96, @intCast(iterations))));
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const iterations: usize = if (smoke) 4 else 2000;
    var buffer: [2048]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    inline for (.{ .{ "P-256", ecdh.P256, std.crypto.ecc.P256 }, .{ "P-384", ecdh.P384, std.crypto.ecc.P384 } }) |entry| {
        const group = entry[1];
        const curve = entry[2];
        var a: [group.scalar_length]u8 = undefined;
        var b: [group.scalar_length]u8 = undefined;
        init.io.random(&a);
        init.io.random(&b);
        a[0] &= 0x7f;
        b[0] &= 0x7f;
        var a_public: [group.public_length]u8 = undefined;
        var b_public: [group.public_length]u8 = undefined;
        try group.publicKey(&a, &a_public);
        try group.publicKey(&b, &b_public);
        var shared: [group.scalar_length]u8 = undefined;
        const peer = try curve.fromSec1(&b_public);
        const Cloak = struct {
            fn publicKey(scalar: *const [group.scalar_length]u8, public: *[group.public_length]u8) void {
                group.publicKey(scalar, public) catch unreachable; // unreachable: the benchmark's scalar is in range
                std.mem.doNotOptimizeAway(public);
            }
            fn agree(scalar: *const [group.scalar_length]u8, public: []const u8, secret: *[group.scalar_length]u8) void {
                group.agree(scalar, public, secret) catch unreachable; // unreachable: the benchmark's peer key is valid
                std.mem.doNotOptimizeAway(secret);
            }
        };
        const Std = struct {
            fn base(scalar: [group.scalar_length]u8) void {
                const point = curve.basePoint.mul(scalar, .big) catch unreachable; // unreachable: in range
                std.mem.doNotOptimizeAway(&point);
            }
            fn mul(point: curve, scalar: [group.scalar_length]u8) void {
                const product = point.mul(scalar, .big) catch unreachable; // unreachable: in range
                std.mem.doNotOptimizeAway(&product);
            }
        };
        const cloak_base = time(init.io, Cloak.publicKey, .{ &a, &a_public }, iterations);
        const cloak_agree = time(init.io, Cloak.agree, .{ &a, &b_public, &shared }, iterations);
        const std_base = time(init.io, Std.base, .{a}, iterations);
        const std_mul = time(init.io, Std.mul, .{ peer, a }, iterations);
        try out.interface.print("{s}: cloak keygen={d}ns agree={d}ns | std basePoint.mul={d}ns point.mul={d}ns\n", .{ entry[0], cloak_base, cloak_agree, std_base, std_mul });
    }
    try signing(init, &out.interface, iterations);
    try out.interface.flush();
}

/// A TLS CertificateVerify signature: cloak's `PrivateKey.sign` (hedged nonce, masked secret
/// multiplication) against std's `KeyPair.sign` with noise.
fn signing(init: std.process.Init, out: *std.Io.Writer, iterations: usize) !void {
    const message = "TLS 1.3, server CertificateVerify                    0123456789abcdef0123456789abcdef";
    var noise: [cloak.PrivateKey.max_noise]u8 = undefined;
    init.io.random(&noise);
    inline for (.{
        .{ "P-256", @embedFile("data/p256.pem"), std.crypto.sign.ecdsa.EcdsaP256Sha256, cloak.certificates.certificate.Algorithm.Signature{ .ecdsa = .sha256 } },
        .{ "P-384", @embedFile("data/p384.pem"), std.crypto.sign.ecdsa.EcdsaP384Sha384, cloak.certificates.certificate.Algorithm.Signature{ .ecdsa = .sha384 } },
    }) |entry| {
        const Ecdsa = entry[2];
        const key = try cloak.PrivateKey.parse(init.gpa, entry[1], .{});
        defer key.deinit();
        const pair = Ecdsa.KeyPair.generate(init.io);
        const Run = struct {
            fn cloakSign(k: cloak.PrivateKey, n: []const u8) void {
                var buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
                const signature = k.sign(entry[3], message, n, &buffer) catch unreachable; // unreachable: the key and algorithm agree
                std.mem.doNotOptimizeAway(signature);
            }
            fn stdSign(p: Ecdsa.KeyPair, n: [Ecdsa.noise_length]u8) void {
                const signature = p.sign(message, n) catch unreachable; // unreachable: any noise signs
                std.mem.doNotOptimizeAway(&signature);
            }
        };
        const ours = time(init.io, Run.cloakSign, .{ key, noise[0..Ecdsa.noise_length] }, iterations);
        const theirs = time(init.io, Run.stdSign, .{ pair, noise[0..Ecdsa.noise_length].* }, iterations);
        try out.print("{s} sign: cloak={d}ns | std={d}ns\n", .{ entry[0], ours, theirs });
    }
    const Ed = std.crypto.sign.Ed25519;
    const key = try cloak.PrivateKey.parse(init.gpa, @embedFile("data/ed25519.pem"), .{});
    defer key.deinit();
    const pair = Ed.KeyPair.generate(init.io);
    const Run = struct {
        fn cloakSign(k: cloak.PrivateKey) void {
            var buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
            const signature = k.sign(.ed25519, message, "", &buffer) catch unreachable; // unreachable: the key and algorithm agree
            std.mem.doNotOptimizeAway(signature);
        }
        fn stdSign(p: Ed.KeyPair) void {
            const signature = p.sign(message, null) catch unreachable; // unreachable: the key pair is consistent
            std.mem.doNotOptimizeAway(&signature);
        }
    };
    const ours = time(init.io, Run.cloakSign, .{key}, iterations);
    const theirs = time(init.io, Run.stdSign, .{pair}, iterations);
    try out.print("Ed25519 sign: cloak={d}ns | std={d}ns\n", .{ ours, theirs });
}
