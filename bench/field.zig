//! The P-256, P-384 and P-521 fields behind their seam, each backend this build has: s2n-bignum's
//! assembly (the plain routines and, for multiplication and squaring, the `_alt` ones) and
//! fiat-crypto's Zig. Multiplication, squaring and inversion as dependent chains, and a
//! walk-shaped loop: a window per five scalar bits (P-256 52, P-384 77, P-521 105), each of six
//! Jacobian doublings (dbl-2001-b, a = -3) and one addition (add-2007-bl), the field work of a
//! five-bit variable-point multiplication without its table scans. The rival harnesses (trials,
//! cloak/field) run the same chains and formulas. ReleaseFast, by hand.
const std = @import("std");
const builtin = @import("builtin");
const harness = @import("harness");
const p521 = harness.p521_field;
const nist = harness.nist_field;
const s2n = harness.s2n;

fn now(io: std.Io) i96 {
    return std.Io.Clock.awake.now(io).nanoseconds;
}

/// Nanoseconds per call of `body`, the best of five runs of `iterations` calls.
fn best(io: std.Io, comptime body: anytype, args: anytype, iterations: usize) f64 {
    var fastest: f64 = std.math.inf(f64);
    for (0..5) |_| {
        const start = now(io);
        for (0..iterations) |_| @call(.auto, body, args);
        // safe: elapsed monotonic nanoseconds are positive and far below 2^53.
        const elapsed: f64 = @floatFromInt(now(io) - start);
        fastest = @min(fastest, elapsed / @as(f64, @floatFromInt(iterations)));
    }
    return fastest;
}

fn Chains(comptime F: type, comptime windows: usize) type {
    return struct {
        const Point = struct { x: F, y: F, z: F };

        fn mul(a: *F, b: *const F) void {
            a.* = a.mul(b);
            std.mem.doNotOptimizeAway(a);
        }
        fn sqr(a: *F) void {
            a.* = a.sqr();
            std.mem.doNotOptimizeAway(a);
        }
        fn invert(a: *F) void {
            a.* = a.invert();
            std.mem.doNotOptimizeAway(a);
        }

        fn dbl(p: *Point) void {
            const delta = p.z.sqr();
            const gamma = p.y.sqr();
            const beta = p.x.mul(&gamma);
            const t = p.x.sub(&delta).mul(&p.x.add(&delta));
            const alpha = t.dbl().add(&t);
            const beta4 = beta.dbl().dbl();
            const x3 = alpha.sqr().sub(&beta4.dbl());
            const z3 = p.y.add(&p.z).sqr().sub(&gamma).sub(&delta);
            const y3 = alpha.mul(&beta4.sub(&x3)).sub(&gamma.sqr().dbl().dbl().dbl());
            p.* = .{ .x = x3, .y = y3, .z = z3 };
        }

        fn add(p: *Point, q: *const Point) void {
            const z1z1 = p.z.sqr();
            const z2z2 = q.z.sqr();
            const x1z = p.x.mul(&z2z2);
            const x2z = q.x.mul(&z1z1);
            const s1 = p.y.mul(&q.z).mul(&z2z2);
            const s2 = q.y.mul(&p.z).mul(&z1z1);
            const h = x2z.sub(&x1z);
            const i = h.dbl().sqr();
            const j = h.mul(&i);
            const r = s2.sub(&s1).dbl();
            const v = x1z.mul(&i);
            const x3 = r.sqr().sub(&j).sub(&v.dbl());
            const y3 = r.mul(&v.sub(&x3)).sub(&s1.mul(&j).dbl());
            const z3 = p.z.add(&q.z).sqr().sub(&z1z1).sub(&z2z2).mul(&h);
            p.* = .{ .x = x3, .y = y3, .z = z3 };
        }

        fn walk(p: *Point, q: *const Point) void {
            for (0..windows) |_| {
                inline for (0..6) |_| dbl(p);
                add(p, q);
            }
            std.mem.doNotOptimizeAway(p);
        }
    };
}

fn element(comptime F: type, seed: u8) !F {
    var bytes: [F.encoded_length]u8 = undefined;
    for (&bytes, 0..) |*b, i| b.* = @truncate(i *% 37 +% seed); // safe: any byte will do
    bytes[0] = 1;
    return F.fromBytes(&bytes);
}

fn row(out: *std.Io.Writer, curve: []const u8, backend: []const u8, operation: []const u8, ns: f64) !void {
    try out.print("{{\"date\":\"2026-10-25\",\"arch\":\"{s}\",\"curve\":\"{s}\",\"backend\":\"{s}\",\"operation\":\"{s}\",\"ns\":{d:.1}}}\n", .{ @tagName(builtin.cpu.arch), curve, backend, operation, ns });
}

fn measure(comptime F: type, comptime curve: []const u8, comptime windows: usize, out: *std.Io.Writer, io: std.Io, name: []const u8, scale: usize) !void {
    const C = Chains(F, windows);
    var a = try element(F, 3);
    const b = try element(F, 7);
    try row(out, curve, name, "mul", best(io, C.mul, .{ &a, &b }, 200_000 / scale));
    try row(out, curve, name, "sqr", best(io, C.sqr, .{&a}, 200_000 / scale));
    try row(out, curve, name, "invert", best(io, C.invert, .{&a}, 2_000 / scale));
    var p: C.Point = .{ .x = a, .y = b, .z = F.one };
    const q: C.Point = .{ .x = b, .y = a, .z = try element(F, 11) };
    try row(out, curve, name, "walk", best(io, C.walk, .{ &p, &q }, 200 / scale));
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const scale: usize = if (smoke) 100 else 1;
    var buffer: [4096]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const out = &stdout.interface;
    const plain = s2n.assembly and s2n.plainRuns();
    inline for (.{ .{ .p256, "P-256", 52 }, .{ .p384, "P-384", 77 } }) |c| {
        try measure(nist.Field(c[0], .fiat), c[1], c[2], out, init.io, "fiat-crypto Zig", scale);
        if (s2n.assembly) {
            if (plain) try measure(nist.FieldWith(c[0], .s2n, .plain), c[1], c[2], out, init.io, "s2n-bignum", scale);
            try measure(nist.FieldWith(c[0], .s2n, .alt), c[1], c[2], out, init.io, "s2n-bignum _alt", scale);
        }
    }
    try measure(p521.Field(.fiat), "P-521", 105, out, init.io, "fiat-crypto Zig", scale);
    if (s2n.assembly) {
        if (plain) try measure(p521.FieldWith(.s2n, .plain), "P-521", 105, out, init.io, "s2n-bignum", scale);
        try measure(p521.FieldWith(.s2n, .alt), "P-521", 105, out, init.io, "s2n-bignum _alt", scale);
    }
    try out.flush();
}
