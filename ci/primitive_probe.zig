//! Optimized inspection entry points; no secret output is formatted.
const std = @import("std");
const Curve = @import("credentials").Curve;
const curve_inspect = @import("curve_inspect.zig");
comptime {
    _ = curve_inspect;
}
const Samples = struct {
    n: usize = 0,
    mean: f64 = 0,
    m2: f64 = 0,
    fn add(self: *Samples, value: f64) void {
        self.n += 1;
        const delta = value - self.mean;
        self.mean += delta / @as(f64, @floatFromInt(self.n)); // safe: public sample count converted for statistical reporting
        self.m2 += delta * (value - self.mean);
    }
    fn variance(self: Samples) f64 {
        return self.m2 / @as(f64, @floatFromInt(self.n - 1)); // safe: public sample count above one converted for statistics
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    var buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    inline for (.{ std.crypto.ecc.P256, std.crypto.ecc.P384, std.crypto.ecc.Edwards25519 }, .{ "P256", "P384", "Edwards" }) |Point, name| {
        var groups: [2]Samples = @splat(.{});
        var scalar: [@sizeOf(Point.scalar.CompressedScalar)]u8 = undefined;
        defer std.crypto.secureZero(u8, &scalar);
        for (0..24000) |_| {
            var random: [scalar.len + 1]u8 = undefined;
            defer std.crypto.secureZero(u8, &random);
            try init.io.randomSecure(&random);
            const class: usize = random[0] & 1;
            if (class == 0) {
                @memset(&scalar, 0);
                scalar[scalar.len - 1] = 1;
            } else @memcpy(&scalar, random[1..]);
            const start = std.Io.Clock.awake.now(init.io).nanoseconds;
            var point = try Curve.base(Point, if (Point == std.crypto.ecc.Edwards25519) .little else .big, &scalar);
            const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
            std.mem.doNotOptimizeAway(&point);
            std.crypto.secureZero(u8, std.mem.asBytes(&point));
            groups[class].add(@floatFromInt(elapsed)); // safe: public elapsed time becomes approximate statistics
        }
        const a = groups[0];
        const b = groups[1];
        const t = (a.mean - b.mean) / @sqrt(a.variance() / @as(f64, @floatFromInt(a.n)) + b.variance() / @as(f64, @floatFromInt(b.n))); // safe: public counts converted for Welch reporting
        try out.interface.print("{s}: n0={d} n1={d} mean0_ns={d:.3} mean1_ns={d:.3} variance0={d:.3} variance1={d:.3} welch_t={d:.3}\n", .{ name, a.n, b.n, a.mean, b.mean, a.variance(), b.variance(), t });
        try out.interface.flush();
    }
}
