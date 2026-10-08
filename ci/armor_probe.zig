//! Inspection entry point: no secret output formatting and no runtime facade.
const std = @import("std");
const Inspection = @import("armor_inspect.zig");
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
    var groups: [2]Samples = @splat(.{});
    var bytes: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &bytes);
    var text: [1368]u8 = undefined;
    defer std.crypto.secureZero(u8, &text);
    var output: [1024]u8 = undefined;
    defer std.crypto.secureZero(u8, &output);
    for (0..24000) |_| {
        var random: [1025]u8 = undefined;
        defer std.crypto.secureZero(u8, &random);
        try init.io.randomSecure(&random);
        const class: usize = random[0] & 1;
        if (class == 0) @memset(&bytes, 0) else @memcpy(&bytes, random[1..]);
        const encoded = std.base64.standard.Encoder.encode(&text, &bytes);
        const start = std.Io.Clock.awake.now(init.io).nanoseconds;
        const status = @call(.never_inline, Inspection.cloakArmor, .{ &output, output.len, encoded.ptr, encoded.len });
        const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
        if (status != 0 or !std.crypto.timing_safe.eql([1024]u8, output, bytes)) return error.DecoderMismatch;
        groups[class].add(@floatFromInt(elapsed)); // safe: elapsed public time becomes approximate statistics
    }
    const a = groups[0];
    const b = groups[1];
    const t = (a.mean - b.mean) / @sqrt(a.variance() / @as(f64, @floatFromInt(a.n)) + b.variance() / @as(f64, @floatFromInt(b.n))); // safe: public sample counts converted for Welch reporting
    var buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    try out.interface.print("armor: n0={d} n1={d} mean0_ns={d:.3} mean1_ns={d:.3} variance0={d:.3} variance1={d:.3} welch_t={d:.3}\n", .{ a.n, b.n, a.mean, b.mean, a.variance(), b.variance(), t });
    try out.interface.flush();
}
