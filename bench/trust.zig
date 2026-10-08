//! Immutable trust publication and shared-reference costs, ReleaseFast.
const std = @import("std");
const cloak = @import("cloak");

pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const rounds: usize = if (smoke) 1 else 100_000;
    var trust = cloak.Trust.init(init.gpa);
    defer trust.deinit();
    // The publication row isolates the shared owner from native OS evaluation.
    trust.system = .macos;
    var buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (0..rounds) |_| {
        const snapshot = try trust.freeze();
        const held = snapshot.retain();
        std.mem.doNotOptimizeAway(held.generation());
        held.deinit();
        snapshot.deinit();
    }
    const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
    try out.interface.print("trust publish/retain/release: {d:.3} ns/op ({d} rounds)\n", .{ @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(rounds)), rounds }); // safe: public time and counts become approximate f64 statistics only
    try out.interface.flush();
}
