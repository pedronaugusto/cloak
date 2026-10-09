//! Immutable trust publication and shared-reference costs.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const Context = struct {
    trust: *cloak.Trust,
    fn publish(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            const snapshot = try context.trust.freeze();
            defer snapshot.deinit();
            const held = snapshot.retain();
            defer held.deinit();
            std.mem.doNotOptimizeAway(held.generation());
        }
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    var trust = cloak.Trust.init(init.gpa);
    defer trust.deinit();
    // Isolate publication of a native-policy marker from native OS evaluation.
    trust.system = .macos;
    var context: Context = .{ .trust = &trust };
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    try shakedown.bench.run(@typeInfo(@typeInfo(@TypeOf(Context.publish)).@"fn".return_type.?).error_union.error_set, init.gpa, init.io, &out.interface, &context, &.{.{ .name = "trust publish/retain/release", .unit = "snapshot", .run = Context.publish }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    try out.interface.flush();
}
