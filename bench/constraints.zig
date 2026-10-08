//! Signed public constraint-path workload with request-bound receipt checks.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const Context = struct {
    gpa: std.mem.Allocator,
    request: cloak.types.Request,
    fn verify(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            var receipt = try cloak.verify.verify(context.gpa, context.request, &.{@embedFile("data/work-root.der")});
            defer receipt.deinit();
            try receipt.check(context.request);
        }
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    var context: Context = .{ .gpa = init.gpa, .request = .{ .chain = &.{ @embedFile("data/work-leaf-1.der"), @embedFile("data/work-inter-1.der") }, .identity = .{ .dns = "review.example" }, .time = 1791467000, .trust_generation = 1, .policy_generation = 1 } };
    var output: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &output);
    try shakedown.bench.run(init.gpa, init.io, &out.interface, &context, &.{.{ .name = "signed constraint path", .unit = "verification", .initial = 1000, .run = Context.verify }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    try out.interface.flush();
}
