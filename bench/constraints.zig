//! Same public verification workloads for interleaved checkpoint/candidate timing.
const std = @import("std");
const cloak = @import("cloak");
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    var output: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &output);
    const small_leaf = @embedFile("data/work-leaf-1.der");
    const issuer = @embedFile("data/work-inter-1.der");
    const root = @embedFile("data/work-root.der");
    const request: cloak.types.Request = .{ .chain = &.{ small_leaf, issuer }, .identity = .{ .dns = "review.example" }, .time = 1791467000, .trust_generation = 1, .policy_generation = 1 };
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const rounds: usize = if (args.len == 2 and std.mem.eql(u8, args[1], "--smoke")) 1 else 1000;
    const start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (0..rounds) |_| {
        var receipt = try cloak.verify.verify(init.gpa, request, &.{root});
        defer receipt.deinit();
        try receipt.check(request);
    }
    const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
    try out.interface.print("signed constraint path: {d:.3} us/op\n", .{@as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(rounds)) / 1000}); // safe: public elapsed time is converted to approximate statistics
    try out.interface.flush();
}
