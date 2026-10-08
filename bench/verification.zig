//! Authenticated explicit-root verification and native-policy setup rows.
const std = @import("std");
const builtin = @import("builtin");
const cloak = @import("cloak");
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const rounds: usize = if (smoke) 1 else 500;
    const request: cloak.types.Request = .{ .chain = &.{@embedFile("data/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("data/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    const anchors = &.{@embedFile("data/anchor.der")};
    var buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const start = std.Io.Clock.awake.now(init.io).nanoseconds;
    for (0..rounds) |_| {
        var receipt = try cloak.verify.verify(init.gpa, request, anchors);
        try receipt.check(request);
        receipt.deinit();
    }
    const elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - start;
    try out.interface.print("P-256 two-certificate portable path/receipt: {d:.3} us/op ({d} rounds)\n", .{ @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(rounds)) / 1000, rounds }); // safe: public time and counts become approximate f64 statistics only
    if (builtin.os.tag == .macos or builtin.os.tag == .windows) {
        var budget: cloak.services.Budget = .{};
        const native_rounds: usize = if (smoke) 1 else 20;
        const native_start = std.Io.Clock.awake.now(init.io).nanoseconds;
        for (0..native_rounds) |_| {
            const job = try cloak.NativeVerification.init(init.gpa, &budget, request, .{ .anchors = anchors });
            defer job.deinit();
            var receipt = try job.take(init.gpa, request, request.time);
            receipt.deinit();
        }
        const native_elapsed = std.Io.Clock.awake.now(init.io).nanoseconds - native_start;
        try out.interface.print("native scoped policy plus portable floors/receipt: {d:.3} us/op ({d} rounds)\n", .{ @as(f64, @floatFromInt(native_elapsed)) / @as(f64, @floatFromInt(native_rounds)) / 1000, native_rounds }); // safe: public time and counts become approximate f64 statistics only
    }
    try out.interface.flush();
}
