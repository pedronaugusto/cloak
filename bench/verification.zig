//! Authenticated explicit-root verification and native-policy setup rows.
const std = @import("std");
const builtin = @import("builtin");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const Context = struct {
    gpa: std.mem.Allocator,
    request: cloak.types.Request,
    fn portable(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            var receipt = try cloak.verify.verify(context.gpa, context.request, &.{@embedFile("data/anchor.der")});
            defer receipt.deinit();
            try receipt.check(context.request);
        }
    }
    fn native(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        var budget: cloak.services.Budget = .{};
        for (0..units) |_| {
            const job = try cloak.NativeVerification.init(context.gpa, &budget, context.request, .{ .anchors = &.{@embedFile("data/anchor.der")} });
            defer job.deinit();
            var receipt = try job.take(context.gpa, context.request, context.request.time);
            defer receipt.deinit();
            try receipt.check(context.request);
        }
        if (budget.counts().jobs != 0 or budget.counts().bytes != 0) return error.UnreapedJob;
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    var context: Context = .{ .gpa = init.gpa, .request = .{ .chain = &.{@embedFile("data/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("data/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) } };
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    try shakedown.bench.run(@typeInfo(@typeInfo(@TypeOf(Context.portable)).@"fn".return_type.?).error_union.error_set || @typeInfo(@typeInfo(@TypeOf(Context.native)).@"fn".return_type.?).error_union.error_set, init.gpa, init.io, &out.interface, &context, &.{.{ .name = "P-256 two-certificate portable path/receipt", .unit = "verification", .initial = 500, .run = Context.portable }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    if (builtin.os.tag == .macos or builtin.os.tag == .windows) {
        try shakedown.bench.run(@typeInfo(@typeInfo(@TypeOf(Context.native)).@"fn".return_type.?).error_union.error_set, init.gpa, init.io, &out.interface, &context, &.{.{ .name = "native scoped policy plus portable floors/receipt", .unit = "verification", .initial = 20, .run = Context.native }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    }
    try out.interface.flush();
}
