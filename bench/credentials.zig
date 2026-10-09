//! Cold owned-key preparation, separate from warm retained-identity use.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const Context = struct {
    gpa: std.mem.Allocator,
    pem: []const u8,
    options: cloak.PrivateKey.ParseOptions,
    fn parse(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            const key = try cloak.PrivateKey.parse(context.gpa, context.pem, context.options);
            key.deinit();
        }
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    const io = init.io;
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &buffer);
    for ([_][]const u8{ @embedFile("data/ed25519.pem"), @embedFile("data/p256.pem"), @embedFile("data/p384.pem"), @embedFile("data/rsa.pem") }, [_][]const u8{ "Ed25519", "P-256", "P-384", "RSA-2048" }) |pem, name| {
        var context: Context = .{ .gpa = init.gpa, .pem = pem, .options = .{ .entropy = cloak.PrivateKey.Entropy.fromIo(&io) } };
        const row = try init.arena.allocator().print("{s} owned key parse/validate/release", .{name});
        try shakedown.bench.run(@typeInfo(@typeInfo(@TypeOf(Context.parse)).@"fn".return_type.?).error_union.error_set, init.gpa, io, &out.interface, &context, &.{.{ .name = row, .unit = "key", .run = Context.parse }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    }
    try out.interface.flush();
}
