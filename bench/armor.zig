//! Cold textual-armor ownership, with output checked against a public fixture.
const std = @import("std");
const shakedown = @import("shakedown");
const Pem = @import("armor");
const Context = struct {
    gpa: std.mem.Allocator,
    expected: [32]u8,
    fn parse(context: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            var pem = Pem.init(@embedFile("data/p256.pem"));
            var block = (try pem.next(context.gpa, 65536)) orelse return error.MissingBlock;
            defer block.deinit(context.gpa);
            var digest: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(block.der, &digest, .{});
            if (!std.mem.eql(u8, &digest, &context.expected)) return error.WrongDecodedFixture;
            if (try pem.next(context.gpa, 65536)) |value| {
                var extra = value;
                defer extra.deinit(context.gpa);
                return error.ExtraBlock;
            }
        }
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    if (args.len != 1 and !smoke and args.len != 3) return error.InvalidArguments;
    var context: Context = .{ .gpa = init.gpa, .expected = undefined };
    _ = try std.fmt.hexToBytes(&context.expected, "a4f2fd268a5524d87c8ae647afd03db038457d7a3e383ca57e3996709b4c15a6");
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    try shakedown.bench.run(init.gpa, init.io, &out.interface, &context, &.{.{ .name = "P-256 armor parse/check/release", .unit = "block", .run = Context.parse }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 9 });
    try out.interface.flush();
}
