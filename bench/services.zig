//! Short service admission and offline key-buffer ownership hot paths.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const Context = struct {
    gpa: std.mem.Allocator,
    budget: cloak.services.Budget = .{},
    fn admission(c: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            try c.budget.reserve(1024);
            c.budget.release(1024);
        }
        if (c.budget.counts().bytes != 0) return error.LeakedCharge;
    }
    fn encrypted(c: *Context, units: u64) !void {
        @setRuntimeSafety(true);
        for (0..units) |_| {
            const key = try cloak.PrivateKey.parse(c.gpa, @embedFile("data/p256.legacy-aes128.pem"), .{ .passphrase = "correct-horse" });
            key.deinit();
        }
    }
};
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    var c: Context = .{ .gpa = init.gpa };
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    try shakedown.bench.run(init.gpa, init.io, &out.interface, &c, &.{
        .{ .name = "service reserve/release", .unit = "charge", .run = Context.admission },
        .{ .name = "P-256 legacy buffer parse/release", .unit = "key", .run = Context.encrypted },
    }, .{ .commit = "unrecorded" }, .{ .samples = 9, .smoke = smoke });
    try out.interface.flush();
}
