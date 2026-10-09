//! TLS 1.3 record round trips. Fixed public keys are for measurement only.
const std = @import("std");
const shakedown = @import("shakedown");
const record = @import("records").Epoch;
const Suite = @import("records").Suite;
const WorkError = record.InitError || record.SealError || record.OpenError || error{WrongPlaintext};
fn Context(comptime suite: Suite, comptime size: usize) type {
    return struct {
        const Self = @This();
        tx: record.Epoch(suite) = undefined,
        rx: record.Epoch(suite) = undefined,
        input: [size]u8 = @splat(0x5a),
        wire: [size + 22]u8 = undefined,
        out: [size + 1]u8 = undefined,
        fn setup(self: *Self) WorkError!void {
            self.tx = try record.Epoch(suite).init(@splat(1), @splat(2), .{});
            errdefer self.tx.deinit();
            self.rx = try record.Epoch(suite).init(@splat(1), @splat(2), .{});
        }
        fn teardown(self: *Self) WorkError!void {
            self.tx.deinit();
            self.rx.deinit();
        }
        fn run(self: *Self, units: u64) WorkError!void {
            for (0..units) |_| {
                const plain = try self.rx.open(try self.tx.seal(.application, &self.input, 0, &self.wire), &self.out);
                if (!std.mem.eql(u8, &self.input, plain.bytes)) return error.WrongPlaintext;
            }
            std.mem.doNotOptimizeAway(&self.out);
        }
    };
}
fn measure(comptime suite: Suite, comptime size: usize, init: std.process.Init, writer: *std.Io.Writer, commit: []const u8, smoke: bool) !void {
    var context: Context(suite, size) = .{};
    try shakedown.bench.run(WorkError, init.gpa, init.io, writer, &context, &.{.{
        .name = @tagName(suite) ++ "/" ++ std.fmt.comptimePrint("{d}", .{size}) ++ " seal/open/check",
        .unit = "record-pair",
        .run = Context(suite, size).run,
        .setup = Context(suite, size).setup,
        .teardown = Context(suite, size).teardown,
    }}, .{ .commit = commit }, .{ .smoke = smoke, .samples = 31 });
}
pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const commit = if (args.len == 3 and std.mem.eql(u8, args[1], "--commit")) args[2] else "unrecorded";
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    inline for (std.enums.values(Suite)) |suite| inline for (.{ 64, 1024, 16384 }) |size| try measure(suite, size, init, &out.interface, commit, smoke);
    try out.interface.flush();
}
