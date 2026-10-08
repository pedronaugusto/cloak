//! Cold owned-key preparation, separate from warm retained-identity use.
const std = @import("std");
const cloak = @import("cloak");
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const io = init.io;
    var buffer: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(io, &buffer);
    for ([_][]const u8{ @embedFile("data/ed25519.pem"), @embedFile("data/p256.pem"), @embedFile("data/p384.pem"), @embedFile("data/rsa.pem") }, [_][]const u8{ "Ed25519", "P-256", "P-384", "RSA-2048" }) |pem, name| {
        const rounds: usize = if (smoke) 1 else if (std.mem.eql(u8, name, "RSA-2048")) 3 else 5000;
        const options: cloak.PrivateKey.ParseOptions = .{ .entropy = @import("cloak").PrivateKey.Entropy.fromIo(&io) };
        const start = std.Io.Clock.awake.now(io).nanoseconds;
        for (0..rounds) |_| {
            const key = try cloak.PrivateKey.parse(init.gpa, pem, options);
            key.deinit();
        }
        const elapsed = std.Io.Clock.awake.now(io).nanoseconds - start;
        try out.interface.print("{s} owned key parse/validate/release: {d:.3} us/op ({d} rounds)\n", .{ name, @as(f64, @floatFromInt(elapsed)) / @as(f64, @floatFromInt(rounds)) / 1000, rounds }); // safe: public time and counts become approximate f64 statistics only
    }
    try out.interface.flush();
}
