//! Negative consumer compilation must fail at the private-kernel policy guard.
const std = @import("std");
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.ZigExecutableRequired;
    const result = try std.process.run(init.gpa, init.io, .{ .argv = &.{ args[1], "build-exe", "--dep", "cloak", "-Mroot=ci/weak_options.zig", "--dep", "aegis", "-Mcloak=src/root.zig", "-Maegis=zig-pkg/aegis-0.0.0-rsxouqqVAQB8lG0Hvuq-66KIDi_j3LOazxoGwg0_JwHo/src/root.zig", "-fno-emit-bin", "--cache-dir", ".zig-cache/options", "--global-cache-dir", ".zig-cache/global" }, .stdout_limit = .limited(4096), .stderr_limit = .limited(16384) });
    defer init.gpa.free(result.stdout);
    defer init.gpa.free(result.stderr);
    if (result.term != .exited or result.term.exited == 0) return error.WeakOptionsAccepted;
    if (std.mem.find(u8, result.stderr, "cloak private-key construction requires std side-channel mitigations") == null) return error.UnexpectedCompilationFailure;
}
