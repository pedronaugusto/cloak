//! Client handshake CPU: the time spent inside the client connection's calls, with entropy,
//! the portable path verifier and signatures included and the scripted peer's own work
//! excluded. Measurements run by hand in ReleaseFast; CI only compiles this.
const std = @import("std");
const harness = @import("harness");
const Pair = harness.Pair.Pair;

const Scenario = struct { name: []const u8, config: harness.Peer.Config, options: harness.Pair.Options };

fn measure(comptime suite: harness.Suite, scenario: Scenario, init: std.process.Init, writer: *std.Io.Writer, samples: usize) !void {
    const gpa = std.heap.smp_allocator;
    const times = try gpa.alloc(u64, samples);
    defer gpa.free(times);
    for (times) |*slot| {
        const pair = try Pair(suite).init(gpa, scenario.config, scenario.options);
        defer pair.deinit();
        pair.clock = init.io;
        try pair.handshake();
        slot.* = pair.client_ns;
    }
    std.mem.sort(u64, times, {}, std.sort.asc(u64));
    const median = times[times.len / 2];
    try writer.print("{s} {s}: min={d}us median={d}us p95={d}us handshakes/s/core={d}\n", .{
        @tagName(suite),
        scenario.name,
        times[0] / 1000,
        median / 1000,
        times[times.len * 95 / 100] / 1000,
        1_000_000_000 / @max(median, 1),
    });
}

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    const smoke = args.len == 2 and std.mem.eql(u8, args[1], "--smoke");
    const samples: usize = if (smoke) 4 else 400;
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    const scenarios = [_]Scenario{
        .{ .name = "x25519 P-256 chain verified", .config = .{ .group = .x25519 }, .options = .{} },
        .{ .name = "hybrid ML-KEM P-256 chain verified", .config = .{ .group = .x25519_mlkem768 }, .options = .{} },
        .{ .name = "P-256 after retry P-256 chain verified", .config = .{ .group = .p256, .retry = .p256 }, .options = .{} },
        .{ .name = "x25519 Ed25519 chain verified", .config = .{ .group = .x25519, .cert = .ed25519 }, .options = .{} },
        .{ .name = "x25519 P-384 chain verified", .config = .{ .group = .x25519, .cert = .p384 }, .options = .{} },
        .{ .name = "x25519 no verification", .config = .{ .group = .x25519 }, .options = .{ .verify_none = true, .identity = .none } },
    };
    inline for (.{ harness.Suite.aes_128_gcm_sha256, harness.Suite.chacha20_poly1305_sha256 }) |suite| {
        for (scenarios) |scenario| try measure(suite, scenario, init, &out.interface, samples);
    }
    try out.interface.flush();
}
