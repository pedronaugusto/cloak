//! Handshake CPU of each role: the time spent inside one connection's calls, with entropy, the
//! portable path verifier and signatures included and the scripted peer's own work excluded. Measurements run by hand in ReleaseFast; CI only compiles this.
const std = @import("std");
const harness = @import("harness");
const Pair = harness.Pair.Pair;
const ServerPair = harness.ServerPair.ServerPair;

const Scenario = struct { name: []const u8, config: harness.Peer.Config, options: harness.Pair.Options };

fn measure(comptime suite: harness.Suite13, scenario: Scenario, init: std.process.Init, writer: *std.Io.Writer, samples: usize) !void {
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

const ServerScenario = struct { name: []const u8, config: harness.ClientPeer.Config, options: harness.ServerPair.Options };

fn measureServer(comptime suite: harness.Suite13, scenario: ServerScenario, init: std.process.Init, writer: *std.Io.Writer, samples: usize) !void {
    const gpa = std.heap.smp_allocator;
    const times = try gpa.alloc(u64, samples);
    defer gpa.free(times);
    for (times) |*slot| {
        const pair = try ServerPair(suite).init(gpa, scenario.config, scenario.options);
        defer pair.deinit();
        pair.clock = init.io;
        try pair.run();
        slot.* = pair.server_ns;
    }
    std.mem.sort(u64, times, {}, std.sort.asc(u64));
    const median = times[times.len / 2];
    try writer.print("server {s} {s}: min={d}us median={d}us p95={d}us handshakes/s/core={d}\n", .{
        @tagName(suite),
        scenario.name,
        times[0] / 1000,
        median / 1000,
        times[times.len * 95 / 100] / 1000,
        1_000_000_000 / @max(median, 1),
    });
}

/// Both cloak ends in memory: one full handshake, or one resumed from the previous connection's
/// ticket (TLS 1.3 PSK-DHE, or a TLS 1.2 abbreviated handshake), timed together, client and server.
fn measureResumption(name: []const u8, tls12: bool, resumed: bool, init: std.process.Init, writer: *std.Io.Writer, samples: usize) !void {
    const gpa = std.heap.smp_allocator;
    const cloak = harness.cloak;
    const times = try gpa.alloc(u64, samples);
    defer gpa.free(times);
    var cache = try cloak.tls.SessionCache.init(gpa, .{});
    defer cache.deinit();
    var keys = try cloak.tls.TicketKeys.init(gpa, .{});
    defer keys.deinit();
    try keys.rotate(&@as([32]u8, @splat(0x5e)), .fromNanoseconds(@as(i96, harness.Peer.pki.time) * std.time.ns_per_s));
    for (times, 0..) |*slot, i| {
        var options: harness.Duo.Options = .{ .seed = i + 1, .cache = &cache, .tickets = &keys };
        if (tls12) {
            options.client_max = .tls12;
            options.client_tls12_tickets = true;
            options.server_tls12_tickets = true;
        }
        if (resumed) {
            const first = try harness.Duo.init(gpa, options);
            defer first.deinit();
            try first.handshake();
        } else cache.clear();
        options.seed = i + 1_000_000;
        const duo = try harness.Duo.init(gpa, options);
        defer duo.deinit();
        const start = std.Io.Clock.awake.now(init.io).nanoseconds;
        try duo.handshake();
        // Monotonic nanoseconds only grow.
        slot.* = @intCast(std.Io.Clock.awake.now(init.io).nanoseconds - start);
        if (duo.client.info().?.resumed != resumed) return error.UnexpectedResumption;
    }
    std.mem.sort(u64, times, {}, std.sort.asc(u64));
    const median = times[times.len / 2];
    try writer.print("both ends {s}: min={d}us median={d}us p95={d}us\n", .{ name, times[0] / 1000, median / 1000, times[times.len * 95 / 100] / 1000 });
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
    inline for (.{ harness.Suite13.aes_128_gcm_sha256, harness.Suite13.chacha20_poly1305_sha256 }) |suite| {
        for (scenarios) |scenario| try measure(suite, scenario, init, &out.interface, samples);
    }
    const server_scenarios = [_]ServerScenario{
        .{ .name = "x25519 P-256 certificate", .config = .{ .shares = &.{.x25519} }, .options = .{} },
        .{ .name = "hybrid ML-KEM P-256 certificate", .config = .{}, .options = .{} },
        .{ .name = "P-256 after retry", .config = .{ .shares = &.{.x25519}, .groups = &.{ .x25519, .p256 } }, .options = .{ .groups = &.{.p256} } },
        .{ .name = "x25519 Ed25519 certificate", .config = .{ .shares = &.{.x25519}, .schemes = &.{0x0807} }, .options = .{ .cert = .ed25519 } },
        .{ .name = "x25519 client certificate", .config = .{ .shares = &.{.x25519}, .client_cert = true }, .options = .{ .client_auth = .required } },
    };
    inline for (.{ harness.Suite13.aes_128_gcm_sha256, harness.Suite13.chacha20_poly1305_sha256 }) |suite| {
        for (server_scenarios) |scenario| try measureServer(suite, scenario, init, &out.interface, samples);
    }
    try measureResumption("TLS 1.3 full, hybrid ML-KEM, P-256 chain verified", false, false, init, &out.interface, samples);
    try measureResumption("TLS 1.3 resumed, hybrid ML-KEM", false, true, init, &out.interface, samples);
    try measureResumption("TLS 1.2 full, X25519, P-256 chain verified", true, false, init, &out.interface, samples);
    try measureResumption("TLS 1.2 resumed (abbreviated)", true, true, init, &out.interface, samples);
    try out.interface.flush();
}
