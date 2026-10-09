//! Runtime stack high-water and allocator-peak probes on a caller-owned POSIX stack.
const std = @import("std");
const cloak = @import("cloak");
const shakedown = @import("shakedown");
const leaf = @embedFile("data/leaf.der");
const anchor = @embedFile("data/anchor.der");
const roots: [4096][]const u8 = @splat(anchor);
const peers: [16][]const u8 = @splat(leaf);
const Issuers = @typeInfo(@typeInfo(@TypeOf(cloak.verify.indexed)).@"fn".param_types[2].?).pointer.child;
const State = struct { profile: usize, peak: usize = 0, live: usize = 0, entry: usize = 0, failed: bool = false };
fn run(raw: ?*anyopaque) callconv(.c) ?*anyopaque {
    @setRuntimeSafety(true);
    const s: *State = @ptrCast(@alignCast(raw.?)); // safe: pthread receives the address of the live aligned State and is joined before it expires
    var marker: u8 = 0;
    std.mem.doNotOptimizeAway(&marker);
    s.entry = @intFromPtr(&marker); // safe: numeric stack address is used only for measurement, never dereferenced through an integer
    var count = shakedown.alloc.Counting.init(std.heap.page_allocator);
    defer {
        s.peak = count.peak_bytes;
        s.live = count.live_bytes;
    }
    const req: cloak.types.Request = .{ .chain = if (s.profile == 0) &.{leaf} else &peers, .identity = .{ .dns = "example.com" }, .time = std.fmt.parseInt(i64, @embedFile("data/time.txt"), 10) catch {
        s.failed = true;
        return null;
    }, .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var receipt = if (s.profile == 0) cloak.verify.verify(count.allocator(), req, &.{anchor}) catch {
        s.failed = true;
        return null;
    } else blk: {
        // Shared root index/storage are charged separately from per-call scratch.
        var index = Issuers.init(std.heap.page_allocator, &roots, .{}) catch {
            s.failed = true;
            return null;
        };
        defer index.deinit();
        break :blk cloak.verify.indexed(count.allocator(), req, &index) catch {
            s.failed = true;
            return null;
        };
    };
    receipt.deinit();
    return null;
}
pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    var output: [1024]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &output);
    for (0..2) |profile| {
        const stack = try std.heap.page_allocator.alloc(u8, 2 * 1024 * 1024);
        defer std.heap.page_allocator.free(stack);
        @memset(stack, 0xa5);
        var attr: std.c.pthread_attr_t = undefined;
        if (std.c.pthread_attr_init(&attr) != .SUCCESS) return error.ThreadAttribute;
        defer _ = std.c.pthread_attr_destroy(&attr);
        if (std.c.pthread_attr_setstack(&attr, stack.ptr, stack.len) != .SUCCESS) return error.ThreadStack;
        var state: State = .{ .profile = profile };
        var thread: std.c.pthread_t = undefined;
        if (std.c.pthread_create(&thread, &attr, run, &state) != .SUCCESS) return error.ThreadStart;
        // A failed join cannot permit the supplied stack/state to be freed while live.
        if (std.c.pthread_join(thread, null) != .SUCCESS) std.process.abort();
        if (state.failed or state.live != 0) return error.ResourceProbe;
        var first: usize = 0;
        while (first < stack.len and stack[first] == 0xa5) : (first += 1) {}
        const touched = stack.len - first;
        const below_entry = state.entry - @intFromPtr(stack.ptr) - first; // safe: joined worker entry and touched bytes lie inside its supplied stack
        try out.interface.print("profile={d} peak_heap={d} live_after={d} total_touched_stack={d} below_entry={d} heap_plus_touched={d}\n", .{ profile, state.peak, state.live, touched, below_entry, state.peak + touched });
    }
    try out.interface.flush();
}
