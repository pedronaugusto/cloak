const std = @import("std");
const builtin = @import("builtin");
const Job = @import("Job.zig");
const Budget = @import("Budget.zig");
const types = @import("../types.zig");
const shakedown = @import("shakedown");
const Queue = struct {
    held: ?Job = null,
    fn submit(context: *anyopaque, job: Job) Job.SubmitError!void {
        @setRuntimeSafety(true); // Executor context is exactly this queue and remains alive until drain.
        const q: *Queue = @ptrCast(@alignCast(context)); // safe: submit receives the aligned Queue context supplied by this test
        if (q.held != null) return error.ServiceBusy;
        q.held = job;
    }
    fn drain(q: *Queue) void {
        @setRuntimeSafety(true);
        const job = q.held.?;
        q.held = null;
        job.run();
        job.deinit();
    }
};
fn request() types.Request {
    @setRuntimeSafety(true);
    return .{ .chain = &.{"abc"}, .time = 1, .trust_generation = 1, .policy_generation = 1, .token = .{ .generation = 2, .id = 7 } };
}
test "service finite deadline rejects missing executor before copying" {
    @setRuntimeSafety(true);
    var budget: Budget = .{};
    try std.testing.expectError(error.ServiceExecutorRequired, Job.init(std.testing.failing_allocator, &budget, request(), .{ .timeout = .{ .duration = .{ .raw = .fromNanoseconds(1), .clock = .awake } } }));
    try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
}
test "service timeout late completion reaps only executor owned memory" {
    @setRuntimeSafety(true);
    var budget: Budget = .{ .max_jobs = 1 };
    var q: Queue = .{};
    const job = try Job.init(std.testing.allocator, &budget, request(), .{ .executor = .{ .context = &q, .submit = Queue.submit } });
    try std.testing.expectError(error.ServicePending, job.take(request()));
    job.abandon();
    try std.testing.expectError(error.ServiceAbandoned, job.take(request()));
    job.deinit();
    try std.testing.expectEqual(@as(usize, 1), budget.counts().jobs);
    try std.testing.expectError(error.ServiceBusy, Job.init(std.testing.failing_allocator, &budget, request(), .{}));
    q.drain();
    try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
    try std.testing.expectEqual(@as(usize, 0), budget.counts().bytes);
}
test "service queued job every allocation failure without resize" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), allocations, .{});
}
fn allocations(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var budget: Budget = .{};
    defer std.debug.assert(budget.counts().jobs == 0);
    var q: Queue = .{};
    const job = try Job.init(gpa, &budget, request(), .{ .executor = .{ .context = &q, .submit = Queue.submit } });
    job.abandon();
    job.deinit();
    q.drain();
}

test "service public budget arithmetic cannot wrap before admission" {
    @setRuntimeSafety(true);
    var budget: Budget = .{};
    var req = request();
    req.limits.receipt_bytes = std.math.maxInt(usize);
    try std.testing.expectError(error.ServiceLimit, Job.init(std.testing.failing_allocator, &budget, req, .{}));
    try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
}

test "service admission covers owned state and input allocation with a zero receipt limit" {
    @setRuntimeSafety(true);
    var counting = shakedown.alloc.Counting.init(std.testing.allocator);
    var budget: Budget = .{};
    var q: Queue = .{};
    var req = request();
    req.limits.receipt_bytes = 0;
    const job = try Job.init(counting.allocator(), &budget, req, .{ .executor = .{ .context = &q, .submit = Queue.submit } });
    try std.testing.expect(budget.counts().bytes >= counting.peak_bytes);
    job.abandon();
    job.deinit();
    q.drain();
    try std.testing.expectEqual(@as(usize, 0), counting.live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.counts().bytes);
}

// Domain instrumentation: observe the completion guard at the exact path free.
// This is not a generic fault allocator; NoResize owns allocation scheduling.
const Cleanup = struct {
    backing: std.mem.Allocator,
    lock: ?*std.atomic.Value(bool) = null,
    state_allocation: ?[*]u8 = null,
    frees: usize = 0,
    locked_frees: usize = 0,
    abandon_on_alloc: ?Job = null,
    pause: ?*Pause = null,
    fn allocator(self: *Cleanup) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn context(raw: *anyopaque) *Cleanup {
        @setRuntimeSafety(true);
        return @ptrCast(@alignCast(raw)); // safe: allocator context is a live aligned Cleanup owned by this test
    }
    fn alloc(raw: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        @setRuntimeSafety(true);
        const self = context(raw);
        if (self.pause) |pause| {
            self.pause = null;
            pause.entered.set(pause.io);
            pause.proceed.wait(pause.io) catch return null;
        }
        if (self.abandon_on_alloc) |job| {
            self.abandon_on_alloc = null;
            job.abandon();
        }
        return self.backing.rawAlloc(len, alignment, ret);
    }
    fn resize(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
        @setRuntimeSafety(true);
        return context(raw).backing.rawResize(bytes, alignment, len, ret);
    }
    fn remap(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
        @setRuntimeSafety(true);
        return context(raw).backing.rawRemap(bytes, alignment, len, ret);
    }
    fn free(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
        @setRuntimeSafety(true);
        const self = context(raw);
        // Allocator.destroy poisons State before rawFree in safe builds. Stop
        // observing its guard at that boundary rather than reading dead state.
        if (self.state_allocation == bytes.ptr) {
            self.state_allocation = null;
            self.lock = null;
        }
        if (self.lock) |lock| {
            self.frees += 1;
            self.locked_frees += @intFromBool(lock.load(.acquire));
        }
        self.backing.rawFree(bytes, alignment, ret);
    }
};
test "catalogue_verify_job_path_cleanup_releases_spin_guard" {
    @setRuntimeSafety(true);
    const Path = @import("Path.zig");
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var cleanup: Cleanup = .{ .backing = no_resize.allocator() };
    inline for (.{ true, false }) |abandon| {
        var budget: Budget = .{};
        var q: Queue = .{};
        const job = try Job.init(cleanup.allocator(), &budget, request(), .{ .executor = .{ .context = &q, .submit = Queue.submit } });
        // Inject owned public native evidence, keeping the executor handle live.
        const path = try Path.init(cleanup.allocator(), request(), &.{"abc"});
        var guard = job.state.shared.acquire();
        guard.value().phase = .ready;
        guard.value().result = path;
        guard.deinit();
        cleanup.lock = &job.state.shared.lock;
        cleanup.state_allocation = std.mem.asBytes(job.state).ptr;
        if (abandon) job.abandon();
        job.deinit();
        if (abandon) {
            q.drain();
        } else {
            const executor_job = q.held.?;
            q.held = null;
            executor_job.deinit();
        }
        cleanup.lock = null;
        try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
    }
    try std.testing.expect(cleanup.frees >= 4);
    try std.testing.expectEqual(@as(usize, 0), cleanup.locked_frees);
}

test "catalogue_verify_job_native_abandon_during_evaluation_reaps_outside_guard" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    const root = @embedFile("../verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("../verify/fixtures/vectors/leaf.der");
    const req: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var cleanup: Cleanup = .{ .backing = no_resize.allocator() };
    var budget: Budget = .{};
    var q: Queue = .{};
    const job = try Job.init(cleanup.allocator(), &budget, req, .{ .executor = .{ .context = &q, .submit = Queue.submit }, .anchors = &.{root} });
    defer job.deinit();
    cleanup.lock = &job.state.shared.lock;
    cleanup.state_allocation = std.mem.asBytes(job.state).ptr;
    cleanup.abandon_on_alloc = job;
    q.drain();
    try std.testing.expect(cleanup.abandon_on_alloc == null);
    try std.testing.expectError(error.ServiceAbandoned, job.take(req));
    try std.testing.expect(cleanup.frees >= 4);
    try std.testing.expectEqual(@as(usize, 0), cleanup.locked_frees);
    try std.testing.expectEqual(@as(usize, 1), budget.counts().jobs);
}

const Pause = struct { io: std.Io, entered: std.Io.Event = .unset, proceed: std.Io.Event = .unset };
fn execute(job: Job) anyerror!void {
    @setRuntimeSafety(true);
    defer job.deinit();
    job.run();
}
test "catalogue_verify_job_native_concurrent_abandon_retains_charge_until_reap" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .concurrent_limit = .limited(1) });
    defer threaded.deinit();
    const io = threaded.io();
    var pause: Pause = .{ .io = io };
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var cleanup: Cleanup = .{ .backing = no_resize.allocator() };
    var budget: Budget = .{ .max_jobs = 1 };
    var q: Queue = .{};
    const req: types.Request = .{ .chain = &.{@embedFile("../verify/fixtures/vectors/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10), .trust_generation = 1, .policy_generation = 1 };
    var caller: ?Job = try Job.init(cleanup.allocator(), &budget, req, .{ .executor = .{ .context = &q, .submit = Queue.submit }, .anchors = &.{@embedFile("../verify/fixtures/vectors/p256.der")} });
    defer if (caller) |job| {
        job.abandon();
        job.deinit();
    };
    const executor_job = q.held.?;
    defer if (q.held != null) {
        executor_job.abandon();
        executor_job.run();
        executor_job.deinit();
    };
    cleanup.lock = &executor_job.state.shared.lock;
    cleanup.state_allocation = std.mem.asBytes(executor_job.state).ptr;
    cleanup.pause = &pause;
    var worker = try io.concurrent(execute, .{executor_job});
    q.held = null;
    // Reap before the borrowed allocator, pause or backend can expire, on errors too.
    defer {
        pause.proceed.set(io);
        _ = worker.cancel(io) catch {};
    }
    try pause.entered.wait(io);
    caller.?.abandon();
    caller.?.deinit();
    caller = null;
    try std.testing.expectEqual(@as(usize, 1), budget.counts().jobs);
    pause.proceed.set(io);
    try worker.await(io);
    try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
    try std.testing.expectEqual(@as(usize, 0), budget.counts().bytes);
    try std.testing.expectEqual(@as(usize, 0), cleanup.locked_frees);
    try std.testing.expect(cleanup.frees >= 4);
}
