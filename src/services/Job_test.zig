const std = @import("std");
const builtin = @import("builtin");
const Job = @import("Job.zig");
const Budget = @import("Budget.zig");
const types = @import("../types.zig");
const shakedown = @import("shakedown");
const Queue = struct {
    held: ?Job = null,
    executor: Job.Executor = .{ .submit = submit },
    fn submit(executor: *Job.Executor, job: Job) Job.SubmitError!void {
        @setRuntimeSafety(true);
        const q: *Queue = @fieldParentPtr("executor", executor);
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
    return .{ .chain = &.{"abc"}, .time = .fromNanoseconds(1 * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1), .token = .{ .generation = .fromRaw(2), .id = .fromRaw(7) } };
}
test "service finite deadline rejects missing executor before copying" {
    @setRuntimeSafety(true);
    var budget: Budget = .init(.{});
    try std.testing.expectError(error.ServiceExecutorRequired, Job.init(std.testing.failing_allocator, &budget, request(), .{ .timeout = .{ .duration = .{ .raw = .fromNanoseconds(1), .clock = .awake } } }));
    try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
}
test "F26 catalogue_verify_job_cancel_alloc_and_late_result (a late completion after abandonment is refused and reaps only executor-owned memory, its charge held until reaped)" {
    @setRuntimeSafety(true);
    var budget: Budget = .init(.{ .max_jobs = 1 });
    var q: Queue = .{};
    const job = try Job.init(std.testing.allocator, &budget, request(), .{ .executor = &q.executor });
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
test "F26 catalogue_verify_job_cancel_alloc_and_late_result (a queued job survives every allocation failure without resize)" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), allocations, .{});
}
fn allocations(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var budget: Budget = .init(.{});
    defer std.debug.assert(budget.counts().jobs == 0);
    var q: Queue = .{};
    const job = try Job.init(gpa, &budget, request(), .{ .executor = &q.executor });
    job.abandon();
    job.deinit();
    q.drain();
}

test "service public budget arithmetic cannot wrap before admission" {
    @setRuntimeSafety(true);
    var budget: Budget = .init(.{});
    var req = request();
    req.limits.receipt_bytes = std.math.maxInt(usize);
    try std.testing.expectError(error.ServiceLimit, Job.init(std.testing.failing_allocator, &budget, req, .{}));
    try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
}

test "service admission covers owned state and input allocation with a zero receipt limit" {
    @setRuntimeSafety(true);
    var counting = shakedown.alloc.Counting.init(std.testing.allocator);
    var budget: Budget = .init(.{});
    var q: Queue = .{};
    var req = request();
    req.limits.receipt_bytes = 0;
    const job = try Job.init(counting.allocator(), &budget, req, .{ .executor = &q.executor });
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
    guard: ?*const @FieldType(@typeInfo(@FieldType(Job, "state").Ref).pointer.child, "shared") = null,
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
        // Allocator.destroy poisons the shared block before rawFree in safe builds. Stop
        // observing its guard at the free of the block that holds it rather than read dead state.
        if (self.guard) |guard| {
            const at = @intFromPtr(guard);
            if (at >= @intFromPtr(bytes.ptr) and at - @intFromPtr(bytes.ptr) < bytes.len) self.guard = null;
        }
        if (self.guard) |guard| {
            self.frees += 1;
            self.locked_frees += @intFromBool(guard.isHeld());
        }
        self.backing.rawFree(bytes, alignment, ret);
    }
};
test "F26 catalogue_verify_job_cancel_alloc_and_late_result (path cleanup releases the spin guard)" {
    @setRuntimeSafety(true);
    const Path = @import("Path.zig");
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var cleanup: Cleanup = .{ .backing = no_resize.allocator() };
    inline for (.{ true, false }) |abandon| {
        var budget: Budget = .init(.{});
        var q: Queue = .{};
        const job = try Job.init(cleanup.allocator(), &budget, request(), .{ .executor = &q.executor });
        // Inject owned public native evidence, keeping the executor handle live.
        const path = try Path.init(cleanup.allocator(), request(), &.{"abc"});
        var guard = job.state.get().shared.acquire();
        guard.value().phase = .ready;
        guard.value().result = path;
        guard.deinit();
        cleanup.guard = &job.state.get().shared;
        if (abandon) job.abandon();
        job.deinit();
        if (abandon) {
            q.drain();
        } else {
            const executor_job = q.held.?;
            q.held = null;
            executor_job.deinit();
        }
        cleanup.guard = null;
        try std.testing.expectEqual(@as(usize, 0), budget.counts().jobs);
    }
    try std.testing.expect(cleanup.frees >= 4);
    try std.testing.expectEqual(@as(usize, 0), cleanup.locked_frees);
}

test "F26 catalogue_verify_job_cancel_alloc_and_late_result (abandoned during evaluation, the result is reaped outside the guard)" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    const root = @embedFile("../verify/fixtures/vectors/p256.der");
    const leaf = @embedFile("../verify/fixtures/vectors/leaf.der");
    const req: types.Request = .{ .chain = &.{leaf}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var cleanup: Cleanup = .{ .backing = no_resize.allocator() };
    var budget: Budget = .init(.{});
    var q: Queue = .{};
    const job = try Job.init(cleanup.allocator(), &budget, req, .{ .executor = &q.executor, .anchors = &.{root} });
    defer job.deinit();
    cleanup.guard = &job.state.get().shared;
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
test "F26 catalogue_verify_job_cancel_alloc_and_late_result (a concurrent abandon retains the charge until reaped)" {
    @setRuntimeSafety(true);
    if (builtin.os.tag != .macos and builtin.os.tag != .windows) return error.SkipZigTest;
    var threaded = std.Io.Threaded.init(std.testing.allocator, .{ .concurrent_limit = .limited(1) });
    defer threaded.deinit();
    const io = threaded.io();
    var pause: Pause = .{ .io = io };
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var cleanup: Cleanup = .{ .backing = no_resize.allocator() };
    var budget: Budget = .init(.{ .max_jobs = 1 });
    var q: Queue = .{};
    const req: types.Request = .{ .chain = &.{@embedFile("../verify/fixtures/vectors/leaf.der")}, .identity = .{ .dns = "example.com" }, .time = .fromNanoseconds(@as(i96, try std.fmt.parseInt(i64, @embedFile("../verify/fixtures/vectors/time.txt"), 10)) * std.time.ns_per_s), .trust_generation = .fromRaw(1), .policy_generation = .fromRaw(1) };
    var caller: ?Job = try Job.init(cleanup.allocator(), &budget, req, .{ .executor = &q.executor, .anchors = &.{@embedFile("../verify/fixtures/vectors/p256.der")} });
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
    cleanup.guard = &executor_job.state.get().shared;
    cleanup.pause = &pause;
    var worker = try io.concurrent(execute, .{executor_job});
    q.held = null;
    // Reap before the borrowed allocator, pause or backend can expire, on errors too.
    defer {
        pause.proceed.set(io);
        _ = worker.cancel(io) catch {}; // glint-ignore: Z026 -- reaping on exit; the success path awaits the worker and checks its result, so only a test that is already failing drops it here
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
