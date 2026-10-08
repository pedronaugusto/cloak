const std = @import("std");
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
