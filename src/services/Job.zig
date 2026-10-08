//! One caller handle and one executor handle; completion never points to a connection.
const std = @import("std");
const types = @import("../types.zig");
const Native = @import("Native.zig");
const Budget = @import("Budget.zig");
const OwnedRequest = @import("OwnedRequest.zig");
const Path = @import("Path.zig");
const Guarded = @import("Guarded.zig").Guarded;
const Job = @This();
/// Private: the independent completion remains alive through its executor handle.
state: *State,
const State = struct {
    gpa: std.mem.Allocator,
    budget: *Budget,
    charge: usize,
    inputs: OwnedRequest,
    refs: std.atomic.Value(usize) = .init(1),
    shared: Guarded(Completion) = .init(.{}),
};
const Completion = struct { phase: Phase = .pending, result: ?Native.EvaluateError!Path = null };
const Phase = enum { pending, running, ready, abandoned, acknowledged };
pub const Executor = struct {
    context: *anyopaque,
    /// Success transfers a retained job to the executor. It must call run then deinit,
    /// including during shutdown, and may not store a connection pointer.
    submit: *const fn (*anyopaque, Job) SubmitError!void,
};
pub const SubmitError = error{ ServiceBusy, ExecutorClosed };
pub const Options = struct { timeout: std.Io.Timeout = .none, executor: ?Executor = null, anchors: []const []const u8 = &.{} };
pub const InitError = OwnedRequest.InitError || Budget.ReserveError || SubmitError || error{ ServiceExecutorRequired, ServiceLimit };
pub fn init(gpa: std.mem.Allocator, budget: *Budget, request: types.Request, options: Options) InitError!Job {
    @setRuntimeSafety(true);
    if (options.timeout != .none and options.executor == null) return error.ServiceExecutorRequired;
    const charge = try inputSize(request, options.anchors);
    try budget.reserve(charge);
    errdefer budget.release(charge);
    var inputs = try OwnedRequest.init(gpa, request, options.anchors);
    errdefer inputs.deinit();
    const state = try gpa.create(State);
    errdefer gpa.destroy(state);
    state.* = .{ .gpa = gpa, .budget = budget, .charge = charge, .inputs = inputs };
    const job: Job = .{ .state = state };
    if (options.executor) |executor| {
        _ = job.state.refs.fetchAdd(1, .monotonic);
        executor.submit(executor.context, job) catch |err| {
            _ = job.state.refs.fetchSub(1, .monotonic);
            return err;
        };
    } else job.run();
    return job;
}
pub fn run(job: Job) void {
    @setRuntimeSafety(true);
    var guard = job.state.shared.acquire();
    if (guard.value().phase == .abandoned) {
        guard.deinit();
        return;
    }
    if (guard.value().phase != .pending) @panic("cloak service completion executed twice");
    guard.value().phase = .running;
    guard.deinit();
    var result = Native.evaluate(job.state.gpa, job.state.inputs.request, job.state.inputs.anchors);
    guard = job.state.shared.acquire();
    defer guard.deinit();
    if (guard.value().phase == .abandoned) {
        if (result) |*path| path.deinit() else |_| {}
    } else {
        guard.value().result = result;
        guard.value().phase = .ready;
    }
}
/// Cancels only this completion. The executor remains responsible for reaping work.
pub fn abandon(job: Job) void {
    @setRuntimeSafety(true);
    var guard = job.state.shared.acquire();
    defer guard.deinit();
    if (guard.value().phase == .acknowledged) return;
    guard.value().phase = .abandoned;
    if (guard.value().result) |*result| {
        if (result.*) |*path| path.deinit() else |_| {}
        guard.value().result = null;
    }
}
pub const TakeError = Native.EvaluateError || Path.CheckError || error{ ServicePending, ServiceAbandoned, ServiceAcknowledged };
pub fn take(job: Job, request: types.Request) TakeError!Path {
    @setRuntimeSafety(true);
    var guard = job.state.shared.acquire();
    defer guard.deinit();
    switch (guard.value().phase) {
        .pending, .running => return error.ServicePending,
        .abandoned => return error.ServiceAbandoned,
        .acknowledged => return error.ServiceAcknowledged,
        .ready => {},
    }
    if (!std.crypto.timing_safe.eql([32]u8, job.state.inputs.request.digest(), request.digest())) return error.WrongVerificationRequest;
    const result = guard.value().result.?;
    guard.value().result = null;
    guard.value().phase = .acknowledged;
    return result;
}
pub fn deinit(job: Job) void {
    @setRuntimeSafety(true);
    if (job.state.refs.fetchSub(1, .acq_rel) != 1) return;
    var guard = job.state.shared.acquire();
    if (guard.value().phase == .running) @panic("cloak executor released running completion");
    if (guard.value().result) |*result| {
        if (result.*) |*path| path.deinit() else |_| {}
    }
    guard.deinit();
    job.state.inputs.deinit();
    job.state.budget.release(job.state.charge);
    const gpa = job.state.gpa;
    gpa.destroy(job.state);
}
fn inputSize(request: types.Request, anchors: []const []const u8) error{ServiceLimit}!usize {
    @setRuntimeSafety(true);
    if (request.chain.len == 0 or request.chain.len > request.limits.certificates or request.pins.len > 256 or request.anchor_policies.len > 4096) return error.ServiceLimit;
    if (request.limits.depth > 16 or request.limits.certificates > 16) return error.ServiceLimit;
    for ([_][]const []const u8{ request.chain, anchors, request.policy.required_policies, request.evidence.crls, request.evidence.ocsp }) |list| {
        if (list.len > 4096) return error.ServiceLimit;
    }
    if (request.identity == .dns and request.identity.dns.len > 253) return error.ServiceLimit;
    for (request.anchor_policies) |policy| if (policy.required_policies.len > 256) return error.ServiceLimit;
    var total = std.math.add(usize, @sizeOf(State), try OwnedRequest.byteSize(request, anchors)) catch return error.ServiceLimit;
    total = std.math.add(usize, total, request.limits.receipt_bytes) catch return error.ServiceLimit;
    // Charge all cloak-owned native descriptor/name scratch alongside the path.
    // Framework/CryptoAPI private allocations remain OS-owned and job-count bounded.
    const descriptors = std.math.mul(usize, request.limits.depth, 2 * @sizeOf([]const u8) + @sizeOf(usize)) catch return error.ServiceLimit;
    total = std.math.add(usize, total, descriptors + 508) catch return error.ServiceLimit;
    const references = std.math.mul(usize, @max(request.chain.len, anchors.len), @sizeOf(usize)) catch return error.ServiceLimit;
    return std.math.add(usize, total, references) catch error.ServiceLimit;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Job_test.zig");
    _ = @import("Guarded.zig");
}
