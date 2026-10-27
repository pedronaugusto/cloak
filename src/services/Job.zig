//! One caller handle and one executor handle; completion never points to a connection.
const std = @import("std");
const aegis = @import("aegis");
const types = @import("../types.zig");
const Native = @import("Native.zig");
const Budget = @import("Budget.zig");
const OwnedRequest = @import("OwnedRequest.zig");
const Path = @import("Path.zig");
const Guarded = @import("aegis").Guarded;
const Job = @This();
/// Private: the independent completion remains alive through its executor handle.
state: Handle,
const Handle = aegis.Shared(State, release);
const State = struct {
    /// Everything either handle changes is behind `shared`'s lock; the inputs are fixed from
    /// creation, and the charge and inputs are released by the last handle alone.
    pub const interior_lock = true;
    gpa: std.mem.Allocator,
    charge: Budget.Charge,
    inputs: OwnedRequest,
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
    const job = try make(gpa, budget, request, options.anchors);
    if (options.executor) |executor| {
        const handed: Job = .{ .state = job.state.retain() };
        executor.submit(executor.context, handed) catch |err| {
            handed.deinit();
            job.deinit();
            return err;
        };
    } else job.run();
    return job;
}
/// The job with its one handle: the charge and the owned inputs move into it.
fn make(gpa: std.mem.Allocator, budget: *Budget, request: types.Request, anchors: []const []const u8) (OwnedRequest.InitError || Budget.ReserveError || error{ServiceLimit})!Job {
    @setRuntimeSafety(true);
    var charge = try budget.reserve(try inputSize(request, anchors));
    errdefer charge.release();
    var inputs = try OwnedRequest.init(gpa, request, anchors);
    errdefer inputs.deinit();
    return .{ .state = try .create(gpa, .{ .gpa = gpa, .charge = charge, .inputs = inputs }) };
}
pub fn run(job: Job) void {
    @setRuntimeSafety(true);
    var guard = job.state.get().shared.acquire();
    if (guard.value().phase == .abandoned) {
        guard.deinit();
        return;
    }
    if (guard.value().phase != .pending) @panic("cloak service completion executed twice");
    guard.value().phase = .running;
    guard.deinit();
    var result = Native.evaluate(job.state.get().gpa, job.state.get().inputs.request, job.state.get().inputs.anchors);
    guard = job.state.get().shared.acquire();
    const abandoned = guard.value().phase == .abandoned;
    if (!abandoned) {
        guard.value().result = result;
        guard.value().phase = .ready;
    }
    guard.deinit();
    // Allocator cleanup can block or reenter: it runs after the mutation lease.
    if (abandoned) {
        if (result) |*path| path.deinit() else |_| {}
    }
}
/// Cancels only this completion. The executor remains responsible for reaping work.
pub fn abandon(job: Job) void {
    @setRuntimeSafety(true);
    var guard = job.state.get().shared.acquire();
    if (guard.value().phase == .acknowledged) {
        guard.deinit();
        return;
    }
    guard.value().phase = .abandoned;
    var detached = guard.value().result;
    guard.value().result = null;
    guard.deinit();
    if (detached) |*result| {
        if (result.*) |*path| path.deinit() else |_| {}
    }
}
pub const TakeError = Native.EvaluateError || Path.CheckError || error{ ServicePending, ServiceAbandoned, ServiceAcknowledged };
pub fn take(job: Job, request: types.Request) TakeError!Path {
    @setRuntimeSafety(true);
    var guard = job.state.get().shared.acquire();
    const phase = guard.value().phase;
    guard.deinit();
    try ready(phase);
    // Inputs are immutable while either handle is retained. Hash outside spin.
    const expected = job.state.get().inputs.request.digest();
    const supplied = request.digest();
    guard = job.state.get().shared.acquire();
    defer guard.deinit();
    try ready(guard.value().phase);
    if (!aegis.secret.equal(32, &expected, &supplied).declassify("a request mismatch is refused")) return error.WrongVerificationRequest;
    const result = guard.value().result.?;
    guard.value().result = null;
    guard.value().phase = .acknowledged;
    return result;
}
fn ready(phase: Phase) error{ ServicePending, ServiceAbandoned, ServiceAcknowledged }!void {
    @setRuntimeSafety(true);
    switch (phase) {
        .pending, .running => return error.ServicePending,
        .abandoned => return error.ServiceAbandoned,
        .acknowledged => return error.ServiceAcknowledged,
        .ready => {},
    }
}
pub fn deinit(job: Job) void {
    var handle = job.state;
    handle.release();
}
/// The last handle's cleanup.
fn release(state: *State) void {
    @setRuntimeSafety(true);
    var guard = state.shared.acquire();
    if (guard.value().phase == .running) @panic("cloak executor released running completion");
    var detached = guard.value().result;
    guard.value().result = null;
    guard.deinit();
    if (detached) |*result| {
        if (result.*) |*path| path.deinit() else |_| {}
    }
    state.inputs.deinit();
    state.charge.release();
}
fn inputSize(request: types.Request, anchors: []const []const u8) error{ServiceLimit}!usize {
    @setRuntimeSafety(true);
    if (request.chain.len == 0 or request.chain.len > request.limits.certificates or request.pins.len > 256 or request.anchor_policies.len > 4096) return error.ServiceLimit;
    if (request.limits.depth > 16 or request.limits.certificates > 16) return error.ServiceLimit;
    for ([_][]const []const u8{ request.chain, anchors, request.policy.required_policies, request.evidence.crls, request.evidence.ocsp }) |list| {
        if (list.len > 4096) return error.ServiceLimit;
    }
    if (request.evidence.scts.len > types.TransparencyPolicy.max_lists) return error.ServiceLimit;
    if (request.policy.transparency) |policy| if (policy.logs.len > types.TransparencyPolicy.max_logs) return error.ServiceLimit;
    if (request.identity == .dns and request.identity.dns.len > 253) return error.ServiceLimit;
    for (request.anchor_policies) |policy| if (policy.required_policies.len > 256) return error.ServiceLimit;
    var total = (aegis.int.Checked(usize).init(@sizeOf(State)).add(try OwnedRequest.byteSize(request, anchors)) catch return error.ServiceLimit).raw();
    total = (aegis.int.Checked(usize).init(total).add(request.limits.receipt_bytes) catch return error.ServiceLimit).raw();
    // Charge all cloak-owned native descriptor/name scratch alongside the path.
    // Framework/CryptoAPI private allocations remain OS-owned and job-count bounded.
    const descriptors = (aegis.int.Checked(usize).init(request.limits.depth).mul(2 * @sizeOf([]const u8) + @sizeOf(usize)) catch return error.ServiceLimit).raw();
    total = (aegis.int.Checked(usize).init(total).add(descriptors + 508) catch return error.ServiceLimit).raw();
    const references = (aegis.int.Checked(usize).init(@max(request.chain.len, anchors.len)).mul(@sizeOf(usize)) catch return error.ServiceLimit).raw();
    return (aegis.int.Checked(usize).init(total).add(references) catch return error.ServiceLimit).raw();
}
test {
    @setRuntimeSafety(true);
    _ = @import("Job_test.zig");
}
