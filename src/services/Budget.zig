//! Caller-owned shared admission. Abandoned work remains charged until reaped.
const Guarded = @import("aegis").Guarded;
const Budget = @This();
const aegis = @import("aegis");
const Bytes = aegis.units.Bytes(usize);
const Jobs = aegis.units.Count(struct {}, usize);
/// Configure before publishing this owner; limits are immutable during use.
max_jobs: usize = 64,
max_bytes: usize = 16 * 1024 * 1024,
shared: Guarded(Active) = .init(.{}),
const Active = struct { jobs: Jobs = .fromRaw(0), bytes: Bytes = .fromRaw(0) };
/// Scalar snapshot for observers; no live borrow leaves the guard.
pub const Counts = struct { jobs: usize = 0, bytes: usize = 0 };
pub const ReserveError = error{ServiceBusy};
pub fn reserve(b: *Budget, amount: usize) ReserveError!void {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    const active = guard.value();
    if (active.jobs.raw() >= b.max_jobs or active.bytes.raw() > b.max_bytes) return error.ServiceBusy;
    const available = Bytes.fromRaw(b.max_bytes).sub(active.bytes) catch unreachable; // unreachable: active bytes fit the configured ceiling
    if (amount > available.raw()) return error.ServiceBusy;
    // Each addition is bounded before mutation; no failing publication or rollback.
    active.jobs = active.jobs.add(.fromRaw(1)) catch unreachable; // unreachable: jobs are strictly below their usize ceiling
    active.bytes = active.bytes.add(.fromRaw(amount)) catch unreachable; // unreachable: amount fits the checked remaining byte budget

}
pub fn release(b: *Budget, amount: usize) void {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    const active = guard.value();
    aegis.assert.pre(active.bytes.raw() >= amount and active.jobs.raw() != 0, "service release owns its charge");
    active.bytes = active.bytes.sub(.fromRaw(amount)) catch unreachable; // unreachable: ownership invariant checked above
    active.jobs = active.jobs.sub(.fromRaw(1)) catch unreachable; // unreachable: ownership invariant checked above
}
pub fn counts(b: *Budget) Counts {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    return .{ .jobs = guard.value().jobs.raw(), .bytes = guard.value().bytes.raw() };
}
test {
    @setRuntimeSafety(true);
    _ = @import("Budget_test.zig");
}
