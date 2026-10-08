//! Caller-owned shared admission. Abandoned work remains charged until reaped.
const Guarded = @import("Guarded.zig").Guarded;
const Budget = @This();
/// Configure before publishing this owner; limits are immutable during use.
max_jobs: usize = 64,
max_bytes: usize = 16 * 1024 * 1024,
shared: Guarded(Counts) = .init(.{}),
pub const Counts = struct { jobs: usize = 0, bytes: usize = 0 };
pub const ReserveError = error{ServiceBusy};
pub fn reserve(b: *Budget, amount: usize) ReserveError!void {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    const active = guard.value();
    if (active.jobs >= b.max_jobs or active.bytes > b.max_bytes or amount > b.max_bytes -| active.bytes) return error.ServiceBusy;
    active.jobs += 1;
    active.bytes += amount;
}
pub fn release(b: *Budget, amount: usize) void {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    const active = guard.value();
    if (active.bytes < amount or active.jobs == 0) @panic("cloak service admission released without ownership");
    active.bytes -= amount;
    active.jobs -= 1;
}
pub fn counts(b: *Budget) Counts {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    return guard.value().*;
}
test {
    @setRuntimeSafety(true);
    _ = @import("Budget_test.zig");
    _ = @import("Guarded.zig");
}
