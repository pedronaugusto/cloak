//! Caller-owned shared admission. Abandoned work remains charged until reaped.
const aegis = @import("aegis");
const Guarded = aegis.Guarded;
const Budget = @This();
const Counter = aegis.bounded.Budget(usize);
/// Private: the two counters, changed only under the guard. Their ceilings are set by `init` and
/// never change.
shared: Guarded(Active),
const Active = struct { jobs: Counter, bytes: Counter };

pub const Limits = struct {
    /// Jobs admitted and not yet reaped.
    max_jobs: usize = 64,
    /// Bytes those jobs own.
    max_bytes: usize = 16 * 1024 * 1024,
};

/// A budget with these limits. It must not move once a job holds a charge of it.
pub fn init(limits: Limits) Budget {
    return .{ .shared = .init(.{ .jobs = .init(limits.max_jobs), .bytes = .init(limits.max_bytes) }) };
}

/// One admitted job's share: one job and its bytes. Exactly one `release` returns it; moving it
/// is by `moveInto`, a copy is a second owner.
pub const Charge = struct {
    /// Private: the budget the reservations point into, whose guard `release` takes.
    budget: *Budget,
    jobs: Counter.Reservation,
    bytes: Counter.Reservation,

    /// Returns the charge under its budget's guard.
    pub fn release(self: *Charge) void {
        @setRuntimeSafety(true);
        var guard = self.budget.shared.acquire();
        defer guard.deinit();
        self.jobs.release();
        self.bytes.release();
    }

    pub fn moveInto(self: *Charge, destination: *Charge) void {
        destination.budget = self.budget;
        self.jobs.moveInto(&destination.jobs);
        self.bytes.moveInto(&destination.bytes);
    }
};

/// Scalar snapshot for observers; no live borrow leaves the guard.
pub const Counts = struct { jobs: usize = 0, bytes: usize = 0 };
pub const ReserveError = error{ServiceBusy};

/// Admits one job owning `amount` bytes, or none: a refusal leaves both counts as they were.
pub fn reserve(b: *Budget, amount: usize) ReserveError!Charge {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    const active = guard.value();
    var jobs = active.jobs.reserve(1) catch return error.ServiceBusy;
    const bytes = active.bytes.reserve(amount) catch {
        jobs.release();
        return error.ServiceBusy;
    };
    return .{ .budget = b, .jobs = jobs, .bytes = bytes };
}

pub fn counts(b: *Budget) Counts {
    @setRuntimeSafety(true);
    var guard = b.shared.acquire();
    defer guard.deinit();
    return .{ .jobs = guard.value().jobs.charged(), .bytes = guard.value().bytes.charged() };
}

test {
    @setRuntimeSafety(true);
    _ = @import("Budget_test.zig");
}
