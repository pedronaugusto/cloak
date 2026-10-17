const std = @import("std");
const Budget = @import("Budget.zig");
test "service admission charges abandoned work and rolls back byte rejection" {
    @setRuntimeSafety(true);
    var b: Budget = .init(.{ .max_jobs = 1, .max_bytes = 10 });
    // Too many bytes: the job it would have counted is not left charged.
    try std.testing.expectError(error.ServiceBusy, b.reserve(11));
    try std.testing.expectEqual(Budget.Counts{}, b.counts());
    var first = try b.reserve(8);
    try std.testing.expectEqual(Budget.Counts{ .jobs = 1, .bytes = 8 }, b.counts());
    // The one job is taken, however few bytes the next asks for.
    try std.testing.expectError(error.ServiceBusy, b.reserve(0));
    first.release();
    try std.testing.expectEqual(Budget.Counts{}, b.counts());
    var whole = try b.reserve(10);
    whole.release();
}
test "service admission: a charge moves to its holder and returns what it took" {
    @setRuntimeSafety(true);
    var b: Budget = .init(.{ .max_jobs = 2, .max_bytes = 10 });
    var charge = try b.reserve(4);
    var held: Budget.Charge = undefined;
    charge.moveInto(&held);
    var other = try b.reserve(6);
    try std.testing.expectError(error.ServiceBusy, b.reserve(0));
    held.release();
    try std.testing.expectEqual(Budget.Counts{ .jobs = 1, .bytes = 6 }, b.counts());
    other.release();
    try std.testing.expectEqual(Budget.Counts{}, b.counts());
}
