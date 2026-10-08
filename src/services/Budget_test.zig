const std = @import("std");
const Budget = @import("Budget.zig");
test "service admission charges abandoned work and rolls back byte rejection" {
    @setRuntimeSafety(true);
    var b: Budget = .{ .max_jobs = 1, .max_bytes = 10 };
    try std.testing.expectError(error.ServiceBusy, b.reserve(11));
    try std.testing.expectEqual(@as(usize, 0), b.counts().jobs);
    try b.reserve(8);
    try std.testing.expectError(error.ServiceBusy, b.reserve(1));
    b.release(8);
    try b.reserve(10);
    b.release(10);
}
