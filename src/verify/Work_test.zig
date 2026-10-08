const std = @import("std");
const Work = @import("Work.zig");
test "verification work charges bytes without overflow or refund" {
    var work: Work = .{ .remaining = 6 };
    try std.testing.expect(try work.equal("ok", "ok"));
    try std.testing.expectEqual(@as(usize, 1), work.remaining);
    try std.testing.expectError(error.VerificationLimit, work.charge(std.math.maxInt(usize)));
    try work.charge(1);
    try std.testing.expectError(error.VerificationLimit, work.charge(1));
}
