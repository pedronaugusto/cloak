//! Per-request public-input work owner; failed paths never refund a charge.
const std = @import("std");
const Work = @This();
remaining: usize,
pub const ChargeError = error{VerificationLimit};
pub fn charge(self: *Work, amount: usize) ChargeError!void {
    @setRuntimeSafety(true);
    if (amount > self.remaining) return error.VerificationLimit;
    self.remaining -= amount;
}
pub fn equal(self: *Work, a: []const u8, b: []const u8) ChargeError!bool {
    @setRuntimeSafety(true);
    try self.charge(1);
    try self.charge(a.len);
    try self.charge(b.len);
    return std.mem.eql(u8, a, b);
}
test {
    _ = @import("Work_test.zig");
}
