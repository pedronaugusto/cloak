const std = @import("std");
const Primality = @import("Primality.zig");
const Entropy = @import("Entropy.zig");
test "credential primality independent entropy failure fails closed" {
    @setRuntimeSafety(true);
    try std.testing.expectError(error.EntropyUnavailable, Primality.check("\x01\x01", .{ .context = &std.testing.io, .fill = fail }));
}
fn fail(_: *const anyopaque, _: []u8) Entropy.FillError!void {
    @setRuntimeSafety(true);
    return error.EntropyUnavailable;
}
