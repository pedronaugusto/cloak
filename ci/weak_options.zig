const std = @import("std");
const cloak = @import("cloak");
pub const std_options: std.Options = .{ .side_channels_mitigations = .none };
pub fn main() !void {
    @setRuntimeSafety(true);
    const key = try cloak.PrivateKey.parse(std.heap.page_allocator, "invalid", .{});
    key.deinit();
}
