const std = @import("std");
const cloak = @import("cloak");
pub const std_options: std.Options = .{ .side_channels_mitigations = .none };
pub fn main() void {
    @setRuntimeSafety(true);
    const key = cloak.PrivateKey.parse(std.heap.page_allocator, "invalid", .{}) catch return;
    key.deinit();
}
