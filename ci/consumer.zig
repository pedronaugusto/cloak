const cloak = @import("cloak");
const std = @import("std");
pub fn main() void {
    @setRuntimeSafety(true);
    var trust = cloak.Trust.init(std.heap.page_allocator);
    defer trust.deinit();
}
