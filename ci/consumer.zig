const cloak = @import("cloak");
const certificates = @import("cloak.certificates");
const tls = @import("cloak.tls");
const std = @import("std");
pub fn main() void {
    @setRuntimeSafety(true);
    std.mem.doNotOptimizeAway(tls.Suite.aes_128_gcm_sha256);
    var independent = certificates.Trust.init(std.heap.page_allocator);
    defer independent.deinit();
    var trust = cloak.Trust.init(std.heap.page_allocator);
    defer trust.deinit();
}
