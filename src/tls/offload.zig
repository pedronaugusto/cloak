//! The kernel record layer's tests: sans-I/O against a kernel the tests play, and on Linux
//! against the running kernel.
test {
    _ = @import("offload/Offload_test.zig");
    _ = @import("offload/freebsd_test.zig");
    if (@import("builtin").os.tag == .linux) _ = @import("offload/linux_test.zig");
}
