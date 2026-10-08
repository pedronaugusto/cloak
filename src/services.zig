//! Bounded caller-executed native verification with owned inputs and completions.
pub const Budget = @import("services/Budget.zig");
pub const Job = @import("services/Job.zig");
pub const Path = @import("services/Path.zig");
test {
    @setRuntimeSafety(true);
    _ = @import("services/Native.zig");
    _ = @import("services/OwnedRequest.zig");
}
