//! Public name for the lower-layer owned verification receipt.
pub const Verification = @import("types.zig").Verification;
test {
    _ = @import("verify/Verification_test.zig");
}
