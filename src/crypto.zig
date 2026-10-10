//! cloak's private crypto layer: owned constant-time kernels where std's are slower or cannot
//! promise constant time. Nothing here is public API.
pub const p256 = @import("crypto/p256.zig");
test {
    _ = p256;
}
