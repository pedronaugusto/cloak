//! Private TLS record protection. Sequence and epoch ownership stays in Connection.
pub const Epoch = @import("record/Epoch.zig");
test {
    _ = Epoch;
}
pub const Suite = @import("crypto/Suite.zig").Suite;
