//! Private TLS record protection. Sequence and epoch ownership stays in Connection.
pub const Epoch = @import("record/Epoch.zig");
pub const Epoch12 = @import("record/Epoch12.zig");
test {
    _ = Epoch;
    _ = Epoch12;
}
pub const Protection = @import("record/Protection.zig");
pub const Suite13 = @import("crypto/Suite.zig").Suite13;
