//! Private TLS cryptographic adapters, independent of records and handshake state.
pub const suites = @import("crypto/Suite.zig");
pub const Labels = @import("crypto/Labels.zig");
pub const Group = @import("crypto/Group.zig").Group;
pub const Exchange = @import("crypto/Exchange.zig");
test {
    _ = Labels;
    _ = Exchange;
}
