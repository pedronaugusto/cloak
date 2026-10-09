//! Private TLS cryptographic adapters, independent of records and handshake state.
pub const suites = @import("crypto/Suite.zig");
pub const Labels = @import("crypto/Labels.zig");
test {
    _ = Labels;
}
