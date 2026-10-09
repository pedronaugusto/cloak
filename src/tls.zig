//! TLS protocol vocabulary. Connection and client flights are under construction.
/// Modern TLS 1.3 suite identifiers; this table does not negotiate a connection.
pub const Suite = @import("tls/crypto/Suite.zig").Suite;
test {
    _ = @import("tls/record.zig");
    _ = @import("tls/wire.zig");
    _ = @import("tls/handshake.zig");
    _ = @import("tls/crypto.zig");
}
