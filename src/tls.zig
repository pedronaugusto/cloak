//! TLS 1.3 for Zig. The client connection is sans-I/O; callers drive it with bytes, entropy,
//! time and verification answers.
/// Modern TLS 1.3 suite identifiers.
pub const Suite = @import("tls/crypto/Suite.zig").Suite;
/// Key-exchange groups.
pub const Group = @import("tls/crypto/Group.zig").Group;
/// Alert descriptions.
pub const Alert = @import("tls/wire/Alert.zig").Alert;
/// A sans-I/O client connection.
pub const Connection = @import("tls/Connection.zig");
test {
    _ = @import("tls/record.zig");
    _ = @import("tls/wire.zig");
    _ = @import("tls/handshake.zig");
    _ = @import("tls/crypto.zig");
    _ = Connection;
}
