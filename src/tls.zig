//! TLS 1.3 for Zig. The client connection is sans-I/O; callers drive it with bytes, entropy,
//! time and verification answers.
/// Modern TLS 1.3 suite identifiers.
pub const Suite13 = @import("tls/crypto/Suite.zig").Suite13;
/// Key-exchange groups.
pub const Group = @import("tls/crypto/Group.zig").Group;
/// Signature schemes a signing request names.
pub const SignatureScheme = @import("tls/handshake/Hello.zig").SignatureScheme;
/// Alert descriptions.
pub const Alert = @import("tls/wire/Alert.zig").Alert;
/// A certificate chain a server can present, with the names it answers for.
pub const Credential = @import("tls/handshake/Server.zig").Credential;
/// Whether a server asks for a client certificate.
pub const ClientCertificate = @import("tls/handshake/Server.zig").Auth;
/// A sans-I/O connection, client or server.
pub const Connection = @import("tls/Connection.zig");
/// The record-free handshake for QUIC.
pub const quic = @import("tls/quic.zig");
/// A client stream over `std.Io` readers and writers.
pub const Session = @import("tls/Session.zig");
test {
    _ = @import("tls/record.zig");
    _ = @import("tls/catalogue_test.zig");
    _ = @import("tls/wire.zig");
    _ = @import("tls/handshake.zig");
    _ = @import("tls/crypto.zig");
    _ = Connection;
    _ = Session;
    _ = quic;
}
