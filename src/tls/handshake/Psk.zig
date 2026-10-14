//! Provisioned (external) PSKs for TLS 1.3, PSK-DHE only (RFC 8446 section 4.2.11, with RFC 9257's
//! guidance): a key both ends hold beforehand, named by an opaque identity. A handshake on one
//! authenticates the peer as whoever holds that key: no certificate either way, and no X.509
//! identity implied. Every exchange is still an (EC)DHE one, so a leaked key exposes nothing
//! already recorded. No early data.
const Transport = @import("../crypto/Suite.zig").Transport;

/// The hash a key is for; a suite of that hash must be negotiated to use it.
pub const Hash = enum {
    sha256,
    sha384,

    pub fn length(hash: Hash) usize {
        return if (hash == .sha256) 32 else 48;
    }
};

/// The longest identity cloak offers or looks up. Identities are bytes, compared exactly: no
/// terminator, no case folding, no trimming (F86).
pub const max_identity = 1024;

pub const External = struct {
    identity: []const u8,
    /// Exactly `hash.length()` bytes of the provisioned key. Borrowed.
    secret: []const u8,
    hash: Hash = .sha256,
};

/// What a server's lookup sees, so the caller can bind a key to the endpoint, application and
/// transport it was provisioned for (RFC 9257 section 4): the offered identity, the server name
/// the client asked for, the protocol the server chose and the transport.
pub const Query = struct {
    identity: []const u8,
    server_name: []const u8,
    alpn: []const u8,
    transport: Transport,
};

/// A server's provisioned keys: `find` returns the key for a query, or null. Its result is
/// copied before `find` is called again; it must name the queried identity exactly.
pub const Lookup = struct {
    context: ?*anyopaque = null,
    find: *const fn (context: ?*anyopaque, query: Query) ?External,
};

pub fn validate(psk: External) error{InvalidOptions}!void {
    if (psk.identity.len == 0 or psk.identity.len > max_identity) return error.InvalidOptions;
    if (psk.secret.len != psk.hash.length()) return error.InvalidOptions;
    // An all-zero key is the usual stand-in for a missing one.
    for (psk.secret) |b| {
        if (b != 0) break;
    } else return error.InvalidOptions;
}
