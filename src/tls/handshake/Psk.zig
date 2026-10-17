//! Provisioned (external) PSKs: a key both ends hold beforehand, named by an opaque identity. A
//! handshake on one authenticates the peer as whoever holds that key: no certificate either way,
//! and no X.509 identity implied. A key is for one version (RFC 8446 appendix E.7):
//! - TLS 1.3, PSK-DHE only (RFC 8446 section 4.2.11, with RFC 9257's guidance): every exchange
//!   is still an (EC)DHE one, so a leaked key exposes nothing already recorded. No early data.
//! - TLS 1.2, plain PSK (RFC 4279 with RFC 6655's CCM suites), for CoAP's and LwM2M's PSK mode
//!   (RFC 7925): no key exchange, so a key that leaks opens every session recorded under it, and
//!   an eavesdropper can test guesses at a weak key offline against the Finished. Keys are 16 to
//!   64 bytes for that reason; the identity crosses the wire in clear.
const suites = @import("../crypto/Suite.zig");
const Transport = suites.Transport;
pub const Version = suites.Version;

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

/// The shortest and longest TLS 1.2 key: shorter is a password, which plain PSK exposes to an
/// offline search; RFC 4279 section 5.3 asks for keys up to 64 bytes.
pub const min_secret12 = 16;
pub const max_secret12 = 64;

pub const External = struct {
    identity: []const u8,
    /// The provisioned key, borrowed: TLS 1.3, exactly `hash.length()` bytes; TLS 1.2,
    /// `min_secret12` to `max_secret12` bytes.
    secret: []const u8,
    /// The hash of the suites the key is for. TLS 1.2's PSK suites are SHA-256's.
    hash: Hash = .sha256,
    /// The one version the key is used with; never the same key for both.
    version: Version = .tls13,
};

/// What a server's lookup sees, so the caller can bind a key to the endpoint, application and
/// transport it was provisioned for (RFC 9257 section 4): the offered identity, the server name
/// the client asked for, the protocol the server chose and the transport.
pub const Query = struct {
    identity: []const u8,
    server_name: []const u8,
    alpn: []const u8,
    transport: Transport,
    /// The version being negotiated: a key for the other one is passed over.
    version: Version,
};

/// A server's provisioned keys: `find` returns the key for a query, or null. Its result is
/// copied before `find` is called again; it must name the queried identity exactly.
pub const Lookup = struct {
    context: ?*anyopaque = null,
    find: *const fn (context: ?*anyopaque, query: Query) ?External,
};

pub fn validate(psk: External) error{InvalidOptions}!void {
    if (psk.identity.len == 0 or psk.identity.len > max_identity) return error.InvalidOptions;
    switch (psk.version) {
        .tls13 => if (psk.secret.len != psk.hash.length()) return error.InvalidOptions,
        .tls12 => if (psk.hash != .sha256 or psk.secret.len < min_secret12 or psk.secret.len > max_secret12) return error.InvalidOptions,
    }
    // An all-zero key is the usual stand-in for a missing one.
    for (psk.secret) |b| {
        if (b != 0) break;
    } else return error.InvalidOptions;
}
