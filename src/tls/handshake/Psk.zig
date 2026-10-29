//! Provisioned (external) PSKs: a key both ends hold beforehand, named by an opaque identity. A
//! handshake on one authenticates the peer as whoever holds that key: no certificate either way,
//! and no X.509 identity implied. A key is for one version (RFC 8446 appendix E.7):
//! - TLS 1.3, PSK-DHE only (RFC 8446 section 4.2.11, with RFC 9257's guidance): every exchange
//!   is still an (EC)DHE one, so a leaked key exposes nothing already recorded. No early data.
//! - TLS 1.2, plain PSK (RFC 4279 with RFC 6655's CCM suites), for CoAP's and LwM2M's PSK mode
//!   (RFC 7925): no key exchange, so a key that leaks opens every session recorded under it, and
//!   an eavesdropper can test guesses at a weak key offline against the Finished. Keys are 16 to
//!   64 bytes for that reason; the identity crosses the wire in clear.
//! A TLS 1.3 key may be imported (RFC 9258): offered under an ImportedIdentity for each hash
//! the hello's suites use, each under a key derived for that protocol and hash.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Labels = @import("../crypto/Labels.zig");
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

/// The most keys a client offers (`external_psks`).
pub const max_keys = 4;

/// The longest identity cloak offers or looks up. Identities are bytes, compared exactly: no
/// terminator, no case folding, no trimming (F86).
pub const max_identity = 1024;

/// The shortest and longest TLS 1.2 key: shorter is a password, which plain PSK exposes to an
/// offline search; RFC 4279 section 5.3 asks for keys up to 64 bytes.
pub const min_secret12 = 16;
pub const max_secret12 = 64;

pub const External = struct {
    identity: []const u8,
    /// The provisioned key, borrowed: TLS 1.3, exactly `hash.length()` bytes, or an imported
    /// key's `min_imported` to `max_imported`; TLS 1.2, `min_secret12` to `max_secret12` bytes.
    secret: []const u8,
    /// The hash of the suites the key is for; an imported key's, the hash it is imported with,
    /// whatever the suite's. TLS 1.2's PSK suites are SHA-256's.
    hash: Hash = .sha256,
    /// The one version the key is used with; never the same key for both.
    version: Version = .tls13,
    /// The key is imported (RFC 9258, TLS 1.3 only): never used as it is, only as the keys
    /// derived from it for TLS 1.3, DTLS 1.3 or QUIC and a suite's hash (RFC 9257 section 6), so
    /// one provisioned key serves every hash; a server's lookup answers it only for an imported
    /// identity, and an imported key only for one.
    imported: ?Imported = null,
};

/// An imported key's binding beyond its identity (RFC 9258 section 5.1).
pub const Imported = struct {
    /// Bytes both ends bind the key to, such as an application's name; empty by default. At most
    /// `max_context`.
    context: []const u8 = "",
};

pub const max_context = 1024;
/// An imported key's length: a key shorter than 16 bytes is a password (RFC 9257 section 4).
pub const min_imported = 16;
pub const max_imported = 1024;
/// The longest ImportedIdentity: the identity and context, each with its length, and the target
/// protocol and KDF.
pub const max_imported_identity = 2 + max_identity + 2 + max_context + 4;

/// RFC 9258's target_protocol: TLS 1.3's version number, or DTLS 1.3's (QUIC carries TLS 1.3).
pub fn targetProtocol(transport: Transport) u16 {
    return if (transport == .datagram) 0xfefc else 0x0304;
}

/// RFC 9258's target_kdf: HKDF_SHA256 (1) or HKDF_SHA384 (2).
pub fn targetKdf(hash: Hash) u16 {
    return if (hash == .sha256) 1 else 2;
}

/// An ImportedIdentity as it crosses the wire (RFC 9258 section 5.1).
pub const ImportedIdentity = struct {
    identity: []const u8,
    context: []const u8,
    protocol: u16,
    kdf: u16,

    /// Reads one from an offered identity: exactly the structure, with a non-empty identity;
    /// null for any other bytes, which are then a plain identity.
    pub fn parse(bytes: []const u8) ?ImportedIdentity {
        @setRuntimeSafety(true);
        if (bytes.len < 2) return null;
        const id_len = std.mem.readInt(u16, bytes[0..2], .big);
        if (id_len == 0 or bytes.len < 2 + id_len + 2) return null;
        const identity = bytes[2..][0..id_len];
        const rest = bytes[2 + id_len ..];
        const context_len = std.mem.readInt(u16, rest[0..2], .big);
        if (rest.len != 2 + context_len + 4) return null;
        return .{ .identity = identity, .context = rest[2..][0..context_len], .protocol = std.mem.readInt(u16, rest[2 + context_len ..][0..2], .big), .kdf = std.mem.readInt(u16, rest[4 + context_len ..][0..2], .big) };
    }

    /// Writes this ImportedIdentity into `out` (at least its length).
    pub fn write(self: ImportedIdentity, out: []u8) []u8 {
        @setRuntimeSafety(true);
        const len = 2 + self.identity.len + 2 + self.context.len + 4;
        std.mem.writeInt(u16, out[0..2], @intCast(self.identity.len), .big); // at most max_identity
        @memcpy(out[2..][0..self.identity.len], self.identity);
        const rest = out[2 + self.identity.len ..];
        std.mem.writeInt(u16, rest[0..2], @intCast(self.context.len), .big); // at most max_context
        @memcpy(rest[2..][0..self.context.len], self.context);
        std.mem.writeInt(u16, rest[2 + self.context.len ..][0..2], self.protocol, .big);
        std.mem.writeInt(u16, rest[4 + self.context.len ..][0..2], self.kdf, .big);
        return out[0..len];
    }
};

/// The ImportedIdentity a hello offers for an imported key, its target protocol and hash.
pub fn importedIdentity(psk: External, transport: Transport, target: Hash) ImportedIdentity {
    return .{ .identity = psk.identity, .context = psk.imported.?.context, .protocol = targetProtocol(transport), .kdf = targetKdf(target) };
}

/// The key an imported key yields under `imported_identity` (RFC 9258 section 5.2): ipskx, the
/// HKDF-Extract of the key under a zero salt, expanded by "derived psk" over the hash of the
/// ImportedIdentity's bytes to the length of `out` (the target hash's), all by the key's own hash
/// and with the target protocol's label prefix.
pub fn derive(psk: External, prefix: Labels.Prefix, imported_identity: []const u8, out: []u8) void {
    @setRuntimeSafety(true);
    switch (psk.hash) {
        inline else => |tag| {
            const H = if (tag == .sha256) std.crypto.hash.sha2.Sha256 else std.crypto.hash.sha2.Sha384;
            var epskx = aegis.Secret([H.digest_length]u8).init(undefined);
            defer epskx.deinit();
            Labels.extract(H, epskx.exposeMut(), &@as([H.digest_length]u8, @splat(0)), psk.secret);
            var identity_hash: [H.digest_length]u8 = undefined;
            H.hash(imported_identity, &identity_hash, .{});
            Labels.expandWith(H, prefix, out, epskx.expose(), "derived psk", &identity_hash) catch unreachable; // unreachable: the label, a hash and at most 48 bytes are within the bounds
        },
    }
}

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
    /// The offer was an ImportedIdentity (RFC 9258) for this protocol and the suite's hash, and
    /// `identity` its external identity: only an imported key with this context answers it.
    /// Null for a plain identity, which only a key that is not imported answers.
    imported: ?Imported = null,

    /// Whether `answer` is a key this query may take: of its version, naming its identity byte for
    /// byte, imported exactly when the offer was and under the same context, and valid.
    pub fn takes(query: Query, answer: External) bool {
        if (answer.version != query.version or !std.mem.eql(u8, answer.identity, query.identity)) return false;
        if ((answer.imported == null) != (query.imported == null)) return false;
        if (query.imported) |imported| if (!std.mem.eql(u8, answer.imported.?.context, imported.context)) return false;
        validate(answer) catch return false;
        return true;
    }
};

/// A server's provisioned keys: `find` returns the key for a query, or null. Its result is
/// copied before `find` is called again; it must name the queried identity exactly. It is a field
/// of the caller's own type, which `find` recovers with `@fieldParentPtr`.
pub const Lookup = struct {
    find: *const fn (lookup: *Lookup, query: Query) ?External,
};

pub fn validate(psk: External) error{InvalidOptions}!void {
    if (psk.identity.len == 0 or psk.identity.len > max_identity) return error.InvalidOptions;
    if (psk.imported) |imported| {
        if (psk.version != .tls13 or imported.context.len > max_context or psk.secret.len < min_imported or psk.secret.len > max_imported) return error.InvalidOptions;
    } else switch (psk.version) {
        .tls13 => if (psk.secret.len != psk.hash.length()) return error.InvalidOptions,
        .tls12 => if (psk.hash != .sha256 or psk.secret.len < min_secret12 or psk.secret.len > max_secret12) return error.InvalidOptions,
    }
    // An all-zero key is the usual stand-in for a missing one.
    for (psk.secret) |b| {
        if (b != 0) break;
    } else return error.InvalidOptions;
}
