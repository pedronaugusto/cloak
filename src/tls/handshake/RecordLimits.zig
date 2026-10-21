//! RFC 8449 record_size_limit, as negotiated: `send` the most a protected record this end seals
//! may carry in the peer's terms, `receive` the most one it opens may; each the extension's value,
//! clamped to the version's maximum (2^14 for TLS 1.2, 2^14 + 1 for TLS 1.3, whose count takes in
//! the inner content type and padding). Unnegotiated, both are the version's maximum.
const suites = @import("../crypto/Suite.zig");

send: u16 = max13,
receive: u16 = max13,

/// TLS 1.3's: the inner plaintext's 2^14 bytes and content type.
pub const max13: u16 = (1 << 14) + 1;
pub const max12: u16 = 1 << 14;
/// The smallest value a peer may name (RFC 8449 section 4).
pub const min: u16 = 64;

pub fn max(version: suites.Version) u16 {
    return if (version == .tls13) max13 else max12;
}

/// The most content bytes one record carries under `limit`: TLS 1.3 and DTLS 1.2 with a
/// connection ID (RFC 9146) add a content type inside, TLS 1.2 adds nothing.
pub fn content(limit: u16, inner_type: bool) usize {
    const bound: usize = limit - @intFromBool(inner_type);
    return @min(bound, 1 << 14);
}

/// A caller's `max_fragment`, the most plaintext one record this end sends carries: 64 (RFC 8449's
/// smallest limit) to 2^14; null is 2^14.
pub fn fragment(option: ?u16) error{InvalidOptions}!u16 {
    const value = option orelse return 1 << 14;
    if (value < min or value > 1 << 14) return error.InvalidOptions;
    return value;
}

/// The extension's number (RFC 8449 section 7).
pub const extension: u16 = 28;
