//! TLS 1.2 handshake messages: Certificate without contexts or entry extensions, the ECDHE
//! ServerKeyExchange, CertificateRequest, ServerHelloDone, ClientKeyExchange, the plain-PSK forms
//! of the two key exchange messages and the session ticket's NewSessionTicket (RFC 5246,
//! RFC 8422, RFC 4279, RFC 5077). Parsed fields borrow their message; every length is checked against its parent.
const std = @import("std");
const aegis = @import("aegis");
const Reader = @import("../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Group = @import("../crypto/Group.zig").Group;
const Messages = @import("Messages.zig");

pub const ParseError = Messages.ParseError;
pub const BuildError = Messages.BuildError;
pub const max_certificates = Messages.max_certificates;

/// A TLS 1.2 Certificate: the DER of each entry, leaf first.
pub fn certificate(message: []const u8, max_count: usize, max_bytes: usize, out: *[max_certificates][]const u8) ParseError!usize {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .certificate) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    var list = try r.vector(u24);
    try r.finish();
    var count: usize = 0;
    var total: usize = 0;
    while (list.pos != list.bytes.len) {
        const der = (try list.vector(u24)).bytes;
        if (der.len == 0) return error.InvalidMessage;
        if (count == @min(max_count, max_certificates)) return error.CertificateLimit;
        total = std.math.add(usize, total, der.len) catch return error.CertificateLimit;
        if (total > max_bytes) return error.CertificateLimit;
        out[count] = der;
        count += 1;
    }
    return count;
}

/// A TLS 1.2 Certificate of the raw public key type (RFC 7250 section 3): the one
/// SubjectPublicKeyInfo, with no list around it. Empty when the sender has no key, the same bytes
/// as an empty X.509 list (the type's own form is at least one byte).
pub fn rawKey(message: []const u8) ParseError![]const u8 {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .certificate) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const spki = (try r.vector(u24)).bytes;
    try r.finish();
    return spki;
}

/// A raw-key Certificate carrying `spki`, or none (empty).
pub fn buildRawKey(out: []u8, spki: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .certificate);
    if (spki.len > 0xffffff) return error.BufferTooSmall;
    try w.vector(u24, spki);
    return Messages.seal(&w);
}

pub fn buildCertificate(out: []u8, chain: []const []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .certificate);
    const list_at = w.pos;
    try w.int(u24, 0);
    for (chain) |der| try w.vector(u24, der);
    const list_len = w.pos - list_at - 3;
    if (list_len > 0xffffff) return error.BufferTooSmall;
    // safe: the list length was checked against the u24 maximum above.
    std.mem.writeInt(u24, out[list_at..][0..3], @intCast(list_len), .big);
    return Messages.seal(&w);
}

/// The ECDHE parameters and their signature.
pub const ServerKeyExchange = struct {
    group: Group,
    /// The server's public point or X25519 key.
    public: []const u8,
    /// The encoded ServerECDHParams: what the signature covers after the two randoms.
    params: []const u8,
    scheme: u16,
    signature: []const u8,
};

/// A named-curve ServerKeyExchange; explicit curves and unknown groups are refused, and the
/// point length must be exactly the group's.
pub fn serverKeyExchange(message: []const u8) ParseError!ServerKeyExchange {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .server_key_exchange) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    if (try r.int(u8) != 3) return error.IllegalParameter;
    const group: Group = @fromBackingInt(try r.int(u16));
    if (!group.supported() or !group.classical()) return error.IllegalParameter;
    const public = (try r.vector(u8)).bytes;
    if (public.len != group.serverShareLength()) return error.IllegalParameter;
    const params = parsed.bytes[0..r.pos];
    const scheme = try r.int(u16);
    const signature = (try r.vector(u16)).bytes;
    try r.finish();
    if (signature.len == 0) return error.InvalidMessage;
    return .{ .group = group, .public = public, .params = params, .scheme = scheme, .signature = signature };
}

/// The ServerECDHParams of a named group.
pub fn buildParams(out: []u8, group: Group, public: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.int(u8, 3);
    try w.int(u16, @backingInt(group));
    try w.vector(u8, public);
    return out[0..w.pos];
}

pub fn buildServerKeyExchange(out: []u8, params: []const u8, scheme: u16, signature: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .server_key_exchange);
    try w.put(params);
    try w.int(u16, scheme);
    try w.vector(u16, signature);
    return Messages.seal(&w);
}

/// What a ServerKeyExchange signature covers: client random, server random, params.
pub const max_signed = 32 + 32 + 4 + 97;
pub fn signedParams(out: *[max_signed]u8, client_random: *const [32]u8, server_random: *const [32]u8, params: []const u8) []const u8 {
    @setRuntimeSafety(true);
    aegis.assert.invariant(params.len <= max_signed - 64, "the signed parameters fit their buffer");
    @memcpy(out[0..32], client_random);
    @memcpy(out[32..64], server_random);
    @memcpy(out[64..][0..params.len], params);
    return out[0 .. 64 + params.len];
}

/// A TLS 1.2 CertificateRequest: certificate types, signature schemes and CA names. Names are
/// a hint cloak does not use for selection.
pub const CertificateRequest = struct {
    types: []const u8,
    schemes: []const u8,

    pub fn accepts(self: CertificateRequest, scheme: u16) bool {
        @setRuntimeSafety(true);
        var at: usize = 0;
        while (at + 2 <= self.schemes.len) : (at += 2) {
            if (std.mem.readInt(u16, self.schemes[at..][0..2], .big) == scheme) return true;
        }
        return false;
    }
};

pub fn certificateRequest(message: []const u8) ParseError!CertificateRequest {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .certificate_request) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const types = (try r.vector(u8)).bytes;
    const schemes = (try r.vector(u16)).bytes;
    var names = try r.vector(u16);
    try r.finish();
    if (types.len == 0 or schemes.len < 2 or schemes.len % 2 != 0) return error.InvalidMessage;
    while (names.pos != names.bytes.len) {
        if ((try names.vector(u16)).bytes.len == 0) return error.InvalidMessage;
    }
    return .{ .types = types, .schemes = schemes };
}

/// Asks for an ECDSA or RSA client certificate signed with one of `schemes`; no CA names.
pub fn buildCertificateRequest(out: []u8, schemes: []const u16) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .certificate_request);
    // rsa_sign (1) and ecdsa_sign (64).
    try w.put(&.{ 2, 1, 64 });
    // safe: the scheme table holds a dozen entries.
    try w.int(u16, @intCast(schemes.len * 2));
    for (schemes) |scheme| try w.int(u16, scheme);
    try w.int(u16, 0);
    return Messages.seal(&w);
}

pub fn serverHelloDone(message: []const u8) ParseError!void {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .server_hello_done or parsed.bytes.len != 0) return error.InvalidMessage;
}

pub fn buildServerHelloDone(out: []u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .server_hello_done);
    return Messages.seal(&w);
}

/// The client's ECDHE public value; its length must be exactly the group's.
pub fn clientKeyExchange(message: []const u8, group: Group) ParseError![]const u8 {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .client_key_exchange) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const public = (try r.vector(u8)).bytes;
    try r.finish();
    if (public.len != group.clientShareLength()) return error.IllegalParameter;
    return public;
}

pub fn buildClientKeyExchange(out: []u8, public: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .client_key_exchange);
    try w.vector(u8, public);
    return Messages.seal(&w);
}

/// A plain-PSK ClientKeyExchange (RFC 4279 section 2): the identity the client's key goes by, as
/// sent (cloak bounds it when looking it up).
pub fn pskClientKeyExchange(message: []const u8) ParseError![]const u8 {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .client_key_exchange) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const identity = (try r.vector(u16)).bytes;
    try r.finish();
    return identity;
}

pub fn buildPskClientKeyExchange(out: []u8, identity: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .client_key_exchange);
    try w.vector(u16, identity);
    return Messages.seal(&w);
}

/// A plain-PSK ServerKeyExchange: an identity hint, which a client ignores (RFC 4279 section 2
/// leaves its use to the application, and cloak's keys are named by the client alone).
pub fn pskServerKeyExchange(message: []const u8) ParseError![]const u8 {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .server_key_exchange) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const hint = (try r.vector(u16)).bytes;
    try r.finish();
    return hint;
}

pub fn buildPskServerKeyExchange(out: []u8, hint: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .server_key_exchange);
    try w.vector(u16, hint);
    return Messages.seal(&w);
}

/// The plain-PSK premaster secret (RFC 4279 section 2): the key's length, as many zeros, the
/// length again, then the key.
pub const max_premaster = 2 + 64 + 2 + 64;
pub fn pskPremaster(out: *[max_premaster]u8, secret: []const u8) []const u8 {
    @setRuntimeSafety(true);
    aegis.assert.invariant(secret.len <= 64, "a TLS 1.2 key is at most 64 bytes");
    // safe: at most 64.
    const n: u16 = @intCast(secret.len);
    std.mem.writeInt(u16, out[0..2], n, .big);
    @memset(out[2..][0..n], 0);
    std.mem.writeInt(u16, out[2 + n ..][0..2], n, .big);
    @memcpy(out[4 + n ..][0..n], secret);
    return out[0 .. 4 + 2 * @as(usize, n)];
}

/// A TLS 1.2 NewSessionTicket (RFC 5077 section 3.3): the lifetime hint in seconds (zero for
/// none) and the ticket, which may be empty when the server changed its mind.
pub const Ticket = struct { lifetime_hint: u32, ticket: []const u8 };

pub fn newSessionTicket(message: []const u8) ParseError!Ticket {
    @setRuntimeSafety(true);
    const parsed = try Messages.body(message);
    if (parsed.kind != .new_session_ticket) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const hint = try r.int(u32);
    const ticket = (try r.vector(u16)).bytes;
    try r.finish();
    return .{ .lifetime_hint = hint, .ticket = ticket };
}

pub fn buildNewSessionTicket(out: []u8, lifetime_hint: u32, ticket: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try Messages.header(&w, .new_session_ticket);
    try w.int(u32, lifetime_hint);
    try w.vector(u16, ticket);
    return Messages.seal(&w);
}

test {
    _ = @import("Messages12_test.zig");
}
