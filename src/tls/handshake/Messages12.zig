//! TLS 1.2 handshake messages: Certificate without contexts or entry extensions, the ECDHE
//! ServerKeyExchange, CertificateRequest, ServerHelloDone and ClientKeyExchange (RFC 5246,
//! RFC 8422). Parsed fields borrow their message; every length is checked against its parent.
const std = @import("std");
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
    const group = std.enums.fromInt(Group, try r.int(u16)) orelse return error.IllegalParameter;
    if (group == .x25519_mlkem768) return error.IllegalParameter;
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
    std.debug.assert(params.len <= max_signed - 64);
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

test {
    _ = @import("Messages12_test.zig");
}
