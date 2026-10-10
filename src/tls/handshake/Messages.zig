//! TLS 1.3 handshake messages after the hello family. Parsed fields borrow their message.
const std = @import("std");
const aegis = @import("aegis");
const Reader = @import("../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Extensions = @import("../wire/Extensions.zig");

pub const Type = enum(u8) {
    server_hello = 2,
    new_session_ticket = 4,
    encrypted_extensions = 8,
    certificate = 11,
    certificate_request = 13,
    certificate_verify = 15,
    finished = 20,
    key_update = 24,
    _,
};

pub const ParseError = Reader.ReadError || Extensions.NextError || error{
    InvalidMessage,
    EmptyCertificate,
    CertificateLimit,
    UnsolicitedExtension,
    MissingExtension,
    IllegalParameter,
};

/// Splits a message into type and body after checking the enclosing length exactly.
pub fn body(message: []const u8) ParseError!struct { kind: Type, bytes: []const u8 } {
    @setRuntimeSafety(true);
    if (message.len < 4 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    return .{ .kind = @fromBackingInt(@intCast(message[0])), .bytes = message[4..] };
}

pub const max_certificates = 16;

/// A server Certificate: the context and the DER of each entry, leaf first.
pub const Certificates = struct {
    context: []const u8,
    count: usize,
    total_bytes: usize,
};

/// Parses a Certificate message into `out`. No entry extension is accepted: the client
/// offers none (no status_request, no SCT), so any extension is unsolicited.
pub fn certificate(message: []const u8, max_count: usize, max_bytes: usize, out: *[max_certificates][]const u8) ParseError!Certificates {
    @setRuntimeSafety(true);
    const parsed = try body(message);
    if (parsed.kind != .certificate) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const context = (try r.vector(u8)).bytes;
    var list = try r.vector(u24);
    try r.finish();
    var count: usize = 0;
    var total: usize = 0;
    while (list.pos != list.bytes.len) {
        const der = (try list.vector(u24)).bytes;
        if (der.len == 0) return error.InvalidMessage;
        const extensions = (try list.vector(u16)).bytes;
        if (extensions.len != 0) return error.UnsolicitedExtension;
        if (count == @min(max_count, max_certificates)) return error.CertificateLimit;
        total = (aegis.int.Checked(usize).init(total).add(der.len) catch return error.CertificateLimit).raw();
        if (total > max_bytes) return error.CertificateLimit;
        out[count] = der;
        count += 1;
    }
    return .{ .context = context, .count = count, .total_bytes = total };
}

/// Borrowed view of a CertificateRequest.
pub const CertificateRequest = struct {
    context: []const u8,
    /// signature_algorithms body: even-length list of two-byte scheme identifiers.
    schemes: []const u8,

    /// Whether the server accepts a given scheme for the client's CertificateVerify.
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
    const parsed = try body(message);
    if (parsed.kind != .certificate_request) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const context = (try r.vector(u8)).bytes;
    var ext: Extensions = .{ .reader = try r.vector(u16) };
    try r.finish();
    var schemes: ?[]const u8 = null;
    while (try ext.next()) |item| {
        if (item.id != 13) continue;
        var value: Reader = .{ .bytes = item.bytes };
        const list = (try value.vector(u16)).bytes;
        try value.finish();
        if (list.len < 2 or list.len % 2 != 0) return error.InvalidMessage;
        schemes = list;
    }
    return .{ .context = context, .schemes = schemes orelse return error.MissingExtension };
}

pub const CertificateVerify = struct { scheme: u16, signature: []const u8 };

pub fn certificateVerify(message: []const u8) ParseError!CertificateVerify {
    @setRuntimeSafety(true);
    const parsed = try body(message);
    if (parsed.kind != .certificate_verify) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const scheme = try r.int(u16);
    const signature = (try r.vector(u16)).bytes;
    try r.finish();
    return .{ .scheme = scheme, .signature = signature };
}

/// Returns verify_data of a Finished message of exactly `len` bytes.
pub fn finished(message: []const u8, len: usize) ParseError![]const u8 {
    @setRuntimeSafety(true);
    const parsed = try body(message);
    if (parsed.kind != .finished or parsed.bytes.len != len) return error.InvalidMessage;
    return parsed.bytes;
}

/// Lifetimes above seven days are illegal (RFC 8446 section 4.6.1).
pub const max_ticket_lifetime = 7 * 24 * 60 * 60;

pub const Ticket = struct { lifetime: u32, age_add: u32, nonce: []const u8, ticket: []const u8 };

/// Validates a NewSessionTicket. Unknown extensions are ignored; early_data must be
/// exactly a four-byte limit because the client never uses it.
pub fn newSessionTicket(message: []const u8) ParseError!Ticket {
    @setRuntimeSafety(true);
    const parsed = try body(message);
    if (parsed.kind != .new_session_ticket) return error.InvalidMessage;
    var r: Reader = .{ .bytes = parsed.bytes };
    const lifetime = try r.int(u32);
    const age_add = try r.int(u32);
    const nonce = (try r.vector(u8)).bytes;
    const ticket = (try r.vector(u16)).bytes;
    var ext: Extensions = .{ .reader = try r.vector(u16) };
    try r.finish();
    if (ticket.len == 0 or lifetime > max_ticket_lifetime) return error.IllegalParameter;
    while (try ext.next()) |item| if (item.id == 42 and item.bytes.len != 4) return error.InvalidMessage;
    return .{ .lifetime = lifetime, .age_add = age_add, .nonce = nonce, .ticket = ticket };
}

/// Returns whether the peer asks for an update in return.
pub fn keyUpdate(message: []const u8) ParseError!bool {
    @setRuntimeSafety(true);
    const parsed = try body(message);
    if (parsed.kind != .key_update or parsed.bytes.len != 1) return error.InvalidMessage;
    return switch (parsed.bytes[0]) {
        0 => false,
        1 => true,
        else => error.IllegalParameter,
    };
}

pub const BuildError = Writer.WriteError;

fn header(w: *Writer, kind: Type) BuildError!void {
    try w.int(u8, @backingInt(kind));
    try w.int(u24, 0);
}

fn seal(w: *Writer) []u8 {
    @setRuntimeSafety(true);
    // safe: every builder bounds its body below 2^24 before this length is written.
    std.mem.writeInt(u24, w.bytes[1..4], @intCast(w.pos - 4), .big);
    return w.bytes[0..w.pos];
}

pub fn buildFinished(out: []u8, verify_data: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try header(&w, .finished);
    try w.put(verify_data);
    return seal(&w);
}

pub fn buildKeyUpdate(out: []u8, request_peer: bool) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try header(&w, .key_update);
    try w.int(u8, @intFromBool(request_peer));
    return seal(&w);
}

/// A Certificate with an empty context and one entry per DER, each without extensions.
pub fn buildCertificate(out: []u8, context: []const u8, chain: []const []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try header(&w, .certificate);
    try w.vector(u8, context);
    const list_at = w.pos;
    try w.int(u24, 0);
    for (chain) |der| {
        if (der.len > 0xffffff) return error.BufferTooSmall;
        // safe: certificate length was just bounded by the u24 maximum.
        try w.int(u24, @intCast(der.len));
        try w.put(der);
        try w.int(u16, 0);
    }
    const list_len = w.pos - list_at - 3;
    if (list_len > 0xffffff) return error.BufferTooSmall;
    // safe: the list length was checked against the u24 maximum above.
    std.mem.writeInt(u24, out[list_at..][0..3], @intCast(list_len), .big);
    return seal(&w);
}

/// A CertificateRequest with an empty context asking for these signature schemes.
pub fn buildCertificateRequest(out: []u8, schemes: []const u16) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try header(&w, .certificate_request);
    try w.int(u8, 0);
    // safe: the extension is four bytes of header and the list, bounded by the scheme table.
    try w.int(u16, @intCast(6 + schemes.len * 2));
    try w.int(u16, 13);
    try w.int(u16, @intCast(2 + schemes.len * 2));
    try w.int(u16, @intCast(schemes.len * 2));
    for (schemes) |scheme| try w.int(u16, scheme);
    return seal(&w);
}

pub fn buildCertificateVerify(out: []u8, scheme: u16, signature: []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try header(&w, .certificate_verify);
    try w.int(u16, scheme);
    try w.vector(u16, signature);
    return seal(&w);
}

/// Bytes the CertificateVerify signature covers: 64 spaces, the context label, a zero
/// separator and the transcript hash (RFC 8446 section 4.4.3).
pub const max_signed = 64 + 33 + 1 + 48;
pub fn signedContent(out: *[max_signed]u8, server: bool, transcript: []const u8) []const u8 {
    @setRuntimeSafety(true);
    const label = if (server) "TLS 1.3, server CertificateVerify" else "TLS 1.3, client CertificateVerify";
    @memset(out[0..64], 0x20);
    @memcpy(out[64..][0..label.len], label);
    out[64 + label.len] = 0;
    @memcpy(out[65 + label.len ..][0..transcript.len], transcript);
    return out[0 .. 65 + label.len + transcript.len];
}

test {
    _ = @import("Messages_test.zig");
}
