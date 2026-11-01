//! Certificate compression (RFC 8879) through codecs the caller supplies: cloak holds no
//! compression code. A codec names its algorithm and gives a decoder, an encoder or both; the
//! handshake bounds every size around them and commits the compressed message to the transcript
//! as it crossed the wire.
const std = @import("std");
const Reader = @import("../../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");

/// CertificateCompressionAlgorithm (RFC 8879 section 7.3).
pub const Algorithm = enum(u16) { zlib = 1, brotli = 2, zstd = 3, _ };

pub const Error = error{Failed};

/// A caller's codec. `decompress` must fill exactly `out` from all of `input` and fail on any
/// other outcome (short, long, trailing data, a malformed stream); `compress` writes into `out`
/// and returns the length, or fails when the result does not fit. Neither may keep the slices.
/// Both run inside the handshake, so their work is the caller's to bound beyond the sizes cloak
/// enforces (at most `max_uncompressed` bytes out). A codec is a field of the caller's own type,
/// which the functions recover with `@fieldParentPtr`.
pub const Codec = struct {
    algorithm: Algorithm,
    decompress: ?*const fn (codec: *Codec, input: []const u8, out: []u8) Error!void = null,
    compress: ?*const fn (codec: *Codec, input: []const u8, out: []u8) Error!usize = null,
};

/// Codecs one side may list.
pub const max_codecs = 8;

/// The extension's code point (RFC 8879 section 3) and the message's type (section 4).
pub const extension_id: u16 = 27;
pub const message_type: u8 = 25;

pub const ValidateError = error{InvalidOptions};

/// At most `max_codecs`, each algorithm once and with the direction this side uses.
pub fn validate(codecs: []const *Codec, direction: enum { decompress, compress }) ValidateError!void {
    @setRuntimeSafety(true);
    if (codecs.len > max_codecs) return error.InvalidOptions;
    for (codecs, 0..) |codec, i| {
        if (@backingInt(codec.algorithm) == 0) return error.InvalidOptions;
        const has = switch (direction) {
            .decompress => codec.decompress != null,
            .compress => codec.compress != null,
        };
        if (!has) return error.InvalidOptions;
        for (codecs[0..i]) |old| if (old.algorithm == codec.algorithm) return error.InvalidOptions;
    }
}

/// The compress_certificate extension body: the algorithms of `codecs`, in order.
pub fn writeExtension(w: *Writer, codecs: []const *Codec) Writer.WriteError!void {
    @setRuntimeSafety(true);
    try w.int(u16, extension_id);
    try w.int(u16, @intCast(1 + 2 * codecs.len)); // at most `max_codecs`
    try w.int(u8, @intCast(2 * codecs.len)); // at most `max_codecs`
    for (codecs) |codec| try w.int(u16, @backingInt(codec.algorithm));
}

pub const ParseError = error{ DecodeError, IllegalParameter, BadCertificate, HandshakeLimit };

/// Checks a compress_certificate extension body: a list of 2 to 254 bytes, two per algorithm.
pub fn checkExtension(bytes: []const u8) ParseError!void {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = bytes };
    const list = (r.vector(u8) catch return error.DecodeError).bytes;
    r.finish() catch return error.DecodeError;
    if (list.len < 2 or list.len % 2 != 0) return error.DecodeError;
}

/// The first of `codecs` (the server's order) with an encoder whose algorithm the peer listed.
pub fn choose(codecs: []const *Codec, offered: []const u8) ?*Codec {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = offered };
    const list = (r.vector(u8) catch return null).bytes;
    for (codecs) |codec| {
        if (codec.compress == null) continue;
        var at: usize = 0;
        while (at + 2 <= list.len) : (at += 2) {
            if (std.mem.readInt(u16, list[at..][0..2], .big) == @backingInt(codec.algorithm)) return codec;
        }
    }
    return null;
}

/// A CompressedCertificate message's fields.
pub const Compressed = struct { algorithm: Algorithm, length: u24, data: []const u8 };

/// Parses a whole CompressedCertificate message.
pub fn parse(message: []const u8) ParseError!Compressed {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != message_type or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.DecodeError;
    var r: Reader = .{ .bytes = message[4..] };
    const algorithm: Algorithm = @fromBackingInt(@intCast(r.int(u16) catch return error.DecodeError));
    const length = r.int(u24) catch return error.DecodeError;
    const data = (r.vector(u24) catch return error.DecodeError).bytes;
    r.finish() catch return error.DecodeError;
    if (data.len == 0 or length == 0) return error.DecodeError;
    return .{ .algorithm = algorithm, .length = length, .data = data };
}

/// Decompresses a CompressedCertificate into a whole Certificate message (header included),
/// allocated. The algorithm must be one this side offered; the declared length is bounded by
/// `max_message` before anything is allocated; the codec must produce exactly that many bytes
/// (RFC 8879 section 4: bad_certificate otherwise).
pub fn decompress(gpa: std.mem.Allocator, codecs: []const *Codec, compressed: Compressed, max_message: usize) (ParseError || std.mem.Allocator.Error)![]u8 {
    @setRuntimeSafety(true);
    const codec = for (codecs) |codec| {
        if (codec.algorithm == compressed.algorithm and codec.decompress != null) break codec;
    } else return error.IllegalParameter;
    if (@as(usize, compressed.length) + 4 > max_message) return error.HandshakeLimit;
    const out = try gpa.alloc(u8, 4 + @as(usize, compressed.length));
    errdefer gpa.free(out);
    @memset(out, 0);
    out[0] = 11;
    std.mem.writeInt(u24, out[1..4], compressed.length, .big);
    codec.decompress.?(codec, compressed.data, out[4..]) catch return error.BadCertificate;
    return out;
}

/// A CompressedCertificate carrying `certificate` (a whole Certificate message) compressed by
/// `codec`, written into `out`; null when the codec fails or gains nothing, and the plain
/// message goes instead.
pub fn build(out: []u8, codec: *Codec, certificate: []const u8) ?[]u8 {
    @setRuntimeSafety(true);
    const body = certificate[4..];
    if (out.len <= 12 or body.len > std.math.maxInt(u24)) return null;
    // Only a message smaller than the plain one is worth sending.
    const room = @min(out.len - 12, certificate.len -| 13);
    if (room == 0) return null;
    const n = codec.compress.?(codec, body, out[12..][0..room]) catch return null;
    if (n == 0 or n > room) return null;
    out[0] = message_type;
    std.mem.writeInt(u24, out[1..4], @intCast(8 + n), .big); // smaller than the certificate
    std.mem.writeInt(u16, out[4..6], @backingInt(codec.algorithm), .big);
    std.mem.writeInt(u24, out[6..9], @intCast(body.len), .big); // checked above
    std.mem.writeInt(u24, out[9..12], @intCast(n), .big); // below the certificate's length
    return out[0 .. 12 + n];
}

test {
    _ = @import("Compression_test.zig");
}
