//! A zlib certificate codec for tests, on std's flate: cloak ships no codec; callers bring theirs
//! (in the family, warp's).
const std = @import("std");
const flate = std.compress.flate;
const Compression = @import("../tls/handshake/Compression.zig");

pub const codec: Compression.Codec = .{ .algorithm = .zlib, .decompress = decompress, .compress = compress };

/// Fills exactly `out` from all of `input`: a short or long stream, or bytes after it, fail.
pub fn decompress(_: ?*anyopaque, input: []const u8, out: []u8) Compression.Error!void {
    var reader: std.Io.Reader = .fixed(input);
    var window: [flate.max_window_len]u8 = undefined;
    var d: flate.Decompress = .init(&reader, .zlib, &window);
    d.reader.readSliceAll(out) catch return error.Failed;
    var extra: [1]u8 = undefined;
    if ((d.reader.readSliceShort(&extra) catch return error.Failed) != 0) return error.Failed;
    if (reader.seek != reader.end) return error.Failed;
}

pub fn compress(_: ?*anyopaque, input: []const u8, out: []u8) Compression.Error!usize {
    // std's encoder needs room for at least its header and a little more.
    if (out.len <= 8) return error.Failed;
    var writer: std.Io.Writer = .fixed(out);
    var window: [flate.max_window_len]u8 = undefined;
    var c = flate.Compress.init(&writer, &window, .zlib, .default) catch return error.Failed;
    c.writer.writeAll(input) catch return error.Failed;
    c.finish() catch return error.Failed;
    return writer.end;
}
