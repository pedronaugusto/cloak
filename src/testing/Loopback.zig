//! A synchronous in-memory transport between a `Session` and a scripted `Peer`: bytes the
//! session writes reach the peer at once, and the peer's replies are what it reads.
const std = @import("std");

pub fn Loopback(comptime PeerType: type) type {
    return struct {
        const Self = @This();

        peer: *PeerType,
        reader: std.Io.Reader,
        writer: std.Io.Writer,
        /// Stop delivering peer bytes after this many (truncation tests).
        deliver_limit: usize = std.math.maxInt(usize),
        delivered: usize = 0,
        write_buffer: [0]u8 = .{},
        read_buffer: [0]u8 = .{},

        pub fn init(self: *Self, peer: *PeerType, read_buffer: []u8, write_buffer: []u8) void {
            self.* = .{
                .peer = peer,
                .reader = .{ .vtable = &.{ .stream = stream }, .buffer = read_buffer, .seek = 0, .end = 0 },
                .writer = .{ .vtable = &.{ .drain = drain }, .buffer = write_buffer },
            };
        }

        fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
            const self: *Self = @fieldParentPtr("reader", r);
            const pending = self.peer.pending();
            const allowed = @min(pending.len, self.deliver_limit - self.delivered);
            if (allowed == 0) return error.EndOfStream;
            const n = limit.minInt(allowed);
            const written = try w.write(pending[0..n]);
            self.peer.drained(written);
            self.delivered += written;
            return written;
        }

        fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
            const self: *Self = @fieldParentPtr("writer", w);
            self.peer.feed(w.buffer[0..w.end]) catch return error.WriteFailed;
            w.end = 0;
            var consumed: usize = 0;
            for (data[0 .. data.len - 1]) |slice| {
                self.peer.feed(slice) catch return error.WriteFailed;
                consumed += slice.len;
            }
            for (0..splat) |_| {
                self.peer.feed(data[data.len - 1]) catch return error.WriteFailed;
                consumed += data[data.len - 1].len;
            }
            return consumed;
        }
    };
}
