//! A blocking in-memory byte pipe over `std.Io` synchronization: one task writes, another reads;
//! the writer waits while the ring is full and the reader while it is empty, and closing the
//! write end ends the stream. Two pipes make the duplex transport of two sessions running on
//! tasks of their own.
const std = @import("std");

const Pipe = @This();

io: std.Io,
mutex: std.Io.Mutex = .init,
changed: std.Io.Condition = .init,
ring: []u8,
/// Where the next byte is read.
head: usize = 0,
len: usize = 0,
closed: bool = false,
reader: std.Io.Reader,
writer: std.Io.Writer,

/// `ring` holds bytes in flight; `read_buffer` and `write_buffer` are the interfaces' buffers.
pub fn init(self: *Pipe, io: std.Io, ring: []u8, read_buffer: []u8, write_buffer: []u8) void {
    self.* = .{
        .io = io,
        .ring = ring,
        .reader = .{ .vtable = &.{ .stream = stream }, .buffer = read_buffer, .seek = 0, .end = 0 },
        .writer = .{ .vtable = &.{ .drain = drain }, .buffer = write_buffer },
    };
}

/// Ends the stream once what was written has been read; writes after it fail.
pub fn close(self: *Pipe) void {
    self.mutex.lockUncancelable(self.io);
    defer self.mutex.unlock(self.io);
    self.closed = true;
    self.changed.broadcast(self.io);
}

fn stream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const self: *Pipe = @alignCast(@fieldParentPtr("reader", r)); // the interface is a field of a Pipe
    self.mutex.lock(self.io) catch return error.ReadFailed;
    defer self.mutex.unlock(self.io);
    while (self.len == 0) {
        if (self.closed) return error.EndOfStream;
        self.changed.wait(self.io, &self.mutex) catch return error.ReadFailed;
    }
    const contiguous = @min(self.len, self.ring.len - self.head);
    const dest = limit.slice(try w.writableSliceGreedy(1));
    const n = @min(dest.len, contiguous);
    @memcpy(dest[0..n], self.ring[self.head..][0..n]);
    w.advance(n);
    self.head = (self.head + n) % self.ring.len;
    self.len -= n;
    self.changed.broadcast(self.io);
    return n;
}

fn put(self: *Pipe, bytes: []const u8) std.Io.Writer.Error!void {
    var rest = bytes;
    self.mutex.lock(self.io) catch return error.WriteFailed;
    defer self.mutex.unlock(self.io);
    while (rest.len != 0) {
        while (self.len == self.ring.len and !self.closed) self.changed.wait(self.io, &self.mutex) catch return error.WriteFailed;
        if (self.closed) return error.WriteFailed;
        const tail = (self.head + self.len) % self.ring.len;
        const n = @min(rest.len, self.ring.len - self.len, self.ring.len - tail);
        @memcpy(self.ring[tail..][0..n], rest[0..n]);
        self.len += n;
        rest = rest[n..];
        self.changed.broadcast(self.io);
    }
}

fn drain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const self: *Pipe = @alignCast(@fieldParentPtr("writer", w)); // the interface is a field of a Pipe
    try self.put(w.buffer[0..w.end]);
    w.end = 0;
    var consumed: usize = 0;
    for (data[0 .. data.len - 1]) |slice| {
        try self.put(slice);
        consumed += slice.len;
    }
    for (0..splat) |_| {
        try self.put(data[data.len - 1]);
        consumed += data[data.len - 1].len;
    }
    return consumed;
}
