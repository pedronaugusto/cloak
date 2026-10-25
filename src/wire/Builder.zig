//! DER, written: elements appended in order, a constructed element's length patched in when it
//! closes. Lengths are definite and minimal and integers minimal, so what it writes is the one
//! DER encoding of its content and the strict reader reads it back. The caller owns the bytes.
const std = @import("std");
const Builder = @This();

gpa: std.mem.Allocator,
bytes: std.ArrayList(u8) = .empty,

pub const Error = std.mem.Allocator.Error;
/// An open constructed element: where its contents begin.
pub const Mark = struct { at: usize };

pub fn init(gpa: std.mem.Allocator) Builder {
    return .{ .gpa = gpa };
}

pub fn deinit(self: *Builder) void {
    self.bytes.deinit(self.gpa);
}

/// The bytes written, the caller's: the builder is empty after.
pub fn toOwnedSlice(self: *Builder) Error![]u8 {
    return self.bytes.toOwnedSlice(self.gpa);
}

/// Opens an element of `tag` whose length is not known yet; `close` ends it.
pub fn open(self: *Builder, tag: u8) Error!Mark {
    @setRuntimeSafety(true);
    try self.bytes.appendSlice(self.gpa, &.{ tag, 0 });
    return .{ .at = self.bytes.items.len };
}

/// Ends the element `mark` opened: its length goes in, the contents moving up when it needs
/// the long form.
pub fn close(self: *Builder, mark: Mark) Error!void {
    @setRuntimeSafety(true);
    const len = self.bytes.items.len - mark.at;
    if (len < 0x80) {
        // safe: below 0x80.
        self.bytes.items[mark.at - 1] = @intCast(len);
        return;
    }
    const count = @sizeOf(usize) - @clz(len) / 8;
    const zeros: [8]u8 = @splat(0);
    try self.bytes.insertSlice(self.gpa, mark.at, zeros[0..count]);
    // safe: a usize has at most eight bytes.
    self.bytes.items[mark.at - 1] = 0x80 | @as(u8, @intCast(count));
    for (0..count) |i| self.bytes.items[mark.at + i] = @truncate(len >> @intCast(8 * (count - 1 - i)));
}

/// A primitive element of `tag` holding `value`.
pub fn element(self: *Builder, tag: u8, value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var header: [10]u8 = undefined;
    header[0] = tag;
    var n: usize = 2;
    if (value.len < 0x80) {
        header[1] = @intCast(value.len); // safe: below 0x80.
    } else {
        const count = @sizeOf(usize) - @clz(value.len) / 8;
        header[1] = 0x80 | @as(u8, @intCast(count)); // safe: at most eight.
        for (0..count) |i| header[2 + i] = @truncate(value.len >> @intCast(8 * (count - 1 - i)));
        n += count;
    }
    try self.bytes.appendSlice(self.gpa, header[0..n]);
    try self.bytes.appendSlice(self.gpa, value);
}

/// Bytes already DER-encoded, as they are.
pub fn raw(self: *Builder, encoded: []const u8) Error!void {
    try self.bytes.appendSlice(self.gpa, encoded);
}

/// A non-negative INTEGER from its big-endian magnitude: leading zeros dropped, one added
/// when the top bit is set.
pub fn unsigned(self: *Builder, magnitude: []const u8) Error!void {
    @setRuntimeSafety(true);
    var m = magnitude;
    while (m.len > 1 and m[0] == 0) m = m[1..];
    if (m.len == 0) return self.element(0x02, &.{0});
    if (m[0] & 0x80 == 0) return self.element(0x02, m);
    // A zero byte first keeps it positive; open and close only write the length.
    const mark = try self.open(0x02);
    try self.bytes.append(self.gpa, 0);
    try self.bytes.appendSlice(self.gpa, m);
    try self.close(mark);
}

/// A small non-negative INTEGER.
pub fn small(self: *Builder, value: u64) Error!void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .big);
    return self.unsigned(&bytes);
}

/// A BOOLEAN.
pub fn boolean(self: *Builder, value: bool) Error!void {
    return self.element(0x01, &.{if (value) 0xff else 0});
}

/// A BIT STRING with no unused bits.
pub fn bits(self: *Builder, value: []const u8) Error!void {
    @setRuntimeSafety(true);
    const mark = try self.open(0x03);
    try self.bytes.append(self.gpa, 0);
    try self.bytes.appendSlice(self.gpa, value);
    try self.close(mark);
}

/// A named-bit BIT STRING (KeyUsage's form): bit 0 is the most significant bit of the first
/// byte; trailing zero bits are dropped (X.690 11.2.2).
pub fn namedBits(self: *Builder, set: u16) Error!void {
    @setRuntimeSafety(true);
    // Bits 0..15 in the order the encoding puts them.
    const value = @bitReverse(set);
    if (value == 0) return self.element(0x03, &.{0});
    const bytes: [2]u8 = .{ @truncate(value >> 8), @truncate(value) };
    const used: usize = if (bytes[1] != 0) 2 else 1;
    const last = bytes[used - 1];
    // safe: the trailing zero count of a nonzero byte is at most seven.
    const unused: u8 = @ctz(last);
    const encoded: [3]u8 = .{ unused, bytes[0], bytes[1] };
    try self.element(0x03, encoded[0 .. used + 1]);
}

test {
    _ = @import("Builder_test.zig");
}
