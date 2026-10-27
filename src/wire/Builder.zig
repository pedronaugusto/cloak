//! DER, written: elements appended in order, a constructed element's length patched in when it
//! closes. Lengths are definite and minimal and integers minimal, so what it writes is the one
//! DER encoding of its content and the strict reader reads it back. The bytes sit in a secret
//! owner, so a private key written here leaves no unerased copy as the storage grows; a
//! certificate's, public, are copied out (`toOwnedSlice`), a key's handed over (`take`).
const std = @import("std");
const aegis = @import("aegis");
const Builder = @This();

gpa: std.mem.Allocator,
/// Private: what is written so far.
bytes: aegis.SecretBytes = .empty,

pub const Error = std.mem.Allocator.Error;
/// An open constructed element: where its contents begin.
pub const Mark = struct { at: usize };

pub fn init(gpa: std.mem.Allocator) Builder {
    return .{ .gpa = gpa };
}

pub fn deinit(self: *Builder) void {
    self.bytes.deinit(self.gpa);
}

/// What is written so far, borrowed until the next write.
pub fn written(self: *const Builder) []const u8 {
    return self.bytes.expose(); // aegis: design: a borrow of the builder's bytes, ended by its next write, as SecretBytes.expose's is
}

/// A copy of the bytes written, the caller's, for public DER: the builder is empty after.
pub fn toOwnedSlice(self: *Builder) Error![]u8 {
    const out = try self.gpa.dupe(u8, self.bytes.expose());
    self.bytes.deinit(self.gpa);
    self.bytes = .empty;
    return out;
}

/// The bytes written, in their secret owner, for a private key's DER: the builder is empty
/// after.
pub fn take(self: *Builder) aegis.SecretBytes {
    var out: aegis.SecretBytes = undefined;
    self.bytes.moveInto(&out);
    self.bytes = .empty;
    return out;
}

fn append(self: *Builder, bytes: []const u8) Error!void {
    self.bytes.appendSlice(self.gpa, bytes) catch return error.OutOfMemory;
}

/// Opens an element of `tag` whose length is not known yet; `close` ends it.
pub fn open(self: *Builder, tag: u8) Error!Mark {
    @setRuntimeSafety(true);
    try self.append(&.{ tag, 0 });
    return .{ .at = self.bytes.len() };
}

/// Ends the element `mark` opened: its length goes in, the contents moving up when it needs
/// the long form.
pub fn close(self: *Builder, mark: Mark) Error!void {
    @setRuntimeSafety(true);
    const end = self.bytes.len();
    const len = end - mark.at;
    if (len < 0x80) {
        self.bytes.exposeMut()[mark.at - 1] = @intCast(len); // safe: below 0x80
        return;
    }
    // The long form: the contents move up by the length's bytes.
    const count = @sizeOf(usize) - @clz(len) / 8;
    if (end + count > self.bytes.capacity()) {
        self.bytes.reserve(self.gpa, @max(end + count, 2 * self.bytes.capacity())) catch return error.OutOfMemory;
    }
    // unreachable: reserved above.
    self.bytes.resizeWithinCapacity(end + count) catch unreachable;
    const items = self.bytes.exposeMut();
    @memmove(items[mark.at + count .. end + count], items[mark.at..end]);
    items[mark.at - 1] = 0x80 | @as(u8, @intCast(count)); // safe: a usize has at most eight bytes
    for (0..count) |i| items[mark.at + i] = @truncate(len >> @intCast(8 * (count - 1 - i)));
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
    try self.append(header[0..n]);
    try self.append(value);
}

/// Bytes already DER-encoded, as they are.
pub fn raw(self: *Builder, encoded: []const u8) Error!void {
    try self.append(encoded);
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
    try self.append(&.{0});
    try self.append(m);
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
    try self.append(&.{0});
    try self.append(value);
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
