//! Strict, allocation-free DER. Each Reader is confined to one parent value.
const std = @import("std");
pub const Error = error{ InvalidDer, DerLimit };
pub const Limits = struct { bytes: usize = 65536, elements: usize = 4096, depth: usize = 24 };
pub const Element = struct {
    tag: u8,
    encoded: []const u8,
    value: []const u8,
    pub fn reader(self: Element) Reader {
        @setRuntimeSafety(true);
        return .{ .bytes = self.value };
    }
};
pub const Reader = struct {
    bytes: []const u8,
    offset: usize = 0,
    pub fn empty(self: Reader) bool {
        @setRuntimeSafety(true);
        return self.offset == self.bytes.len;
    }
    pub fn finish(self: Reader) Error!void {
        @setRuntimeSafety(true);
        if (!self.empty()) return error.InvalidDer;
    }
    pub fn peek(self: Reader) ?u8 {
        @setRuntimeSafety(true);
        return if (self.empty()) null else self.bytes[self.offset];
    }
    pub fn next(self: *Reader) Error!Element {
        @setRuntimeSafety(true);
        const start = self.offset;
        if (self.bytes.len - start < 2) return error.InvalidDer;
        const tag = self.bytes[start];
        if (tag & 0x1f == 0x1f or tag == 0) return error.InvalidDer;
        var cursor = start + 2;
        const first = self.bytes[start + 1];
        var len: usize = first;
        if (first & 0x80 != 0) {
            const count: usize = first & 0x7f;
            if (count == 0 or count > @sizeOf(usize) or count > self.bytes.len - cursor) return error.InvalidDer;
            if (self.bytes[cursor] == 0) return error.InvalidDer;
            len = 0;
            for (self.bytes[cursor..][0..count]) |b| len = (len << 8) | b;
            cursor += count;
            if (len < 128) return error.InvalidDer;
        }
        if (len > self.bytes.len - cursor) return error.InvalidDer;
        self.offset = cursor + len;
        return .{ .tag = tag, .encoded = self.bytes[start..self.offset], .value = self.bytes[cursor..self.offset] };
    }
    pub fn expect(self: *Reader, tag: u8) Error!Element {
        @setRuntimeSafety(true);
        const e = try self.next();
        if (e.tag != tag) return error.InvalidDer;
        return e;
    }
};
pub fn single(bytes: []const u8, tag: u8) Error!Element {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = bytes };
    const e = try r.expect(tag);
    try r.finish();
    return e;
}
pub fn integer(bytes: []const u8) Error![]const u8 {
    @setRuntimeSafety(true);
    if (bytes.len == 0 or bytes[0] & 0x80 != 0) return error.InvalidDer;
    if (bytes.len > 1 and bytes[0] == 0) {
        if (bytes[1] & 0x80 == 0) return error.InvalidDer;
        return bytes[1..];
    }
    return bytes;
}
pub fn number(bytes: []const u8) Error!usize {
    @setRuntimeSafety(true);
    const b = try integer(bytes);
    if (b.len > @sizeOf(usize)) return error.DerLimit;
    var n: usize = 0;
    for (b) |v| n = (n << 8) | v;
    return n;
}
pub fn boolean(bytes: []const u8) Error!bool {
    @setRuntimeSafety(true);
    if (bytes.len != 1 or (bytes[0] != 0 and bytes[0] != 255)) return error.InvalidDer;
    return bytes[0] != 0;
}
pub fn bits(bytes: []const u8) Error![]const u8 {
    @setRuntimeSafety(true);
    if (bytes.len == 0 or bytes[0] > 7) return error.InvalidDer;
    if (bytes.len == 1 and bytes[0] != 0) return error.InvalidDer;
    // safe: the unused-bit count was checked to be at most seven above.
    if (bytes.len > 1 and bytes[0] != 0 and bytes[bytes.len - 1] & ((@as(u8, 1) << @intCast(bytes[0])) - 1) != 0) return error.InvalidDer;
    return bytes[1..];
}
pub fn octetBits(bytes: []const u8) Error![]const u8 {
    @setRuntimeSafety(true);
    const b = try bits(bytes);
    if (bytes[0] != 0) return error.InvalidDer;
    return b;
}
pub fn oid(bytes: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (bytes.len == 0) return error.InvalidDer;
    var begin = true;
    for (bytes) |b| {
        if (begin and b == 0x80) return error.InvalidDer;
        begin = b & 0x80 == 0;
    }
    if (!begin) return error.InvalidDer;
}
/// Validate constructed contents, canonical primitive representations and SET ordering.
pub fn validate(bytes: []const u8, limits: Limits) Error!void {
    @setRuntimeSafety(true);
    if (limits.depth > 64) return error.DerLimit; // Recursive parser stack has a hard ceiling.
    if (bytes.len > limits.bytes) return error.DerLimit;
    var remaining = limits.elements;
    try tree(bytes, limits.depth, &remaining, false);
}
fn tree(bytes: []const u8, depth: usize, remaining: *usize, set: bool) Error!void {
    @setRuntimeSafety(true);
    if (depth == 0) return error.DerLimit;
    var r: Reader = .{ .bytes = bytes };
    var prior: ?[]const u8 = null;
    while (!r.empty()) {
        if (remaining.* == 0) return error.DerLimit;
        remaining.* -= 1;
        const e = try r.next();
        if (set) {
            if (prior) |p| if (std.mem.order(u8, p, e.encoded) == .gt) return error.InvalidDer;
            prior = e.encoded;
        }
        if (e.tag & 0xc0 == 0) {
            const id = e.tag & 0x1f;
            if (id == 16 or id == 17) {
                if (e.tag & 0x20 == 0) return error.InvalidDer;
            } else if (e.tag & 0x20 != 0) return error.InvalidDer;
            switch (id) {
                1 => {
                    _ = try boolean(e.value);
                },
                2, 10 => {
                    if (e.value.len == 0) return error.InvalidDer;
                    if (e.value.len > 1 and ((e.value[0] == 0 and e.value[1] & 0x80 == 0) or (e.value[0] == 255 and e.value[1] & 0x80 != 0))) return error.InvalidDer;
                },
                3 => {
                    _ = try bits(e.value);
                },
                5 => if (e.value.len != 0) return error.InvalidDer,
                6 => try oid(e.value),
                12 => if (!std.unicode.utf8ValidateSlice(e.value)) return error.InvalidDer,
                else => {},
            }
        }
        if (e.tag & 0x20 != 0) try tree(e.value, depth - 1, remaining, e.tag == 0x31);
    }
}
test {
    _ = @import("Der_test.zig");
}
