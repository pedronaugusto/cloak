//! BER to DER, bounded: indefinite lengths become definite and minimal, and constructed
//! universal strings become one primitive string. Containers that BER writers produce (PKCS#12
//! from NSS and Windows, PKCS#7) are normalised once and then read by the strict DER reader;
//! nothing else is reinterpreted. Two passes over the input, `measure` then `write`, so the
//! output is exactly sized and the caller chooses its owner (a secret's or not).
const std = @import("std");
const aegis = @import("aegis");
const Checked = aegis.int.Checked(usize);
const Der = @import("Der.zig");
const header = Der.header;
const headerLength = Der.headerLength;
pub const Error = error{ InvalidDer, DerLimit };
pub const Limits = struct { depth: usize = 24, elements: usize = 16384 };

/// The DER length of `bytes`, a sequence of BER elements, within `limits`.
pub fn measure(bytes: []const u8, limits: Limits) Error!usize {
    @setRuntimeSafety(true);
    if (limits.depth > 64) return error.DerLimit; // The recursion has a hard ceiling.
    var remaining = limits.elements;
    var at: usize = 0;
    var total: usize = 0;
    while (at < bytes.len) {
        const element = try parse(bytes, at, limits.depth, &remaining);
        total = (Checked.init(total).add(element.der) catch return error.DerLimit).raw();
        at = element.end;
    }
    return total;
}

/// Writes the DER of `bytes` into `out`, which is exactly `measure(bytes, limits)` long.
pub fn write(bytes: []const u8, limits: Limits, out: []u8) Error!void {
    @setRuntimeSafety(true);
    var at: usize = 0;
    var written: usize = 0;
    var remaining = limits.elements;
    while (at < bytes.len) {
        const element = try parse(bytes, at, limits.depth, &remaining);
        written = emit(bytes, element, out, written);
        at = element.end;
    }
    std.debug.assert(written == out.len);
}

/// `measure` and `write` into a new allocation.
pub fn toDer(gpa: std.mem.Allocator, bytes: []const u8, limits: Limits) (Error || std.mem.Allocator.Error)![]u8 {
    @setRuntimeSafety(true);
    const out = try gpa.alloc(u8, try measure(bytes, limits));
    errdefer gpa.free(out);
    try write(bytes, limits, out);
    return out;
}

/// One parsed BER element: where its contents are, how it ends, and its DER size.
const Element = struct {
    tag: u8,
    /// The contents: for an indefinite length, through the end-of-contents octets' start.
    start: usize,
    stop: usize,
    /// Just past the element (after its end-of-contents octets when indefinite).
    end: usize,
    /// The DER contents' length, and the whole element's.
    content: usize,
    der: usize,
    /// A constructed universal string, written as its primitive form.
    flatten: bool,
};

fn parse(bytes: []const u8, at: usize, depth: usize, remaining: *usize) Error!Element {
    @setRuntimeSafety(true);
    if (depth == 0) return error.DerLimit;
    if (remaining.* == 0) return error.DerLimit;
    remaining.* -= 1;
    if (bytes.len - at < 2) return error.InvalidDer;
    const tag = bytes[at];
    // High tag numbers do not occur in the containers this serves; tag zero is end-of-contents.
    if (tag & 0x1f == 0x1f or tag == 0) return error.InvalidDer;
    const constructed = tag & 0x20 != 0;
    var cursor = at + 2;
    const first = bytes[at + 1];
    var element: Element = .{ .tag = tag, .start = undefined, .stop = undefined, .end = undefined, .content = 0, .der = 0, .flatten = false };
    // Universal string types (BIT STRING excepted: its unused-bits octet does not concatenate).
    const string = tag & 0xc0 == 0 and switch (tag & 0x1f) {
        4, 12, 18, 19, 20, 21, 22, 25, 26, 27, 28, 30 => true,
        else => false,
    };
    if (first == 0x80) {
        if (!constructed) return error.InvalidDer;
        element.start = cursor;
        while (true) {
            if (bytes.len - cursor < 2) return error.InvalidDer;
            if (bytes[cursor] == 0 and bytes[cursor + 1] == 0) break;
            const child = try parse(bytes, cursor, depth - 1, remaining);
            if (string and child.tag != tag & 0xdf and child.tag != tag) return error.InvalidDer;
            element.content = (Checked.init(element.content).add(if (string) child.content else child.der) catch return error.DerLimit).raw();
            cursor = child.end;
        }
        element.stop = cursor;
        element.end = cursor + 2;
    } else {
        var len: usize = first;
        if (first & 0x80 != 0) {
            const count: usize = first & 0x7f;
            if (count > @sizeOf(usize) or count > bytes.len - cursor) return error.InvalidDer;
            len = 0;
            for (bytes[cursor..][0..count]) |b| {
                const shifted = Checked.init(len).shl(8) catch return error.DerLimit;
                len = (shifted.add(b) catch return error.DerLimit).raw();
            }
            cursor += count;
        }
        if (len > bytes.len - cursor) return error.InvalidDer;
        element.start = cursor;
        element.stop = cursor + len;
        element.end = cursor + len;
        if (constructed) {
            var inner = element.start;
            while (inner < element.stop) {
                const child = try parse(bytes[0..element.stop], inner, depth - 1, remaining);
                if (string and child.tag != tag & 0xdf and child.tag != tag) return error.InvalidDer;
                element.content = (Checked.init(element.content).add(if (string) child.content else child.der) catch return error.DerLimit).raw();
                inner = child.end;
            }
        } else element.content = len;
    }
    element.flatten = constructed and string;
    element.der = (Checked.init(headerLength(element.content)).add(element.content) catch return error.DerLimit).raw();
    return element;
}

/// Writes `element` (already parsed and bounded) at `out[at..]`; returns the offset after it.
fn emit(bytes: []const u8, element: Element, out: []u8, at: usize) usize {
    @setRuntimeSafety(true);
    var next = header(out, at, if (element.flatten) element.tag & 0xdf else element.tag, element.content);
    if (element.tag & 0x20 == 0) {
        @memcpy(out[next..][0..element.content], bytes[element.start..element.stop]);
        return next + element.content;
    }
    next = contents(bytes, element, out, next);
    return next;
}

/// The children of a constructed element, as DER, or their concatenated strings when it flattens.
fn contents(bytes: []const u8, element: Element, out: []u8, at: usize) usize {
    @setRuntimeSafety(true);
    var next = at;
    var cursor = element.start;
    var budget: usize = std.math.maxInt(usize);
    while (cursor < element.stop) {
        // unreachable: the element was parsed whole within the same bounds.
        const child = parse(bytes[0..element.stop], cursor, 64, &budget) catch unreachable;
        if (element.flatten) {
            if (child.tag & 0x20 == 0) {
                @memcpy(out[next..][0..child.content], bytes[child.start..child.stop]);
                next += child.content;
            } else next = contents(bytes, child, out, next);
        } else next = emit(bytes, child, out, next);
        cursor = child.end;
    }
    return next;
}

test {
    _ = @import("Ber_test.zig");
}
