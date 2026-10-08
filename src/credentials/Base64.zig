//! Private armor decoding without character-indexed tables.
//! Length, padding count and final validity are framing decisions. Character
//! classification and byte reconstruction use fixed arithmetic at public offsets.
const std = @import("std");
pub const Error = error{InvalidBase64};

pub fn size(source: []const u8) Error!usize {
    @setRuntimeSafety(true);
    if (source.len % 4 != 0) return error.InvalidBase64;
    if (source.len == 0) return 0;
    const padding: usize = @intFromBool(source[source.len - 1] == '=') + @as(usize, @intFromBool(source[source.len - 2] == '='));
    return source.len / 4 * 3 - padding;
}

pub fn decode(dest: []u8, source: []const u8) Error!void {
    @setRuntimeSafety(true);
    errdefer std.crypto.secureZero(u8, dest);
    const wanted = try size(source);
    if (dest.len != wanted) return error.InvalidBase64;
    var scratch: struct { values: [4]Sextet = @splat(.{ .value = 0, .valid = 0 }), invalid: u8 = 0 } = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&scratch));
    const groups = dest.len / 3;
    for (0..groups) |group| {
        inline for (0..4) |i| {
            sextet(&scratch.values[i], source[group * 4 + i]);
            scratch.invalid |= ~scratch.values[i].valid;
        }
        dest[group * 3] = (scratch.values[0].value << 2) | (scratch.values[1].value >> 4);
        dest[group * 3 + 1] = (scratch.values[1].value << 4) | (scratch.values[2].value >> 2);
        dest[group * 3 + 2] = (scratch.values[2].value << 6) | scratch.values[3].value;
    }
    // Only the publicly visible padding count selects the final group shape.
    const tail = dest.len % 3;
    if (tail != 0) {
        const at = groups * 4;
        for (0..tail + 1) |i| {
            sextet(&scratch.values[i], source[at + i]);
            scratch.invalid |= ~scratch.values[i].valid;
        }
        dest[groups * 3] = (scratch.values[0].value << 2) | (scratch.values[1].value >> 4);
        if (tail == 1) {
            scratch.invalid |= scratch.values[1].value & 15;
        } else {
            dest[groups * 3 + 1] = (scratch.values[1].value << 4) | (scratch.values[2].value >> 2);
            scratch.invalid |= scratch.values[2].value & 3;
        }
        for (source[at + tail + 1 ..]) |c| scratch.invalid |= c ^ '=';
    }
    if (scratch.invalid != 0) return error.InvalidBase64;
}

const Sextet = struct { value: u8, valid: u8 };
// Keep the small classifier separate: inspected baseline x86/AArch64 kernels
// write directly into the wiped owner and create no character/mask stack spills.
// This does not prove erasure of the enclosing decoder's compiler-created copies.
noinline fn sextet(out: *Sextet, c: u8) void {
    @setRuntimeSafety(true);
    const upper = range(c, 'A', 'Z');
    const lower = range(c, 'a', 'z');
    const digit = range(c, '0', '9');
    const plus = range(c, '+', '+');
    const slash = range(c, '/', '/');
    out.* = .{
        .value = ((c -% 'A') & upper) | ((c -% 'a' +% 26) & lower) | ((c -% '0' +% 52) & digit) | (62 & plus) | (63 & slash),
        .valid = upper | lower | digit | plus | slash,
    };
}
fn range(c: u8, low: u8, high: u8) u8 {
    @setRuntimeSafety(true);
    // Each difference lies in [-255,255], so bit 15 detects either exclusion.
    const outside = ((@as(u16, c) -% low) | (@as(u16, high) -% c)) >> 15;
    return @truncate(outside -% 1); // safe: low byte of 0xffff/0 is the desired full/empty mask
}

test {
    @setRuntimeSafety(true);
    _ = @import("Base64_test.zig");
}
