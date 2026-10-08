const std = @import("std");
const Der = @import("../wire/Der.zig");
pub const Error = Der.Error || error{ InvalidName, UnsupportedName };
pub fn validate(encoded: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = (try Der.single(encoded, 0x30)).reader();
    var count: usize = 0;
    while (!r.empty()) {
        var set = (try r.expect(0x31)).reader();
        if (set.empty()) return error.InvalidName;
        while (!set.empty()) {
            count += 1;
            if (count > 128) return error.DerLimit;
            var attr = (try set.expect(0x30)).reader();
            try Der.oid((try attr.expect(6)).value);
            const v = try attr.next();
            try attr.finish();
            if (v.value.len == 0) return error.InvalidName;
            switch (v.tag) {
                12 => if (!std.unicode.utf8ValidateSlice(v.value)) return error.InvalidName,
                19 => for (v.value) |c| {
                    if (!std.ascii.isAlphanumeric(c) and std.mem.findScalar(u8, " '()+,-./:=?", c) == null) return error.InvalidName;
                },
                22 => for (v.value) |c| {
                    if (c == 0 or c > 127) return error.InvalidName;
                },
                20 => {},
                30 => {
                    if (v.value.len % 2 != 0) return error.InvalidName;
                    for (0..v.value.len / 2) |i| {
                        const cp = std.mem.readInt(u16, v.value[i * 2 ..][0..2], .big);
                        if (cp >= 0xd800 and cp <= 0xdfff) return error.InvalidName;
                    }
                },
                28 => {
                    if (v.value.len % 4 != 0) return error.InvalidName;
                    for (0..v.value.len / 4) |i| {
                        const cp = std.mem.readInt(u32, v.value[i * 4 ..][0..4], .big);
                        if (cp > 0x10ffff or (cp >= 0xd800 and cp <= 0xdfff)) return error.InvalidName;
                    }
                },
                else => {}, // Unknown attribute syntaxes compare by their exact DER.
            }
        }
    }
}
fn normalizedEqual(a: Der.Element, b: Der.Element) bool {
    @setRuntimeSafety(true);
    if (std.mem.eql(u8, a.encoded, b.encoded)) return true;
    if ((a.tag != 12 and a.tag != 19 and a.tag != 20 and a.tag != 22) or (b.tag != 12 and b.tag != 19 and b.tag != 20 and b.tag != 22)) return false;
    // ASCII DirectoryStrings: case-fold, trim and collapse spaces. Non-ASCII
    // values remain exact; no guessed Unicode normalization can create an issuer.
    for (a.value) |c| if (c >= 128) return false;
    for (b.value) |c| if (c >= 128) return false;
    const aa = std.mem.trim(u8, a.value, " ");
    const bb = std.mem.trim(u8, b.value, " ");
    var i: usize = 0;
    var j: usize = 0;
    while (i < aa.len and j < bb.len) {
        if (std.ascii.toLower(aa[i]) != std.ascii.toLower(bb[j])) return false;
        const space = aa[i] == ' ';
        i += 1;
        j += 1;
        if (space) {
            while (i < aa.len and aa[i] == ' ') i += 1;
            while (j < bb.len and bb[j] == ' ') j += 1;
        }
    }
    return i == aa.len and j == bb.len;
}
fn attributeEqual(a: Der.Element, b: Der.Element) bool {
    @setRuntimeSafety(true);
    var ar = a.reader();
    var br = b.reader();
    const ao = ar.expect(6) catch return false;
    const bo = br.expect(6) catch return false;
    if (!std.mem.eql(u8, ao.value, bo.value)) return false;
    return normalizedEqual(ar.next() catch return false, br.next() catch return false);
}
fn setEqual(a: Der.Element, b: Der.Element) bool {
    @setRuntimeSafety(true);
    var ar = a.reader();
    var br = b.reader();
    var used: [128]bool = @splat(false);
    var count: usize = 0;
    while (!br.empty()) {
        _ = br.next() catch return false;
        count += 1;
        if (count > used.len) return false;
    }
    while (!ar.empty()) {
        const attr = ar.next() catch return false;
        br = b.reader();
        var i: usize = 0;
        var found = false;
        while (!br.empty()) : (i += 1) {
            const candidate = br.next() catch return false;
            if (!used[i] and attributeEqual(attr, candidate)) {
                used[i] = true;
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    for (used[0..count]) |v| if (!v) return false;
    return true;
}
pub fn equal(a: []const u8, b: []const u8) bool {
    @setRuntimeSafety(true);
    return nameCompare(a, b, false);
}
/// directoryName subtree: the initial sequence of RDNs must match.
pub fn within(a: []const u8, subtree: []const u8) bool {
    @setRuntimeSafety(true);
    return nameCompare(a, subtree, true);
}
fn nameCompare(a: []const u8, b: []const u8, prefix: bool) bool {
    @setRuntimeSafety(true);
    if (std.mem.eql(u8, a, b)) return true;
    var ar = (Der.single(a, 0x30) catch return false).reader();
    var br = (Der.single(b, 0x30) catch return false).reader();
    while (!br.empty()) {
        if (ar.empty()) return false;
        if (!setEqual(ar.expect(0x31) catch return false, br.expect(0x31) catch return false)) return false;
    }
    return prefix or ar.empty();
}
/// Stable normalized issuer key; equal validated names have equal keys.
/// Hash collisions only add candidates: verification still compares full names.
pub fn key(encoded: []const u8) Error![32]u8 {
    @setRuntimeSafety(true);
    try validate(encoded);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("cloak issuer name v1");
    var r = (try Der.single(encoded, 0x30)).reader();
    while (!r.empty()) {
        var set = (try r.expect(0x31)).reader();
        var attributes: [128][32]u8 = undefined;
        var count: usize = 0;
        while (!set.empty()) {
            var attr = (try set.expect(0x30)).reader();
            var ah = std.crypto.hash.sha2.Sha256.init(.{});
            const id = (try attr.expect(6)).value;
            var oid_length: [8]u8 = undefined;
            std.mem.writeInt(u64, &oid_length, id.len, .big);
            ah.update(&oid_length);
            ah.update(id);
            const value = try attr.next();
            var ascii = value.tag == 12 or value.tag == 19 or value.tag == 20 or value.tag == 22;
            for (value.value) |c| if (c >= 128) {
                ascii = false;
            };
            if (ascii) {
                ah.update(&.{0});
                const trimmed = std.mem.trim(u8, value.value, " ");
                var space = false;
                for (trimmed) |c| {
                    if (c != ' ' or !space) ah.update(&.{std.ascii.toLower(c)});
                    space = c == ' ';
                }
            } else {
                ah.update(&.{1});
                ah.update(value.encoded);
            }
            attributes[count] = ah.finalResult();
            count += 1;
        }
        std.mem.sortUnstable([32]u8, attributes[0..count], {}, lessKey);
        var size: [8]u8 = undefined;
        std.mem.writeInt(u64, &size, count, .big);
        hash.update(&size);
        for (attributes[0..count]) |a| hash.update(&a);
    }
    return hash.finalResult();
}
fn lessKey(_: void, a: [32]u8, b: [32]u8) bool {
    @setRuntimeSafety(true);
    return std.mem.order(u8, &a, &b) == .lt;
}
pub fn canonicalDns(input: []const u8, wildcard: bool) Error![]const u8 {
    @setRuntimeSafety(true);
    var name = input;
    if (name.len != 0 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    if (name.len == 0 or name.len > 253) return error.InvalidName;
    var labels = std.mem.splitScalar(u8, name, '.');
    var index: usize = 0;
    while (labels.next()) |label| : (index += 1) {
        if (label.len == 0 or label.len > 63) return error.InvalidName;
        if (wildcard and index == 0 and std.mem.eql(u8, label, "*")) continue;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidName;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidName;
        if (label.len >= 4 and label[2] == '-' and label[3] == '-') {
            if (!std.ascii.eqlIgnoreCase(label[0..4], "xn--")) return error.InvalidName;
            try punycode(label[4..]);
        }
    }
    if (name[0] == '*' and index < 3) return error.InvalidName;
    return name;
}
pub fn dnsMatch(reference: []const u8, san: []const u8) bool {
    @setRuntimeSafety(true);
    const ref = canonicalDns(reference, false) catch return false;
    const name = canonicalDns(san, true) catch return false;
    if (name[0] != '*') return std.ascii.eqlIgnoreCase(ref, name);
    const dot = std.mem.findScalar(u8, ref, '.') orelse return false;
    if (std.ascii.startsWithIgnoreCase(ref[0..dot], "xn--")) return false;
    return std.ascii.eqlIgnoreCase(ref[dot + 1 ..], name[2..]);
}
/// Decode enough RFC 3492 to reject malformed A-labels and overflow. IDNA mapping
/// stays upstream; the decoded label must contain a non-ASCII scalar.
fn punycode(input: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (input.len == 0) return error.InvalidName;
    var length: usize = 0;
    var pos: usize = 0;
    if (std.mem.findScalarLast(u8, input, '-')) |d| {
        if (d == 0) return error.InvalidName;
        length = d;
        pos = d + 1;
    }
    var n: usize = 128;
    var i: usize = 0;
    var bias: usize = 72;
    var decoded = false;
    while (pos < input.len) {
        const old = i;
        var w: usize = 1;
        var k: usize = 36;
        while (true) : (k += 36) {
            if (pos == input.len or k > 4096) return error.InvalidName;
            const c = std.ascii.toLower(input[pos]);
            pos += 1;
            const digit: usize = if (c >= 'a' and c <= 'z') c - 'a' else if (c >= '0' and c <= '9') c - '0' + 26 else return error.InvalidName;
            const product = std.math.mul(usize, digit, w) catch return error.InvalidName;
            i = std.math.add(usize, i, product) catch return error.InvalidName;
            const t: usize = if (k <= bias) 1 else if (k >= bias + 26) 26 else k - bias;
            if (digit < t) break;
            w = std.math.mul(usize, w, 36 - t) catch return error.InvalidName;
        }
        length += 1;
        const divisor: usize = if (!decoded) 700 else 2;
        var delta = (i - old) / divisor;
        delta += delta / length;
        var base: usize = 0;
        while (delta > 455) {
            delta /= 35;
            base += 36;
        }
        bias = base + 36 * delta / (delta + 38);
        n = std.math.add(usize, n, i / length) catch return error.InvalidName;
        if (n > 0x10ffff or (n >= 0xd800 and n <= 0xdfff) or n == 0x200c or n == 0x200d) return error.InvalidName;
        i = i % length + 1;
        decoded = true;
    }
    if (!decoded or length > 63) return error.InvalidName;
}
test {
    _ = @import("Name_test.zig");
}
