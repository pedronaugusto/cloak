const std = @import("std");
const Der = @import("../wire/Der.zig");
const Cert = @import("fields.zig");
const Name = @import("Name.zig");
pub const Error = Cert.ParseError || Name.Error;
pub const Basic = struct { ca: bool = false, path_length: ?usize = null };
pub fn basic(value: []const u8) Error!Basic {
    @setRuntimeSafety(true);
    var r = (try Der.single(value, 0x30)).reader();
    var result: Basic = .{};
    if (r.peek() == 1) {
        result.ca = try Der.boolean((try r.next()).value);
        if (!result.ca) return error.InvalidDer;
    }
    if (!r.empty()) result.path_length = try Der.number((try r.expect(2)).value);
    try r.finish();
    if (!result.ca and result.path_length != null) return error.InvalidCertificate;
    return result;
}
pub fn keyUsage(value: []const u8) Error!u16 {
    @setRuntimeSafety(true);
    const b = (try Der.single(value, 3)).value;
    const bits = try Der.bits(b);
    if (bits.len == 0 or bits.len > 2 or bits[bits.len - 1] == 0) return error.InvalidCertificate;
    // safe: the final byte is nonzero, so its trailing-zero count fits u3.
    if (@as(u3, @intCast(@ctz(bits[bits.len - 1]))) != b[0]) return error.InvalidDer;
    if (bits.len == 2 and (bits[1] != 128 or b[0] != 7)) return error.InvalidCertificate;
    var mask: u16 = 0;
    for (bits, 0..) |v, i| {
        for (0..8) |j| {
            // safe: j is below eight and i * 8 + j is below sixteen.
            if (v & (@as(u8, 128) >> @intCast(j)) != 0) mask |= @as(u16, 1) << @intCast(i * 8 + j);
        }
    }
    if (mask & 0x180 != 0 and mask & 0x10 == 0) return error.InvalidCertificate;
    return mask;
}
pub fn sequence(value: []const u8) Error!Der.Reader {
    @setRuntimeSafety(true);
    return (try Der.single(value, 0x30)).reader();
}
pub fn validate(e: Cert.Extension, limits: Cert.Limits) Error!void {
    @setRuntimeSafety(true);
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x0e") or std.mem.eql(u8, e.oid, "\x55\x1d\x23")) {
        if (e.critical) return error.InvalidCertificate;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x1e") or std.mem.eql(u8, e.oid, "\x55\x1d\x24") or std.mem.eql(u8, e.oid, "\x55\x1d\x36")) {
        if (!e.critical) return error.InvalidCertificate;
    }
    try Der.validate(e.value, .{ .bytes = limits.bytes, .elements = limits.elements, .depth = limits.depth });
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x13")) {
        _ = try basic(e.value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x0f")) {
        _ = try keyUsage(e.value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x0e")) {
        if ((try Der.single(e.value, 4)).value.len == 0) return error.InvalidCertificate;
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x23")) {
        try authority(e.value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x11") or std.mem.eql(u8, e.oid, "\x55\x1d\x12")) {
        var r = try sequence(e.value);
        if (r.empty()) return error.InvalidCertificate;
        while (!r.empty()) {
            const name = try r.next();
            if (e.critical and name.tag != 0x81 and name.tag != 0x82 and name.tag != 0x86 and name.tag != 0x87 and name.tag != 0xa4) return error.UnsupportedName;
            try general(name, false);
        }
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x1e")) {
        try nameConstraints(e.value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x25")) {
        try oidList(e.value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x20")) {
        try policies(e.value, e.critical);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x21")) {
        try mappings(e.value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x24")) {
        var r = try sequence(e.value);
        if (r.empty()) return error.InvalidCertificate;
        if (r.peek() == 0x80) _ = try Der.number((try r.next()).value);
        if (r.peek() == 0x81) _ = try Der.number((try r.next()).value);
        try r.finish();
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x55\x1d\x36")) {
        _ = try Der.number((try Der.single(e.value, 2)).value);
        return;
    }
    if (std.mem.eql(u8, e.oid, "\x2b\x06\x01\x05\x05\x07\x01\x18")) {
        var r = try sequence(e.value);
        if (r.empty()) return error.InvalidCertificate;
        while (!r.empty()) {
            const v = try Der.number((try r.expect(2)).value);
            if (e.critical and v != 5 and v != 17) return error.UnknownCriticalExtension;
        }
        return;
    }
    // Revocation owns CRL distribution points and AIA semantics. Non-critical
    // evidence locations never authorize fetching or count as revocation evidence.
    if (e.critical) return error.UnknownCriticalExtension;
}
fn oidList(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = try sequence(value);
    if (r.empty()) return error.InvalidCertificate;
    var prior: [64][]const u8 = undefined;
    var count: usize = 0;
    while (!r.empty()) {
        const id = (try r.expect(6)).value;
        try Der.oid(id);
        if (count == prior.len) return error.DerLimit;
        for (prior[0..count]) |p| if (std.mem.eql(u8, p, id)) return error.InvalidCertificate;
        prior[count] = id;
        count += 1;
    }
}
fn authority(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = try sequence(value);
    if (r.empty()) return error.InvalidCertificate;
    if (r.peek() == 0x80) if ((try r.next()).value.len == 0) return error.InvalidCertificate;
    const has_issuer = r.peek() == 0xa1;
    if (has_issuer) {
        var names = (try r.next()).reader();
        if (names.empty()) return error.InvalidCertificate;
        while (!names.empty()) try general(try names.next(), false);
        if (r.peek() != 0x82) return error.InvalidCertificate;
    }
    if (r.peek() == 0x82) {
        if (!has_issuer) return error.InvalidCertificate;
        _ = try Der.integer((try r.next()).value);
    }
    try r.finish();
}
pub fn general(e: Der.Element, constraint: bool) Error!void {
    @setRuntimeSafety(true);
    if (constraint and e.tag != 0x81 and e.tag != 0x82 and e.tag != 0x86 and e.tag != 0x87 and e.tag != 0xa4) return error.UnsupportedName;
    switch (e.tag) {
        0x81, 0x82, 0x86 => {
            if (e.value.len == 0) return error.InvalidCertificate;
            for (e.value) |c| if (c < 32 or c >= 127) return error.InvalidCertificate;
            if (e.tag == 0x82) {
                _ = try Name.canonicalDns(e.value, !constraint);
            }
            if (e.tag == 0x81) {
                if (!constraint or std.mem.findScalar(u8, e.value, '@') != null) {
                    const at = std.mem.findScalar(u8, e.value, '@') orelse return error.InvalidName;
                    if (at == 0 or std.mem.findScalarLast(u8, e.value, '@').? != at) return error.InvalidName;
                    _ = try Name.canonicalDns(e.value[at + 1 ..], false);
                } else _ = try Name.canonicalDns(if (e.value[0] == '.') e.value[1..] else e.value, false);
            }
            if (e.tag == 0x86) {
                if (constraint) _ = try Name.canonicalDns(if (e.value[0] == '.') e.value[1..] else e.value, false) else {
                    _ = std.Uri.parse(e.value) catch return error.InvalidName;
                    for (e.value) |c| if (std.ascii.isWhitespace(c) or c < 32) return error.InvalidName;
                }
            }
        },
        0x87 => if (e.value.len != (if (constraint) @as(usize, 8) else 4) and e.value.len != (if (constraint) @as(usize, 32) else 16)) return error.InvalidCertificate,
        0xa4 => try Name.validate(e.value),
        0xa0 => {
            var r = e.reader();
            _ = try r.expect(6);
            var explicit = (try r.expect(0xa0)).reader();
            _ = try explicit.next();
            try explicit.finish();
            try r.finish();
        },
        0xa3 => return error.UnsupportedName, // ORAddress semantics are outside this profile.
        0xa5 => {
            var r = e.reader();
            if (r.peek() == 0xa0) try directoryString((try r.next()).value);
            try directoryString((try r.expect(0xa1)).value);
            try r.finish();
        },
        0x88 => try Der.oid(e.value),
        else => return error.InvalidCertificate,
    }
}
pub fn nameConstraints(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = try sequence(value);
    if (r.empty()) return error.InvalidCertificate;
    if (r.peek() == 0xa0) try subtrees((try r.next()).value);
    if (r.peek() == 0xa1) try subtrees((try r.next()).value);
    try r.finish();
}
fn subtrees(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r: Der.Reader = .{ .bytes = value };
    if (r.empty()) return error.InvalidCertificate;
    while (!r.empty()) {
        var s = (try r.expect(0x30)).reader();
        try general(try s.next(), true);
        // RFC 5280 profile minimum is zero (omitted in DER), maximum absent.
        if (!s.empty()) return error.UnsupportedName;
    }
}
pub const any_policy = "\x55\x1d\x20\x00";
fn policies(value: []const u8, critical: bool) Error!void {
    @setRuntimeSafety(true);
    var r = try sequence(value);
    if (r.empty()) return error.InvalidCertificate;
    var ids: [64][]const u8 = undefined;
    var count: usize = 0;
    while (!r.empty()) {
        var p = (try r.expect(0x30)).reader();
        const id = (try p.expect(6)).value;
        if (count == ids.len) return error.DerLimit;
        for (ids[0..count]) |prior| if (std.mem.eql(u8, prior, id)) return error.InvalidCertificate;
        ids[count] = id;
        count += 1;
        if (!p.empty()) {
            var q = (try p.expect(0x30)).reader();
            if (q.empty()) return error.InvalidCertificate;
            while (!q.empty()) {
                var qr = (try q.expect(0x30)).reader();
                const qid = (try qr.expect(6)).value;
                const qualifier = try qr.next();
                try qr.finish();
                if (std.mem.eql(u8, qid, "\x2b\x06\x01\x05\x05\x07\x02\x01")) {
                    if (qualifier.tag != 22) return error.InvalidCertificate;
                    for (qualifier.value) |c| if (c < 32 or c >= 127) return error.InvalidCertificate;
                    _ = std.Uri.parse(qualifier.value) catch return error.InvalidCertificate;
                } else if (std.mem.eql(u8, qid, "\x2b\x06\x01\x05\x05\x07\x02\x02")) {
                    try userNotice(qualifier);
                } else if (critical or std.mem.eql(u8, id, any_policy)) return error.UnknownCriticalExtension;
            }
        }
        try p.finish();
    }
}
fn userNotice(e: Der.Element) Error!void {
    @setRuntimeSafety(true);
    if (e.tag != 0x30) return error.InvalidCertificate;
    var r = e.reader();
    if (r.peek() == 0x30) {
        var notice = (try r.next()).reader();
        try displayText(try notice.next());
        var numbers = (try notice.expect(0x30)).reader();
        if (numbers.empty()) return error.InvalidCertificate;
        while (!numbers.empty()) _ = try Der.integer((try numbers.expect(2)).value);
        try notice.finish();
    }
    if (!r.empty()) try displayText(try r.next());
    try r.finish();
}
fn displayText(e: Der.Element) Error!void {
    @setRuntimeSafety(true);
    var characters: usize = e.value.len;
    switch (e.tag) {
        12 => characters = std.unicode.utf8CountCodepoints(e.value) catch return error.InvalidCertificate,
        22 => for (e.value) |c| {
            if (c > 127) return error.InvalidCertificate;
        },
        26 => for (e.value) |c| {
            if (c < 32 or c > 126) return error.InvalidCertificate;
        },
        30 => {
            if (e.value.len % 2 != 0) return error.InvalidCertificate;
            characters /= 2;
            for (0..characters) |i| {
                const cp = std.mem.readInt(u16, e.value[i * 2 ..][0..2], .big);
                if (cp >= 0xd800 and cp <= 0xdfff) return error.InvalidCertificate;
            }
        },
        else => return error.InvalidCertificate,
    }
    if (characters == 0 or characters > 200) return error.InvalidCertificate;
}
fn directoryString(encoded: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r: Der.Reader = .{ .bytes = encoded };
    const e = try r.next();
    try r.finish();
    if (e.tag != 12 and e.tag != 19 and e.tag != 20 and e.tag != 28 and e.tag != 30) return error.InvalidCertificate;
    if (e.value.len == 0) return error.InvalidCertificate;
}
fn mappings(value: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = try sequence(value);
    if (r.empty()) return error.InvalidCertificate;
    while (!r.empty()) {
        var m = (try r.expect(0x30)).reader();
        const issuer = (try m.expect(6)).value;
        const subject = (try m.expect(6)).value;
        try m.finish();
        if (std.mem.eql(u8, issuer, any_policy) or std.mem.eql(u8, subject, any_policy)) return error.InvalidCertificate;
    }
}
test {
    _ = @import("Extensions_test.zig");
}
