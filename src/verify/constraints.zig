const std = @import("std");
const C = @import("../certificate.zig");
const Der = @import("../wire/Der.zig");
pub const Error = C.ParseError || error{NameConstraintViolation};
pub fn check(path: []const C.Certificate, anchor_constraints: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (anchor_constraints.len != 0) {
        try C.Extensions.nameConstraints(anchor_constraints);
        for (path[0 .. path.len - 1], 0..) |*sub, i| if (i == 0 or !sub.selfIssued()) try imposed(sub, anchor_constraints);
    }
    for (path, 0..) |*issuer, index| {
        if (issuer.x509(30)) |e| {
            if (index == 0) return error.NameConstraintViolation;
            for (path[0..index], 0..) |*sub, i| if (i == 0 or !sub.selfIssued()) try imposed(sub, e.value);
        }
    }
}
fn imposed(cert: *const C.Certificate, encoded: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = try C.Extensions.sequence(encoded);
    const permitted = if (r.peek() == 0xa0) (try r.next()).value else &.{};
    const excluded = if (r.peek() == 0xa1) (try r.next()).value else &.{};
    try r.finish();
    try checkName(.{ .tag = 0xa4, .encoded = &.{}, .value = cert.subject }, permitted, excluded);
    if (cert.x509(17)) |san| {
        var names = try C.Extensions.sequence(san.value);
        while (!names.empty()) try checkName(try names.next(), permitted, excluded);
    } else {
        // Legacy emailAddress attributes are constrained too; never used for identity.
        var dn = (try Der.single(cert.subject, 0x30)).reader();
        while (!dn.empty()) {
            var set = (try dn.expect(0x31)).reader();
            while (!set.empty()) {
                var attr = (try set.expect(0x30)).reader();
                const id = (try attr.expect(6)).value;
                const value = try attr.next();
                if (std.mem.eql(u8, id, "\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01")) try checkName(.{ .tag = 0x81, .encoded = &.{}, .value = value.value }, permitted, excluded);
            }
        }
    }
}
fn checkName(name: Der.Element, permitted: []const u8, excluded: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r: Der.Reader = .{ .bytes = excluded };
    while (!r.empty()) {
        var s = (try r.expect(0x30)).reader();
        const base = try s.next();
        if (base.tag == name.tag and try matches(name, base.value, true)) return error.NameConstraintViolation;
    }
    r = .{ .bytes = permitted };
    var constrained = false;
    var allowed = false;
    while (!r.empty()) {
        var s = (try r.expect(0x30)).reader();
        const base = try s.next();
        if (base.tag == name.tag) {
            constrained = true;
            allowed = allowed or try matches(name, base.value, false);
        }
    }
    if (constrained and !allowed) return error.NameConstraintViolation;
}
fn matches(name: Der.Element, base: []const u8, excluded: bool) Error!bool {
    @setRuntimeSafety(true);
    return switch (name.tag) {
        0x82 => dns(name.value, base, excluded),
        0x87 => ip(name.value, base),
        0xa4 => C.Name.within(name.value, base),
        0x81 => email(name.value, base),
        0x86 => if (base.len != 0 and base[0] == '.') dns(try uriHost(name.value), base, excluded) else std.ascii.eqlIgnoreCase(try uriHost(name.value), base),
        else => error.UnsupportedName,
    };
}
fn dns(input: []const u8, constraint: []const u8, excluded: bool) bool {
    @setRuntimeSafety(true);
    const name = C.Name.canonicalDns(input, true) catch return false;
    const leading = constraint.len != 0 and constraint[0] == '.';
    const base = C.Name.canonicalDns(if (leading) constraint[1..] else constraint, false) catch return false;
    if (!leading and std.ascii.eqlIgnoreCase(name, base)) return true;
    if (name.len > base.len and name[name.len - base.len - 1] == '.' and std.ascii.eqlIgnoreCase(name[name.len - base.len ..], base)) return true;
    // An excluded individual host also intersects a whole-label wildcard SAN.
    if (excluded and !leading and std.mem.startsWith(u8, name, "*.")) {
        const dot = std.mem.findScalar(u8, base, '.') orelse return false;
        return std.ascii.eqlIgnoreCase(base[dot + 1 ..], name[2..]);
    }
    return false;
}
fn ip(name: []const u8, base: []const u8) bool {
    @setRuntimeSafety(true);
    if (base.len != name.len * 2) return false;
    for (name, base[0..name.len], base[name.len..]) |n, b, mask| if (n & mask != b & mask) return false;
    return true;
}
fn email(name: []const u8, base: []const u8) bool {
    @setRuntimeSafety(true);
    const at = std.mem.findScalarLast(u8, name, '@') orelse return false;
    if (std.mem.findScalar(u8, base, '@')) |b| return std.mem.eql(u8, name[0..at], base[0..b]) and std.ascii.eqlIgnoreCase(name[at + 1 ..], base[b + 1 ..]);
    if (base.len != 0 and base[0] == '.') return dns(name[at + 1 ..], base, false);
    return std.ascii.eqlIgnoreCase(name[at + 1 ..], base);
}
fn uriHost(uri: []const u8) Error![]const u8 {
    @setRuntimeSafety(true);
    const marker = std.mem.find(u8, uri, "://") orelse return error.NameConstraintViolation;
    const authority = uri[marker + 3 ..];
    const end = std.mem.findAny(u8, authority, "/?#") orelse authority.len;
    var host = authority[0..end];
    if (std.mem.findScalarLast(u8, host, '@')) |at| host = host[at + 1 ..];
    if (std.mem.findScalar(u8, host, ':')) |colon| host = host[0..colon];
    _ = C.Name.canonicalDns(host, false) catch return error.NameConstraintViolation;
    return host;
}
test {
    _ = @import("constraints_test.zig");
}
