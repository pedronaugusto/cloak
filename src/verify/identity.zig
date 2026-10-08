const std = @import("std");
const C = @import("../certificate.zig");
const T = @import("../types.zig");
pub const Error = C.ParseError || error{ IdentityRequired, IdentityMismatch, PinMismatch, InvalidPurpose };
pub fn validate(reference: T.Identity, desired: T.Purpose) Error!void {
    @setRuntimeSafety(true);
    switch (reference) {
        .none => if (desired == .server) return error.IdentityRequired,
        .dns => |s| {
            _ = try C.Name.canonicalDns(s, false);
        },
        else => {},
    }
}
pub fn check(cert: *const C.Certificate, reference: T.Identity) Error!void {
    @setRuntimeSafety(true);
    if (reference == .none) return;
    const san = cert.x509(17) orelse return error.IdentityMismatch;
    var names = try C.Extensions.sequence(san.value);
    var matched = false;
    while (!names.empty()) {
        const name = try names.next();
        matched = matched or switch (reference) {
            .none => true,
            .dns => |s| name.tag == 0x82 and C.Name.dnsMatch(s, name.value),
            .ipv4 => |ip| name.tag == 0x87 and std.mem.eql(u8, &ip, name.value),
            .ipv6 => |ip| name.tag == 0x87 and std.mem.eql(u8, &ip, name.value),
        };
    }
    if (!matched) return error.IdentityMismatch;
}
pub fn pins(cert: *const C.Certificate, set: []const [32]u8) Error!void {
    @setRuntimeSafety(true);
    if (set.len == 0) return;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert.spki, &hash, .{});
    var matches: u8 = 0;
    for (set) |pin| matches |= @intFromBool(std.crypto.timing_safe.eql([32]u8, hash, pin));
    if (matches == 0) return error.PinMismatch;
}
pub fn purpose(cert: *const C.Certificate, desired: T.Purpose, ca: bool) Error!void {
    @setRuntimeSafety(true);
    if (cert.x509(15)) |ku| {
        const usage = try C.Extensions.keyUsage(ku.value);
        if (!ca and usage & (1 << 5) != 0) {
            const bc = cert.x509(19) orelse return error.InvalidPurpose;
            if (!(try C.Extensions.basic(bc.value)).ca) return error.InvalidPurpose;
        }
        if (usage & (if (ca) @as(u16, 1 << 5) else 1) == 0) return error.InvalidPurpose;
    }
    if (cert.x509(37)) |eku| {
        var r = try C.Extensions.sequence(eku.value);
        var allowed = false;
        const wanted: []const u8 = if (desired == .server) "\x2b\x06\x01\x05\x05\x07\x03\x01" else "\x2b\x06\x01\x05\x05\x07\x03\x02";
        while (!r.empty()) {
            const id = (try r.expect(6)).value;
            allowed = allowed or std.mem.eql(u8, id, wanted) or std.mem.eql(u8, id, "\x55\x1d\x25\x00");
        }
        if (!allowed) return error.InvalidPurpose;
    }
}
