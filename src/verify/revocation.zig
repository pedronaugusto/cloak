//! Offline evidence only. Invalid supplied evidence is never silently ignored.
const std = @import("std");
const C = @import("../certificate.zig");
const T = @import("../types.zig");
const Der = @import("../wire/Der.zig");
const signatures = @import("signature.zig");
pub const Error = C.ParseError || signatures.Error || error{ Revoked, MissingRevocation, UnknownRevocation, InvalidRevocation, StaleRevocation, UnsupportedRevocation, VerificationLimit, NotApplicableRevocation };
pub const Result = struct { status: T.RevocationStatus, expires: ?i64 = null };
const EvidenceResult = struct { covered: usize, mask: u16 = 0, expires: i64 };
pub fn check(path: []const C.Certificate, now: i64, policy: T.RevocationPolicy, evidence: T.Evidence) Error!Result {
    @setRuntimeSafety(true);
    if (policy.mode == .off) return .{ .status = .unchecked };
    if (path.len == 0 or path.len > 16 or evidence.crls.len > 64 or evidence.ocsp.len > 64 - evidence.crls.len) return error.VerificationLimit;
    var covered: [16]bool = @splat(false);
    var stapled = false;
    var expires: ?i64 = null;
    var bytes: usize = 0;
    for (evidence.crls) |der| {
        bytes = std.math.add(usize, bytes, der.len) catch return error.VerificationLimit;
        if (bytes > 262144) return error.VerificationLimit;
        const result = crl(path, now, policy, der) catch |err| {
            if (err == error.NotApplicableRevocation) continue;
            return err;
        };
        for (covered[0..path.len], 0..) |*ok, index| if (result.mask & bit(index) != 0) {
            ok.* = true;
        };
        expires = if (expires) |e| @min(e, result.expires) else result.expires;
    }
    for (evidence.ocsp) |der| {
        bytes = std.math.add(usize, bytes, der.len) catch return error.VerificationLimit;
        if (bytes > 262144) return error.VerificationLimit;
        const result = try ocsp(path, now, policy, evidence, der);
        covered[result.covered] = true;
        stapled = stapled or result.covered == 0;
        expires = if (expires) |e| @min(e, result.expires) else result.expires;
    }
    if (path[0].extension("\x2b\x06\x01\x05\x05\x07\x01\x18")) |feature| {
        var r = try C.Extensions.sequence(feature.value);
        while (!r.empty()) {
            const f = try Der.number((try r.expect(2)).value);
            if ((f == 5 or f == 17) and !stapled) return error.MissingRevocation;
        }
    }
    const count = if (policy.coverage == .whole_path) path.len -| 1 else @min(path.len, 1);
    if (policy.mode == .required) for (covered[0..count]) |ok| {
        if (!ok) return error.MissingRevocation;
    };
    return .{ .status = if (expires != null) .good else .not_present, .expires = expires };
}
fn fresh(this: i64, next: ?i64, now: i64, policy: T.RevocationPolicy) Error!i64 {
    @setRuntimeSafety(true);
    if (policy.clock_skew > 86400 or policy.max_age > 365 * 86400) return error.InvalidRevocation;
    const skew: i64 = @intCast(policy.clock_skew); // safe: policy is bounded above.
    const age: i64 = @intCast(policy.max_age); // safe: policy is bounded above.
    if (this > now +| skew) return error.StaleRevocation;
    const expires = next orelse (this +| age);
    if (expires < this or expires < now -| skew) return error.StaleRevocation;
    return expires;
}
fn crl(path: []const C.Certificate, now: i64, policy: T.RevocationPolicy, der: []const u8) Error!EvidenceResult {
    @setRuntimeSafety(true);
    try Der.validate(der, .{});
    var outer = (try Der.single(der, 0x30)).reader();
    const tbs = try outer.expect(0x30);
    const algorithm = try outer.expect(0x30);
    const sig = try Der.octetBits((try outer.expect(3)).value);
    try outer.finish();
    var r = tbs.reader();
    var version: usize = 0;
    if (r.peek() == 2) {
        version = try Der.number((try r.next()).value);
        if (version != 1) return error.InvalidRevocation;
    }
    if (!std.mem.eql(u8, (try r.expect(0x30)).encoded, algorithm.encoded)) return error.InvalidRevocation;
    const issuer = (try r.expect(0x30)).encoded;
    try C.Name.validate(issuer);
    const this = try C.Certificate.evidenceTime(try r.next());
    const next: ?i64 = if (r.peek() == 0x17 or r.peek() == 0x18) try C.Certificate.evidenceTime(try r.next()) else null;
    const expires = try fresh(this, next, now, policy);
    const entries = if (r.peek() == 0x30) (try r.next()).value else &.{};
    var aki: ?[]const u8 = null;
    var has_number = false;
    if (r.peek() == 0xa0) {
        if (version != 1) return error.InvalidRevocation;
        var exts = try C.Extensions.sequence((try r.next()).value);
        var ids: [64][]const u8 = undefined;
        var count: usize = 0;
        while (!exts.empty()) {
            const e = try extension(try exts.expect(0x30));
            try unique(&ids, &count, e.oid);
            if (std.mem.eql(u8, e.oid, "\x55\x1d\x23")) {
                var a = try C.Extensions.sequence(e.value);
                if (a.peek() == 0x80) aki = (try a.next()).value;
            } else if (std.mem.eql(u8, e.oid, "\x55\x1d\x14")) {
                if (e.critical) return error.InvalidRevocation;
                has_number = true;
                _ = try Der.number((try Der.single(e.value, 2)).value);
            } else if (std.mem.eql(u8, e.oid, "\x55\x1d\x1b") or std.mem.eql(u8, e.oid, "\x55\x1d\x1c")) return error.UnsupportedRevocation else if (e.critical) return error.UnsupportedRevocation;
        }
    }
    try r.finish();
    if (version == 1 and !has_number) return error.InvalidRevocation;
    var applicable = false;
    for (path[0..path.len -| 1]) |*cert| if (C.Name.equal(cert.issuer, issuer)) {
        applicable = true;
    };
    if (!applicable) return error.NotApplicableRevocation;
    var mask: u16 = 0;
    for (path[0..path.len -| 1], 0..) |*cert, i| {
        if (!C.Name.equal(cert.issuer, issuer)) continue;
        const ca = &path[i + 1];
        if (!C.Name.equal(ca.subject, issuer)) continue;
        if (ca.x509(15)) |ku| if (try C.Extensions.keyUsage(ku.value) & (1 << 6) == 0) continue;
        if (aki) |id| {
            const ski = ca.x509(14) orelse continue;
            if (!std.mem.eql(u8, id, (try Der.single(ski.value, 4)).value)) continue;
        }
        signatures.verify(ca.public_key, try C.Algorithm.signature(algorithm.encoded), tbs.encoded, sig) catch continue;
        mask |= bit(i);
    }
    if (mask == 0) return error.InvalidRevocation;
    try crlEntries(path, mask, entries, version);
    return .{ .covered = 0, .mask = mask, .expires = deadline(expires, policy) };
}
fn crlEntries(path: []const C.Certificate, mask: u16, entries: []const u8, version: usize) Error!void {
    @setRuntimeSafety(true);
    // A full direct CRL covers all serials issued by this issuer. Validate every
    // entry, even unrelated ones, so unknown critical entry semantics fail closed.
    var revoked = false;
    var entries_reader: Der.Reader = .{ .bytes = entries };
    // Public DER offsets keep duplicate detection bounded without a 64 KiB
    // slice table on the stack; binary search retains every serial.
    var serials: [4096]u32 = undefined;
    var serial_count: usize = 0;
    while (!entries_reader.empty()) {
        const offset = entries_reader.offset;
        var entry = (try entries_reader.expect(0x30)).reader();
        const serial = try Der.integer((try entry.expect(2)).value);
        try addSerial(entries, serial, &serials, &serial_count, offset);
        // An authoritative listed serial is revoked regardless of its entry date.
        // Unrelated entry dates still require canonical calendar encoding.
        _ = try C.Certificate.evidenceTime(try entry.next());
        if (!entry.empty()) {
            if (version != 1) return error.InvalidRevocation;
            var exts = (try entry.expect(0x30)).reader();
            var ids: [64][]const u8 = undefined;
            var count: usize = 0;
            while (!exts.empty()) {
                const e = try extension(try exts.expect(0x30));
                try unique(&ids, &count, e.oid);
                if (std.mem.eql(u8, e.oid, "\x55\x1d\x15")) {
                    const reason = try Der.number((try Der.single(e.value, 10)).value);
                    if (reason > 10 or reason == 7) return error.InvalidRevocation;
                    // removeFromCRL is meaningful only in delta CRLs, which this
                    // direct-full-CRL profile rejects rather than treating as good.
                    if (reason == 8) return error.UnsupportedRevocation;
                } else if (std.mem.eql(u8, e.oid, "\x55\x1d\x18")) {
                    _ = try C.Certificate.evidenceTime(try Der.single(e.value, 0x18));
                } else if (e.critical or std.mem.eql(u8, e.oid, "\x55\x1d\x1d")) return error.UnsupportedRevocation;
            }
        }
        try entry.finish();
        for (path[0..path.len -| 1], 0..) |*cert, index| {
            if (mask & bit(index) != 0 and std.mem.eql(u8, serial, cert.serial)) revoked = true;
        }
    }
    if (revoked) return error.Revoked;
}
fn addSerial(entries: []const u8, serial: []const u8, offsets: []u32, count: *usize, offset: usize) Error!void {
    @setRuntimeSafety(true);
    if (count.* == offsets.len or offset > std.math.maxInt(u32)) return error.VerificationLimit;
    var start: usize = 0;
    var end = count.*;
    while (start < end) {
        const middle = start + (end - start) / 2;
        var reader: Der.Reader = .{ .bytes = entries, .offset = offsets[middle] };
        var old_entry = (try reader.expect(0x30)).reader();
        const old = try Der.integer((try old_entry.expect(2)).value);
        switch (std.mem.order(u8, old, serial)) {
            .eq => return error.InvalidRevocation,
            .lt => start = middle + 1,
            .gt => end = middle,
        }
    }
    @memmove(offsets[start + 1 .. count.* + 1], offsets[start..count.*]);
    offsets[start] = @intCast(offset); // safe: the public byte offset is bounded above by maxInt(u32).
    count.* += 1;
}
fn bit(index: usize) u16 {
    @setRuntimeSafety(true);
    return @as(u16, 1) << @intCast(index); // safe: all path indices are bounded below 16.
}
fn deadline(expires: i64, policy: T.RevocationPolicy) i64 {
    @setRuntimeSafety(true);
    // Acceptance and receipt expiry use the same explicitly configured skew.
    // safe: the skew is clamped to 86400 before conversion.
    return expires +| @as(i64, @intCast(@min(policy.clock_skew, 86400)));
}
fn extension(e: Der.Element) Error!C.Certificate.Extension {
    @setRuntimeSafety(true);
    var r = e.reader();
    const id = (try r.expect(6)).value;
    var critical = false;
    if (r.peek() == 1) {
        critical = try Der.boolean((try r.next()).value);
        if (!critical) return error.InvalidDer;
    }
    const value = (try r.expect(4)).value;
    try r.finish();
    try Der.validate(value, .{});
    return .{ .oid = id, .critical = critical, .value = value };
}
fn unique(ids: *[64][]const u8, count: *usize, id: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (count.* == ids.len) return error.VerificationLimit;
    for (ids[0..count.*]) |old| if (std.mem.eql(u8, old, id)) return error.InvalidRevocation;
    ids[count.*] = id;
    count.* += 1;
}
fn ocsp(path: []const C.Certificate, now: i64, policy: T.RevocationPolicy, evidence: T.Evidence, der: []const u8) Error!EvidenceResult {
    @setRuntimeSafety(true);
    try Der.validate(der, .{});
    var r = (try Der.single(der, 0x30)).reader();
    if (try Der.number((try r.expect(10)).value) != 0) return error.UnknownRevocation;
    var response = (try Der.single((try r.expect(0xa0)).value, 0x30)).reader();
    try r.finish();
    if (!std.mem.eql(u8, (try response.expect(6)).value, "\x2b\x06\x01\x05\x05\x07\x30\x01\x01")) return error.UnsupportedRevocation;
    const bytes = (try response.expect(4)).value;
    try response.finish();
    try Der.validate(bytes, .{});
    var basic = (try Der.single(bytes, 0x30)).reader();
    const tbs = try basic.expect(0x30);
    const algorithm = try basic.expect(0x30);
    const sig = try Der.octetBits((try basic.expect(3)).value);
    const certs = if (basic.peek() == 0xa0) (try Der.single((try basic.next()).value, 0x30)).value else &.{};
    try basic.finish();
    var data = tbs.reader();
    if (data.peek() == 0xa0) return error.InvalidDer; // v1 DEFAULT must be absent.
    const responder = try data.next();
    if (responder.tag != 0xa1 and responder.tag != 0xa2) return error.InvalidRevocation;
    const produced = try C.Certificate.evidenceTime(try data.expect(0x18));
    // safe: the skew is clamped to 86400 before conversion.
    if (produced > now +| @as(i64, @intCast(@min(policy.clock_skew, 86400)))) return error.StaleRevocation;
    const responses = (try data.expect(0x30)).value;
    if (data.peek() == 0xa1) try ocspExtensions((try data.next()).value);
    try data.finish();
    var selected = try responsesFor(path, responses, now, policy, produced);
    const issuer = &path[selected.covered + 1];
    var authority = try authorized(issuer, responder, issuer, now, policy, evidence, algorithm.encoded, tbs.encoded, sig);
    if (authority == null) {
        var supplied: Der.Reader = .{ .bytes = certs };
        var count: usize = 0;
        while (!supplied.empty()) {
            count += 1;
            if (count > 16) return error.VerificationLimit;
            const delegated = try C.parse((try supplied.expect(0x30)).encoded, .{});
            if (try authorized(&delegated, responder, issuer, now, policy, evidence, algorithm.encoded, tbs.encoded, sig)) |expiry| {
                authority = if (authority) |old| @min(old, expiry) else expiry;
            }
        }
        if (authority == null) return error.InvalidRevocation;
    }
    selected.expires = @min(selected.expires, authority.?);
    return selected;
}
fn responsesFor(path: []const C.Certificate, responses: []const u8, now: i64, policy: T.RevocationPolicy, produced: i64) Error!EvidenceResult {
    @setRuntimeSafety(true);
    var r: Der.Reader = .{ .bytes = responses };
    var selected: ?EvidenceResult = null;
    var ids: [64][]const u8 = undefined;
    var count: usize = 0;
    while (!r.empty()) {
        var single = (try r.expect(0x30)).reader();
        const cert_id = try single.expect(0x30);
        try unique(&ids, &count, cert_id.encoded);
        const status = try single.next();
        if (status.tag != 0x80 and status.tag != 0xa1 and status.tag != 0x82) return error.InvalidRevocation;
        if ((status.tag == 0x80 or status.tag == 0x82) and status.value.len != 0) return error.InvalidRevocation;
        const this = try C.Certificate.evidenceTime(try single.expect(0x18));
        const next: ?i64 = if (single.peek() == 0xa0) try C.Certificate.evidenceTime(try Der.single((try single.next()).value, 0x18)) else null;
        if (single.peek() == 0xa1) try ocspExtensions((try single.next()).value);
        try single.finish();
        const expires = try fresh(this, next, now, policy);
        // safe: the skew is clamped to 86400 before conversion.
        if (produced < this -| @as(i64, @intCast(@min(policy.clock_skew, 86400))) or produced > expires +| @as(i64, @intCast(@min(policy.clock_skew, 86400)))) return error.StaleRevocation;
        for (path[0..path.len -| 1], 0..) |*cert, index| {
            if (!try certId(cert_id, cert, &path[index + 1])) continue;
            if (status.tag == 0xa1) return error.Revoked;
            if (status.tag == 0x82) return error.UnknownRevocation;
            if (selected != null) return error.InvalidRevocation;
            selected = .{ .covered = index, .expires = deadline(expires, policy) };
        }
    }
    return selected orelse error.InvalidRevocation;
}
fn certId(e: Der.Element, cert: *const C.Certificate, issuer: *const C.Certificate) Error!bool {
    @setRuntimeSafety(true);
    var r = e.reader();
    var hash = (try r.expect(0x30)).reader();
    const id = (try hash.expect(6)).value;
    if (!hash.empty()) if ((try hash.expect(5)).value.len != 0) return error.InvalidDer;
    try hash.finish();
    const name = (try r.expect(4)).value;
    const key = (try r.expect(4)).value;
    const serial = try Der.integer((try r.expect(2)).value);
    try r.finish();
    if (!std.mem.eql(u8, serial, cert.serial)) return false;
    if (std.mem.eql(u8, id, "\x2b\x0e\x03\x02\x1a")) return hashes(std.crypto.hash.Sha1, issuer, name, key);
    if (std.mem.eql(u8, id, "\x60\x86\x48\x01\x65\x03\x04\x02\x01")) return hashes(std.crypto.hash.sha2.Sha256, issuer, name, key);
    return error.UnsupportedRevocation;
}
fn hashes(comptime H: type, issuer: *const C.Certificate, name: []const u8, key: []const u8) Error!bool {
    @setRuntimeSafety(true);
    var spki = (try Der.single(issuer.spki, 0x30)).reader();
    _ = try spki.expect(0x30);
    const bytes = try Der.octetBits((try spki.expect(3)).value);
    var n: [H.digest_length]u8 = undefined;
    var k: [H.digest_length]u8 = undefined;
    H.hash(issuer.subject, &n, .{});
    H.hash(bytes, &k, .{});
    return std.mem.eql(u8, name, &n) and std.mem.eql(u8, key, &k);
}
fn authorized(cert: *const C.Certificate, responder: Der.Element, issuer: *const C.Certificate, now: i64, policy: T.RevocationPolicy, evidence: T.Evidence, algorithm: []const u8, message: []const u8, sig: []const u8) Error!?i64 {
    @setRuntimeSafety(true);
    var expiry: i64 = std.math.maxInt(i64);
    if (responder.tag == 0xa1) {
        if (!C.Name.equal(cert.subject, responder.value)) return null;
    } else {
        var spki = (try Der.single(cert.spki, 0x30)).reader();
        _ = try spki.expect(0x30);
        const key = try Der.octetBits((try spki.expect(3)).value);
        var digest: [20]u8 = undefined;
        std.crypto.hash.Sha1.hash(key, &digest, .{});
        if (!std.mem.eql(u8, (try Der.single(responder.value, 4)).value, &digest)) return null;
    }
    if (!std.mem.eql(u8, cert.der, issuer.der)) {
        if (!C.Name.equal(cert.issuer, issuer.subject) or cert.not_before > now or cert.not_after < now) return null;
        const eku = cert.x509(37) orelse return null;
        var r = try C.Extensions.sequence(eku.value);
        var signing = false;
        while (!r.empty()) if (std.mem.eql(u8, (try r.expect(6)).value, "\x2b\x06\x01\x05\x05\x07\x03\x09")) {
            signing = true;
        };
        if (!signing) return null;
        if (cert.x509(15)) |ku| if (try C.Extensions.keyUsage(ku.value) & 1 == 0) return null;
        signatures.verify(issuer.public_key, cert.signature_algorithm, cert.tbs, cert.signature) catch return null;
        expiry = cert.not_after;
        if (cert.extension("\x2b\x06\x01\x05\x05\x07\x30\x01\x05")) |no_check| {
            const value = try Der.single(no_check.value, 5);
            if (value.value.len != 0) return error.InvalidRevocation;
        } else {
            // A delegated responder is itself checked against supplied direct CRLs.
            // Its OCSP response cannot establish its own non-revocation.
            expiry = @min(expiry, try responderCrl(cert, issuer, now, policy, evidence.crls));
        }
    }
    signatures.verify(cert.public_key, try C.Algorithm.signature(algorithm), message, sig) catch return null;
    return expiry;
}
fn responderCrl(cert: *const C.Certificate, issuer: *const C.Certificate, now: i64, policy: T.RevocationPolicy, crls: []const []const u8) Error!i64 {
    @setRuntimeSafety(true);
    var expiry: ?i64 = null;
    for (crls) |der| {
        const result = crl(&.{ cert.*, issuer.* }, now, policy, der) catch |err| {
            if (err == error.NotApplicableRevocation) continue;
            return err;
        };
        expiry = if (expiry) |old| @min(old, result.expires) else result.expires;
    }
    return expiry orelse error.MissingRevocation;
}
fn ocspExtensions(encoded: []const u8) Error!void {
    @setRuntimeSafety(true);
    var r = try C.Extensions.sequence(encoded);
    var ids: [64][]const u8 = undefined;
    var count: usize = 0;
    while (!r.empty()) {
        const e = try extension(try r.expect(0x30));
        try unique(&ids, &count, e.oid);
        if (e.critical) return error.UnsupportedRevocation;
    }
}
test {
    _ = @import("revocation_test.zig");
}
