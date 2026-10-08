//! A bounded borrowed view. The caller owns DER for the view's lifetime.
const Der = @import("../wire/Der.zig");
pub const Algorithm = @import("Algorithm.zig");
const Name = @import("Name.zig");
const Extensions = @import("Extensions.zig");
const fields = @import("fields.zig");
pub const Limits = fields.Limits;
pub const ParseError = fields.ParseError;
pub const Extension = fields.Extension;
pub const Certificate = @This();
der: []const u8,
tbs: []const u8,
serial: []const u8,
issuer: []const u8,
subject: []const u8,
spki: []const u8,
public_key: Algorithm.PublicKey,
signature_algorithm: Algorithm.Signature,
signature: []const u8,
not_before: i64,
not_after: i64,
version: u8,
extensions: [64]Extension = undefined,
extension_count: usize = 0,
pub fn extension(self: *const Certificate, id: []const u8) ?Extension {
    @setRuntimeSafety(true);
    for (self.extensions[0..self.extension_count]) |e| if (Algorithm.eql(e.oid, id)) return e;
    return null;
}
pub fn x509(self: *const Certificate, id: u8) ?Extension {
    @setRuntimeSafety(true);
    return self.extension(&.{ 0x55, 0x1d, id });
}
pub fn selfIssued(self: *const Certificate) bool {
    @setRuntimeSafety(true);
    return Name.equal(self.subject, self.issuer);
}
pub fn parse(bytes: []const u8, limits: Limits) ParseError!Certificate {
    @setRuntimeSafety(true);
    try Der.validate(bytes, .{ .bytes = limits.bytes, .elements = limits.elements, .depth = limits.depth });
    var outer = (try Der.single(bytes, 0x30)).reader();
    const tbs = try outer.expect(0x30);
    const alg = try outer.expect(0x30);
    const sig = try Der.octetBits((try outer.expect(3)).value);
    try outer.finish();
    var r = tbs.reader();
    var version: u8 = 0;
    if (r.peek() == 0xa0) {
        const v = try Der.number((try Der.single((try r.next()).value, 2)).value);
        if (v == 0 or v > 2) return error.InvalidCertificate;
        // safe: the version was checked to be one or two.
        version = @intCast(v);
    }
    const serial = try Der.integer((try r.expect(2)).value);
    if (serial.len > 20) return error.InvalidCertificate;
    const inner_alg = try r.expect(0x30);
    if (!Algorithm.eql(inner_alg.encoded, alg.encoded)) return error.InvalidCertificate;
    const signature_algorithm = try Algorithm.signature(alg.encoded);
    const issuer = try r.expect(0x30);
    try Name.validate(issuer.encoded);
    if (issuer.value.len == 0) return error.InvalidCertificate;
    var validity = (try r.expect(0x30)).reader();
    const not_before = try time(try validity.next());
    const not_after = try time(try validity.next());
    try validity.finish();
    if (not_after < not_before) return error.InvalidCertificate;
    const subject = try r.expect(0x30);
    try Name.validate(subject.encoded);
    const spki = try r.expect(0x30);
    const pk = try Algorithm.publicKey(spki.encoded);
    var cert: Certificate = .{ .der = bytes, .tbs = tbs.encoded, .serial = serial, .issuer = issuer.encoded, .subject = subject.encoded, .spki = spki.encoded, .public_key = pk, .signature_algorithm = signature_algorithm, .signature = sig, .not_before = not_before, .not_after = not_after, .version = version };
    if (r.peek() == 0x81) {
        if (version == 0) return error.InvalidCertificate;
        _ = try Der.bits((try r.next()).value);
    }
    if (r.peek() == 0x82) {
        if (version == 0) return error.InvalidCertificate;
        _ = try Der.bits((try r.next()).value);
    }
    if (r.peek() == 0xa3) {
        if (version != 2) return error.InvalidCertificate;
        var exts = (try Der.single((try r.next()).value, 0x30)).reader();
        if (exts.empty()) return error.InvalidCertificate;
        while (!exts.empty()) {
            if (cert.extension_count >= @min(limits.extensions, cert.extensions.len)) return error.DerLimit;
            var er = (try exts.expect(0x30)).reader();
            const id = (try er.expect(6)).value;
            var critical = false;
            if (er.peek() == 1) {
                critical = try Der.boolean((try er.next()).value);
                if (!critical) return error.InvalidDer;
            }
            const value = (try er.expect(4)).value;
            try er.finish();
            if (cert.extension(id) != null) return error.DuplicateExtension;
            cert.extensions[cert.extension_count] = .{ .oid = id, .critical = critical, .value = value };
            cert.extension_count += 1;
            try Extensions.validate(.{ .oid = id, .critical = critical, .value = value }, limits);
        }
    }
    try r.finish();
    if (subject.value.len == 0) {
        const san = cert.x509(17) orelse return error.InvalidCertificate;
        if (!san.critical) return error.InvalidCertificate;
    }
    // Signatures have their own canonical encoding, independent of issuer selection.
    switch (signature_algorithm) {
        .ecdsa => {
            var sr = (try Der.single(sig, 0x30)).reader();
            for (0..2) |_| {
                const n = try Der.integer((try sr.expect(2)).value);
                if (n.len > 48 or (n.len == 1 and n[0] == 0)) return error.InvalidCertificate;
            }
            try sr.finish();
        },
        .ed25519 => if (sig.len != 64) return error.InvalidCertificate,
        .unsupported => {},
        .rsa, .pss => if (sig.len < 256 or sig.len > 512) return error.InvalidCertificate,
    }
    return cert;
}
pub fn time(e: Der.Element) ParseError!i64 {
    @setRuntimeSafety(true);
    return parseTime(e, true);
}
pub fn evidenceTime(e: Der.Element) ParseError!i64 {
    @setRuntimeSafety(true);
    return parseTime(e, false);
}
fn parseTime(e: Der.Element, profile: bool) ParseError!i64 {
    @setRuntimeSafety(true);
    const s = e.value;
    var cursor: usize = 0;
    var year: i64 = undefined;
    if (e.tag == 0x17) {
        if (s.len != 13) return error.InvalidTime;
        const y = try digits(s[0..2]);
        year = if (y >= 50) 1900 + y else 2000 + y;
        cursor = 2;
    } else if (e.tag == 0x18) {
        if (s.len != 15) return error.InvalidTime;
        year = try digits(s[0..4]);
        if (year == 0) return error.InvalidTime;
        if (profile and year < 2050) return error.InvalidTime;
        cursor = 4;
    } else return error.InvalidTime;
    if (s[s.len - 1] != 'Z') return error.InvalidTime;
    const month = try digits(s[cursor..][0..2]);
    const day = try digits(s[cursor + 2 ..][0..2]);
    const hour = try digits(s[cursor + 4 ..][0..2]);
    const minute = try digits(s[cursor + 6 ..][0..2]);
    const second = try digits(s[cursor + 8 ..][0..2]);
    const leap = @mod(year, 4) == 0 and (@mod(year, 100) != 0 or @mod(year, 400) == 0);
    const days = [_]i64{ 31, if (leap) 29 else 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31 };
    // safe: month bounds short-circuit before month - 1 is cast or indexed.
    if (month < 1 or month > 12 or day < 1 or day > days[@intCast(month - 1)] or hour > 23 or minute > 59 or second > 59) return error.InvalidTime;
    var total: i64 = 0;
    var y: i64 = 1970;
    while (y < year) : (y += 1) total += if (@mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0)) @as(i64, 366) else 365;
    while (y > year) {
        y -= 1;
        total -= if (@mod(y, 4) == 0 and (@mod(y, 100) != 0 or @mod(y, 400) == 0)) @as(i64, 366) else 365;
    }
    // safe: the validated month is in 1..12.
    for (days[0..@intCast(month - 1)]) |d| total += d;
    return (total + day - 1) * 86400 + hour * 3600 + minute * 60 + second;
}
fn digits(s: []const u8) ParseError!i64 {
    @setRuntimeSafety(true);
    var n: i64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return error.InvalidTime;
        n = n * 10 + c - '0';
    }
    return n;
}
test {
    _ = @import("Certificate_test.zig");
}
