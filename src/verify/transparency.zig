//! Certificate Transparency (RFC 6962): a verified path's signed certificate timestamps checked
//! against the caller's logs and policy. Offline: log lists, their states and freshness are the
//! caller's; inclusion proofs and gossip are not checked.
const std = @import("std");
const C = @import("../certificate.zig");
const T = @import("../types.zig");
const Der = @import("../wire/Der.zig");
const Reader = @import("../wire/Reader.zig");
const signatures = @import("signature.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = std.mem.Allocator.Error || error{ MissingTransparency, InvalidTransparency, StaleTransparency, InvalidTransparencyPolicy, VerificationLimit };
pub const Result = struct { status: T.TransparencyStatus, expires: ?i64 = null };

/// The certificate extension carrying the SCTs a log issued for the precertificate
/// (1.3.6.1.4.1.11129.2.4.2, RFC 6962 section 3.3).
pub const sct_list_oid = "\x2b\x06\x01\x04\x01\xd6\x79\x02\x04\x02";

/// A version 1 SCT, borrowed from its list.
pub const Sct = struct {
    log_id: *const [32]u8,
    /// Milliseconds since the epoch, as the log signed it.
    timestamp: u64,
    extensions: []const u8,
    hash: u8,
    signature_algorithm: u8,
    signature: []const u8,
};

/// What a log signed: the certificate itself (an SCT delivered beside it), or its precertificate
/// (an SCT embedded in it): the issuer's key hash and the TBSCertificate without the SCT list.
pub const Entry = union(enum) {
    x509: []const u8,
    precert: struct { issuer_key_hash: *const [32]u8, tbs: []const u8 },
};

/// The SCTs of a SignedCertificateTimestampList: its whole framing checked first (one or more
/// SCTs, none empty, each version 1 SCT exactly its fields), then version 1 SCTs one by one; an
/// SCT of another version is skipped (RFC 6962 section 3.2).
pub const List = struct {
    reader: Reader,

    pub fn init(bytes: []const u8) error{InvalidTransparency}!List {
        @setRuntimeSafety(true);
        var r: Reader = .{ .bytes = bytes };
        const list = r.vector(u16) catch return error.InvalidTransparency;
        r.finish() catch return error.InvalidTransparency;
        if (list.bytes.len == 0) return error.InvalidTransparency;
        var framing: List = .{ .reader = list };
        while (try framing.entry()) |_| {}
        return .{ .reader = list };
    }

    pub fn next(self: *List) ?Sct {
        @setRuntimeSafety(true);
        // unreachable: `init` checked the framing whole.
        while (self.entry() catch unreachable) |found| if (found) |sct| return sct;
        return null;
    }

    /// The next serialized SCT: a version 1 SCT, or null for another version; null at the end.
    fn entry(self: *List) error{InvalidTransparency}!??Sct {
        @setRuntimeSafety(true);
        if (self.reader.pos == self.reader.bytes.len) return null;
        var one = self.reader.vector(u16) catch return error.InvalidTransparency;
        if (one.bytes.len == 0) return error.InvalidTransparency;
        if (one.bytes[0] != 0) return @as(?Sct, null);
        return @as(?Sct, parse(&one) catch return error.InvalidTransparency);
    }

    fn parse(r: *Reader) Reader.ReadError!Sct {
        @setRuntimeSafety(true);
        _ = try r.int(u8);
        const id = (try r.take(32))[0..32];
        const timestamp = try r.int(u64);
        const extensions = (try r.vector(u16)).bytes;
        const hash = try r.int(u8);
        const algorithm = try r.int(u8);
        const signature = (try r.vector(u16)).bytes;
        try r.finish();
        if (signature.len == 0) return error.InvalidLength;
        return .{ .log_id = id, .timestamp = timestamp, .extensions = extensions, .hash = hash, .signature_algorithm = algorithm, .signature = signature };
    }
};

/// Checks `path`'s SCTs, those embedded in its leaf and those delivered beside it (`scts`),
/// against `policy` at `now_ms`. Each signature verified spends one of `signatures`.
pub fn check(gpa: std.mem.Allocator, path: []const C.Certificate, now_ms: i64, required: ?*const T.TransparencyPolicy, scts: []const []const u8, signatures_left: *usize) Error!Result {
    @setRuntimeSafety(true);
    const policy = (required orelse return .{ .status = .unchecked }).*;
    try validate(policy);
    if (path.len == 0 or scts.len > T.TransparencyPolicy.max_lists) return error.VerificationLimit;
    const expires: ?i64 = if (policy.expires) |t| T.milliseconds(t) else null;
    if (expires) |deadline| if (now_ms >= deadline) return error.StaleTransparency;
    const ids = try gpa.alloc([32]u8, policy.logs.len);
    defer gpa.free(ids);
    // Every listed key is checked, not only those an SCT names: a list naming a key no log can
    // hold is the caller's error, refused whatever the certificate carries.
    for (policy.logs, ids) |log, *id| {
        _ = try logKey(log.key);
        Sha256.hash(log.key, id, .{});
    }
    var context: Context = .{ .gpa = gpa, .policy = policy, .ids = ids, .now_ms = now_ms, .signatures_left = signatures_left };
    const leaf = &path[0];
    // Embedded SCTs are checked over the precertificate, which names its issuer's key: a leaf
    // that is its own anchor has none to check them by.
    if (leaf.extension(sct_list_oid)) |ext| if (path.len > 1) {
        const bytes = (Der.single(ext.value, 4) catch return error.InvalidTransparency).value;
        var list = try List.init(bytes);
        const tbs = try precertificate(gpa, leaf.tbs);
        defer gpa.free(tbs);
        var issuer_key_hash: [32]u8 = undefined;
        Sha256.hash(path[1].spki, &issuer_key_hash, .{});
        const lifetime = leaf.not_after -| leaf.not_before;
        const need = if (lifetime > T.spanSeconds(policy.long_lifetime)) policy.embedded_long else policy.embedded;
        var tally: Tally = .{};
        while (list.next()) |sct| {
            try context.count(&tally, sct, .{ .precert = .{ .issuer_key_hash = &issuer_key_hash, .tbs = tbs } }, true);
            if (tally.meets(policy, need)) return compliant(expires);
        }
    };
    // Delivered SCTs sign the certificate as it is, and count only from logs not retired.
    var tally: Tally = .{};
    for (scts) |bytes| {
        var list = try List.init(bytes);
        while (list.next()) |sct| {
            try context.count(&tally, sct, .{ .x509 = leaf.der }, false);
            if (tally.meets(policy, policy.delivered)) return compliant(expires);
        }
    }
    return error.MissingTransparency;
}

/// A compliant verdict, holding through the last whole second before the list expires (a
/// receipt's `expires` is the start of the last second it holds for).
fn compliant(expires_ms: ?i64) Result {
    return .{ .status = .compliant, .expires = if (expires_ms) |ms| @divFloor(ms - 1, std.time.ms_per_s) else null };
}

/// The policy's shape: one to `max_logs` logs, each count one to `max_count`.
pub fn validate(policy: T.TransparencyPolicy) error{InvalidTransparencyPolicy}!void {
    @setRuntimeSafety(true);
    const P = T.TransparencyPolicy;
    if (policy.logs.len == 0 or policy.logs.len > P.max_logs) return error.InvalidTransparencyPolicy;
    for ([_]u8{ policy.embedded, policy.embedded_long, policy.delivered, policy.operators }) |n| if (n == 0 or n > P.max_count) return error.InvalidTransparencyPolicy;
    if (T.Nanoseconds.fromIoDuration(policy.long_lifetime, .exact).compare(.fromRaw(0)) == .lt) return error.InvalidTransparencyPolicy;
}

/// The distinct logs whose SCTs verified, in one tally (embedded or delivered).
const Tally = struct {
    logs: [max]u16 = undefined,
    current: bool = false,
    n: usize = 0,
    const max = T.TransparencyPolicy.max_count * 4;

    fn has(self: *const Tally, index: usize) bool {
        for (self.logs[0..self.n]) |log| if (log == index) return true;
        return false;
    }

    fn meets(self: *const Tally, policy: T.TransparencyPolicy, need: u8) bool {
        @setRuntimeSafety(true);
        if (self.n < need or !self.current) return false;
        // Distinct operators among the counted logs.
        var operators: usize = 0;
        for (self.logs[0..self.n], 0..) |log, i| {
            const name = policy.logs[log].operator;
            const seen = for (self.logs[0..i]) |prior| {
                if (std.mem.eql(u8, policy.logs[prior].operator, name)) break true;
            } else false;
            operators += @intFromBool(!seen);
        }
        return operators >= policy.operators;
    }
};

const Context = struct {
    gpa: std.mem.Allocator,
    policy: T.TransparencyPolicy,
    ids: []const [32]u8,
    now_ms: i64,
    signatures_left: *usize,

    /// Counts `sct` when it is from a listed log not yet counted, timestamped before now and
    /// before the log retired (a delivered one only from a log not retired), and its signature
    /// verifies over `entry`. Anything else is skipped, never trusted.
    fn count(self: *Context, tally: *Tally, sct: Sct, entry: Entry, embedded: bool) Error!void {
        @setRuntimeSafety(true);
        if (tally.n == Tally.max) return;
        const index = for (self.ids, 0..) |*id, i| {
            if (std.mem.eql(u8, id, sct.log_id)) break i;
        } else return;
        if (tally.has(index)) return;
        const log = self.policy.logs[index];
        const timestamp = std.math.cast(i64, sct.timestamp) orelse return;
        if (timestamp > self.now_ms) return;
        const current = if (log.retired) |at| self.now_ms < T.milliseconds(at) else true;
        if (log.retired) |at| if (timestamp >= T.milliseconds(at)) return;
        if (!embedded and !current) return;
        const key = try logKey(log.key);
        const signs: u8 = if (key.algorithm == .ecdsa) 3 else 1;
        if (sct.hash != 4 or sct.signature_algorithm != signs) return;
        if (self.signatures_left.* == 0) return error.VerificationLimit;
        self.signatures_left.* -= 1;
        const input = try signedInput(self.gpa, sct, entry);
        defer self.gpa.free(input);
        signatures.verify(key.key, key.algorithm, input, sct.signature) catch return;
        tally.logs[tally.n] = @intCast(index);
        tally.n += 1;
        tally.current = tally.current or current;
    }
};

/// A log's key and what it signs with (RFC 6962 section 2.1.4): ECDSA over P-256 or RSA
/// (PKCS#1 v1.5), each with SHA-256.
fn logKey(spki: []const u8) error{InvalidTransparencyPolicy}!struct { key: C.Algorithm.PublicKey, algorithm: C.Algorithm.Signature } {
    @setRuntimeSafety(true);
    const key = C.Algorithm.publicKey(spki) catch return error.InvalidTransparencyPolicy;
    return .{ .key = key, .algorithm = switch (key) {
        .ec => |ec| if (ec.curve == .p256) .{ .ecdsa = .sha256 } else return error.InvalidTransparencyPolicy,
        .rsa => |rsa| if (!rsa.pss_only) .{ .rsa = .sha256 } else return error.InvalidTransparencyPolicy,
        else => return error.InvalidTransparencyPolicy,
    } };
}

/// The bytes an SCT's signature covers (RFC 6962 section 3.2): its version, the
/// certificate_timestamp type, its timestamp, the entry and its extensions.
pub fn signedInput(gpa: std.mem.Allocator, sct: Sct, entry: Entry) Error![]u8 {
    @setRuntimeSafety(true);
    const der = switch (entry) {
        .x509 => |bytes| bytes,
        .precert => |pre| pre.tbs,
    };
    if (der.len > 0xffffff) return error.InvalidTransparency;
    const key_hash: usize = if (entry == .precert) 32 else 0;
    const entry_len = key_hash + 3 + der.len;
    const out = try gpa.alloc(u8, 12 + entry_len + 2 + sct.extensions.len);
    var at: usize = 0;
    const put = struct {
        fn bytes(o: []u8, cursor: *usize, value: []const u8) void {
            @memcpy(o[cursor.*..][0..value.len], value);
            cursor.* += value.len;
        }
    }.bytes;
    put(out, &at, &.{ 0, 0 });
    std.mem.writeInt(u64, out[at..][0..8], sct.timestamp, .big);
    at += 8;
    std.mem.writeInt(u16, out[at..][0..2], @intFromBool(entry == .precert), .big);
    at += 2;
    if (entry == .precert) put(out, &at, entry.precert.issuer_key_hash);
    // safe: bounded by the u24 maximum above.
    std.mem.writeInt(u24, out[at..][0..3], @intCast(der.len), .big);
    at += 3;
    put(out, &at, der);
    // safe: a vector of a u16-framed list.
    std.mem.writeInt(u16, out[at..][0..2], @intCast(sct.extensions.len), .big);
    at += 2;
    put(out, &at, sct.extensions);
    return out;
}

/// The precertificate's TBSCertificate a log signed (RFC 6962 section 3.2), from the final
/// certificate's: the SCT list extension removed and the TBS re-encoded; with no extension left,
/// the extensions field goes too. The issuer and its key identifier are the final issuer's
/// already, also when a precertificate signing certificate signed the precertificate.
pub fn precertificate(gpa: std.mem.Allocator, tbs: []const u8) Error![]u8 {
    @setRuntimeSafety(true);
    const body = (Der.single(tbs, 0x30) catch return error.InvalidTransparency).value;
    var r: Der.Reader = .{ .bytes = body };
    const extensions = while (!r.empty()) {
        const start = r.offset;
        const element = r.next() catch return error.InvalidTransparency;
        if (element.tag == 0xa3) break .{ .start = start, .element = element };
    } else return error.InvalidTransparency;
    const sequence = Der.single(extensions.element.value, 0x30) catch return error.InvalidTransparency;
    var list = sequence.reader();
    var kept: usize = 0;
    var found: usize = 0;
    while (!list.empty()) {
        const ext = list.expect(0x30) catch return error.InvalidTransparency;
        var er = ext.reader();
        const id = (er.expect(6) catch return error.InvalidTransparency).value;
        if (std.mem.eql(u8, id, sct_list_oid)) found += 1 else kept += ext.encoded.len;
    }
    if (found != 1) return error.InvalidTransparency;
    const prefix = body[0..extensions.start];
    const suffix = body[r.offset..];
    const inner = if (kept == 0) 0 else Der.headerLength(kept) + kept;
    const fields = if (kept == 0) 0 else Der.headerLength(inner) + inner;
    const total = prefix.len + fields + suffix.len;
    const out = try gpa.alloc(u8, Der.headerLength(total) + total);
    var at = Der.header(out, 0, 0x30, total);
    @memcpy(out[at..][0..prefix.len], prefix);
    at += prefix.len;
    if (kept != 0) {
        at = Der.header(out, at, 0xa3, inner);
        at = Der.header(out, at, 0x30, kept);
        list = sequence.reader();
        while (!list.empty()) {
            // unreachable: the first pass read every extension and its OID.
            const ext = list.expect(0x30) catch unreachable;
            var er = ext.reader();
            // unreachable: as above.
            if (std.mem.eql(u8, (er.expect(6) catch unreachable).value, sct_list_oid)) continue;
            @memcpy(out[at..][0..ext.encoded.len], ext.encoded);
            at += ext.encoded.len;
        }
    }
    @memcpy(out[at..][0..suffix.len], suffix);
    at += suffix.len;
    std.debug.assert(at == out.len);
    return out;
}

test {
    _ = @import("transparency_test.zig");
}
