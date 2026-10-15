//! Stateless return routability for a DTLS server (RFC 9147 section 5.1, RFC 6347 section
//! 4.2.1): before any association exists, `check` answers a ClientHello without a valid cookie
//! with a HelloRetryRequest carrying one (DTLS 1.3) or a HelloVerifyRequest (DTLS 1.2), written
//! into the caller's buffer, at most three times the datagram's size (RFC 9147 section 5.1), and
//! keeps nothing. A hello that brings
//! a valid cookie back is admitted: the caller creates the association with the `Admission` and
//! hands it the same datagram.
//!
//! A cookie is a MAC under a key the caller supplies and rotates, over the client's address as
//! the caller names it, the time it was made and what the server answered: for DTLS 1.3 the
//! transcript hash of the first hello, the suite and group the retry request named and the
//! hello's fingerprint, which the association resumes from; for DTLS 1.2 the hello's random,
//! session id and suites. It is honoured for `lifetime` after it was made, under the current key
//! or the one before it.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Group = @import("../crypto/Group.zig").Group;
const Hello = @import("../handshake/Hello.zig");
const ClientHello = @import("../handshake/ClientHello.zig");
const Reader = @import("../wire/Reader.zig");
const Record = @import("Record.zig");
const Datagram = @import("Datagram.zig");

const Cookies = @This();
const Mac = std.crypto.auth.hmac.sha2.HmacSha256;

pub const Key = struct {
    id: u8,
    material: aegis.Secret([32]u8),
};

/// The current key and the one it replaced.
keys: [2]?Key = .{ null, null },
next_id: u8 = 0,
/// How long a cookie is honoured after it was made.
lifetime: std.Io.Duration = .fromSeconds(60),

pub const RotateError = error{InvalidKey};

/// Installs fresh key material (32 bytes the caller drew): cookies made under the key it replaces
/// stay valid for their lifetime, older ones no longer.
pub fn rotate(self: *Cookies, material: [32]u8) RotateError!void {
    @setRuntimeSafety(true);
    if (std.mem.allEqual(u8, &material, 0)) return error.InvalidKey;
    if (self.keys[1]) |*old| old.material.deinit();
    self.keys[1] = self.keys[0];
    self.keys[0] = .{ .id = self.next_id, .material = .init(material) };
    self.next_id +%= 1;
}

pub fn deinit(self: *Cookies) void {
    for (&self.keys) |*slot| if (slot.*) |*key| key.material.deinit();
    self.* = undefined;
}

/// What a valid cookie admits.
pub const Admission = @import("Admission.zig");

pub const Verdict = union(enum) {
    /// Send these bytes back to the hello's address, and keep nothing.
    respond: []u8,
    /// The address is proven: create the association and give it the datagram.
    admit: Admission,
    /// Not a hello this server answers: drop it.
    drop,
};

const max_cookie = Admission.max_cookie;
const v13: u8 = 0x13;

/// Checks the first record of `datagram`, from `address` (any bytes that name the client's path:
/// its IP and port), at `now` on the caller's clock. A response is written into `out`, which must
/// hold the datagram.
pub fn check(self: *const Cookies, options: *const Datagram.ServerOptions, address: []const u8, now: std.Io.Timestamp, datagram: []u8, out: []u8) Verdict {
    @setRuntimeSafety(true);
    if (self.keys[0] == null or address.len > 64) return .drop;
    const first = Record.split(datagram, 0) orelse return .drop;
    const header = switch (first.kind) {
        .classic => |h| h,
        .unified => return .drop,
    };
    if (first.record[0] != 22 or header.epoch != 0) return .drop;
    const body = first.record[header.length..];
    if (body.len < 12 or body[0] != 1) return .drop;
    const length: usize = std.mem.readInt(u24, body[1..4], .big);
    const offset: usize = std.mem.readInt(u24, body[6..9], .big);
    const fragment_len: usize = std.mem.readInt(u24, body[9..12], .big);
    if (offset != 0 or fragment_len > body.len - 12 or fragment_len > length or length > 64 * 1024) return .drop;
    const fragment = body[12..][0..fragment_len];
    const seconds: u64 = @intCast(@max(0, @divFloor(now.nanoseconds, std.time.ns_per_s)));
    const policy: Hello.Options = .{ .transport = .datagram, .suites = options.suites, .min_version = options.min_version, .max_version = options.max_version, .groups = options.groups, .require_hybrid = options.require_hybrid };
    // A whole hello is read as such; the first fragment of a longer one can still carry its
    // cookie (in the cookie field or, early enough, the cookie extension).
    if (fragment_len < length) return self.checkFragment(&policy, address, seconds, fragment, header.sequence, datagram.len, out);
    if (out.len < 4 + length + Record.header12 + 12) return .drop;
    // The hello in its TLS form: type and length, then the body.
    const message = out[0 .. 4 + length];
    message[0] = 1;
    // safe: bounded at 64 KiB above.
    std.mem.writeInt(u24, message[1..4], @intCast(length), .big);
    @memcpy(message[4..], fragment);
    const hello = ClientHello.parse(message, .datagram) catch return .drop;
    if (hello.offers13() and policy.allows13()) {
        if (hello.cookie.len != 0) return self.admit13(address, seconds, hello.cookie);
        return self.retry13(policy, address, seconds, &hello, message, header.sequence, datagram.len, out);
    }
    if (hello.offers12() and policy.allows12()) {
        if (hello.legacy_cookie.len != 0) return self.admit12(address, seconds, hello.random, hello.session, hello.suites, hello.legacy_cookie);
        return self.verify12(address, seconds, hello.random, hello.session, hello.suites, header.sequence, datagram.len, out);
    }
    return .drop;
}

fn keyFor(self: *const Cookies, id: u8) ?*const Key {
    for (&self.keys) |*slot| if (slot.*) |*key| if (key.id == id) return key;
    return null;
}

fn fresh(self: *const Cookies, issued: u64, now: u64) bool {
    const lifetime: u64 = @intCast(@max(0, @divFloor(self.lifetime.nanoseconds, std.time.ns_per_s)));
    // A minute of the caller's clock running back is tolerated, not more.
    return issued <= now + 60 and now -| issued <= lifetime;
}

fn mac(key: *const Key, label: []const u8, address: []const u8, parts: []const []const u8, out: *[32]u8) void {
    var h = Mac.init(key.material.expose());
    defer std.crypto.secureZero(u8, std.mem.asBytes(&h));
    h.update(label);
    h.update(&.{@intCast(address.len)});
    h.update(address);
    for (parts) |part| {
        var len: [2]u8 = undefined;
        // safe: every part is a field of a bounded hello.
        std.mem.writeInt(u16, &len, @intCast(part.len), .big);
        h.update(&len);
        h.update(part);
    }
    h.final(out);
}

// ---------------------------------------------------------------- DTLS 1.3

/// A retry request with a cookie for this hello: the suite and group the server would choose,
/// asking for the group's share only when the hello has none.
fn retry13(self: *const Cookies, policy: Hello.Options, address: []const u8, seconds: u64, hello: *const ClientHello, message: []const u8, record_sequence: u64, received: usize, out: []u8) Verdict {
    @setRuntimeSafety(true);
    if (!hello.null_compression_only or hello.legacy_cookie.len != 0 or !hello.has_schemes or !hello.has_groups or hello.sharesOutsideGroups()) return .drop;
    const suite = for (policy.suites) |candidate| {
        if (candidate.tls13()) |s| if (hello.offersSuite(@backingInt(s))) break s;
    } else return .drop;
    var asked = false;
    const group = for (policy.groups) |g| {
        if (hello.offersGroup(g) and hello.shareFor(g) != null) break g;
    } else for (policy.groups) |g| {
        if (hello.offersGroup(g)) {
            asked = true;
            break g;
        }
    } else return .drop;
    if (policy.require_hybrid and !group.hybrid()) return .drop;
    const key = &self.keys[0].?;
    var cookie: [max_cookie]u8 = undefined;
    cookie[0] = v13;
    cookie[1] = key.id;
    std.mem.writeInt(u64, cookie[2..10], seconds, .big);
    std.mem.writeInt(u16, cookie[10..12], @backingInt(suite), .big);
    std.mem.writeInt(u16, cookie[12..14], @backingInt(group), .big);
    const hash_len = suites.digestLength(suite);
    // safe: a digest length, 32 or 48.
    cookie[14] = @as(u8, @intCast(hash_len)) | @as(u8, if (asked) 0x80 else 0);
    cookie[15..47].* = hello.fingerprint();
    switch (hash_len) {
        48 => std.crypto.hash.sha2.Sha384.hash(message, cookie[47..][0..48], .{}),
        else => std.crypto.hash.sha2.Sha256.hash(message, cookie[47..][0..32], .{}),
    }
    const signed = 47 + hash_len;
    mac(key, "cloak dtls cookie 1.3", address, &.{cookie[0..signed]}, cookie[signed..][0..32]);
    const cookie_len = signed + 32;
    // The request goes out as the server's first message (message_seq 0), under the hello's own
    // record sequence (RFC 6347 section 4.2.1).
    var buffer: [256]u8 = undefined;
    const hrr = Hello.buildRetry(&buffer, .datagram, "", suite, if (asked) group else null, cookie[0..cookie_len], false) catch return .drop;
    return respond(hrr, record_sequence, received, out);
}

fn admit13(self: *const Cookies, address: []const u8, seconds: u64, cookie: []const u8) Verdict {
    @setRuntimeSafety(true);
    if (cookie.len < 47 + 32 + 32 or cookie.len > max_cookie or cookie[0] != v13) return .drop;
    const key = self.keyFor(cookie[1]) orelse return .drop;
    const hash_len: usize = cookie[14] & 0x7f;
    if ((hash_len != 32 and hash_len != 48) or cookie.len != 47 + hash_len + 32) return .drop;
    var expected: [32]u8 = undefined;
    mac(key, "cloak dtls cookie 1.3", address, &.{cookie[0 .. 47 + hash_len]}, &expected);
    if (!aegis.secret.equal(32, &expected, cookie[47 + hash_len ..][0..32]).declassify("a forged cookie is dropped")) return .drop;
    if (!self.fresh(std.mem.readInt(u64, cookie[2..10], .big), seconds)) return .drop;
    const suite = std.enums.fromInt(suites.Suite13, std.mem.readInt(u16, cookie[10..12], .big)) orelse return .drop;
    const group = std.enums.fromInt(Group, std.mem.readInt(u16, cookie[12..14], .big)) orelse return .drop;
    if (suites.digestLength(suite) != hash_len) return .drop;
    var retry: Admission.Retry = .{
        .suite = suite,
        .group = group,
        .asked = cookie[14] & 0x80 != 0,
        .hello_hash = @splat(0),
        // safe: 32 or 48.
        .hash_len = @intCast(hash_len),
        .fingerprint = cookie[15..47].*,
        .cookie = undefined,
        // safe: bounded at max_cookie above.
        .cookie_len = @intCast(cookie.len),
    };
    @memcpy(retry.hello_hash[0..hash_len], cookie[47..][0..hash_len]);
    @memcpy(retry.cookie[0..cookie.len], cookie);
    return .{ .admit = .{ .retry = retry } };
}

// ---------------------------------------------------------------- DTLS 1.2

/// A DTLS 1.2 cookie is 32 bytes, DTLS 1.0's limit, which some DTLS 1.2 clients still keep (one
/// sent back an empty cookie field for a longer one): the key's id, the time in 32 bits and 27
/// bytes of the MAC.
const cookie12 = 32;

fn verify12(self: *const Cookies, address: []const u8, seconds: u64, random: []const u8, session: []const u8, offered: []const u8, record_sequence: u64, received: usize, out: []u8) Verdict {
    @setRuntimeSafety(true);
    const key = &self.keys[0].?;
    var cookie: [cookie12]u8 = undefined;
    cookie[0] = key.id;
    std.mem.writeInt(u32, cookie[1..5], @truncate(seconds), .big);
    var full: [32]u8 = undefined;
    mac(key, "cloak dtls cookie 1.2", address, &.{ cookie[0..5], random, session, offered }, &full);
    cookie[5..32].* = full[0..27].*;
    var buffer: [64]u8 = undefined;
    const request = Hello.buildHelloVerify(&buffer, &cookie) catch return .drop;
    return respond(request, record_sequence, received, out);
}

fn admit12(self: *const Cookies, address: []const u8, seconds: u64, random: []const u8, session: []const u8, offered: []const u8, cookie: []const u8) Verdict {
    @setRuntimeSafety(true);
    if (cookie.len != cookie12) return .drop;
    const key = self.keyFor(cookie[0]) orelse return .drop;
    var expected: [32]u8 = undefined;
    mac(key, "cloak dtls cookie 1.2", address, &.{ cookie[0..5], random, session, offered }, &expected);
    if (!aegis.secret.equal(27, expected[0..27], cookie[5..32]).declassify("a forged cookie is dropped")) return .drop;
    // The 32-bit time wraps: its age is the difference, which must be within the lifetime.
    const lifetime: u64 = @intCast(@max(0, @divFloor(self.lifetime.nanoseconds, std.time.ns_per_s)));
    const age = @as(u32, @truncate(seconds)) -% std.mem.readInt(u32, cookie[1..5], .big);
    if (age > lifetime) return .drop;
    return .{ .admit = .{} };
}

/// The first fragment of a hello too long for one record: admitted if it carries a valid cookie.
/// Without one, a server of DTLS 1.2 alone answers it with a HelloVerifyRequest, whose cookie
/// covers only the random, session id and suites at its start; a server that also speaks DTLS 1.3
/// drops it, since the hello's versions may lie beyond the fragment, a DTLS 1.3 server must not
/// send a HelloVerifyRequest (RFC 9147 section 5.2), and its retry request's cookie covers the
/// whole hello's hash.
fn checkFragment(self: *const Cookies, policy: *const Hello.Options, address: []const u8, seconds: u64, fragment: []const u8, record_sequence: u64, received: usize, out: []u8) Verdict {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = fragment };
    _ = r.int(u16) catch return .drop;
    const random = r.take(32) catch return .drop;
    const session = (r.vector(u8) catch return .drop).bytes;
    const legacy_cookie = (r.vector(u8) catch return .drop).bytes;
    const offered = (r.vector(u16) catch return .drop).bytes;
    if (legacy_cookie.len != 0) return self.admit12(address, seconds, random, session, offered, legacy_cookie);
    if (!policy.allows13() and policy.allows12()) {
        if (session.len > 32 or offered.len < 2 or offered.len % 2 != 0) return .drop;
        return self.verify12(address, seconds, random, session, offered, record_sequence, received, out);
    }
    _ = r.vector(u8) catch return .drop;
    // The extensions present in this fragment, looking for the cookie.
    _ = r.int(u16) catch return .drop;
    while (r.bytes.len - r.pos >= 4) {
        const id = r.int(u16) catch return .drop;
        const len = r.int(u16) catch return .drop;
        if (r.bytes.len - r.pos < len) return .drop;
        const value = r.take(len) catch return .drop;
        if (id != 44) continue;
        var v: Reader = .{ .bytes = value };
        const cookie = (v.vector(u16) catch return .drop).bytes;
        return self.admit13(address, seconds, cookie);
    }
    return .drop;
}

/// `message` as the server's first handshake message (message_seq 0, unfragmented) in one
/// plaintext record with the hello's record sequence, at most three times the `received`
/// datagram: what answers an unproven address must not amplify it.
fn respond(message: []const u8, record_sequence: u64, received: usize, out: []u8) Verdict {
    @setRuntimeSafety(true);
    const total = Record.header12 + 12 + (message.len - 4);
    if (out.len < total or total > 3 * received) return .drop;
    var body: [12 + 512]u8 = undefined;
    if (message.len - 4 > 512) return .drop;
    body[0..4].* = message[0..4].*;
    body[4..6].* = .{ 0, 0 };
    body[6..9].* = .{ 0, 0, 0 };
    body[9..12].* = message[1..4].*;
    @memcpy(body[12..][0 .. message.len - 4], message[4..]);
    const record = Record.plaintext(.handshake, record_sequence, body[0 .. 12 + message.len - 4], out) catch return .drop;
    return .{ .respond = record };
}

test {
    _ = @import("Cookies_test.zig");
}
