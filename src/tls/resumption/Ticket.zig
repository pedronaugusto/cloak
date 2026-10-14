//! The server's session state inside a ticket: versioned, authenticated, opened only by the
//! ring key that sealed it. The client holds it as an opaque bearer token.
//!
//! Wire: format (1) | key id (8) | salt (16) | ciphertext | tag (16). The format byte names the
//! protocol version the session is for (1: a TLS 1.3 PSK, 2: a TLS 1.2 master secret), so a
//! ticket of one version is never opened as the other. The sealing key is HKDF of the ring key
//! over the salt, used for this one ticket with a zero nonce; the header is the associated data.
//! The plaintext is the session's suite, its secret, the times that bound it, the age obfuscator
//! (TLS 1.3), the ALPN protocol and server name it was made for, the client's authentication
//! and its expiry, and the digest of the policy it was made under.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Group = @import("../crypto/Group.zig").Group;
const TicketKeys = @import("TicketKeys.zig");

/// The format byte of each protocol version's tickets.
pub fn format(version: suites.Version) u8 {
    return switch (version) {
        .tls13 => 1,
        .tls12 => 2,
    };
}
pub const salt_length = 16;
const header_length = 1 + 8 + salt_length;
const Aead = suites.AeadOf(.aes_256_gcm);
const Hkdf = std.crypto.kdf.hkdf.HkdfSha256;

/// What a ticket says of its session. `secret` (a TLS 1.3 PSK or a TLS 1.2 master secret) is
/// erased by `deinit`.
pub const State = struct {
    version: suites.Version = .tls13,
    /// A suite of `version`.
    suite: suites.Suite,
    secret: aegis.Secret([48]u8) = .init(@splat(0)),
    /// The key exchange group of the session's full handshake (a resumed TLS 1.2 handshake has
    /// none of its own).
    group: Group = .x25519,
    /// When this ticket was issued, and when every ticket of its session expires (seconds).
    issued: i64,
    expires: i64,
    age_add: u32,
    alpn: [255]u8 = undefined,
    alpn_len: u8 = 0,
    server_name: [253]u8 = undefined,
    server_name_len: u8 = 0,
    /// The client was authenticated by a certificate under `policy`, until `auth_expires`.
    client_authenticated: bool = false,
    auth_expires: i64 = 0,
    policy: [32]u8,

    /// The secret's length: the suite's digest for a TLS 1.3 PSK, 48 bytes for a master secret.
    pub fn secretLength(version: suites.Version, suite: suites.Suite) usize {
        return switch (version) {
            .tls13 => suites.digestLength(suite.tls13().?),
            .tls12 => 48,
        };
    }

    pub fn secretBytes(state: *const State) []const u8 {
        return state.secret.expose()[0..secretLength(state.version, state.suite)];
    }

    pub fn alpnBytes(state: *const State) []const u8 {
        return state.alpn[0..state.alpn_len];
    }

    pub fn serverName(state: *const State) []const u8 {
        return state.server_name[0..state.server_name_len];
    }

    pub fn deinit(state: *State) void {
        state.secret.deinit();
    }
};

/// The longest plaintext: suite, PSK, times, age obfuscator, names, authentication, policy.
const max_plain = 2 + 1 + 48 + 2 + 8 + 8 + 4 + 1 + 255 + 1 + 253 + 1 + 8 + 32;
pub const max_length = header_length + max_plain + Aead.tag_length;

pub const SealError = error{BufferTooSmall};

/// Seals `state` under `key` with a fresh `salt` from the handshake's entropy.
pub fn seal(key: *const TicketKeys.Key, salt: *const [salt_length]u8, state: *const State, out: []u8) SealError![]u8 {
    @setRuntimeSafety(true);
    var plain_buf: [max_plain]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain_buf);
    const plain = encode(state, &plain_buf);
    const total = header_length + plain.len + Aead.tag_length;
    if (out.len < total) return error.BufferTooSmall;
    out[0] = format(state.version);
    out[1..9].* = key.id;
    out[9..][0..salt_length].* = salt.*;
    var sealing = aegis.Secret([Aead.key_length]u8).init(undefined);
    defer sealing.deinit();
    derive(key, salt, sealing.exposeMut());
    Aead.encrypt(out[header_length..][0..plain.len], out[header_length + plain.len ..][0..Aead.tag_length], plain, out[0..header_length], @splat(0), sealing.expose().*);
    return out[0..total];
}

pub const OpenError = error{Undecryptable};

/// Opens a ticket with the ring's key that sealed it, if that key still opens tickets at `now`.
/// Every failure is the same refusal: an unknown, retired, forged or malformed ticket.
pub fn open(ring: *const TicketKeys.Ring, ticket: []const u8, now: i64, out: *State) OpenError!void {
    @setRuntimeSafety(true);
    if (ticket.len < header_length + Aead.tag_length or ticket.len > max_length) return error.Undecryptable;
    const version: suites.Version = switch (ticket[0]) {
        1 => .tls13,
        2 => .tls12,
        else => return error.Undecryptable,
    };
    const key = ring.find(ticket[1..9], now) orelse return error.Undecryptable;
    const salt = ticket[9..][0..salt_length];
    var plain_buf: [max_plain]u8 = undefined;
    defer std.crypto.secureZero(u8, &plain_buf);
    const length = ticket.len - header_length - Aead.tag_length;
    const plain = plain_buf[0..length];
    var sealing = aegis.Secret([Aead.key_length]u8).init(undefined);
    defer sealing.deinit();
    derive(key, salt, sealing.exposeMut());
    Aead.decrypt(plain, ticket[header_length..][0..length], ticket[ticket.len - Aead.tag_length ..][0..Aead.tag_length].*, ticket[0..header_length], @splat(0), sealing.expose().*) catch return error.Undecryptable;
    decode(version, plain, out) catch {
        out.deinit();
        return error.Undecryptable;
    };
}

fn derive(key: *const TicketKeys.Key, salt: *const [salt_length]u8, out: *[Aead.key_length]u8) void {
    @setRuntimeSafety(true);
    var prk = Hkdf.extract(salt, key.material.expose());
    defer std.crypto.secureZero(u8, &prk);
    var info: [16 + 8]u8 = undefined;
    info[0..16].* = "cloak ticket v1\x00".*;
    info[16..24].* = key.id;
    Hkdf.expand(out, &info, prk);
}

fn encode(state: *const State, out: *[max_plain]u8) []const u8 {
    @setRuntimeSafety(true);
    var at: usize = 0;
    std.mem.writeInt(u16, out[at..][0..2], @backingInt(state.suite), .big);
    at += 2;
    const secret = state.secretBytes();
    // safe: a secret is 32 or 48 bytes.
    out[at] = @intCast(secret.len);
    @memcpy(out[at + 1 ..][0..secret.len], secret);
    at += 1 + secret.len;
    std.mem.writeInt(u16, out[at..][0..2], @backingInt(state.group), .big);
    at += 2;
    for ([_]i64{ state.issued, state.expires }) |t| {
        std.mem.writeInt(i64, out[at..][0..8], t, .big);
        at += 8;
    }
    std.mem.writeInt(u32, out[at..][0..4], state.age_add, .big);
    at += 4;
    for ([_][]const u8{ state.alpnBytes(), state.serverName() }) |name| {
        // safe: both names were bounded at 255 bytes where they were stored.
        out[at] = @intCast(name.len);
        @memcpy(out[at + 1 ..][0..name.len], name);
        at += 1 + name.len;
    }
    out[at] = @intFromBool(state.client_authenticated);
    at += 1;
    std.mem.writeInt(i64, out[at..][0..8], state.auth_expires, .big);
    at += 8;
    out[at..][0..32].* = state.policy;
    at += 32;
    return out[0..at];
}

fn decode(version: suites.Version, plain: []const u8, out: *State) error{Invalid}!void {
    @setRuntimeSafety(true);
    var at: usize = 0;
    const take = struct {
        fn bytes(p: []const u8, pos: *usize, n: usize) error{Invalid}![]const u8 {
            if (p.len - pos.* < n) return error.Invalid;
            defer pos.* += n;
            return p[pos.*..][0..n];
        }
    }.bytes;
    const suite = std.enums.fromInt(suites.Suite, std.mem.readInt(u16, (try take(plain, &at, 2))[0..2], .big)) orelse return error.Invalid;
    if (suite.version() != version) return error.Invalid;
    const secret_len = (try take(plain, &at, 1))[0];
    if (secret_len != State.secretLength(version, suite)) return error.Invalid;
    out.* = .{ .version = version, .suite = suite, .issued = 0, .expires = 0, .age_add = 0, .policy = undefined };
    @memcpy(out.secret.exposeMut()[0..secret_len], try take(plain, &at, secret_len));
    out.group = std.enums.fromInt(Group, std.mem.readInt(u16, (try take(plain, &at, 2))[0..2], .big)) orelse return error.Invalid;
    out.issued = std.mem.readInt(i64, (try take(plain, &at, 8))[0..8], .big);
    out.expires = std.mem.readInt(i64, (try take(plain, &at, 8))[0..8], .big);
    const span = std.math.sub(i64, out.expires, out.issued) catch return error.Invalid;
    if (span <= 0 or span > TicketKeys.max_lifetime) return error.Invalid;
    out.age_add = std.mem.readInt(u32, (try take(plain, &at, 4))[0..4], .big);
    const alpn_len = (try take(plain, &at, 1))[0];
    @memcpy(out.alpn[0..alpn_len], try take(plain, &at, alpn_len));
    out.alpn_len = alpn_len;
    const name_len = (try take(plain, &at, 1))[0];
    if (name_len > out.server_name.len) return error.Invalid;
    @memcpy(out.server_name[0..name_len], try take(plain, &at, name_len));
    out.server_name_len = name_len;
    const auth = (try take(plain, &at, 1))[0];
    if (auth > 1) return error.Invalid;
    out.client_authenticated = auth == 1;
    out.auth_expires = std.mem.readInt(i64, (try take(plain, &at, 8))[0..8], .big);
    out.policy = (try take(plain, &at, 32))[0..32].*;
    if (at != plain.len) return error.Invalid;
}

test {
    _ = @import("Ticket_test.zig");
}
