//! TLS 1.3 hello negotiation. Borrowed fields retain their enclosing message lease.
const std = @import("std");
const Reader = @import("../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Extensions = @import("../wire/Extensions.zig");
const Suite13 = @import("../crypto/Suite.zig").Suite13;
pub const Group = @import("../crypto/Group.zig").Group;
pub const retry_random = std.crypto.tls.hello_retry_request_sequence;
pub const Share = struct { group: Group, bytes: []const u8 };
pub const Options = struct {
    suites: []const Suite13 = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    sni: []const u8 = "",
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    quic: bool = false,
    parameters: []const u8 = "",
};
pub const SignatureScheme = enum(u16) { ecdsa_p256_sha256 = 0x0403, ecdsa_p384_sha384 = 0x0503, rsa_pss_rsae_sha256 = 0x0804, rsa_pss_rsae_sha384 = 0x0805, rsa_pss_rsae_sha512 = 0x0806, ed25519 = 0x0807, rsa_pss_pss_sha256 = 0x0809, rsa_pss_pss_sha384 = 0x080a, rsa_pss_pss_sha512 = 0x080b };
pub const schemes = [_]SignatureScheme{ .ecdsa_p256_sha256, .ecdsa_p384_sha384, .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .ed25519, .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 };
pub const ValidateError = error{InvalidOptions};
pub fn validate(options: Options) ValidateError!void {
    @setRuntimeSafety(true);
    if (options.suites.len == 0 or options.suites.len > 3 or options.groups.len == 0 or options.groups.len > 4 or options.alpn.len > 32 or options.parameters.len > 65535) return error.InvalidOptions;
    for (options.suites, 0..) |suite, i| for (options.suites[0..i]) |old| {
        if (old == suite) return error.InvalidOptions;
    };
    for (options.groups, 0..) |group, i| for (options.groups[0..i]) |old| {
        if (old == group) return error.InvalidOptions;
    };
    if (options.require_hybrid and !std.mem.containsAtLeast(Group, options.groups, 1, &.{.x25519_mlkem768})) return error.InvalidOptions;
    var alpn_bytes: usize = 0;
    for (options.alpn) |protocol| {
        if (protocol.len == 0 or protocol.len > 255) return error.InvalidOptions;
        alpn_bytes += 1 + protocol.len;
    }
    if (alpn_bytes > 65533 or ((options.require_alpn or options.quic) and options.alpn.len == 0)) return error.InvalidOptions;
    if (options.sni.len > 253) return error.InvalidOptions;
    if (options.sni.len != 0) {
        var label: usize = 0;
        for (options.sni, 0..) |c, i| {
            if (c == '.') {
                if (label == 0 or options.sni[i - 1] == '-') return error.InvalidOptions;
                label = 0;
            } else {
                if (!std.ascii.isAlphanumeric(c) and c != '-') return error.InvalidOptions;
                if (label == 0 and c == '-') return error.InvalidOptions;
                label += 1;
                if (label > 63) return error.InvalidOptions;
            }
        }
        if (label == 0 or options.sni[options.sni.len - 1] == '-') return error.InvalidOptions;
    }
}
pub const EncodeError = ValidateError || Writer.WriteError;
pub fn client(out: []u8, random: *const [32]u8, session: []const u8, shares: []const Share, cookie: []const u8, options: Options) EncodeError![]u8 {
    @setRuntimeSafety(true);
    try validate(options);
    if (session.len > 32 or (options.quic and session.len != 0) or shares.len == 0 or shares.len > 2 or cookie.len > 4096) return error.InvalidOptions;
    for (shares, 0..) |share, i| {
        if (!std.mem.containsAtLeast(Group, options.groups, 1, &.{share.group}) or share.bytes.len != share.group.clientShareLength()) return error.InvalidOptions;
        for (shares[0..i]) |old| if (old.group == share.group) return error.InvalidOptions;
    }
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 1, 0, 0, 0, 3, 3 });
    try w.put(random);
    try w.vector(u8, session);
    // safe: the allowlist has at most three two-byte suite identifiers.
    try w.int(u16, @intCast(options.suites.len * 2));
    for (options.suites) |suite| try w.int(u16, @backingInt(suite));
    try w.put(&.{ 1, 0 });
    const ext_at = w.pos;
    try w.int(u16, 0);
    if (options.sni.len != 0) {
        var sni: [258]u8 = undefined;
        var x: Writer = .{ .bytes = &sni };
        // safe: DNS SNI length is at most 253, plus its three-byte entry header.
        try x.int(u16, @intCast(options.sni.len + 3));
        try x.int(u8, 0);
        try x.vector(u16, options.sni);
        try extension(&w, 0, sni[0..x.pos]);
    }
    var group_bytes: [10]u8 = undefined;
    var g: Writer = .{ .bytes = &group_bytes };
    // safe: at most four group identifiers, each two bytes.
    try g.int(u16, @intCast(options.groups.len * 2));
    for (options.groups) |group| try g.int(u16, @backingInt(group));
    try extension(&w, 10, group_bytes[0..g.pos]);
    var signature_bytes: [2 + schemes.len * 2]u8 = undefined;
    var s: Writer = .{ .bytes = &signature_bytes };
    try s.int(u16, schemes.len * 2);
    for (schemes) |scheme| try s.int(u16, @backingInt(scheme));
    try extension(&w, 13, &signature_bytes);
    try extension(&w, 43, &.{ 2, 3, 4 });
    if (options.alpn.len != 0) {
        // Bounded client offer, not a record buffer retained by an idle connection.
        var alpn: [8194]u8 = undefined;
        var a: Writer = .{ .bytes = &alpn };
        try a.int(u16, 0);
        for (options.alpn) |protocol| try a.vector(u8, protocol);
        // safe: 32 entries of at most 256 bytes each fit u16.
        std.mem.writeInt(u16, alpn[0..2], @intCast(a.pos - 2), .big);
        try extension(&w, 16, alpn[0..a.pos]);
    }
    if (cookie.len != 0) {
        try w.int(u16, 44);
        // safe: cookie is bounded at 4096 bytes plus its two-byte vector length.
        try w.int(u16, @intCast(cookie.len + 2));
        try w.vector(u16, cookie);
    }
    const share_at = w.pos;
    try w.put(&.{ 0, 51, 0, 0, 0, 0 });
    for (shares) |share| {
        try w.int(u16, @backingInt(share.group));
        try w.vector(u16, share.bytes);
    }
    // safe: two shares, the largest 1216 bytes, are below the u16 extension bound.
    std.mem.writeInt(u16, out[share_at + 2 ..][0..2], @intCast(w.pos - share_at - 4), .big);
    // safe: the key_share vector is two bytes shorter than the bounded extension.
    std.mem.writeInt(u16, out[share_at + 4 ..][0..2], @intCast(w.pos - share_at - 6), .big);
    if (options.quic) try extension(&w, 57, options.parameters);
    if (w.pos - ext_at - 2 > 65535 or w.pos - 4 > 128 * 1024) return error.InvalidOptions;
    // safe: total extension and handshake lengths have just been bounded.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded to 128 KiB, below the u24 handshake length limit.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}
fn extension(w: *Writer, id: u16, bytes: []const u8) Writer.WriteError!void {
    try w.int(u16, id);
    try w.vector(u16, bytes);
}
pub const ServerHello = struct { suite: Suite13, group: ?Group, share: []const u8, retry: bool, cookie: []const u8 };
pub const ParseError = Reader.ReadError || Extensions.NextError || error{ InvalidHello, UnofferedSelection, HybridRequired, UnsupportedVersion, Downgrade, NoApplicationProtocol, MissingExtension };
pub fn server(message: []const u8, session: []const u8, shares: []const Share, options: Options) ParseError!ServerHello {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 2 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    if (try r.int(u16) != 0x0303) return error.InvalidHello;
    const random = try r.take(32);
    const retry = std.mem.eql(u8, random, &retry_random);
    if (!std.mem.eql(u8, (try r.vector(u8)).bytes, session)) return error.InvalidHello;
    const suite_id = try r.int(u16);
    if (try r.int(u8) != 0) return error.InvalidHello;
    // An older server may send no extension block at all; for TLS 1.3 that is a missing version.
    var ext: Extensions = .{ .reader = if (r.pos == r.bytes.len) .{ .bytes = "" } else try r.vector(u16) };
    try r.finish();
    var version = false;
    var group: ?Group = null;
    var share: []const u8 = "";
    var cookie: []const u8 = "";
    while (try ext.next()) |item| {
        var value: Reader = .{ .bytes = item.bytes };
        switch (item.id) {
            43 => {
                if (try value.int(u16) != 0x0304) return error.InvalidHello;
                version = true;
            },
            51 => {
                group = std.enums.fromInt(Group, try value.int(u16)) orelse return error.UnofferedSelection;
                if (!retry) share = (try value.vector(u16)).bytes;
            },
            44 => {
                if (!retry) return error.InvalidHello;
                cookie = (try value.vector(u16)).bytes;
                if (cookie.len == 0 or cookie.len > 4096) return error.InvalidHello;
            },
            else => return error.InvalidHello,
        }
        try value.finish();
    }
    if (!version) {
        // A server answering an older version marks its random (RFC 8446 section 4.1.3).
        if (std.mem.eql(u8, random[24..], "DOWNGRD\x01") or std.mem.eql(u8, random[24..], "DOWNGRD\x00")) return error.Downgrade;
        return error.UnsupportedVersion;
    }
    const suite = std.enums.fromInt(Suite13, suite_id) orelse return error.UnofferedSelection;
    if (!std.mem.containsAtLeast(Suite13, options.suites, 1, &.{suite})) return error.UnofferedSelection;
    if (retry and group == null and cookie.len != 0) return .{ .suite = suite, .group = null, .share = "", .retry = true, .cookie = cookie };
    const selected = group orelse return error.InvalidHello;
    if (!std.mem.containsAtLeast(Group, options.groups, 1, &.{selected})) return error.UnofferedSelection;
    if (options.require_hybrid and selected != .x25519_mlkem768) return error.HybridRequired;
    var shared = false;
    for (shares) |offered| if (offered.group == selected) {
        shared = true;
    };
    if (retry) {
        if (shared) return error.InvalidHello;
    } else {
        if (!shared or share.len != selected.serverShareLength()) return error.InvalidHello;
    }
    return .{ .suite = suite, .group = selected, .share = share, .retry = retry, .cookie = cookie };
}
pub const EncryptedExtensions = struct { alpn: []const u8, parameters: []const u8 };
pub fn encrypted(message: []const u8, options: Options) ParseError!EncryptedExtensions {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 8 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    var ext: Extensions = .{ .reader = try r.vector(u16) };
    try r.finish();
    var alpn: []const u8 = "";
    var parameters: []const u8 = "";
    var has_parameters = false;
    while (try ext.next()) |item| switch (item.id) {
        0 => {
            if (options.sni.len == 0 or item.bytes.len != 0) return error.InvalidHello;
        },
        10 => {
            var groups: Reader = .{ .bytes = item.bytes };
            const list = try groups.vector(u16);
            if (list.bytes.len == 0 or list.bytes.len % 2 != 0) return error.InvalidHello;
            try groups.finish();
        },
        16 => {
            var value: Reader = .{ .bytes = item.bytes };
            var protocols = try value.vector(u16);
            alpn = (try protocols.vector(u8)).bytes;
            try protocols.finish();
            try value.finish();
            var matched = false;
            for (options.alpn) |offered| if (std.mem.eql(u8, offered, alpn)) {
                matched = true;
            };
            if (!matched or alpn.len == 0) return error.UnofferedSelection;
        },
        57 => {
            if (!options.quic) return error.InvalidHello;
            parameters = item.bytes;
            has_parameters = true;
        },
        else => return error.InvalidHello,
    };
    if ((options.require_alpn or options.quic) and alpn.len == 0) return error.NoApplicationProtocol;
    if (options.quic and !has_parameters) return error.MissingExtension;
    return .{ .alpn = alpn, .parameters = parameters };
}

/// A ServerHello selecting `suite` and answering the client's share for `group`.
pub fn buildServer(out: []u8, random: *const [32]u8, session: []const u8, suite: Suite13, group: Group, share: []const u8) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 2, 0, 0, 0, 3, 3 });
    try w.put(random);
    try w.vector(u8, session);
    try w.int(u16, @backingInt(suite));
    try w.put(&.{0});
    const ext_at = w.pos;
    try w.int(u16, 0);
    try w.put(&.{ 0, 43, 0, 2, 3, 4 });
    try w.int(u16, 51);
    // safe: a key_exchange entry is at most 1,120 bytes.
    try w.int(u16, @intCast(4 + share.len));
    try w.int(u16, @backingInt(group));
    try w.vector(u16, share);
    // safe: the extension block holds two short extensions.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: the whole message is bounded by the caller's buffer, far below 2^24.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// A HelloRetryRequest asking for `group` (RFC 8446 section 4.1.4).
pub fn buildRetry(out: []u8, session: []const u8, suite: Suite13, group: Group) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 2, 0, 0, 0, 3, 3 });
    try w.put(&retry_random);
    try w.vector(u8, session);
    try w.int(u16, @backingInt(suite));
    try w.put(&.{0});
    try w.int(u16, 12);
    try w.put(&.{ 0, 43, 0, 2, 3, 4 });
    try w.put(&.{ 0, 51, 0, 2 });
    try w.int(u16, @backingInt(group));
    // safe: the message is 56 bytes plus the session id.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

pub const EncryptedParts = struct {
    /// Acknowledge a server_name the client sent.
    server_name: bool = false,
    alpn: []const u8 = "",
    /// The server's quic_transport_parameters, when QUIC.
    parameters: ?[]const u8 = null,
};

pub fn buildEncrypted(out: []u8, parts: EncryptedParts) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 8, 0, 0, 0 });
    const ext_at = w.pos;
    try w.int(u16, 0);
    if (parts.server_name) try w.put(&.{ 0, 0, 0, 0 });
    if (parts.alpn.len != 0) {
        try w.int(u16, 16);
        // safe: a protocol name is at most 255 bytes.
        try w.int(u16, @intCast(parts.alpn.len + 3));
        try w.int(u16, @intCast(parts.alpn.len + 1));
        try w.vector(u8, parts.alpn);
    }
    if (parts.parameters) |parameters| {
        try w.int(u16, 57);
        try w.vector(u16, parameters);
    }
    // safe: parameters are bounded at 64 KiB by the options.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded by the caller's buffer.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

test {
    _ = @import("Hello_test.zig");
}
