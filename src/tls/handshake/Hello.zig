//! Hello negotiation for TLS 1.3 and TLS 1.2. Borrowed fields retain their enclosing message lease.
const std = @import("std");
const Reader = @import("../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Extensions = @import("../wire/Extensions.zig");
const Ech = @import("Ech.zig");
const Compression = @import("Compression.zig");
const suites = @import("../crypto/Suite.zig");
const Suite = suites.Suite;
const Suite13 = suites.Suite13;
const Suite12 = suites.Suite12;
const Version = suites.Version;
pub const Group = @import("../crypto/Group.zig").Group;
pub const retry_random = std.crypto.tls.hello_retry_request_sequence;
/// The last eight bytes of a TLS 1.3 server's random when it negotiates TLS 1.2 (RFC 8446 section 4.1.3).
pub const downgrade_tls12 = "DOWNGRD\x01";
pub const Share = struct { group: Group, bytes: []const u8 };
pub const Options = struct {
    /// Suites of both versions, in preference order.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions offered or accepted.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    sni: []const u8 = "",
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    /// Set by the carrier: `Connection` is a stream, `quic.Handshake` QUIC, `dtls.Datagram` a datagram.
    transport: suites.Transport = .stream,
    parameters: []const u8 = "",
    /// Certificate decoders a client offers (RFC 8879), TLS 1.3 only.
    certificate_compression: []const Compression.Codec = &.{},

    /// Whether TLS 1.2 is offered or accepted: it is allowed, the policy does not need TLS 1.3
    /// (QUIC, hybrid-only), and a TLS 1.2 suite is listed. The version follows from the suites.
    pub fn allows12(options: Options) bool {
        if (options.min_version != .tls12 or options.transport == .quic or options.require_hybrid) return false;
        for (options.suites) |suite| if (suite.version() == .tls12) return true;
        return false;
    }

    /// Whether TLS 1.3 is offered or accepted: allowed, and one of its suites listed.
    pub fn allows13(options: Options) bool {
        if (options.max_version != .tls13) return false;
        for (options.suites) |suite| if (suite.version() == .tls13) return true;
        return false;
    }

    pub fn offers13(options: Options, suite: Suite13) bool {
        return std.mem.containsAtLeast(Suite, options.suites, 1, &.{Suite.from13(suite)});
    }

    pub fn offers12(options: Options, suite: Suite12) bool {
        return options.allows12() and std.mem.containsAtLeast(Suite, options.suites, 1, &.{Suite.from12(suite)});
    }
};
pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    rsa_pkcs1_sha384 = 0x0501,
    rsa_pkcs1_sha512 = 0x0601,
    ecdsa_p256_sha256 = 0x0403,
    ecdsa_p384_sha384 = 0x0503,
    rsa_pss_rsae_sha256 = 0x0804,
    rsa_pss_rsae_sha384 = 0x0805,
    rsa_pss_rsae_sha512 = 0x0806,
    ed25519 = 0x0807,
    rsa_pss_pss_sha256 = 0x0809,
    rsa_pss_pss_sha384 = 0x080a,
    rsa_pss_pss_sha512 = 0x080b,
};
/// Schemes a TLS 1.3 CertificateVerify may use.
pub const schemes = [_]SignatureScheme{ .ecdsa_p256_sha256, .ecdsa_p384_sha384, .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .ed25519, .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 };
/// Schemes a TLS 1.2 ServerKeyExchange may use: the 1.3 set plus PKCS#1 v1.5 RSA.
pub const schemes12 = schemes ++ [_]SignatureScheme{ .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 };
/// Schemes a TLS 1.2 CertificateVerify may use. It signs the transcript hash of the scheme's own
/// hash, which cloak keeps for SHA-256 and SHA-384 only; Ed25519 signs the handshake messages
/// themselves, which the transcript keeps whole when an Ed25519 signature may be needed.
pub const schemes12_verify = [_]SignatureScheme{ .ecdsa_p256_sha256, .ecdsa_p384_sha384, .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .ed25519 };
pub const ValidateError = error{InvalidOptions};
pub fn validate(options: Options) ValidateError!void {
    @setRuntimeSafety(true);
    Compression.validate(options.certificate_compression, .decompress) catch return error.InvalidOptions;
    if (options.suites.len == 0 or options.suites.len > std.enums.values(Suite).len or options.groups.len == 0 or options.groups.len > 4 or options.alpn.len > 32 or options.parameters.len > 65535) return error.InvalidOptions;
    for (options.suites, 0..) |suite, i| for (options.suites[0..i]) |old| {
        if (old == suite) return error.InvalidOptions;
    };
    if (@backingInt(options.min_version) > @backingInt(options.max_version)) return error.InvalidOptions;
    // Some version must be left, and QUIC and a hybrid-only policy need TLS 1.3.
    if (!options.allows13() and !options.allows12()) return error.InvalidOptions;
    if ((options.transport == .quic or options.require_hybrid) and !options.allows13()) return error.InvalidOptions;
    for (options.groups, 0..) |group, i| for (options.groups[0..i]) |old| {
        if (old == group) return error.InvalidOptions;
    };
    if (options.require_hybrid and !std.mem.containsAtLeast(Group, options.groups, 1, &.{.x25519_mlkem768})) return error.InvalidOptions;
    var alpn_bytes: usize = 0;
    for (options.alpn) |protocol| {
        if (protocol.len == 0 or protocol.len > 255) return error.InvalidOptions;
        alpn_bytes += 1 + protocol.len;
    }
    if (alpn_bytes > 65533 or ((options.require_alpn or options.transport == .quic) and options.alpn.len == 0)) return error.InvalidOptions;
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
/// What a client says of resumption: that it takes tickets (psk_key_exchange_modes, PSK-DHE
/// only), and the ticket it offers, if any, with its obfuscated age. The offer's one binder is
/// written as zeros, `binder_len` bytes ending the hello, for the caller to fill.
pub const Resume = struct {
    modes: bool = false,
    ticket: []const u8 = "",
    age: u32 = 0,
    binder_len: usize = 0,
    /// TLS 1.2 SessionTicket (RFC 5077): null sends none, empty asks for one, else the ticket.
    ticket12: ?[]const u8 = null,
};
/// A ClientHello. `legacy_cookie` is a datagram hello's cookie field (RFC 6347 section 4.2.1):
/// empty, or a DTLS 1.2 HelloVerifyRequest's cookie; a stream hello has no such field. `cookie`
/// is a HelloRetryRequest's cookie extension.
pub fn client(out: []u8, random: *const [32]u8, session: []const u8, legacy_cookie: []const u8, shares: []const Share, cookie: []const u8, options: Options, resumption: Resume) EncodeError![]u8 {
    return clientForm(out, random, session, legacy_cookie, shares, cookie, options, resumption, .plain);
}

/// A PSK offer with nothing behind it, for a ClientHelloOuter whose inner hello resumes: an
/// identity, age and binder of the inner offer's lengths, all random (RFC 9849 section 6.1.2).
pub const GreasePsk = struct { identity: []const u8, age: u32, binder: []const u8 };

/// Which hello `clientForm` writes. ECH needs three encodings of one hello (RFC 9849 section 5):
/// the ClientHelloInner the transcript hashes, its encoded form inside the outer hello, and the
/// ClientHelloOuter on the wire. Only TLS 1.3 is offered in any of them.
pub const Form = union(enum) {
    plain,
    /// A plain hello with a GREASE encrypted_client_hello extension of this body.
    grease: []const u8,
    /// ClientHelloInner: the true name, the inner marker, the real PSK offer.
    inner,
    /// EncodedClientHelloInner (with its four-byte header, which the caller drops): an empty
    /// session id, and `Ech.compressed` replaced by ech_outer_extensions. Unpadded.
    encoded,
    /// ClientHelloOuter: `name` in server_name, `ext` as encrypted_client_hello, and `psk` in
    /// place of the real offer.
    outer: struct { name: []const u8, ext: []const u8, psk: ?GreasePsk },
};

pub fn clientForm(out: []u8, random: *const [32]u8, session_in: []const u8, legacy_cookie: []const u8, shares: []const Share, cookie: []const u8, options: Options, resumption: Resume, form: Form) EncodeError![]u8 {
    @setRuntimeSafety(true);
    try validate(options);
    const ech = form == .inner or form == .encoded or form == .outer;
    if (ech and (options.allows12() or options.transport == .datagram)) return error.InvalidOptions;
    const session = if (form == .encoded) "" else session_in;
    const sni = switch (form) {
        .outer => |o| o.name,
        else => options.sni,
    };
    const datagram = options.transport == .datagram;
    // Key shares are TLS 1.3: present exactly when it is offered. QUIC and DTLS 1.3 have no
    // legacy session id; a datagram hello sends one only to resume a DTLS 1.2 ticket.
    if (session.len > 32 or (options.transport == .quic and session.len != 0) or (datagram and session.len != 0 and !options.allows12()) or (shares.len == 0) == options.allows13() or shares.len > 2 or cookie.len > 4096) return error.InvalidOptions;
    if (legacy_cookie.len > 255 or (legacy_cookie.len != 0 and !datagram)) return error.InvalidOptions;
    for (shares, 0..) |share, i| {
        if (!std.mem.containsAtLeast(Group, options.groups, 1, &.{share.group}) or share.bytes.len != share.group.clientShareLength()) return error.InvalidOptions;
        for (shares[0..i]) |old| if (old.group == share.group) return error.InvalidOptions;
    }
    const tls12 = options.allows12();
    const tls13 = options.allows13();
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 1, 0, 0, 0 });
    try w.int(u16, options.transport.legacy());
    try w.put(random);
    try w.vector(u8, session);
    if (datagram) try w.vector(u8, legacy_cookie);
    var offered_suites: usize = 0;
    for (options.suites) |suite| offered_suites += @intFromBool(if (suite.version() == .tls13) tls13 else tls12);
    // safe: the allowlist has at most nine two-byte suite identifiers.
    try w.int(u16, @intCast(offered_suites * 2));
    for (options.suites) |suite| if (if (suite.version() == .tls13) tls13 else tls12) try w.int(u16, @backingInt(suite));
    try w.put(&.{ 1, 0 });
    const ext_at = w.pos;
    try w.int(u16, 0);
    if (sni.len != 0) try serverName(&w, sni);
    // An encoded inner hello leaves its contiguous run of shared extensions to the outer one.
    const compress = form == .encoded;
    if (compress) try outerExtensions(&w, options, cookie);
    var group_bytes: [10]u8 = undefined;
    var g: Writer = .{ .bytes = &group_bytes };
    // safe: at most four group identifiers, each two bytes.
    try g.int(u16, @intCast(options.groups.len * 2));
    for (options.groups) |group| try g.int(u16, @backingInt(group));
    if (!compress) try extension(&w, 10, group_bytes[0..g.pos]);
    if (tls12) {
        // ec_point_formats: uncompressed only (RFC 8422 section 5.1.2).
        try extension(&w, 11, &.{ 1, 0 });
    }
    const offered: []const SignatureScheme = if (tls12) &schemes12 else &schemes;
    var signature_bytes: [2 + schemes12.len * 2]u8 = undefined;
    var s: Writer = .{ .bytes = &signature_bytes };
    // safe: at most twelve two-byte schemes.
    try s.int(u16, @intCast(offered.len * 2));
    for (offered) |scheme| try s.int(u16, @backingInt(scheme));
    if (!compress) try extension(&w, 13, signature_bytes[0..s.pos]);
    if (tls13 and options.certificate_compression.len != 0) try Compression.writeExtension(&w, options.certificate_compression);
    if (tls12) {
        // extended_master_secret (RFC 7627) and an empty renegotiation_info (RFC 5746).
        try extension(&w, 23, "");
        try extension(&w, 0xff01, &.{0});
        if (resumption.ticket12) |ticket| try extension(&w, 35, ticket);
    }
    // A TLS 1.2-only client sends no supported_versions, as TLS 1.2 clients do.
    if (tls13 and !compress) {
        var versions: [5]u8 = undefined;
        versions[0] = if (tls12) 4 else 2;
        std.mem.writeInt(u16, versions[1..3], options.transport.wire(.tls13), .big);
        std.mem.writeInt(u16, versions[3..5], options.transport.wire(.tls12), .big);
        try extension(&w, 43, versions[0 .. 1 + @as(usize, versions[0])]);
    }
    if (options.alpn.len != 0 and !compress) {
        // Bounded client offer, not a record buffer retained by an idle connection.
        var alpn: [8194]u8 = undefined;
        var a: Writer = .{ .bytes = &alpn };
        try a.int(u16, 0);
        for (options.alpn) |protocol| try a.vector(u8, protocol);
        // safe: 32 entries of at most 256 bytes each fit u16.
        std.mem.writeInt(u16, alpn[0..2], @intCast(a.pos - 2), .big);
        try extension(&w, 16, alpn[0..a.pos]);
    }
    if (cookie.len != 0 and !compress) {
        try w.int(u16, 44);
        // safe: cookie is bounded at 4096 bytes plus its two-byte vector length.
        try w.int(u16, @intCast(cookie.len + 2));
        try w.vector(u16, cookie);
    }
    if (tls13 and !compress) {
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
    }
    if (options.transport == .quic) try extension(&w, 57, options.parameters);
    switch (form) {
        .plain => {},
        .grease => |body| try extension(&w, Ech.extension_id, body),
        .inner, .encoded => try extension(&w, Ech.extension_id, &.{1}),
        .outer => |o| try extension(&w, Ech.extension_id, o.ext),
    }
    if (tls13 and (resumption.modes or resumption.ticket.len != 0)) try extension(&w, 45, &.{ 1, 1 });
    if (form == .outer) {
        // Random bytes in the shape of the inner offer: nothing a client-facing server can resume.
        if (form.outer.psk) |psk| try greasePsk(&w, psk);
    } else if (tls13 and resumption.ticket.len != 0) try offeredPsk(&w, resumption);
    if (w.pos - ext_at - 2 > 65535 or w.pos - 4 > 128 * 1024) return error.InvalidOptions;
    // safe: total extension and handshake lengths have just been bounded.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded to 128 KiB, below the u24 handshake length limit.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}
fn serverName(w: *Writer, sni: []const u8) EncodeError!void {
    @setRuntimeSafety(true);
    if (sni.len > 253) return error.InvalidOptions;
    var sni_bytes: [258]u8 = undefined;
    var x: Writer = .{ .bytes = &sni_bytes };
    // safe: DNS SNI length is at most 253, plus its three-byte entry header.
    try x.int(u16, @intCast(sni.len + 3));
    try x.int(u8, 0);
    try x.vector(u16, sni);
    try extension(w, 0, sni_bytes[0..x.pos]);
}

/// ech_outer_extensions naming `Ech.compressed`, those of them the hello carries.
fn outerExtensions(w: *Writer, options: Options, cookie: []const u8) EncodeError!void {
    @setRuntimeSafety(true);
    var list: [1 + 2 * Ech.compressed.len]u8 = undefined;
    var l: Writer = .{ .bytes = &list };
    try l.int(u8, 0);
    for (Ech.compressed) |id| {
        if ((id == 44 and cookie.len == 0) or (id == 16 and options.alpn.len == 0)) continue;
        try l.int(u16, id);
    }
    list[0] = @intCast(l.pos - 1); // safe: at most twelve bytes
    try extension(w, Ech.outer_extensions_id, list[0..l.pos]);
}

/// pre_shared_key, the last extension (RFC 8446 section 4.2.11): the ticket, its age and a binder
/// of zeros for the caller to fill.
fn offeredPsk(w: *Writer, resumption: Resume) EncodeError!void {
    @setRuntimeSafety(true);
    if (resumption.ticket.len > 65535 - 6 or resumption.binder_len < 32 or resumption.binder_len > 255) return error.InvalidOptions;
    try w.int(u16, 41);
    // safe: the ticket was bounded just above; the binder at 255 bytes.
    try w.int(u16, @intCast(2 + 2 + resumption.ticket.len + 4 + 2 + 1 + resumption.binder_len));
    try w.int(u16, @intCast(2 + resumption.ticket.len + 4)); // safe: bounded above
    try w.vector(u16, resumption.ticket);
    try w.int(u32, resumption.age);
    try w.int(u16, @intCast(1 + resumption.binder_len)); // safe: at most 256
    try w.int(u8, @intCast(resumption.binder_len)); // safe: at most 255
    if (w.bytes.len - w.pos < resumption.binder_len) return error.BufferTooSmall;
    @memset(w.bytes[w.pos..][0..resumption.binder_len], 0);
    w.pos += resumption.binder_len;
}

fn greasePsk(w: *Writer, psk: GreasePsk) EncodeError!void {
    @setRuntimeSafety(true);
    if (psk.identity.len == 0 or psk.identity.len > 65535 - 6 or psk.binder.len < 32 or psk.binder.len > 255) return error.InvalidOptions;
    try w.int(u16, 41);
    try w.int(u16, @intCast(2 + 2 + psk.identity.len + 4 + 2 + 1 + psk.binder.len)); // safe: bounded just above
    try w.int(u16, @intCast(2 + psk.identity.len + 4)); // safe: bounded above
    try w.vector(u16, psk.identity);
    try w.int(u32, psk.age);
    try w.int(u16, @intCast(1 + psk.binder.len)); // safe: at most 256
    try w.vector(u8, psk.binder);
}

fn extension(w: *Writer, id: u16, bytes: []const u8) Writer.WriteError!void {
    try w.int(u16, id);
    try w.vector(u16, bytes);
}
pub const ServerHello = struct {
    suite: Suite13,
    group: ?Group,
    share: []const u8,
    retry: bool,
    cookie: []const u8,
    psk: bool = false,
    /// A retry request's encrypted_client_hello: the eight bytes that may confirm ECH.
    ech: ?*const [8]u8 = null,
};
/// A TLS 1.2 ServerHello: always a full handshake with extended master secret and secure
/// renegotiation indicated.
/// `resumed`: the server echoed the session id sent with a ticket, resuming that session; `ticket`:
/// a NewSessionTicket follows (RFC 5077 section 3.2).
pub const ServerHello12 = struct { suite: Suite12, random: *const [32]u8, alpn: []const u8, resumed: bool = false, ticket: bool = false };
pub const Answer = union(Version) { tls12: ServerHello12, tls13: ServerHello };
pub const ParseError = Reader.ReadError || Extensions.NextError || error{ DecodeError, InvalidHello, UnsolicitedExtension, UnofferedSelection, HybridRequired, UnsupportedVersion, Downgrade, NoApplicationProtocol, MissingExtension, NoExtendedMasterSecret, NoSecureRenegotiation };
/// What a client's hello offered for resumption: one TLS 1.3 PSK identity, which a ServerHello may
/// select; a TLS 1.2 SessionTicket extension, which a ServerHello may answer, and a ticket in it,
/// which it may resume by echoing the session id.
pub const Offered = struct { psk: bool = false, ticket12: bool = false, session12: bool = false, ech: bool = false };
pub fn server(message: []const u8, session: []const u8, shares: []const Share, options: Options, sent: Offered) ParseError!Answer {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 2 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    const legacy_version = try r.int(u16);
    const random = (try r.take(32))[0..32];
    const retry = std.mem.eql(u8, random, &retry_random);
    const echoed = (try r.vector(u8)).bytes;
    const suite_id = try r.int(u16);
    if (try r.int(u8) != 0) return error.InvalidHello;
    // An older server may send no extension block at all.
    var ext: Extensions = .{ .reader = if (r.pos == r.bytes.len) .{ .bytes = "" } else try r.vector(u16) };
    try r.finish();
    var version13 = false;
    var group: ?Group = null;
    var share: []const u8 = "";
    var cookie: []const u8 = "";
    var only12 = false;
    var alpn: []const u8 = "";
    var ems = false;
    var renegotiation = false;
    var psk = false;
    var ticket = false;
    var ech: ?*const [8]u8 = null;
    while (try ext.next()) |item| {
        var value: Reader = .{ .bytes = item.bytes };
        switch (item.id) {
            43 => {
                if (try value.int(u16) != options.transport.wire(.tls13)) return error.InvalidHello;
                version13 = true;
            },
            51 => {
                group = std.enums.fromInt(Group, try value.int(u16)) orelse return error.UnofferedSelection;
                if (!retry) share = (try value.vector(u16)).bytes;
            },
            41 => {
                // The client offered one identity; a retry request selects none.
                if (!sent.psk) return error.UnsolicitedExtension;
                if (retry or try value.int(u16) != 0) return error.InvalidHello;
                psk = true;
            },
            Ech.extension_id => {
                // Only a retry request carries it, and only to a hello that offered ECH; its
                // payload is the confirmation, eight bytes (RFC 9849 section 6.1.4).
                if (!sent.ech or !retry) return error.UnsolicitedExtension;
                if (item.bytes.len != 8) return error.DecodeError;
                ech = item.bytes[0..8];
                value.pos = 8;
            },
            44 => {
                if (!retry) return error.InvalidHello;
                cookie = (try value.vector(u16)).bytes;
                if (cookie.len == 0 or cookie.len > 4096) return error.InvalidHello;
            },
            // The rest belong to a TLS 1.2 ServerHello.
            0 => {
                only12 = true;
                if (options.sni.len == 0) return error.UnsolicitedExtension;
            },
            11 => {
                only12 = true;
                const formats = (try value.vector(u8)).bytes;
                if (std.mem.findScalar(u8, formats, 0) == null) return error.InvalidHello;
            },
            16 => {
                only12 = true;
                alpn = try selectedAlpn(&value, options);
            },
            23 => {
                only12 = true;
                ems = true;
            },
            35 => {
                // An empty SessionTicket: a NewSessionTicket will follow.
                only12 = true;
                if (!sent.ticket12) return error.UnsolicitedExtension;
                if (item.bytes.len != 0) return error.InvalidHello;
                ticket = true;
            },
            0xff01 => {
                only12 = true;
                // The initial handshake's renegotiated_connection is empty (RFC 5746 section 3.4).
                if ((try value.vector(u8)).bytes.len != 0) return error.NoSecureRenegotiation;
                renegotiation = true;
            },
            // One this client sends that has no place in a ServerHello is illegal_parameter; one
            // it never sends is unsupported_extension (RFC 5246 section 7.4.1.4, RFC 8446 section 4.2).
            10, 13, 45, 57 => return error.InvalidHello,
            else => return error.UnsolicitedExtension,
        }
        try value.finish();
    }
    if (version13 and !options.allows13()) return error.UnsupportedVersion;
    if (!version13 and psk) return error.InvalidHello;
    if (!version13) return server12(legacy_version, random, echoed, session, suite_id, .{ .group = group != null or cookie.len != 0, .alpn = alpn, .ems = ems, .renegotiation = renegotiation, .ticket = ticket, .session12 = sent.session12 }, options);
    if (only12) return error.InvalidHello;
    // A DTLS 1.3 server never echoes the session id (RFC 9147 section 5).
    const echo = if (options.transport == .datagram) "" else session;
    if (legacy_version != options.transport.legacy() or !std.mem.eql(u8, echoed, echo)) return error.InvalidHello;
    const suite = std.enums.fromInt(Suite13, suite_id) orelse return error.UnofferedSelection;
    if (!options.offers13(suite)) return error.UnofferedSelection;
    if (retry and group == null and cookie.len != 0) return .{ .tls13 = .{ .suite = suite, .group = null, .share = "", .retry = true, .cookie = cookie, .ech = ech } };
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
    return .{ .tls13 = .{ .suite = suite, .group = selected, .share = share, .retry = retry, .cookie = cookie, .psk = psk, .ech = ech } };
}
/// The one protocol an ALPN answer selects, which must be one this client offered.
fn selectedAlpn(value: *Reader, options: Options) ParseError![]const u8 {
    @setRuntimeSafety(true);
    var protocols = try value.vector(u16);
    const alpn = (try protocols.vector(u8)).bytes;
    try protocols.finish();
    for (options.alpn) |offered| if (std.mem.eql(u8, offered, alpn) and alpn.len != 0) return alpn;
    return error.UnofferedSelection;
}

const Seen12 = struct { group: bool, alpn: []const u8, ems: bool, renegotiation: bool, ticket: bool, session12: bool };
fn server12(legacy_version: u16, random: *const [32]u8, echoed: []const u8, session: []const u8, suite_id: u16, seen: Seen12, options: Options) ParseError!Answer {
    @setRuntimeSafety(true);
    // A server answering below TLS 1.3 marks its random; this client offered TLS 1.3, so a
    // marked random is an attacker's downgrade (RFC 8446 section 4.1.3).
    if (options.allows13() and (std.mem.eql(u8, random[24..], downgrade_tls12) or std.mem.eql(u8, random[24..], "DOWNGRD\x00"))) return error.Downgrade;
    if (legacy_version != options.transport.legacy() or !options.allows12()) return error.UnsupportedVersion;
    // No TLS 1.3 field in a TLS 1.2 answer, and no resumption this client did not ask for: an echo
    // of its session id resumes, which it may only with a ticket it sent (RFC 5077 section 3.4).
    if (seen.group or std.mem.eql(u8, random, &retry_random)) return error.InvalidHello;
    if (echoed.len > 32) return error.InvalidHello;
    const resumed = session.len != 0 and std.mem.eql(u8, echoed, session);
    if (resumed and !seen.session12) return error.InvalidHello;
    const suite = std.enums.fromInt(Suite12, suite_id) orelse return error.UnofferedSelection;
    if (!options.offers12(suite)) return error.UnofferedSelection;
    if (!seen.ems) return error.NoExtendedMasterSecret;
    if (!seen.renegotiation) return error.NoSecureRenegotiation;
    if (options.require_alpn and seen.alpn.len == 0) return error.NoApplicationProtocol;
    return .{ .tls12 = .{ .suite = suite, .random = random, .alpn = seen.alpn, .resumed = resumed, .ticket = seen.ticket } };
}
/// A DTLS 1.2 HelloVerifyRequest's cookie (RFC 6347 section 4.2.1). Its server_version only
/// formats the record (DTLS 1.0's or 1.2's number) and negotiates nothing.
pub fn helloVerify(message: []const u8) ParseError![]const u8 {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 3 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    const version = try r.int(u16);
    if (version != 0xfeff and version != 0xfefd) return error.InvalidHello;
    const cookie = (try r.vector(u8)).bytes;
    try r.finish();
    if (cookie.len == 0) return error.InvalidHello;
    return cookie;
}

/// A HelloVerifyRequest carrying `cookie`, with DTLS 1.0's version as RFC 6347 asks.
pub fn buildHelloVerify(out: []u8, cookie: []const u8) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    if (cookie.len == 0 or cookie.len > 255) return error.BufferTooSmall;
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 3, 0, 0, 0, 0xfe, 0xff });
    try w.vector(u8, cookie);
    // safe: at most 258 bytes.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// `ech`: an ECHConfigList the server offered for a retry (RFC 9849 section 7.1).
pub const EncryptedExtensions = struct { alpn: []const u8, parameters: []const u8, ech: ?[]const u8 = null };
/// `ech_sent`: the hello carried encrypted_client_hello, real or GREASE, so the server may answer it.
pub fn encrypted(message: []const u8, options: Options, ech_sent: bool) ParseError!EncryptedExtensions {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 8 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    var ext: Extensions = .{ .reader = try r.vector(u16) };
    try r.finish();
    var alpn: []const u8 = "";
    var parameters: []const u8 = "";
    var has_parameters = false;
    var ech: ?[]const u8 = null;
    while (try ext.next()) |item| switch (item.id) {
        Ech.extension_id => {
            if (!ech_sent) return error.UnsolicitedExtension;
            Ech.checkList(item.bytes) catch return error.DecodeError;
            ech = item.bytes;
        },
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
            if (options.transport != .quic) return error.InvalidHello;
            parameters = item.bytes;
            has_parameters = true;
        },
        else => return error.InvalidHello,
    };
    if ((options.require_alpn or options.transport == .quic) and alpn.len == 0) return error.NoApplicationProtocol;
    if (options.transport == .quic and !has_parameters) return error.MissingExtension;
    return .{ .alpn = alpn, .parameters = parameters, .ech = ech };
}

/// A ServerHello selecting `suite`, answering the client's share for `group`, and, when `psk`,
/// selecting the PSK identity at index `psk`.
pub fn buildServer(out: []u8, transport: suites.Transport, random: *const [32]u8, session: []const u8, suite: Suite13, group: Group, share: []const u8, psk: ?u16) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 2, 0, 0, 0 });
    try w.int(u16, transport.legacy());
    try w.put(random);
    try w.vector(u8, session);
    try w.int(u16, @backingInt(suite));
    try w.put(&.{0});
    const ext_at = w.pos;
    try w.int(u16, 0);
    try w.put(&.{ 0, 43, 0, 2 });
    try w.int(u16, transport.wire(.tls13));
    try w.int(u16, 51);
    // safe: a key_exchange entry is at most 1,120 bytes.
    try w.int(u16, @intCast(4 + share.len));
    try w.int(u16, @backingInt(group));
    try w.vector(u16, share);
    if (psk) |index| {
        try w.put(&.{ 0, 41, 0, 2 });
        try w.int(u16, index);
    }
    // safe: the extension block holds three short extensions.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: the whole message is bounded by the caller's buffer, far below 2^24.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// What a TLS 1.2 ServerHello answers because the client sent it: no extension appears in a
/// ServerHello unless the ClientHello carried it (RFC 5246 section 7.4.1.4).
pub const Echo12 = struct { server_name: bool, point_formats: bool, ticket: bool = false };

/// A TLS 1.2 ServerHello: the session id (empty, or the client's when resuming its ticket), the
/// suite, and the extended master secret, renegotiation_info, point formats, SessionTicket and
/// ALPN answers.
pub fn buildServer12(out: []u8, transport: suites.Transport, random: *const [32]u8, session: []const u8, suite: Suite12, alpn: []const u8, echo: Echo12) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 2, 0, 0, 0 });
    try w.int(u16, transport.legacy());
    try w.put(random);
    try w.vector(u8, session);
    try w.int(u16, @backingInt(suite));
    try w.put(&.{0});
    const ext_at = w.pos;
    try w.int(u16, 0);
    if (echo.server_name) try w.put(&.{ 0, 0, 0, 0 });
    if (echo.point_formats) try w.put(&.{ 0, 11, 0, 2, 1, 0 });
    try w.put(&.{ 0, 23, 0, 0 });
    try w.put(&.{ 0xff, 0x01, 0, 1, 0 });
    if (echo.ticket) try w.put(&.{ 0, 35, 0, 0 });
    if (alpn.len != 0) {
        try w.int(u16, 16);
        // safe: a protocol name is at most 255 bytes.
        try w.int(u16, @intCast(alpn.len + 3));
        try w.int(u16, @intCast(alpn.len + 1));
        try w.vector(u8, alpn);
    }
    // safe: the extension block holds short fixed extensions and one protocol name.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded by the caller's buffer.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// A HelloRetryRequest asking for `group` (RFC 8446 section 4.1.4). With `ech`, it ends with an
/// encrypted_client_hello of eight zero bytes, the last eight of the message, for the caller to
/// replace with the confirmation (RFC 9849 section 7.2.1).
pub fn buildRetry(out: []u8, transport: suites.Transport, session: []const u8, suite: Suite13, group: Group, ech: bool) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 2, 0, 0, 0 });
    try w.int(u16, transport.legacy());
    try w.put(&retry_random);
    try w.vector(u8, session);
    try w.int(u16, @backingInt(suite));
    try w.put(&.{0});
    try w.int(u16, if (ech) 24 else 12);
    try w.put(&.{ 0, 43, 0, 2 });
    try w.int(u16, transport.wire(.tls13));
    try w.put(&.{ 0, 51, 0, 2 });
    try w.int(u16, @backingInt(group));
    if (ech) {
        try w.int(u16, Ech.extension_id);
        try w.int(u16, 8);
        try w.put(&@as([8]u8, @splat(0)));
    }
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
    /// The ECH keys whose configs a client retries with (those marked `retry`), when it offered
    /// ECH that was not accepted; nothing is sent when none is marked.
    ech_retry: []const Ech.Key = &.{},
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
    var retry_len: usize = 0;
    for (parts.ech_retry) |key| if (key.retry) {
        retry_len += key.config.len;
    };
    if (retry_len != 0) {
        // An ECHConfigList of the retry configs (RFC 9849 section 7.1); `Ech.max_keys` configs of
        // a few hundred bytes each stay far below the u16 bounds.
        if (retry_len > 65533) return error.BufferTooSmall;
        try w.int(u16, Ech.extension_id);
        try w.int(u16, @intCast(retry_len + 2)); // safe: checked above
        try w.int(u16, @intCast(retry_len)); // safe: checked above
        for (parts.ech_retry) |key| if (key.retry) try w.put(key.config);
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
