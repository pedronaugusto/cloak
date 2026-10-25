//! Encrypted Client Hello (RFC 9849): ECHConfig parsing and building, the encrypted_client_hello
//! extension's forms, ClientHelloInner reconstruction and the acceptance confirmations. The
//! handshake roles drive it; nothing here keeps state of its own.
const std = @import("std");
const Reader = @import("../../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Extensions = @import("../wire/Extensions.zig");
const Labels = @import("../crypto/Labels.zig");
const Hpke = @import("../crypto/Hpke.zig");
const Suites = @import("../crypto/Suite.zig");
const Transport = Suites.Transport;
const Suite13 = Suites.Suite13;
const Transcripts = @import("Transcripts.zig");

/// The ECHConfig version and the extension's code point.
pub const version: u16 = 0xfe0d;
pub const extension_id: u16 = 0xfe0d;
pub const outer_extensions_id: u16 = 0xfd00;
/// Configs a server holds keys for: a bound on trial decryption.
pub const max_keys = 16;
/// The extensions a ClientHelloInner leaves to the ClientHelloOuter (`ech_outer_extensions`), in
/// the order cloak writes them: supported_groups, signature_algorithms, supported_versions, ALPN,
/// cookie, key_share.
pub const compressed = [_]u16{ 10, 13, 43, 16, 44, 51 };

pub const ParseError = error{ InvalidConfig, InvalidLength };

/// What a client does about Encrypted Client Hello.
pub const Mode = union(enum) {
    off,
    /// A GREASE encrypted_client_hello (RFC 9849 section 6.2): it looks like ECH and offers
    /// nothing; the handshake is otherwise the ordinary one.
    grease,
    /// The server's ECHConfigList, as its HTTPS record carries it. ECH is then required: the true
    /// server name is never sent in clear, only TLS 1.3 is offered, and a server that does not
    /// accept it ends the handshake with `EchRejected`.
    config_list: []const u8,
};

/// One ECHConfig, borrowed from the bytes it was parsed from.
pub const Config = struct {
    /// The whole ECHConfig, version and length included: HPKE's info follows it.
    raw: []const u8,
    id: u8,
    kem: Hpke.Kem,
    public_key: []const u8,
    /// HpkeSymmetricCipherSuite entries, four bytes each.
    suites: []const u8,
    max_name_length: u8,
    public_name: []const u8,
    extensions: []const u8,

    /// The first suite this config lists that cloak supports.
    pub fn suite(self: *const Config) ?Hpke.Suite {
        var at: usize = 0;
        while (at + 4 <= self.suites.len) : (at += 4) {
            const candidate: Hpke.Suite = .{
                .kdf = @fromBackingInt(@intCast(std.mem.readInt(u16, self.suites[at..][0..2], .big))),
                .aead = @fromBackingInt(@intCast(std.mem.readInt(u16, self.suites[at + 2 ..][0..2], .big))),
            };
            if (candidate.kdf == .hkdf_sha256 and candidate.aead.supported()) return candidate;
        }
        return null;
    }

    pub fn lists(self: *const Config, wanted: Hpke.Suite) bool {
        var at: usize = 0;
        while (at + 4 <= self.suites.len) : (at += 4) {
            if (std.mem.readInt(u16, self.suites[at..][0..2], .big) == @backingInt(wanted.kdf) and
                std.mem.readInt(u16, self.suites[at + 2 ..][0..2], .big) == @backingInt(wanted.aead)) return true;
        }
        return false;
    }

    /// Whether a client can use this config: X25519, a supported suite, a valid public name and
    /// no mandatory extension it does not know (it knows none).
    pub fn usable(self: *const Config) bool {
        if (self.kem != .x25519_sha256 or self.public_key.len != Hpke.public_length) return false;
        if (self.suite() == null or !publicName(self.public_name)) return false;
        var r: Reader = .{ .bytes = self.extensions };
        while (r.pos != r.bytes.len) {
            const id = r.int(u16) catch return false;
            _ = r.vector(u16) catch return false;
            if (id & 0x8000 != 0) return false;
        }
        return true;
    }
};

/// Parses one ECHConfig of version 0xfe0d from the start of `bytes`; the returned config's
/// `raw` says how much it took. A config of another version is skipped by its length: `null`.
pub fn parseConfig(bytes: []const u8) ParseError!struct { config: ?Config, len: usize } {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = bytes };
    const config_version = try r.int(u16);
    const contents = try r.vector(u16);
    const len = r.pos;
    if (config_version != version) return .{ .config = null, .len = len };
    var c = contents;
    var config: Config = undefined;
    config.raw = bytes[0..len];
    config.id = try c.int(u8);
    config.kem = @fromBackingInt(@intCast(try c.int(u16)));
    config.public_key = (try c.vector(u16)).bytes;
    config.suites = (try c.vector(u16)).bytes;
    config.max_name_length = try c.int(u8);
    config.public_name = (try c.vector(u8)).bytes;
    config.extensions = (try c.vector(u16)).bytes;
    try c.finish();
    if (config.public_key.len == 0 or config.suites.len < 4 or config.suites.len % 4 != 0 or config.public_name.len == 0) return error.InvalidConfig;
    // Extensions are well formed and unique.
    var ext: Extensions = .{ .reader = .{ .bytes = config.extensions } };
    while (ext.next() catch return error.InvalidConfig) |_| {}
    return .{ .config = config, .len = len };
}

/// Checks an ECHConfigList's syntax (RFC 9849 section 4): every config of a known version parses.
pub fn checkList(list: []const u8) ParseError!void {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = list };
    const body = try r.vector(u16);
    try r.finish();
    if (body.bytes.len < 4) return error.InvalidConfig;
    var at: usize = 0;
    while (at != body.bytes.len) at += (try parseConfig(body.bytes[at..])).len;
}

/// The first config of the list a client can use, in the server's order of preference; null
/// when none is.
pub fn choose(list: []const u8) ParseError!?Config {
    @setRuntimeSafety(true);
    try checkList(list);
    const body = list[2..];
    var at: usize = 0;
    while (at != body.len) {
        const parsed = try parseConfig(body[at..]);
        at += parsed.len;
        if (parsed.config) |config| if (config.usable()) return config;
    }
    return null;
}

/// A public name a client accepts (RFC 9849 section 6.1.7): LDH labels of at most 63 bytes, no
/// leading or trailing dot, and a last label that cannot be read as an IPv4 literal.
pub fn publicName(name: []const u8) bool {
    @setRuntimeSafety(true);
    if (name.len == 0 or name.len > 253) return false;
    var labels = std.mem.splitScalar(u8, name, '.');
    var last: []const u8 = "";
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |c| if (!std.ascii.isAlphanumeric(c) and c != '-') return false;
        last = label;
    }
    var digits = true;
    for (last) |c| digits = digits and std.ascii.isDigit(c);
    if (digits) return false;
    if (last.len >= 2 and last[0] == '0' and (last[1] == 'x' or last[1] == 'X')) {
        var hex = true;
        for (last[2..]) |c| hex = hex and std.ascii.isHex(c);
        if (hex) return false;
    }
    return true;
}

/// The HPKE info for a config: "tls ech" || 0x00 || ECHConfig.
pub fn info(out: []u8, config_raw: []const u8) []const u8 {
    @memcpy(out[0..8], "tls ech\x00");
    @memcpy(out[8..][0..config_raw.len], config_raw);
    return out[0 .. 8 + config_raw.len];
}

/// A config a server decrypts with: the ECHConfig as published and the X25519 secret key of its
/// public key, borrowed for the life of the connections using it.
pub const Key = struct {
    /// One ECHConfig (version 0xfe0d), version and length included.
    config: []const u8,
    secret: *const [Hpke.secret_length]u8,
    /// Offered in retry_configs to a client whose ECH this server could not decrypt.
    retry: bool = true,
};

/// Checks a server's keys: each config one well-formed ECHConfig of this version, X25519, a
/// supported suite, a usable public name, and the public key of its secret.
pub fn checkKeys(keys: []const Key) error{InvalidConfig}!void {
    @setRuntimeSafety(true);
    if (keys.len > max_keys) return error.InvalidConfig;
    for (keys) |key| {
        const parsed = parseConfig(key.config) catch return error.InvalidConfig;
        const config = parsed.config orelse return error.InvalidConfig;
        if (parsed.len != key.config.len or !config.usable()) return error.InvalidConfig;
        const public = Hpke.publicKey(key.secret);
        if (!std.mem.eql(u8, &public, config.public_key)) return error.InvalidConfig;
    }
}

/// How a stateless retry request answered a first hello's ECH (`dtls.Cookies`), for the server
/// that takes the second: no ECH offered (or no keys to open it), not opened (the second is not
/// opened either), or opened, with what the second opens under again and the inner hello's
/// random, which the request's confirmation is made with.
pub const Retried = union(enum) {
    none,
    rejected,
    accepted: struct { config_id: u8, suite: Hpke.Suite, enc: [Hpke.enc_length]u8, random: [32]u8 },
};

/// What a ClientHello's encrypted_client_hello extension holds.
pub const Offer = union(enum) {
    inner,
    outer: Outer,
    pub const Outer = struct { suite: Hpke.Suite, config_id: u8, enc: []const u8, payload: []const u8 };
};

pub const OfferError = error{ DecodeError, IllegalParameter };

pub fn parseOffer(body: []const u8) OfferError!Offer {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = body };
    const kind = r.int(u8) catch return error.DecodeError;
    switch (kind) {
        1 => {
            if (body.len != 1) return error.DecodeError;
            return .inner;
        },
        0 => {
            const kdf = r.int(u16) catch return error.DecodeError;
            const aead = r.int(u16) catch return error.DecodeError;
            const id = r.int(u8) catch return error.DecodeError;
            const enc = (r.vector(u16) catch return error.DecodeError).bytes;
            const payload = (r.vector(u16) catch return error.DecodeError).bytes;
            r.finish() catch return error.DecodeError;
            if (payload.len == 0) return error.DecodeError;
            return .{ .outer = .{ .suite = .{ .kdf = @fromBackingInt(@intCast(kdf)), .aead = @fromBackingInt(@intCast(aead)) }, .config_id = id, .enc = enc, .payload = payload } };
        },
        else => return error.IllegalParameter,
    }
}

/// An outer encrypted_client_hello body with a zero payload of `payload_len` bytes; the caller
/// seals into its last `payload_len` bytes.
pub fn writeOuter(out: []u8, suite: Hpke.Suite, config_id: u8, enc: []const u8, payload_len: usize) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.int(u8, 0);
    try w.int(u16, @backingInt(suite.kdf));
    try w.int(u16, @backingInt(suite.aead));
    try w.int(u8, config_id);
    try w.vector(u16, enc);
    if (payload_len > 65535) return error.BufferTooSmall;
    try w.int(u16, @intCast(payload_len)); // safe: checked just above
    if (out.len - w.pos < payload_len) return error.BufferTooSmall;
    @memset(out[w.pos..][0..payload_len], 0);
    w.pos += payload_len;
    return out[0..w.pos];
}

/// The padded length of an EncodedClientHelloInner of `len` bytes whose true name is `name_len`
/// bytes (zero when none), by RFC 9849 section 6.1.3 with the config's maximum name length.
pub fn paddedLength(len: usize, name_len: usize, max_name_length: u8) usize {
    var padded = len;
    padded += if (name_len != 0) @as(usize, max_name_length) -| name_len else @as(usize, max_name_length) + 9;
    return padded + (31 - ((padded - 1) % 32));
}

/// Where a ClientHello's encrypted_client_hello extension body sits in `message`, a hello of
/// `transport` (a datagram hello has its cookie field).
pub fn extensionSpan(message: []const u8, transport: Transport) ?struct { start: usize, len: usize } {
    @setRuntimeSafety(true);
    var r: Reader = .{ .bytes = message };
    _ = r.take(4 + 2 + 32) catch return null;
    _ = r.vector(u8) catch return null;
    if (transport == .datagram) _ = r.vector(u8) catch return null;
    _ = r.vector(u16) catch return null;
    _ = r.vector(u8) catch return null;
    const block = r.vector(u16) catch return null;
    const base = r.pos - block.bytes.len;
    var ext: Reader = .{ .bytes = block.bytes };
    while (ext.pos != ext.bytes.len) {
        const id = ext.int(u16) catch return null;
        const body = ext.vector(u16) catch return null;
        if (id == extension_id) return .{ .start = base + ext.pos - body.bytes.len, .len = body.bytes.len };
    }
    return null;
}

pub const ReconstructError = error{ IllegalParameter, OutOfMemory };
pub const OpenError = ReconstructError || error{DecryptFailed};

/// A first hello's ECH opened: the context it opened under, past that nonce, and the
/// ClientHelloInner, the caller's to free.
pub const Opened = struct { context: Hpke.Context, inner: []u8 };

/// Opens the encrypted_client_hello `offer` of the ClientHelloOuter `wire` (a whole handshake
/// message of `transport`) under each of `keys` with its config id and suite, a bounded trial,
/// the HPKE context set up from `enc` and at its nonce `seq`: zero for a first hello, one for a
/// second whose first a stateless retry request answered. Null when no key opens it, which is no
/// error: the server goes on with the outer hello.
pub fn open(gpa: std.mem.Allocator, keys: []const Key, wire: []const u8, offer: Offer.Outer, enc: []const u8, seq: u64, transport: Transport) ReconstructError!?Opened {
    @setRuntimeSafety(true);
    if (offer.payload.len <= Hpke.tag_length) return null;
    const aad = try outerAad(gpa, wire, offer.payload);
    defer gpa.free(aad);
    const encoded = try gpa.alloc(u8, offer.payload.len - Hpke.tag_length);
    defer {
        std.crypto.secureZero(u8, encoded);
        gpa.free(encoded);
    }
    var context = for (keys) |key| {
        const config = (parseConfig(key.config) catch continue).config orelse continue;
        if (config.id != offer.config_id or !config.lists(offer.suite)) continue;
        const info_buf = try gpa.alloc(u8, 8 + key.config.len);
        defer gpa.free(info_buf);
        var context = Hpke.setupRecipient(offer.suite, enc, key.secret, info(info_buf, key.config)) catch continue;
        context.seq = seq;
        context.open(encoded, aad, offer.payload) catch {
            context.deinit();
            continue;
        };
        break context;
    } else return null;
    errdefer context.deinit();
    return .{ .context = context, .inner = try reconstruct(gpa, wire, encoded, transport) };
}

/// Opens a second hello's `offer` under the first one's `context`, at its next nonce: the
/// ClientHelloInner, the caller's to free.
pub fn openUnder(gpa: std.mem.Allocator, context: *Hpke.Context, wire: []const u8, offer: Offer.Outer, transport: Transport) OpenError![]u8 {
    @setRuntimeSafety(true);
    if (offer.payload.len <= Hpke.tag_length) return error.DecryptFailed;
    const aad = try outerAad(gpa, wire, offer.payload);
    defer gpa.free(aad);
    const encoded = try gpa.alloc(u8, offer.payload.len - Hpke.tag_length);
    defer {
        std.crypto.secureZero(u8, encoded);
        gpa.free(encoded);
    }
    context.open(encoded, aad, offer.payload) catch return error.DecryptFailed;
    return reconstruct(gpa, wire, encoded, transport);
}

/// ClientHelloOuterAAD (RFC 9849 section 5.2): the hello `wire` without its four-byte header,
/// the payload zeroed; the caller's to free.
fn outerAad(gpa: std.mem.Allocator, wire: []const u8, payload: []const u8) error{OutOfMemory}![]u8 {
    @setRuntimeSafety(true);
    const at = @intFromPtr(payload.ptr) - @intFromPtr(wire.ptr); // aegis: no-danger: the payload is a slice of `wire`
    const aad = try gpa.dupe(u8, wire[4..]);
    @memset(aad[at - 4 ..][0..payload.len], 0);
    return aad;
}

/// ClientHelloInner from the ClientHelloOuter `outer` (a whole handshake message) and the opened
/// EncodedClientHelloInner (RFC 9849 section 5.1), hellos of `transport`: the outer session id
/// restored and every extension `ech_outer_extensions` names copied from the outer hello, which
/// must hold each, once and in the same order. A datagram hello's cookie field is the inner
/// hello's own (RFC 9849 section 5.1 takes RFC 9147's ClientHello). Linear in both inputs; the
/// result is at most their sum.
pub fn reconstruct(gpa: std.mem.Allocator, outer: []const u8, encoded: []const u8, transport: Transport) ReconstructError![]u8 {
    @setRuntimeSafety(true);
    const datagram = transport == .datagram;
    var r: Reader = .{ .bytes = encoded };
    const head = r.take(2 + 32) catch return error.IllegalParameter;
    const session = (r.vector(u8) catch return error.IllegalParameter).bytes;
    if (session.len != 0) return error.IllegalParameter;
    const legacy_cookie = if (datagram) (r.vector(u8) catch return error.IllegalParameter).bytes else "";
    const suites = (r.vector(u16) catch return error.IllegalParameter).bytes;
    const compression = (r.vector(u8) catch return error.IllegalParameter).bytes;
    const block = (r.vector(u16) catch return error.IllegalParameter).bytes;
    // Everything after the ClientHello is padding, all zeros.
    for (r.bytes[r.pos..]) |b| if (b != 0) return error.IllegalParameter;
    // The outer hello parsed already; its session id and extensions are read again here.
    var o: Reader = .{ .bytes = outer };
    _ = o.take(4 + 2 + 32) catch return error.IllegalParameter;
    const outer_session = (o.vector(u8) catch return error.IllegalParameter).bytes;
    if (datagram) _ = o.vector(u8) catch return error.IllegalParameter;
    _ = o.vector(u16) catch return error.IllegalParameter;
    _ = o.vector(u8) catch return error.IllegalParameter;
    var outer_ext: Reader = .{ .bytes = (o.vector(u16) catch return error.IllegalParameter).bytes };

    const out = try gpa.alloc(u8, outer.len + encoded.len + 4);
    errdefer gpa.free(out);
    var w: Writer = .{ .bytes = out };
    const put = struct {
        fn bytes(writer: *Writer, data: []const u8) ReconstructError!void {
            writer.put(data) catch return error.IllegalParameter;
        }
    }.bytes;
    try put(&w, &.{ 1, 0, 0, 0 });
    try put(&w, head);
    w.vector(u8, outer_session) catch return error.IllegalParameter;
    if (datagram) w.vector(u8, legacy_cookie) catch return error.IllegalParameter;
    w.vector(u16, suites) catch return error.IllegalParameter;
    w.vector(u8, compression) catch return error.IllegalParameter;
    const ext_at = w.pos;
    try put(&w, &.{ 0, 0 });
    var inner: Reader = .{ .bytes = block };
    while (inner.pos != inner.bytes.len) {
        const id = inner.int(u16) catch return error.IllegalParameter;
        const body = (inner.vector(u16) catch return error.IllegalParameter).bytes;
        if (id != outer_extensions_id) {
            w.int(u16, id) catch return error.IllegalParameter;
            w.vector(u16, body) catch return error.IllegalParameter;
            continue;
        }
        var list_reader: Reader = .{ .bytes = body };
        const list = (list_reader.vector(u8) catch return error.IllegalParameter).bytes;
        list_reader.finish() catch return error.IllegalParameter;
        if (list.len < 2 or list.len % 2 != 0) return error.IllegalParameter;
        var at: usize = 0;
        while (at < list.len) : (at += 2) {
            const wanted = std.mem.readInt(u16, list[at..][0..2], .big);
            if (wanted == extension_id) return error.IllegalParameter;
            // The cursor only moves forward: a repeat or a reordering finds nothing.
            while (true) {
                if (outer_ext.pos == outer_ext.bytes.len) return error.IllegalParameter;
                const id_outer = outer_ext.int(u16) catch return error.IllegalParameter;
                const body_outer = (outer_ext.vector(u16) catch return error.IllegalParameter).bytes;
                if (id_outer != wanted) continue;
                w.int(u16, id_outer) catch return error.IllegalParameter;
                w.vector(u16, body_outer) catch return error.IllegalParameter;
                break;
            }
        }
    }
    const ext_len = w.pos - ext_at - 2;
    if (ext_len > 65535 or w.pos - 4 > 0xffffff) return error.IllegalParameter;
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(ext_len), .big); // safe: checked above
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big); // safe: checked above
    if (gpa.resize(out, w.pos)) return out[0..w.pos];
    const exact = try gpa.dupe(u8, out[0..w.pos]);
    gpa.free(out);
    return exact;
}

/// The eight bytes that confirm acceptance (RFC 9849 section 7.2): HKDF-Expand-Label over
/// HKDF-Extract(0, ClientHelloInner.random), under the transcript hash `digest`. `label` is
/// "ech accept confirmation" for a ServerHello, "hrr ech accept confirmation" for a retry request.
/// DTLS takes its own label prefix (RFC 9849 section 7.2, RFC 9147 section 5.9).
pub fn confirmation(comptime Hash: type, transport: Transport, inner_random: *const [32]u8, label: []const u8, digest: *const [Hash.digest_length]u8) [8]u8 {
    var prk: [Hash.digest_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &prk);
    const zero: [Hash.digest_length]u8 = @splat(0);
    Labels.extract(Hash, &prk, &zero, inner_random);
    var out: [8]u8 = undefined;
    Labels.expandWith(Hash, transport.prefix(), &out, &prk, label, digest) catch unreachable; // unreachable: fixed labels, hash-sized context
    return out;
}

/// Confirms a retry request answered statelessly (RFC 9849 section 7.2.1): its last eight bytes,
/// zero as built, become the confirmation over the inner hello's hash `hello_hash` (as the
/// synthetic message_hash) and the request.
pub fn confirmRetry(transport: Transport, suite: Suite13, inner_random: *const [32]u8, hello_hash: []const u8, hrr: []u8) Transcripts.CommitError!void {
    @setRuntimeSafety(true);
    var transcript: Transcripts = .{};
    defer std.crypto.secureZero(u8, std.mem.asBytes(&transcript));
    try transcript.restoreRetry(suite, hello_hash, hrr);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    switch (suite) {
        inline else => |tag| {
            const Hash = Suites.Hash(tag);
            const digest = transcript.digest(&digest_buf);
            hrr[hrr.len - 8 ..][0..8].* = confirmation(Hash, transport, inner_random, retry_accept_label, digest[0..Hash.digest_length]);
        },
    }
}

pub const accept_label = "ech accept confirmation";
pub const retry_accept_label = "hrr ech accept confirmation";

// ---------------------------------------------------------------- building configs

/// What an ECHConfig says: the key's id and public half, the suites a client may use, the public
/// name the client-facing server answers for, and the longest name behind it, for padding.
pub const ConfigSpec = struct {
    id: u8,
    public_key: [Hpke.public_length]u8,
    public_name: []const u8,
    max_name_length: u8 = 0,
    suites: []const Hpke.Suite = &.{ .{ .kdf = .hkdf_sha256, .aead = .aes_128_gcm }, .{ .kdf = .hkdf_sha256, .aead = .chacha20_poly1305 } },
};

pub const BuildError = Writer.WriteError || error{InvalidConfig};

/// Writes one ECHConfig (version 0xfe0d) for `spec`.
pub fn writeConfig(out: []u8, spec: ConfigSpec) BuildError![]u8 {
    @setRuntimeSafety(true);
    if (!publicName(spec.public_name) or spec.suites.len == 0 or spec.suites.len > 16) return error.InvalidConfig;
    for (spec.suites) |s| if (s.kdf != .hkdf_sha256 or !s.aead.supported()) return error.InvalidConfig;
    var w: Writer = .{ .bytes = out };
    try w.int(u16, version);
    const len_at = w.pos;
    try w.int(u16, 0);
    try w.int(u8, spec.id);
    try w.int(u16, @backingInt(Hpke.Kem.x25519_sha256));
    try w.vector(u16, &spec.public_key);
    try w.int(u16, @intCast(spec.suites.len * 4)); // safe: at most sixteen suites
    for (spec.suites) |s| {
        try w.int(u16, @backingInt(s.kdf));
        try w.int(u16, @backingInt(s.aead));
    }
    try w.int(u8, spec.max_name_length);
    try w.vector(u8, spec.public_name);
    try w.int(u16, 0);
    std.mem.writeInt(u16, out[len_at..][0..2], @intCast(w.pos - len_at - 2), .big); // safe: a few hundred bytes
    return out[0..w.pos];
}

/// Writes an ECHConfigList of `configs`, in the order given (the server's preference).
pub fn writeList(out: []u8, configs: []const []const u8) BuildError![]u8 {
    @setRuntimeSafety(true);
    var w: Writer = .{ .bytes = out };
    try w.int(u16, 0);
    for (configs) |config| try w.put(config);
    if (w.pos - 2 > 65535 or w.pos == 2) return error.InvalidConfig;
    std.mem.writeInt(u16, out[0..2], @intCast(w.pos - 2), .big); // safe: checked above
    checkList(out[0..w.pos]) catch return error.InvalidConfig;
    return out[0..w.pos];
}

test {
    _ = @import("Ech_test.zig");
}
