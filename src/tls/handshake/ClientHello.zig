//! A hostile ClientHello, parsed once into borrowed views. This checks structure and
//! uniqueness, never policy: which suite, group or identity to pick is the server's.
const std = @import("std");
const Reader = @import("../../wire/Reader.zig");
const Extensions = @import("../wire/Extensions.zig");
const Group = @import("../crypto/Group.zig").Group;
const Transport = @import("../crypto/Suite.zig").Transport;
const Authorities = @import("Authorities.zig");

pub const ParseError = Reader.ReadError || Extensions.NextError || error{
    InvalidHello,
    UnsolicitedExtension,
    IllegalParameter,
    MissingExtension,
    NoSecureRenegotiation,
    DecodeError,
};

const ClientHello = @This();

/// The carrier this hello came over: it decides the wire versions and the cookie field.
transport: Transport,
random: []const u8,
session: []const u8,
/// A datagram hello's cookie field (RFC 6347 section 4.2.1); always empty on a stream.
legacy_cookie: []const u8,
/// Two-byte cipher suite identifiers, in the client's order.
suites: []const u8,
/// supported_groups identifiers, two bytes each; empty when the extension is absent.
groups: []const u8,
/// key_share entries: group, then a two-byte length and the key_exchange bytes.
shares: []const u8,
/// signature_algorithms identifiers, two bytes each.
schemes: []const u8,
/// supported_versions identifiers, two bytes each.
versions: []const u8,
/// The host_name from server_name, or empty.
server_name: []const u8,
/// ProtocolNameList entries: one-byte length then name; empty when absent.
alpn: []const u8,
/// The quic_transport_parameters body, when sent.
parameters: ?[]const u8,
cookie: []const u8,
early_data: bool,
has_psk: bool,
/// pre_shared_key: the identities list body (identity, then the obfuscated ticket age) and the
/// binders list body, and the wire length of the binders list, which ends the hello.
psk_identities: []const u8,
psk_binders: []const u8,
psk_binders_wire: usize,
/// psk_key_exchange_modes lists psk_dhe_ke, the only mode cloak uses.
psk_dhe: bool,
/// TLS 1.2 SessionTicket (RFC 5077): absent, empty (asking for one) or a ticket.
session_ticket: ?[]const u8,
has_groups: bool,
has_shares: bool,
has_schemes: bool,
/// legacy_version: what a client without supported_versions offers.
legacy_version: u16,
/// TLS 1.2: extended_master_secret was sent (RFC 7627).
extended_master_secret: bool,
/// TLS 1.2: an empty renegotiation_info was sent (RFC 5746). The SCSV counts too; see `secureRenegotiation`.
renegotiation_info: bool,
/// TLS 1.2: ec_point_formats was absent or listed the uncompressed form.
uncompressed_points: bool,
/// TLS 1.2: ec_point_formats was sent, so a server may answer it (RFC 8422 section 5.2).
point_formats: bool,
/// legacy_compression_methods was exactly the null method, as TLS 1.3 requires; a TLS 1.2
/// hello need only list it (RFC 8446 section 4.1.2).
null_compression_only: bool,
/// The whole extension block, for the comparison a retry requires.
extensions: []const u8,
/// The encrypted_client_hello body (RFC 9849), when sent.
ech: ?[]const u8,
/// compress_certificate (RFC 8879): the algorithm list with its length byte, when sent.
compress_certificate: ?[]const u8,
/// delegated_credential (RFC 9345): the SignatureSchemeList body, two bytes each, when sent.
delegated: ?[]const u8,
/// signed_certificate_timestamp (RFC 6962 section 3.3.1) was sent, empty: the client takes SCTs.
scts: bool,
/// DTLS connection_id (RFC 9146): the connection ID the client receives on, when sent.
connection_id: ?[]const u8,
/// DTLS use_srtp (RFC 5764): the two-byte profiles in the client's order, when sent.
srtp: ?[]const u8,
/// post_handshake_auth (RFC 8446 section 4.2.6) was sent, empty: the client answers a
/// CertificateRequest after the handshake.
post_handshake_auth: bool,
/// RFC 7250: the certificate types the client takes from the server, and those it can present,
/// one byte each in its order, when sent. Absent means X.509 alone.
server_certificate_types: ?[]const u8,
client_certificate_types: ?[]const u8,
/// record_size_limit (RFC 8449): the most a protected record sent to the client may carry, when
/// sent; at least 64.
record_size_limit: ?u16,
/// certificate_authorities (RFC 8446 section 4.2.4): the names the client trusts, each with its
/// two-byte length, when sent; a preference in the server's credential choice.
authorities: ?[]const u8,

pub fn parse(message: []const u8, transport: Transport) ParseError!ClientHello {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 1 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    var self: ClientHello = undefined;
    self.transport = transport;
    // legacy_version decides only when supported_versions is absent.
    self.legacy_version = try r.int(u16);
    self.random = try r.take(32);
    self.session = (try r.vector(u8)).bytes;
    if (self.session.len > 32) return error.DecodeError;
    self.legacy_cookie = if (transport == .datagram) (try r.vector(u8)).bytes else "";
    self.suites = (try r.vector(u16)).bytes;
    if (self.suites.len < 2 or self.suites.len % 2 != 0) return error.DecodeError;
    const compression = (try r.vector(u8)).bytes;
    if (compression.len == 0) return error.DecodeError;
    self.null_compression_only = compression.len == 1;
    // A TLS 1.2 hello may carry no extensions at all; the caller refuses it by its versions.
    const block: Reader = if (r.pos == r.bytes.len) .{ .bytes = "" } else try r.vector(u16);
    self.extensions = block.bytes;
    try r.finish();
    // The null method must be offered; a server never compresses (CRIME). Judged once the
    // message decodes: a length that does not fit it is decode_error first.
    if (std.mem.findScalar(u8, compression, 0) == null) return error.IllegalParameter;
    self.groups = "";
    self.shares = "";
    self.schemes = "";
    self.versions = "";
    self.server_name = "";
    self.alpn = "";
    self.parameters = null;
    self.cookie = "";
    self.early_data = false;
    self.has_psk = false;
    self.psk_identities = "";
    self.psk_binders = "";
    self.psk_binders_wire = 0;
    self.psk_dhe = false;
    self.session_ticket = null;
    self.has_groups = false;
    self.has_shares = false;
    self.has_schemes = false;
    self.extended_master_secret = false;
    self.renegotiation_info = false;
    self.uncompressed_points = true;
    self.point_formats = false;
    self.ech = null;
    self.compress_certificate = null;
    self.delegated = null;
    self.scts = false;
    self.post_handshake_auth = false;
    self.connection_id = null;
    self.srtp = null;
    self.server_certificate_types = null;
    self.client_certificate_types = null;
    self.record_size_limit = null;
    self.authorities = null;
    var modes = false;
    var ext: Extensions = .{ .reader = block };
    var last: u16 = 0;
    while (try ext.next()) |item| {
        last = item.id;
        try self.extension(item.id, item.bytes, &modes);
    }
    if (self.has_psk) {
        // pre_shared_key must be the last extension, and needs its exchange modes.
        if (last != 41) return error.IllegalParameter;
        if (!modes) return error.MissingExtension;
    }
    return self;
}

fn extension(self: *ClientHello, id: u16, bytes: []const u8, modes: *bool) ParseError!void {
    @setRuntimeSafety(true);
    var value: Reader = .{ .bytes = bytes };
    switch (id) {
        0 => {
            var list = try value.vector(u16);
            try value.finish();
            // server_name_list<1..2^16-1> and HostName<1..2^16-1> (RFC 6066 section 3): out of
            // range is decode_error; a name that decodes but is no host name is illegal_parameter.
            if (list.bytes.len == 0) return error.DecodeError;
            var seen = false;
            while (list.pos != list.bytes.len) {
                const kind = try list.int(u8);
                const name = (try list.vector(u16)).bytes;
                if (kind != 0) continue;
                if (name.len == 0) return error.DecodeError;
                if (seen or !hostName(name)) return error.IllegalParameter;
                seen = true;
                self.server_name = name;
            }
            if (!seen) return error.IllegalParameter;
        },
        10 => {
            self.groups = (try value.vector(u16)).bytes;
            try value.finish();
            if (self.groups.len < 2 or self.groups.len % 2 != 0) return error.DecodeError;
            self.has_groups = true;
        },
        13 => {
            self.schemes = try schemeList(&value);
            self.has_schemes = true;
        },
        16 => {
            const list = (try value.vector(u16)).bytes;
            try value.finish();
            if (list.len == 0) return error.DecodeError;
            var names: Reader = .{ .bytes = list };
            while (names.pos != names.bytes.len) {
                if ((try names.vector(u8)).bytes.len == 0) return error.DecodeError;
            }
            self.alpn = list;
        },
        41 => try self.offeredPsks(&value),
        42 => self.early_data = try empty(bytes),
        43 => {
            self.versions = (try value.vector(u8)).bytes;
            try value.finish();
            if (self.versions.len < 2 or self.versions.len % 2 != 0) return error.DecodeError;
        },
        44 => {
            self.cookie = (try value.vector(u16)).bytes;
            try value.finish();
            if (self.cookie.len == 0) return error.DecodeError;
        },
        45 => {
            const list = (try value.vector(u8)).bytes;
            if (list.len == 0) return error.DecodeError;
            try value.finish();
            modes.* = true;
            self.psk_dhe = std.mem.findScalar(u8, list, 1) != null;
        },
        51 => {
            self.shares = (try value.vector(u16)).bytes;
            try value.finish();
            // Any number of shares, each group once (RFC 8446 section 4.2.8): entries shaped
            // like extensions, so the same bounded walk refuses a repeat.
            var entries: Extensions = .{ .reader = .{ .bytes = self.shares } };
            while (entries.next() catch |err| return switch (err) {
                error.DuplicateExtension => error.IllegalParameter,
                else => |e| e,
            }) |entry| if (entry.bytes.len == 0) return error.DecodeError;
            self.has_shares = true;
        },
        57 => {
            // Off QUIC it is unsupported_extension (RFC 9001 section 8.2).
            if (self.transport != .quic) return error.UnsolicitedExtension;
            self.parameters = bytes;
        },
        35 => self.session_ticket = bytes,
        0xfe0d => self.ech = bytes,
        27 => {
            @import("Compression.zig").checkExtension(bytes) catch return error.DecodeError;
            self.compress_certificate = bytes;
        },
        34 => self.delegated = try schemeList(&value),
        18 => self.scts = try empty(bytes),
        49 => self.post_handshake_auth = try empty(bytes),
        54 => self.connection_id = try whole8(&value),
        28 => self.record_size_limit = try recordSizeLimit(&value),
        Authorities.extension => self.authorities = try Authorities.parse(bytes),
        14 => {
            const profiles = (try value.vector(u16)).bytes;
            _ = try value.vector(u8);
            try value.finish();
            if (profiles.len < 2 or profiles.len % 2 != 0) return error.DecodeError;
            self.srtp = profiles;
        },
        19, 20 => (if (id == 19) &self.client_certificate_types else &self.server_certificate_types).* = try certificateTypes(&value),
        // ech_outer_extensions lives only inside an encrypted inner hello (RFC 9849 section 5.1).
        0xfd00 => return error.IllegalParameter,
        11 => {
            const formats = (try value.vector(u8)).bytes;
            try value.finish();
            if (formats.len == 0) return error.DecodeError;
            self.point_formats = true;
            self.uncompressed_points = std.mem.findScalar(u8, formats, 0) != null;
        },
        23 => self.extended_master_secret = try empty(bytes),
        0xff01 => {
            // The initial handshake's renegotiated_connection is empty; anything else is
            // handshake_failure (RFC 5746 section 3.6).
            if ((try value.vector(u8)).bytes.len != 0) return error.NoSecureRenegotiation;
            try value.finish();
            self.renegotiation_info = true;
        },
        else => {},
    }
}

/// A vector<0..255> filling its extension.
fn whole8(value: *Reader) ParseError![]const u8 {
    const bytes = (try value.vector(u8)).bytes;
    try value.finish();
    return bytes;
}

/// RecordSizeLimit, a uint16 of at least 64 (RFC 8449 section 4). One past the version's maximum
/// is the client's to name: a server takes it as that maximum, never refuses it.
fn recordSizeLimit(value: *Reader) ParseError!u16 {
    if (value.bytes.len != 2) return error.DecodeError;
    const limit = try value.int(u16);
    if (limit < 64) return error.IllegalParameter;
    return limit;
}

/// An extension whose presence says it all: its body must be empty.
fn empty(bytes: []const u8) ParseError!bool {
    if (bytes.len != 0) return error.DecodeError;
    return true;
}

/// A SignatureSchemeList filling its extension: two bytes per scheme, at least one.
fn schemeList(value: *Reader) ParseError![]const u8 {
    const list = (try value.vector(u16)).bytes;
    try value.finish();
    if (list.len < 2 or list.len % 2 != 0) return error.DecodeError;
    return list;
}

/// A client_certificate_type or server_certificate_type list (RFC 7250): one or more types.
fn certificateTypes(value: *Reader) ParseError![]const u8 {
    @setRuntimeSafety(true);
    const types = (try value.vector(u8)).bytes;
    try value.finish();
    if (types.len == 0) return error.DecodeError;
    return types;
}

/// Whether a certificate type list (RFC 7250) admits `kind`: an absent list admits X.509 alone.
pub fn admitsType(list: ?[]const u8, kind: u8) bool {
    const types = list orelse return kind == 0;
    return std.mem.findScalar(u8, types, kind) != null;
}

/// Whether this client takes a server authenticated by a raw public key (`raw`) or by a
/// certificate (RFC 7250 section 4.2): its server_certificate_type list names the type, or the
/// type is X.509 and it sent none.
pub fn takesServerForm(self: *const ClientHello, raw: bool) bool {
    // RFC 7250 section 3: X509 is 0, RawPublicKey 2.
    return admitsType(self.server_certificate_types, if (raw) 2 else 0);
}

/// OfferedPsks (RFC 8446 section 4.2.11): identities, then one binder of 32 bytes or more for each.
fn offeredPsks(self: *ClientHello, value: *Reader) ParseError!void {
    @setRuntimeSafety(true);
    const identities = try value.vector(u16);
    const binders = try value.vector(u16);
    try value.finish();
    if (identities.bytes.len == 0 or binders.bytes.len == 0) return error.DecodeError;
    var count: usize = 0;
    var list: Reader = .{ .bytes = identities.bytes };
    while (list.pos != list.bytes.len) {
        if ((try list.vector(u16)).bytes.len == 0) return error.DecodeError;
        _ = try list.int(u32);
        count += 1;
    }
    var entries: Reader = .{ .bytes = binders.bytes };
    var binder_count: usize = 0;
    while (entries.pos != entries.bytes.len) {
        if ((try entries.vector(u8)).bytes.len < 32) return error.DecodeError;
        binder_count += 1;
    }
    if (binder_count != count) return error.IllegalParameter;
    self.psk_identities = identities.bytes;
    self.psk_binders = binders.bytes;
    self.psk_binders_wire = 2 + binders.bytes.len;
    self.has_psk = true;
}

/// Letters, digits, hyphen and underscore in labels of at most 63 bytes, 253 in all.
fn hostName(name: []const u8) bool {
    @setRuntimeSafety(true);
    if (name.len == 0 or name.len > 253) return false;
    var label: usize = 0;
    for (name) |c| {
        if (c == '.') {
            if (label == 0) return false;
            label = 0;
        } else {
            if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
            label += 1;
            if (label > 63) return false;
        }
    }
    return label != 0;
}

pub const PskIdentity = struct { identity: []const u8, age: u32 };

/// The `index`th offered PSK identity, if there is one.
pub fn pskIdentity(self: *const ClientHello, index: usize) ?PskIdentity {
    @setRuntimeSafety(true);
    var list: Reader = .{ .bytes = self.psk_identities };
    var i: usize = 0;
    // The list was validated while parsing.
    while (list.pos != list.bytes.len) : (i += 1) {
        const identity = (list.vector(u16) catch return null).bytes;
        const age = list.int(u32) catch return null;
        if (i == index) return .{ .identity = identity, .age = age };
    }
    return null;
}

/// The binder for the `index`th identity; parsing matched their counts.
pub fn pskBinder(self: *const ClientHello, index: usize) []const u8 {
    @setRuntimeSafety(true);
    var list: Reader = .{ .bytes = self.psk_binders };
    var i: usize = 0;
    while (list.pos != list.bytes.len) : (i += 1) {
        const binder = (list.vector(u8) catch return "").bytes;
        if (i == index) return binder;
    }
    return "";
}

/// The hello up to its binders: what the binders cover (RFC 8446 section 4.2.11.2). `message`
/// is the one this view was parsed from, whose last extension is the pre_shared_key.
pub fn truncated(self: *const ClientHello, message: []const u8) []const u8 {
    return message[0 .. message.len - self.psk_binders_wire];
}

/// Whether TLS 1.3 (DTLS 1.3 in a datagram) is listed in supported_versions.
pub fn offers13(self: *const ClientHello) bool {
    return containsU16(self.versions, self.transport.wire(.tls13));
}

/// Whether TLS 1.2 is offered: listed in supported_versions, or, when that extension is
/// absent, a legacy version of at least TLS 1.2 (RFC 8446 section 4.2.1: a server that speaks
/// TLS 1.2 negotiates it even for a legacy_version of 0x0304 or later; RFC 5246 appendix E.1:
/// any version above the highest answers with that one, 0xfefe included, a stream knowing no
/// DTLS numbering). DTLS numbers its versions downward: DTLS 1.2 is 0xfefd and a newer one smaller.
pub fn offers12(self: *const ClientHello) bool {
    if (self.versions.len != 0) return containsU16(self.versions, self.transport.wire(.tls12));
    return switch (self.transport) {
        .stream, .quic => self.legacy_version >= 0x0303,
        .datagram => self.legacy_version <= 0xfefd and self.legacy_version >= 0xfe00,
    };
}

/// A legacy_version of SSL 3.0 (0x0300) or older, which a hello must not name and a server
/// refuses with protocol_version whatever supported_versions says (RFC 8446 appendix D.5).
/// DTLS numbers its versions apart (0xfeXX); its hellos are refused by their versions alone.
pub fn legacyObsolete(self: *const ClientHello) bool {
    return switch (self.transport) {
        .stream, .quic => self.legacy_version <= 0x0300,
        .datagram => false,
    };
}

/// Secure renegotiation is indicated by the extension or TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
pub fn secureRenegotiation(self: *const ClientHello) bool {
    return self.renegotiation_info or containsU16(self.suites, 0x00ff);
}

/// TLS_FALLBACK_SCSV: the client retried with a lower version than it supports (RFC 7507).
pub fn fallback(self: *const ClientHello) bool {
    return containsU16(self.suites, 0x5600);
}

pub fn offersSuite(self: *const ClientHello, id: u16) bool {
    return containsU16(self.suites, id);
}

pub fn offersGroup(self: *const ClientHello, group: Group) bool {
    return containsU16(self.groups, @backingInt(group));
}

pub fn accepts(self: *const ClientHello, scheme: u16) bool {
    return containsU16(self.schemes, scheme);
}

/// The key_exchange bytes the client sent for `group`, if any.
pub fn shareFor(self: *const ClientHello, group: Group) ?[]const u8 {
    @setRuntimeSafety(true);
    var entries: Reader = .{ .bytes = self.shares };
    while (entries.pos != entries.bytes.len) {
        // The entries were validated while parsing.
        const id = entries.int(u16) catch return null;
        const bytes = entries.vector(u16) catch return null;
        if (id == @backingInt(group)) return bytes.bytes;
    }
    return null;
}

/// Whether a share was sent for a group that supported_groups does not list (illegal).
pub fn sharesOutsideGroups(self: *const ClientHello) bool {
    @setRuntimeSafety(true);
    // Linear in both lists whatever their length: one pass per high nibble the shares use, the
    // groups of that nibble in a 512-byte bit set.
    var nibbles: std.bit_set.Static(16) = .empty;
    var entries: Reader = .{ .bytes = self.shares };
    while (entries.pos != entries.bytes.len) {
        const id = entries.int(u16) catch return true;
        _ = entries.vector(u16) catch return true;
        nibbles.set(id >> 12);
    }
    var used = nibbles.iterator(.{});
    while (used.next()) |nibble| {
        var listed: std.bit_set.Static(4096) = .empty;
        var at: usize = 0;
        while (at + 2 <= self.groups.len) : (at += 2) {
            const id = std.mem.readInt(u16, self.groups[at..][0..2], .big);
            if (id >> 12 == nibble) listed.set(id & 0xfff);
        }
        entries = .{ .bytes = self.shares };
        while (entries.pos != entries.bytes.len) {
            const id = entries.int(u16) catch return true;
            _ = entries.vector(u16) catch return true;
            if (id >> 12 == nibble and !listed.isSet(id & 0xfff)) return true;
        }
    }
    return false;
}

/// The offered protocol equal to one of `preference`, in the server's order.
pub fn selectAlpn(self: *const ClientHello, preference: []const []const u8) ?[]const u8 {
    @setRuntimeSafety(true);
    for (preference) |wanted| {
        var names: Reader = .{ .bytes = self.alpn };
        while (names.pos != names.bytes.len) {
            const name = names.vector(u8) catch return null;
            if (std.mem.eql(u8, name.bytes, wanted)) return wanted;
        }
    }
    return null;
}

fn containsU16(list: []const u8, id: u16) bool {
    @setRuntimeSafety(true);
    var at: usize = 0;
    while (at + 2 <= list.len) : (at += 2) {
        if (std.mem.readInt(u16, list[at..][0..2], .big) == id) return true;
    }
    return false;
}

/// A digest of everything a retry's second ClientHello may not change: the random, session id,
/// suites and every extension except the key share, cookie, early data, PSK and padding
/// (RFC 8446 section 4.1.2), and encrypted_client_hello, whose second payload is a new
/// encryption (RFC 9849 section 6.1.5). The extensions go in ascending type order, not the order
/// sent: section 4.1.2's MUST is the client's, and a server compares what the second hello offers
/// (wolfSSL's second DTLS 1.3 hello reorders). Types are unique (checked at parsing), so the order
/// is one per hello and each entry is hashed with its type and length. The sort is by buckets,
/// 4,096 types at a time, one pass over the block per top nibble in use: linear in the block,
/// with 8 KiB of entry starts and a 512-byte set for a block of any size.
pub fn fingerprint(self: *const ClientHello) [32]u8 {
    @setRuntimeSafety(true);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(self.random);
    h.update(&.{@intCast(self.session.len)}); // safe: parsing bounds the session id at 32 bytes
    h.update(self.session);
    h.update(self.suites);
    // The block was validated when parsed; a malformed entry cannot occur and would end a pass.
    var nibbles: std.bit_set.Static(16) = .empty;
    var all: Reader = .{ .bytes = self.extensions };
    while (all.pos < all.bytes.len) {
        const id = all.int(u16) catch break;
        _ = all.vector(u16) catch break;
        if (!exempt(id)) nibbles.set(id >> 12);
    }
    var in_use = nibbles.iterator(.{});
    while (in_use.next()) |nibble| {
        var present: std.bit_set.Static(4096) = .empty;
        // Read only where `present` is set.
        var starts: [4096]u16 = undefined;
        var pass: Reader = .{ .bytes = self.extensions };
        while (pass.pos < pass.bytes.len) {
            const start = pass.pos;
            const id = pass.int(u16) catch break;
            _ = pass.vector(u16) catch break;
            if (id >> 12 != nibble or exempt(id)) continue;
            present.set(id & 0xfff);
            starts[id & 0xfff] = @intCast(start); // safe: a block is at most 65,535 bytes
        }
        var ids = present.iterator(.{});
        while (ids.next()) |low| {
            var entry: Reader = .{ .bytes = self.extensions[starts[low]..] };
            const id = entry.int(u16) catch break;
            const bytes = (entry.vector(u16) catch break).bytes;
            var head: [6]u8 = undefined;
            std.mem.writeInt(u16, head[0..2], id, .big);
            std.mem.writeInt(u32, head[2..6], @intCast(bytes.len), .big); // safe: an extension is at most 65,535 bytes
            h.update(&head);
            h.update(bytes);
        }
    }
    return h.finalResult();
}

fn exempt(id: u16) bool {
    return id == 51 or id == 44 or id == 42 or id == 41 or id == 21 or id == 0xfe0d;
}

test {
    _ = @import("ClientHello_test.zig");
}
