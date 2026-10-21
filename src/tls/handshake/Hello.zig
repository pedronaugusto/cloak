//! Hello negotiation for TLS 1.3 and TLS 1.2. Borrowed fields retain their enclosing message lease.
const std = @import("std");
const Reader = @import("../../wire/Reader.zig");
const Writer = @import("../wire/Writer.zig");
const Extensions = @import("../wire/Extensions.zig");
const Ech = @import("Ech.zig");
const Compression = @import("Compression.zig");
const Messages = @import("Messages.zig");
const suites = @import("../crypto/Suite.zig");
const RecordLimits = @import("RecordLimits.zig");
const Authorities = @import("Authorities.zig");
const Suite = suites.Suite;
const Suite13 = suites.Suite13;
const Suite12 = suites.Suite12;
const Version = suites.Version;
pub const Group = @import("../crypto/Group.zig").Group;
pub const retry_random = std.crypto.tls.hello_retry_request_sequence;
/// The last eight bytes of a TLS 1.3 server's random when it negotiates TLS 1.2 (RFC 8446 section 4.1.3).
pub const downgrade_tls12 = "DOWNGRD\x01";
pub const Share = struct { group: Group, bytes: []const u8 };
/// An SRTP protection profile a DTLS association keys for its media, by its IANA number (RFC 5764
/// section 4.1.2, RFC 7714 section 14.2). The type is open: `supported` says whether cloak keys
/// for it; the NULL-cipher profiles are not among those.
pub const Srtp = enum(u16) {
    aes128_cm_hmac_sha1_80 = 0x0001,
    aes128_cm_hmac_sha1_32 = 0x0002,
    aead_aes_128_gcm = 0x0007,
    aead_aes_256_gcm = 0x0008,
    _,

    /// Whether cloak keys for this profile: one of the named ones.
    pub fn supported(profile: Srtp) bool {
        return profile.keyLength() != null;
    }

    /// The master key's length.
    pub fn keyLength(profile: Srtp) ?usize {
        return switch (profile) {
            .aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32, .aead_aes_128_gcm => 16,
            .aead_aes_256_gcm => 32,
            _ => null,
        };
    }

    /// The master salt's length.
    pub fn saltLength(profile: Srtp) ?usize {
        return switch (profile) {
            .aes128_cm_hmac_sha1_80, .aes128_cm_hmac_sha1_32 => 14,
            .aead_aes_128_gcm, .aead_aes_256_gcm => 12,
            _ => null,
        };
    }
};
/// client_certificate_type and server_certificate_type (RFC 7250 section 3), and the two types
/// cloak names in them: X.509 and a raw public key.
pub const client_certificate_type = 19;
pub const server_certificate_type = 20;
/// post_handshake_auth (RFC 8446 section 4.2.6): empty, from a client only.
pub const post_handshake_auth = 49;
pub const CertificateType = enum(u8) { x509 = 0, raw_public_key = 2, _ };
/// The certificate types a client can present, in its order (RFC 7250 client_certificate_type).
pub const ClientTypes = enum {
    x509,
    raw,
    raw_then_x509,
    x509_then_raw,

    /// The types the extension lists, in order: none for X.509 alone.
    pub fn list(self: ClientTypes) []const u8 {
        const x509 = @backingInt(CertificateType.x509);
        const raw = @backingInt(CertificateType.raw_public_key);
        return switch (self) {
            .x509 => &.{},
            .raw => &.{raw},
            .raw_then_x509 => &.{ raw, x509 },
            .x509_then_raw => &.{ x509, raw },
        };
    }
};
/// The connection_id extension's number (RFC 9146 section 3).
pub const connection_id_extension = 54;
/// The use_srtp extension's number (RFC 5764 section 4.1.1).
pub const srtp_extension = 14;
pub const Options = struct {
    /// Suites of both versions, in preference order.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions offered or accepted.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = Group.default,
    sni: []const u8 = "",
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    /// The peer authenticates with ML-DSA (draft-ietf-tls-mldsa): its CertificateVerify, and
    /// every certificate signature on its verified path up to the trust anchor. A hybrid key
    /// exchange does not meet it; a provisioned PSK, a symmetric key, does. TLS 1.3 only.
    require_pq_auth: bool = false,
    /// The server presents a raw public key (RFC 7250), which this client trusts by its pin:
    /// server_certificate_type offers that type alone. Either version.
    raw_server_key: bool = false,
    /// The certificate types this client can present (RFC 7250 client_certificate_type), in the
    /// order of its credentials. X.509 alone sends no extension: a hello without it means X.509.
    client_types: ClientTypes = .x509,
    /// The client answers a CertificateRequest after the handshake (RFC 8446 section 4.6.2):
    /// post_handshake_auth is offered. TLS 1.3 over a stream only: QUIC forbids it (RFC 9001
    /// section 4.4), and cloak's datagrams do not build it.
    post_handshake_auth: bool = false,
    /// Set by the carrier: `Connection` is a stream, `quic.Handshake` QUIC, `dtls.Datagram` a datagram.
    transport: suites.Transport = .stream,
    parameters: []const u8 = "",
    /// Certificate decoders a client offers (RFC 8879), TLS 1.3 only.
    certificate_compression: []const Compression.Codec = &.{},
    /// The client takes a server's delegated credential (RFC 9345), TLS 1.3 only: the hello's
    /// delegated_credential lists the schemes a credential's key may use.
    accept_delegated: bool = false,
    /// The client asks for the server's SCTs (RFC 6962 section 3.3.1): set by `Client` when its
    /// verification requires Certificate Transparency.
    request_scts: bool = false,
    /// The client asks for the server's stapled OCSP status (status_request, RFC 6066 section 8):
    /// set by `Client` when its verification checks revocation.
    request_ocsp: bool = false,
    /// DTLS: connection_id (RFC 9146). Null offers or accepts none; otherwise the connection ID
    /// this end receives records with, borrowed; empty: it sends with the peer's but takes none.
    connection_id: ?[]const u8 = null,
    /// DTLS: use_srtp (RFC 5764), the SRTP profiles offered (client) or accepted (server), in
    /// preference order, borrowed. Empty offers or answers none.
    srtp: []const Srtp = &.{},
    /// record_size_limit (RFC 8449): the most a protected record sent to this end may carry, the
    /// extension's value (64 to 2^14 + 1; TLS 1.3 counts the inner content type in it). Null
    /// names the version's maximum. Offered by a client and answered by a server on streams and
    /// datagrams; QUIC has no records.
    record_size_limit: ?u16 = null,
    /// certificate_authorities (RFC 8446 section 4.2.4): the DER Names of the anchors this
    /// client's verifier trusts, named in a hello offering TLS 1.3 (an ECH hello's inner one
    /// alone), a server's preference among its credentials; borrowed. None by default; at most
    /// `Authorities.max_bytes` on the wire.
    certificate_authorities: []const []const u8 = &.{},

    /// The record_size_limit this end names: its own, or the most the versions it allows take.
    pub fn recordSizeLimit(options: Options) u16 {
        return options.record_size_limit orelse if (options.allows13()) RecordLimits.max13 else RecordLimits.max12;
    }

    /// Whether TLS 1.2 is offered or accepted: it is allowed, the policy does not need TLS 1.3
    /// (QUIC, hybrid-only), a TLS 1.2 suite is listed and so is a classical group, the only kind
    /// TLS 1.2 has. The version follows from the suites and groups.
    pub fn allows12(options: Options) bool {
        if (options.min_version != .tls12 or options.transport == .quic or options.require_hybrid or options.require_pq_auth) return false;
        for (options.groups) |group| {
            if (group.classical()) break;
        } else return false;
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
/// A signature scheme by its IANA number (TLS SignatureScheme). The type is open: any number is a
/// `SignatureScheme`, so a signer switching on one handles a scheme named later; `supported` says
/// whether cloak signs or verifies with it.
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
    /// ML-DSA (FIPS 204, pure, empty context), TLS 1.3 only (draft-ietf-tls-mldsa).
    mldsa44 = 0x0904,
    mldsa65 = 0x0905,
    mldsa87 = 0x0906,
    _,

    /// Whether cloak signs or verifies with this scheme: one of the named ones.
    pub fn supported(scheme: SignatureScheme) bool {
        return std.enums.tagName(SignatureScheme, scheme) != null;
    }
};
/// The schemes of both versions' handshakes.
const classical = [_]SignatureScheme{ .ecdsa_p256_sha256, .ecdsa_p384_sha384, .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_rsae_sha512, .ed25519, .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pss_pss_sha512 };
/// ML-DSA's, TLS 1.3 only.
pub const mldsa_schemes = [_]SignatureScheme{ .mldsa44, .mldsa65, .mldsa87 };
/// Schemes a TLS 1.3 CertificateVerify may use.
pub const schemes = classical ++ mldsa_schemes;
/// Schemes a TLS 1.2 ServerKeyExchange may use: the classical ones plus PKCS#1 v1.5 RSA.
pub const schemes12 = classical ++ [_]SignatureScheme{ .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .rsa_pkcs1_sha512 };
/// What a hello offering both versions lists: TLS 1.2's schemes and ML-DSA's.
const schemes_both = schemes12 ++ mldsa_schemes;

/// The schemes a delegated credential's key may use (RFC 9345 section 4): the TLS 1.3
/// CertificateVerify schemes but rsa_pss_rsae_*, a credential's RSA key never having the
/// rsaEncryption OID; ML-DSA's alone under a post-quantum authentication policy.
pub const credential_schemes = withoutRsae(&schemes);
const pq_credential_schemes = withoutRsae(&mldsa_schemes);

pub fn credentialSchemes(require_pq_auth: bool) []const SignatureScheme {
    return if (require_pq_auth) &pq_credential_schemes else &credential_schemes;
}

fn withoutRsae(comptime from: []const SignatureScheme) [countWithoutRsae(from)]SignatureScheme {
    var out: [countWithoutRsae(from)]SignatureScheme = undefined;
    var n: usize = 0;
    for (from) |scheme| if (!rsae(scheme)) {
        out[n] = scheme;
        n += 1;
    };
    return out;
}

fn countWithoutRsae(comptime from: []const SignatureScheme) usize {
    var n: usize = 0;
    for (from) |scheme| n += @intFromBool(!rsae(scheme));
    return n;
}

fn rsae(scheme: SignatureScheme) bool {
    return scheme == .rsa_pss_rsae_sha256 or scheme == .rsa_pss_rsae_sha384 or scheme == .rsa_pss_rsae_sha512;
}

/// The schemes a CertificateVerify (TLS 1.3) may use under `options`: ML-DSA's alone when the
/// policy requires post-quantum authentication.
pub fn verifySchemes(options: Options) []const SignatureScheme {
    return if (options.require_pq_auth) &mldsa_schemes else &schemes;
}
/// Schemes a TLS 1.2 CertificateVerify may use. It signs the transcript hash of the scheme's own
/// hash, which cloak keeps for SHA-256 and SHA-384 only; Ed25519 signs the handshake messages
/// themselves, which the transcript keeps whole when an Ed25519 signature may be needed.
pub const schemes12_verify = [_]SignatureScheme{ .ecdsa_p256_sha256, .ecdsa_p384_sha384, .rsa_pss_rsae_sha256, .rsa_pss_rsae_sha384, .rsa_pss_pss_sha256, .rsa_pss_pss_sha384, .rsa_pkcs1_sha256, .rsa_pkcs1_sha384, .ed25519 };
pub const ValidateError = error{InvalidOptions};
pub fn validate(options: Options) ValidateError!void {
    @setRuntimeSafety(true);
    Compression.validate(options.certificate_compression, .decompress) catch return error.InvalidOptions;
    if (options.suites.len == 0 or options.suites.len > std.enums.values(Suite).len or options.groups.len == 0 or options.groups.len > std.enums.values(Group).len or options.alpn.len > 32 or options.parameters.len > 65535) return error.InvalidOptions;
    // The suites, groups and profiles listed are ones cloak speaks: the types are open, so a
    // caller can name any number, and every later step relies on this check.
    for (options.suites) |suite| if (!suite.supported()) return error.InvalidOptions;
    for (options.groups) |group| if (!group.supported()) return error.InvalidOptions;
    for (options.srtp) |profile| if (!profile.supported()) return error.InvalidOptions;
    for (options.suites, 0..) |suite, i| for (options.suites[0..i]) |old| {
        if (old == suite) return error.InvalidOptions;
    };
    if (@backingInt(options.min_version) > @backingInt(options.max_version)) return error.InvalidOptions;
    // Some version must be left, and QUIC and a hybrid-only policy need TLS 1.3.
    if (!options.allows13() and !options.allows12()) return error.InvalidOptions;
    if ((options.transport == .quic or options.require_hybrid or options.require_pq_auth) and !options.allows13()) return error.InvalidOptions;
    for (options.groups, 0..) |group, i| for (options.groups[0..i]) |old| {
        if (old == group) return error.InvalidOptions;
    };
    if (options.require_hybrid) {
        for (options.groups) |group| {
            if (group.hybrid()) break;
        } else return error.InvalidOptions;
    }
    var alpn_bytes: usize = 0;
    for (options.alpn) |protocol| {
        if (protocol.len == 0 or protocol.len > 255) return error.InvalidOptions;
        alpn_bytes += 1 + protocol.len;
    }
    if (alpn_bytes > 65533 or ((options.require_alpn or options.transport == .quic) and options.alpn.len == 0)) return error.InvalidOptions;
    if (options.connection_id) |cid| if (options.transport != .datagram or cid.len > 255) return error.InvalidOptions;
    if (options.srtp.len != 0 and options.transport != .datagram) return error.InvalidOptions;
    for (options.srtp, 0..) |profile, i| for (options.srtp[0..i]) |old| {
        if (old == profile) return error.InvalidOptions;
    };
    if (options.post_handshake_auth and (options.transport != .stream or !options.allows13())) return error.InvalidOptions;
    if (options.record_size_limit) |limit| if (options.transport == .quic or limit < RecordLimits.min or limit > (if (options.allows13()) RecordLimits.max13 else RecordLimits.max12)) return error.InvalidOptions;
    Authorities.validate(options.certificate_authorities) catch return error.InvalidOptions;
    if (options.certificate_authorities.len != 0 and !options.allows13()) return error.InvalidOptions;
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
/// only), and the PSKs it offers, if any: a ticket with its obfuscated age, or provisioned keys.
/// Each offer's binder is written as zeros, `binder_len` bytes, in the binders that end the
/// hello, for the caller to fill.
pub const Resume = struct {
    modes: bool = false,
    offers: []const PskOffer = &.{},
    /// TLS 1.2 SessionTicket (RFC 5077): null sends none, empty asks for one, else the ticket.
    ticket12: ?[]const u8 = null,

    /// The bytes of the binders vector that ends a hello with these offers; 0 with none.
    pub fn bindersLength(resumption: Resume) usize {
        if (resumption.offers.len == 0) return 0;
        var n: usize = 2;
        for (resumption.offers) |offer| n += 1 + offer.binder_len;
        return n;
    }
};

/// One identity of a pre_shared_key offer.
pub const PskOffer = struct { identity: []const u8, age: u32 = 0, binder_len: usize };

/// The most identities a hello offers, and a server looks at.
pub const max_psk_offers = 8;
/// A ClientHello. `legacy_cookie` is a datagram hello's cookie field (RFC 6347 section 4.2.1):
/// empty, or a DTLS 1.2 HelloVerifyRequest's cookie; a stream hello has no such field. `cookie`
/// is a HelloRetryRequest's cookie extension.
pub fn client(out: []u8, random: *const [32]u8, session: []const u8, legacy_cookie: []const u8, shares: []const Share, cookie: []const u8, options: Options, resumption: Resume) EncodeError![]u8 {
    return clientForm(out, random, session, legacy_cookie, shares, cookie, options, resumption, .plain);
}

/// A PSK offer with nothing behind it, for a ClientHelloOuter whose inner hello resumes: for
/// each inner identity, an identity, age and binder of its lengths, all random (RFC 9849 section
/// 6.1.2).
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
    outer: struct { name: []const u8, ext: []const u8, psk: []const GreasePsk },
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
    // Key shares are TLS 1.3: present exactly when it is offered, except that a datagram hello
    // may carry none (it must fit one datagram; the retry request asks for the group). QUIC and
    // DTLS 1.3 have no legacy session id; a datagram hello sends one only to resume a DTLS 1.2 ticket.
    const shares_ok = if (options.allows13()) shares.len != 0 or datagram else shares.len == 0;
    if (session.len > 32 or (options.transport == .quic and session.len != 0) or (datagram and session.len != 0 and !options.allows12()) or !shares_ok or shares.len > 2 or cookie.len > 4096) return error.InvalidOptions;
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
    // A datagram hello answering a retry request leads with its cookie, so that when the hello
    // is cut to the path's MTU a stateless server finds the cookie in the first fragment, the
    // only one it reads, whatever follows (no ECH over datagrams moves it).
    if (datagram and cookie.len != 0) try cookieExtension(&w, cookie);
    if (sni.len != 0) try serverName(&w, sni);
    // An encoded inner hello leaves a contiguous run of shared extensions to the outer one: none of its own inside.
    try leadingOffers(&w, options, tls13);
    const compress = form == .encoded;
    if (compress) try outerExtensions(&w, options, cookie);
    if (!compress) try supportedGroups(&w, options, tls13);
    // ec_point_formats: uncompressed only (RFC 8422 section 5.1.2).
    if (tls12) try extension(&w, 11, &.{ 1, 0 });
    const offered: []const SignatureScheme = if (!tls12) verifySchemes(options) else if (tls13) &schemes_both else &schemes12;
    var signature_bytes: [2 + schemes_both.len * 2]u8 = undefined;
    var s: Writer = .{ .bytes = &signature_bytes };
    // safe: at most fifteen two-byte schemes.
    try s.int(u16, @intCast(offered.len * 2));
    for (offered) |scheme| try s.int(u16, @backingInt(scheme));
    if (!compress) try extension(&w, 13, signature_bytes[0..s.pos]);
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
    if (datagram) try datagramOffer(&w, options);
    try certificateTypes(&w, options);
    // The names say what the client trusts: an ECH outer hello carries none.
    if (tls13 and form != .outer and options.certificate_authorities.len != 0) try authoritiesExtension(&w, options.certificate_authorities);
    if (cookie.len != 0 and !compress and !datagram) try cookieExtension(&w, cookie);
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
    if (tls13 and (resumption.modes or resumption.offers.len != 0)) try extension(&w, 45, &.{ 1, 1 });
    if (form == .outer) {
        // Random bytes in the shape of the inner offer: nothing a client-facing server can resume.
        if (form.outer.psk.len != 0) try greasePsk(&w, form.outer.psk);
    } else if (tls13 and resumption.offers.len != 0) try offeredPsk(&w, resumption);
    if (w.pos - ext_at - 2 > 65535 or w.pos - 4 > 128 * 1024) return error.InvalidOptions;
    // safe: total extension and handshake lengths have just been bounded.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded to 128 KiB, below the u24 handshake length limit.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}
/// What the hello offers ahead of the extensions an ECH outer hello may share: certificate
/// decoders (TLS 1.3), the evidence `evidenceExtensions` asks for, and record_size_limit, which a
/// record layer of streams or datagrams takes (RFC 8449).
fn leadingOffers(w: *Writer, options: Options, tls13: bool) EncodeError!void {
    if (tls13 and options.certificate_compression.len != 0) try Compression.writeExtension(w, options.certificate_compression);
    try evidenceExtensions(w, options, tls13);
    if (options.transport != .quic) {
        var value: [2]u8 = undefined;
        std.mem.writeInt(u16, &value, options.recordSizeLimit(), .big);
        try extension(w, RecordLimits.extension, &value);
    }
}

/// What this client takes to authenticate the server beyond its certificate's key: a delegated
/// credential (RFC 9345, TLS 1.3), SCTs (RFC 6962) and a stapled OCSP status (RFC 6066), each
/// asked for only when policy says so.
fn evidenceExtensions(w: *Writer, options: Options, tls13: bool) EncodeError!void {
    if (tls13 and options.accept_delegated) try delegatedExtension(w, options.require_pq_auth);
    if (options.request_scts) try extension(w, Messages.signed_certificate_timestamp, "");
    // CertificateStatusRequest: ocsp, no responder IDs, no request extensions.
    if (options.request_ocsp) try extension(w, Messages.status_request, &.{ 1, 0, 0, 0, 0 });
}

/// delegated_credential (RFC 9345 section 4.1.1): the schemes a credential's key may use.
fn delegatedExtension(w: *Writer, require_pq_auth: bool) EncodeError!void {
    const list = credentialSchemes(require_pq_auth);
    try w.int(u16, Messages.delegated_credential);
    // safe: bounded by the scheme table.
    try w.int(u16, @intCast(2 + list.len * 2));
    try w.int(u16, @intCast(list.len * 2));
    for (list) |scheme| try w.int(u16, @backingInt(scheme));
}

/// What the client's certificate may be and when it may be asked for: RFC 7250's types (X.509 is
/// what a hello without the extension means) and post_handshake_auth.
fn certificateTypes(w: *Writer, options: Options) EncodeError!void {
    const raw: []const u8 = &.{ 1, @backingInt(CertificateType.raw_public_key) };
    const offered = options.client_types.list();
    if (offered.len != 0) {
        var body: [3]u8 = undefined;
        body[0] = @intCast(offered.len); // safe: at most two types
        @memcpy(body[1..][0..offered.len], offered);
        try extension(w, client_certificate_type, body[0 .. 1 + offered.len]);
    }
    if (options.raw_server_key) try extension(w, server_certificate_type, raw);
    if (options.post_handshake_auth and options.allows13()) try extension(w, post_handshake_auth, "");
}

/// certificate_authorities (RFC 8446 section 4.2.4) naming `names`, checked by `Authorities.validate`.
fn authoritiesExtension(w: *Writer, names: []const []const u8) EncodeError!void {
    @setRuntimeSafety(true);
    const length = Authorities.wireLength(names);
    try w.int(u16, Authorities.extension);
    // safe: `Authorities.validate` bounds the names to `max_bytes`.
    try w.int(u16, @intCast(2 + length));
    try w.int(u16, @intCast(length));
    try Authorities.write(w, names);
}

/// connection_id and use_srtp as a datagram hello offers them.
fn datagramOffer(w: *Writer, options: Options) EncodeError!void {
    @setRuntimeSafety(true);
    if (options.connection_id) |cid| {
        try w.int(u16, connection_id_extension);
        // safe: validate bounds a connection ID at 255 bytes.
        try w.int(u16, @intCast(cid.len + 1));
        try w.vector(u8, cid);
    }
    if (options.srtp.len != 0) {
        // UseSRTPData: the profiles in preference order and an empty srtp_mki: cloak keys no MKI
        // (RFC 5764 section 4.1.1).
        try w.int(u16, srtp_extension);
        // safe: at most four distinct profiles.
        try w.int(u16, @intCast(2 + 2 * options.srtp.len + 1));
        try w.int(u16, @intCast(2 * options.srtp.len));
        for (options.srtp) |profile| try w.int(u16, @backingInt(profile));
        try w.int(u8, 0);
    }
}

fn cookieExtension(w: *Writer, cookie: []const u8) EncodeError!void {
    try w.int(u16, 44);
    // safe: cookie is bounded at 4096 bytes plus its two-byte vector length.
    try w.int(u16, @intCast(cookie.len + 2));
    try w.vector(u16, cookie);
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

/// pre_shared_key, the last extension (RFC 8446 section 4.2.11): each offer's identity and age,
/// then a binder of zeros for each, for the caller to fill.
fn offeredPsk(w: *Writer, resumption: Resume) EncodeError!void {
    @setRuntimeSafety(true);
    if (resumption.offers.len > max_psk_offers) return error.InvalidOptions;
    var identities: usize = 0;
    for (resumption.offers) |offer| {
        if (offer.identity.len == 0 or offer.identity.len > 65535 - 6 or offer.binder_len < 32 or offer.binder_len > 255) return error.InvalidOptions;
        identities += 2 + offer.identity.len + 4;
    }
    const binders = resumption.bindersLength();
    if (identities > 65535 or 2 + identities + binders > 65535) return error.InvalidOptions;
    try w.int(u16, 41);
    try w.int(u16, @intCast(2 + identities + binders)); // safe: bounded just above
    try w.int(u16, @intCast(identities)); // safe: bounded above
    for (resumption.offers) |offer| {
        try w.vector(u16, offer.identity);
        try w.int(u32, offer.age);
    }
    try w.int(u16, @intCast(binders - 2)); // safe: at most eight binders of 256 bytes
    for (resumption.offers) |offer| {
        try w.int(u8, @intCast(offer.binder_len)); // safe: at most 255
        if (w.bytes.len - w.pos < offer.binder_len) return error.BufferTooSmall;
        @memset(w.bytes[w.pos..][0..offer.binder_len], 0);
        w.pos += offer.binder_len;
    }
}

fn greasePsk(w: *Writer, offers: []const GreasePsk) EncodeError!void {
    @setRuntimeSafety(true);
    if (offers.len > max_psk_offers) return error.InvalidOptions;
    var identities: usize = 0;
    var binders: usize = 0;
    for (offers) |psk| {
        if (psk.identity.len == 0 or psk.identity.len > 65535 - 6 or psk.binder.len < 32 or psk.binder.len > 255) return error.InvalidOptions;
        identities += 2 + psk.identity.len + 4;
        binders += 1 + psk.binder.len;
    }
    if (identities > 65535 or 4 + identities + binders > 65535) return error.InvalidOptions;
    try w.int(u16, 41);
    try w.int(u16, @intCast(4 + identities + binders)); // safe: bounded just above
    try w.int(u16, @intCast(identities)); // safe: bounded above
    for (offers) |psk| {
        try w.vector(u16, psk.identity);
        try w.int(u32, psk.age);
    }
    try w.int(u16, @intCast(binders)); // safe: bounded above
    for (offers) |psk| try w.vector(u8, psk.binder);
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
    /// The offered identity the server selected (pre_shared_key); null for none.
    psk: ?u16 = null,
    /// A retry request's encrypted_client_hello: the eight bytes that may confirm ECH.
    ech: ?*const [8]u8 = null,
    /// DTLS: the connection ID the server receives on, when it answered connection_id.
    connection_id: ?[]const u8 = null,
};
/// A TLS 1.2 ServerHello: always a full handshake with extended master secret and secure
/// renegotiation indicated.
/// `resumed`: the server echoed the session id sent with a ticket, resuming that session; `ticket`:
/// a NewSessionTicket follows (RFC 5077 section 3.2).
/// DTLS: `connection_id` the server's answer to connection_id, `srtp` the profile it chose.
/// `raw_server_key`, `raw_client_key`: the server selected the raw public key type (RFC 7250) for
/// its own Certificate or the client's, which TLS 1.2 answers in its ServerHello.
pub const ServerHello12 = struct {
    suite: Suite12,
    random: *const [32]u8,
    alpn: []const u8,
    resumed: bool = false,
    ticket: bool = false,
    connection_id: ?[]const u8 = null,
    srtp: ?Srtp = null,
    raw_server_key: bool = false,
    raw_client_key: bool = false,
    /// The server's SignedCertificateTimestampList (RFC 6962 section 3.3.1), when the client asked.
    scts: ?[]const u8 = null,
    /// The server answered status_request (RFC 6066 section 8): a CertificateStatus may follow
    /// its Certificate.
    ocsp: bool = false,
    /// The server's record_size_limit (RFC 8449), when it answered the client's.
    record_size_limit: ?u16 = null,
};
pub const Answer = union(Version) { tls12: ServerHello12, tls13: ServerHello };
pub const ParseError = Reader.ReadError || Extensions.NextError || error{ DecodeError, InvalidHello, UnsolicitedExtension, UnofferedSelection, HybridRequired, UnsupportedVersion, Downgrade, NoApplicationProtocol, MissingExtension, NoExtendedMasterSecret, NoSecureRenegotiation };
/// What a client's hello offered for resumption: how many TLS 1.3 PSK identities, one of which a
/// ServerHello may select; a TLS 1.2 SessionTicket extension, which a ServerHello may answer, and a ticket in it,
/// which it may resume by echoing the session id.
pub const Offered = struct { psk: usize = 0, ticket12: bool = false, session12: bool = false, ech: bool = false };
pub fn server(message: []const u8, session: []const u8, shares: []const Share, options: Options, sent: Offered) ParseError!Answer {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 2 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    const legacy_version = try r.int(u16);
    const random = (try r.take(32))[0..32];
    const retry = std.mem.eql(u8, random, &retry_random);
    const echoed = try sessionEcho(&r);
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
    var psk: ?u16 = null;
    var ticket = false;
    var ech: ?*const [8]u8 = null;
    var answered: DatagramAnswer = .{};
    var types: CertificateTypes = .{};
    var delivered: Delivered = .{};
    var record_size_limit: ?u16 = null;
    var groups_answered = false;
    while (try ext.next()) |item| {
        var value: Reader = .{ .bytes = item.bytes };
        only12 = only12 or answers12(item.id);
        switch (item.id) {
            connection_id_extension, srtp_extension => try answered.read(item.id, &value, options, retry),
            43 => {
                if (try value.int(u16) != options.transport.wire(.tls13)) return error.InvalidHello;
                version13 = true;
            },
            51 => {
                const named: Group = @fromBackingInt(try value.int(u16));
                group = if (named.supported()) named else return error.UnofferedSelection;
                if (!retry) share = (try value.vector(u16)).bytes;
            },
            41 => {
                // One of the identities the client offered (RFC 8446 section 4.2.11); a retry
                // request selects none.
                if (sent.psk == 0) return error.UnsolicitedExtension;
                const index = try value.int(u16);
                if (retry or index >= sent.psk) return error.InvalidHello;
                psk = index;
            },
            Ech.extension_id => {
                // Only a retry request carries it, and only to a hello that offered ECH; its
                // payload is the confirmation, eight bytes (RFC 9849 section 6.1.4).
                if (!sent.ech or !retry) return error.UnsolicitedExtension;
                if (item.bytes.len != 8) return error.DecodeError;
                ech = item.bytes[0..8];
                value.pos = 8;
            },
            44 => cookie = try retryCookie(&value, retry),
            // The rest belong to a TLS 1.2 ServerHello (`answers12`).
            client_certificate_type, server_certificate_type => try types.read(item.id, &value, options),
            0 => if (options.sni.len == 0) return error.UnsolicitedExtension,
            11 => {
                const formats = (try value.vector(u8)).bytes;
                if (std.mem.findScalar(u8, formats, 0) == null) return error.InvalidHello;
            },
            16 => alpn = try selectedAlpn(&value, options),
            23 => ems = true,
            RecordLimits.extension => record_size_limit = try recordSizeAnswer(&value, options),
            Messages.signed_certificate_timestamp, Messages.status_request => {
                try delivered.read(item.id, item.bytes, options);
                value.pos = item.bytes.len;
            },
            35 => {
                // An empty SessionTicket: a NewSessionTicket will follow.
                if (!sent.ticket12) return error.UnsolicitedExtension;
                if (item.bytes.len != 0) return error.InvalidHello;
                ticket = true;
            },
            0xff01 => {
                // The initial handshake's renegotiated_connection is empty (RFC 5746 section 3.4).
                if ((try value.vector(u8)).bytes.len != 0) return error.NoSecureRenegotiation;
                renegotiation = true;
            },
            // supported_groups: RFC 8446 section 4.2 has no place for it in a TLS 1.3 ServerHello
            // (checked below); no TLS 1.2 text forbids it, so a TLS 1.2 one is ignored.
            10 => {
                groups_answered = true;
                value.pos = item.bytes.len;
            },
            // One this client sends that a server must not send is illegal_parameter
            // (signature_algorithms RFC 5246 section 7.4.1.4.1, psk_key_exchange_modes RFC 8446
            // section 4.2.9; QUIC's parameters belong in EncryptedExtensions, RFC 9001 section
            // 8.2); one it never sends is unsupported_extension (RFC 5246 section 7.4.1.4, RFC
            // 8446 section 4.2), QUIC's parameters off QUIC among them (RFC 9001 section 8.2).
            13, 45 => return error.InvalidHello,
            57 => return if (options.transport == .quic) error.InvalidHello else error.UnsolicitedExtension,
            else => return error.UnsolicitedExtension,
        }
        try value.finish();
    }
    if (version13 and !options.allows13()) return error.UnsupportedVersion;
    if (!version13 and psk != null) return error.InvalidHello;
    if (!version13) return server12(legacy_version, random, echoed, session, suite_id, .{ .group = group != null or cookie.len != 0, .alpn = alpn, .ems = ems, .renegotiation = renegotiation, .ticket = ticket, .session12 = sent.session12, .connection_id = answered.connection_id, .srtp = answered.srtp, .types = types, .scts = delivered.scts, .ocsp = delivered.ocsp, .record_size_limit = record_size_limit }, options);
    // DTLS 1.3 answers use_srtp in EncryptedExtensions, never in its ServerHello.
    if (only12 or groups_answered or answered.srtp != null) return error.InvalidHello;
    // A DTLS 1.3 server never echoes the session id (RFC 9147 section 5).
    const echo = if (options.transport == .datagram) "" else session;
    if (legacy_version != options.transport.legacy() or !std.mem.eql(u8, echoed, echo)) return error.InvalidHello;
    const suite = std.enums.fromInt(Suite13, suite_id) orelse return error.UnofferedSelection;
    if (!options.offers13(suite)) return error.UnofferedSelection;
    if (retry and group == null and cookie.len != 0) return .{ .tls13 = .{ .suite = suite, .group = null, .share = "", .retry = true, .cookie = cookie, .ech = ech } };
    const selected = try selectedGroup(group, share, shares, retry, options);
    return .{ .tls13 = .{ .suite = suite, .group = selected, .share = share, .retry = retry, .cookie = cookie, .psk = psk, .ech = ech, .connection_id = answered.connection_id } };
}

/// A retry request's cookie, which only a retry request carries: cookie<1..2^16-1> (RFC 8446
/// section 4.2.2), so an empty one is out of its range; past 4096 bytes is this end's bound.
fn retryCookie(value: *Reader, retry: bool) ParseError![]const u8 {
    if (!retry) return error.InvalidHello;
    const cookie = (try value.vector(u16)).bytes;
    if (cookie.len == 0) return error.DecodeError;
    if (cookie.len > 4096) return error.InvalidHello;
    return cookie;
}

/// The group a TLS 1.3 ServerHello or retry request selects, checked against the client's
/// groups and shares: a ServerHello answers a share sent, a retry asks for one not sent.
fn selectedGroup(group: ?Group, share: []const u8, shares: []const Share, retry: bool, options: Options) ParseError!Group {
    @setRuntimeSafety(true);
    // This client offers psk_dhe_ke alone, so a ServerHello lacks a mandatory key_share
    // (missing_extension, RFC 8446 section 6.2); a retry request asking for nothing changes
    // nothing (illegal_parameter, section 4.1.4).
    const selected = group orelse return if (retry) error.InvalidHello else error.MissingExtension;
    if (!std.mem.containsAtLeast(Group, options.groups, 1, &.{selected})) return error.UnofferedSelection;
    if (options.require_hybrid and !selected.hybrid()) return error.HybridRequired;
    var shared = false;
    for (shares) |offered| if (offered.group == selected) {
        shared = true;
    };
    if (retry) {
        if (shared) return error.InvalidHello;
    } else {
        if (!shared or share.len != selected.serverShareLength()) return error.InvalidHello;
    }
    return selected;
}

/// A ServerHello's answers to a datagram hello's connection_id and use_srtp.
const DatagramAnswer = struct {
    connection_id: ?[]const u8 = null,
    srtp: ?Srtp = null,

    fn read(self: *DatagramAnswer, id: u16, value: *Reader, options: Options, retry: bool) ParseError!void {
        @setRuntimeSafety(true);
        if (id == srtp_extension) {
            self.srtp = try selectedSrtp(value, options);
            return;
        }
        // Either version's ServerHello answers connection_id, never a retry request.
        if (options.connection_id == null) return error.UnsolicitedExtension;
        if (retry) return error.InvalidHello;
        self.connection_id = (try value.vector(u8)).bytes;
    }
};

/// The one SRTP profile a use_srtp answer selects, which this end offered, with no MKI: cloak
/// offers none, so a server's MKI differs from it (RFC 5764 section 4.1.3).
fn selectedSrtp(value: *Reader, options: Options) ParseError!Srtp {
    @setRuntimeSafety(true);
    if (options.srtp.len == 0) return error.UnsolicitedExtension;
    var profiles = try value.vector(u16);
    const id = try profiles.int(u16);
    try profiles.finish();
    if ((try value.vector(u8)).bytes.len != 0) return error.InvalidHello;
    for (options.srtp) |offered| if (@backingInt(offered) == id) return offered;
    return error.UnofferedSelection;
}
/// A server's record_size_limit (RFC 8449 section 4): one this client offered (streams and
/// datagrams), at least 64. A value past the version's maximum is taken as that maximum, the RFC's
/// MAY of refusing it not taken: a server may name the larger value of another version.
fn recordSizeAnswer(value: *Reader, options: Options) ParseError!u16 {
    if (options.transport == .quic) return error.UnsolicitedExtension;
    if (value.bytes.len != 2) return error.DecodeError;
    const limit = try value.int(u16);
    if (limit < RecordLimits.min) return error.InvalidHello;
    return limit;
}

/// The one protocol an ALPN answer selects, which must be one this client offered.
/// The protocol a server selected: one the client offered, and no answer when it offered none
/// (unsupported_extension, RFC 8446 section 4.2 and RFC 5246 section 7.4.1.4).
fn selectedAlpn(value: *Reader, options: Options) ParseError![]const u8 {
    @setRuntimeSafety(true);
    if (options.alpn.len == 0) return error.UnsolicitedExtension;
    var protocols = try value.vector(u16);
    const alpn = (try protocols.vector(u8)).bytes;
    try protocols.finish();
    // ProtocolName<1..2^8-1> (RFC 7301 section 3.1): an empty name is out of its range.
    if (alpn.len == 0) return error.DecodeError;
    for (options.alpn) |offered| if (std.mem.eql(u8, offered, alpn)) return alpn;
    return error.UnofferedSelection;
}

/// What a TLS 1.2 ServerHello delivers beside the certificate, each only to a client that asked:
/// its SCTs (RFC 6962 section 3.3.1, not empty) and, answering status_request empty, the promise
/// that a CertificateStatus may follow (RFC 6066 section 8).
const Delivered = struct {
    scts: ?[]const u8 = null,
    ocsp: bool = false,

    fn read(self: *Delivered, id: u16, bytes: []const u8, options: Options) ParseError!void {
        switch (id) {
            Messages.signed_certificate_timestamp => {
                if (!options.request_scts) return error.UnsolicitedExtension;
                if (bytes.len == 0) return error.DecodeError;
                self.scts = bytes;
            },
            else => {
                if (!options.request_ocsp) return error.UnsolicitedExtension;
                if (bytes.len != 0) return error.DecodeError;
                self.ocsp = true;
            },
        }
    }
};

const Seen12 = struct { group: bool, alpn: []const u8, ems: bool, renegotiation: bool, ticket: bool, session12: bool, connection_id: ?[]const u8, srtp: ?Srtp, types: CertificateTypes, scts: ?[]const u8, ocsp: bool, record_size_limit: ?u16 };

/// The ServerHello extensions only a TLS 1.2 answer carries.
fn answers12(id: u16) bool {
    return switch (id) {
        // record_size_limit: a TLS 1.3 server answers it in EncryptedExtensions (RFC 8449 section 4).
        0, 5, 11, 16, 18, 23, 35, 0xff01, client_certificate_type, server_certificate_type, RecordLimits.extension => true,
        else => false,
    };
}

/// A server's answers to client_certificate_type and server_certificate_type (RFC 7250 section
/// 4.2): one type each, among those offered (the server's, the raw key alone).
const CertificateTypes = struct {
    raw_server_key: bool = false,
    raw_client_key: bool = false,

    fn read(self: *CertificateTypes, id: u16, value: *Reader, options: Options) ParseError!void {
        @setRuntimeSafety(true);
        const offered = if (id == server_certificate_type) options.raw_server_key else options.client_types != .x509;
        if (!offered) return error.UnsolicitedExtension;
        if (value.bytes.len != 1) return error.DecodeError;
        const kind = try value.int(u8);
        const raw = @backingInt(CertificateType.raw_public_key);
        if (id == server_certificate_type) {
            if (kind != raw) return error.UnofferedSelection;
            self.raw_server_key = true;
        } else {
            if (std.mem.findScalar(u8, options.client_types.list(), kind) == null) return error.UnofferedSelection;
            self.raw_client_key = kind == raw;
        }
    }
};
fn server12(legacy_version: u16, random: *const [32]u8, echoed: []const u8, session: []const u8, suite_id: u16, seen: Seen12, options: Options) ParseError!Answer {
    @setRuntimeSafety(true);
    // A server answering below TLS 1.3 marks its random; this client offered TLS 1.3, so a
    // marked random is an attacker's downgrade (RFC 8446 section 4.1.3).
    if (options.allows13() and (std.mem.eql(u8, random[24..], downgrade_tls12) or std.mem.eql(u8, random[24..], "DOWNGRD\x00"))) return error.Downgrade;
    if (legacy_version != options.transport.legacy() or !options.allows12()) return error.UnsupportedVersion;
    // No TLS 1.3 field in a TLS 1.2 answer, and no resumption this client did not ask for: an echo
    // of its session id resumes, which it may only with a ticket it sent (RFC 5077 section 3.4).
    if (seen.group or std.mem.eql(u8, random, &retry_random)) return error.InvalidHello;
    const resumed = session.len != 0 and std.mem.eql(u8, echoed, session);
    if (resumed and !seen.session12) return error.InvalidHello;
    const suite = std.enums.fromInt(Suite12, suite_id) orelse return error.UnofferedSelection;
    if (!options.offers12(suite)) return error.UnofferedSelection;
    if (!seen.ems) return error.NoExtendedMasterSecret;
    if (!seen.renegotiation) return error.NoSecureRenegotiation;
    if (options.require_alpn and seen.alpn.len == 0) return error.NoApplicationProtocol;
    return .{ .tls12 = .{ .suite = suite, .random = random, .alpn = seen.alpn, .resumed = resumed, .ticket = seen.ticket, .connection_id = seen.connection_id, .srtp = seen.srtp, .raw_server_key = seen.types.raw_server_key, .raw_client_key = seen.types.raw_client_key, .scts = seen.scts, .ocsp = seen.ocsp, .record_size_limit = seen.record_size_limit } };
}
/// A DTLS 1.2 HelloVerifyRequest's cookie (RFC 6347 section 4.2.1). Its server_version only
/// formats the record (DTLS 1.0's or 1.2's number) and negotiates nothing.
pub fn helloVerify(message: []const u8) ParseError![]const u8 {
    @setRuntimeSafety(true);
    if (message.len < 4 or message[0] != 3 or std.mem.readInt(u24, message[1..4], .big) != message.len - 4) return error.InvalidLength;
    var r: Reader = .{ .bytes = message[4..] };
    const version = try r.int(u16);
    if (version != 0xfeff and version != 0xfefd) return error.InvalidHello;
    // opaque cookie<0..2^8-1>: an empty one too, which the second hello then carries.
    const cookie = (try r.vector(u8)).bytes;
    try r.finish();
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

/// supported_groups: a hello without TLS 1.3 names only the groups TLS 1.2 has, the classical
/// ones (F118).
fn supportedGroups(w: *Writer, options: Options, tls13: bool) Writer.WriteError!void {
    @setRuntimeSafety(true);
    var group_bytes: [2 + 2 * std.enums.values(Group).len]u8 = undefined;
    var g: Writer = .{ .bytes = &group_bytes };
    var listed: usize = 0;
    for (options.groups) |group| listed += @intFromBool(tls13 or group.classical());
    // safe: at most every group once, each two bytes.
    try g.int(u16, @intCast(listed * 2));
    for (options.groups) |group| if (tls13 or group.classical()) try g.int(u16, @backingInt(group));
    try extension(w, 10, group_bytes[0..g.pos]);
}

/// legacy_session_id_echo<0..32>: a longer echo is out of the field's range (decode_error).
fn sessionEcho(r: *Reader) ParseError![]const u8 {
    const echoed = (try r.vector(u8)).bytes;
    if (echoed.len > 32) return error.DecodeError;
    return echoed;
}

/// The extensions cloak implements, in either role: any other is one its hellos never carry.
fn recognized(id: u16) bool {
    const known = [_]u16{ 0, 10, 11, 13, 14, 16, 18, 19, 20, 23, 27, 28, 34, 35, 41, 42, 43, 44, 45, 49, 51, 54, 57, 0xfd00, Ech.extension_id, 0xff01 };
    return std.mem.containsAtLeast(u16, &known, 1, &.{id});
}

/// `ech`: an ECHConfigList the server offered for a retry (RFC 9849 section 7.1).
/// `srtp`: DTLS 1.3, the SRTP profile the server chose.
/// `raw_server_key`, `raw_client_key`: the server selected the raw public key type (RFC 7250)
/// for its own Certificate, and for the client's.
pub const EncryptedExtensions = struct { alpn: []const u8, parameters: []const u8, ech: ?[]const u8 = null, srtp: ?Srtp = null, raw_server_key: bool = false, raw_client_key: bool = false, record_size_limit: ?u16 = null };
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
    var srtp: ?Srtp = null;
    var types: CertificateTypes = .{};
    var record_size_limit: ?u16 = null;
    while (try ext.next()) |item| switch (item.id) {
        client_certificate_type, server_certificate_type => {
            var value: Reader = .{ .bytes = item.bytes };
            try types.read(item.id, &value, options);
        },
        srtp_extension, RecordLimits.extension => {
            var value: Reader = .{ .bytes = item.bytes };
            if (item.id == srtp_extension) srtp = try selectedSrtp(&value, options) else record_size_limit = try recordSizeAnswer(&value, options);
            try value.finish();
        },
        Ech.extension_id => {
            if (!ech_sent) return error.UnsolicitedExtension;
            Ech.checkList(item.bytes) catch return error.DecodeError;
            ech = item.bytes;
        },
        // RFC 8446 section 4.2: an answer to an extension the client never sent is
        // unsupported_extension; the empty acknowledgement with data in it is out of range.
        0 => {
            if (options.sni.len == 0) return error.UnsolicitedExtension;
            if (item.bytes.len != 0) return error.DecodeError;
        },
        10 => {
            var groups: Reader = .{ .bytes = item.bytes };
            const list = try groups.vector(u16);
            if (list.bytes.len == 0 or list.bytes.len % 2 != 0) return error.InvalidHello;
            try groups.finish();
        },
        16 => {
            var value: Reader = .{ .bytes = item.bytes };
            alpn = try selectedAlpn(&value, options);
            try value.finish();
        },
        57 => {
            if (options.transport != .quic) return error.UnsolicitedExtension;
            parameters = item.bytes;
            has_parameters = true;
        },
        // One cloak knows is out of place here (illegal_parameter); one it does not know it
        // never sent.
        else => return if (recognized(item.id)) error.InvalidHello else error.UnsolicitedExtension,
    };
    if ((options.require_alpn or options.transport == .quic) and alpn.len == 0) return error.NoApplicationProtocol;
    if (options.transport == .quic and !has_parameters) return error.MissingExtension;
    return .{ .alpn = alpn, .parameters = parameters, .ech = ech, .srtp = srtp, .raw_server_key = types.raw_server_key, .raw_client_key = types.raw_client_key, .record_size_limit = record_size_limit };
}

/// A ServerHello selecting `suite`, answering the client's share for `group`, when `psk`
/// selecting the PSK identity at index `psk`, and in DTLS answering connection_id with the
/// connection ID the server receives on.
pub fn buildServer(out: []u8, transport: suites.Transport, random: *const [32]u8, session: []const u8, suite: Suite13, group: Group, share: []const u8, psk: ?u16, connection_id: ?[]const u8) Writer.WriteError![]u8 {
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
    if (connection_id) |cid| try connectionIdAnswer(&w, cid);
    // safe: the extension block holds four short extensions.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: the whole message is bounded by the caller's buffer, far below 2^24.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// The longest SignedCertificateTimestampList a server sends.
pub const max_scts = 2048;
/// What a TLS 1.2 ServerHello answers because the client sent it: no extension appears in a
/// ServerHello unless the ClientHello carried it (RFC 5246 section 7.4.1.4).
/// `renegotiation_info`: the client signalled secure renegotiation, by the extension or the SCSV
/// (RFC 5746 section 3.6). `record_size_limit`: this server's, answering the client's (RFC 8449).
/// DTLS: `connection_id` the connection ID the server receives on, `srtp` the profile it chose.
/// `client_certificate_type`, `server_certificate_type`: the types selected (RFC 7250), answered
/// when the client sent the extension.
/// `scts`: the certificate's SignedCertificateTimestampList, for a client that asked (RFC 6962
/// section 3.3.1), at most `max_scts` bytes. `ocsp`: a CertificateStatus follows the
/// Certificate, for a client that asked (RFC 6066 section 8).
pub const Echo12 = struct { server_name: bool, renegotiation_info: bool, point_formats: bool, record_size_limit: ?u16 = null, ticket: bool = false, connection_id: ?[]const u8 = null, srtp: ?Srtp = null, client_certificate_type: ?CertificateType = null, server_certificate_type: ?CertificateType = null, scts: ?[]const u8 = null, ocsp: bool = false };

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
    if (echo.renegotiation_info) try w.put(&.{ 0xff, 0x01, 0, 1, 0 });
    if (echo.ticket) try w.put(&.{ 0, 35, 0, 0 });
    if (echo.record_size_limit) |limit| try recordSizeExtension(&w, limit);
    if (echo.connection_id) |cid| try connectionIdAnswer(&w, cid);
    if (echo.srtp) |profile| try srtpAnswer(&w, profile);
    if (echo.client_certificate_type) |kind| try extension(&w, client_certificate_type, &.{@backingInt(kind)});
    if (echo.server_certificate_type) |kind| try extension(&w, server_certificate_type, &.{@backingInt(kind)});
    if (echo.scts) |list| try extension(&w, Messages.signed_certificate_timestamp, list);
    if (echo.ocsp) try extension(&w, Messages.status_request, "");
    if (alpn.len != 0) {
        try w.int(u16, 16);
        // safe: a protocol name is at most 255 bytes.
        try w.int(u16, @intCast(alpn.len + 3));
        try w.int(u16, @intCast(alpn.len + 1));
        try w.vector(u8, alpn);
    }
    // safe: the extension block holds short fixed extensions, an SCT list bounded by the
    // server's options and one protocol name.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded by the caller's buffer.
    std.mem.writeInt(u24, out[1..4], @intCast(w.pos - 4), .big);
    return out[0..w.pos];
}

/// A HelloRetryRequest (RFC 8446 section 4.1.4) asking for `group`'s share when there is one,
/// carrying `cookie` when it is not empty (DTLS's stateless return-routability check). With
/// `ech`, it ends with an encrypted_client_hello of eight zero bytes, the last eight of the
/// message, for the caller to replace with the confirmation (RFC 9849 section 7.2.1).
pub fn buildRetry(out: []u8, transport: suites.Transport, session: []const u8, suite: Suite13, group: ?Group, cookie: []const u8, ech: bool) Writer.WriteError![]u8 {
    @setRuntimeSafety(true);
    if (cookie.len > 4096) return error.BufferTooSmall;
    var w: Writer = .{ .bytes = out };
    try w.put(&.{ 2, 0, 0, 0 });
    try w.int(u16, transport.legacy());
    try w.put(&retry_random);
    try w.vector(u8, session);
    try w.int(u16, @backingInt(suite));
    try w.put(&.{0});
    const ext_at = w.pos;
    try w.int(u16, 0);
    try w.put(&.{ 0, 43, 0, 2 });
    try w.int(u16, transport.wire(.tls13));
    if (group) |selected| {
        try w.put(&.{ 0, 51, 0, 2 });
        try w.int(u16, @backingInt(selected));
    }
    if (cookie.len != 0) {
        try w.int(u16, 44);
        // safe: bounded at 4096 above.
        try w.int(u16, @intCast(cookie.len + 2));
        try w.vector(u16, cookie);
    }
    if (ech) {
        try w.int(u16, Ech.extension_id);
        try w.int(u16, 8);
        try w.put(&@as([8]u8, @splat(0)));
    }
    // safe: four short extensions and a bounded cookie.
    std.mem.writeInt(u16, out[ext_at..][0..2], @intCast(w.pos - ext_at - 2), .big);
    // safe: bounded by the cookie's limit.
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
    /// DTLS 1.3: the SRTP profile chosen.
    srtp: ?Srtp = null,
    /// RFC 7250: the certificate types selected, answering the client's lists.
    server_certificate_type: ?CertificateType = null,
    client_certificate_type: ?CertificateType = null,
    /// This server's record_size_limit, answering the client's (RFC 8449).
    record_size_limit: ?u16 = null,
};

fn recordSizeExtension(w: *Writer, limit: u16) Writer.WriteError!void {
    try w.put(&.{ 0, RecordLimits.extension, 0, 2 });
    try w.int(u16, limit);
}

fn connectionIdAnswer(w: *Writer, cid: []const u8) Writer.WriteError!void {
    if (cid.len > 255) return error.BufferTooSmall;
    try w.int(u16, connection_id_extension);
    try w.int(u16, @intCast(cid.len + 1)); // safe: at most 256
    try w.vector(u8, cid);
}

/// use_srtp answering with one profile and no MKI (RFC 5764 section 4.1.3).
fn srtpAnswer(w: *Writer, profile: Srtp) Writer.WriteError!void {
    try w.put(&.{ 0, srtp_extension, 0, 5, 0, 2 });
    try w.int(u16, @backingInt(profile));
    try w.int(u8, 0);
}

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
    if (parts.srtp) |profile| try srtpAnswer(&w, profile);
    if (parts.client_certificate_type) |kind| try extension(&w, client_certificate_type, &.{@backingInt(kind)});
    if (parts.server_certificate_type) |kind| try extension(&w, server_certificate_type, &.{@backingInt(kind)});
    if (parts.record_size_limit) |limit| try recordSizeExtension(&w, limit);
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
