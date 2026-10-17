//! The TLS 1.3 client handshake. It takes whole handshake messages with their epoch and
//! record alignment and returns outputs through a queue: messages to send, traffic secrets
//! to install, and requests for services it never performs itself (entropy, time, peer
//! verification, signing). It owns the transcript, the key schedule and the checked state;
//! records and QUIC levels belong to the callers that translate its outputs.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const suites = @import("../crypto/Suite.zig");
const Suite13 = suites.Suite13;
const Labels = @import("../crypto/Labels.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Group = @import("../crypto/Group.zig").Group;
const Alert = @import("../wire/Alert.zig").Alert;
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const Flight = @import("Flight.zig");
const Possession = @import("Possession.zig");
const Schedule = @import("Schedule.zig");
const State = @import("State.zig");
const Transcripts = @import("Transcripts.zig");
const Client12 = @import("Client12.zig");
const SessionCache = @import("../resumption/SessionCache.zig");
const Ech = @import("Ech.zig");
const Compression = @import("Compression.zig");
const Hpke = @import("../crypto/Hpke.zig");
const Psk = @import("Psk.zig");
const Delegation = @import("Delegation.zig");
const transparency = @import("../../verify/transparency.zig");
const PostAuth = @import("PostAuth.zig");
const Terms = @import("Terms.zig");

pub const Epoch = Flight.Epoch;
pub const Direction = Flight.Direction;

pub const Limits = Terms.Limits;
pub const Verify = Terms.Verify;

/// Receives NSS key-log lines. The sink is outside the confidentiality guarantee.
pub const KeyLog = struct {
    context: ?*anyopaque = null,
    write: *const fn (context: ?*anyopaque, line: []const u8) void,
};

/// Resumption from a cache of tickets: TLS 1.3 PSK-DHE, a fresh key exchange every time.
pub const Resumption = struct {
    cache: *SessionCache,
    /// Separates callers sharing a cache whose tickets must never cross: tenants, or a proxy and
    /// the origins behind it. The server name, identity, ALPN, transport, verification policy,
    /// trust generation and client certificate are in the cache key already.
    namespace: []const u8 = "",
    /// The longest a session is resumed after the full handshake that authenticated it.
    max_age: std.Io.Duration = .fromSeconds(7 * 24 * 60 * 60),
    /// TLS 1.2 session tickets too (RFC 5077). An abbreviated TLS 1.2 handshake reuses the
    /// session's master secret with no new key exchange, so it gives up forward secrecy between
    /// the connections of a session: off unless asked for.
    tls12: bool = false,
};

pub const Options = struct {
    hello: Hello.Options = .{},
    resumption: ?Resumption = null,
    /// Encrypted Client Hello (RFC 9849). A config list makes it required and the connection
    /// TLS 1.3 only.
    ech: Ech.Mode = .off,
    /// A provisioned key to offer, for its one version: TLS 1.3 (PSK-DHE), offered instead of a
    /// ticket, never with one; or TLS 1.2 (plain PSK, RFC 4279), offered by listing its suites,
    /// which have no forward secrecy. A server that selects it is authenticated by it, with no
    /// certificate.
    external_psk: ?Psk.External = null,
    /// The identity the server certificate must carry.
    identity: types.Identity = .none,
    verify: Verify,
    /// Certificates and key for a CertificateRequest; its signature is a signing request.
    auth: ?certificates.ClientAuth = null,
    /// A delegated credential of `auth`'s certificate (RFC 9345, role `client`), presented with
    /// it when the server's CertificateRequest takes one; its key signs then. Needs full
    /// verification of the server, whose clock decides whether it is still valid.
    auth_delegated: ?Delegation.Credential = null,
    limits: Limits = .{},
    /// A random legacy session id and one change_cipher_spec, for middleboxes (stream only).
    compat: bool = true,
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Traffic = Flight.Traffic;
pub const Emit = Flight.Emit;

pub const Need = Terms.Need;
pub const SignRequest = Terms.SignRequest;

pub const Info = struct {
    version: suites.Version,
    /// The handshake resumed a session from a ticket: the peer's authentication is the original
    /// handshake's.
    suite: suites.Suite,
    /// The key exchange's group; null for a TLS 1.2 provisioned key, which has none.
    group: ?Group,
    alpn: []const u8,
    server_name: []const u8,
    peer_authenticated: bool,
    peer_parameters: []const u8,
    resumed: bool = false,
    /// Encrypted Client Hello was offered and accepted: the true server name never crossed the
    /// wire in clear.
    ech_accepted: bool = false,
    /// The handshake used a provisioned key: the peer is whoever holds it, no certificate.
    external_psk: bool = false,
    /// DTLS: the SRTP profile use_srtp agreed (RFC 5764), keyed by the "EXTRACTOR-dtls_srtp"
    /// exporter; null when none was offered or none agreed.
    srtp: ?Hello.Srtp = null,
    /// The peer proved a raw public key (RFC 7250): its index in the policy's pins. Null when it
    /// presented certificates or nothing.
    raw_key_pin: ?u16 = null,
    /// The peer proved possession with a delegated credential (RFC 9345) its verified certificate
    /// signed, not with the certificate's own key.
    delegated_credential: bool = false,
};

pub const InitError = Hello.ValidateError || std.mem.Allocator.Error || error{InvalidOptions};
pub const Error = @import("Errors.zig").Error;

/// The alert that reports an error to the peer. Local service failures are internal errors.
pub fn alertFor(err: anyerror) Alert {
    return switch (err) {
        error.UnexpectedMessage, error.WrongEpoch, error.MissingProof, error.RecordAlignment => .unexpected_message,
        error.InvalidLength, error.InvalidMessage, error.EmptyCertificate, error.CertificateLimit => .decode_error,
        error.NoSharedGroup, error.NoSharedSuite, error.NoSignatureScheme => .handshake_failure,
        error.UnrecognizedName => .unrecognized_name,
        error.CertificateRequired => .certificate_required,
        error.DecodeError => .decode_error,
        error.UnexpectedCookie => .illegal_parameter,
        error.DuplicateExtension, error.ExtensionLimit, error.InvalidHello, error.IllegalParameter, error.UnofferedSelection, error.InvalidShare, error.WeakKey, error.InvalidRetry => .illegal_parameter,
        error.UnsolicitedExtension => .unsupported_extension,
        error.EchRejected => .ech_required,
        error.EchDecryptFailed => .decrypt_error,
        error.MissingExtension => .missing_extension,
        error.HybridRequired, error.PqAuthenticationRequired => .insufficient_security,
        error.UnsupportedVersion => .protocol_version,
        error.UnsupportedCertificate => .unsupported_certificate,
        error.PinMismatch => .bad_certificate,
        error.NoExtendedMasterSecret, error.NoSecureRenegotiation, error.NoClientCertificate, error.PskRequired => .handshake_failure,
        error.InappropriateFallback => .inappropriate_fallback,
        error.Downgrade => .illegal_parameter,
        error.NoApplicationProtocol => .no_application_protocol,
        error.UnofferedScheme, error.SchemeKeyMismatch => .illegal_parameter,
        error.BadSignature, error.BadFinished, error.BadBinder => .decrypt_error,
        error.HandshakeLimit => .internal_error,
        error.VerificationRejected, error.UnsupportedKey, error.InvalidCertificate, error.InvalidDer => .bad_certificate,
        else => .internal_error,
    };
}

const Client = @This();

gpa: std.mem.Allocator,
/// The options, kept in the handshake scratch and gone with it once the connection is
/// established: an idle connection holds only `kept`.
options: *Options,
/// What outlives the handshake: tickets that arrive later, the message bound, the name `info`
/// reports and the client certificate's retained identity.
kept: Kept,
state: State.State,
need_now: Need = .{ .entropy = .{ .len = 0 } },
/// A post-handshake output (ticket, key update), once the queue is released.
post: ?Emit = null,
// Hello state.
/// Handshake-only state, one allocation released when the connection is established.
scratch: ?*Scratch,
retry_suite: ?Suite13 = null,
retry_group: ?Group = null,
ccs_sent: bool = false,
total_bytes: usize = 0,
// Negotiation and peer state.
suite: ?Suite13 = null,
group: ?Group = null,
keys: ?Keys = null,
alpn: []const u8 = "",
srtp: ?Hello.Srtp = null,
peer_parameters: []u8 = &.{},
held: []u8 = &.{},
now: ?std.Io.Timestamp = null,
request_id: u64 = 0,
authenticated: bool = false,
requested_certificate: bool = false,
/// The index of the pin the server's raw public key matched (RFC 7250).
raw_pin: ?u16 = null,
/// The server proved possession with a delegated credential (RFC 9345).
delegated_used: bool = false,
sign_scheme: Hello.SignatureScheme = .ed25519,
established: bool = false,
/// The client's application write secret, queued after its Finished.
app_write: ?Traffic = null,
// TLS 1.2.
/// The version the ServerHello chose; TLS 1.3 until then.
version: suites.Version = .tls13,
suite12: ?suites.Suite12 = null,
/// TLS 1.2 secrets that outlive the handshake (the exporter needs them), allocated only for a
/// TLS 1.2 connection.
tls12: ?*Flight.Secrets12 = null,
// Resumption.
/// The cache key: everything the authority of a stored session depended on.
cache_key: [32]u8 = @splat(0),
/// The tickets offered in the hello (TLS 1.3, TLS 1.2), until the ServerHello answers them.
offered: ?SessionCache.Taken = null,
offered12: ?SessionCache.Taken = null,
/// TLS 1.2: the NewSessionTicket's ticket and lifetime hint, kept until the server's Finished.
ticket12: []u8 = &.{},
ticket12_hint: u32 = 0,
resumed: bool = false,
ech_accepted: bool = false,
/// The provisioned key is still on offer (until the server's answer, or a retry to another hash).
external_offered: bool = false,
/// The server selected the provisioned key.
external_used: bool = false,
/// After an authenticated rejection: the server's retry configurations (empty when it sent none,
/// ECH securely disabled); null otherwise. Kept past the failure, freed with the client.
ech_retry: ?[]u8 = null,
/// Seconds: the full handshake this session began with, and when its server authentication
/// expires. Tickets of the session never outlive either.
origin: i64 = 0,
auth_expires: i64 = std.math.maxInt(i64),
/// Post-handshake authentication, kept from the client's Finished when it was offered.
post_auth: ?*PostAuth = null,

const Kept = struct {
    auth: ?certificates.ClientAuth,
    auth_delegated: ?Delegation.Credential = null,
    resumption: ?Resumption,
    sni: []const u8,
    message_limit: usize,
    compat: bool,
    allows12: bool,
};

const Scratch = struct {
    options: Options = undefined,
    flight: Flight = .{},
    transcripts: Transcripts = .{},
    random: [32]u8 = @splat(0),
    session: [32]u8 = @splat(0),
    session_len: u8 = 0,
    shares: [2]?Exchange.Share = @splat(null),
    cookie: [4096]u8 = undefined,
    cookie_len: u16 = 0,
    /// DTLS 1.2: a HelloVerifyRequest's cookie, for the hello's cookie field.
    legacy_cookie: [255]u8 = undefined,
    legacy_cookie_len: u8 = 0,
    /// DTLS: the server answered connection_id with the connection ID it receives on.
    peer_cid: [255]u8 = undefined,
    peer_cid_len: u8 = 0,
    cid_agreed: bool = false,
    chain: [Messages.max_certificates][]const u8 = undefined,
    chain_len: usize = 0,
    /// RFC 7250: the server selected the raw key type for its Certificate, and for the client's.
    peer_raw: bool = false,
    client_raw: bool = false,
    /// RFC 6962: the server's SignedCertificateTimestampList, owned, and the request's lists
    /// with it after the caller's.
    scts: []u8 = &.{},
    sct_lists: [types.TransparencyPolicy.max_lists][]const u8 = undefined,
    /// RFC 9345: the server's delegated credential (in `held`) and, once checked, its key.
    delegated: ?[]const u8 = null,
    delegated_key: ?Delegation.Checked = null,
    cr_schemes: [1024]u8 = undefined,
    cr_len: u16 = 0,
    /// The CertificateRequest's delegated_credential list, when it sent one.
    cr_delegated: [1024]u8 = undefined,
    cr_delegated_len: ?u16 = null,
    /// TLS 1.2: the certificate types a CertificateRequest named (Client12.rsa_sign, ecdsa_sign).
    cr_types: u8 = 0,
    sign_content: [Messages.max_signed]u8 = undefined,
    sign_content_len: u8 = 0,
    /// Fresh noise for the hedged client signature, drawn with the first entropy.
    sign_noise: [certificates.PrivateKey.max_noise]u8 = @splat(0),
    // TLS 1.2: the server's ECDHE public value and the client's share for it.
    server_public: [97]u8 = undefined,
    server_public_len: u8 = 0,
    share12: ?Exchange.Share = null,
    ech: EchScratch = .{},
};

/// Encrypted Client Hello in flight: until the server's first answer, two hellos and two
/// transcripts run side by side, the outer one on the wire and the inner one the transcript of an
/// accepted handshake.
const EchScratch = struct {
    status: enum { none, offered, accepted_retry, accepted, rejected } = .none,
    outer_random: [32]u8 = @splat(0),
    /// The HPKE ephemeral key's input, used once.
    ikm: [32]u8 = @splat(0),
    /// Seeds the GREASE bytes: a GREASE extension, or a GREASE PSK in the outer hello.
    seed: [32]u8 = @splat(0),
    context: ?Hpke.Context = null,
    enc: [Hpke.enc_length]u8 = undefined,
    inner: Transcripts = .{},
    /// The first hello's encrypted_client_hello body: a retry request that does not accept ECH,
    /// or GREASE, sends it again unchanged.
    ext: []u8 = &.{},
    /// The retry configurations of a rejection, held until the public name is authenticated.
    retry_list: []u8 = &.{},
};

fn Keyed(comptime suite: Suite13) type {
    return struct {
        const K = Schedule.Schedule(suite);
        schedule: K,
        handshake: K.Traffic,
    };
}
const Keys = union(Suite13) {
    aes_128_gcm_sha256: Keyed(.aes_128_gcm_sha256),
    aes_256_gcm_sha384: Keyed(.aes_256_gcm_sha384),
    chacha20_poly1305_sha256: Keyed(.chacha20_poly1305_sha256),
    aes_128_ccm_sha256: Keyed(.aes_128_ccm_sha256),
};

pub fn init(gpa: std.mem.Allocator, options: Options) InitError!*Client {
    @setRuntimeSafety(true);
    try Hello.validate(options.hello);
    switch (options.verify) {
        .full => if (options.identity == .none) return error.InvalidOptions,
        // Post-quantum authentication is of a verified path or a pinned ML-DSA key.
        .none => if (options.hello.require_pq_auth) return error.InvalidOptions,
        .raw_key => |raw| if (raw.pins.len == 0 or raw.pins.len > Verify.RawKey.max_pins) return error.InvalidOptions,
    }
    // Middlebox compatibility is a stream's: QUIC and DTLS have neither its session id nor its
    // ChangeCipherSpec.
    if (options.hello.transport != .stream and options.compat) return error.InvalidOptions;
    if (options.limits.message < 1024 or options.limits.handshake < options.limits.message or options.limits.certificates == 0) return error.InvalidOptions;
    if (options.resumption) |resumption| if (resumption.namespace.len > 1024 or resumption.max_age.nanoseconds <= 0) return error.InvalidOptions;
    var hello = options.hello;
    // RFC 7250: the types this client asks for and can present.
    hello.raw_server_key = options.verify == .raw_key;
    // RFC 6962 section 3.3.1: a client requiring Certificate Transparency asks for the server's
    // SCTs, which join the verification request beside the caller's lists.
    if (options.verify == .full) {
        const full = options.verify.full;
        if (full.policy.transparency) |policy| transparency.validate(policy.*) catch return error.InvalidOptions;
        hello.request_scts = full.policy.transparency != null;
        if (hello.request_scts and full.evidence.scts.len >= types.TransparencyPolicy.max_lists) return error.InvalidOptions;
    } else hello.request_scts = false;
    hello.raw_client_key = if (options.auth) |auth| auth.identity.form() == .raw_public_key else false;
    Hello.validate(hello) catch return error.InvalidOptions;
    // ECH over datagrams (RFC 9849 with DTLS 1.3) is not built: refused rather than ignored.
    if (options.ech != .off and options.hello.transport == .datagram) return error.InvalidOptions;
    switch (options.ech) {
        .off => {},
        // GREASE needs a TLS 1.3 offer to ride on.
        .grease => if (!hello.allows13()) return error.InvalidOptions,
        .config_list => |list| {
            // A rejected attempt authenticates the public name's certificate, which a client
            // trusting a raw key alone cannot (RFC 9849 section 6.1.7).
            if (options.verify == .raw_key) return error.InvalidOptions;
            // A list with no config this client can use is a configuration error, never a
            // reason to send the true name in clear.
            _ = (Ech.choose(list) catch return error.InvalidOptions) orelse return error.InvalidOptions;
            // ECH is TLS 1.3 only (RFC 9849 section 6.1).
            hello.min_version = .tls13;
            Hello.validate(hello) catch return error.InvalidOptions;
        },
    }
    // A delegated credential is checked by the clock of a verified chain (RFC 9345 section 4.1.3),
    // in TLS 1.3 only; a client's own belongs to its certificate.
    if (hello.accept_delegated and (options.verify != .full or !hello.allows13())) return error.InvalidOptions;
    if (options.auth_delegated) |delegated| {
        const auth = options.auth orelse return error.InvalidOptions;
        if (options.verify != .full or !hello.allows13() or delegated.side() != .client or !delegated.belongsTo(auth.identity)) return error.InvalidOptions;
    }
    if (options.external_psk) |psk| {
        Psk.validate(psk) catch return error.InvalidOptions;
        if (!offersKeySuite(hello, psk)) return error.InvalidOptions;
    }
    // The TLS 1.2 PSK suites are offered only with a TLS 1.2 key to complete them.
    const key12 = if (options.external_psk) |psk| psk.version == .tls12 else false;
    for (hello.suites) |suite| if (suite.tls12()) |s12| if (s12.authentication() == .psk and !key12) return error.InvalidOptions;
    const self = try gpa.create(Client);
    errdefer gpa.destroy(self);
    const scratch = try gpa.create(Scratch);
    errdefer gpa.destroy(scratch);
    scratch.* = .{ .options = options };
    scratch.options.hello = hello;
    self.* = .{
        .gpa = gpa,
        .options = &scratch.options,
        .kept = .{ .auth = null, .resumption = options.resumption, .sni = hello.sni, .message_limit = options.limits.message, .compat = options.compat, .allows12 = hello.allows12() },
        .state = .init(.client, options.hello.transport),
        .scratch = scratch,
    };
    // A TLS 1.3 key goes in the hello's pre_shared_key; a TLS 1.2 key waits for its suite.
    self.external_offered = if (options.external_psk) |psk| psk.version == .tls13 else false;
    self.need_now = .{ .entropy = .{ .len = self.initialEntropy() } };
    // A datagram hello that may be answered in DTLS 1.2 is hashed in its DTLS form too.
    if (options.hello.transport == .datagram and options.hello.allows12()) scratch.transcripts.startDatagram(0, 0, options.hello.allows13());
    if (options.resumption) |resumption| {
        // A ticket is chosen and aged by the clock, before the hello.
        if (options.hello.allows13() or (resumption.tls12 and options.hello.allows12())) self.need_now = .time;
        self.cache_key = cacheKey(options, resumption.namespace);
    }
    if (options.auth_delegated) |delegated| self.kept.auth_delegated = delegated.retain();
    if (options.auth) |auth| {
        self.kept.auth = auth.retain();
        // A TLS 1.2 CertificateVerify by Ed25519 signs the handshake messages themselves.
        if (hello.allows12() and auth.identity.publicKey() == .ed25519) scratch.transcripts.keep(gpa);
    }
    return self;
}

/// Whether the hello offers a suite a provisioned key can complete: one of its version and hash.
fn offersKeySuite(hello: Hello.Options, psk: Psk.External) bool {
    for (hello.suites) |suite| switch (psk.version) {
        .tls13 => if (suite.tls13()) |s13| if (hello.allows13() and suites.digestLength(s13) == psk.hash.length()) return true,
        .tls12 => if (suite.tls12()) |s12| if (hello.allows12() and s12.authentication() == .psk) return true,
    };
    return false;
}

pub fn deinit(self: *Client) void {
    @setRuntimeSafety(true);
    const gpa = self.gpa;
    self.wipe();
    if (self.kept.auth) |auth| auth.deinit();
    if (self.kept.auth_delegated) |delegated| delegated.deinit();
    if (self.post_auth) |post| post.deinit();
    if (self.ech_retry) |list| gpa.free(list);
    self.* = undefined;
    gpa.destroy(self);
}

/// Erases secrets and releases buffers; callable once the connection is established.
pub fn wipe(self: *Client) void {
    @setRuntimeSafety(true);
    self.releaseOffer();
    self.dropTicket12();
    self.releaseScratch();
    if (self.post) |*emit| Flight.eraseEmit(emit);
    self.post = null;
    if (self.keys) |*keys| switch (keys.*) {
        inline else => |*k| {
            k.schedule.deinit();
            k.handshake.deinit();
        },
    };
    self.keys = null;
    if (self.tls12) |secrets| secrets.destroy(self.gpa);
    self.tls12 = null;
    self.keys = null;
    if (self.held.len != 0) {
        self.gpa.free(self.held);
        self.held = &.{};
    }
    if (self.peer_parameters.len != 0) {
        self.gpa.free(self.peer_parameters);
        self.peer_parameters = &.{};
    }
    self.state.fail();
}

// ---------------------------------------------------------------- services

/// A ChangeCipherSpec record arrived; only TLS 1.2 expects one, once, before the server's Finished.
pub fn receiveCcs(self: *Client) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() == .failed) return error.Closed;
    if (self.version != .tls12) return error.UnexpectedMessage;
    errdefer self.state.fail();
    return Client12.onCcs(self);
}

pub fn compat(self: *const Client) bool {
    return self.kept.compat;
}

/// Whether TLS 1.2 was offered.
pub fn allows12(self: *const Client) bool {
    return self.kept.allows12;
}

pub fn need(self: *const Client) Need {
    if (self.need_now == .none) if (self.post_auth) |post| return post.need;
    return self.need_now;
}

fn initialGroups(self: *const Client) struct { groups: [2]?Group, count: usize } {
    @setRuntimeSafety(true);
    var out: [2]?Group = .{ null, null };
    var count: usize = 0;
    // A TLS 1.2-only client sends no key shares.
    if (!self.options.hello.allows13()) return .{ .groups = out, .count = 0 };
    // A datagram hello stays within one datagram, so that a server can check its address
    // without keeping state (RFC 9147 section 5.1): at most one classical share, X25519 when
    // listed, and none for a hybrid-only or post-quantum-only list, whose shares (1,184 to 1,665
    // bytes) do not fit beside the hello. The server asks for the group it wants with the retry
    // request that brings its cookie.
    if (self.options.hello.transport == .datagram) {
        if (self.options.hello.require_hybrid) return .{ .groups = out, .count = 0 };
        const classical = if (std.mem.containsAtLeast(Group, self.options.hello.groups, 1, &.{.x25519})) .x25519 else for (self.options.hello.groups) |group| {
            if (group.classical()) break group;
        } else return .{ .groups = out, .count = 0 };
        out[0] = classical;
        return .{ .groups = out, .count = 1 };
    }
    for ([_]Group{ .x25519_mlkem768, .x25519 }) |group| {
        if (std.mem.containsAtLeast(Group, self.options.hello.groups, 1, &.{group})) {
            out[count] = group;
            count += 1;
        }
    }
    if (count == 0) {
        out[0] = self.options.hello.groups[0];
        count = 1;
    }
    return .{ .groups = out, .count = count };
}

/// A legacy session id: for middleboxes, or to see a TLS 1.2 ticket accepted (RFC 5077 section 3.4).
fn sendsSessionId(self: *const Client) bool {
    return self.options.compat or self.offered12 != null;
}

fn initialEntropy(self: *const Client) usize {
    @setRuntimeSafety(true);
    var len: usize = 32 + @as(usize, if (self.sendsSessionId()) 32 else 0);
    const initial = self.initialGroups();
    for (initial.groups[0..initial.count]) |group| len += Exchange.entropyLength(group.?);
    len += self.echEntropy();
    // A client certificate whose key cloak holds is signed for here, with noise drawn up front.
    // A delegated credential signs instead when the server takes it: noise for either.
    if (self.options.auth) |auth| len += @max(auth.identity.noiseLength() orelse 0, if (self.options.auth_delegated) |delegated| delegated.noiseLength() else 0);
    return len;
}

/// ECH's draw: the outer random, the HPKE key's input and the GREASE seed; GREASE alone needs
/// only the seed.
fn echEntropy(self: *const Client) usize {
    return switch (self.options.ech) {
        .off => 0,
        .grease => 32,
        .config_list => 96,
    };
}

/// Answers an entropy request. `InvalidEntropy` is public (a scalar draw outside its range)
/// and leaves the request open for a fresh draw.
pub fn provideEntropy(self: *Client, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    const expected = switch (self.need()) {
        .entropy => |e| e.len,
        else => return error.UnexpectedService,
    };
    if (entropy.len != expected) return error.InvalidEntropy;
    errdefer self.eraseShares();
    if (self.version == .tls12) return Client12.onEntropy(self, entropy);
    if (self.established) return self.postAnswered(self.post_auth.?.provideEntropy(entropy, self.kept.auth.?));
    if (self.state.phase() == .start) {
        var at: usize = 0;
        self.scratch.?.random = entropy[0..32].*;
        at += 32;
        if (self.sendsSessionId()) {
            self.scratch.?.session = entropy[at..][0..32].*;
            self.scratch.?.session_len = 32;
            at += 32;
        }
        const initial = self.initialGroups();
        for (initial.groups[0..initial.count], 0..) |group, i| {
            const length = Exchange.entropyLength(group.?);
            self.scratch.?.shares[i] = Exchange.Share.init(group.?, entropy[at..][0..length]) catch return error.InvalidEntropy;
            at += length;
        }
        const e = &self.scratch.?.ech;
        switch (self.options.ech) {
            .off => {},
            .grease => {
                e.seed = entropy[at..][0..32].*;
                at += 32;
            },
            .config_list => {
                e.outer_random = entropy[at..][0..32].*;
                e.ikm = entropy[at + 32 ..][0..32].*;
                e.seed = entropy[at + 64 ..][0..32].*;
                at += 96;
            },
        }
        @memcpy(self.scratch.?.sign_noise[0 .. entropy.len - at], entropy[at..]);
        self.need_now = .none;
        try self.sendHello();
    } else {
        // A retry request named a group: one fresh share, the old halves are gone.
        const group = self.retry_group.?;
        self.eraseShares();
        self.scratch.?.shares[0] = Exchange.Share.init(group, entropy) catch return error.InvalidEntropy;
        self.need_now = .none;
        try self.sendCompatCcs();
        try self.sendHello();
    }
}

pub fn eraseShares(self: *Client) void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse return;
    if (scratch.share12) |*share| share.deinit();
    scratch.share12 = null;
    for (&scratch.shares) |*slot| if (slot.*) |*share| {
        share.deinit();
        slot.* = null;
    };
}

/// Erases and frees the handshake-only state.
fn releaseScratch(self: *Client) void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse return;
    self.eraseShares();
    self.releaseEch();
    scratch.flight.deinit(self.gpa);
    scratch.transcripts.release();
    if (scratch.scts.len != 0) self.gpa.free(scratch.scts);
    std.crypto.secureZero(u8, std.mem.asBytes(scratch));
    self.gpa.destroy(scratch);
    self.scratch = null;
    self.options = undefined;
}

fn releaseEch(self: *Client) void {
    @setRuntimeSafety(true);
    const e = &self.scratch.?.ech;
    if (e.context) |*context| context.deinit();
    e.context = null;
    std.crypto.secureZero(u8, &e.ikm);
    for ([_]*[]u8{ &e.ext, &e.retry_list }) |slot| if (slot.len != 0) {
        self.gpa.free(slot.*);
        slot.* = &.{};
    };
}

/// The retry configurations of a rejected ECH attempt, once the public name is authenticated:
/// an ECHConfigList to retry with on a new connection, or empty when the server sent none (ECH
/// is then securely disabled for it). Null for any other outcome (RFC 9849 section 6.1.6).
pub fn echRetryConfigs(self: *const Client) ?[]const u8 {
    return self.ech_retry;
}

/// The config ECH uses: the first usable one of the list, chosen again from the caller's bytes
/// rather than kept (init checked there is one).
fn echConfig(self: *const Client) ?Ech.Config {
    return switch (self.options.ech) {
        .config_list => |list| Ech.choose(list) catch null,
        else => null,
    };
}

fn echRejected(self: *const Client) bool {
    const scratch = self.scratch orelse return false;
    return scratch.ech.status == .rejected;
}

pub fn provideTime(self: *Client, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .time) return error.UnexpectedService;
    self.now = now;
    if (self.state.phase() == .start) {
        // Resumption's clock, before the hello: the session this one may resume, then the draw.
        self.origin = types.seconds(now);
        self.takeTicket();
        self.need_now = .{ .entropy = .{ .len = self.initialEntropy() } };
        return;
    }
    self.need_now = .verify;
}

/// The cache key: SHA-256 over every input a session's authority depended on, each length-prefixed.
fn cacheKey(options: Options, namespace: []const u8) [32]u8 {
    @setRuntimeSafety(true);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    const part = struct {
        fn bytes(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
            var length: [8]u8 = undefined;
            std.mem.writeInt(u64, &length, value.len, .big);
            hash.update(&length);
            hash.update(value);
        }
    }.bytes;
    part(&h, "cloak session cache v1");
    part(&h, namespace);
    part(&h, options.hello.sni);
    part(&h, &.{ @backingInt(options.hello.transport), @intFromBool(options.hello.require_hybrid), @intFromBool(options.hello.require_alpn), @intFromBool(options.hello.require_pq_auth) });
    part(&h, std.mem.asBytes(&options.hello.alpn.len));
    for (options.hello.alpn) |protocol| part(&h, protocol);
    // The reference identity and the whole verification policy, through the request digest of
    // a request with no chain, time or token.
    switch (options.verify) {
        .none => part(&h, "verify none"),
        .raw_key => |raw| {
            part(&h, "verify raw keys");
            for (raw.pins) |*pin| part(&h, pin);
        },
        .full => |full| {
            const request: types.Request = .{
                .chain = &.{},
                .identity = options.identity,
                .purpose = .server,
                .time = .fromNanoseconds(0),
                .trust_generation = full.trust_generation,
                .policy_generation = full.policy_generation,
                .mode = .full,
                .policy = full.policy,
                .pins = full.pins,
                .evidence = full.evidence,
                .limits = full.limits,
                .anchor_policies = full.anchor_policies,
            };
            part(&h, &request.digest());
        },
    }
    // The ECH policy: a session from an ECH handshake resumes only under the same configs.
    switch (options.ech) {
        .config_list => |list| {
            part(&h, "ech");
            part(&h, list);
        },
        else => part(&h, "no ech"),
    }
    // The client certificate a server may have authenticated, by its whole chain.
    if (options.auth) |auth| {
        part(&h, switch (auth.identity.form()) {
            .x509 => "client certificate",
            .raw_public_key => "client raw key",
        });
        for (auth.entries()) |der| part(&h, der);
    } else part(&h, "no client certificate");
    // A session a delegated credential authenticated resumes only where one is taken.
    part(&h, if (options.hello.accept_delegated) "delegated credentials" else "no delegated credentials");
    return h.finalResult();
}

/// Takes the newest usable ticket of each offered version for this connection's key: one the
/// offered suites can resume.
fn takeTicket(self: *Client) void {
    @setRuntimeSafety(true);
    const resumption = self.options.resumption orelse return;
    if (self.options.hello.allows13() and !self.external_offered) if (resumption.cache.take(&self.cache_key, .tls13, self.origin)) |found| {
        var taken = found;
        if (self.options.hello.offers13(taken.entry.suite.tls13().?)) self.offered = taken else taken.release();
    };
    if (self.sendsTickets12()) if (resumption.cache.take(&self.cache_key, .tls12, self.origin)) |found| {
        var taken = found;
        if (self.options.hello.offers12(taken.entry.suite.tls12().?)) self.offered12 = taken else taken.release();
    };
}

/// Whether the hello carries a TLS 1.2 SessionTicket extension.
pub fn sendsTickets12(self: *const Client) bool {
    const resumption = self.options.resumption orelse return false;
    return resumption.tls12 and self.options.hello.allows12();
}

/// Spends the offered tickets, taken or not: none is offered again.
pub fn releaseOffer(self: *Client) void {
    self.releaseOffer13();
    if (self.offered12) |*taken| taken.release();
    self.offered12 = null;
}

pub fn releaseOffer13(self: *Client) void {
    if (self.offered) |*taken| taken.release();
    self.offered = null;
    self.external_offered = false;
}

/// The PSK the hello offers: the taken ticket, or the provisioned key.
const Offer = struct { identity: []const u8, secret: []const u8, binder_len: usize, kind: enum { resumption, external } };

fn pskOffer(self: *const Client) ?Offer {
    @setRuntimeSafety(true);
    if (self.offered) |taken| return .{ .identity = taken.entry.ticket, .secret = taken.entry.secretBytes(), .binder_len = suites.digestLength(taken.entry.suite.tls13().?), .kind = .resumption };
    if (self.external_offered) {
        const psk = self.options.external_psk.?;
        return .{ .identity = psk.identity, .secret = psk.secret, .binder_len = psk.hash.length(), .kind = .external };
    }
    return null;
}

pub fn dropTicket12(self: *Client) void {
    if (self.ticket12.len != 0) {
        std.crypto.secureZero(u8, self.ticket12);
        self.gpa.free(self.ticket12);
    }
    self.ticket12 = &.{};
}

/// The verification request for the pending peer chain; valid while `need` is `.verify`.
pub fn verification(self: *const Client, token: types.Token) types.Request {
    @setRuntimeSafety(true);
    const full = self.options.verify.full;
    // A rejected ECH attempt authenticates the public name, only to trust its retry
    // configurations (RFC 9849 section 6.1.7); the origin's pins are not the public name's.
    const rejected = self.echRejected();
    return .{
        .chain = self.scratch.?.chain[0..self.scratch.?.chain_len],
        .identity = if (rejected) .{ .dns = self.echConfig().?.public_name } else self.options.identity,
        .purpose = .server,
        .time = self.now.?,
        .trust_generation = full.trust_generation,
        .policy_generation = full.policy_generation,
        .token = token,
        .mode = .full,
        .policy = full.policy,
        .pins = if (rejected) &.{} else full.pins,
        .evidence = self.evidence(full.evidence),
        .limits = full.limits,
        .anchor_policies = full.anchor_policies,
    };
}

/// The caller's evidence, and the SCTs the server sent after its lists.
fn evidence(self: *const Client, caller: types.Evidence) types.Evidence {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (scratch.scts.len == 0) return caller;
    // `init` left room for one more list.
    const n = caller.scts.len;
    @memcpy(scratch.sct_lists[0..n], caller.scts);
    scratch.sct_lists[n] = scratch.scts;
    return .{ .crls = caller.crls, .ocsp = caller.ocsp, .scts = scratch.sct_lists[0 .. n + 1] };
}

/// Keeps the server's SignedCertificateTimestampList for the verification request.
pub fn keepScts(self: *Client, list: ?[]const u8) Error!void {
    @setRuntimeSafety(true);
    const bytes = list orelse return;
    const scratch = self.scratch.?;
    if (scratch.scts.len != 0) self.gpa.free(scratch.scts);
    scratch.scts = &.{};
    scratch.scts = try self.gpa.dupe(u8, bytes);
}

/// Accepts the receipt for exactly the pending request. Any mismatch is terminal.
pub fn provideVerification(self: *Client, token: types.Token, receipt: *const types.Verification) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .verify) return error.UnexpectedService;
    receipt.check(self.verification(token)) catch return error.VerificationRejected;
    if (self.options.hello.require_pq_auth and !Possession.postQuantumPath(receipt.path)) return error.PqAuthenticationRequired;
    // A delegated credential is checked against the certificate just verified (RFC 9345 section
    // 4.1.3); its key then proves possession.
    if (self.scratch.?.delegated) |bytes| {
        const view = Delegation.parse(bytes) catch return error.IllegalParameter;
        const hello = self.options.hello;
        self.scratch.?.delegated_key = try Delegation.check(self.gpa, view, self.scratch.?.chain[0], .server, types.seconds(self.now.?), Hello.verifySchemes(hello), Delegation.offered(hello.require_pq_auth));
    }
    try self.state.advance(.verify_chain, self.verifyEpoch(), .chain, true);
    self.authenticated = true;
    // A session resumed from this one is authenticated no longer than this verdict holds, nor
    // than the delegated credential that proved it.
    self.auth_expires = types.seconds(receipt.expires);
    if (receipt.revocation_expires) |until| self.auth_expires = @min(self.auth_expires, types.seconds(until));
    if (self.scratch.?.delegated_key) |checked| self.auth_expires = @min(self.auth_expires, checked.expires);
    self.need_now = .none;
}

/// The epoch a chain verification completes in: TLS 1.2 verifies before any key exists.
pub fn verifyEpoch(self: *const Client) Epoch {
    return if (self.version == .tls12) .initial else .handshake;
}

/// The peer chain failed verification (or its service did); the handshake ends.
pub fn rejectVerification(self: *Client) void {
    @setRuntimeSafety(true);
    self.state.fail();
    self.need_now = .none;
}

pub fn signRequest(self: *const Client) SignRequest {
    @setRuntimeSafety(true);
    if (self.established) return self.post_auth.?.signRequest();
    // Ed25519 in TLS 1.2 signs the handshake messages, not their digest.
    if (self.version == .tls12 and self.sign_scheme == .ed25519) return .{ .scheme = .ed25519, .content = self.scratch.?.transcripts.keptBytes() };
    return .{ .scheme = self.sign_scheme, .content = self.scratch.?.sign_content[0..self.scratch.?.sign_content_len], .prehashed = self.version == .tls12 };
}

/// Checks the signature against the identity's public key before using it.
pub fn provideSignature(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (self.need() != .sign) return error.UnexpectedService;
    if (self.established) return self.postAnswered(self.post_auth.?.provideSignature(signature, self.kept.auth.?));
    if (self.version == .tls12) return Client12.onSignature(self, signature);
    const auth = self.options.auth.?;
    Possession.verifyKey(@backingInt(self.sign_scheme), &.{self.sign_scheme}, auth.identity.publicKey(), self.signRequest().content, signature) catch return error.BadSignature;
    self.need_now = .none;
    try self.sendCertificateVerify(signature);
}

fn sendCertificateVerify(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const dst = try self.reserve(Messages.max_signed + signature.len + 16);
    const built = try Messages.buildCertificateVerify(dst, @backingInt(self.sign_scheme), signature);
    try self.state.advance(.local_certificate_verify, .handshake, .possession, true);
    try self.queueMessage(.handshake, built);
    try self.finishFlight();
}

pub fn provideParameters(self: *Client, accept: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .parameters) return error.UnexpectedService;
    if (!accept) return error.ParametersRejected;
    self.need_now = .none;
}

// ---------------------------------------------------------------- outputs

/// Moves the next output into `out`; see `Flight.pop`.
pub fn pop(self: *Client, out: *Emit) bool {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        const post = &(self.post orelse return false);
        out.* = post.*;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.post));
        self.post = null;
        return true;
    };
    return scratch.flight.pop(out);
}

pub fn pending(self: *const Client) bool {
    const scratch = self.scratch orelse return self.post != null;
    return scratch.flight.pending();
}

/// Bytes of a queued message; valid until `recycle` or the next input.
pub fn flightBytes(self: *const Client, start: u32, len: u32) []const u8 {
    return self.scratch.?.flight.bytes(start, len);
}

/// Releases the flight buffer for reuse once every message emitted so far was read.
pub fn recycle(self: *Client) void {
    if (self.scratch) |scratch| scratch.flight.recycle();
}

pub fn push(self: *Client, emit: Emit) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        if (self.post != null) return error.QueueFull;
        self.post = emit;
        return;
    };
    try scratch.flight.push(emit);
}

pub fn reserve(self: *Client, want: usize) Error![]u8 {
    return self.scratch.?.flight.reserve(self.gpa, want, self.options.limits.handshake);
}

/// `message` was built at the end of the flight buffer: commit it to the transcript and queue it.
pub fn queueMessage(self: *Client, epoch: Epoch, wire: []const u8) Error!void {
    @setRuntimeSafety(true);
    try self.scratch.?.transcripts.commitOwn(wire);
    try self.scratch.?.flight.queueMessage(epoch, wire.len);
}

fn sendCompatCcs(self: *Client) Error!void {
    @setRuntimeSafety(true);
    if (!self.options.compat or self.ccs_sent) return;
    self.ccs_sent = true;
    try self.push(.compat_ccs);
}

/// An upper bound on the encoded ClientHello: its fixed fields and extensions, plus every
/// variable part.
fn helloCapacity(self: *const Client, shares: []const Hello.Share) usize {
    @setRuntimeSafety(true);
    var n: usize = 256 + self.options.hello.sni.len + self.options.hello.parameters.len + self.scratch.?.cookie_len;
    if (self.pskOffer()) |offer| n += 64 + offer.identity.len;
    if (self.offered12) |taken| n += 8 + taken.entry.ticket.len;
    for (self.options.hello.alpn) |protocol| n += 1 + protocol.len;
    for (shares) |share| n += 4 + share.bytes.len;
    return n;
}

fn sendHello(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    switch (scratch.ech.status) {
        .none, .accepted_retry, .offered => if (self.options.ech == .config_list) return self.sendEchHello(),
        .rejected => return self.sendOuterHello(),
        .accepted => unreachable, // unreachable: acceptance is decided by the ServerHello, after the last hello
    }
    var offered: [2]Hello.Share = undefined;
    const shares = self.offeredShares(&offered);
    const resumption = self.resumeOffer();
    var form: Hello.Form = .plain;
    if (self.options.ech == .grease) {
        if (scratch.ech.ext.len == 0) try self.makeGrease(shares, resumption);
        form = .{ .grease = scratch.ech.ext };
    }
    const dst = try self.reserve(self.helloCapacity(shares) + scratch.ech.ext.len);
    const hello = try Hello.clientForm(dst, &scratch.random, scratch.session[0..scratch.session_len], scratch.legacy_cookie[0..scratch.legacy_cookie_len], shares, scratch.cookie[0..scratch.cookie_len], self.options.hello, resumption, form);
    if (self.pskOffer()) |offer| self.writeBinder(&scratch.transcripts, offer, hello, resumption.binder_len);
    try self.state.advance(.client_hello, .initial, .parsed, true);
    try self.queueMessage(.initial, hello);
}

/// What the hello says of resumption: PSK-DHE when there is a cache, and the ticket taken for it
/// with its obfuscated age (its binder is filled after encoding).
fn resumeOffer(self: *const Client) Hello.Resume {
    @setRuntimeSafety(true);
    var resumption: Hello.Resume = .{ .modes = self.options.resumption != null };
    if (self.sendsTickets12()) resumption.ticket12 = if (self.offered12) |taken| taken.entry.ticket else "";
    if (self.external_offered) {
        // A provisioned key has no age: its obfuscated_ticket_age is zero (RFC 8446 4.2.11).
        const psk = self.options.external_psk.?;
        resumption.ticket = psk.identity;
        resumption.binder_len = psk.hash.length();
    }
    if (self.offered) |taken| {
        const entry = taken.entry;
        // The obfuscated age: milliseconds since the ticket arrived, plus its obfuscator.
        const now_ms = @divFloor(self.now.?.nanoseconds, std.time.ns_per_ms);
        const age: u64 = @intCast(std.math.clamp(now_ms - entry.received_ms, 0, std.math.maxInt(u32))); // safe: clamped to u32
        resumption.ticket = entry.ticket;
        resumption.age = @truncate(age +% entry.age_add);
        resumption.binder_len = suites.digestLength(entry.suite.tls13().?);
    }
    return resumption;
}

/// The binder covers the transcript so far and this hello up to its binders.
fn writeBinder(self: *const Client, transcripts: *const Transcripts, offer: Offer, hello: []u8, n: usize) void {
    @setRuntimeSafety(true);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const truncated = transcripts.digestWith(&digest_buf, n, hello[0 .. hello.len - (2 + 1 + n)]);
    // The binder's schedule is the PSK's hash; any suite of that hash derives the same.
    const kind: Schedule.BinderKind = if (offer.kind == .external) .external else .resumption;
    switch (@as(Suite13, if (n == 48) .aes_256_gcm_sha384 else .aes_128_gcm_sha256)) {
        inline else => |tag| {
            const K = Schedule.Schedule(tag);
            K.binderOf(self.options.hello.transport.prefix(), kind, offer.secret[0..K.length], truncated[0..K.length], hello[hello.len - K.length ..][0..K.length]);
        },
    }
}

/// A GREASE encrypted_client_hello (RFC 9849 section 6.2.1): a random config id, a supported
/// suite, a valid X25519 key and a random payload as long as this hello's encrypted inner form
/// would be. Kept, so a second hello repeats it.
fn makeGrease(self: *Client, shares: []const Hello.Share, resumption: Hello.Resume) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var drbg = std.Random.ChaCha.init(scratch.ech.seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&drbg));
    var draw: [34]u8 = undefined;
    drbg.fill(&draw);
    var key = Hpke.deriveKeyPair(draw[2..34]);
    defer key.deinit();
    // The length the inner hello would have, encoded and padded with no name bound.
    var options = self.options.hello;
    options.min_version = .tls13;
    const buf = try self.gpa.alloc(u8, self.helloCapacity(shares));
    defer self.gpa.free(buf);
    const encoded = try Hello.clientForm(buf, &scratch.random, "", "", shares, "", options, resumption, .encoded);
    const payload_len = Ech.paddedLength(encoded.len - 4, options.sni.len, 0) + Hpke.tag_length;
    const suite: Hpke.Suite = .{ .kdf = .hkdf_sha256, .aead = if (draw[1] & 1 == 0) .aes_128_gcm else .chacha20_poly1305 };
    const ext = try self.gpa.alloc(u8, 8 + Hpke.enc_length + 2 + payload_len);
    errdefer self.gpa.free(ext);
    const written = try Ech.writeOuter(ext, suite, draw[0], &key.public, payload_len);
    drbg.fill(written[written.len - payload_len ..]);
    scratch.ech.ext = ext[0..written.len];
}

/// Random bytes in the shape of the inner hello's PSK offer, for the outer hello (RFC 9849
/// section 6.1.2), the same each time from the GREASE seed.
fn greasePsk(self: *const Client, storage: []u8, binder_len: usize) ?Hello.GreasePsk {
    @setRuntimeSafety(true);
    const offer = self.pskOffer() orelse return null;
    const identity_len = offer.identity.len;
    var drbg = std.Random.ChaCha.init(self.scratch.?.ech.seed);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&drbg));
    var skip: [34]u8 = undefined;
    drbg.fill(&skip);
    drbg.fill(storage[0 .. identity_len + 4 + binder_len]);
    return .{
        .identity = storage[0..identity_len],
        .age = std.mem.readInt(u32, storage[identity_len..][0..4], .big),
        .binder = storage[identity_len + 4 ..][0..binder_len],
    };
}

/// ClientHelloOuter carrying the encrypted ClientHelloInner (RFC 9849 section 6.1). The first
/// hello sets up the HPKE context; the second, after a retry request that accepted ECH, seals
/// under the same context with an empty enc. The inner hello joins the inner transcript, the
/// outer one the transcript of the wire.
fn sendEchHello(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const e = &scratch.ech;
    const config = self.echConfig().?;
    var offered: [2]Hello.Share = undefined;
    const shares = self.offeredShares(&offered);
    const session = scratch.session[0..scratch.session_len];
    const cookie = scratch.cookie[0..scratch.cookie_len];
    const resumption = self.resumeOffer();
    const capacity = self.helloCapacity(shares) + 64;
    const inner_buf = try self.gpa.alloc(u8, capacity);
    defer {
        std.crypto.secureZero(u8, inner_buf);
        self.gpa.free(inner_buf);
    }
    const inner = try Hello.clientForm(inner_buf, &scratch.random, session, "", shares, cookie, self.options.hello, resumption, .inner);
    if (self.pskOffer()) |offer| self.writeBinder(&e.inner, offer, inner, resumption.binder_len);
    try e.inner.commitOwn(inner);
    // The encoded inner hello, padded (RFC 9849 section 6.1.3): its binder is the inner one's.
    const encoded_buf = try self.gpa.alloc(u8, capacity + 255 + 9 + 32);
    defer {
        std.crypto.secureZero(u8, encoded_buf);
        self.gpa.free(encoded_buf);
    }
    const encoded = try Hello.clientForm(encoded_buf, &scratch.random, session, "", shares, cookie, self.options.hello, resumption, .encoded);
    if (self.pskOffer() != null) @memcpy(encoded[encoded.len - resumption.binder_len ..], inner[inner.len - resumption.binder_len ..]);
    const padded = Ech.paddedLength(encoded.len - 4, self.options.hello.sni.len, config.max_name_length);
    @memset(encoded_buf[encoded.len .. 4 + padded], 0);
    const plaintext = encoded_buf[4 .. 4 + padded];
    const payload_len = padded + Hpke.tag_length;
    const suite = config.suite().?;
    const first = e.context == null;
    if (first) {
        const info_buf = try self.gpa.alloc(u8, 8 + config.raw.len);
        defer self.gpa.free(info_buf);
        e.context = Hpke.setupSender(suite, config.public_key[0..Hpke.public_length], Ech.info(info_buf, config.raw), &e.ikm, &e.enc) catch return error.InvalidOptions;
        std.crypto.secureZero(u8, &e.ikm);
        e.status = .offered;
    }
    const ext_buf = try self.gpa.alloc(u8, 8 + Hpke.enc_length + 2 + payload_len);
    defer self.gpa.free(ext_buf);
    const ext = try Ech.writeOuter(ext_buf, suite, config.id, if (first) &e.enc else "", payload_len);
    const psk_buf = try self.gpa.alloc(u8, if (self.pskOffer()) |offer| offer.identity.len + 4 + resumption.binder_len else 0);
    defer self.gpa.free(psk_buf);
    const grease = self.greasePsk(psk_buf, resumption.binder_len);
    const dst = try self.reserve(capacity + ext.len + config.public_name.len + psk_buf.len + 64);
    const outer = try Hello.clientForm(dst, &e.outer_random, session, "", shares, cookie, self.options.hello, resumption, .{ .outer = .{ .name = config.public_name, .ext = ext, .psk = grease } });
    // Seal with the outer hello, payload zeroed, as the associated data (RFC 9849 section 5.2).
    const span = Ech.extensionSpan(outer) orelse unreachable; // unreachable: the outer form writes it
    const sealed = try self.gpa.alloc(u8, payload_len);
    defer self.gpa.free(sealed);
    e.context.?.seal(sealed, outer[4..], plaintext) catch return error.InvalidOptions;
    @memcpy(outer[span.start + span.len - payload_len ..][0..payload_len], sealed);
    if (first) e.ext = try self.gpa.dupe(u8, outer[span.start..][0..span.len]);
    try self.state.advance(.client_hello, .initial, .parsed, true);
    try self.queueMessage(.initial, outer);
}

/// The second hello after a retry request that did not accept ECH: the outer hello alone, its
/// encrypted_client_hello the first one's (RFC 9849 section 6.1.6). The inner hello is gone, and
/// so is its PSK.
fn sendOuterHello(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const config = self.echConfig().?;
    var offered: [2]Hello.Share = undefined;
    const shares = self.offeredShares(&offered);
    const resumption: Hello.Resume = .{ .modes = self.options.resumption != null };
    const dst = try self.reserve(self.helloCapacity(shares) + scratch.ech.ext.len + config.public_name.len + 64);
    const outer = try Hello.clientForm(dst, &scratch.ech.outer_random, scratch.session[0..scratch.session_len], "", shares, scratch.cookie[0..scratch.cookie_len], self.options.hello, resumption, .{ .outer = .{ .name = config.public_name, .ext = scratch.ech.ext, .psk = null } });
    try self.state.advance(.client_hello, .initial, .parsed, true);
    try self.queueMessage(.initial, outer);
}

// ---------------------------------------------------------------- inputs

/// Consumes one complete handshake message. `boundary` says the message ended exactly at the
/// end of its record, which key-changing messages require.
pub fn receive(self: *Client, bytes_in: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() == .failed) return error.Closed;
    if (self.need() != .none) return error.Pending;
    errdefer self.state.fail();
    if (bytes_in.len > self.kept.message_limit) return error.HandshakeLimit;
    if (!self.established) {
        const total = (aegis.int.Checked(usize).init(self.total_bytes).add(bytes_in.len) catch return error.HandshakeLimit).raw();
        if (total > self.options.limits.handshake) return error.HandshakeLimit;
        self.total_bytes = total;
    }
    const parsed = try Messages.body(bytes_in);
    if (self.version == .tls12) return Client12.receive(self, parsed.kind, bytes_in, epoch, boundary);
    switch (parsed.kind) {
        .server_hello => try self.onServerHello(bytes_in, epoch, boundary),
        .hello_verify_request => try self.onHelloVerify(bytes_in, epoch, boundary),
        .encrypted_extensions => try self.onEncrypted(bytes_in, epoch, boundary),
        .certificate_request => if (self.established) try self.onPostRequest(bytes_in, epoch) else try self.onCertificateRequest(bytes_in, epoch, boundary),
        .certificate => try self.onCertificate(bytes_in, epoch, boundary),
        .compressed_certificate => try self.onCompressedCertificate(bytes_in, epoch, boundary),
        .certificate_verify => try self.onCertificateVerify(bytes_in, epoch, boundary),
        .finished => try self.onFinished(bytes_in, epoch, boundary),
        .new_session_ticket => try self.onTicket(bytes_in, epoch, boundary),
        .key_update => try self.onKeyUpdate(bytes_in, epoch, boundary),
        else => return error.UnexpectedMessage,
    }
}

fn offeredShares(self: *const Client, out: *[2]Hello.Share) []const Hello.Share {
    @setRuntimeSafety(true);
    var count: usize = 0;
    for (&self.scratch.?.shares) |*slot| if (slot.*) |*share| {
        out[count] = .{ .group = share.group, .bytes = share.wire() };
        count += 1;
    };
    return out[0..count];
}

fn onServerHello(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    var offered: [2]Hello.Share = undefined;
    const ech_sent = self.options.ech == .config_list or self.scratch.?.ech.ext.len != 0;
    const answer = try Hello.server(msg, self.scratch.?.session[0..self.scratch.?.session_len], self.offeredShares(&offered), self.options.hello, .{ .psk = self.pskOffer() != null, .ticket12 = self.sendsTickets12() and self.retry_suite == null, .session12 = self.offered12 != null and self.retry_suite == null, .ech = ech_sent });
    const parsed = switch (answer) {
        // A DTLS 1.3 server never asks for a HelloVerifyRequest's cookie (RFC 9147 section 5.2).
        .tls13 => |hello| if (self.state.verified != 0) return error.IllegalParameter else hello,
        .tls12 => |hello| {
            // TLS 1.2 after a retry request is a version change mid-handshake.
            if (self.retry_suite != null) return error.IllegalParameter;
            self.releaseOffer13();
            return Client12.onServerHello(self, msg, hello, epoch, boundary);
        },
    };
    if (parsed.retry) return self.onRetry(msg, parsed, epoch, boundary);
    try self.state.advance(.server_hello, epoch, .parsed, boundary);
    self.noteConnectionId(parsed.connection_id);
    if (self.options.ech == .config_list and self.scratch.?.ech.status != .rejected) try self.decideEch(msg, parsed);
    if (self.retry_suite) |suite| if (suite != parsed.suite) return error.IllegalParameter;
    // A ticket not taken is spent all the same: it is never offered again.
    defer self.releaseOffer();
    var psk: ?[]const u8 = null;
    if (parsed.psk) {
        const offer = self.pskOffer().?;
        // The PSK's hash must be the suite's (RFC 8446 section 4.2.11).
        if (offer.binder_len != suites.digestLength(parsed.suite)) return error.IllegalParameter;
        try self.state.markResumed();
        psk = offer.secret;
        switch (offer.kind) {
            .resumption => {
                const entry = self.offered.?.entry;
                self.resumed = true;
                self.authenticated = entry.authenticated;
                self.origin = entry.origin;
                self.auth_expires = entry.auth_expires;
                self.raw_pin = entry.raw_key_pin;
            },
            // The holder of the provisioned key is the peer: authenticated by it, with no X.509
            // identity and nothing to expire but the key itself, which is the caller's.
            .external => {
                self.external_used = true;
                self.authenticated = true;
            },
        }
    }
    const group = parsed.group.?;
    const share = for (&self.scratch.?.shares) |*slot| {
        if (slot.*) |*candidate| if (candidate.group == group) break candidate;
    } else return error.InvalidHello;
    var agreed = try share.agree(parsed.share);
    defer agreed.deinit();
    self.scratch.?.transcripts.select(parsed.suite);
    try self.scratch.?.transcripts.commit(msg);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const hello_hash = self.scratch.?.transcripts.digest(&digest_buf);
    self.suite = parsed.suite;
    self.group = group;
    switch (parsed.suite) {
        inline else => |suite| {
            const Hash = suites.Hash(suite);
            const K = Schedule.Schedule(suite);
            var traffic: K.Traffic = .{};
            errdefer traffic.deinit();
            const key: ?*const [K.length]u8 = if (psk) |secret| secret[0..K.length] else null;
            var schedule = try K.init(self.options.hello.transport.prefix(), key, agreed.bytes(), hello_hash[0..Hash.digest_length], &traffic);
            errdefer schedule.deinit();
            self.keys = @unionInit(Keys, @tagName(suite), .{ .schedule = schedule, .handshake = traffic });
        },
    }
    self.eraseShares();
    try self.emitHandshakeSecrets();
}

/// Whether the ServerHello accepted ECH: the last eight bytes of its random confirm the inner
/// transcript (RFC 9849 section 6.1.4). Accepted, the inner transcript becomes the transcript;
/// rejected, the handshake goes on with the outer hello to authenticate the public name, never
/// resuming (the outer offer was GREASE) and never reaching the application.
fn decideEch(self: *Client, msg: []const u8, parsed: Hello.ServerHello) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const e = &scratch.ech;
    e.inner.select(parsed.suite);
    const zeroed = try self.gpa.dupe(u8, msg);
    defer self.gpa.free(zeroed);
    @memset(zeroed[4 + 2 + 24 ..][0..8], 0);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const accepted = switch (parsed.suite) {
        inline else => |tag| blk: {
            const Hash = suites.Hash(tag);
            const digest = e.inner.digestWith(&digest_buf, Hash.digest_length, zeroed);
            const expected = Ech.confirmation(Hash, &scratch.random, Ech.accept_label, digest[0..Hash.digest_length]);
            break :blk aegis.secret.equal(8, &expected, msg[4 + 2 + 24 ..][0..8]).declassify("ECH acceptance shows in the keys that follow");
        },
    };
    if (e.context) |*context| context.deinit();
    e.context = null;
    if (accepted) {
        e.status = .accepted;
        scratch.transcripts.release();
        std.crypto.secureZero(u8, std.mem.asBytes(&scratch.transcripts));
        scratch.transcripts = e.inner;
        e.inner = .{};
        self.ech_accepted = true;
        return;
    }
    // A retry request that accepted ECH binds the ServerHello to accept it too.
    if (e.status == .accepted_retry) return error.IllegalParameter;
    e.status = .rejected;
    // The handshake is the outer hello's now, and so is the random a key log names.
    scratch.random = e.outer_random;
    // The outer hello offered only a GREASE PSK: a server that selects it is lying.
    if (parsed.psk) return error.IllegalParameter;
    self.releaseOffer13();
}

fn emitHandshakeSecrets(self: *Client) Error!void {
    @setRuntimeSafety(true);
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const len = suites.Hash(tag).digest_length;
            try self.install(.read, .handshake, tag, len, k.handshake.server.expose(), "SERVER_HANDSHAKE_TRAFFIC_SECRET");
            try self.install(.write, .handshake, tag, len, k.handshake.client.expose(), "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        },
    }
}

fn install(self: *Client, direction: Direction, epoch: Epoch, suite: Suite13, len: usize, secret: []const u8, label: []const u8) Error!void {
    @setRuntimeSafety(true);
    var made = self.makeTraffic(suite, len, secret, label);
    errdefer made.secret.deinit();
    try self.push(.{ .secret = .{ .direction = direction, .epoch = epoch, .traffic = made } });
}

fn makeTraffic(self: *const Client, suite: Suite13, len: usize, secret: []const u8, label: []const u8) Traffic {
    @setRuntimeSafety(true);
    var holder = aegis.Secret([Transcripts.max_digest]u8).init(@splat(0));
    @memcpy(holder.exposeMut()[0..len], secret[0..len]);
    self.keyLog(label, secret[0..len]);
    // safe: the secret length is a digest length, at most 48.
    return .{ .suite = suite, .secret = holder, .len = @intCast(len) };
}

pub fn keyLog(self: *const Client, label: []const u8, secret: []const u8) void {
    @setRuntimeSafety(true);
    const sink = self.options.key_log orelse return;
    var line: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &line);
    const hex = "0123456789abcdef";
    var at: usize = 0;
    @memcpy(line[at..][0..label.len], label);
    at += label.len;
    line[at] = ' ';
    at += 1;
    for (self.scratch.?.random) |b| {
        line[at] = hex[b >> 4];
        line[at + 1] = hex[b & 15];
        at += 2;
    }
    line[at] = ' ';
    at += 1;
    for (secret) |b| {
        line[at] = hex[b >> 4];
        line[at + 1] = hex[b & 15];
        at += 2;
    }
    line[at] = '\n';
    sink.write(sink.context, line[0 .. at + 1]);
}

/// A DTLS 1.2 server asks the hello again with its cookie (RFC 6347 section 4.2.1): the same
/// hello, its cookie field filled, with the next message_seq; neither hello nor request enters
/// the transcript.
fn onHelloVerify(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.hello_verify, epoch, .parsed, boundary);
    const cookie = try Hello.helloVerify(msg);
    const scratch = self.scratch.?;
    @memcpy(scratch.legacy_cookie[0..cookie.len], cookie);
    // safe: the parser bounds the cookie at 255 bytes.
    scratch.legacy_cookie_len = @intCast(cookie.len);
    scratch.transcripts.restart();
    try self.sendHello();
}

fn onRetry(self: *Client, msg: []const u8, parsed: Hello.ServerHello, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.hello_retry, epoch, .parsed, boundary);
    if (self.options.ech == .config_list) try self.retryEch(msg, parsed);
    self.scratch.?.transcripts.select(parsed.suite);
    try self.scratch.?.transcripts.retry(msg);
    self.retry_suite = parsed.suite;
    // A ticket of another hash cannot follow the server's suite into the second hello.
    // (A TLS 1.2 ticket stays in it, unchanged as a second hello must be, though no longer usable.)
    if (self.pskOffer()) |offer| if (offer.binder_len != suites.digestLength(parsed.suite)) self.releaseOffer13();
    @memcpy(self.scratch.?.cookie[0..parsed.cookie.len], parsed.cookie);
    // safe: Hello.server bounds the cookie at 4096 bytes.
    self.scratch.?.cookie_len = @intCast(parsed.cookie.len);
    if (parsed.group) |group| {
        self.retry_group = group;
        self.need_now = .{ .entropy = .{ .len = Exchange.entropyLength(group) } };
        return;
    }
    try self.sendCompatCcs();
    try self.sendHello();
}

/// A retry request accepts ECH when its encrypted_client_hello confirms the inner transcript with
/// that payload zeroed (RFC 9849 section 6.1.4); otherwise the second hello is the outer one alone.
fn retryEch(self: *Client, msg: []const u8, parsed: Hello.ServerHello) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const e = &scratch.ech;
    e.inner.select(parsed.suite);
    var accepted = false;
    if (parsed.ech) |got| {
        const zeroed = try self.gpa.dupe(u8, msg);
        defer self.gpa.free(zeroed);
        const at = @intFromPtr(got) - @intFromPtr(msg.ptr); // safe: the confirmation is a slice of `msg`
        @memset(zeroed[at..][0..8], 0);
        var confirm = e.inner;
        try confirm.retry(zeroed);
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        switch (parsed.suite) {
            inline else => |tag| {
                const Hash = suites.Hash(tag);
                const digest = confirm.digest(&digest_buf);
                const expected = Ech.confirmation(Hash, &scratch.random, Ech.retry_accept_label, digest[0..Hash.digest_length]);
                accepted = aegis.secret.equal(8, &expected, got).declassify("ECH acceptance shows in the keys that follow");
            },
        }
        std.crypto.secureZero(u8, std.mem.asBytes(&confirm));
    }
    if (accepted) {
        e.status = .accepted_retry;
        try e.inner.retry(msg);
        return;
    }
    e.status = .rejected;
    scratch.random = e.outer_random;
    if (e.context) |*context| context.deinit();
    e.context = null;
    self.releaseOffer13();
}

/// DTLS: the server's answer to connection_id, for the carrier's records.
pub fn noteConnectionId(self: *Client, answer: ?[]const u8) void {
    const scratch = self.scratch.?;
    const cid = answer orelse {
        scratch.cid_agreed = false;
        return;
    };
    @memcpy(scratch.peer_cid[0..cid.len], cid);
    scratch.peer_cid_len = @intCast(cid.len); // safe: a vector<0..255>
    scratch.cid_agreed = true;
}

fn onEncrypted(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.encrypted_extensions, epoch, .parsed, boundary);
    const e = &self.scratch.?.ech;
    const parsed = try Hello.encrypted(msg, self.options.hello, self.options.ech == .config_list or e.ext.len != 0);
    if (parsed.ech) |list| switch (e.status) {
        // Retry configurations answer only a hello whose ECH the server did not use.
        .accepted => return error.UnsolicitedExtension,
        .rejected => e.retry_list = try self.gpa.dupe(u8, list),
        // GREASE: checked for syntax, never kept (RFC 9849 section 6.2.1).
        else => {},
    };
    try self.scratch.?.transcripts.commit(msg);
    for (self.options.hello.alpn) |offered| if (std.mem.eql(u8, offered, parsed.alpn)) {
        self.alpn = offered;
    };
    self.srtp = parsed.srtp;
    // RFC 7250: a client that asked for the raw key alone takes no certificate (a server that
    // does not answer the extension means X.509); the types answered say what each side sends.
    // A PSK handshake has no Certificate, and so no type to answer.
    const psk = self.resumed or self.external_used;
    if (self.options.hello.raw_server_key and !parsed.raw_server_key and !psk) return error.UnsupportedCertificate;
    self.scratch.?.peer_raw = parsed.raw_server_key;
    self.scratch.?.client_raw = parsed.raw_client_key;
    if (self.options.hello.transport == .quic) {
        if (parsed.parameters.len > 64 * 1024) return error.HandshakeLimit;
        self.peer_parameters = try self.gpa.dupe(u8, parsed.parameters);
        self.need_now = .parameters;
    }
}

fn onCertificateRequest(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.certificate_request, epoch, .parsed, boundary);
    const parsed = try Messages.certificateRequest(msg);
    if (parsed.context.len != 0) return error.IllegalParameter;
    try self.scratch.?.transcripts.commit(msg);
    self.requested_certificate = true;
    const keep = @min(parsed.schemes.len, self.scratch.?.cr_schemes.len) & ~@as(usize, 1);
    @memcpy(self.scratch.?.cr_schemes[0..keep], parsed.schemes[0..keep]);
    // safe: at most 1024 bytes are kept.
    self.scratch.?.cr_len = @intCast(keep);
    if (parsed.delegated) |list| {
        const kept = @min(list.len, self.scratch.?.cr_delegated.len) & ~@as(usize, 1);
        @memcpy(self.scratch.?.cr_delegated[0..kept], list[0..kept]);
        // safe: at most 1024 bytes are kept.
        self.scratch.?.cr_delegated_len = @intCast(kept);
    }
}

fn onCertificate(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    // The chain outlives this call: a verification request borrows it until answered.
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = try self.gpa.dupe(u8, msg);
    return self.takeCertificate(msg);
}

/// A CompressedCertificate in place of the Certificate (RFC 8879 section 4): an algorithm this
/// client offered, a declared length within the message limit, and a codec that yields exactly
/// that length. The chain is read from the decompressed message; the transcript takes the
/// compressed one, as it crossed the wire.
fn onCompressedCertificate(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.options.hello.certificate_compression.len == 0) return error.UnexpectedMessage;
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    const compressed = Compression.parse(msg) catch |err| return switch (err) {
        error.DecodeError => error.DecodeError,
        else => error.IllegalParameter,
    };
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = Compression.decompress(self.gpa, self.options.hello.certificate_compression, compressed, self.options.limits.message) catch |err| return switch (err) {
        error.IllegalParameter => error.IllegalParameter,
        error.HandshakeLimit => error.HandshakeLimit,
        error.OutOfMemory => error.OutOfMemory,
        error.BadCertificate, error.DecodeError => error.InvalidCertificate,
    };
    return self.takeCertificate(msg);
}

/// The chain of the Certificate message in `held`, with `wire` (what was received) committed.
fn takeCertificate(self: *Client, wire: []const u8) Error!void {
    @setRuntimeSafety(true);
    const msg = wire;
    const limits = self.options.limits;
    const parsed = try Messages.certificate(self.held, limits.certificates, limits.chain_bytes, &self.scratch.?.chain, .{ .delegated = self.options.hello.accept_delegated, .scts = self.options.hello.request_scts });
    if (parsed.context.len != 0) return error.IllegalParameter;
    if (parsed.count == 0) return error.EmptyCertificate;
    self.scratch.?.chain_len = parsed.count;
    self.scratch.?.delegated = parsed.leaf.delegated;
    try self.keepScts(parsed.leaf.scts);
    if (self.scratch.?.peer_raw) {
        // One entry, a SubjectPublicKeyInfo the policy pins (RFC 7250 section 3).
        self.raw_pin = try Possession.pinnedKey(self.scratch.?.chain[0..parsed.count], self.options.verify.raw_key.pins);
        try self.scratch.?.transcripts.commit(msg);
        try self.state.advance(.verify_chain, .handshake, .chain, true);
        self.authenticated = true;
        return;
    }
    try self.scratch.?.transcripts.commit(msg);
    switch (self.options.verify) {
        .none => try self.state.advance(.verify_chain, .handshake, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
        // unreachable: EncryptedExtensions refused a server that did not select the raw key.
        .raw_key => unreachable,
    }
}

fn onCertificateVerify(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .possession) return error.UnexpectedMessage;
    const parsed = try Messages.certificateVerify(msg);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    var content_buf: [Messages.max_signed]u8 = undefined;
    const content = Messages.signedContent(&content_buf, true, self.scratch.?.transcripts.digest(&digest_buf));
    if (self.scratch.?.delegated_key) |checked| {
        // The credential's key signs, under the one scheme the credential names (RFC 9345
        // section 4.1.3): any other is unoffered.
        try Possession.verifyKey(parsed.scheme, &.{checked.scheme}, checked.key, content, parsed.signature);
        self.delegated_used = true;
    } else try Possession.verifyKey(parsed.scheme, Hello.verifySchemes(self.options.hello), try Possession.peerKey(self.scratch.?.chain[0], self.scratch.?.peer_raw), content, parsed.signature);
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try self.scratch.?.transcripts.commit(msg);
}

fn onFinished(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .finished) return error.UnexpectedMessage;
    var before_buf: [Transcripts.max_digest]u8 = undefined;
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const Hash = suites.Hash(tag);
            const received = try Messages.finished(msg, Hash.digest_length);
            const before = self.scratch.?.transcripts.digest(&before_buf);
            try Labels.checkFinished(Hash, k.schedule.prefix, k.handshake.server.expose(), before[0..Hash.digest_length], received);
            if (self.echRejected()) return self.endRejected();
            try self.state.advance(.finished, epoch, .finished, boundary);
            try self.scratch.?.transcripts.commit(msg);
            var after_buf: [Transcripts.max_digest]u8 = undefined;
            const after = self.scratch.?.transcripts.digest(&after_buf);
            var app: @TypeOf(k.schedule).Traffic = .{};
            defer app.deinit();
            try k.schedule.application(after[0..Hash.digest_length], &app);
            const len = Hash.digest_length;
            try self.install(.read, .application, tag, len, app.server.expose(), "SERVER_TRAFFIC_SECRET_0");
            self.app_write = self.makeTraffic(tag, len, app.client.expose(), "CLIENT_TRAFFIC_SECRET_0");
            self.keyLog("EXPORTER_SECRET", k.schedule.exporter.expose());
        },
    }
    try self.continueFlight();
}

/// The server rejected ECH and the handshake with the outer hello is complete, the public name
/// authenticated or not. The connection never reaches the application: it ends with
/// ech_required, before the client's Finished, and the retry configurations are released only
/// when the public name was authenticated (RFC 9849 sections 6.1.6 and 6.1.7).
fn endRejected(self: *Client) Error {
    @setRuntimeSafety(true);
    const e = &self.scratch.?.ech;
    if (self.authenticated and self.options.verify == .full) {
        self.ech_retry = e.retry_list;
        e.retry_list = &.{};
    }
    self.authenticated = false;
    return error.EchRejected;
}

/// The client's second flight: the response to a CertificateRequest, then Finished.
fn continueFlight(self: *Client) Error!void {
    @setRuntimeSafety(true);
    try self.sendCompatCcs();
    if (!self.requested_certificate) return self.finishFlight();
    const auth = self.options.auth orelse return self.sendEmptyCertificate();
    // The type the server selected (RFC 7250) must be the one this credential is.
    if ((auth.identity.form() == .raw_public_key) != self.scratch.?.client_raw) return self.sendEmptyCertificate();
    const request: Messages.CertificateRequest = .{ .context = "", .schemes = self.scratch.?.cr_schemes[0..self.scratch.?.cr_len] };
    // RFC 9345 section 4.1.2: a credential the server listed a scheme for, while it is valid.
    const delegated: ?Delegation.Credential = if (self.kept.auth_delegated) |credential| use: {
        const listed = self.scratch.?.cr_delegated_len orelse break :use null;
        const now = self.now orelse break :use null;
        break :use if (credential.usable(types.seconds(now), self.scratch.?.cr_delegated[0..listed], request)) credential else null;
    } else null;
    const scheme = if (delegated) |credential| credential.keyScheme() else Possession.choose(auth.identity.publicKey(), request) orelse return self.sendEmptyCertificate();
    var total: usize = 64;
    for (auth.entries()) |der| total += der.len + 5;
    if (delegated) |credential| total += credential.wire().len + 4;
    const dst = try self.reserve(total);
    const message_bytes = try Messages.buildCertificate(dst, "", auth.entries(), .{ .delegated = if (delegated) |credential| credential.wire() else null });
    try self.state.advance(.local_certificate, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message_bytes);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const content = Messages.signedContent(&self.scratch.?.sign_content, false, self.scratch.?.transcripts.digest(&digest_buf));
    // safe: signed content is at most 64 + 33 + 1 + 48 bytes.
    self.scratch.?.sign_content_len = @intCast(content.len);
    self.sign_scheme = scheme;
    if (delegated) |credential| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = credential.sign(content, self.scratch.?.sign_noise[0..credential.noiseLength()], &out) catch return error.SigningFailed;
        return self.sendCertificateVerify(signature);
    }
    // Cloak signs for a key it holds; a key held elsewhere is the caller's to sign with.
    if (auth.identity.noiseLength()) |noise_length| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = Possession.sign(auth.identity, scheme, content, self.scratch.?.sign_noise[0..noise_length], &out) catch return error.SigningFailed;
        return self.sendCertificateVerify(signature);
    }
    self.need_now = .sign;
}

fn sendEmptyCertificate(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const dst = try self.reserve(16);
    const message_bytes = try Messages.buildCertificate(dst, "", &.{}, .{});
    try self.state.advance(.local_empty_certificate, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message_bytes);
    try self.finishFlight();
}

fn finishFlight(self: *Client) Error!void {
    @setRuntimeSafety(true);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const Hash = suites.Hash(tag);
            const digest = self.scratch.?.transcripts.digest(&digest_buf);
            var verify_data: [Hash.digest_length]u8 = undefined;
            Labels.finished(Hash, k.schedule.prefix, &verify_data, k.handshake.client.expose(), digest[0..Hash.digest_length]);
            const dst = try self.reserve(4 + Hash.digest_length);
            const message_bytes = try Messages.buildFinished(dst, &verify_data);
            try self.state.advance(.local_finished, .handshake, .finished, true);
            try self.queueMessage(.handshake, message_bytes);
            try self.push(.{ .secret = .{ .direction = .write, .epoch = .application, .traffic = self.app_write.? } });
            self.app_write.?.secret.deinit();
            self.app_write = null;
            var finished_buf: [Transcripts.max_digest]u8 = undefined;
            try k.schedule.complete(self.scratch.?.transcripts.digest(&finished_buf)[0..Hash.digest_length]);
            k.handshake.deinit();
            // Every later exchange starts from the transcript through this Finished.
            if (self.options.hello.post_handshake_auth) self.post_auth = try PostAuth.init(self.gpa, .client, tag, &self.scratch.?.transcripts, self.scratch.?.client_raw, false);
        },
    }
    self.established = true;
    // A provisioned key authenticates whatever the certificate policy; otherwise only a full
    // verification does.
    self.authenticated = self.external_used or (self.authenticated and self.options.verify != .none);
    try self.push(.complete);
}

fn onTicket(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.ticket, epoch, .parsed, boundary);
    const ticket = try Messages.newSessionTicket(msg);
    self.storeTicket(&ticket);
    try self.push(.ticket);
}

/// Keeps a ticket for a later connection. It expires with the ticket's lifetime, the session's
/// maximum age from its full handshake, or the server authentication's expiry, whichever is
/// first; it is received, for its age, at the handshake's time. A ticket that cannot be kept
/// is dropped: it never fails the connection.
fn storeTicket(self: *Client, ticket: *const Messages.Ticket) void {
    @setRuntimeSafety(true);
    const resumption = self.kept.resumption orelse return;
    const now = self.now orelse return;
    // A session on a provisioned key is resumed by offering the key again, not by tickets.
    if (self.version != .tls13 or ticket.lifetime == 0 or self.external_used) return;
    const keys = if (self.keys) |*keys| keys else return;
    const now_s = types.seconds(now);
    const max_age = @divFloor(resumption.max_age.nanoseconds, std.time.ns_per_s);
    const by_age: i64 = std.math.cast(i64, @as(i96, self.origin) + max_age) orelse std.math.maxInt(i64);
    const expires = @min(now_s +| @as(i64, ticket.lifetime), @min(by_age, self.auth_expires));
    if (expires <= now_s) return;
    switch (keys.*) {
        inline else => |*k, tag| {
            var psk = aegis.Secret([Schedule.Schedule(tag).length]u8).init(undefined);
            defer psk.deinit();
            k.schedule.ticketSecret(ticket.nonce, psk.exposeMut()) catch return;
            resumption.cache.store(.{
                .key = &self.cache_key,
                .ticket = ticket.ticket,
                .suite = suites.Suite.from13(tag),
                .secret = psk.expose(),
                .age_add = ticket.age_add,
                .received_ms = std.math.cast(i64, @divFloor(now.nanoseconds, std.time.ns_per_ms)) orelse return,
                .expires = expires,
                .origin = self.origin,
                .auth_expires = self.auth_expires,
                .authenticated = self.authenticated,
                .raw_key_pin = self.raw_pin,
            }) catch return;
        },
    }
}

/// A CertificateRequest after the handshake (RFC 8446 section 4.6.2): only to a client that
/// offered post_handshake_auth, unexpected_message otherwise. Each counts as a control message.
fn onPostRequest(self: *Client, msg: []const u8, epoch: Epoch) Error!void {
    @setRuntimeSafety(true);
    const post = self.post_auth orelse return error.UnexpectedMessage;
    if (self.version != .tls13 or self.state.phase() != .connected) return error.UnexpectedMessage;
    if (epoch != .application) return error.WrongEpoch;
    return self.postAnswered(post.onRequest(msg, self.kept.auth));
}

/// After a step of a post-handshake answer: once it is built, the write half is told.
fn postAnswered(self: *Client, step: Error!void) Error!void {
    try step;
    if (self.post_auth.?.answerReady()) try self.push(.auth_response);
}

fn onKeyUpdate(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.key_update, epoch, .parsed, boundary);
    try self.push(.{ .key_update = .{ .request_peer = try Messages.keyUpdate(msg) } });
}

// ---------------------------------------------------------------- results

/// Releases handshake scratch (flight, peer chain, offered shares) once the connection is
/// established and every output was read. Keys for the exporter and the info stay.
pub fn settle(self: *Client) void {
    @setRuntimeSafety(true);
    if (!self.established or self.pending()) return;
    self.releaseScratch();
    if (self.held.len != 0) {
        self.gpa.free(self.held);
        self.held = &.{};
    }
}

pub fn info(self: *const Client) ?Info {
    @setRuntimeSafety(true);
    if (!self.established or self.state.phase() == .failed) return null;
    return .{
        .version = self.version,
        .suite = if (self.suite12) |suite| suites.Suite.from12(suite) else suites.Suite.from13(self.suite.?),
        .group = self.group,
        .alpn = self.alpn,
        .server_name = self.kept.sni,
        .peer_authenticated = self.authenticated,
        .peer_parameters = self.peer_parameters,
        .resumed = self.resumed,
        .ech_accepted = self.ech_accepted,
        .external_psk = self.external_used,
        .srtp = self.srtp,
        .raw_key_pin = self.raw_pin,
        .delegated_credential = self.delegated_used,
    };
}

pub const ExportError = @import("Errors.zig").ExportError;

/// RFC 8446 section 7.5 exporter; only after the connection is established.
pub fn exportKeyingMaterial(self: *const Client, out: []u8, label: []const u8, context: ?[]const u8) ExportError!void {
    @setRuntimeSafety(true);
    // A failed connection has erased its secrets; established stays true for the record.
    if (!self.established or self.state.phase() == .failed) return error.WrongPhase;
    if (self.version == .tls12) {
        const secrets = self.tls12 orelse return error.WrongPhase;
        return secrets.exportKeyingMaterial(self.suite12 orelse return error.WrongPhase, out, label, context);
    }
    const keys = if (self.keys) |*keys| keys else return error.WrongPhase;
    switch (keys.*) {
        // TLS 1.3 has one form: no context is the empty one (RFC 8446 section 7.5).
        inline else => |*k| try k.schedule.exportBytes(out, label, context orelse ""),
    }
}

test {
    _ = @import("Client_test.zig");
}
