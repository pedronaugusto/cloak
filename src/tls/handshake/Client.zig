//! The TLS 1.3 client handshake. It takes whole handshake messages with their epoch and
//! record alignment and returns outputs through a queue: messages to send, traffic secrets
//! to install, and requests for services it never performs itself (entropy, time, peer
//! verification, signing). It owns the transcript, the key schedule and the checked state;
//! records and QUIC levels belong to the callers that translate its outputs.
const std = @import("std");
const aegis = @import("aegis");
const Buffer = @import("../wire/Buffer.zig");
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
const Authorities = @import("Authorities.zig");

pub const Epoch = Flight.Epoch;
pub const Direction = Flight.Direction;

pub const Limits = Terms.Limits;
pub const Verify = Terms.Verify;

/// Receives NSS key-log lines. The sink is outside the confidentiality guarantee. It is a field
/// of the sink's own type, which `write` recovers with `@fieldParentPtr`.
pub const KeyLog = struct {
    write: *const fn (log: *KeyLog, line: []const u8) void,
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

pub const Credential = Terms.ClientCredential;
pub const max_credentials = Terms.ClientCredential.max;

pub const Options = struct {
    hello: Hello.Options = .{},
    /// GREASE (RFC 8701): reserved values in the hello, drawn per connection, so servers that
    /// would choke on what they do not know are found now rather than when it is real.
    grease: bool = false,
    /// The hello's extensions in a random order per connection (`Hello.Permutation`), so servers
    /// that depend on one order are found now rather than when a new extension moves it.
    permute_extensions: bool = false,
    resumption: ?Resumption = null,
    /// Encrypted Client Hello (RFC 9849). A config list makes it required and the connection
    /// TLS 1.3 only.
    ech: Ech.Mode = .off,
    /// Provisioned keys to offer, each for its one version, at most `Psk.max_keys`: TLS 1.3
    /// (PSK-DHE) keys, offered in this order instead of a ticket, never with one (a plain key
    /// once, an imported one, RFC 9258, once per hash of the TLS 1.3 suites offered); at most one
    /// TLS 1.2 key (plain PSK, RFC 4279), offered by listing its suites, which have no forward
    /// secrecy. A server that selects one is authenticated by it, with no certificate
    /// (`Info.external_psk`).
    external_psks: []const Psk.External = &.{},
    /// The identity the server certificate must carry.
    identity: types.Identity = .none,
    verify: Verify,
    /// What a CertificateRequest is answered with, in this client's order, at most
    /// `max_credentials`: of the form the server selected (certificates, or raw keys, RFC 7250:
    /// the types are offered in the order the forms first appear), the first the request takes
    /// that chains to an authority it names, else the first it takes (`Credential`). A key cloak
    /// does not hold signs through a signing request.
    credentials: []const Credential = &.{},
    limits: Limits = .{},
    /// A random legacy session id and one change_cipher_spec, for middleboxes (stream only).
    compat: bool = true,
    key_log: ?*KeyLog = null,
    /// Keep the server's leaf certificate for `peerLeaf` (RFC 8705's certificate binding, a
    /// pin checked after the handshake): a copy the connection holds until `deinit`. Off, a
    /// connection keeps none and `peerLeaf` is null.
    keep_peer_leaf: bool = false,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Traffic = Flight.Traffic;
pub const Emit = Flight.Emit;

pub const Need = Terms.Need;
pub const SignRequest = Terms.SignRequest;

pub const Info = struct {
    version: suites.Version,
    suite: suites.Suite,
    /// The key exchange's group; null for a TLS 1.2 provisioned key, which has none.
    group: ?Group,
    alpn: []const u8,
    server_name: []const u8,
    peer_authenticated: bool,
    peer_parameters: []const u8,
    /// The handshake resumed a session from a ticket: the peer's authentication is the original
    /// handshake's.
    resumed: bool = false,
    /// Encrypted Client Hello was offered and accepted: the true server name never crossed the
    /// wire in clear.
    ech_accepted: bool = false,
    /// The identity of the provisioned key the handshake used (an imported key's external
    /// identity): the peer is whoever holds it, no certificate. Null when none authenticated.
    external_psk: ?[]const u8 = null,
    /// DTLS: the SRTP profile use_srtp agreed (RFC 5764), keyed by the "EXTRACTOR-dtls_srtp"
    /// exporter; null when none was offered or none agreed.
    srtp: ?Hello.Srtp = null,
    /// The peer proved a pinned key, a raw public key (RFC 7250) or its leaf certificate's key
    /// under `Verify.leaf_key`: its index in the policy's pins. Null otherwise.
    pin: ?u16 = null,
    /// The signature scheme the peer proved possession under in this handshake (its
    /// CertificateVerify, or a TLS 1.2 server's ServerKeyExchange); null when it signed nothing,
    /// a resumption among them.
    peer_scheme: ?Hello.SignatureScheme = null,
    /// The peer proved possession with a delegated credential (RFC 9345) its verified certificate
    /// signed, not with the certificate's own key.
    delegated_credential: bool = false,
    /// The credential this end authenticated with in the handshake: its index in the options'
    /// `credentials`, the server's answer to the client or the client's to a CertificateRequest.
    /// Null when this end presented none: a resumption, a provisioned key, a client not asked
    /// for a certificate or answering with an empty one. Post-handshake answers are not counted.
    credential: ?u8 = null,
};

pub const InitError = Hello.ValidateError || std.mem.Allocator.Error || error{InvalidOptions};
pub const Error = @import("Errors.zig").Error;

/// The alert that reports an error to the peer. Local service failures are internal errors.
pub fn alertFor(err: anyerror) Alert {
    return switch (err) {
        error.UnexpectedMessage, error.WrongEpoch, error.MissingProof, error.RecordAlignment => .unexpected_message,
        error.InvalidLength, error.InvalidMessage, error.EmptyCertificate, error.CertificateLimit => .decode_error,
        error.NoSharedGroup, error.NoSharedSuite, error.NoSignatureScheme, error.NoMatchingIssuer => .handshake_failure,
        error.UnrecognizedName => .unrecognized_name,
        error.CertificateRequired => .certificate_required,
        error.DecodeError => .decode_error,
        error.UnexpectedCookie => .illegal_parameter,
        error.DuplicateExtension, error.InvalidHello, error.IllegalParameter, error.UnofferedSelection, error.InvalidShare, error.WeakKey, error.InvalidRetry => .illegal_parameter,
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
        // A peer's message or handshake past the receiver's bounds: a length out of the range it
        // takes (RFC 8446 section 6.2), not an internal failure.
        error.HandshakeLimit => .decode_error,
        error.VerificationRejected, error.UnsupportedKey, error.InvalidCertificate, error.InvalidDer, error.KeyUsage => .bad_certificate,
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
/// The index of the pin the server's key matched: a raw public key (RFC 7250) or a pinned leaf.
pin: ?u16 = null,
/// The scheme the server signed its CertificateVerify or ServerKeyExchange under.
peer_scheme: ?Hello.SignatureScheme = null,
/// The server's leaf certificate, kept once its chain passed and its key signed; owned, freed
/// at deinit. Empty for a raw key and on resumption.
peer_leaf: []u8 = &.{},
/// The server proved possession with a delegated credential (RFC 9345).
delegated_used: bool = false,
sign_scheme: Hello.SignatureScheme = .ed25519,
/// The credential answering the CertificateRequest: its index in `kept.credentials`; null until
/// one is chosen, and when none answers it (an empty Certificate).
credential: ?u8 = null,
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
/// The provisioned keys' TLS 1.3 offers still made, a bit each (`Scratch.externals`): until the
/// server's answer, a retry drops those of another hash.
external_live: u8 = 0,
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
    /// The credential table, copied, its identities and delegated credentials retained.
    credentials: []Credential = &.{},
    resumption: ?Resumption,
    sni: []const u8,
    message_limit: usize,
    allows12: bool,
    /// The identity of the provisioned key the server selected, borrowed from the options.
    psk_identity: []const u8 = "",
};

/// A provisioned key's TLS 1.3 offer: its key in `external_psks`, the hash of the suites it
/// serves, its binder label and its identity on the wire.
const External13 = struct { key: u8, hash: Psk.Hash, kind: Schedule.BinderKind, identity: []const u8 };

const Scratch = struct {
    options: Options = undefined,
    flight: Flight = .{},
    transcripts: Transcripts = .{},
    /// A nonce, and with ECH the inner hello's, which only the client-facing server reads.
    random: aegis.Secret([32]u8) = .init(@splat(0)),
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
    /// RFC 6066: the server's stapled OCSPResponse, owned, and the request's responses with it
    /// after the caller's.
    ocsp: []u8 = &.{},
    ocsp_lists: [max_evidence][]const u8 = undefined,
    /// The provisioned keys' TLS 1.3 offers in the hello's order, the keys their binders and
    /// schedules take (a plain key's own, an imported one's derived, `Psk.derive`), 48 bytes each,
    /// and the imported identities' bytes; owned, allocated only for a client with such keys.
    externals: []External13 = &.{},
    external_keys: Buffer = .{},
    imported: []u8 = &.{},
    /// TLS 1.2: a ServerKeyExchange that came where a CertificateStatus might have, owned; it is
    /// taken once the chain it follows is verified.
    held_ske: []u8 = &.{},
    held_ske_boundary: bool = false,
    /// RFC 9345: the server's delegated credential (in `held`) and, once checked, its key.
    delegated: ?[]const u8 = null,
    delegated_key: ?Delegation.Checked = null,
    cr_schemes: [1024]u8 = undefined,
    cr_len: u16 = 0,
    /// The credentials that chain to an authority the CertificateRequest named, a bit each; null
    /// when it named none.
    cr_named: ?u32 = null,
    /// The CertificateRequest's delegated_credential list, when it sent one.
    cr_delegated: [1024]u8 = undefined,
    cr_delegated_len: ?u16 = null,
    /// TLS 1.2: the certificate types a CertificateRequest named (Client12.rsa_sign, ecdsa_sign).
    cr_types: u8 = 0,
    sign_content: aegis.Secret([Messages.max_signed]u8) = .init(@splat(0)),
    sign_content_len: u8 = 0,
    /// Fresh noise for the hedged client signature, drawn with the first entropy.
    sign_noise: aegis.Secret([certificates.PrivateKey.max_noise]u8) = .init(@splat(0)),
    // TLS 1.2: the server's ECDHE public value and the client's share for it.
    /// The longest classical public value: P-521's uncompressed point.
    server_public: [133]u8 = undefined,
    server_public_len: u8 = 0,
    share12: ?Exchange.Share = null,
    ech: EchScratch = .{},
};

/// ECH's course: offered with the first hello, accepted by a retry request (which binds the
/// ServerHello to accept it too) or by the ServerHello, or rejected.
const EchMachine = aegis.state.Machine(enum { none, offered, accepted_retry, accepted, rejected }, enum { offer, accept_retry, accept, reject }, .{ .initial = .none, .terminal = &.{ .accepted, .rejected }, .edges = &.{
    .{ .from = .none, .on = .offer, .to = .offered },
    .{ .from = .offered, .on = .accept_retry, .to = .accepted_retry },
    .{ .from = .offered, .on = .accept, .to = .accepted },
    .{ .from = .accepted_retry, .on = .accept, .to = .accepted },
    .{ .from = .offered, .on = .reject, .to = .rejected },
} });

/// Moves ECH's status along its machine; every caller reaches it from a state the event leaves.
fn echStep(e: *EchScratch, event: @FieldType(EchMachine.Edge, "on")) void {
    _ = e.status.step(event) catch aegis.assert.never("ECH's status moves along its machine's edges");
}

/// Encrypted Client Hello in flight: until the server's first answer, two hellos and two
/// transcripts run side by side, the outer one on the wire and the inner one the transcript of an
/// accepted handshake.
const EchScratch = struct {
    status: EchMachine.Runtime(void) = .init({}),
    outer_random: [32]u8 = @splat(0),
    /// The HPKE ephemeral key's input, erased once the context is set up from it.
    ikm: ?aegis.Secret([32]u8) = null,
    /// Seeds the GREASE bytes: a GREASE extension, or a GREASE PSK in the outer hello.
    seed: aegis.Secret([32]u8) = .init(@splat(0)),
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
        .raw_key, .leaf_key => |pinned| if (pinned.pins.len == 0 or pinned.pins.len > Verify.Pins.max_pins) return error.InvalidOptions,
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
        // RFC 6066 section 8: a client checking revocation asks for the server's stapled status,
        // which joins the request's evidence after the caller's (a Must-Staple certificate needs
        // it).
        hello.request_ocsp = full.policy.revocation.mode != .off;
        if (hello.request_ocsp and full.evidence.crls.len + full.evidence.ocsp.len >= max_evidence) return error.InvalidOptions;
    } else {
        hello.request_scts = false;
        hello.request_ocsp = false;
    }
    if (options.credentials.len > max_credentials) return error.InvalidOptions;
    for (options.credentials) |credential| if (credential.schemes.len > Possession.max_schemes) return error.InvalidOptions;
    hello.client_types = clientTypes(options.credentials);
    Hello.validate(hello) catch return error.InvalidOptions;
    switch (options.ech) {
        .off => {},
        // GREASE needs a TLS 1.3 offer to ride on.
        .grease => if (!hello.allows13()) return error.InvalidOptions,
        .config_list => |list| {
            // A rejected attempt authenticates the public name's certificate, which a client
            // trusting a pinned key alone cannot (RFC 9849 section 6.1.7).
            if (options.verify == .raw_key or options.verify == .leaf_key) return error.InvalidOptions;
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
    for (options.credentials) |credential| if (credential.delegated) |delegated| {
        if (options.verify != .full or !hello.allows13() or delegated.side() != .client or !delegated.belongsTo(credential.auth.identity)) return error.InvalidOptions;
    };
    if (options.external_psks.len > Psk.max_keys) return error.InvalidOptions;
    var keys12: usize = 0;
    var offers13: usize = 0;
    for (options.external_psks) |psk| {
        Psk.validate(psk) catch return error.InvalidOptions;
        if (!offersKeySuite(hello, psk)) return error.InvalidOptions;
        keys12 += @intFromBool(psk.version == .tls12);
        if (psk.version == .tls13) offers13 += if (psk.imported != null) offeredHashes(hello).len else 1;
    }
    if (keys12 > 1 or offers13 > Hello.max_psk_offers) return error.InvalidOptions;
    // The TLS 1.2 PSK suites are offered only with a TLS 1.2 key to complete them.
    for (hello.suites) |suite| if (suite.tls12()) |s12| if (s12.authentication() == .psk and keys12 == 0) return error.InvalidOptions;
    const self = try gpa.create(Client);
    errdefer gpa.destroy(self);
    const scratch = try gpa.create(Scratch);
    errdefer gpa.destroy(scratch);
    // The credential table is copied; the identities (retained below) are the caller's.
    const credentials = try gpa.dupe(Credential, options.credentials);
    errdefer gpa.free(credentials);
    scratch.* = .{ .options = options };
    scratch.options.hello = hello;
    self.* = .{
        .gpa = gpa,
        .options = &scratch.options,
        .kept = .{ .credentials = credentials, .resumption = options.resumption, .sni = hello.sni, .message_limit = options.limits.message, .allows12 = hello.allows12() },
        .state = .init(.client, options.hello.transport),
        .scratch = scratch,
    };
    // TLS 1.3 keys go in the hello's pre_shared_key; a TLS 1.2 key waits for its suite.
    try self.offerExternals();
    self.need_now = .{ .entropy = .{ .len = self.initialEntropy() } };
    // A datagram hello that may be answered in DTLS 1.2 is hashed in its DTLS form too.
    if (options.hello.transport == .datagram and options.hello.allows12()) scratch.transcripts.startDatagram(0, 0, options.hello.allows13());
    if (options.resumption) |resumption| {
        // A ticket is chosen and aged by the clock, before the hello.
        if (options.hello.allows13() or (resumption.tls12 and options.hello.allows12())) self.need_now = .time;
        self.cache_key = cacheKey(options, resumption.namespace);
    }
    var keep = false;
    for (credentials) |credential| {
        _ = credential.auth.retain();
        if (credential.delegated) |delegated| _ = delegated.retain();
        // A TLS 1.2 CertificateVerify by Ed25519 signs the handshake messages themselves.
        keep = keep or credential.auth.identity.publicKey() == .ed25519;
    }
    if (keep and hello.allows12()) scratch.transcripts.keep(gpa);
    return self;
}

/// Whether the hello offers a suite a provisioned key can complete: one of its version and hash,
/// any TLS 1.3 suite for an imported key.
fn offersKeySuite(hello: Hello.Options, psk: Psk.External) bool {
    for (hello.suites) |suite| switch (psk.version) {
        .tls13 => if (suite.tls13()) |s13| if (hello.allows13() and (psk.imported != null or suites.digestLength(s13) == psk.hash.length())) return true,
        .tls12 => if (suite.tls12()) |s12| if (hello.allows12() and s12.authentication() == .psk) return true,
    };
    return false;
}

/// The hashes of the TLS 1.3 suites the hello offers, in its order, each once.
fn offeredHashes(hello: Hello.Options) []const Psk.Hash {
    if (!hello.allows13()) return &.{};
    var sha256 = false;
    var sha384 = false;
    var first: ?Psk.Hash = null;
    for (hello.suites) |suite| if (suite.tls13()) |s13| {
        const hash: Psk.Hash = if (suites.digestLength(s13) == 48) .sha384 else .sha256;
        if (first == null) first = hash;
        if (hash == .sha256) sha256 = true else sha384 = true;
    };
    if (sha256 and sha384) return if (first.? == .sha256) &.{ .sha256, .sha384 } else &.{ .sha384, .sha256 };
    if (sha256) return &.{.sha256};
    if (sha384) return &.{.sha384};
    return &.{};
}

/// Lays out the provisioned keys' TLS 1.3 offers (`Scratch.externals`) and puts them all on
/// offer: a plain key under its own identity, an imported one under an ImportedIdentity for each
/// offered hash with the key derived for it (RFC 9258 section 5).
fn offerExternals(self: *Client) std.mem.Allocator.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const options = self.options;
    const hashes = offeredHashes(options.hello);
    var count: usize = 0;
    var bytes: usize = 0;
    for (options.external_psks) |psk| if (psk.version == .tls13) {
        if (psk.imported) |imported| {
            count += hashes.len;
            bytes += hashes.len * (2 + psk.identity.len + 2 + imported.context.len + 4);
        } else count += 1;
    };
    if (count == 0) return;
    const gpa = self.gpa;
    const externals = try gpa.alloc(External13, count);
    errdefer gpa.free(externals);
    var keys_owner: Buffer = .{};
    errdefer keys_owner.free(gpa);
    const keys = try keys_owner.ensure(gpa, count * 48);
    const imported_bytes = try gpa.alloc(u8, bytes);
    var at: usize = 0;
    var n: usize = 0;
    for (options.external_psks, 0..) |psk, key| {
        if (psk.version != .tls13) continue;
        if (psk.imported == null) {
            externals[n] = .{ .key = @intCast(key), .hash = psk.hash, .kind = .external, .identity = psk.identity }; // at most Psk.max_keys keys
            @memcpy(keys[n * 48 ..][0..psk.secret.len], psk.secret);
            n += 1;
            continue;
        }
        for (hashes) |hash| {
            const identity = Psk.importedIdentity(psk, options.hello.transport, hash).write(imported_bytes[at..]);
            at += identity.len;
            externals[n] = .{ .key = @intCast(key), .hash = hash, .kind = .imported, .identity = identity }; // at most Psk.max_keys keys
            Psk.derive(psk, options.hello.transport.prefix(), identity, keys[n * 48 ..][0..hash.length()]);
            n += 1;
        }
    }
    scratch.externals = externals;
    scratch.external_keys = keys_owner;
    scratch.imported = imported_bytes;
    self.external_live = @truncate((@as(u16, 1) << @intCast(n)) - 1); // n is at most eight
}

/// The TLS 1.2 key: the one of that version in `external_psks`.
pub fn key12(self: *const Client) ?Psk.External {
    for (self.options.external_psks) |psk| if (psk.version == .tls12) return psk;
    return null;
}

pub fn deinit(self: *Client) void {
    @setRuntimeSafety(true);
    const gpa = self.gpa;
    self.wipe();
    for (self.kept.credentials) |credential| {
        credential.auth.deinit();
        if (credential.delegated) |delegated| delegated.deinit();
    }
    gpa.free(self.kept.credentials);
    if (self.post_auth) |post| post.deinit();
    if (self.ech_retry) |list| gpa.free(list);
    if (self.peer_leaf.len != 0) gpa.free(self.peer_leaf);
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
    // The caller's order decides: a share for the first post-quantum or hybrid group listed and
    // one for the first classical group, at most two, in supported_groups' order (RFC 8446
    // section 4.2.8 lets a client send any subset; the shares follow the list). Under
    // require_hybrid only the first hybrid: a server could take no other share.
    var quantum = false;
    var classical = false;
    for (self.options.hello.groups) |group| {
        if (self.options.hello.require_hybrid and !group.hybrid()) continue;
        const kind = if (group.classical()) &classical else &quantum;
        if (kind.*) continue;
        kind.* = true;
        out[count] = group;
        count += 1;
        if (count == out.len) break;
    }
    return .{ .groups = out, .count = count };
}

/// A legacy session id: for middleboxes in a hello offering TLS 1.3 (RFC 8446 appendix D.4), or to
/// see a TLS 1.2 ticket accepted (RFC 5077 section 3.4). Otherwise it is empty: a TLS 1.2 hello
/// resuming nothing has no session to name (RFC 5246 section 7.4.1.2).
fn sendsSessionId(self: *const Client) bool {
    return (self.options.compat and self.options.hello.allows13()) or self.offered12 != null;
}

fn initialEntropy(self: *const Client) usize {
    @setRuntimeSafety(true);
    var len: usize = 32 + @as(usize, if (self.sendsSessionId()) 32 else 0);
    const initial = self.initialGroups();
    for (initial.groups[0..initial.count]) |group| len += Exchange.entropyLength(group.?);
    len += self.echEntropy();
    if (self.options.grease) len += 6;
    if (self.options.permute_extensions) len += 16;
    // A client certificate whose key cloak holds is signed for here, with noise drawn up front.
    // A delegated credential signs instead when the server takes it: noise for either.
    var noise: usize = 0;
    for (self.kept.credentials) |credential| noise = @max(noise, credential.auth.identity.noiseLength() orelse 0, if (credential.delegated) |delegated| delegated.noiseLength() else 0);
    len += noise;
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
    if (self.established) return self.postAnswered(self.post_auth.?.provideEntropy(entropy, self.kept.credentials));
    if (self.state.phase() == .start) {
        var at: usize = 0;
        self.scratch.?.random.exposeMut().* = entropy[0..32].*;
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
                e.seed.exposeMut().* = entropy[at..][0..32].*;
                at += 32;
            },
            .config_list => {
                e.outer_random = entropy[at..][0..32].*;
                e.ikm = .init(entropy[at + 32 ..][0..32].*);
                e.seed.exposeMut().* = entropy[at + 64 ..][0..32].*;
                at += 96;
            },
        }
        if (self.options.grease) {
            self.options.hello.grease = Hello.Grease.fromSeed(entropy[at..][0..6]);
            at += 6;
        }
        if (self.options.permute_extensions) {
            self.options.hello.permutation = .{ .key = entropy[at..][0..16].* };
            at += 16;
        }
        @memcpy(self.scratch.?.sign_noise.exposeMut()[0 .. entropy.len - at], entropy[at..]);
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
    scratch.transcripts.deinit();
    scratch.random.deinit();
    scratch.sign_content.deinit();
    scratch.sign_noise.deinit();
    scratch.external_keys.free(self.gpa);
    // The rest is public: what the hellos carry in the clear (the outer random, the session id,
    // the cookies, the connection ID), the peer's certificates and the statements about them (its
    // SCTs and OCSP response), a TLS 1.2 ServerKeyExchange, the PSK identities and the
    // CertificateRequest's lists. Each secret above had its own owner.
    if (scratch.scts.len != 0) self.gpa.free(scratch.scts);
    if (scratch.ocsp.len != 0) self.gpa.free(scratch.ocsp);
    if (scratch.held_ske.len != 0) self.gpa.free(scratch.held_ske);
    if (scratch.externals.len != 0) self.gpa.free(scratch.externals);
    if (scratch.imported.len != 0) self.gpa.free(scratch.imported);
    self.gpa.destroy(scratch);
    self.scratch = null;
    self.options = undefined;
}

fn releaseEch(self: *Client) void {
    @setRuntimeSafety(true);
    const e = &self.scratch.?.ech;
    if (e.context) |*context| context.deinit();
    e.context = null;
    if (e.ikm) |*ikm| ikm.deinit();
    e.ikm = null;
    e.seed.deinit();
    e.inner.deinit();
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
    return scratch.ech.status.current() == .rejected;
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
/// The certificate types `credentials` can present, in the order their forms first appear.
fn clientTypes(credentials: []const Credential) Hello.ClientTypes {
    if (credentials.len == 0) return .x509;
    const first_raw = credentials[0].auth.identity.form() == .raw_public_key;
    for (credentials[1..]) |credential| {
        if ((credential.auth.identity.form() == .raw_public_key) != first_raw) return if (first_raw) .raw_then_x509 else .x509_then_raw;
    }
    return if (first_raw) .raw else .x509;
}

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
        .leaf_key => |leaf| {
            part(&h, "verify leaf keys");
            for (leaf.pins) |*pin| part(&h, pin);
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
    // The client certificates a server may have authenticated, each by its whole chain.
    if (options.credentials.len == 0) part(&h, "no client certificate");
    for (options.credentials) |credential| {
        part(&h, switch (credential.auth.identity.form()) {
            .x509 => "client certificate",
            .raw_public_key => "client raw key",
        });
        for (credential.auth.entries()) |der| part(&h, der);
    }
    // A session a delegated credential authenticated resumes only where one is taken.
    part(&h, if (options.hello.accept_delegated) "delegated credentials" else "no delegated credentials");
    return h.finalResult();
}

/// Takes the newest usable ticket of each offered version for this connection's key: one the
/// offered suites can resume.
fn takeTicket(self: *Client) void {
    @setRuntimeSafety(true);
    const resumption = self.options.resumption orelse return;
    if (self.options.hello.allows13() and self.external_live == 0) if (resumption.cache.take(&self.cache_key, .tls13, self.origin)) |found| {
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
    self.external_live = 0;
}

/// A PSK the hello offers: the taken ticket, or a provisioned key's offer (`slot` in
/// `Scratch.externals`).
const Offer = struct { identity: []const u8, secret: []const u8, binder_len: usize, kind: Schedule.BinderKind, slot: u8 = 0 };

/// The PSKs the hello offers, in its order: the taken ticket, or the provisioned keys' offers
/// still live.
fn pskOffers(self: *const Client, out: *[Hello.max_psk_offers]Offer) []const Offer {
    @setRuntimeSafety(true);
    if (self.offered) |taken| {
        out[0] = .{ .identity = taken.entry.ticket, .secret = taken.entry.secretBytes(), .binder_len = suites.digestLength(taken.entry.suite.tls13().?), .kind = .resumption };
        return out[0..1];
    }
    const scratch = self.scratch orelse return out[0..0];
    var n: usize = 0;
    for (scratch.externals, 0..) |external, slot| {
        if (self.external_live & (@as(u8, 1) << @intCast(slot)) == 0) continue; // at most eight slots
        out[n] = .{ .identity = external.identity, .secret = scratch.external_keys.view()[slot * 48 ..][0..external.hash.length()], .binder_len = external.hash.length(), .kind = external.kind, .slot = @intCast(slot) };
        n += 1;
    }
    return out[0..n];
}

pub fn dropTicket12(self: *Client) void {
    // A ticket is the server's ciphertext, sent back in the clear.
    if (self.ticket12.len != 0) self.gpa.free(self.ticket12);
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

/// The caller's evidence, and the SCTs and stapled status the server sent after its own.
fn evidence(self: *const Client, caller: types.Evidence) types.Evidence {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var out = caller;
    // `init` left room for one more list and one more response.
    if (scratch.scts.len != 0) {
        const n = caller.scts.len;
        @memcpy(scratch.sct_lists[0..n], caller.scts);
        scratch.sct_lists[n] = scratch.scts;
        out.scts = scratch.sct_lists[0 .. n + 1];
    }
    if (scratch.ocsp.len != 0) {
        const n = caller.ocsp.len;
        @memcpy(scratch.ocsp_lists[0..n], caller.ocsp);
        scratch.ocsp_lists[n] = scratch.ocsp;
        out.ocsp = scratch.ocsp_lists[0 .. n + 1];
    }
    return out;
}

/// The most CRLs and OCSP responses one verification reads (`verify.revocation`).
const max_evidence = 64;

/// Keeps the server's stapled OCSPResponse for the verification request.
pub fn keepOcsp(self: *Client, response: ?[]const u8) Error!void {
    @setRuntimeSafety(true);
    const bytes = response orelse return;
    const scratch = self.scratch.?;
    if (scratch.ocsp.len != 0) self.gpa.free(scratch.ocsp);
    scratch.ocsp = &.{};
    scratch.ocsp = try self.gpa.dupe(u8, bytes);
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
    if (!try Possession.signs(receipt.path[0])) return error.KeyUsage;
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
    // TLS 1.2: a ServerKeyExchange that came where a CertificateStatus might have waited for this.
    if (self.version == .tls12) try Client12.takeHeldKeyExchange(self);
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
    if (self.version == .tls12 and self.sign_scheme == .ed25519) return .{ .scheme = .ed25519, .content = self.scratch.?.transcripts.keptBytes(), .credential = self.credential.? };
    return .{ .scheme = self.sign_scheme, .content = self.scratch.?.sign_content.expose()[0..self.scratch.?.sign_content_len], .prehashed = self.version == .tls12, .credential = self.credential.? };
}

/// Checks the signature against the identity's public key before using it.
pub fn provideSignature(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (self.need() != .sign) return error.UnexpectedService;
    if (self.established) return self.postAnswered(self.post_auth.?.provideSignature(signature, self.kept.credentials));
    if (self.version == .tls12) return Client12.onSignature(self, signature);
    const auth = self.kept.credentials[self.credential.?].auth;
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
        const post = if (self.post) |*post| post else return false;
        Flight.moveEmit(post, out);
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

/// RFC 8449: a server that answered record_size_limit bounds the records sealed for it, and the
/// limit this client named bounds the ones it opens from the record after the answer. One that
/// did not answer is held to neither: the extension is not negotiated.
pub fn limitRecords(self: *Client, answer: ?u16, version: suites.Version) Error!void {
    const peer = answer orelse return;
    const max = Flight.RecordLimits.max(version);
    try self.push(.{ .record_limits = .{ .send = @min(peer, max), .receive = @min(self.options.hello.recordSizeLimit(), max) } });
}

/// Queues `emit`, which carries no secret.
pub fn push(self: *Client, emit: Emit) Error!void {
    (try self.claim()).* = emit;
}

/// Claims the next output slot; see `Flight.claim`.
pub fn claim(self: *Client) Error!*Emit {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        if (self.post != null) return error.QueueFull;
        self.post = @as(Emit, .complete);
        return &self.post.?;
    };
    return scratch.flight.claim();
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
    // GREASE: a suite, a group with its share, a version, a scheme and two extensions.
    if (self.options.hello.grease != null) n += 32;
    var offers_buf: [Hello.max_psk_offers]Offer = undefined;
    for (self.pskOffers(&offers_buf)) |offer| n += 64 + offer.identity.len;
    if (self.offered12) |taken| n += 8 + taken.entry.ticket.len;
    for (self.options.hello.alpn) |protocol| n += 1 + protocol.len;
    for (shares) |share| n += 4 + share.bytes.len;
    const authorities = self.options.hello.certificate_authorities;
    if (authorities.len != 0) n += 6 + Authorities.wireLength(authorities);
    return n;
}

fn sendHello(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    switch (scratch.ech.status.current()) {
        .none, .accepted_retry, .offered => if (self.options.ech == .config_list) return self.sendEchHello(),
        .rejected => return self.sendOuterHello(),
        .accepted => unreachable, // unreachable: acceptance is decided by the ServerHello, after the last hello
    }
    var offered: [2]Hello.Share = undefined;
    const shares = self.offeredShares(&offered);
    var offers_buf: [Hello.max_psk_offers]Offer = undefined;
    const offers = self.pskOffers(&offers_buf);
    var identities: [Hello.max_psk_offers]Hello.PskOffer = undefined;
    const resumption = self.resumeOffer(offers, &identities);
    var form: Hello.Form = .plain;
    if (self.options.ech == .grease) {
        if (scratch.ech.ext.len == 0) try self.makeGrease(shares, resumption);
        form = .{ .grease = scratch.ech.ext };
    }
    const dst = try self.reserve(self.helloCapacity(shares) + scratch.ech.ext.len);
    const hello = try Hello.clientForm(dst, scratch.random.expose(), scratch.session[0..scratch.session_len], scratch.legacy_cookie[0..scratch.legacy_cookie_len], shares, scratch.cookie[0..scratch.cookie_len], self.options.hello, resumption, form);
    self.writeBinders(&scratch.transcripts, offers, hello, resumption.bindersLength());
    try self.state.advance(.client_hello, .initial, .parsed, true);
    try self.queueMessage(.initial, hello);
}

/// What the hello says of resumption: PSK-DHE when there is a cache, and the PSKs it offers
/// (`pskOffers`), a ticket with its obfuscated age (their binders are filled after encoding).
fn resumeOffer(self: *const Client, offers: []const Offer, out: *[Hello.max_psk_offers]Hello.PskOffer) Hello.Resume {
    @setRuntimeSafety(true);
    var resumption: Hello.Resume = .{ .modes = self.options.resumption != null };
    if (self.sendsTickets12()) resumption.ticket12 = if (self.offered12) |taken| taken.entry.ticket else "";
    for (offers, out[0..offers.len]) |offer, *identity| {
        // A provisioned key has no age: its obfuscated_ticket_age is zero (RFC 8446 4.2.11).
        identity.* = .{ .identity = offer.identity, .binder_len = offer.binder_len };
        if (offer.kind == .resumption) {
            const entry = self.offered.?.entry;
            // The obfuscated age: milliseconds since the ticket arrived, plus its obfuscator.
            const now_ms = types.milliseconds(self.now.?);
            const age: u64 = @intCast(std.math.clamp(now_ms - entry.received_ms, 0, std.math.maxInt(u32))); // clamped to u32
            identity.age = @truncate(age +% entry.age_add);
        }
    }
    resumption.offers = out[0..offers.len];
    return resumption;
}

/// Each binder covers the transcript so far and this hello up to its binders (`binders` bytes,
/// RFC 8446 section 4.2.11.2), under its offer's hash and key.
fn writeBinders(self: *const Client, transcripts: *const Transcripts, offers: []const Offer, hello: []u8, binders: usize) void {
    @setRuntimeSafety(true);
    if (offers.len == 0) return;
    const truncated = hello[0 .. hello.len - binders];
    var at = hello.len - binders + 2;
    for (offers) |offer| {
        at += 1;
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        const digest = transcripts.digestWith(&digest_buf, offer.binder_len, truncated);
        // The binder's schedule is the PSK's hash; any suite of that hash derives the same.
        switch (@as(Suite13, if (offer.binder_len == 48) .aes_256_gcm_sha384 else .aes_128_gcm_sha256)) {
            inline else => |tag| {
                const K = Schedule.Schedule(tag);
                K.binderOf(self.options.hello.transport.prefix(), offer.kind, offer.secret[0..K.length], digest[0..K.length], hello[at..][0..K.length]);
            },
        }
        at += offer.binder_len;
    }
}

/// A GREASE encrypted_client_hello (RFC 9849 section 6.2.1): a random config id, a supported
/// suite, a valid X25519 key and a random payload as long as this hello's encrypted inner form
/// would be. Kept, so a second hello repeats it.
fn makeGrease(self: *Client, shares: []const Hello.Share, resumption: Hello.Resume) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var drbg_owner: aegis.Secret(std.Random.ChaCha) = .init(.init(scratch.ech.seed.expose().*));
    defer drbg_owner.deinit();
    const drbg = drbg_owner.exposeMut();
    var draw: [34]u8 = undefined;
    drbg.fill(&draw);
    var key = Hpke.deriveKeyPair(draw[2..34]);
    defer key.deinit();
    // The length the inner hello would have, encoded and padded with no name bound.
    var options = self.options.hello;
    options.min_version = .tls13;
    var buf: Buffer = .{};
    defer buf.free(self.gpa);
    const encoded = try Hello.clientForm(try buf.ensure(self.gpa, self.helloCapacity(shares)), scratch.random.expose(), "", "", shares, "", options, resumption, .encoded);
    const payload_len = Ech.paddedLength(encoded.len - 4, options.sni.len, 0) + Hpke.tag_length;
    const suite: Hpke.Suite = .{ .kdf = .hkdf_sha256, .aead = if (draw[1] & 1 == 0) .aes_128_gcm else .chacha20_poly1305 };
    const ext = try self.gpa.alloc(u8, 8 + Hpke.enc_length + 2 + payload_len);
    errdefer self.gpa.free(ext);
    const written = try Ech.writeOuter(ext, suite, draw[0], &key.public, payload_len);
    drbg.fill(written[written.len - payload_len ..]);
    scratch.ech.ext = ext[0..written.len];
}

/// Random bytes in the shape of the inner hello's PSK offers, for the outer hello (RFC 9849
/// section 6.1.2), the same each time from the GREASE seed.
fn greasePsk(self: *const Client, offers: []const Offer, storage: []u8, out: *[Hello.max_psk_offers]Hello.GreasePsk) []const Hello.GreasePsk {
    @setRuntimeSafety(true);
    var drbg_owner: aegis.Secret(std.Random.ChaCha) = .init(.init(self.scratch.?.ech.seed.expose().*));
    defer drbg_owner.deinit();
    const drbg = drbg_owner.exposeMut();
    var skip: [34]u8 = undefined;
    drbg.fill(&skip);
    drbg.fill(storage);
    var at: usize = 0;
    for (offers, out[0..offers.len]) |offer, *grease| {
        const identity_len = offer.identity.len;
        grease.* = .{
            .identity = storage[at..][0..identity_len],
            .age = std.mem.readInt(u32, storage[at + identity_len ..][0..4], .big),
            .binder = storage[at + identity_len + 4 ..][0..offer.binder_len],
        };
        at += identity_len + 4 + offer.binder_len;
    }
    return out[0..offers.len];
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
    var offers_buf: [Hello.max_psk_offers]Offer = undefined;
    const offers = self.pskOffers(&offers_buf);
    var identities: [Hello.max_psk_offers]Hello.PskOffer = undefined;
    const resumption = self.resumeOffer(offers, &identities);
    const binders = resumption.bindersLength();
    const capacity = self.helloCapacity(shares) + 64;
    var inner_owner: Buffer = .{};
    defer inner_owner.free(self.gpa);
    const inner_buf = try inner_owner.ensure(self.gpa, capacity);
    const inner = try Hello.clientForm(inner_buf, scratch.random.expose(), session, "", shares, cookie, self.options.hello, resumption, .inner);
    self.writeBinders(&e.inner, offers, inner, binders);
    try e.inner.commitOwn(inner);
    // The encoded inner hello, padded (RFC 9849 section 6.1.3): its binders are the inner one's.
    var encoded_owner: Buffer = .{};
    defer encoded_owner.free(self.gpa);
    const encoded_buf = try encoded_owner.ensure(self.gpa, capacity + 255 + 9 + 32);
    const encoded = try Hello.clientForm(encoded_buf, scratch.random.expose(), session, "", shares, cookie, self.options.hello, resumption, .encoded);
    @memcpy(encoded[encoded.len - binders ..], inner[inner.len - binders ..]);
    const padded = Ech.paddedLength(encoded.len - 4, self.options.hello.sni.len, config.max_name_length);
    @memset(encoded_buf[encoded.len .. 4 + padded], 0);
    const plaintext = encoded_buf[4 .. 4 + padded];
    const payload_len = padded + Hpke.tag_length;
    const suite = config.suite().?;
    const first = e.context == null;
    if (first) {
        const info_buf = try self.gpa.alloc(u8, 8 + config.raw.len);
        defer self.gpa.free(info_buf);
        e.context = Hpke.setupSender(suite, config.public_key[0..Hpke.public_length], Ech.info(info_buf, config.raw), e.ikm.?.expose(), &e.enc) catch return error.InvalidOptions;
        e.ikm.?.deinit();
        e.ikm = null;
        echStep(e, .offer);
    }
    const ext_buf = try self.gpa.alloc(u8, 8 + Hpke.enc_length + 2 + payload_len);
    defer self.gpa.free(ext_buf);
    const ext = try Ech.writeOuter(ext_buf, suite, config.id, if (first) &e.enc else "", payload_len);
    var psk_len: usize = 0;
    for (offers) |offer| psk_len += offer.identity.len + 4 + offer.binder_len;
    const psk_buf = try self.gpa.alloc(u8, psk_len);
    defer self.gpa.free(psk_buf);
    var grease_buf: [Hello.max_psk_offers]Hello.GreasePsk = undefined;
    const grease = self.greasePsk(offers, psk_buf, &grease_buf);
    const dst = try self.reserve(capacity + ext.len + config.public_name.len + psk_buf.len + 64);
    const outer = try Hello.clientForm(dst, &e.outer_random, session, "", shares, cookie, self.options.hello, resumption, .{ .outer = .{ .name = config.public_name, .ext = ext, .psk = grease } });
    // Seal with the outer hello, payload zeroed, as the associated data (RFC 9849 section 5.2).
    const span = Ech.extensionSpan(outer, self.options.hello.transport) orelse unreachable; // unreachable: the outer form writes it
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
    const outer = try Hello.clientForm(dst, &scratch.ech.outer_random, scratch.session[0..scratch.session_len], "", shares, scratch.cookie[0..scratch.cookie_len], self.options.hello, resumption, .{ .outer = .{ .name = config.public_name, .ext = scratch.ech.ext, .psk = &.{} } });
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
    // A second retry request is unexpected_message whatever it asks (RFC 8446 section 4.1.4).
    if (self.retry_suite != null and msg.len >= 4 + 2 + 32 and std.mem.eql(u8, msg[6..38], &Hello.retry_random)) return error.UnexpectedMessage;
    var offered: [2]Hello.Share = undefined;
    const ech_sent = self.options.ech == .config_list or self.scratch.?.ech.ext.len != 0;
    var offers_buf: [Hello.max_psk_offers]Offer = undefined;
    const offers = self.pskOffers(&offers_buf);
    const answer = try Hello.server(msg, self.scratch.?.session[0..self.scratch.?.session_len], self.offeredShares(&offered), self.options.hello, .{ .psk = offers.len, .ticket12 = self.sendsTickets12() and self.retry_suite == null, .session12 = self.offered12 != null and self.retry_suite == null, .ech = ech_sent });
    const parsed = switch (answer) {
        // A DTLS 1.3 server never asks for a HelloVerifyRequest's cookie (RFC 9147 section 5.2).
        .tls13 => |hello| if (self.state.flags.verified != 0) return error.IllegalParameter else hello,
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
    if (self.options.ech == .config_list and self.scratch.?.ech.status.current() != .rejected) try self.decideEch(msg, parsed);
    if (self.retry_suite) |suite| if (suite != parsed.suite) return error.IllegalParameter;
    // A ticket not taken is spent all the same: it is never offered again.
    defer self.releaseOffer();
    var psk: ?[]const u8 = null;
    if (parsed.psk) |index| {
        const offer = offers[index];
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
                self.pin = entry.pin;
            },
            // The holder of the provisioned key is the peer: authenticated by it, with no X.509
            // identity and nothing to expire but the key itself, which is the caller's.
            .external, .imported => {
                self.external_used = true;
                self.authenticated = true;
                self.kept.psk_identity = self.options.external_psks[self.scratch.?.externals[offer.slot].key].identity;
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

            const key: ?*const [K.length]u8 = if (psk) |secret| secret[0..K.length] else null;
            self.keys = @unionInit(Keys, @tagName(suite), .{ .schedule = undefined, .handshake = .{} });
            errdefer self.keys = null;
            const k = &@field(self.keys.?, @tagName(suite));
            try k.schedule.init(self.options.hello.transport.prefix(), key, agreed.bytes(), hello_hash[0..Hash.digest_length], &k.handshake);
        },
    }
    self.eraseShares();
    // RFC 8446 appendix D.4: the dummy change_cipher_spec goes before the first record under
    // the handshake keys, whether that is the second flight or an alert refusing the server's.
    try self.sendCompatCcs();
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
            const expected = Ech.confirmation(Hash, self.options.hello.transport, scratch.random.expose(), Ech.accept_label, digest[0..Hash.digest_length]);
            break :blk aegis.secret.equal(8, &expected, msg[4 + 2 + 24 ..][0..8]).declassify("ECH acceptance shows in the keys that follow");
        },
    };
    if (e.context) |*context| context.deinit();
    e.context = null;
    if (accepted) {
        echStep(e, .accept);
        scratch.transcripts.deinit();
        e.inner.moveInto(&scratch.transcripts);
        e.inner = .{};
        self.ech_accepted = true;
        return;
    }
    // A retry request that accepted ECH binds the ServerHello to accept it too.
    if (e.status.current() == .accepted_retry) return error.IllegalParameter;
    echStep(e, .reject);
    // The handshake is the outer hello's now, and so is the random a key log names.
    scratch.random.exposeMut().* = e.outer_random;
    // The outer hello offered only a GREASE PSK: a server that selects it is lying.
    if (parsed.psk != null) return error.IllegalParameter;
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
    const emit = try self.claim();
    emit.* = .{ .secret = .{ .direction = direction, .epoch = epoch, .traffic = undefined } };
    self.makeTraffic(&emit.secret.traffic, suite, secret[0..len], label);
}

fn makeTraffic(self: *const Client, out: *Traffic, suite: Suite13, secret: []const u8, label: []const u8) void {
    @setRuntimeSafety(true);
    out.init(suite, secret);
    self.keyLog(label, secret);
}

pub fn keyLog(self: *const Client, label: []const u8, secret: []const u8) void {
    @setRuntimeSafety(true);
    const sink = self.options.key_log orelse return;
    var line_owner: aegis.Secret([256]u8) = .init(undefined);
    defer line_owner.deinit();
    const line = line_owner.exposeMut();
    const hex = "0123456789abcdef";
    var at: usize = 0;
    @memcpy(line[at..][0..label.len], label);
    at += label.len;
    line[at] = ' ';
    at += 1;
    for (self.scratch.?.random.expose()) |b| {
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
    sink.write(sink, line[0 .. at + 1]);
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
    // The parser bounds the cookie at 255 bytes.
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
    if (self.offered) |taken| if (suites.digestLength(taken.entry.suite.tls13().?) != suites.digestLength(parsed.suite)) self.releaseOffer13();
    // So can no provisioned key's offer of another hash (RFC 8446 section 4.1.4).
    for (self.scratch.?.externals, 0..) |external, slot| {
        if (external.hash.length() != suites.digestLength(parsed.suite)) self.external_live &= ~(@as(u8, 1) << @intCast(slot)); // at most eight slots
    }
    @memcpy(self.scratch.?.cookie[0..parsed.cookie.len], parsed.cookie);
    // Hello.server bounds the cookie at 4096 bytes.
    self.scratch.?.cookie_len = @intCast(parsed.cookie.len);
    if (parsed.group) |group| {
        self.retry_group = group;
        // The second hello carries the named group's share alone (RFC 8446 section 4.1.2).
        if (self.options.hello.grease) |*grease| grease.share = false;
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
        const at = @intFromPtr(got) - @intFromPtr(msg.ptr); // the confirmation is a slice of `msg`
        @memset(zeroed[at..][0..8], 0);
        var confirm = e.inner.fork();
        defer confirm.deinit();
        try confirm.retry(zeroed);
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        switch (parsed.suite) {
            inline else => |tag| {
                const Hash = suites.Hash(tag);
                const digest = confirm.digest(&digest_buf);
                const expected = Ech.confirmation(Hash, self.options.hello.transport, scratch.random.expose(), Ech.retry_accept_label, digest[0..Hash.digest_length]);
                accepted = aegis.secret.equal(8, &expected, got).declassify("ECH acceptance shows in the keys that follow");
            },
        }
    }
    if (accepted) {
        echStep(e, .accept_retry);
        try e.inner.retry(msg);
        return;
    }
    echStep(e, .reject);
    scratch.random.exposeMut().* = e.outer_random;
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
    scratch.peer_cid_len = @intCast(cid.len); // a vector<0..255>
    scratch.cid_agreed = true;
}

fn onEncrypted(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.encrypted_extensions, epoch, .parsed, boundary);
    const e = &self.scratch.?.ech;
    const parsed = try Hello.encrypted(msg, self.options.hello, self.options.ech == .config_list or e.ext.len != 0);
    if (parsed.ech) |list| switch (e.status.current()) {
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
    try self.limitRecords(parsed.record_size_limit, .tls13);
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
    // At most 1024 bytes are kept.
    self.scratch.?.cr_len = @intCast(keep);
    if (parsed.delegated) |list| {
        const kept = @min(list.len, self.scratch.?.cr_delegated.len) & ~@as(usize, 1);
        @memcpy(self.scratch.?.cr_delegated[0..kept], list[0..kept]);
        // At most 1024 bytes are kept.
        self.scratch.?.cr_delegated_len = @intCast(kept);
    }
    self.scratch.?.cr_named = self.namedCredentials(parsed.authorities);
}

/// Which credentials chain to an authority a CertificateRequest named (`authorities`, null for
/// none), a bit each.
pub fn namedCredentials(self: *const Client, authorities: ?[]const u8) ?u32 {
    @setRuntimeSafety(true);
    const names = authorities orelse return null;
    var named: u32 = 0;
    for (self.kept.credentials, 0..) |credential, i| {
        if (Authorities.chains(credential.auth.identity, names)) named |= Authorities.bit(i);
    }
    return named;
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
    const parsed = try Messages.certificate(self.held, limits.certificates, limits.chain_bytes, &self.scratch.?.chain, .{ .delegated = self.options.hello.accept_delegated, .scts = self.options.hello.request_scts, .ocsp = self.options.hello.request_ocsp });
    if (parsed.context.len != 0) return error.IllegalParameter;
    if (parsed.count == 0) return error.EmptyCertificate;
    self.scratch.?.chain_len = parsed.count;
    self.scratch.?.delegated = parsed.leaf.delegated;
    try self.keepScts(parsed.leaf.scts);
    try self.keepOcsp(parsed.leaf.ocsp);
    if (self.scratch.?.peer_raw) {
        // One entry, a SubjectPublicKeyInfo the policy pins (RFC 7250 section 3).
        self.pin = try Possession.pinnedKey(self.scratch.?.chain[0..parsed.count], self.options.verify.raw_key.pins);
        try self.scratch.?.transcripts.commit(msg);
        try self.state.advance(.verify_chain, .handshake, .chain, true);
        self.authenticated = true;
        return;
    }
    try self.scratch.?.transcripts.commit(msg);
    switch (self.options.verify) {
        .none => try self.state.advance(.verify_chain, .handshake, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
        .leaf_key => |leaf| {
            // The leaf's key is the trust: its pin, and nothing else of the chain.
            self.pin = try Possession.pinnedLeaf(self.scratch.?.chain[0], leaf.pins);
            try self.state.advance(.verify_chain, .handshake, .chain, true);
            self.authenticated = true;
        },
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
    } else {
        var taken: [Hello.max_peer_schemes]Hello.SignatureScheme = undefined;
        try Possession.verifyKey(parsed.scheme, Hello.peerSchemes(self.options.hello.peer_schemes, Hello.verifySchemes(self.options.hello), &taken), try Possession.peerKey(self.scratch.?.chain[0], self.scratch.?.peer_raw), content, parsed.signature);
    }
    self.peer_scheme = @fromBackingInt(parsed.scheme);
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try self.scratch.?.transcripts.commit(msg);
    if (self.options.keep_peer_leaf) try Possession.keepLeaf(self.gpa, &self.peer_leaf, self.scratch.?.chain[0], self.scratch.?.peer_raw);
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
            try self.state.advance(.finished, epoch, .finished, boundary);
            try self.scratch.?.transcripts.commit(msg);
            var after_buf: [Transcripts.max_digest]u8 = undefined;
            const after = self.scratch.?.transcripts.digest(&after_buf);
            var app: @TypeOf(k.schedule).Traffic = .{};
            defer app.deinit();
            try k.schedule.application(after[0..Hash.digest_length], &app);
            const len = Hash.digest_length;
            try self.install(.read, .application, tag, len, app.server.expose(), "SERVER_TRAFFIC_SECRET_0");
            self.app_write = @as(Traffic, undefined);
            self.makeTraffic(&self.app_write.?, tag, app.client.expose()[0..len], "CLIENT_TRAFFIC_SECRET_0");
            self.keyLog("EXPORTER_SECRET", k.schedule.exporter.expose());
        },
    }
    try self.continueFlight();
}

/// The server rejected ECH and the handshake with the outer hello is complete, the client's
/// flight queued, the public name authenticated or not. The connection never reaches the
/// application: it ends with ech_required (`Emit.rejected`), and the retry configurations are
/// released only when the public name was authenticated (RFC 9849 sections 6.1.6 and 6.1.7).
fn endRejected(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const e = &self.scratch.?.ech;
    if (self.authenticated and self.options.verify == .full) {
        self.ech_retry = e.retry_list;
        e.retry_list = &.{};
    }
    self.authenticated = false;
    try self.push(.rejected);
}

/// The client's second flight: the response to a CertificateRequest, then Finished. After an
/// ECH rejection a CertificateRequest is answered with an empty Certificate: no certificate goes
/// to a name the client did not ask for (RFC 9849 section 6.1.7).
fn continueFlight(self: *Client) Error!void {
    @setRuntimeSafety(true);
    if (!self.requested_certificate) return self.finishFlight();
    if (self.echRejected()) return self.sendEmptyCertificate();
    const chosen = self.chooseCredential() orelse return self.sendEmptyCertificate();
    self.credential = @intCast(chosen.index); // at most 32 credentials
    const auth = self.kept.credentials[chosen.index].auth;
    const delegated: ?Delegation.Credential = if (chosen.value.delegating) self.kept.credentials[chosen.index].delegated.? else null;
    const scheme = chosen.value.scheme;
    var total: usize = 64;
    for (auth.entries()) |der| total += der.len + 5;
    if (delegated) |credential| total += credential.wire().len + 4;
    const dst = try self.reserve(total);
    const message_bytes = try Messages.buildCertificate(dst, "", auth.entries(), .{ .delegated = if (delegated) |credential| credential.wire() else null });
    try self.state.advance(.local_certificate, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message_bytes);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const content = Messages.signedContent(self.scratch.?.sign_content.exposeMut(), false, self.scratch.?.transcripts.digest(&digest_buf));
    // Signed content is at most 64 + 33 + 1 + 48 bytes.
    self.scratch.?.sign_content_len = @intCast(content.len);
    self.sign_scheme = scheme;
    if (delegated) |credential| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = credential.sign(content, self.scratch.?.sign_noise.expose()[0..credential.noiseLength()], &out) catch return error.SigningFailed;
        return self.sendCertificateVerify(signature);
    }
    // Cloak signs for a key it holds; a key held elsewhere is the caller's to sign with.
    if (auth.identity.noiseLength()) |noise_length| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = Possession.sign(auth.identity, scheme, content, self.scratch.?.sign_noise.expose()[0..noise_length], &out) catch return error.SigningFailed;
        return self.sendCertificateVerify(signature);
    }
    self.need_now = .sign;
}

/// The credential a CertificateRequest is answered with (RFC 8446 section 4.4.2): of a form the
/// server selected (RFC 7250), with its delegated credential while the server lists a scheme for
/// it and it is valid (RFC 9345 section 4.1.2), or a scheme the server lists for its key; of those
/// the first that chains to an authority the server named (section 4.2.4), else the first.
fn chooseCredential(self: *const Client) ?Authorities.Pick(Possession.Fit).Choice {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const request: Messages.CertificateRequest = .{ .context = "", .schemes = scratch.cr_schemes[0..scratch.cr_len] };
    var pick: Authorities.Pick(Possession.Fit) = .{};
    for (self.kept.credentials, 0..) |credential, i| {
        if ((credential.auth.identity.form() == .raw_public_key) != scratch.client_raw) continue;
        if (credential.must_match_issuer and !Authorities.required(scratch.cr_named, i)) continue;
        const fit: Possession.Fit = fit: {
            if (credential.delegated) |delegated| if (scratch.cr_delegated_len) |listed| if (self.now) |now| {
                if (delegated.usable(types.seconds(now), scratch.cr_delegated[0..listed], request)) break :fit .{ .scheme = delegated.keyScheme(), .delegating = true };
            };
            break :fit .{ .scheme = Possession.choose(credential.auth.identity.publicKey(), credential.schemes, request) orelse continue };
        };
        if (pick.offer(i, fit, Authorities.marked(scratch.cr_named, i))) break;
    }
    return pick.chosen();
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
            const emit = try self.claim();
            emit.* = .{ .secret = .{ .direction = .write, .epoch = .application, .traffic = undefined } };
            self.app_write.?.moveInto(&emit.secret.traffic);
            self.app_write = null;
            var finished_buf: [Transcripts.max_digest]u8 = undefined;
            try k.schedule.complete(self.scratch.?.transcripts.digest(&finished_buf)[0..Hash.digest_length]);
            k.handshake.deinit();
            // Every later exchange starts from the transcript through this Finished.
            if (self.options.hello.post_handshake_auth) self.post_auth = try PostAuth.init(self.gpa, .client, tag, &self.scratch.?.transcripts, self.scratch.?.client_raw, false, &.{}, &.{});
        },
    }
    if (self.echRejected()) return self.endRejected();
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
    const max_age = types.spanSeconds(resumption.max_age);
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
                .received_ms = types.milliseconds(now),
                .expires = expires,
                .origin = self.origin,
                .auth_expires = self.auth_expires,
                .authenticated = self.authenticated,
                .pin = self.pin,
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
    return self.postAnswered(post.onRequest(msg, self.kept.credentials));
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
        .external_psk = if (self.external_used) self.kept.psk_identity else null,
        .srtp = self.srtp,
        .pin = self.pin,
        .peer_scheme = self.peer_scheme,
        .delegated_credential = self.delegated_used,
        .credential = self.credential,
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
