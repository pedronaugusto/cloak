//! The TLS 1.3 server handshake. Like the client it takes whole handshake messages with their
//! epoch and record alignment and queues messages, traffic secrets and requests for the
//! services it never performs itself: entropy, time, client verification and, for a key cloak
//! does not hold, signing. A key it holds signs inside the machine. Policy
//! lives in `Options`; the checked state table, transcript and key schedule are the same ones
//! the client uses.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const suites = @import("../crypto/Suite.zig");
const Suite13 = suites.Suite13;
const Suite = suites.Suite;
const Version = suites.Version;
const Labels = @import("../crypto/Labels.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Group = @import("../crypto/Group.zig").Group;
const Client = @import("Client.zig");
const ClientHello = @import("ClientHello.zig");
const Flight = @import("Flight.zig");
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const Possession = @import("Possession.zig");
const Schedule = @import("Schedule.zig");
const State = @import("State.zig");
const Transcripts = @import("Transcripts.zig");
const Messages12 = @import("Messages12.zig");
const Server12 = @import("Server12.zig");
const Ticket = @import("../resumption/Ticket.zig");
const Ech = @import("Ech.zig");
const Compression = @import("Compression.zig");
const Psk = @import("Psk.zig");
const Hpke = @import("../crypto/Hpke.zig");

pub const Epoch = Flight.Epoch;
pub const Emit = Flight.Emit;
pub const Traffic = Flight.Traffic;
pub const Need = Client.Need;
pub const SignRequest = Client.SignRequest;
pub const Verify = Client.Verify;
pub const Limits = Client.Limits;
pub const KeyLog = Client.KeyLog;
pub const Auth = State.Auth;
pub const TicketKeys = @import("../resumption/TicketKeys.zig");

/// A certificate chain the server can present, or a raw public key (RFC 7250, TLS 1.3, for a
/// client that asks for one), and the names it answers for.
pub const Credential = struct {
    identity: certificates.Identity,
    /// Server names this identity answers for: exact, or `*.` plus a domain for one label.
    /// An identity without names answers for any name.
    names: []const []const u8 = &.{},
};

pub const Options = struct {
    /// Suites of both versions in the server's order of preference.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions accepted; TLS 1.3 is preferred whenever the client offers it.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    /// Groups in the server's order of preference.
    groups: []const Group = Group.default,
    /// Application protocols in the server's order of preference. When set and the client offers
    /// some, one must match.
    alpn: []const []const u8 = &.{},
    /// Fail when the client offers no protocol at all.
    require_alpn: bool = false,
    require_hybrid: bool = false,
    /// The client authenticates with ML-DSA (`Hello.Options.require_pq_auth`): it needs a
    /// required, verified client certificate, and TLS 1.3.
    require_pq_auth: bool = false,
    /// Set by the carrier: `Connection` is a stream, `quic.Handshake` QUIC, `dtls.Datagram` a datagram.
    transport: suites.Transport = .stream,
    /// The server's QUIC transport parameters.
    parameters: []const u8 = "",
    /// The first answers when no name matches or none was sent. None only with `external_psk`:
    /// such a server authenticates by provisioned keys alone.
    credentials: []const Credential,
    /// What to do with a server name no credential answers for.
    unknown_name: enum { first, reject } = .first,
    client_auth: Auth = .none,
    /// How a presented client chain is checked; `none` accepts any chain unauthenticated.
    client_verify: Verify = .none,
    /// Session tickets: issued after each TLS 1.3 handshake and resumed from (PSK-DHE). The
    /// ring is shared, and must outlive the connections using it.
    tickets: ?*TicketKeys = null,
    /// TLS 1.2 session tickets too (RFC 5077), from the same ring. An abbreviated TLS 1.2
    /// handshake reuses the session's master secret with no new key exchange: off unless asked.
    tls12_tickets: bool = false,
    /// Encrypted Client Hello (RFC 9849, shared mode): the configs this server decrypts with,
    /// at most `Ech.max_keys`, borrowed for the life of the connection. A client whose ECH does
    /// not decrypt is answered with the configs marked `retry`.
    ech_keys: []const Ech.Key = &.{},
    /// Certificate encoders (RFC 8879), in the server's order of preference: the first whose
    /// algorithm the client lists compresses the Certificate, when that makes it smaller.
    certificate_compression: []const Compression.Codec = &.{},
    /// Provisioned keys, looked up by the identity a client offers, for the version negotiated:
    /// TLS 1.3 PSK-DHE, tried before tickets; TLS 1.2 plain PSK when a PSK suite is listed and
    /// chosen. A client that proves one is authenticated by it, with no certificate either way,
    /// and is issued no tickets.
    external_psk: ?Psk.Lookup = null,
    /// DTLS: connection_id (RFC 9146), answered when a client offers it. Null answers none;
    /// otherwise the connection ID this server receives records with, borrowed; empty: it sends
    /// with the client's but takes none.
    connection_id: ?[]const u8 = null,
    /// DTLS: the SRTP profiles accepted (RFC 5764), in preference order: the first the client
    /// offered is chosen. None answers no use_srtp.
    srtp: []const Hello.Srtp = &.{},
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Info = Client.Info;

/// Tickets sent after each handshake (design: at most two).
pub const tickets_per_handshake = 2;
/// Entropy each ticket draws: its sealing salt and its age obfuscator.
pub const ticket_entropy = Ticket.salt_length + 4;

pub const InitError = Hello.ValidateError || std.mem.Allocator.Error || error{InvalidOptions};
pub const Error = Client.Error || Flight.Error || ClientHello.ParseError || error{
    NoSharedGroup,
    NoSharedSuite,
    NoSignatureScheme,
    UnrecognizedName,
    CertificateRequired,
    UnexpectedCookie,
};

const Server = @This();

gpa: std.mem.Allocator,
options: Options,
state: State.State,
need_now: Need = .none,
/// What follows once the client's QUIC transport parameters are accepted.
deferred: Need = .none,
parameters_accepted: bool = false,
post: ?Emit = null,
held: []u8 = &.{},
scratch: ?*Scratch = null,
suite: ?Suite13 = null,
group: ?Group = null,
alpn: []const u8 = "",
/// DTLS: the SRTP profile chosen.
srtp: ?Hello.Srtp = null,
credential: usize = 0,
scheme: Hello.SignatureScheme = .ed25519,
keys: ?Keys = null,
peer_parameters: []u8 = &.{},
now: ?std.Io.Timestamp = null,
authenticated: bool = false,
/// The index of the pin the client's raw public key matched (RFC 7250).
raw_pin: ?u16 = null,
peer_certificate: bool = false,
established: bool = false,
retried: bool = false,
/// The ClientHello is final (not answered by a retry request): the client may send nothing more
/// at the initial level.
answered: bool = false,
ccs_sent: bool = false,
app_read: ?Traffic = null,
server_name_copy: []const u8 = &.{},
/// The handshake resumed a session from a ticket.
resumed: bool = false,
/// DTLS: the message_seq of the client's hello, from which DTLS 1.2 numbers both sides'
/// messages in its transcript (RFC 6347 section 4.2.2). The carrier sets it.
first_sequence: u16 = 0,
ech_accepted: bool = false,
/// The handshake uses a provisioned key: TLS 1.3 once its binder checked, TLS 1.2 once a PSK
/// suite is chosen (the key itself proves at the client's Finished).
external: bool = false,
/// DTLS: the first hello was answered statelessly (`resumeRetry`), so the second is also the
/// first this server sees whole: what a first hello records is recorded from it.
stateless_retry: bool = false,
// TLS 1.2.
version: suites.Version = .tls13,
suite12: ?suites.Suite12 = null,
/// TLS 1.2 secrets that outlive the handshake (the exporter needs them), allocated only for a
/// TLS 1.2 connection.
tls12: ?*Flight.Secrets12 = null,

const Scratch = struct {
    flight: Flight = .{},
    transcripts: Transcripts = .{},
    client_random: [32]u8 = @splat(0),
    session: [32]u8 = @splat(0),
    session_len: u8 = 0,
    server_name: [253]u8 = undefined,
    server_name_len: u8 = 0,
    /// TLS 1.2: the client sent ec_point_formats, so the ServerHello answers it.
    point_formats: bool = false,
    /// The client's key share for the chosen group.
    share: [Exchange.max_share]u8 = undefined,
    share_len: usize = 0,
    first: [32]u8 = @splat(0),
    retry_group: ?Group = null,
    chain: [Messages.max_certificates][]const u8 = undefined,
    chain_len: usize = 0,
    sign_content: [Messages.max_signed]u8 = undefined,
    sign_content_len: u8 = 0,
    /// Fresh noise for the hedged signature, when the credential's key signs here.
    sign_noise: [certificates.PrivateKey.max_noise]u8 = @splat(0),
    /// The resumed session's PSK, and each ticket's salt and age obfuscator.
    psk: aegis.Secret([48]u8) = .init(@splat(0)),
    ticket_entropy: [tickets_per_handshake * ticket_entropy]u8 = @splat(0),
    /// The offered identity the ServerHello selects.
    psk_index: u16 = 0,
    /// The ClientHello is held until the clock answers: tickets are opened and issued by it.
    hello_held: bool = false,
    /// The client sent psk_key_exchange_modes with PSK-DHE: tickets may be issued.
    takes_tickets: bool = false,
    /// The client offered early data, which this server never accepts: its records are skipped.
    early_offered: bool = false,
    /// Seconds: when the session's tickets expire (from its full handshake), and when the
    /// client's authentication expires.
    session_expires: i64 = std.math.maxInt(i64),
    client_auth_expires: i64 = std.math.maxInt(i64),
    /// Client signature_algorithms, kept to pick the CertificateVerify scheme.
    schemes: [256]u8 = undefined,
    schemes_len: u16 = 0,
    /// The server flight is built; only the CertificateVerify signature is missing.
    signing: bool = false,
    // TLS 1.2: the server's ECDHE share and the ServerKeyExchange content it signs.
    share12: ?Exchange.Share = null,
    params12: [Messages12.max_signed]u8 = undefined,
    params12_len: u8 = 0,
    ech: EchScratch = .{},
    /// The client's compress_certificate list, when it sent one.
    compression: [255]u8 = undefined,
    compression_len: u8 = 0,
    /// DTLS: the client offered connection_id and this server answers it: the client's
    /// connection ID, which records this server sends carry.
    peer_cid: [255]u8 = undefined,
    peer_cid_len: u8 = 0,
    cid_agreed: bool = false,
    /// RFC 7250: the certificate types EncryptedExtensions answers, and whether the client's
    /// Certificate is a raw key.
    server_type: ?Hello.CertificateType = null,
    client_type: ?Hello.CertificateType = null,
    peer_raw: bool = false,
};

/// Encrypted Client Hello on the server: whether the first hello's ECH decrypted, the HPKE
/// context a second hello opens under, and the ClientHelloInner in use.
const EchScratch = struct {
    status: enum { none, accepted, rejected } = .none,
    suite: Hpke.Suite = undefined,
    config_id: u8 = 0,
    context: ?Hpke.Context = null,
    inner: []u8 = &.{},
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

pub fn init(gpa: std.mem.Allocator, options: Options) InitError!*Server {
    @setRuntimeSafety(true);
    try Hello.validate(.{ .suites = options.suites, .min_version = options.min_version, .max_version = options.max_version, .groups = options.groups, .alpn = options.alpn, .require_alpn = options.require_alpn or options.transport == .quic, .require_hybrid = options.require_hybrid, .require_pq_auth = options.require_pq_auth, .transport = options.transport, .parameters = options.parameters, .connection_id = options.connection_id, .srtp = options.srtp });
    // Provisioned keys may be a server's only authentication; otherwise it needs a credential.
    if (options.credentials.len > 32 or (options.credentials.len == 0 and options.external_psk == null)) return error.InvalidOptions;
    if (options.require_pq_auth and (options.client_auth != .required or options.client_verify == .none)) return error.InvalidOptions;
    switch (options.client_verify) {
        .raw_key => |raw| if (raw.pins.len == 0 or raw.pins.len > Verify.RawKey.max_pins or options.client_auth == .none) return error.InvalidOptions,
        else => {},
    }
    for (options.credentials) |credential| for (credential.names) |name| {
        if (name.len == 0 or name.len > 253) return error.InvalidOptions;
    };
    if (options.client_auth != .none and options.client_verify == .full and options.client_verify.full.limits.certificates == 0) return error.InvalidOptions;
    if (options.limits.message < 1024 or options.limits.handshake < options.limits.message or options.limits.certificates == 0) return error.InvalidOptions;
    // The TLS 1.2 PSK suites are spoken only with provisioned keys to complete them.
    for (options.suites) |suite| if (suite.tls12()) |s12| if (s12.authentication() == .psk and options.external_psk == null) return error.InvalidOptions;
    Ech.checkKeys(options.ech_keys) catch return error.InvalidOptions;
    Compression.validate(options.certificate_compression, .compress) catch return error.InvalidOptions;
    // ECH is TLS 1.3: a server that cannot speak it has no use for the keys.
    if (options.ech_keys.len != 0 and (options.max_version != .tls13 or options.transport == .datagram)) return error.InvalidOptions;
    const self = try gpa.create(Server);
    errdefer gpa.destroy(self);
    // The credential table is copied; the names it points at and the identities (retained below)
    // are the caller's to keep alive.
    const credentials = try gpa.dupe(Credential, options.credentials);
    errdefer gpa.free(credentials);

    self.* = .{
        .gpa = gpa,
        .options = options,
        .state = server_state: {
            var state = State.State.init(.server, options.transport);
            state.auth = options.client_auth;
            break :server_state state;
        },
    };
    self.options.credentials = credentials;
    for (credentials) |credential| _ = credential.identity.retain();
    return self;
}

pub fn deinit(self: *Server) void {
    @setRuntimeSafety(true);
    const gpa = self.gpa;
    self.wipe();
    for (self.options.credentials) |credential| credential.identity.deinit();
    gpa.free(self.options.credentials);
    self.* = undefined;
    gpa.destroy(self);
}

/// Erases secrets and releases buffers.
pub fn wipe(self: *Server) void {
    @setRuntimeSafety(true);
    self.releaseScratch();
    if (self.post) |*emit| Flight.eraseEmit(emit);
    self.post = null;
    if (self.app_read) |*traffic| traffic.secret.deinit();
    self.app_read = null;
    if (self.tls12) |secrets| secrets.destroy(self.gpa);
    self.tls12 = null;
    if (self.keys) |*keys| switch (keys.*) {
        inline else => |*k| {
            k.schedule.deinit();
            k.handshake.deinit();
        },
    };
    self.keys = null;
    if (self.held.len != 0) {
        self.gpa.free(self.held);
        self.held = &.{};
    }
    if (self.peer_parameters.len != 0) {
        self.gpa.free(self.peer_parameters);
        self.peer_parameters = &.{};
    }
    if (self.server_name_copy.len != 0) {
        self.gpa.free(self.server_name_copy);
        self.server_name_copy = &.{};
    }
    self.state.fail();
}

fn startScratch(self: *Server) std.mem.Allocator.Error!*Scratch {
    @setRuntimeSafety(true);
    const scratch = try self.gpa.create(Scratch);
    scratch.* = .{};
    self.scratch = scratch;
    return scratch;
}

fn releaseScratch(self: *Server) void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse return;
    if (scratch.share12) |*share| share.deinit();
    scratch.share12 = null;
    if (scratch.ech.context) |*context| context.deinit();
    if (scratch.ech.inner.len != 0) {
        std.crypto.secureZero(u8, scratch.ech.inner);
        self.gpa.free(scratch.ech.inner);
    }
    scratch.flight.deinit(self.gpa);
    scratch.transcripts.release();
    scratch.psk.deinit();
    std.crypto.secureZero(u8, std.mem.asBytes(scratch));
    self.gpa.destroy(scratch);
    self.scratch = null;
}

/// A ChangeCipherSpec record arrived; only TLS 1.2 expects one, once, before the client's Finished.
pub fn receiveCcs(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() == .failed) return error.Closed;
    if (self.version != .tls12) return error.UnexpectedMessage;
    errdefer self.state.fail();
    return Server12.onCcs(self);
}

pub fn compat(self: *const Server) bool {
    const scratch = self.scratch orelse return false;
    return scratch.session_len != 0;
}

pub fn need(self: *const Server) Need {
    return self.need_now;
}

// ---------------------------------------------------------------- services

/// Answers an entropy request: the server random and the key exchange. `InvalidEntropy` is
/// public (a scalar draw outside its range) and leaves the request open.
pub fn provideEntropy(self: *Server, entropy: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const expected = switch (self.need_now) {
        .entropy => |e| e.len,
        else => return error.UnexpectedService,
    };
    if (entropy.len != expected) return error.InvalidEntropy;
    if (self.version == .tls12) return Server12.onEntropy(self, entropy);
    const group = self.group.?;
    const exchange_end = 32 + Exchange.respondEntropyLength(group);
    var response = Exchange.respond(group, scratch.share[0..scratch.share_len], entropy[32..exchange_end]) catch |err| return switch (err) {
        error.InvalidEntropy => error.InvalidEntropy,
        error.InvalidShare => error.InvalidShare,
        error.WeakKey => error.WeakKey,
    };
    defer response.deinit();
    self.need_now = .none;
    const noise_end = exchange_end + if (self.pskMode()) 0 else self.signNoiseLength();
    @memcpy(scratch.sign_noise[0 .. noise_end - exchange_end], entropy[exchange_end..noise_end]);
    @memcpy(scratch.ticket_entropy[0 .. entropy.len - noise_end], entropy[noise_end..]);
    try self.sendServerFlight(entropy[0..32], &response);
}

pub fn provideTime(self: *Server, now: std.Io.Timestamp) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .time) return error.UnexpectedService;
    self.now = now;
    self.need_now = .none;
    if (self.scratch.?.hello_held) {
        // The ClientHello waited for the clock; it was parsed and checked once already.
        errdefer self.state.fail();
        self.scratch.?.hello_held = false;
        const hello = ClientHello.parse(self.held, self.options.transport) catch unreachable; // unreachable: these bytes parsed before
        if (self.version == .tls12) return Server12.answer(self, self.held, &hello);
        return self.answerHello(self.held, &hello);
    }
    self.need_now = .verify;
}

/// The verification request for the pending client chain; valid while `need` is `.verify`.
pub fn verification(self: *const Server, token: types.Token) types.Request {
    @setRuntimeSafety(true);
    const full = self.options.client_verify.full;
    const scratch = self.scratch.?;
    return .{
        .chain = scratch.chain[0..scratch.chain_len],
        .identity = .none,
        .purpose = .client,
        .time = self.now.?,
        .trust_generation = full.trust_generation,
        .policy_generation = full.policy_generation,
        .token = token,
        .mode = .full,
        .policy = full.policy,
        .pins = full.pins,
        .evidence = full.evidence,
        .limits = full.limits,
        .anchor_policies = full.anchor_policies,
    };
}

pub fn provideVerification(self: *Server, token: types.Token, receipt: *const types.Verification) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .verify) return error.UnexpectedService;
    receipt.check(self.verification(token)) catch return error.VerificationRejected;
    if (self.options.require_pq_auth and !Possession.postQuantumPath(receipt.path)) return error.PqAuthenticationRequired;
    try self.state.advance(.verify_chain, if (self.version == .tls12) .initial else .handshake, .chain, true);
    self.authenticated = true;
    self.scratch.?.client_auth_expires = types.seconds(receipt.expires);
    if (receipt.revocation_expires) |until| self.scratch.?.client_auth_expires = @min(self.scratch.?.client_auth_expires, types.seconds(until));
    self.need_now = .none;
}

pub fn rejectVerification(self: *Server) void {
    self.state.fail();
    self.need_now = .none;
}

pub fn signRequest(self: *const Server) SignRequest {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (self.version == .tls12) return .{ .scheme = self.scheme, .content = scratch.params12[0..scratch.params12_len] };
    return .{ .scheme = self.scheme, .content = scratch.sign_content[0..scratch.sign_content_len] };
}

/// Checks the signature against the credential's public key before it is used.
pub fn provideSignature(self: *Server, signature: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .sign) return error.UnexpectedService;
    if (self.version == .tls12) return Server12.onSignature(self, signature);
    const key = self.options.credentials[self.credential].identity.publicKey();
    Possession.verifyKey(@backingInt(self.scheme), &.{self.scheme}, key, self.signRequest().content, signature) catch return error.BadSignature;
    try self.sendCertificateVerify(signature);
    self.need_now = .none;
}

fn sendCertificateVerify(self: *Server, signature: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const dst = try scratch.flight.reserve(self.gpa, 8 + signature.len, self.options.limits.handshake);
    const built = try Messages.buildCertificateVerify(dst, @backingInt(self.scheme), signature);
    try self.state.advance(.certificate_verify, .handshake, .possession, true);
    try self.queueMessage(.handshake, built);
    try self.finishFlight();
}

/// The fresh noise the chosen credential's signature draws with the key exchange's entropy; zero
/// when its key is held elsewhere or signs without noise.
pub fn signNoiseLength(self: *const Server) usize {
    return self.options.credentials[self.credential].identity.noiseLength() orelse 0;
}

pub fn provideParameters(self: *Server, accept: bool) Client.Error!void {
    if (self.need_now != .parameters) return error.UnexpectedService;
    if (!accept) return error.ParametersRejected;
    self.parameters_accepted = true;
    self.need_now = self.deferred;
    self.deferred = .none;
}

// ---------------------------------------------------------------- outputs

/// Moves the next output into `out`; see `Flight.pop`.
pub fn pop(self: *Server, out: *Emit) bool {
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

pub fn pending(self: *const Server) bool {
    const scratch = self.scratch orelse return self.post != null;
    return scratch.flight.pending();
}

pub fn flightBytes(self: *const Server, start: u32, len: u32) []const u8 {
    return self.scratch.?.flight.bytes(start, len);
}

pub fn recycle(self: *Server) void {
    if (self.scratch) |scratch| scratch.flight.recycle();
}

pub fn push(self: *Server, emit: Emit) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        if (self.post != null) return error.QueueFull;
        self.post = emit;
        return;
    };
    try scratch.flight.push(emit);
}

pub fn reserve(self: *Server, want: usize) Client.Error![]u8 {
    return self.scratch.?.flight.reserve(self.gpa, want, self.options.limits.handshake);
}

pub fn queueMessage(self: *Server, epoch: Epoch, wire: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    try self.scratch.?.transcripts.commitOwn(wire);
    try self.scratch.?.flight.queueMessage(epoch, wire.len);
}

fn install(self: *Server, direction: Flight.Direction, epoch: Epoch, suite: Suite13, len: usize, secret: []const u8, label: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    var made = self.makeTraffic(suite, len, secret, label);
    errdefer made.secret.deinit();
    try self.push(.{ .secret = .{ .direction = direction, .epoch = epoch, .traffic = made } });
}

fn makeTraffic(self: *const Server, suite: Suite13, len: usize, secret: []const u8, label: []const u8) Traffic {
    @setRuntimeSafety(true);
    var holder = aegis.Secret([Transcripts.max_digest]u8).init(@splat(0));
    @memcpy(holder.exposeMut()[0..len], secret[0..len]);
    self.keyLog(label, secret[0..len]);
    // safe: the secret length is a digest length, at most 48.
    return .{ .suite = suite, .secret = holder, .len = @intCast(len) };
}

pub fn keyLog(self: *const Server, label: []const u8, secret: []const u8) void {
    @setRuntimeSafety(true);
    const sink = self.options.key_log orelse return;
    const scratch = self.scratch orelse return;
    var line: [256]u8 = undefined;
    defer std.crypto.secureZero(u8, &line);
    const hex = "0123456789abcdef";
    var at: usize = 0;
    @memcpy(line[at..][0..label.len], label);
    at += label.len;
    line[at] = ' ';
    at += 1;
    for (scratch.client_random) |b| {
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

// ---------------------------------------------------------------- input

/// Consumes one complete handshake message; `boundary` says it ended exactly at its record.
pub fn receive(self: *Server, bytes_in: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() == .failed) return error.Closed;
    if (self.need_now != .none) return error.Pending;
    errdefer self.state.fail();
    if (bytes_in.len > self.options.limits.message) return error.HandshakeLimit;
    const parsed = try Messages.body(bytes_in);
    if (self.version == .tls12) return Server12.receive(self, parsed.kind, bytes_in, epoch, boundary);
    switch (parsed.kind) {
        .client_hello => try self.onClientHello(bytes_in, epoch, boundary),
        .certificate => try self.onCertificate(bytes_in, epoch, boundary),
        .certificate_verify => try self.onCertificateVerify(bytes_in, epoch, boundary),
        .finished => try self.onFinished(bytes_in, epoch, boundary),
        .key_update => try self.onKeyUpdate(bytes_in, epoch, boundary),
        else => return error.UnexpectedMessage,
    }
}

/// The forms of credential a client takes (RFC 7250's server_certificate_type).
pub const Forms = struct { x509: bool, raw_public_key: bool };

/// The first credential of a form the client takes that answers for `name`.
pub fn credentialFor(self: *const Server, name: []const u8, forms: Forms) ?usize {
    @setRuntimeSafety(true);
    for (self.options.credentials, 0..) |credential, i| {
        if (!admits(forms, credential.identity)) continue;
        if (credential.names.len == 0) return i;
        for (credential.names) |pattern| if (nameMatches(pattern, name)) return i;
    }
    return null;
}

fn admits(forms: Forms, identity: certificates.Identity) bool {
    return switch (identity.form()) {
        .x509 => forms.x509,
        .raw_public_key => forms.raw_public_key,
    };
}

/// The credential answering `name`; without one, the first of a form the client takes, or
/// unrecognized_name when the server says so. None of a form it takes is unsupported_certificate.
pub fn chooseCredential(self: *const Server, name: []const u8, forms: Forms) Client.Error!usize {
    @setRuntimeSafety(true);
    if (self.credentialFor(name, forms)) |index| return index;
    if (self.options.unknown_name == .reject) return error.UnrecognizedName;
    for (self.options.credentials, 0..) |credential, i| if (admits(forms, credential.identity)) return i;
    return error.UnsupportedCertificate;
}

/// Exact, ASCII case-insensitive, or `*.` plus a domain standing for exactly one leftmost label.
pub fn nameMatches(pattern: []const u8, name: []const u8) bool {
    @setRuntimeSafety(true);
    if (name.len == 0) return false;
    if (std.mem.startsWith(u8, pattern, "*.")) {
        const dot = std.mem.findScalar(u8, name, '.') orelse return false;
        return dot != 0 and std.ascii.eqlIgnoreCase(pattern[1..], name[dot..]);
    }
    return std.ascii.eqlIgnoreCase(pattern, name);
}

fn onClientHello(self: *Server, wire: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.client_hello, epoch, .parsed, boundary);
    // The scratch is the connection's one large allocation, made when a peer first sends a
    // ClientHello the state table accepts; a connection that never speaks holds none.
    const scratch = self.scratch orelse try self.startScratch();
    const second = self.retried;
    var msg = wire;
    var hello = try ClientHello.parse(wire, self.options.transport);
    // An ECH this server decrypts replaces the hello by the inner one from here on.
    if (self.options.ech_keys.len != 0) if (try self.openEch(wire, &hello, second)) |inner| {
        msg = inner;
        hello = ClientHello.parse(inner, self.options.transport) catch return error.IllegalParameter;
        try checkInner(&hello);
    };
    if (!hello.offers13() or !self.allows13()) {
        // A client without TLS 1.3 (or a server without it): TLS 1.2 when both sides allow it,
        // never after a retry.
        if (second or !self.allows12() or !hello.offers12()) return error.UnsupportedVersion;
        return Server12.onClientHello(self, msg, &hello, epoch, boundary);
    }
    // A TLS 1.3 hello offers the null compression method alone (RFC 8446 section 4.1.2).
    if (!hello.null_compression_only) return error.IllegalParameter;
    // A DTLS 1.3 hello's cookie field is empty (RFC 9147 section 5.3).
    if (hello.legacy_cookie.len != 0) return error.IllegalParameter;
    if (second) {
        if (!std.mem.eql(u8, &hello.fingerprint(), &scratch.first)) return error.IllegalParameter;
        // A cookie comes back only to a retry request that carried one: the stateless one,
        // which the cookie check already verified.
        if (hello.cookie.len != 0 and !self.stateless_retry) return error.UnexpectedCookie;
    }
    if (!second or self.stateless_retry) {
        scratch.client_random = hello.random[0..32].*;
        @memcpy(scratch.session[0..hello.session.len], hello.session);
        // safe: parsing bounds the session id at 32 bytes.
        scratch.session_len = @intCast(hello.session.len);
        if (self.options.transport == .quic and hello.session.len != 0) return error.IllegalParameter;
        scratch.first = hello.fingerprint();
        @memcpy(scratch.server_name[0..hello.server_name.len], hello.server_name);
        // safe: parsing bounds a host name at 253 bytes.
        scratch.server_name_len = @intCast(hello.server_name.len);
    }
    if (hello.cookie.len != 0 and !self.stateless_retry) return error.UnexpectedCookie;
    if (!hello.has_schemes) return error.MissingExtension;
    if (!hello.has_groups) return error.MissingExtension;
    if (hello.sharesOutsideGroups()) return error.IllegalParameter;
    // A second hello may not offer early data (RFC 8446 section 4.2.10).
    if (second and hello.early_data) return error.IllegalParameter;
    if (!second) self.scratch.?.early_offered = hello.early_data;
    self.scratch.?.takes_tickets = hello.psk_dhe;
    if (hello.compress_certificate) |list| {
        // checkExtension bounded it: one length byte and at most 254 bytes of algorithms.
        @memcpy(self.scratch.?.compression[0..list.len], list);
        self.scratch.?.compression_len = @intCast(list.len); // safe: at most 255 bytes
    } else self.scratch.?.compression_len = 0;
    try self.negotiate(&hello, second);
    const group = self.group.?;
    const share = hello.shareFor(group) orelse {
        // No usable share: ask once for the group the server chose.
        if (second) return error.IllegalParameter;
        try self.scratch.?.transcripts.commit(msg);
        return self.sendRetry(group);
    };
    if (share.len != group.clientShareLength()) return error.IllegalParameter;
    // Tickets are opened and issued by the clock: the hello waits for it.
    if (self.options.tickets != null and self.now == null) return self.holdHello(msg);
    return self.answerHello(msg, &hello);
}

/// DTLS: starts from a retry request a stateless cookie check sent for the client's first hello
/// (`dtls.Cookies`): the transcript holds that hello's hash and the request, the table stands
/// after the retry, and the second hello must have the first's `fingerprint`, a share of
/// `group`, `suite` among its offer and the cookie the request carried.
pub fn resumeRetry(self: *Server, suite: Suite13, group: Group, hello_hash: []const u8, fingerprint: [32]u8, retry: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.options.transport != .datagram or self.state.phase() != .start or self.scratch != null) return error.UnexpectedMessage;
    errdefer self.state.fail();
    const scratch = try self.startScratch();
    try self.state.advance(.client_hello, .initial, .parsed, true);
    try self.state.advance(.hello_retry, .initial, .parsed, true);
    try scratch.transcripts.restoreRetry(suite, hello_hash, retry);
    scratch.first = fingerprint;
    scratch.retry_group = group;
    self.retried = true;
    self.stateless_retry = true;
    self.suite = suite;
}

/// Keeps the ClientHello and asks for the time; `provideTime` answers it.
pub fn holdHello(self: *Server, msg: []const u8) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = try self.gpa.dupe(u8, msg);
    self.scratch.?.hello_held = true;
    self.need_now = .time;
}

/// The ClientHello that a ServerHello answers: a PSK is chosen if one resumes, the hello joins
/// the transcript, and the key exchange's entropy is asked for.
fn answerHello(self: *Server, msg: []const u8, hello: *const ClientHello) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (hello.has_psk and hello.psk_dhe) try self.choosePsk(msg, hello);
    // A PSK authenticates the handshake: only without one is a credential chosen.
    if (!self.pskMode()) try self.chooseAuthentication(hello);
    try scratch.transcripts.commit(msg);
    const group = self.group.?;
    const share = hello.shareFor(group).?;
    @memcpy(scratch.share[0..share.len], share);
    scratch.share_len = share.len;
    self.answered = true;
    const tickets: usize = if (self.options.tickets != null and self.scratch.?.takes_tickets) tickets_per_handshake * ticket_entropy else 0;
    const noise = if (self.pskMode()) 0 else self.signNoiseLength();
    const entropy: Need = .{ .entropy = .{ .len = 32 + Exchange.respondEntropyLength(group) + noise + tickets } };
    // QUIC: the client's transport parameters are provisional, and the server says nothing
    // that depends on them until the caller accepts them.
    if (self.options.transport == .quic and !self.parameters_accepted) {
        self.deferred = entropy;
        self.need_now = .parameters;
    } else self.need_now = entropy;
}

/// The credential, its signature scheme and the certificate types of a handshake no PSK
/// authenticates. A server holding provisioned keys alone has nothing to offer it.
fn chooseAuthentication(self: *Server, hello: *const ClientHello) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.options.credentials.len == 0) return error.PskRequired;
    // RFC 7250: X.509 unless the client lists only other types; a raw key when it lists one.
    self.credential = try self.chooseCredential(hello.server_name, .{
        .x509 = ClientHello.admitsType(hello.server_certificate_types, @backingInt(Hello.CertificateType.x509)),
        .raw_public_key = ClientHello.admitsType(hello.server_certificate_types, @backingInt(Hello.CertificateType.raw_public_key)),
    });
    self.scheme = Possession.choose(self.options.credentials[self.credential].identity.publicKey(), hello) orelse return error.NoSignatureScheme;
    self.negotiateTypes(hello);
}

/// What a ticket must agree with to resume: this policy, this name and protocol, a suite of its
/// hash, its own and the client authentication's lifetimes.
fn resumable(self: *const Server, state: *const Ticket.State, now: i64) bool {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (state.version != .tls13 or state.datagram != (self.options.transport == .datagram)) return false;
    const suite = state.suite.tls13() orelse return false;
    if (suites.digestLength(suite) != suites.digestLength(self.suite.?)) return false;
    // Issued no later than a minute ahead of this clock, and not yet expired.
    if (now >= state.expires or state.issued > now +| 60) return false;
    if (!std.ascii.eqlIgnoreCase(state.serverName(), scratch.server_name[0..scratch.server_name_len])) return false;
    if (!std.mem.eql(u8, state.alpnBytes(), self.alpn)) return false;
    if (!std.mem.eql(u8, &state.policy, &self.policyDigest())) return false;
    if (state.client_authenticated) {
        if (now >= state.auth_expires) return false;
    } else if (self.options.client_auth == .required) return false;
    return true;
}

/// The first offered ticket this server opens and may resume, checked by its binder. A ticket it
/// cannot open or resume is passed over for a full handshake; a binder that fails is fatal.
/// A PSK handshake: a resumed session or a provisioned key, no certificate either way.
fn pskMode(self: *const Server) bool {
    return self.resumed or self.external;
}

/// The first offered identity the caller's lookup knows, for a suite of its key's hash and
/// checked by its binder ("ext binder"); a binder that fails is fatal. Identities are compared as
/// exact bytes. None found: tickets may still resume, or a full handshake follows.
fn chooseExternal(self: *Server, msg: []const u8, hello: *const ClientHello) Client.Error!bool {
    @setRuntimeSafety(true);
    const lookup = self.options.external_psk orelse return false;
    const scratch = self.scratch.?;
    var index: u16 = 0;
    while (index < 8) : (index += 1) {
        const offer = hello.pskIdentity(index) orelse return false;
        if (offer.identity.len > Psk.max_identity) continue;
        const found = lookup.find(lookup.context, .{ .identity = offer.identity, .server_name = scratch.server_name[0..scratch.server_name_len], .alpn = self.alpn, .transport = self.options.transport, .version = .tls13 }) orelse continue;
        if (found.version != .tls13 or !std.mem.eql(u8, found.identity, offer.identity)) continue;
        Psk.validate(found) catch continue;
        if (found.hash.length() != suites.digestLength(self.suite.?)) continue;
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        switch (self.suite.?) {
            inline else => |tag| {
                const K = Schedule.Schedule(tag);
                const truncated = scratch.transcripts.digestWith(&digest_buf, K.length, hello.truncated(msg));
                try K.checkBinderOf(self.options.transport.prefix(), .external, found.secret[0..K.length], truncated[0..K.length], hello.pskBinder(index));
            },
        }
        try self.state.markResumed();
        @memcpy(scratch.psk.exposeMut()[0..found.secret.len], found.secret);
        self.external = true;
        self.authenticated = true;
        scratch.psk_index = index;
        return true;
    }
    return false;
}

fn choosePsk(self: *Server, msg: []const u8, hello: *const ClientHello) Client.Error!void {
    @setRuntimeSafety(true);
    if (try self.chooseExternal(msg, hello)) return;
    const ring_owner = self.options.tickets orelse return;
    var snapshot = ring_owner.acquire() orelse return;
    defer snapshot.release();
    const now = types.seconds(self.now.?);
    // A bounded look: a client offers one ticket or a few.
    var index: u16 = 0;
    while (index < 8) : (index += 1) {
        const offer = hello.pskIdentity(index) orelse return;
        var state: Ticket.State = undefined;
        Ticket.open(snapshot.ring(), offer.identity, now, &state) catch continue;
        defer state.deinit();
        if (!self.resumable(&state, now)) continue;
        const scratch = self.scratch.?;
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        switch (self.suite.?) {
            inline else => |tag| {
                const K = Schedule.Schedule(tag);
                const truncated = scratch.transcripts.digestWith(&digest_buf, K.length, hello.truncated(msg));
                try K.checkBinder(self.options.transport.prefix(), state.secretBytes()[0..K.length], truncated[0..K.length], hello.pskBinder(index));
            },
        }
        try self.state.markResumed();
        @memcpy(scratch.psk.exposeMut()[0..state.secretBytes().len], state.secretBytes());
        self.resumed = true;
        self.scratch.?.psk_index = index;
        self.scratch.?.session_expires = state.expires;
        self.authenticated = state.client_authenticated;
        self.raw_pin = state.client_raw_pin;
        self.scratch.?.client_auth_expires = if (state.client_authenticated) state.auth_expires else std.math.maxInt(i64);
        return;
    }
}

/// What a ticket's resumption depends on beyond its session: how this server treats client
/// certificates, by mode and by the whole verification policy.
pub fn policyDigest(self: *const Server) [32]u8 {
    @setRuntimeSafety(true);
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("cloak ticket policy v1");
    h.update(&.{ @backingInt(self.options.client_auth), @backingInt(std.meta.activeTag(self.options.client_verify)) });
    switch (self.options.client_verify) {
        .none => {},
        .raw_key => |raw| {
            var count: [8]u8 = undefined;
            std.mem.writeInt(u64, &count, raw.pins.len, .big);
            h.update(&count);
            for (raw.pins) |*pin| h.update(pin);
        },
        .full => |full| {
            const request: types.Request = .{
                .chain = &.{},
                .purpose = .client,
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
            h.update(&request.digest());
        },
    }
    return h.finalResult();
}

/// Whether this server speaks TLS 1.3.
pub fn allows13(self: *const Server) bool {
    const hello: Hello.Options = .{ .suites = self.options.suites, .min_version = self.options.min_version, .max_version = self.options.max_version, .groups = self.options.groups, .require_hybrid = self.options.require_hybrid, .require_pq_auth = self.options.require_pq_auth, .transport = self.options.transport };
    return hello.allows13();
}

/// Whether this server takes TLS 1.2 clients.
pub fn allows12(self: *const Server) bool {
    const hello: Hello.Options = .{ .suites = self.options.suites, .min_version = self.options.min_version, .max_version = self.options.max_version, .groups = self.options.groups, .require_hybrid = self.options.require_hybrid, .require_pq_auth = self.options.require_pq_auth, .transport = self.options.transport };
    return hello.allows12();
}

/// Chooses suite, group and protocol from the client's offer and the server's preference; the
/// server's order wins. The credential waits for the PSK decision (`chooseAuthentication`).
fn negotiate(self: *Server, hello: *const ClientHello, second: bool) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (second and !self.hasRetryGroup(hello)) return error.IllegalParameter;
    // A stateless retry request named its suite; this hello's choice must be the same.
    const retried_suite = if (self.stateless_retry) self.suite else null;
    self.suite = for (self.options.suites) |suite| {
        if (suite.tls13()) |candidate| if (hello.offersSuite(@backingInt(candidate))) break candidate;
    } else return error.NoSharedSuite;
    if (retried_suite) |want| if (want != self.suite.?) return error.IllegalParameter;
    if (second) {
        self.group = scratch.retry_group;
    } else {
        // A group with a share beats one needing a retry.
        self.group = for (self.options.groups) |group| {
            if (hello.offersGroup(group) and hello.shareFor(group) != null) break group;
        } else for (self.options.groups) |group| {
            if (hello.offersGroup(group)) break group;
        } else return error.NoSharedGroup;
    }
    if (self.options.require_hybrid and !self.group.?.hybrid()) return error.HybridRequired;
    self.alpn = "";
    if (self.options.alpn.len != 0) {
        if (hello.alpn.len == 0) {
            if (self.options.require_alpn or self.options.transport == .quic) return error.NoApplicationProtocol;
        } else self.alpn = hello.selectAlpn(self.options.alpn) orelse return error.NoApplicationProtocol;
    }
    self.negotiateDatagram(hello);
    if (self.options.transport == .quic) {
        if (hello.parameters == null) return error.MissingExtension;
        if (self.peer_parameters.len == 0) {
            if (hello.parameters.?.len > 64 * 1024) return error.HandshakeLimit;
            self.peer_parameters = try self.gpa.dupe(u8, hello.parameters.?);
        }
    }
    const keep = @min(hello.schemes.len, scratch.schemes.len) & ~@as(usize, 1);
    @memcpy(scratch.schemes[0..keep], hello.schemes[0..keep]);
    // safe: at most 256 bytes are kept.
    scratch.schemes_len = @intCast(keep);
}

/// RFC 7250: the type of each Certificate, answered when the client listed types. The server's is
/// its credential's form; the client's, asked only when a certificate is requested, is the one
/// the client verification takes (a pinned raw key, or X.509), when the client lists it, and
/// otherwise unanswered: the client then sends X.509 or nothing.
pub fn negotiateTypes(self: *Server, hello: *const ClientHello) void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const own: Hello.CertificateType = switch (self.options.credentials[self.credential].identity.form()) {
        .x509 => .x509,
        .raw_public_key => .raw_public_key,
    };
    scratch.server_type = if (hello.server_certificate_types != null) own else null;
    scratch.client_type = null;
    scratch.peer_raw = false;
    if (self.options.client_auth == .none) return;
    const want: Hello.CertificateType = if (self.options.client_verify == .raw_key) .raw_public_key else .x509;
    if (hello.client_certificate_types) |list| if (ClientHello.admitsType(list, @backingInt(want))) {
        scratch.client_type = want;
        scratch.peer_raw = want == .raw_public_key;
    };
}

/// DTLS: connection IDs when the client offers them and this server answers them, and the
/// first SRTP profile of the server's the client offered.
pub fn negotiateDatagram(self: *Server, hello: *const ClientHello) void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    scratch.cid_agreed = false;
    self.srtp = null;
    if (self.options.transport != .datagram) return;
    if (self.options.connection_id != null) if (hello.connection_id) |cid| {
        @memcpy(scratch.peer_cid[0..cid.len], cid);
        scratch.peer_cid_len = @intCast(cid.len); // safe: a vector<0..255>
        scratch.cid_agreed = true;
    };
    const offered = hello.srtp orelse return;
    self.srtp = for (self.options.srtp) |profile| {
        var at: usize = 0;
        while (at < offered.len) : (at += 2) {
            if (std.mem.readInt(u16, offered[at..][0..2], .big) == @backingInt(profile)) break;
        } else continue;
        break profile;
    } else null;
}

/// The connection ID a ServerHello answers connection_id with, when it does.
pub fn ownConnectionId(self: *const Server) ?[]const u8 {
    return if (self.scratch.?.cid_agreed) self.options.connection_id else null;
}

fn hasRetryGroup(self: *const Server, hello: *const ClientHello) bool {
    const group = self.scratch.?.retry_group orelse return false;
    return hello.shareFor(group) != null;
}

fn sendRetry(self: *Server, group: Group) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    try self.state.advance(.hello_retry, .initial, .parsed, true);
    var buffer: [128]u8 = undefined;
    const accepted = scratch.ech.status == .accepted;
    const hrr = try Hello.buildRetry(&buffer, self.options.transport, self.echoedSession(), self.suite.?, group, "", accepted);
    scratch.transcripts.select(self.suite.?);
    if (accepted) {
        // The confirmation covers the inner hello and this retry request with its eight
        // bytes zeroed, as built (RFC 9849 section 7.2.1).
        var confirm = scratch.transcripts;
        defer std.crypto.secureZero(u8, std.mem.asBytes(&confirm));
        try confirm.retry(hrr);
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        switch (self.suite.?) {
            inline else => |tag| {
                const Hash = suites.Hash(tag);
                const digest = confirm.digest(&digest_buf);
                hrr[hrr.len - 8 ..][0..8].* = Ech.confirmation(Hash, &scratch.client_random, Ech.retry_accept_label, digest[0..Hash.digest_length]);
            },
        }
    }
    try scratch.transcripts.retry(hrr);
    const dst = try self.reserve(hrr.len);
    @memcpy(dst[0..hrr.len], hrr);
    try scratch.flight.queueMessage(.initial, hrr.len);
    try self.sendCompatCcs();
    self.retried = true;
    scratch.retry_group = group;
}

/// The legacy session id a TLS 1.3 ServerHello echoes: the client's on a stream, none in DTLS
/// (RFC 9147 section 5) or QUIC, where a client sends none.
fn echoedSession(self: *const Server) []const u8 {
    const scratch = self.scratch.?;
    return if (self.options.transport == .datagram) "" else scratch.session[0..scratch.session_len];
}

fn sendCompatCcs(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    // Middlebox compatibility is a stream's: never a ChangeCipherSpec of TLS 1.3 in DTLS.
    if (self.ccs_sent or self.scratch.?.session_len == 0 or self.options.transport == .datagram) return;
    self.ccs_sent = true;
    try self.push(.compat_ccs);
}

/// ServerHello, key schedule, EncryptedExtensions, optional CertificateRequest and the
/// Certificate; the CertificateVerify waits on the signature.
fn sendServerFlight(self: *Server, random: []const u8, response: *const Exchange.Response) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const suite = self.suite.?;
    // A ServerHello: its fixed fields, a session id and the largest key share.
    var hello_buffer: [512 + Exchange.max_share]u8 = undefined;
    const hello = try Hello.buildServer(&hello_buffer, self.options.transport, random[0..32], self.echoedSession(), suite, self.group.?, response.wire(), if (self.pskMode()) self.scratch.?.psk_index else null, self.ownConnectionId());
    try self.state.advance(.server_hello, .initial, .parsed, true);
    scratch.transcripts.select(suite);
    if (scratch.ech.status == .accepted) {
        // The last eight bytes of the random confirm ECH: the inner transcript through this
        // ServerHello with those bytes zeroed (RFC 9849 section 7.2).
        const confirmed = hello[4 + 2 + 24 ..][0..8];
        @memset(confirmed, 0);
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        switch (suite) {
            inline else => |tag| {
                const Hash = suites.Hash(tag);
                const digest = scratch.transcripts.digestWith(&digest_buf, Hash.digest_length, hello);
                confirmed.* = Ech.confirmation(Hash, &scratch.client_random, Ech.accept_label, digest[0..Hash.digest_length]);
            },
        }
    }
    try scratch.transcripts.commitOwn(hello);
    const dst = try self.reserve(hello.len);
    @memcpy(dst[0..hello.len], hello);
    try scratch.flight.queueMessage(.initial, hello.len);
    try self.sendCompatCcs();
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const hello_hash = scratch.transcripts.digest(&digest_buf);
    switch (suite) {
        inline else => |tag| {
            const Hash = suites.Hash(tag);
            const K = Schedule.Schedule(tag);
            var traffic: K.Traffic = .{};
            errdefer traffic.deinit();
            const psk: ?*const [K.length]u8 = if (self.pskMode()) scratch.psk.expose()[0..K.length] else null;
            var schedule = try K.init(self.options.transport.prefix(), psk, response.agreed.bytes(), hello_hash[0..Hash.digest_length], &traffic);
            errdefer schedule.deinit();
            self.keys = @unionInit(Keys, @tagName(tag), .{ .schedule = schedule, .handshake = traffic });
        },
    }
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const len = suites.Hash(tag).digest_length;
            try self.install(.write, .handshake, tag, len, k.handshake.server.expose(), "SERVER_HANDSHAKE_TRAFFIC_SECRET");
            try self.install(.read, .handshake, tag, len, k.handshake.client.expose(), "CLIENT_HANDSHAKE_TRAFFIC_SECRET");
        },
    }
    scratch.psk.deinit();
    try self.sendEncrypted();
    // A resumed handshake is authenticated by the PSK: no certificate either way.
    if (self.pskMode()) return self.finishFlight();
    if (self.options.client_auth != .none) try self.sendRequest();
    try self.sendCertificate();
}

fn sendEncrypted(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var retry_len: usize = 0;
    for (self.options.ech_keys) |key| retry_len += key.config.len;
    const dst = try self.reserve(1024 + self.options.parameters.len + retry_len);
    const message = try Hello.buildEncrypted(dst, .{
        .server_name = scratch.server_name_len != 0,
        .alpn = self.alpn,
        .parameters = if (self.options.transport == .quic) self.options.parameters else null,
        // A client whose ECH did not decrypt (or was GREASE) learns the current configs.
        .ech_retry = if (scratch.ech.status == .rejected) self.options.ech_keys else &.{},
        .srtp = self.srtp,
        // A PSK handshake sends no certificate either way: no type to answer.
        .server_certificate_type = if (self.pskMode()) null else scratch.server_type,
        .client_certificate_type = if (self.pskMode()) null else scratch.client_type,
    });
    try self.state.advance(.encrypted_extensions, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message);
}

fn sendRequest(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const allowed = Hello.verifySchemes(.{ .require_pq_auth = self.options.require_pq_auth });
    var schemes: [Hello.schemes.len]u16 = undefined;
    for (allowed, schemes[0..allowed.len]) |scheme, *slot| slot.* = @backingInt(scheme);
    const dst = try self.reserve(64);
    const message = try Messages.buildCertificateRequest(dst, schemes[0..allowed.len]);
    try self.state.advance(.certificate_request, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message);
}

fn sendCertificate(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const identity = self.options.credentials[self.credential].identity;
    var total: usize = 64;
    for (identity.entries()) |der| total += der.len + 5;
    const offered = scratch.compression[0..scratch.compression_len];
    const codec = if (offered.len != 0) Compression.choose(self.options.certificate_compression, offered) else null;
    try self.state.advance(.certificate, .handshake, .parsed, true);
    if (codec) |chosen| compressed: {
        // RFC 8879: the CompressedCertificate takes the Certificate's place, in the transcript too.
        const plain_buf = try self.gpa.alloc(u8, total);
        defer self.gpa.free(plain_buf);
        const plain = try Messages.buildCertificate(plain_buf, "", identity.entries());
        const dst = try self.reserve(plain.len);
        const message = Compression.build(dst, chosen, plain) orelse break :compressed;
        try self.queueMessage(.handshake, message);
        return self.signCertificate(identity);
    }
    const dst = try self.reserve(total);
    const message = try Messages.buildCertificate(dst, "", identity.entries());
    try self.queueMessage(.handshake, message);
    return self.signCertificate(identity);
}

/// The CertificateVerify content over the transcript through the certificate, and its signature.
fn signCertificate(self: *Server, identity: certificates.Identity) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const content = Messages.signedContent(&scratch.sign_content, true, scratch.transcripts.digest(&digest_buf));
    // safe: signed content is at most 64 + 33 + 1 + 48 bytes.
    scratch.sign_content_len = @intCast(content.len);
    scratch.signing = true;
    // Cloak signs for a key it holds; a key held elsewhere is the caller's to sign with.
    if (identity.noiseLength()) |noise_length| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = Possession.sign(identity, self.scheme, content, scratch.sign_noise[0..noise_length], &out) catch return error.SigningFailed;
        return self.sendCertificateVerify(signature);
    }
    self.need_now = .sign;
}

/// The server Finished, the application secrets, and then the wait for the client.
fn finishFlight(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var before_buf: [Transcripts.max_digest]u8 = undefined;
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const Hash = suites.Hash(tag);
            const before = scratch.transcripts.digest(&before_buf);
            var verify_data: [Hash.digest_length]u8 = undefined;
            Labels.finished(Hash, k.schedule.prefix, &verify_data, k.handshake.server.expose(), before[0..Hash.digest_length]);
            const dst = try self.reserve(4 + Hash.digest_length);
            const message = try Messages.buildFinished(dst, &verify_data);
            try self.state.advance(.local_finished, .handshake, .finished, true);
            try self.queueMessage(.handshake, message);
            var after_buf: [Transcripts.max_digest]u8 = undefined;
            const after = scratch.transcripts.digest(&after_buf);
            var app: @TypeOf(k.schedule).Traffic = .{};
            defer app.deinit();
            try k.schedule.application(after[0..Hash.digest_length], &app);
            const len = Hash.digest_length;
            try self.install(.write, .application, tag, len, app.server.expose(), "SERVER_TRAFFIC_SECRET_0");
            self.app_read = self.makeTraffic(tag, len, app.client.expose(), "CLIENT_TRAFFIC_SECRET_0");
            self.keyLog("EXPORTER_SECRET", k.schedule.exporter.expose());
        },
    }
    scratch.signing = false;
}

/// Decrypts the encrypted_client_hello of a ClientHelloOuter (RFC 9849 section 7.1) and returns
/// the reconstructed ClientHelloInner, owned by the scratch; null when the hello is to be used as
/// it is. A first hello tries each key of its config id (a bounded trial) and a failure to decrypt
/// is no error: the server goes on with the outer hello and offers its retry configurations. A
/// second hello after an accepted first must open under the first one's context.
fn openEch(self: *Server, wire: []const u8, outer: *const ClientHello, second: bool) Client.Error!?[]const u8 {
    @setRuntimeSafety(true);
    const e = &self.scratch.?.ech;
    const body = outer.ech orelse {
        if (second and e.status == .accepted) return error.MissingExtension;
        return null;
    };
    const offer = switch (Ech.parseOffer(body) catch |err| return err) {
        // An inner hello comes only out of an outer one, never from the network.
        .inner => return error.IllegalParameter,
        .outer => |o| o,
    };
    if (second and e.status != .accepted) return null;
    const payload_at = @intFromPtr(offer.payload.ptr) - @intFromPtr(wire.ptr); // safe: the payload is a slice of `wire`
    const aad = try self.gpa.dupe(u8, wire[4..]);
    defer self.gpa.free(aad);
    @memset(aad[payload_at - 4 ..][0..offer.payload.len], 0);
    if (offer.payload.len <= Hpke.tag_length) return if (second) error.EchDecryptFailed else self.notDecrypted();
    const encoded = try self.gpa.alloc(u8, offer.payload.len - Hpke.tag_length);
    defer {
        std.crypto.secureZero(u8, encoded);
        self.gpa.free(encoded);
    }
    if (second) {
        // The same config and suite, no new key: the first hello's context, its next nonce.
        if (offer.config_id != e.config_id or offer.suite.kdf != e.suite.kdf or offer.suite.aead != e.suite.aead or offer.enc.len != 0) return error.IllegalParameter;
        e.context.?.open(encoded, aad, offer.payload) catch return error.EchDecryptFailed;
        // No third hello: the context has done its work.
        e.context.?.deinit();
        e.context = null;
    } else {
        const opened = for (self.options.ech_keys) |key| {
            const config = (Ech.parseConfig(key.config) catch continue).config orelse continue;
            if (config.id != offer.config_id or !config.lists(offer.suite)) continue;
            const info_buf = try self.gpa.alloc(u8, 8 + key.config.len);
            defer self.gpa.free(info_buf);
            var context = Hpke.setupRecipient(offer.suite, offer.enc, key.secret, Ech.info(info_buf, key.config)) catch continue;
            context.open(encoded, aad, offer.payload) catch {
                context.deinit();
                continue;
            };
            break context;
        } else return self.notDecrypted();
        e.context = opened;
        e.suite = offer.suite;
        e.config_id = offer.config_id;
        e.status = .accepted;
    }
    const inner = Ech.reconstruct(self.gpa, wire, encoded) catch |err| return switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        error.IllegalParameter => error.IllegalParameter,
    };
    if (e.inner.len != 0) {
        std.crypto.secureZero(u8, e.inner);
        self.gpa.free(e.inner);
    }
    e.inner = inner;
    self.ech_accepted = true;
    return inner;
}

fn notDecrypted(self: *Server) ?[]const u8 {
    self.scratch.?.ech.status = .rejected;
    return null;
}

/// A ClientHelloInner carries the inner marker and offers TLS 1.3 and nothing older, GREASE
/// aside (RFC 9849 section 7.1).
fn checkInner(hello: *const ClientHello) Client.Error!void {
    @setRuntimeSafety(true);
    const body = hello.ech orelse return error.IllegalParameter;
    if ((Ech.parseOffer(body) catch return error.IllegalParameter) != .inner) return error.IllegalParameter;
    if (!hello.offers13()) return error.IllegalParameter;
    var at: usize = 0;
    while (at + 2 <= hello.versions.len) : (at += 2) {
        const v = std.mem.readInt(u16, hello.versions[at..][0..2], .big);
        const grease = v & 0x0f0f == 0x0a0a and v >> 8 == v & 0xff;
        if (!grease and v < 0x0304) return error.IllegalParameter;
    }
}

fn onCertificate(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .client_certificate) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    var probe: [Messages.max_certificates][]const u8 = undefined;
    const limits = self.options.limits;
    const parsed = try Messages.certificate(msg, limits.certificates, limits.chain_bytes, &probe);
    if (parsed.context.len != 0) return error.IllegalParameter;
    if (parsed.count == 0) {
        if (self.options.client_auth == .required) return error.CertificateRequired;
        try self.state.advance(.empty_certificate, epoch, .parsed, boundary);
        try scratch.transcripts.commit(msg);
        return;
    }
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    // The chain outlives this call: a verification request borrows it until answered.
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = try self.gpa.dupe(u8, msg);
    const reparsed = try Messages.certificate(self.held, limits.certificates, limits.chain_bytes, &scratch.chain);
    scratch.chain_len = reparsed.count;
    if (scratch.peer_raw) {
        // The raw key this server selected for the client (RFC 7250), one its policy pins.
        self.raw_pin = try Possession.pinnedKey(scratch.chain[0..scratch.chain_len], self.options.client_verify.raw_key.pins);
        try scratch.transcripts.commit(msg);
        try self.state.advance(.verify_chain, .handshake, .chain, true);
        self.authenticated = true;
        return;
    }
    // A chain where only a pinned raw key is trusted: the client did not take that type.
    if (self.options.client_verify == .raw_key) return error.UnsupportedCertificate;
    try scratch.transcripts.commit(msg);
    switch (self.options.client_verify) {
        .none => try self.state.advance(.verify_chain, .handshake, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
        // unreachable: a pinned-key policy took the raw key above or refused the chain.
        .raw_key => unreachable,
    }
}

fn onCertificateVerify(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .client_possession) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const parsed = try Messages.certificateVerify(msg);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    var content_buf: [Messages.max_signed]u8 = undefined;
    const content = Messages.signedContent(&content_buf, false, scratch.transcripts.digest(&digest_buf));
    try Possession.verifyKey(parsed.scheme, Hello.verifySchemes(.{ .require_pq_auth = self.options.require_pq_auth }), try Possession.peerKey(scratch.chain[0], scratch.peer_raw), content, parsed.signature);
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try scratch.transcripts.commit(msg);
    self.peer_certificate = true;
}

fn onFinished(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .client_finished) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    var before_buf: [Transcripts.max_digest]u8 = undefined;
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const Hash = suites.Hash(tag);
            const received = try Messages.finished(msg, Hash.digest_length);
            const before = scratch.transcripts.digest(&before_buf);
            try Labels.checkFinished(Hash, k.schedule.prefix, k.handshake.client.expose(), before[0..Hash.digest_length], received);
            try self.state.advance(.finished, epoch, .finished, boundary);
            try scratch.transcripts.commit(msg);
            var finished_buf: [Transcripts.max_digest]u8 = undefined;
            try k.schedule.complete(scratch.transcripts.digest(&finished_buf)[0..Hash.digest_length]);
            k.handshake.deinit();
        },
    }
    try self.push(.{ .secret = .{ .direction = .read, .epoch = .application, .traffic = self.app_read.? } });
    self.app_read.?.secret.deinit();
    self.app_read = null;
    self.established = true;
    // A provisioned key authenticates the client; otherwise only a fully verified certificate does.
    self.authenticated = self.external or (self.authenticated and self.options.client_verify != .none);
    try self.issueTickets();
    try self.push(.complete);
}

/// NewSessionTickets, sent under the application keys before the connection is complete. A
/// ticket's session expires a lifetime after its full handshake, and no later than the client's
/// authentication; a resumed session's tickets keep the expiry the first ticket had. Nothing is
/// issued without a key that issues now, or to a client that cannot use PSK-DHE.
fn issueTickets(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const ring_owner = self.options.tickets orelse return;
    if (!self.scratch.?.takes_tickets or self.external) return;
    const now = self.now orelse return;
    var snapshot = ring_owner.acquire() orelse return;
    defer snapshot.release();
    const now_s = types.seconds(now);
    const key = snapshot.ring().issuing(now_s) orelse return;
    var expires = if (self.resumed) self.scratch.?.session_expires else now_s +| snapshot.ring().lifetime;
    if (self.authenticated) expires = @min(expires, self.scratch.?.client_auth_expires);
    if (expires <= now_s) return;
    const scratch = self.scratch.?;
    const keys = &self.keys.?;
    for (0..tickets_per_handshake) |i| {
        const drawn = scratch.ticket_entropy[i * ticket_entropy ..][0..ticket_entropy];
        var state: Ticket.State = .{
            .suite = Suite.from13(self.suite.?),
            .datagram = self.options.transport == .datagram,
            .issued = now_s,
            .expires = expires,
            .age_add = std.mem.readInt(u32, drawn[Ticket.salt_length..][0..4], .big),
            .client_authenticated = self.authenticated,
            .client_raw_pin = self.raw_pin,
            .auth_expires = if (self.authenticated) self.scratch.?.client_auth_expires else 0,
            .policy = self.policyDigest(),
        };
        defer state.deinit();
        @memcpy(state.alpn[0..self.alpn.len], self.alpn);
        state.alpn_len = @intCast(self.alpn.len); // safe: a protocol name is at most 255 bytes
        @memcpy(state.server_name[0..scratch.server_name_len], scratch.server_name[0..scratch.server_name_len]);
        state.server_name_len = scratch.server_name_len;
        // Each ticket of the connection has its own nonce, so its own PSK (RFC 8446 section 4.6.1).
        const nonce = [1]u8{@intCast(i)}; // safe: two tickets
        switch (keys.*) {
            inline else => |*k, tag| {
                const K = Schedule.Schedule(tag);
                k.schedule.ticketSecret(&nonce, state.secret.exposeMut()[0..K.length]) catch |err| switch (err) {
                    error.InvalidLabel => unreachable, // unreachable: a fixed label and a one-byte nonce
                    error.WrongPhase => return error.WrongPhase,
                };
            },
        }
        var sealed_buf: [Ticket.max_length]u8 = undefined;
        defer std.crypto.secureZero(u8, &sealed_buf);
        const sealed = Ticket.seal(key, drawn[0..Ticket.salt_length], &state, &sealed_buf) catch unreachable; // unreachable: the buffer holds the longest ticket
        const lifetime: u32 = @intCast(@min(expires - now_s, Messages.max_ticket_lifetime)); // safe: positive and at most seven days
        const dst = try self.reserve(4 + 4 + 4 + 2 + 2 + sealed.len + 2);
        const message = try Messages.buildNewSessionTicket(dst, lifetime, state.age_add, &nonce, sealed);
        // Post-handshake: sent, never part of the transcript.
        try scratch.flight.queueMessage(.application, message.len);
    }
}

fn onKeyUpdate(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.key_update, epoch, .parsed, boundary);
    try self.push(.{ .key_update = .{ .request_peer = try Messages.keyUpdate(msg) } });
}

// ---------------------------------------------------------------- results

/// Releases handshake scratch once the connection is established and every output was read.
pub fn settle(self: *Server) void {
    @setRuntimeSafety(true);
    if (!self.established or self.pending()) return;
    const scratch = self.scratch orelse return;
    // The negotiated name outlives the scratch only through `info`, which borrows the credentials.
    self.server_name_copy = self.gpa.dupe(u8, scratch.server_name[0..scratch.server_name_len]) catch &.{};
    self.releaseScratch();
    if (self.held.len != 0) {
        self.gpa.free(self.held);
        self.held = &.{};
    }
}

pub fn info(self: *const Server) ?Info {
    @setRuntimeSafety(true);
    if (!self.established or self.state.phase() == .failed) return null;
    return .{
        .version = self.version,
        .suite = if (self.suite12) |suite| suites.Suite.from12(suite) else suites.Suite.from13(self.suite.?),
        .group = self.group,
        .alpn = self.alpn,
        .server_name = if (self.scratch) |scratch| scratch.server_name[0..scratch.server_name_len] else self.server_name_copy,
        .peer_authenticated = self.authenticated,
        .peer_parameters = self.peer_parameters,
        .resumed = self.resumed,
        .ech_accepted = self.ech_accepted,
        .external_psk = self.external,
        .srtp = self.srtp,
        .raw_key_pin = self.raw_pin,
    };
}

pub const ExportError = Client.ExportError;

pub fn exportKeyingMaterial(self: *const Server, out: []u8, label: []const u8, context: ?[]const u8) ExportError!void {
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
    _ = @import("Server_test.zig");
}
