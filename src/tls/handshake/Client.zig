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

pub const Epoch = Flight.Epoch;
pub const Direction = Flight.Direction;

pub const Limits = struct {
    /// One handshake message, header included.
    message: usize = 128 * 1024,
    /// All handshake messages of one connection before it is established.
    handshake: usize = 256 * 1024,
    /// Total DER bytes of a peer chain.
    chain_bytes: usize = 64 * 1024,
    /// Entries of a peer chain.
    certificates: usize = Messages.max_certificates,
};

/// Peer verification. `none` is an explicit choice and yields an unauthenticated connection.
pub const Verify = union(enum) {
    none,
    full: Full,
    pub const Full = struct {
        trust_generation: types.TrustGeneration,
        policy_generation: types.PolicyGeneration = .fromRaw(1),
        policy: types.Policy = .{},
        pins: []const [32]u8 = &.{},
        evidence: types.Evidence = .{},
        limits: types.Limits = .{},
        anchor_policies: []const types.AnchorPolicy = &.{},
    };
};

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
    /// The identity the server certificate must carry.
    identity: types.Identity = .none,
    verify: Verify,
    /// Certificates and key for a CertificateRequest; its signature is a signing request.
    auth: ?certificates.ClientAuth = null,
    limits: Limits = .{},
    /// A random legacy session id and one change_cipher_spec, for middleboxes (stream only).
    compat: bool = true,
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Traffic = Flight.Traffic;
pub const Emit = Flight.Emit;

pub const Need = union(enum) {
    none,
    /// Exactly `len` fresh CSPRNG bytes.
    entropy: struct { len: usize },
    /// Real (calendar) time in seconds.
    time,
    /// Peer chain verification.
    verify,
    /// A CertificateVerify signature for the client certificate.
    sign,
    /// Peer QUIC transport parameters need an accept or reject.
    parameters,
};

/// What a key held elsewhere must sign. `prehashed` content is already the digest of the
/// scheme's hash (a TLS 1.2 CertificateVerify signs the transcript hash); sign it as is.
pub const SignRequest = struct { scheme: Hello.SignatureScheme, content: []const u8, prehashed: bool = false };

pub const Info = struct {
    version: suites.Version,
    /// The handshake resumed a session from a ticket: the peer's authentication is the original
    /// handshake's.
    suite: suites.Suite,
    group: Group,
    alpn: []const u8,
    server_name: []const u8,
    peer_authenticated: bool,
    peer_parameters: []const u8,
    resumed: bool = false,
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
        error.MissingExtension => .missing_extension,
        error.HybridRequired => .insufficient_security,
        error.UnsupportedVersion => .protocol_version,
        error.NoExtendedMasterSecret, error.NoSecureRenegotiation, error.NoClientCertificate => .handshake_failure,
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
options: Options,
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
peer_parameters: []u8 = &.{},
held: []u8 = &.{},
now: ?std.Io.Timestamp = null,
request_id: u64 = 0,
authenticated: bool = false,
requested_certificate: bool = false,
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
/// Seconds: the full handshake this session began with, and when its server authentication
/// expires. Tickets of the session never outlive either.
origin: i64 = 0,
auth_expires: i64 = std.math.maxInt(i64),

const Scratch = struct {
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
    chain: [Messages.max_certificates][]const u8 = undefined,
    chain_len: usize = 0,
    cr_schemes: [1024]u8 = undefined,
    cr_len: u16 = 0,
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
};

pub fn init(gpa: std.mem.Allocator, options: Options) InitError!*Client {
    @setRuntimeSafety(true);
    try Hello.validate(options.hello);
    switch (options.verify) {
        .full => if (options.identity == .none) return error.InvalidOptions,
        .none => {},
    }
    // Middlebox compatibility is a stream's: QUIC and DTLS have neither its session id nor its
    // ChangeCipherSpec.
    if (options.hello.transport != .stream and options.compat) return error.InvalidOptions;
    if (options.limits.message < 1024 or options.limits.handshake < options.limits.message or options.limits.certificates == 0) return error.InvalidOptions;
    if (options.resumption) |resumption| if (resumption.namespace.len > 1024 or resumption.max_age.nanoseconds <= 0) return error.InvalidOptions;
    const self = try gpa.create(Client);
    errdefer gpa.destroy(self);
    const scratch = try gpa.create(Scratch);
    errdefer gpa.destroy(scratch);
    scratch.* = .{};
    self.* = .{ .gpa = gpa, .options = options, .state = .{ .role = .client, .mode = options.hello.transport }, .scratch = scratch };
    self.need_now = .{ .entropy = .{ .len = self.initialEntropy() } };
    // A datagram hello that may be answered in DTLS 1.2 is hashed in its DTLS form too.
    if (options.hello.transport == .datagram and options.hello.allows12()) scratch.transcripts.startDatagram(0, 0, options.hello.allows13());
    if (options.resumption) |resumption| {
        // A ticket is chosen and aged by the clock, before the hello.
        if (options.hello.allows13() or (resumption.tls12 and options.hello.allows12())) self.need_now = .time;
        self.cache_key = cacheKey(options, resumption.namespace);
    }
    if (options.auth) |auth| {
        self.options.auth = auth.retain();
        // A TLS 1.2 CertificateVerify by Ed25519 signs the handshake messages themselves.
        if (options.hello.allows12()) if (certificates.certificate.parse(auth.chain()[0], .{})) |leaf| {
            if (leaf.public_key == .ed25519) scratch.transcripts.keep(gpa);
        } else |_| {};
    }
    return self;
}

pub fn deinit(self: *Client) void {
    @setRuntimeSafety(true);
    const gpa = self.gpa;
    self.wipe();
    if (self.options.auth) |auth| auth.deinit();
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
    self.state.phase = .failed;
}

// ---------------------------------------------------------------- services

/// A ChangeCipherSpec record arrived; only TLS 1.2 expects one, once, before the server's Finished.
pub fn receiveCcs(self: *Client) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase == .failed) return error.Closed;
    if (self.version != .tls12) return error.UnexpectedMessage;
    errdefer self.state.fail();
    return Client12.onCcs(self);
}

pub fn compat(self: *const Client) bool {
    return self.options.compat;
}

pub fn need(self: *const Client) Need {
    return self.need_now;
}

fn initialGroups(self: *const Client) struct { groups: [2]?Group, count: usize } {
    @setRuntimeSafety(true);
    var out: [2]?Group = .{ null, null };
    var count: usize = 0;
    // A TLS 1.2-only client sends no key shares.
    if (!self.options.hello.allows13()) return .{ .groups = out, .count = 0 };
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
    // A client certificate whose key cloak holds is signed for here, with noise drawn up front.
    if (self.options.auth) |auth| len += auth.identity.noiseLength() orelse 0;
    return len;
}

/// Answers an entropy request. `InvalidEntropy` is public (a scalar draw outside its range)
/// and leaves the request open for a fresh draw.
pub fn provideEntropy(self: *Client, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    const expected = switch (self.need_now) {
        .entropy => |e| e.len,
        else => return error.UnexpectedService,
    };
    if (entropy.len != expected) return error.InvalidEntropy;
    errdefer self.eraseShares();
    if (self.version == .tls12) return Client12.onEntropy(self, entropy);
    if (self.state.phase == .start) {
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
    scratch.flight.deinit(self.gpa);
    scratch.transcripts.release();
    std.crypto.secureZero(u8, std.mem.asBytes(scratch));
    self.gpa.destroy(scratch);
    self.scratch = null;
}

pub fn provideTime(self: *Client, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .time) return error.UnexpectedService;
    self.now = now;
    if (self.state.phase == .start) {
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
    part(&h, &.{ @backingInt(options.hello.transport), @intFromBool(options.hello.require_hybrid), @intFromBool(options.hello.require_alpn) });
    part(&h, std.mem.asBytes(&options.hello.alpn.len));
    for (options.hello.alpn) |protocol| part(&h, protocol);
    // The reference identity and the whole verification policy, through the request digest of
    // a request with no chain, time or token.
    switch (options.verify) {
        .none => part(&h, "verify none"),
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
    // The client certificate a server may have authenticated, by its whole chain.
    if (options.auth) |auth| {
        part(&h, "client certificate");
        for (auth.chain()) |der| part(&h, der);
    } else part(&h, "no client certificate");
    return h.finalResult();
}

/// Takes the newest usable ticket of each offered version for this connection's key: one the
/// offered suites can resume.
fn takeTicket(self: *Client) void {
    @setRuntimeSafety(true);
    const resumption = self.options.resumption orelse return;
    if (self.options.hello.allows13()) if (resumption.cache.take(&self.cache_key, .tls13, self.origin)) |found| {
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
    return .{
        .chain = self.scratch.?.chain[0..self.scratch.?.chain_len],
        .identity = self.options.identity,
        .purpose = .server,
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

/// Accepts the receipt for exactly the pending request. Any mismatch is terminal.
pub fn provideVerification(self: *Client, token: types.Token, receipt: *const types.Verification) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .verify) return error.UnexpectedService;
    receipt.check(self.verification(token)) catch return error.VerificationRejected;
    try self.state.advance(.verify_chain, self.verifyEpoch(), .chain, true);
    self.authenticated = true;
    // A session resumed from this one is authenticated no longer than this verdict holds.
    self.auth_expires = types.seconds(receipt.expires);
    if (receipt.revocation_expires) |until| self.auth_expires = @min(self.auth_expires, types.seconds(until));
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
    // Ed25519 in TLS 1.2 signs the handshake messages, not their digest.
    if (self.version == .tls12 and self.sign_scheme == .ed25519) return .{ .scheme = .ed25519, .content = self.scratch.?.transcripts.keptBytes() };
    return .{ .scheme = self.sign_scheme, .content = self.scratch.?.sign_content[0..self.scratch.?.sign_content_len], .prehashed = self.version == .tls12 };
}

/// Checks the signature against the identity's public key before using it.
pub fn provideSignature(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .sign) return error.UnexpectedService;
    if (self.version == .tls12) return Client12.onSignature(self, signature);
    const auth = self.options.auth.?;
    Possession.verify(@backingInt(self.sign_scheme), &.{self.sign_scheme}, auth.chain()[0], self.signRequest().content, signature) catch return error.BadSignature;
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
    if (self.offered) |taken| n += 64 + taken.entry.ticket.len;
    if (self.offered12) |taken| n += 8 + taken.entry.ticket.len;
    for (self.options.hello.alpn) |protocol| n += 1 + protocol.len;
    for (shares) |share| n += 4 + share.bytes.len;
    return n;
}

fn sendHello(self: *Client) Error!void {
    @setRuntimeSafety(true);
    var offered: [2]Hello.Share = undefined;
    const shares = self.offeredShares(&offered);
    const dst = try self.reserve(self.helloCapacity(shares));
    var resumption: Hello.Resume = .{ .modes = self.options.resumption != null };
    if (self.sendsTickets12()) resumption.ticket12 = if (self.offered12) |taken| taken.entry.ticket else "";
    if (self.offered) |taken| {
        const entry = taken.entry;
        // The obfuscated age: milliseconds since the ticket arrived, plus its obfuscator.
        const now_ms = @divFloor(self.now.?.nanoseconds, std.time.ns_per_ms);
        const age: u64 = @intCast(std.math.clamp(now_ms - entry.received_ms, 0, std.math.maxInt(u32))); // safe: clamped to u32
        resumption.ticket = entry.ticket;
        resumption.age = @truncate(age +% entry.age_add);
        resumption.binder_len = suites.digestLength(entry.suite.tls13().?);
    }
    const scratch = self.scratch.?;
    const hello = try Hello.client(dst, &scratch.random, scratch.session[0..scratch.session_len], scratch.legacy_cookie[0..scratch.legacy_cookie_len], shares, scratch.cookie[0..scratch.cookie_len], self.options.hello, resumption);
    if (self.offered) |taken| {
        // The binder covers the transcript so far and this hello up to its binders.
        const n = resumption.binder_len;
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        const truncated = self.scratch.?.transcripts.digestWith(&digest_buf, n, hello[0 .. hello.len - (2 + 1 + n)]);
        switch (taken.entry.suite.tls13().?) {
            inline else => |tag| {
                const K = Schedule.Schedule(tag);
                K.binder(self.options.hello.transport.prefix(), taken.entry.secretBytes()[0..K.length], truncated[0..K.length], hello[hello.len - K.length ..][0..K.length]);
            },
        }
    }
    try self.state.advance(.client_hello, .initial, .parsed, true);
    try self.queueMessage(.initial, hello);
}

// ---------------------------------------------------------------- inputs

/// Consumes one complete handshake message. `boundary` says the message ended exactly at the
/// end of its record, which key-changing messages require.
pub fn receive(self: *Client, bytes_in: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase == .failed) return error.Closed;
    if (self.need_now != .none) return error.Pending;
    errdefer self.state.fail();
    if (bytes_in.len > self.options.limits.message) return error.HandshakeLimit;
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
        .certificate_request => try self.onCertificateRequest(bytes_in, epoch, boundary),
        .certificate => try self.onCertificate(bytes_in, epoch, boundary),
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
    const answer = try Hello.server(msg, self.scratch.?.session[0..self.scratch.?.session_len], self.offeredShares(&offered), self.options.hello, .{ .psk = self.offered != null, .ticket12 = self.sendsTickets12() and self.retry_suite == null, .session12 = self.offered12 != null and self.retry_suite == null });
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
    if (self.retry_suite) |suite| if (suite != parsed.suite) return error.IllegalParameter;
    // A ticket not taken is spent all the same: it is never offered again.
    defer self.releaseOffer();
    var psk: ?*const SessionCache.Entry = null;
    if (parsed.psk) {
        const entry = self.offered.?.entry;
        // The PSK's hash must be the suite's (RFC 8446 section 4.2.11).
        if (suites.digestLength(entry.suite.tls13().?) != suites.digestLength(parsed.suite)) return error.IllegalParameter;
        try self.state.markResumed();
        psk = entry;
        self.resumed = true;
        self.authenticated = entry.authenticated;
        self.origin = entry.origin;
        self.auth_expires = entry.auth_expires;
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
            const key: ?*const [K.length]u8 = if (psk) |entry| entry.secretBytes()[0..K.length] else null;
            var schedule = try K.init(self.options.hello.transport.prefix(), key, agreed.bytes(), hello_hash[0..Hash.digest_length], &traffic);
            errdefer schedule.deinit();
            self.keys = @unionInit(Keys, @tagName(suite), .{ .schedule = schedule, .handshake = traffic });
        },
    }
    self.eraseShares();
    try self.emitHandshakeSecrets();
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
    self.scratch.?.transcripts.select(parsed.suite);
    try self.scratch.?.transcripts.retry(msg);
    self.retry_suite = parsed.suite;
    // A ticket of another hash cannot follow the server's suite into the second hello.
    // (A TLS 1.2 ticket stays in it, unchanged as a second hello must be, though no longer usable.)
    if (self.offered) |taken| if (suites.digestLength(taken.entry.suite.tls13().?) != suites.digestLength(parsed.suite)) self.releaseOffer13();
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

fn onEncrypted(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.encrypted_extensions, epoch, .parsed, boundary);
    const parsed = try Hello.encrypted(msg, self.options.hello);
    try self.scratch.?.transcripts.commit(msg);
    for (self.options.hello.alpn) |offered| if (std.mem.eql(u8, offered, parsed.alpn)) {
        self.alpn = offered;
    };
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
}

fn onCertificate(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    // The chain outlives this call: a verification request borrows it until answered.
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = try self.gpa.dupe(u8, msg);
    const limits = self.options.limits;
    const parsed = try Messages.certificate(self.held, limits.certificates, limits.chain_bytes, &self.scratch.?.chain);
    if (parsed.context.len != 0) return error.IllegalParameter;
    if (parsed.count == 0) return error.EmptyCertificate;
    self.scratch.?.chain_len = parsed.count;
    try self.scratch.?.transcripts.commit(msg);
    switch (self.options.verify) {
        .none => try self.state.advance(.verify_chain, .handshake, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
    }
}

fn onCertificateVerify(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .possession) return error.UnexpectedMessage;
    const parsed = try Messages.certificateVerify(msg);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    var content_buf: [Messages.max_signed]u8 = undefined;
    const content = Messages.signedContent(&content_buf, true, self.scratch.?.transcripts.digest(&digest_buf));
    try Possession.verify(parsed.scheme, &Hello.schemes, self.scratch.?.chain[0], content, parsed.signature);
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try self.scratch.?.transcripts.commit(msg);
}

fn onFinished(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .finished) return error.UnexpectedMessage;
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
            self.app_write = self.makeTraffic(tag, len, app.client.expose(), "CLIENT_TRAFFIC_SECRET_0");
            self.keyLog("EXPORTER_SECRET", k.schedule.exporter.expose());
        },
    }
    try self.continueFlight();
}

/// The client's second flight: the response to a CertificateRequest, then Finished.
fn continueFlight(self: *Client) Error!void {
    @setRuntimeSafety(true);
    try self.sendCompatCcs();
    if (!self.requested_certificate) return self.finishFlight();
    const auth = self.options.auth orelse return self.sendEmptyCertificate();
    const cert = certificates.certificate.parse(auth.chain()[0], .{}) catch return self.sendEmptyCertificate();
    const request: Messages.CertificateRequest = .{ .context = "", .schemes = self.scratch.?.cr_schemes[0..self.scratch.?.cr_len] };
    const scheme = Possession.choose(cert.public_key, request) orelse return self.sendEmptyCertificate();
    var total: usize = 64;
    for (auth.chain()) |der| total += der.len + 5;
    const dst = try self.reserve(total);
    const message_bytes = try Messages.buildCertificate(dst, "", auth.chain());
    try self.state.advance(.local_certificate, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message_bytes);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const content = Messages.signedContent(&self.scratch.?.sign_content, false, self.scratch.?.transcripts.digest(&digest_buf));
    // safe: signed content is at most 64 + 33 + 1 + 48 bytes.
    self.scratch.?.sign_content_len = @intCast(content.len);
    self.sign_scheme = scheme;
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
    const message_bytes = try Messages.buildCertificate(dst, "", &.{});
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
        },
    }
    self.established = true;
    self.authenticated = self.authenticated and self.options.verify == .full;
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
    const resumption = self.options.resumption orelse return;
    const now = self.now orelse return;
    if (self.version != .tls13 or ticket.lifetime == 0) return;
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
            }) catch return;
        },
    }
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
    if (!self.established or self.state.phase == .failed) return null;
    return .{
        .version = self.version,
        .suite = if (self.suite12) |suite| suites.Suite.from12(suite) else suites.Suite.from13(self.suite.?),
        .group = self.group.?,
        .alpn = self.alpn,
        .server_name = self.options.hello.sni,
        .peer_authenticated = self.authenticated,
        .peer_parameters = self.peer_parameters,
        .resumed = self.resumed,
    };
}

pub const ExportError = @import("Errors.zig").ExportError;

/// RFC 8446 section 7.5 exporter; only after the connection is established.
pub fn exportKeyingMaterial(self: *const Client, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    @setRuntimeSafety(true);
    // A failed connection has erased its secrets; established stays true for the record.
    if (!self.established or self.state.phase == .failed) return error.WrongPhase;
    if (self.version == .tls12) {
        const secrets = self.tls12 orelse return error.WrongPhase;
        return secrets.exportKeyingMaterial(self.suite12 orelse return error.WrongPhase, out, label, context);
    }
    const keys = if (self.keys) |*keys| keys else return error.WrongPhase;
    switch (keys.*) {
        inline else => |*k| try k.schedule.exportBytes(out, label, context),
    }
}

test {
    _ = @import("Client_test.zig");
}
