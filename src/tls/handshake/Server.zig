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

pub const Epoch = Flight.Epoch;
pub const Emit = Flight.Emit;
pub const Traffic = Flight.Traffic;
pub const Need = Client.Need;
pub const SignRequest = Client.SignRequest;
pub const Verify = Client.Verify;
pub const Limits = Client.Limits;
pub const KeyLog = Client.KeyLog;
pub const Auth = State.Auth;

/// A certificate chain the server can present, and the names it answers for.
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
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    /// Application protocols in the server's order of preference. When set and the client offers
    /// some, one must match.
    alpn: []const []const u8 = &.{},
    /// Fail when the client offers no protocol at all.
    require_alpn: bool = false,
    require_hybrid: bool = false,
    quic: bool = false,
    /// The server's QUIC transport parameters.
    parameters: []const u8 = "",
    /// At least one. The first answers when no name matches or none was sent.
    credentials: []const Credential,
    /// What to do with a server name no credential answers for.
    unknown_name: enum { first, reject } = .first,
    client_auth: Auth = .none,
    /// How a presented client chain is checked; `none` accepts any chain unauthenticated.
    client_verify: Verify = .none,
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Info = Client.Info;

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
credential: usize = 0,
scheme: Hello.SignatureScheme = .ed25519,
keys: ?Keys = null,
peer_parameters: []u8 = &.{},
now: ?std.Io.Timestamp = null,
authenticated: bool = false,
peer_certificate: bool = false,
established: bool = false,
retried: bool = false,
/// The ClientHello is final (not answered by a retry request): the client may send nothing more
/// at the initial level.
answered: bool = false,
ccs_sent: bool = false,
app_read: ?Traffic = null,
server_name_copy: []const u8 = &.{},
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
    /// Client signature_algorithms, kept to pick the CertificateVerify scheme.
    schemes: [256]u8 = undefined,
    schemes_len: u16 = 0,
    /// The server flight is built; only the CertificateVerify signature is missing.
    signing: bool = false,
    // TLS 1.2: the server's ECDHE share and the ServerKeyExchange content it signs.
    share12: ?Exchange.Share = null,
    params12: [Messages12.max_signed]u8 = undefined,
    params12_len: u8 = 0,
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

pub fn init(gpa: std.mem.Allocator, options: Options) InitError!*Server {
    @setRuntimeSafety(true);
    try Hello.validate(.{ .suites = options.suites, .min_version = options.min_version, .max_version = options.max_version, .groups = options.groups, .alpn = options.alpn, .require_alpn = options.require_alpn or options.quic, .require_hybrid = options.require_hybrid, .quic = options.quic, .parameters = options.parameters });
    if (options.credentials.len == 0 or options.credentials.len > 32) return error.InvalidOptions;
    for (options.credentials) |credential| for (credential.names) |name| {
        if (name.len == 0 or name.len > 253) return error.InvalidOptions;
    };
    if (options.client_auth != .none and options.client_verify == .full and options.client_verify.full.limits.certificates == 0) return error.InvalidOptions;
    if (options.limits.message < 1024 or options.limits.handshake < options.limits.message or options.limits.certificates == 0) return error.InvalidOptions;
    const self = try gpa.create(Server);
    errdefer gpa.destroy(self);
    // The credential table is copied; the names it points at and the identities (retained below)
    // are the caller's to keep alive.
    const credentials = try gpa.dupe(Credential, options.credentials);
    errdefer gpa.free(credentials);
    self.* = .{
        .gpa = gpa,
        .options = options,
        .state = .{ .role = .server, .mode = if (options.quic) .quic else .stream, .auth = options.client_auth },
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
    self.state.phase = .failed;
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
    scratch.flight.deinit(self.gpa);
    std.crypto.secureZero(u8, std.mem.asBytes(scratch));
    self.gpa.destroy(scratch);
    self.scratch = null;
}

/// A ChangeCipherSpec record arrived; only TLS 1.2 expects one, once, before the client's Finished.
pub fn receiveCcs(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase == .failed) return error.Closed;
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
    @memcpy(scratch.sign_noise[0 .. entropy.len - exchange_end], entropy[exchange_end..]);
    try self.sendServerFlight(entropy[0..32], &response);
}

pub fn provideTime(self: *Server, now: std.Io.Timestamp) Client.Error!void {
    if (self.need_now != .time) return error.UnexpectedService;
    self.now = now;
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
    try self.state.advance(.verify_chain, if (self.version == .tls12) .initial else .handshake, .chain, true);
    self.authenticated = true;
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
    const leaf = self.options.credentials[self.credential].identity.chain()[0];
    Possession.verify(@backingInt(self.scheme), &.{self.scheme}, leaf, self.signRequest().content, signature) catch return error.BadSignature;
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

pub fn pop(self: *Server) ?Emit {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        const emit = self.post;
        self.post = null;
        return emit;
    };
    return scratch.flight.pop();
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
    try self.scratch.?.transcripts.commit(wire);
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
    if (self.state.phase == .failed) return error.Closed;
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

pub fn credentialFor(self: *const Server, name: []const u8) ?usize {
    @setRuntimeSafety(true);
    for (self.options.credentials, 0..) |credential, i| {
        if (credential.names.len == 0) return i;
        for (credential.names) |pattern| if (nameMatches(pattern, name)) return i;
    }
    return null;
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

fn onClientHello(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.client_hello, epoch, .parsed, boundary);
    // The scratch is the connection's one large allocation, made when a peer first sends a
    // ClientHello the state table accepts; a connection that never speaks holds none.
    const scratch = self.scratch orelse try self.startScratch();
    const hello = try ClientHello.parse(msg);
    const second = self.retried;
    if (!hello.offersVersion(0x0304) or !self.allows13()) {
        // A client without TLS 1.3 (or a server without it): TLS 1.2 when both sides allow it,
        // never after a retry.
        if (second or !self.allows12() or !hello.offers12()) return error.UnsupportedVersion;
        return Server12.onClientHello(self, msg, &hello, epoch, boundary);
    }
    if (second) {
        if (!std.mem.eql(u8, &hello.fingerprint(), &scratch.first)) return error.IllegalParameter;
        if (hello.cookie.len != 0) return error.UnexpectedCookie;
    } else {
        scratch.client_random = hello.random[0..32].*;
        @memcpy(scratch.session[0..hello.session.len], hello.session);
        // safe: parsing bounds the session id at 32 bytes.
        scratch.session_len = @intCast(hello.session.len);
        if (self.options.quic and hello.session.len != 0) return error.IllegalParameter;
        scratch.first = hello.fingerprint();
        @memcpy(scratch.server_name[0..hello.server_name.len], hello.server_name);
        // safe: parsing bounds a host name at 253 bytes.
        scratch.server_name_len = @intCast(hello.server_name.len);
    }
    if (hello.cookie.len != 0) return error.UnexpectedCookie;
    if (!hello.has_schemes) return error.MissingExtension;
    if (!hello.has_groups) return error.MissingExtension;
    if (hello.sharesOutsideGroups()) return error.IllegalParameter;
    try self.negotiate(&hello, second);
    try self.scratch.?.transcripts.commit(msg);
    const group = self.group.?;
    if (hello.shareFor(group)) |share| {
        if (share.len != group.clientShareLength()) return error.IllegalParameter;
        @memcpy(scratch.share[0..share.len], share);
        scratch.share_len = share.len;
        self.answered = true;
        const entropy: Need = .{ .entropy = .{ .len = 32 + Exchange.respondEntropyLength(group) + self.signNoiseLength() } };
        // QUIC: the client's transport parameters are provisional, and the server says nothing
        // that depends on them until the caller accepts them.
        if (self.options.quic and !self.parameters_accepted) {
            self.deferred = entropy;
            self.need_now = .parameters;
        } else self.need_now = entropy;
        return;
    }
    // No usable share: ask once for the group the server chose.
    if (second) return error.IllegalParameter;
    try self.sendRetry(group);
}

/// Whether this server speaks TLS 1.3.
pub fn allows13(self: *const Server) bool {
    const hello: Hello.Options = .{ .suites = self.options.suites, .min_version = self.options.min_version, .max_version = self.options.max_version, .groups = self.options.groups, .require_hybrid = self.options.require_hybrid, .quic = self.options.quic };
    return hello.allows13();
}

/// Whether this server takes TLS 1.2 clients.
pub fn allows12(self: *const Server) bool {
    const hello: Hello.Options = .{ .suites = self.options.suites, .min_version = self.options.min_version, .max_version = self.options.max_version, .groups = self.options.groups, .require_hybrid = self.options.require_hybrid, .quic = self.options.quic };
    return hello.allows12();
}

/// Chooses suite, group, credential, scheme and protocol from the client's offer and the
/// server's preference; the server's order wins.
fn negotiate(self: *Server, hello: *const ClientHello, second: bool) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (second and !self.hasRetryGroup(hello)) return error.IllegalParameter;
    self.suite = for (self.options.suites) |suite| {
        if (suite.tls13()) |candidate| if (hello.offersSuite(@backingInt(candidate))) break candidate;
    } else return error.NoSharedSuite;
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
    if (self.options.require_hybrid and self.group.? != .x25519_mlkem768) return error.HybridRequired;
    if (!second) {
        self.credential = self.credentialFor(hello.server_name) orelse switch (self.options.unknown_name) {
            .first => 0,
            .reject => return error.UnrecognizedName,
        };
    }
    const identity = self.options.credentials[self.credential].identity;
    const leaf = certificates.certificate.parse(identity.chain()[0], .{}) catch return error.InvalidCertificate;
    self.scheme = Possession.choose(leaf.public_key, hello) orelse return error.NoSignatureScheme;
    self.alpn = "";
    if (self.options.alpn.len != 0) {
        if (hello.alpn.len == 0) {
            if (self.options.require_alpn or self.options.quic) return error.NoApplicationProtocol;
        } else self.alpn = hello.selectAlpn(self.options.alpn) orelse return error.NoApplicationProtocol;
    }
    if (self.options.quic) {
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

fn hasRetryGroup(self: *const Server, hello: *const ClientHello) bool {
    const group = self.scratch.?.retry_group orelse return false;
    return hello.shareFor(group) != null;
}

fn sendRetry(self: *Server, group: Group) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    try self.state.advance(.hello_retry, .initial, .parsed, true);
    var buffer: [128]u8 = undefined;
    const hrr = try Hello.buildRetry(&buffer, scratch.session[0..scratch.session_len], self.suite.?, group);
    scratch.transcripts.select(self.suite.?);
    try scratch.transcripts.retry(hrr);
    const dst = try self.reserve(hrr.len);
    @memcpy(dst[0..hrr.len], hrr);
    try scratch.flight.queueMessage(.initial, hrr.len);
    try self.sendCompatCcs();
    self.retried = true;
    scratch.retry_group = group;
}

fn sendCompatCcs(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.ccs_sent or self.scratch.?.session_len == 0) return;
    self.ccs_sent = true;
    try self.push(.compat_ccs);
}

/// ServerHello, key schedule, EncryptedExtensions, optional CertificateRequest and the
/// Certificate; the CertificateVerify waits on the signature.
fn sendServerFlight(self: *Server, random: []const u8, response: *const Exchange.Response) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const suite = self.suite.?;
    var hello_buffer: [1400]u8 = undefined;
    const hello = try Hello.buildServer(&hello_buffer, random[0..32], scratch.session[0..scratch.session_len], suite, self.group.?, response.wire());
    try self.state.advance(.server_hello, .initial, .parsed, true);
    scratch.transcripts.select(suite);
    try scratch.transcripts.commit(hello);
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
            var schedule = try K.init(response.agreed.bytes(), hello_hash[0..Hash.digest_length], &traffic);
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
    try self.sendEncrypted();
    if (self.options.client_auth != .none) try self.sendRequest();
    try self.sendCertificate();
}

fn sendEncrypted(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const dst = try self.reserve(1024 + self.options.parameters.len);
    const message = try Hello.buildEncrypted(dst, .{
        .server_name = scratch.server_name_len != 0,
        .alpn = self.alpn,
        .parameters = if (self.options.quic) self.options.parameters else null,
    });
    try self.state.advance(.encrypted_extensions, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message);
}

fn sendRequest(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    var schemes: [Hello.schemes.len]u16 = undefined;
    for (Hello.schemes, &schemes) |scheme, *slot| slot.* = @backingInt(scheme);
    const dst = try self.reserve(64);
    const message = try Messages.buildCertificateRequest(dst, &schemes);
    try self.state.advance(.certificate_request, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message);
}

fn sendCertificate(self: *Server) Client.Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const identity = self.options.credentials[self.credential].identity;
    var total: usize = 64;
    for (identity.chain()) |der| total += der.len + 5;
    const dst = try self.reserve(total);
    const message = try Messages.buildCertificate(dst, "", identity.chain());
    try self.state.advance(.certificate, .handshake, .parsed, true);
    try self.queueMessage(.handshake, message);
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
            Labels.finished(Hash, &verify_data, k.handshake.server.expose(), before[0..Hash.digest_length]);
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

fn onCertificate(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .client_certificate) return error.UnexpectedMessage;
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
    try scratch.transcripts.commit(msg);
    switch (self.options.client_verify) {
        .none => try self.state.advance(.verify_chain, .handshake, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
    }
}

fn onCertificateVerify(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .client_possession) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const parsed = try Messages.certificateVerify(msg);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    var content_buf: [Messages.max_signed]u8 = undefined;
    const content = Messages.signedContent(&content_buf, false, scratch.transcripts.digest(&digest_buf));
    try Possession.verify(parsed.scheme, &Hello.schemes, scratch.chain[0], content, parsed.signature);
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try scratch.transcripts.commit(msg);
    self.peer_certificate = true;
}

fn onFinished(self: *Server, msg: []const u8, epoch: Epoch, boundary: bool) Client.Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .client_finished) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    var before_buf: [Transcripts.max_digest]u8 = undefined;
    switch (self.keys.?) {
        inline else => |*k, tag| {
            const Hash = suites.Hash(tag);
            const received = try Messages.finished(msg, Hash.digest_length);
            const before = scratch.transcripts.digest(&before_buf);
            try Labels.checkFinished(Hash, k.handshake.client.expose(), before[0..Hash.digest_length], received);
            try self.state.advance(.finished, epoch, .finished, boundary);
            try scratch.transcripts.commit(msg);
            try k.schedule.complete();
            k.handshake.deinit();
        },
    }
    try self.push(.{ .secret = .{ .direction = .read, .epoch = .application, .traffic = self.app_read.? } });
    self.app_read.?.secret.deinit();
    self.app_read = null;
    self.established = true;
    self.authenticated = self.authenticated and self.options.client_verify == .full;
    try self.push(.complete);
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
    if (!self.established or self.state.phase == .failed) return null;
    return .{
        .version = self.version,
        .suite = if (self.suite12) |suite| suites.Suite.from12(suite) else suites.Suite.from13(self.suite.?),
        .group = self.group.?,
        .alpn = self.alpn,
        .server_name = if (self.scratch) |scratch| scratch.server_name[0..scratch.server_name_len] else self.server_name_copy,
        .peer_authenticated = self.authenticated,
        .peer_parameters = self.peer_parameters,
    };
}

pub const ExportError = Client.ExportError;

pub fn exportKeyingMaterial(self: *const Server, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    @setRuntimeSafety(true);
    if (!self.established) return error.WrongPhase;
    if (self.version == .tls12) return Server12.exportKeyingMaterial(self, out, label, context);
    switch (self.keys.?) {
        inline else => |*k| try k.schedule.exportBytes(out, label, context),
    }
}

test {
    _ = @import("Server_test.zig");
}
