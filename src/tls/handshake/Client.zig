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
const Suite = suites.Suite;
const Labels = @import("../crypto/Labels.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Group = @import("../crypto/Group.zig").Group;
const Alert = @import("../wire/Alert.zig").Alert;
const ClientHello = @import("ClientHello.zig");
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const Flight = @import("Flight.zig");
const Possession = @import("Possession.zig");
const Schedule = @import("Schedule.zig");
const State = @import("State.zig");
const Transcripts = @import("Transcripts.zig");

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

pub const Options = struct {
    hello: Hello.Options = .{},
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

pub const SignRequest = struct { scheme: Hello.SignatureScheme, content: []const u8 };

pub const Info = struct {
    suite: Suite,
    group: Group,
    alpn: []const u8,
    server_name: []const u8,
    peer_authenticated: bool,
    peer_parameters: []const u8,
};

pub const InitError = Hello.ValidateError || std.mem.Allocator.Error || error{InvalidOptions};
pub const Error = State.AdvanceError || Hello.ParseError || Hello.EncodeError || Messages.ParseError ||
    Transcripts.CommitError || Labels.CheckError || Possession.Error || Exchange.AgreeError ||
    Schedule.InitError || Schedule.AdvanceError ||
    std.mem.Allocator.Error || error{
    Pending,
    InvalidEntropy,
    EntropyUnavailable,
    BadSignature,
    SigningFailed,
    VerificationFailed,
    VerificationRejected,
    ParametersRejected,
    UnexpectedService,
    QueueFull,
    NoSharedGroup,
    NoSharedSuite,
    NoSignatureScheme,
    UnrecognizedName,
    CertificateRequired,
    UnexpectedCookie,
} || ClientHello.ParseError;

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
        error.Downgrade => .illegal_parameter,
        error.NoApplicationProtocol => .no_application_protocol,
        error.UnofferedScheme, error.SchemeKeyMismatch => .illegal_parameter,
        error.BadSignature, error.BadFinished => .decrypt_error,
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
retry_suite: ?Suite = null,
retry_group: ?Group = null,
ccs_sent: bool = false,
total_bytes: usize = 0,
// Negotiation and peer state.
suite: ?Suite = null,
group: ?Group = null,
keys: ?Keys = null,
alpn: []const u8 = "",
peer_parameters: []u8 = &.{},
held: []u8 = &.{},
now: ?i64 = null,
request_id: u64 = 0,
authenticated: bool = false,
requested_certificate: bool = false,
sign_scheme: Hello.SignatureScheme = .ed25519,
established: bool = false,
/// The client's application write secret, queued after its Finished.
app_write: ?Traffic = null,

const Scratch = struct {
    flight: Flight = .{},
    transcripts: Transcripts = .{},
    random: [32]u8 = @splat(0),
    session: [32]u8 = @splat(0),
    session_len: u8 = 0,
    shares: [2]?Exchange.Share = @splat(null),
    cookie: [4096]u8 = undefined,
    cookie_len: u16 = 0,
    chain: [Messages.max_certificates][]const u8 = undefined,
    chain_len: usize = 0,
    cr_schemes: [1024]u8 = undefined,
    cr_len: u16 = 0,
    sign_content: [Messages.max_signed]u8 = undefined,
    sign_content_len: u8 = 0,
    /// Fresh noise for the hedged client signature, drawn with the first entropy.
    sign_noise: [certificates.PrivateKey.max_noise]u8 = @splat(0),
};

fn Keyed(comptime suite: Suite) type {
    return struct {
        const K = Schedule.Schedule(suite);
        schedule: K,
        handshake: K.Traffic,
    };
}
const Keys = union(Suite) {
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
    if (options.hello.quic and options.compat) return error.InvalidOptions;
    if (options.limits.message < 1024 or options.limits.handshake < options.limits.message or options.limits.certificates == 0) return error.InvalidOptions;
    const self = try gpa.create(Client);
    errdefer gpa.destroy(self);
    const scratch = try gpa.create(Scratch);
    errdefer gpa.destroy(scratch);
    scratch.* = .{};
    self.* = .{ .gpa = gpa, .options = options, .state = .{ .role = .client, .mode = if (options.hello.quic) .quic else .stream }, .scratch = scratch };
    self.need_now = .{ .entropy = .{ .len = self.initialEntropy() } };
    if (options.auth) |auth| self.options.auth = auth.retain();
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

fn initialEntropy(self: *const Client) usize {
    @setRuntimeSafety(true);
    var len: usize = 32 + @as(usize, if (self.options.compat) 32 else 0);
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
    if (self.state.phase == .start) {
        var at: usize = 0;
        self.scratch.?.random = entropy[0..32].*;
        at += 32;
        if (self.options.compat) {
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

fn eraseShares(self: *Client) void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse return;
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
    std.crypto.secureZero(u8, std.mem.asBytes(scratch));
    self.gpa.destroy(scratch);
    self.scratch = null;
}

pub fn provideTime(self: *Client, now: i64) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .time) return error.UnexpectedService;
    self.now = now;
    self.need_now = .verify;
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
    try self.state.advance(.verify_chain, .handshake, .chain, true);
    self.authenticated = true;
    self.need_now = .none;
}

/// The peer chain failed verification (or its service did); the handshake ends.
pub fn rejectVerification(self: *Client) void {
    @setRuntimeSafety(true);
    self.state.fail();
    self.need_now = .none;
}

pub fn signRequest(self: *const Client) SignRequest {
    @setRuntimeSafety(true);
    return .{ .scheme = self.sign_scheme, .content = self.scratch.?.sign_content[0..self.scratch.?.sign_content_len] };
}

/// Checks the signature against the identity's public key before using it.
pub fn provideSignature(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (self.need_now != .sign) return error.UnexpectedService;
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

pub fn pop(self: *Client) ?Emit {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        const emit = self.post;
        self.post = null;
        return emit;
    };
    return scratch.flight.pop();
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

fn push(self: *Client, emit: Emit) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch orelse {
        if (self.post != null) return error.QueueFull;
        self.post = emit;
        return;
    };
    try scratch.flight.push(emit);
}

fn reserve(self: *Client, want: usize) Error![]u8 {
    return self.scratch.?.flight.reserve(self.gpa, want, self.options.limits.handshake);
}

/// `message` was built at the end of the flight buffer: commit it to the transcript and queue it.
fn queueMessage(self: *Client, epoch: Epoch, wire: []const u8) Error!void {
    @setRuntimeSafety(true);
    try self.scratch.?.transcripts.commit(wire);
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
    for (self.options.hello.alpn) |protocol| n += 1 + protocol.len;
    for (shares) |share| n += 4 + share.bytes.len;
    return n;
}

fn sendHello(self: *Client) Error!void {
    @setRuntimeSafety(true);
    var offered: [2]Hello.Share = undefined;
    const shares = self.offeredShares(&offered);
    const dst = try self.reserve(self.helloCapacity(shares));
    const hello = try Hello.client(dst, &self.scratch.?.random, self.scratch.?.session[0..self.scratch.?.session_len], shares, self.scratch.?.cookie[0..self.scratch.?.cookie_len], self.options.hello);
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
    switch (parsed.kind) {
        .server_hello => try self.onServerHello(bytes_in, epoch, boundary),
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
    const parsed = try Hello.server(msg, self.scratch.?.session[0..self.scratch.?.session_len], self.offeredShares(&offered), self.options.hello);
    if (parsed.retry) return self.onRetry(msg, parsed, epoch, boundary);
    try self.state.advance(.server_hello, epoch, .parsed, boundary);
    if (self.retry_suite) |suite| if (suite != parsed.suite) return error.IllegalParameter;
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
            var schedule = try K.init(agreed.bytes(), hello_hash[0..Hash.digest_length], &traffic);
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

fn install(self: *Client, direction: Direction, epoch: Epoch, suite: Suite, len: usize, secret: []const u8, label: []const u8) Error!void {
    @setRuntimeSafety(true);
    var made = self.makeTraffic(suite, len, secret, label);
    errdefer made.secret.deinit();
    try self.push(.{ .secret = .{ .direction = direction, .epoch = epoch, .traffic = made } });
}

fn makeTraffic(self: *const Client, suite: Suite, len: usize, secret: []const u8, label: []const u8) Traffic {
    @setRuntimeSafety(true);
    var holder = aegis.Secret([Transcripts.max_digest]u8).init(@splat(0));
    @memcpy(holder.exposeMut()[0..len], secret[0..len]);
    self.keyLog(label, secret[0..len]);
    // safe: the secret length is a digest length, at most 48.
    return .{ .suite = suite, .secret = holder, .len = @intCast(len) };
}

fn keyLog(self: *const Client, label: []const u8, secret: []const u8) void {
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

fn onRetry(self: *Client, msg: []const u8, parsed: Hello.ServerHello, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.hello_retry, epoch, .parsed, boundary);
    self.scratch.?.transcripts.select(parsed.suite);
    try self.scratch.?.transcripts.retry(msg);
    self.retry_suite = parsed.suite;
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
    if (self.options.hello.quic) {
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
            try Labels.checkFinished(Hash, k.handshake.server.expose(), before[0..Hash.digest_length], received);
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
            Labels.finished(Hash, &verify_data, k.handshake.client.expose(), digest[0..Hash.digest_length]);
            const dst = try self.reserve(4 + Hash.digest_length);
            const message_bytes = try Messages.buildFinished(dst, &verify_data);
            try self.state.advance(.local_finished, .handshake, .finished, true);
            try self.queueMessage(.handshake, message_bytes);
            try self.push(.{ .secret = .{ .direction = .write, .epoch = .application, .traffic = self.app_write.? } });
            self.app_write.?.secret.deinit();
            self.app_write = null;
            try k.schedule.complete();
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
    _ = try Messages.newSessionTicket(msg);
    try self.push(.ticket);
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
        .suite = self.suite.?,
        .group = self.group.?,
        .alpn = self.alpn,
        .server_name = self.options.hello.sni,
        .peer_authenticated = self.authenticated,
        .peer_parameters = self.peer_parameters,
    };
}

pub const ExportError = Schedule.ExportError;

/// RFC 8446 section 7.5 exporter; only after the connection is established.
pub fn exportKeyingMaterial(self: *const Client, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    @setRuntimeSafety(true);
    if (!self.established) return error.WrongPhase;
    switch (self.keys.?) {
        inline else => |*k| try k.schedule.exportBytes(out, label, context),
    }
}

test {
    _ = @import("Client_test.zig");
}
