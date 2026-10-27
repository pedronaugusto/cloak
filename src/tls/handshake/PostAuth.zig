//! TLS 1.3 post-handshake client authentication (RFC 8446 section 4.6.2), over a stream only:
//! QUIC forbids it (RFC 9001 section 4.4) and cloak's datagrams do not build it.
//!
//! A connection keeps one only when the client offered post_handshake_auth (and, at a server,
//! the server allows it): the handshake's transcript through the client's Finished, the hash
//! state alone, which every exchange starts from. An exchange is a CertificateRequest with its
//! own context and the client's Certificate, CertificateVerify and Finished, hashed after that
//! transcript and never into it, so one exchange cannot stand for another.
//!
//! An exchange crosses the connection's halves, so one half holds it at a time (`holder`). At
//! the server the write half issues the request and hands it to the read half, which takes the
//! client's answer, asks for its verification, checks its signature and has the record layer
//! check its Finished under the current read keys; then the request is the write half's again.
//! At the client the read half takes the request, answers its services (entropy for the hedged
//! signature, a signature for a key held elsewhere) and hands the Certificate and
//! CertificateVerify to the write half, which ends them with a Finished under its current write
//! keys and sends all three in one epoch; then the next request is the read half's again. One
//! exchange is outstanding at a time, each way. What the application sees is `Outcome`: how many
//! exchanges completed and what the last one proved, which a server checks before any action a
//! request was made for.
const std = @import("std");
const aegis = @import("aegis");
const Buffer = @import("../wire/Buffer.zig");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const suites = @import("../crypto/Suite.zig");
const Suite13 = suites.Suite13;
const Messages = @import("Messages.zig");
const Hello = @import("Hello.zig");
const Possession = @import("Possession.zig");
const Authorities = @import("Authorities.zig");
const Transcripts = @import("Transcripts.zig");
const Terms = @import("Terms.zig");

pub const Error = @import("Errors.zig").Error;
pub const Need = Terms.Need;
pub const SignRequest = Terms.SignRequest;

/// The half of a connection that holds the exchange.
pub const Half = enum(u8) { read, write };
pub const Role = enum { client, server };

/// The exchanges completed so far and what the last one proved. A server's request returns the
/// number its answer will carry: the answer is in when `generation` reaches it.
pub const Outcome = struct {
    /// Exchanges completed: requests answered (client) or answers checked (server), in order.
    generation: u64,
    /// The last one's client proved a certificate the policy authenticates (server), or
    /// presented one (client). False for an empty Certificate.
    authenticated: bool,
};

pub const ClientState = enum { idle, answering, owed };
pub const ClientEvent = enum { request, answer, sent };
pub const ServerState = enum { idle, requested, chain, possession, finished, checking };
pub const ServerEvent = enum { request, certificate, empty_certificate, verify_chain, certificate_verify, finished, settle };

pub const ClientMachine = aegis.state.Machine(ClientState, ClientEvent, .{ .initial = .idle, .edges = &.{
    .{ .from = .idle, .on = .request, .to = .answering },
    .{ .from = .answering, .on = .answer, .to = .owed },
    .{ .from = .owed, .on = .sent, .to = .idle },
} });

pub const ServerMachine = aegis.state.Machine(ServerState, ServerEvent, .{ .initial = .idle, .edges = &.{
    .{ .from = .idle, .on = .request, .to = .requested },
    .{ .from = .requested, .on = .certificate, .to = .chain },
    .{ .from = .requested, .on = .empty_certificate, .to = .finished },
    .{ .from = .chain, .on = .verify_chain, .to = .possession },
    .{ .from = .possession, .on = .certificate_verify, .to = .finished },
    .{ .from = .finished, .on = .finished, .to = .checking },
    .{ .from = .checking, .on = .settle, .to = .idle },
} });

/// What a server checks a client's answer against: its handshake policy for client chains.
pub const Policy = struct {
    verify: Terms.Verify,
    limits: Terms.Limits,
    require_pq_auth: bool,
};

const PostAuth = @This();

gpa: std.mem.Allocator,
suite: Suite13,
/// The handshake's transcript through the client's Finished.
base: aegis.Secret(Transcripts.Selected),
holder: aegis.Atomic(Half),
machine: union(Role) { client: ClientMachine.Runtime(void), server: ServerMachine.Runtime(void) },
/// The exchange in progress, owned by `holder`.
exchange: ?*Exchange = null,
/// What the read half's exchange waits for.
need: Need = .none,
/// The client's certificate type was agreed as a raw public key in the handshake (RFC 7250):
/// an answer's Certificate is that type.
raw_client: bool,
/// The server asks for ML-DSA alone (`require_pq_auth`).
pq_only: bool,
/// The schemes a server takes from the client's CertificateVerify (`Hello.peerSchemes`), borrowed.
peer: []const Hello.SignatureScheme,
/// Server: the names its requests carry (`Server.Options.certificate_authorities`), borrowed.
authorities: []const []const u8,
/// The server's requests so far; each context is its number.
requests: u64 = 0,
/// The outcome, one cell so either half reads a generation with its own verdict.
outcome: aegis.Atomic(Packed) = .init(.none),
/// Server: the leaf certificate of the last answer that proved one, set as its exchange settles
/// and before its outcome is published; owned, replaced by the next such answer. Kept only with
/// `keep_leaf` (the server's `keep_peer_leaf`).
leaf: []u8 = &.{},
keep_leaf: bool = false,

const Exchange = struct {
    transcript: aegis.Secret(Transcripts.Selected),
    context: [255]u8 = undefined,
    context_len: u8 = 0,
    /// Client: the Certificate and CertificateVerify, built here, sent by the write half.
    flight: Buffer = .{},
    flight_len: usize = 0,
    /// Client: what the CertificateVerify signs, its scheme and the credential that signs.
    sign_scheme: Hello.SignatureScheme = .ed25519,
    credential: u8 = 0,
    sign_content: aegis.Secret([Messages.max_signed]u8) = .init(@splat(0)),
    sign_content_len: u8 = 0,
    /// The transcript through the CertificateVerify (or the empty Certificate), and at a server
    /// the Finished the client sent.
    digest: aegis.Secret([Transcripts.max_digest]u8) = .init(@splat(0)),
    digest_len: u8 = 0,
    received: aegis.Secret([Transcripts.max_digest]u8) = .init(@splat(0)),
    /// Server: the client's Certificate, held while its chain is verified, and the chain in it.
    held: Buffer = .{},
    chain: [Messages.max_certificates][]const u8 = undefined,
    chain_len: usize = 0,
    now: ?std.Io.Timestamp = null,
    /// Server: the leaf's copy once its key signed, kept by `settled`.
    leaf: []u8 = &.{},
    /// The client presented a certificate (client); the server's policy authenticated it.
    presented: bool = false,
    authenticated: bool = false,
};

/// Keeps what later exchanges need: `transcript`, the handshake's through the client's Finished.
pub fn init(gpa: std.mem.Allocator, role: Role, suite: Suite13, transcript: *const Transcripts, raw_client: bool, pq_only: bool, peer: []const Hello.SignatureScheme, authorities: []const []const u8) std.mem.Allocator.Error!*PostAuth {
    const self = try gpa.create(PostAuth);
    self.* = .{
        .gpa = gpa,
        .suite = suite,
        .base = .init(transcript.selected()),
        .holder = .init(if (role == .client) .read else .write),
        .machine = switch (role) {
            .client => .{ .client = .init({}) },
            .server => .{ .server = .init({}) },
        },
        .raw_client = raw_client,
        .pq_only = pq_only,
        .peer = peer,
        .authorities = authorities,
    };
    return self;
}

pub fn deinit(self: *PostAuth) void {
    const gpa = self.gpa;
    self.endExchange();
    if (self.leaf.len != 0) gpa.free(self.leaf);
    // The transcript is the only secret kept between exchanges; the leaf is the certificate
    // handed to the caller.
    self.base.deinit();
    gpa.destroy(self);
}

/// The completed exchanges and the last one's verdict; from either half.
pub fn result(self: *const PostAuth) Outcome {
    return self.outcome.load(.acquire).unpack();
}

/// An `Outcome` in one word: the generation shifted left by one, the verdict in the low bit.
const Packed = enum(u64) {
    none = 0,
    _,

    fn pack(outcome: Outcome) Packed {
        return @fromBackingInt(outcome.generation << 1 | @intFromBool(outcome.authenticated));
    }

    fn unpack(self: Packed) Outcome {
        const word = @backingInt(self);
        return .{ .generation = word >> 1, .authenticated = word & 1 != 0 };
    }
};

/// The leaf of the last settled answer that proved one, after its outcome; null when none has.
pub fn latestLeaf(self: *const PostAuth) ?[]const u8 {
    if (self.outcome.load(.acquire) == .none) return null;
    return if (self.leaf.len == 0) null else self.leaf;
}

fn record(self: *PostAuth, authenticated: bool) void {
    const generation = self.outcome.load(.acquire).unpack().generation + 1;
    self.outcome.store(.pack(.{ .generation = generation, .authenticated = authenticated }), .release);
}

fn startExchange(self: *PostAuth) std.mem.Allocator.Error!*Exchange {
    aegis.assert.invariant(self.exchange == null, "one exchange at a time");
    const ex = try self.gpa.create(Exchange);
    ex.* = .{ .transcript = .init(self.base.expose().*) };
    self.exchange = ex;
    return ex;
}

fn endExchange(self: *PostAuth) void {
    const ex = self.exchange orelse return;
    ex.flight.free(self.gpa);
    ex.held.free(self.gpa);
    if (ex.leaf.len != 0) self.gpa.free(ex.leaf);
    ex.transcript.deinit();
    ex.sign_content.deinit();
    ex.digest.deinit();
    ex.received.deinit();
    self.gpa.destroy(ex);
    self.exchange = null;
    self.need = .none;
}

fn digestLength(self: *const PostAuth) usize {
    return suites.digestLength(self.suite);
}

// ---------------------------------------------------------------- client

/// A CertificateRequest after the handshake, in the read half. A request while the last answer
/// still waits for the write half is a second one outstanding, and refused. The answer is ready
/// (`answered`) at once or after the services it asks for.
pub fn onRequest(self: *PostAuth, msg: []const u8, credentials: []const Terms.ClientCredential) Error!void {
    @setRuntimeSafety(true);
    if (self.holder.load(.acquire) != .read) return error.UnexpectedMessage;
    _ = self.machine.client.step(.request) catch return error.UnexpectedMessage;
    const parsed = try Messages.certificateRequest(msg);
    const ex = try self.startExchange();
    @memcpy(ex.context[0..parsed.context.len], parsed.context);
    ex.context_len = @intCast(parsed.context.len); // safe: a vector<0..255>
    try ex.transcript.exposeMut().commit(msg);
    // A credential of the type the handshake agreed (RFC 7250), with a scheme the server takes,
    // the first that chains to an authority it names, else the first (RFC 8446 section 4.2.4).
    // Delegated credentials answer only the handshake's request: here the certificate's key signs.
    var pick: Authorities.Pick(Hello.SignatureScheme) = .{};
    for (credentials, 0..) |credential, i| {
        const identity = credential.auth.identity;
        if ((identity.form() == .raw_public_key) != self.raw_client) continue;
        if (credential.must_match_issuer and !Authorities.matches(identity, parsed.authorities)) continue;
        const fit = Possession.choose(identity.publicKey(), credential.schemes, parsed) orelse continue;
        if (pick.offer(i, fit, Authorities.prefers(identity, parsed.authorities))) break;
    }
    const choice = pick.chosen();
    const scheme = if (choice) |c| c.value else null;
    if (choice) |c| ex.credential = @intCast(c.index); // safe: at most 32 credentials
    const entries: []const []const u8 = if (choice) |c| credentials[c.index].auth.entries() else &.{};
    var total: usize = 64 + 8 + certificates.PrivateKey.max_signature;
    for (entries) |der| total += der.len + 5;
    const certificate = try Messages.buildCertificate(try ex.flight.ensure(self.gpa, total), parsed.context, entries, .{});
    ex.flight_len = certificate.len;
    try ex.transcript.exposeMut().commit(certificate);
    const chosen = scheme orelse return self.answered(false);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const content = Messages.signedContent(ex.sign_content.exposeMut(), false, ex.transcript.expose().digest(&digest_buf));
    ex.sign_content_len = @intCast(content.len); // safe: signed content is at most 146 bytes
    ex.sign_scheme = chosen;
    const identity = credentials[ex.credential].auth.identity;
    // Cloak signs for a key it holds, with fresh noise; a key held elsewhere is the caller's.
    if (identity.noiseLength()) |noise| {
        if (noise == 0) return self.signWith(identity, "");
        self.need = .{ .entropy = .{ .len = noise } };
        return;
    }
    self.need = .sign;
}

/// The noise for the hedged signature of the pending answer.
pub fn provideEntropy(self: *PostAuth, entropy: []const u8, credentials: []const Terms.ClientCredential) Error!void {
    @setRuntimeSafety(true);
    const expected = switch (self.need) {
        .entropy => |e| e.len,
        else => return error.UnexpectedService,
    };
    if (entropy.len != expected) return error.InvalidEntropy;
    self.need = .none;
    return self.signWith(credentials[self.exchange.?.credential].auth.identity, entropy);
}

fn signWith(self: *PostAuth, identity: certificates.Identity, noise: []const u8) Error!void {
    @setRuntimeSafety(true);
    const ex = self.exchange.?;
    var out_owner: aegis.Secret([certificates.PrivateKey.max_signature]u8) = .init(undefined);
    defer out_owner.deinit();
    const out = out_owner.exposeMut();
    const signature = Possession.sign(identity, ex.sign_scheme, ex.sign_content.expose()[0..ex.sign_content_len], noise, out) catch return error.SigningFailed;
    return self.addCertificateVerify(signature);
}

/// What a key held elsewhere must sign; valid while `need` is `.sign`.
pub fn signRequest(self: *const PostAuth) SignRequest {
    const ex = self.exchange.?;
    return .{ .scheme = ex.sign_scheme, .content = ex.sign_content.expose()[0..ex.sign_content_len], .credential = ex.credential };
}

/// A signature from a key held elsewhere, checked against the identity's key before it is sent.
pub fn provideSignature(self: *PostAuth, signature: []const u8, credentials: []const Terms.ClientCredential) Error!void {
    @setRuntimeSafety(true);
    if (self.need != .sign) return error.UnexpectedService;
    const ex = self.exchange.?;
    Possession.verifyKey(@backingInt(ex.sign_scheme), &.{ex.sign_scheme}, credentials[ex.credential].auth.identity.publicKey(), ex.sign_content.expose()[0..ex.sign_content_len], signature) catch return error.BadSignature;
    self.need = .none;
    return self.addCertificateVerify(signature);
}

fn addCertificateVerify(self: *PostAuth, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const ex = self.exchange.?;
    const built = try Messages.buildCertificateVerify(ex.flight.bytes()[ex.flight_len..], @backingInt(ex.sign_scheme), signature);
    try ex.transcript.exposeMut().commit(built);
    ex.flight_len += built.len;
    return self.answered(true);
}

/// The answer is built: the write half ends it with its Finished.
fn answered(self: *PostAuth, presented: bool) Error!void {
    @setRuntimeSafety(true);
    const ex = self.exchange.?;
    ex.presented = presented;
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const digest = ex.transcript.expose().digest(&digest_buf);
    @memcpy(ex.digest.exposeMut()[0..digest.len], digest);
    ex.digest_len = @intCast(digest.len); // safe: 32 or 48
    _ = self.machine.client.step(.answer) catch unreachable; // unreachable: answering until now
    self.holder.store(.write, .release);
}

/// Whether the read half's answer is built and waits for the write half.
pub fn answerReady(self: *const PostAuth) bool {
    return self.holder.load(.acquire) == .write and self.machine.client.current() == .owed;
}

pub const Response = struct {
    /// The Certificate and, when one was presented, the CertificateVerify.
    flight: []const u8,
    /// The transcript the Finished covers.
    transcript: []const u8,
};

/// The answer for the write half to end with its Finished and send.
pub fn response(self: *const PostAuth) Response {
    aegis.assert.pre(self.holder.load(.acquire) == .write and self.machine.client.current() == .owed, "the write half holds a built answer");
    const ex = self.exchange.?;
    return .{ .flight = ex.flight.view()[0..ex.flight_len], .transcript = ex.digest.expose()[0..ex.digest_len] };
}

/// The write half sent the answer, or never will (it closed): the next request is the read
/// half's again.
pub fn sent(self: *PostAuth) void {
    aegis.assert.pre(self.holder.load(.acquire) == .write and self.machine.client.current() == .owed, "the write half holds a built answer");
    const presented = self.exchange.?.presented;
    self.endExchange();
    _ = self.machine.client.step(.sent) catch unreachable; // unreachable: owed until now
    self.record(presented);
    self.holder.store(.read, .release);
}

// ---------------------------------------------------------------- server

pub const Request = struct {
    /// The CertificateRequest to send.
    message: []u8,
    /// The generation the answer to it will complete.
    number: u64,
};

/// Builds the next CertificateRequest into `out`, in the write half: a context of its own (the
/// request's number, never repeated on the connection) and the signature schemes the handshake's
/// request named. `RequestOutstanding` while the last one has no checked answer. The read half
/// takes the answer only once `publish` hands the request over, after it is sealed.
pub fn request(self: *PostAuth, out: []u8) (Error || error{RequestOutstanding})!Request {
    @setRuntimeSafety(true);
    if (self.holder.load(.acquire) != .write) return error.RequestOutstanding;
    aegis.assert.invariant(self.machine.server.current() == .idle, "the write half holds the server's exchange only when idle");
    const number = self.requests + 1;
    var context: [8]u8 = undefined;
    std.mem.writeInt(u64, &context, number, .big);
    var taken: [Hello.max_peer_schemes]Hello.SignatureScheme = undefined;
    const allowed = Hello.peerSchemes(self.peer, Hello.verifySchemes(.{ .require_pq_auth = self.pq_only }), &taken);
    var schemes: [Hello.schemes.len]u16 = undefined;
    for (allowed, schemes[0..allowed.len]) |scheme, *slot| slot.* = @backingInt(scheme);
    const message = try Messages.buildCertificateRequest(out, &context, schemes[0..allowed.len], &.{}, self.authorities);
    const ex = try self.startExchange();
    errdefer self.endExchange();
    @memcpy(ex.context[0..8], &context);
    ex.context_len = 8;
    try ex.transcript.exposeMut().commit(message);
    _ = self.machine.server.step(.request) catch unreachable; // unreachable: idle, checked above
    self.requests = number;
    return .{ .message = message, .number = number };
}

/// The request is sealed: its answer is the read half's to take.
pub fn publish(self: *PostAuth) void {
    aegis.assert.pre(self.machine.server.current() == .requested, "a built request is published");
    self.holder.store(.read, .release);
}

/// Whether the read half is inside a client's answer, between its Certificate and its Finished,
/// where nothing else may come (RFC 8446 section 4.6.2).
pub fn midFlight(self: *const PostAuth) bool {
    if (self.holder.load(.acquire) != .read) return false;
    return switch (self.machine.server.current()) {
        .chain, .possession, .finished, .checking => true,
        .idle, .requested => false,
    };
}

fn admitAnswer(self: *PostAuth) Error!*Exchange {
    // An answer with no request outstanding is unsolicited.
    if (self.holder.load(.acquire) != .read) return error.UnexpectedMessage;
    return self.exchange orelse error.UnexpectedMessage;
}

/// The client's Certificate: the outstanding request's context, then its chain, whose
/// verification is asked for as in the handshake.
pub fn onCertificate(self: *PostAuth, msg: []const u8, policy: Policy) Error!void {
    @setRuntimeSafety(true);
    const ex = try self.admitAnswer();
    var probe: [Messages.max_certificates][]const u8 = undefined;
    const parsed = try Messages.certificate(msg, policy.limits.certificates, policy.limits.chain_bytes, &probe, .{});
    if (self.machine.server.current() != .requested) return error.UnexpectedMessage;
    // The answer to this request and no other: a context it did not send is a replay or a mix-up.
    if (!std.mem.eql(u8, parsed.context, ex.context[0..ex.context_len])) return error.IllegalParameter;
    if (parsed.count == 0) {
        _ = self.machine.server.step(.empty_certificate) catch unreachable; // unreachable: requested
        try ex.transcript.exposeMut().commit(msg);
        return;
    }
    _ = self.machine.server.step(.certificate) catch unreachable; // unreachable: requested
    const held = (try ex.held.ensure(self.gpa, msg.len))[0..msg.len];
    @memcpy(held, msg);
    const kept = try Messages.certificate(held, policy.limits.certificates, policy.limits.chain_bytes, &ex.chain, .{});
    ex.chain_len = kept.count;
    try ex.transcript.exposeMut().commit(msg);
    ex.presented = true;
    if (self.raw_client) {
        // The raw key the handshake agreed for the client (RFC 7250), one the policy pins.
        _ = try Possession.pinnedKey(ex.chain[0..ex.chain_len], policy.verify.raw_key.pins);
        return self.chainVerified(true);
    }
    switch (policy.verify) {
        .none => return self.chainVerified(false),
        .full => self.need = .time,
        .leaf_key => |leaf| {
            _ = try Possession.pinnedLeaf(ex.chain[0], leaf.pins);
            return self.chainVerified(true);
        },
        // A chain where only a pinned raw key is trusted: the client did not take that type.
        .raw_key => return error.UnsupportedCertificate,
    }
}

fn chainVerified(self: *PostAuth, authenticated: bool) Error!void {
    _ = self.machine.server.step(.verify_chain) catch unreachable; // unreachable: chain
    self.exchange.?.authenticated = authenticated;
}

/// The clock for this answer's verification: the handshake's time is long past.
pub fn provideTime(self: *PostAuth, now: std.Io.Timestamp) Error!void {
    if (self.need != .time) return error.UnexpectedService;
    self.exchange.?.now = now;
    self.need = .verify;
}

/// The verification request for the answer's chain; valid while `need` is `.verify`.
pub fn verification(self: *const PostAuth, token: types.Token, policy: Policy) types.Request {
    const full = policy.verify.full;
    const ex = self.exchange.?;
    return .{
        .chain = ex.chain[0..ex.chain_len],
        .identity = .none,
        .purpose = .client,
        .time = ex.now.?,
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

pub fn provideVerification(self: *PostAuth, token: types.Token, receipt: *const types.Verification, policy: Policy) Error!void {
    @setRuntimeSafety(true);
    if (self.need != .verify) return error.UnexpectedService;
    receipt.check(self.verification(token, policy)) catch return error.VerificationRejected;
    if (!try Possession.signs(receipt.path[0])) return error.KeyUsage;
    if (policy.require_pq_auth and !Possession.postQuantumPath(receipt.path)) return error.PqAuthenticationRequired;
    self.need = .none;
    return self.chainVerified(true);
}

/// The chain failed verification, or its service did: the connection ends.
pub fn rejectVerification(self: *PostAuth) void {
    self.need = .none;
}

/// The client's CertificateVerify, by the key of its leaf over the exchange's transcript.
pub fn onCertificateVerify(self: *PostAuth, msg: []const u8) Error!void {
    @setRuntimeSafety(true);
    const ex = try self.admitAnswer();
    if (self.machine.server.current() != .possession) return error.UnexpectedMessage;
    const parsed = try Messages.certificateVerify(msg);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    var content_buf: [Messages.max_signed]u8 = undefined;
    const content = Messages.signedContent(&content_buf, false, ex.transcript.expose().digest(&digest_buf));
    var taken: [Hello.max_peer_schemes]Hello.SignatureScheme = undefined;
    try Possession.verifyKey(parsed.scheme, Hello.peerSchemes(self.peer, Hello.verifySchemes(.{ .require_pq_auth = self.pq_only }), &taken), try Possession.peerKey(ex.chain[0], self.raw_client), content, parsed.signature);
    _ = self.machine.server.step(.certificate_verify) catch unreachable; // unreachable: possession
    try ex.transcript.exposeMut().commit(msg);
    if (self.keep_leaf) try Possession.keepLeaf(self.gpa, &ex.leaf, ex.chain[0], self.raw_client);
}

/// The client's Finished: the record layer checks it under the keys it came under
/// (`finishedCheck`) before the exchange counts (`settled`).
pub fn onFinished(self: *PostAuth, msg: []const u8) Error!void {
    @setRuntimeSafety(true);
    const ex = try self.admitAnswer();
    if (self.machine.server.current() != .finished) return error.UnexpectedMessage;
    const n = self.digestLength();
    const received = try Messages.finished(msg, n);
    @memcpy(ex.received.exposeMut()[0..n], received);
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    @memcpy(ex.digest.exposeMut()[0..n], ex.transcript.expose().digest(&digest_buf));
    ex.digest_len = @intCast(n); // safe: 32 or 48
    _ = self.machine.server.step(.finished) catch unreachable; // unreachable: finished
}

pub const FinishedCheck = struct { transcript: []const u8, received: []const u8 };

/// The Finished the record layer checks, and the transcript it must be the MAC of.
pub fn finishedCheck(self: *const PostAuth) FinishedCheck {
    aegis.assert.pre(self.machine.server.current() == .checking, "a received Finished awaits its check");
    const ex = self.exchange.?;
    return .{ .transcript = ex.digest.expose()[0..ex.digest_len], .received = ex.received.expose()[0..ex.digest_len] };
}

/// The record layer accepted the Finished: the exchange counts, and the next request is the
/// write half's to make.
pub fn settled(self: *PostAuth) void {
    aegis.assert.pre(self.machine.server.current() == .checking, "a checked Finished settles its exchange");
    const ex = self.exchange.?;
    const authenticated = ex.authenticated;
    if (ex.leaf.len != 0) {
        if (self.leaf.len != 0) self.gpa.free(self.leaf);
        self.leaf = ex.leaf;
        ex.leaf = &.{};
    }
    self.endExchange();
    _ = self.machine.server.step(.settle) catch unreachable; // unreachable: checking
    self.record(authenticated);
    self.holder.store(.write, .release);
}

test {
    _ = @import("PostAuth_test.zig");
}
