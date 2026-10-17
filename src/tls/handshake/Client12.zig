//! The TLS 1.2 client handshake, continuing a `Client` whose ServerHello chose TLS 1.2. The
//! server's Certificate, ServerKeyExchange, optional CertificateRequest and ServerHelloDone; then
//! the client's ECDHE share, optional certificate and CertificateVerify, ChangeCipherSpec and
//! Finished; then the server's ChangeCipherSpec and Finished. Only ECDHE with AEAD suites and
//! the extended master secret (RFC 7627); no renegotiation. With a session ticket (RFC 5077) the
//! server may instead resume: its ServerHello echoes the session id, then its ChangeCipherSpec
//! and Finished, then the client's, all from the ticket's master secret; a NewSessionTicket comes
//! before the server's ChangeCipherSpec whenever its ServerHello said so.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const suites = @import("../crypto/Suite.zig");
const Prf = @import("../crypto/Prf.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Group = @import("../crypto/Group.zig").Group;
const Flight = @import("Flight.zig");
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const Messages12 = @import("Messages12.zig");
const Possession = @import("Possession.zig");
const Transcripts = @import("Transcripts.zig");

const Error = @import("Errors.zig").Error;
const Epoch = Flight.Epoch;

/// Bits of `Scratch.cr_types`: the certificate types a CertificateRequest named.
pub const rsa_sign = 1;
pub const ecdsa_sign = 2;

pub fn onServerHello(self: anytype, msg: []const u8, hello: Hello.ServerHello12, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    self.version = .tls12;
    self.state.version = .tls12;
    // The offered ticket is spent whether or not it resumed.
    defer self.releaseOffer();
    if (hello.resumed) {
        // The parser accepts the echo only when a ticket went with the session id.
        const entry = self.offered12.?.entry;
        // A session resumes with the suite it was made with.
        if (entry.suite.tls12().? != hello.suite) return error.IllegalParameter;
        try self.state.markResumed();
        self.resumed = true;
        self.authenticated = entry.authenticated;
        self.origin = entry.origin;
        self.auth_expires = entry.auth_expires;
        self.group = entry.group;
    }
    self.state.ticket12 = hello.ticket;
    try self.state.advance(.server_hello, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    self.suite12 = hello.suite;
    self.tls12 = try Flight.Secrets12.create(self.gpa);
    @memcpy(self.tls12.?.randoms[0..32], &scratch.random);
    @memcpy(self.tls12.?.randoms[32..64], hello.random);
    for (self.options.hello.alpn) |offered| if (std.mem.eql(u8, offered, hello.alpn)) {
        self.alpn = offered;
    };
    self.srtp = hello.srtp;
    self.noteConnectionId(hello.connection_id);
    // The TLS 1.3 key shares play no part in a TLS 1.2 exchange.
    self.eraseShares();
    // A datagram client that offered both versions hashed its hello both ways until now.
    scratch.transcripts.choose12();
    try scratch.transcripts.commit(msg);
    if (self.resumed) {
        // The session's master secret, and the keys of both directions from it and the new randoms.
        @memcpy(self.tls12.?.master.exposeMut(), self.offered12.?.entry.secretBytes());
        switch (hello.suite) {
            inline else => |suite| self.tls12.?.deriveKeys(suites.Hash12(suite), suite, .client),
        }
        self.keyLog("CLIENT_RANDOM", self.tls12.?.master.expose());
    }
}

pub fn receive(self: anytype, kind: Messages.Type, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    switch (kind) {
        .certificate => try onCertificate(self, msg, epoch, boundary),
        .server_key_exchange => try onServerKeyExchange(self, msg, epoch, boundary),
        .certificate_request => try onCertificateRequest(self, msg, epoch, boundary),
        .server_hello_done => try onServerHelloDone(self, msg, epoch, boundary),
        .new_session_ticket => try onTicket(self, msg, epoch, boundary),
        .finished => try onFinished(self, msg, epoch, boundary),
        // A server asking to renegotiate. cloak never renegotiates: while negotiating the request
        // is ignored, as RFC 5246 section 7.4.1.1 says, and afterwards refused with a warning.
        .hello_request => {
            if (msg.len != 4) return error.DecodeError;
            if (self.established) try self.push(.refuse_renegotiation);
        },
        else => return error.UnexpectedMessage,
    }
}

fn onCertificate(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    // The chain outlives this call: a verification request borrows it until answered.
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = try self.gpa.dupe(u8, msg);
    const limits = self.options.limits;
    const count = try Messages12.certificate(self.held, limits.certificates, limits.chain_bytes, &scratch.chain);
    if (count == 0) return error.EmptyCertificate;
    scratch.chain_len = count;
    try scratch.transcripts.commit(msg);
    switch (self.options.verify) {
        .none => try self.state.advance(.verify_chain, .initial, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
        // unreachable: a raw-key policy offers TLS 1.3 alone, and a TLS 1.2 answer was refused.
        .raw_key => unreachable,
    }
}

/// The certificate's key must be one the suite authenticates with: ECDSA suites take EC and
/// EdDSA keys (RFC 8422), RSA suites take RSA keys.
fn suiteKey(suite: suites.Suite12, key: certificates.certificate.PublicKey) Error!void {
    const ok = switch (suite.authentication()) {
        .ecdsa => key == .ec or key == .ed25519,
        .rsa => key == .rsa,
    };
    if (!ok) return error.UnsupportedKey;
}

fn onServerKeyExchange(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .server_key_exchange12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const ske = try Messages12.serverKeyExchange(msg);
    if (!std.mem.containsAtLeast(Group, self.options.hello.groups, 1, &.{ske.group})) return error.UnofferedSelection;
    const leaf = certificates.certificate.parse(scratch.chain[0], .{}) catch return error.InvalidCertificate;
    try suiteKey(self.suite12.?, leaf.public_key);
    var content_buf: [Messages12.max_signed]u8 = undefined;
    const content = Messages12.signedParams(&content_buf, self.tls12.?.clientRandom(), self.tls12.?.serverRandom(), ske.params);
    try Possession.verifyMessage12(ske.scheme, &Hello.schemes12, scratch.chain[0], content, ske.signature);
    try self.state.advance(.server_key_exchange, epoch, .possession, boundary);
    try scratch.transcripts.commit(msg);
    self.group = ske.group;
    @memcpy(scratch.server_public[0..ske.public.len], ske.public);
    // safe: a classical public value is at most 97 bytes, checked by the parser.
    scratch.server_public_len = @intCast(ske.public.len);
}

fn onCertificateRequest(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.certificate_request, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    const parsed = try Messages12.certificateRequest(msg);
    try scratch.transcripts.commit(msg);
    self.requested_certificate = true;
    var types: u8 = 0;
    for (parsed.types) |kind| switch (kind) {
        1 => types |= rsa_sign,
        64 => types |= ecdsa_sign,
        else => {},
    };
    scratch.cr_types = types;
    const keep = @min(parsed.schemes.len, scratch.cr_schemes.len) & ~@as(usize, 1);
    @memcpy(scratch.cr_schemes[0..keep], parsed.schemes[0..keep]);
    // safe: at most 1024 bytes are kept.
    scratch.cr_len = @intCast(keep);
}

fn onServerHelloDone(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.server_hello_done, epoch, .parsed, boundary);
    try Messages12.serverHelloDone(msg);
    try self.scratch.?.transcripts.commit(msg);
    // The client's own ECDHE key comes from fresh entropy, after the server named the group.
    self.need_now = .{ .entropy = .{ .len = Exchange.entropyLength(self.group.?) } };
}

/// The entropy for the client's ECDHE share: send the flight.
pub fn onEntropy(self: anytype, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .local_flight12) return error.UnexpectedService;
    const scratch = self.scratch.?;
    scratch.share12 = Exchange.Share.init(self.group.?, entropy) catch return error.InvalidEntropy;
    self.need_now = .none;
    try sendFlight(self);
}

/// The scheme the client certificate signs with, or null to answer with an empty certificate.
fn chooseCredential(self: anytype) ?Hello.SignatureScheme {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const auth = self.options.auth orelse return null;
    // A raw public key (RFC 7250) is TLS 1.3's here.
    if (auth.identity.form() != .x509) return null;
    const public_key = auth.identity.publicKey();
    const wanted: u8 = switch (public_key) {
        .rsa => rsa_sign,
        // ecdsa_sign stands for EdDSA keys too (RFC 8422 section 5.5); an Ed25519 signature
        // needs the messages the transcript kept from the start.
        .ec => ecdsa_sign,
        .ed25519 => if (scratch.transcripts.keeper != null) ecdsa_sign else return null,
        // ML-DSA is TLS 1.3's only (draft-ietf-tls-mldsa).
        .mldsa => return null,
    };
    if (scratch.cr_types & wanted == 0) return null;
    const request: Messages12.CertificateRequest = .{ .types = "", .schemes = scratch.cr_schemes[0..scratch.cr_len] };
    return Possession.chooseClient12(public_key, request);
}

fn sendFlight(self: anytype) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var scheme: ?Hello.SignatureScheme = null;
    if (self.requested_certificate) {
        scheme = chooseCredential(self);
        const chain: []const []const u8 = if (scheme != null) self.options.auth.?.chain() else &.{};
        var total: usize = 16;
        for (chain) |der| total += der.len + 3;
        const message = try Messages12.buildCertificate(try self.reserve(total), chain);
        try self.state.advance(if (scheme != null) .local_certificate else .local_empty_certificate, .initial, .parsed, true);
        try self.queueMessage(.initial, message);
    }
    const share = &scratch.share12.?;
    const exchange = try Messages12.buildClientKeyExchange(try self.reserve(8 + share.wire().len), share.wire());
    try self.state.advance(.local_key_exchange, .initial, .parsed, true);
    try self.queueMessage(.initial, exchange);
    var agreed = try share.agree(scratch.server_public[0..scratch.server_public_len]);
    defer agreed.deinit();
    share.deinit();
    scratch.share12 = null;
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            // The session hash covers the handshake through ClientKeyExchange (RFC 7627).
            const session_hash = scratch.transcripts.digestOf(&digest_buf, Hash.digest_length);
            Prf.masterSecret(Hash, self.tls12.?.master.exposeMut(), agreed.bytes(), session_hash);
        },
    }
    self.keyLog("CLIENT_RANDOM", self.tls12.?.master.expose());
    if (scheme) |chosen| {
        self.sign_scheme = chosen;
        if (chosen == .ed25519) {
            // Ed25519 signs the handshake messages so far, kept whole (RFC 8422 section 5.10).
            const identity = self.options.auth.?.identity;
            const messages = scratch.transcripts.keptBytes();
            if (identity.noiseLength()) |noise_length| {
                var out: [certificates.PrivateKey.max_signature]u8 = undefined;
                const signature = Possession.sign12(identity, chosen, messages, scratch.sign_noise[0..noise_length], &out) catch return error.SigningFailed;
                return sendCertificateVerify(self, signature);
            }
            self.need_now = .sign;
            return;
        }
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        const digest = scratch.transcripts.digestOf(&digest_buf, Possession.transcriptHash12(chosen).?);
        @memcpy(scratch.sign_content[0..digest.len], digest);
        // safe: a transcript digest is at most 48 bytes.
        scratch.sign_content_len = @intCast(digest.len);
        const identity = self.options.auth.?.identity;
        // Cloak signs for a key it holds; a key held elsewhere signs the digest for the caller.
        if (identity.noiseLength()) |noise_length| {
            var out: [certificates.PrivateKey.max_signature]u8 = undefined;
            const signature = Possession.signDigest12(identity, chosen, digest, scratch.sign_noise[0..noise_length], &out) catch return error.SigningFailed;
            return sendCertificateVerify(self, signature);
        }
        self.need_now = .sign;
        return;
    }
    try finishFlight(self);
}

/// A signature from the caller's signer for a key cloak does not hold, checked before use.
pub fn onSignature(self: anytype, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    if (self.sign_scheme == .ed25519) {
        Possession.verifyMessage12(@backingInt(self.sign_scheme), &.{self.sign_scheme}, self.options.auth.?.chain()[0], scratch.transcripts.keptBytes(), signature) catch return error.BadSignature;
    } else {
        const digest = scratch.sign_content[0..scratch.sign_content_len];
        Possession.verifyDigest12(@backingInt(self.sign_scheme), &.{self.sign_scheme}, self.options.auth.?.chain()[0], digest, signature) catch return error.BadSignature;
    }
    self.need_now = .none;
    try sendCertificateVerify(self, signature);
}

fn sendCertificateVerify(self: anytype, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const message = try Messages.buildCertificateVerify(try self.reserve(8 + signature.len), @backingInt(self.sign_scheme), signature);
    try self.state.advance(.local_certificate_verify, .initial, .possession, true);
    try self.queueMessage(.initial, message);
    try finishFlight(self);
}

/// ChangeCipherSpec, the client write keys, then Finished under them. The server's keys wait
/// for its ChangeCipherSpec. A resumed session derived both directions at the ServerHello.
fn finishFlight(self: anytype) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    try self.state.advance(.local_ccs, .initial, .parsed, true);
    try self.push(.change_cipher_spec);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            if (!self.resumed) self.tls12.?.deriveKeys(Hash, suite, .client);
            try self.tls12.?.release(self, .write);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            var verify_data: [Prf.verify_length]u8 = undefined;
            Prf.finished(Hash, &verify_data, self.tls12.?.master.expose(), true, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length));
            const message = try Messages.buildFinished(try self.reserve(4 + verify_data.len), &verify_data);
            try self.state.advance(.local_finished, .application, .finished, true);
            try self.queueMessage(.application, message);
        },
    }
}

/// The server's ChangeCipherSpec: its keys protect what follows.
pub fn onCcs(self: anytype) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.ccs, .initial, .parsed, true);
    try self.tls12.?.release(self, .read);
}

fn onFinished(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .peer_finished12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const received = try Messages.finished(msg, Prf.verify_length);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            try Prf.checkFinished(Hash, self.tls12.?.master.expose(), false, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length), received);
        },
    }
    try self.state.advance(.finished, epoch, .finished, boundary);
    try scratch.transcripts.commit(msg);
    // The server's Finished covers its NewSessionTicket: only now is the ticket the server's.
    storeTicket(self);
    // A resumed session's client speaks last.
    if (self.resumed) try finishFlight(self);
    self.established = true;
    self.authenticated = self.authenticated and self.options.verify == .full;
    try self.push(.complete);
}

/// A NewSessionTicket, exactly where the ServerHello promised one; kept until the server's
/// Finished proves it.
fn onTicket(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.ticket, epoch, .parsed, boundary);
    const ticket = try Messages12.newSessionTicket(msg);
    try self.scratch.?.transcripts.commit(msg);
    self.dropTicket12();
    // An empty ticket: the server changed its mind (RFC 5077 section 3.3).
    if (ticket.ticket.len == 0 or self.options.resumption == null) return;
    self.ticket12 = try self.gpa.dupe(u8, ticket.ticket);
    self.ticket12_hint = ticket.lifetime_hint;
}

/// Keeps the session's ticket for a later connection, as the TLS 1.3 client does: it expires with
/// its lifetime hint (or none), the maximum age from the full handshake, or the server
/// authentication's expiry. One the cache cannot keep is dropped.
fn storeTicket(self: anytype) void {
    @setRuntimeSafety(true);
    defer self.dropTicket12();
    const resumption = self.options.resumption orelse return;
    if (self.ticket12.len == 0) return;
    const now = self.now orelse return;
    const now_s = certificates.types.seconds(now);
    const max_age = @divFloor(resumption.max_age.nanoseconds, std.time.ns_per_s);
    const by_age: i64 = std.math.cast(i64, @as(i96, self.origin) + max_age) orelse std.math.maxInt(i64);
    var expires = @min(by_age, self.auth_expires);
    if (self.ticket12_hint != 0) expires = @min(expires, now_s +| @as(i64, self.ticket12_hint));
    if (expires <= now_s) return;
    resumption.cache.store(.{
        .key = &self.cache_key,
        .ticket = self.ticket12,
        .version = .tls12,
        .suite = suites.Suite.from12(self.suite12.?),
        .secret = self.tls12.?.master.expose(),
        .group = self.group.?,
        .age_add = 0,
        .received_ms = std.math.cast(i64, @divFloor(now.nanoseconds, std.time.ns_per_ms)) orelse return,
        .expires = expires,
        .origin = self.origin,
        .auth_expires = self.auth_expires,
        .authenticated = self.authenticated and self.options.verify == .full,
    }) catch return;
}
