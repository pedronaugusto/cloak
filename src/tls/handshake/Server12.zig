//! The TLS 1.2 server handshake, taken by a `Server` whose client offered no TLS 1.3. One
//! flight of ServerHello, Certificate, a signed ECDHE ServerKeyExchange, an optional
//! CertificateRequest and ServerHelloDone; then the client's certificate, ClientKeyExchange,
//! CertificateVerify, ChangeCipherSpec and Finished; then the server's ChangeCipherSpec and
//! Finished. ECDHE with AEAD suites only, extended master secret and secure renegotiation
//! indication required, no renegotiation. With TLS 1.2 tickets on, a client's session ticket may
//! resume its session (RFC 5077): the ServerHello echoes its session id, then this server's
//! ChangeCipherSpec and Finished, then the client's; a NewSessionTicket goes before this server's
//! ChangeCipherSpec, in either handshake, to a client that asked. The server random carries the
//! TLS 1.3 downgrade sentinel, since this server would have spoken TLS 1.3.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const suites = @import("../crypto/Suite.zig");
const Prf = @import("../crypto/Prf.zig");
const Exchange = @import("../crypto/Exchange.zig");
const ClientHello = @import("ClientHello.zig");
const Hello = @import("Hello.zig");
const Flight = @import("Flight.zig");
const Messages = @import("Messages.zig");
const Messages12 = @import("Messages12.zig");
const Possession = @import("Possession.zig");
const Transcripts = @import("Transcripts.zig");
const Ticket = @import("../resumption/Ticket.zig");
const types = certificates.types;

const Error = @import("Errors.zig").Error;
const Epoch = Flight.Epoch;

pub fn onClientHello(self: anytype, msg: []const u8, hello: *const ClientHello, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    self.version = .tls12;
    self.state.version = .tls12;
    const scratch = self.scratch.?;
    // A client that supports more than TLS 1.2 retried with less: a downgrade (RFC 7507).
    if (hello.fallback() and self.allows13()) return error.InappropriateFallback;
    if (!hello.extended_master_secret) return error.NoExtendedMasterSecret;
    if (!hello.secureRenegotiation()) return error.NoSecureRenegotiation;
    if (!hello.uncompressed_points) return error.IllegalParameter;
    // TLS 1.2 has no missing_extension alert: without the lists there is no scheme or curve
    // both sides accept (SHA-1 and the default curves are not), a handshake_failure.
    if (!hello.has_schemes) return error.NoSignatureScheme;
    if (!hello.has_groups) return error.NoSharedGroup;
    if (self.tls12 == null) self.tls12 = try @import("Flight.zig").Secrets12.create(self.gpa);
    scratch.client_random = hello.random[0..32].*;
    @memcpy(scratch.server_name[0..hello.server_name.len], hello.server_name);
    // safe: parsing bounds a host name at 253 bytes.
    scratch.server_name_len = @intCast(hello.server_name.len);
    scratch.point_formats = hello.point_formats;
    self.credential = self.credentialFor(hello.server_name) orelse switch (self.options.unknown_name) {
        .first => 0,
        .reject => return error.UnrecognizedName,
    };
    const identity = self.options.credentials[self.credential].identity;
    const leaf = certificates.certificate.parse(identity.chain()[0], .{}) catch return error.InvalidCertificate;
    // The suite must authenticate with the credential's key type, in the server's order.
    const wanted: @TypeOf(suites.Suite12.authentication(.ecdhe_rsa_aes_128_gcm_sha256)) = switch (leaf.public_key) {
        .rsa => .rsa,
        .ec, .ed25519 => .ecdsa,
    };
    // An ECDSA certificate's curve must be one the client lists (RFC 8422 section 5.1).
    switch (leaf.public_key) {
        .ec => |ec| if (!hello.offersGroup(if (ec.curve == .p256) .p256 else .p384)) return error.NoSharedSuite,
        else => {},
    }
    self.suite12 = for (self.options.suites) |suite| {
        const candidate = suite.tls12() orelse continue;
        if (candidate.authentication() == wanted and hello.offersSuite(@backingInt(candidate))) break candidate;
    } else return error.NoSharedSuite;
    self.group = for (self.options.groups) |group| {
        if (group.classical() and hello.offersGroup(group)) break group;
    } else return error.NoSharedGroup;
    self.scheme = Possession.chooseServer12(leaf.public_key, hello) orelse return error.NoSignatureScheme;
    self.alpn = "";
    if (self.options.alpn.len != 0) {
        if (hello.alpn.len == 0) {
            if (self.options.require_alpn) return error.NoApplicationProtocol;
        } else self.alpn = hello.selectAlpn(self.options.alpn) orelse return error.NoApplicationProtocol;
    }
    self.negotiateDatagram(hello);
    _ = epoch;
    _ = boundary;
    // The client's session id: echoed when its ticket resumes.
    @memcpy(scratch.session[0..hello.session.len], hello.session);
    // safe: parsing bounds the session id at 32 bytes.
    scratch.session_len = @intCast(hello.session.len);
    // Tickets are opened and issued by the clock: the hello waits for it.
    if (takesTickets(self, hello) and self.now == null) return self.holdHello(msg);
    return answer(self, msg, hello);
}

/// TLS 1.2 tickets are on and the client sent the SessionTicket extension.
fn takesTickets(self: anytype, hello: *const ClientHello) bool {
    return self.options.tls12_tickets and self.options.tickets != null and hello.session_ticket != null;
}

/// The ClientHello this server answers: its ticket resumes the session if it may, a ticket is
/// promised if one can be issued, and the entropy is asked for.
pub fn answer(self: anytype, msg: []const u8, hello: *const ClientHello) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var issue = false;
    if (takesTickets(self, hello)) {
        var snapshot = self.options.tickets.?.acquire();
        defer if (snapshot) |*held| held.release();
        if (snapshot) |*held| {
            const now = types.seconds(self.now.?);
            if (hello.session_ticket.?.len != 0) try resumeTicket(self, held.ring(), hello, now);
            issue = held.ring().issuing(now) != null;
        }
    }
    self.state.ticket12 = issue;
    // A client may answer the CertificateRequest with Ed25519, which signs the messages themselves.
    if (self.options.client_auth != .none and !self.resumed) scratch.transcripts.keep(self.gpa);
    // DTLS 1.2 numbers both sides' messages from the client's hello.
    if (self.options.transport == .datagram) scratch.transcripts.startDatagram(self.first_sequence, self.first_sequence, false);
    try scratch.transcripts.commit(msg);
    self.answered = true;
    const exchange = if (self.resumed) 0 else Exchange.entropyLength(self.group.?) + self.signNoiseLength();
    self.need_now = .{ .entropy = .{ .len = 32 + exchange + @as(usize, if (issue) Ticket.salt_length else 0) } };
}

/// Resumes the session of a ticket this server opens and may resume: a TLS 1.2 ticket, of a suite
/// both sides still accept, for this name, protocol and client-certificate policy, before its and
/// the client authentication's expiry. Anything else is a full handshake.
fn resumeTicket(self: anytype, ring: *const @import("../resumption/TicketKeys.zig").Ring, hello: *const ClientHello, now: i64) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var state: Ticket.State = undefined;
    Ticket.open(ring, hello.session_ticket.?, now, &state) catch return;
    defer state.deinit();
    if (state.version != .tls12 or state.datagram != (self.options.transport == .datagram)) return;
    const suite = state.suite.tls12() orelse return;
    if (!hello.offersSuite(@backingInt(suite)) or !std.mem.containsAtLeast(suites.Suite, self.options.suites, 1, &.{state.suite})) return;
    if (now >= state.expires or state.issued > now +| 60) return;
    if (!std.ascii.eqlIgnoreCase(state.serverName(), scratch.server_name[0..scratch.server_name_len])) return;
    if (!std.mem.eql(u8, state.alpnBytes(), self.alpn)) return;
    if (!std.mem.eql(u8, &state.policy, &self.policyDigest())) return;
    if (state.client_authenticated) {
        if (now >= state.auth_expires) return;
    } else if (self.options.client_auth == .required) return;
    try self.state.markResumed();
    self.resumed = true;
    self.suite12 = suite;
    self.group = state.group;
    @memcpy(self.tls12.?.master.exposeMut(), state.secretBytes());
    scratch.session_expires = state.expires;
    self.authenticated = state.client_authenticated;
    scratch.client_auth_expires = if (state.client_authenticated) state.auth_expires else std.math.maxInt(i64);
}

/// The server random, its ECDHE share and signing noise (and a ticket's salt): send the flight.
pub fn onEntropy(self: anytype, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var random: [32]u8 = entropy[0..32].*;
    // A server that speaks TLS 1.3 marks a TLS 1.2 random (RFC 8446 section 4.1.3).
    if (self.allows13()) random[24..32].* = Hello.downgrade_tls12.*;
    const salt_at = entropy.len - @as(usize, if (self.state.ticket12) Ticket.salt_length else 0);
    @memcpy(scratch.ticket_entropy[0 .. entropy.len - salt_at], entropy[salt_at..]);
    if (self.resumed) {
        self.need_now = .none;
        @memcpy(self.tls12.?.randoms[0..32], &scratch.client_random);
        @memcpy(self.tls12.?.randoms[32..64], &random);
        return sendResumed(self, &random);
    }
    const group = self.group.?;
    const share_end = 32 + Exchange.entropyLength(group);
    scratch.share12 = Exchange.Share.init(group, entropy[32..share_end]) catch return error.InvalidEntropy;
    self.need_now = .none;
    @memcpy(self.tls12.?.randoms[0..32], &scratch.client_random);
    @memcpy(self.tls12.?.randoms[32..64], &random);
    @memcpy(scratch.sign_noise[0 .. salt_at - share_end], entropy[share_end..salt_at]);
    var hello_buffer: [1024]u8 = undefined;
    const hello = try Hello.buildServer12(&hello_buffer, self.options.transport, &random, "", self.suite12.?, self.alpn, .{ .server_name = scratch.server_name_len != 0, .point_formats = scratch.point_formats, .ticket = self.state.ticket12, .connection_id = self.ownConnectionId(), .srtp = self.srtp });
    try self.state.advance(.server_hello, .initial, .parsed, true);
    try queue(self, hello);
    const identity = self.options.credentials[self.credential].identity;
    var total: usize = 16;
    for (identity.chain()) |der| total += der.len + 3;
    const certificate = try Messages12.buildCertificate(try self.reserve(total), identity.chain());
    try self.state.advance(.certificate, .initial, .parsed, true);
    try self.queueMessage(.initial, certificate);
    const share = &scratch.share12.?;
    var params_buffer: [4 + 97]u8 = undefined;
    const params = try Messages12.buildParams(&params_buffer, group, share.wire());
    const content = Messages12.signedParams(&scratch.params12, &scratch.client_random, &random, params);
    // safe: the signed content is at most 32 + 32 + 4 + 97 bytes.
    scratch.params12_len = @intCast(content.len);
    // Cloak signs for a key it holds; a key held elsewhere is the caller's to sign with.
    if (identity.noiseLength()) |noise_length| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = Possession.sign12(identity, self.scheme, content, scratch.sign_noise[0..noise_length], &out) catch return error.SigningFailed;
        return sendKeyExchange(self, signature);
    }
    self.need_now = .sign;
}

/// The abbreviated handshake's flight: the ServerHello echoing the client's session id, a new
/// ticket if promised, then this server's ChangeCipherSpec and Finished from the session's master
/// secret and the new randoms.
fn sendResumed(self: anytype, random: *const [32]u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var hello_buffer: [1024]u8 = undefined;
    const hello = try Hello.buildServer12(&hello_buffer, self.options.transport, random, scratch.session[0..scratch.session_len], self.suite12.?, self.alpn, .{ .server_name = scratch.server_name_len != 0, .point_formats = scratch.point_formats, .ticket = self.state.ticket12, .connection_id = self.ownConnectionId(), .srtp = self.srtp });
    try self.state.advance(.server_hello, .initial, .parsed, true);
    try queue(self, hello);
    if (self.state.ticket12) try sendTicket(self);
    try self.state.advance(.local_ccs, .initial, .parsed, true);
    try self.push(.change_cipher_spec);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            self.tls12.?.deriveKeys(Hash, suite, .server);
            try self.tls12.?.release(self, .write);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            var verify_data: [Prf.verify_length]u8 = undefined;
            Prf.finished(Hash, &verify_data, self.tls12.?.master.expose(), false, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length));
            const message = try Messages.buildFinished(try self.reserve(4 + verify_data.len), &verify_data);
            try self.state.advance(.local_finished, .application, .finished, true);
            try self.queueMessage(.application, message);
        },
    }
    self.keyLog("CLIENT_RANDOM", self.tls12.?.master.expose());
}

/// The NewSessionTicket the ServerHello promised: the session's master secret, sealed under the
/// ring's issuing key, or an empty ticket if none issues any more (RFC 5077 section 3.3). A
/// resumed session's ticket keeps the expiry its first had; none outlives the client's
/// authentication.
fn sendTicket(self: anytype) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const now = types.seconds(self.now.?);
    var sealed_buf: [Ticket.max_length]u8 = undefined;
    defer std.crypto.secureZero(u8, &sealed_buf);
    var sealed: []const u8 = "";
    var hint: u32 = 0;
    var snapshot = self.options.tickets.?.acquire();
    defer if (snapshot) |*held| held.release();
    if (snapshot) |*held| if (held.ring().issuing(now)) |key| {
        var expires = if (self.resumed) scratch.session_expires else now +| held.ring().lifetime;
        if (self.authenticated) expires = @min(expires, scratch.client_auth_expires);
        if (expires > now) {
            var state: Ticket.State = .{
                .version = .tls12,
                .datagram = self.options.transport == .datagram,
                .suite = suites.Suite.from12(self.suite12.?),
                .group = self.group.?,
                .issued = now,
                .expires = expires,
                .age_add = 0,
                .client_authenticated = self.authenticated,
                .auth_expires = if (self.authenticated) scratch.client_auth_expires else 0,
                .policy = self.policyDigest(),
            };
            defer state.deinit();
            @memcpy(state.secret.exposeMut(), self.tls12.?.master.expose());
            @memcpy(state.alpn[0..self.alpn.len], self.alpn);
            state.alpn_len = @intCast(self.alpn.len); // safe: a protocol name is at most 255 bytes
            @memcpy(state.server_name[0..scratch.server_name_len], scratch.server_name[0..scratch.server_name_len]);
            state.server_name_len = scratch.server_name_len;
            sealed = Ticket.seal(key, scratch.ticket_entropy[0..Ticket.salt_length], &state, &sealed_buf) catch unreachable; // unreachable: the buffer holds the longest ticket
            hint = @intCast(@min(expires - now, Messages.max_ticket_lifetime)); // safe: positive and at most seven days
        }
    };
    const message = try Messages12.buildNewSessionTicket(try self.reserve(4 + 4 + 2 + sealed.len), hint, sealed);
    try self.state.advance(.local_ticket, .initial, .parsed, true);
    try self.queueMessage(.initial, message);
}

fn queue(self: anytype, message: []const u8) Error!void {
    const dst = try self.reserve(message.len);
    @memcpy(dst[0..message.len], message);
    try self.queueMessage(.initial, dst[0..message.len]);
}

/// A signature from the caller's signer for a key cloak does not hold, checked before use.
pub fn onSignature(self: anytype, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const leaf = self.options.credentials[self.credential].identity.chain()[0];
    Possession.verifyMessage12(@backingInt(self.scheme), &.{self.scheme}, leaf, scratch.params12[0..scratch.params12_len], signature) catch return error.BadSignature;
    self.need_now = .none;
    try sendKeyExchange(self, signature);
}

fn sendKeyExchange(self: anytype, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    // The signed content is the two randoms, then the params the message carries.
    const params = scratch.params12[64..scratch.params12_len];
    const message = try Messages12.buildServerKeyExchange(try self.reserve(16 + params.len + signature.len), params, @backingInt(self.scheme), signature);
    try self.state.advance(.server_key_exchange, .initial, .possession, true);
    try self.queueMessage(.initial, message);
    if (self.options.client_auth != .none) {
        var schemes: [Hello.schemes12_verify.len]u16 = undefined;
        for (Hello.schemes12_verify, &schemes) |scheme, *slot| slot.* = @backingInt(scheme);
        const request = try Messages12.buildCertificateRequest(try self.reserve(64), &schemes);
        try self.state.advance(.certificate_request, .initial, .parsed, true);
        try self.queueMessage(.initial, request);
    }
    const done = try Messages12.buildServerHelloDone(try self.reserve(4));
    try self.state.advance(.server_hello_done, .initial, .parsed, true);
    try self.queueMessage(.initial, done);
}

pub fn receive(self: anytype, kind: Messages.Type, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    switch (kind) {
        .certificate => try onCertificate(self, msg, epoch, boundary),
        .client_key_exchange => try onClientKeyExchange(self, msg, epoch, boundary),
        .certificate_verify => try onCertificateVerify(self, msg, epoch, boundary),
        .finished => try onFinished(self, msg, epoch, boundary),
        // A ClientHello after the handshake asks to renegotiate: refused with a warning, and the
        // connection goes on. One during the handshake is out of order.
        .client_hello => {
            if (!self.established) return error.UnexpectedMessage;
            try self.push(.refuse_renegotiation);
        },
        else => return error.UnexpectedMessage,
    }
}

fn onCertificate(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .c_certificate12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const limits = self.options.limits;
    var probe: [Messages12.max_certificates][]const u8 = undefined;
    const count = try Messages12.certificate(msg, limits.certificates, limits.chain_bytes, &probe);
    if (count == 0) {
        // TLS 1.2 has no certificate_required alert: a missing required certificate is a
        // handshake_failure (RFC 5246 section 7.4.6).
        if (self.options.client_auth == .required) return error.NoClientCertificate;
        try self.state.advance(.empty_certificate, epoch, .parsed, boundary);
        try scratch.transcripts.commit(msg);
        return;
    }
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    // The chain outlives this call: a verification request borrows it until answered.
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = try self.gpa.dupe(u8, msg);
    scratch.chain_len = try Messages12.certificate(self.held, limits.certificates, limits.chain_bytes, &scratch.chain);
    try scratch.transcripts.commit(msg);
    switch (self.options.client_verify) {
        .none => try self.state.advance(.verify_chain, .initial, .chain, true),
        .full => self.need_now = if (self.now == null) .time else .verify,
    }
}

fn onClientKeyExchange(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.client_key_exchange, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    const public = try Messages12.clientKeyExchange(msg, self.group.?);
    try scratch.transcripts.commit(msg);
    const share = &scratch.share12.?;
    var agreed = try share.agree(public);
    defer agreed.deinit();
    share.deinit();
    scratch.share12 = null;
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            // The session hash covers the handshake through ClientKeyExchange (RFC 7627).
            Prf.masterSecret(Hash, self.tls12.?.master.exposeMut(), agreed.bytes(), scratch.transcripts.digestOf(&digest_buf, Hash.digest_length));
            self.tls12.?.deriveKeys(Hash, suite, .server);
        },
    }
    self.keyLog("CLIENT_RANDOM", self.tls12.?.master.expose());
}

fn onCertificateVerify(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .c_verify12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const parsed = try Messages.certificateVerify(msg);
    const scheme = std.enums.fromInt(Hello.SignatureScheme, parsed.scheme) orelse return error.UnofferedScheme;
    if (scheme == .ed25519) {
        // Ed25519 signs the handshake messages, which the transcript kept whole.
        if (scratch.transcripts.keeper == null) return error.UnofferedScheme;
        try Possession.verifyMessage12(parsed.scheme, &Hello.schemes12_verify, scratch.chain[0], scratch.transcripts.keptBytes(), parsed.signature);
    } else {
        const length = Possession.transcriptHash12(scheme) orelse return error.UnofferedScheme;
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        const digest = scratch.transcripts.digestOf(&digest_buf, length);
        try Possession.verifyDigest12(parsed.scheme, &Hello.schemes12_verify, scratch.chain[0], digest, parsed.signature);
    }
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try scratch.transcripts.commit(msg);
    self.peer_certificate = true;
}

/// The client's ChangeCipherSpec: its keys protect what follows.
pub fn onCcs(self: anytype) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.ccs, .initial, .parsed, true);
    try self.tls12.?.release(self, .read);
}

fn onFinished(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .c_finished12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const received = try Messages.finished(msg, Prf.verify_length);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            try Prf.checkFinished(Hash, self.tls12.?.master.expose(), true, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length), received);
            try self.state.advance(.finished, epoch, .finished, boundary);
            try scratch.transcripts.commit(msg);
            if (!self.resumed) {
                // A promised ticket, then ChangeCipherSpec, the server write keys, and its Finished under them.
                if (self.state.ticket12) try sendTicket(self);
                try self.state.advance(.local_ccs, .initial, .parsed, true);
                try self.push(.change_cipher_spec);
                try self.tls12.?.release(self, .write);
                var verify_data: [Prf.verify_length]u8 = undefined;
                Prf.finished(Hash, &verify_data, self.tls12.?.master.expose(), false, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length));
                const message = try Messages.buildFinished(try self.reserve(4 + verify_data.len), &verify_data);
                try self.state.advance(.local_finished, .application, .finished, true);
                try self.queueMessage(.application, message);
            }
        },
    }
    self.established = true;
    self.authenticated = self.authenticated and self.options.client_verify == .full;
    try self.push(.complete);
}
