//! The TLS 1.2 server handshake, taken by a `Server` whose client offered no TLS 1.3. One
//! flight of ServerHello, Certificate, a signed ECDHE ServerKeyExchange, an optional
//! CertificateRequest and ServerHelloDone; then the client's certificate, ClientKeyExchange,
//! CertificateVerify, ChangeCipherSpec and Finished; then the server's ChangeCipherSpec and
//! Finished. ECDHE with AEAD suites only, extended master secret required, no renegotiation: the
//! renegotiation indication (RFC 5746) is answered when the client sends it and not required,
//! since the splice it guards needs a server that renegotiates. With TLS 1.2 tickets on, a client's session ticket may
//! resume its session (RFC 5077): the ServerHello echoes its session id, then this server's
//! ChangeCipherSpec and Finished, then the client's; a NewSessionTicket goes before this server's
//! ChangeCipherSpec, in either handshake, to a client that asked. The server random carries the
//! TLS 1.3 downgrade sentinel, since this server would have spoken TLS 1.3. A PSK suite (RFC 4279)
//! takes the provisioned key's path: ServerHello and ServerHelloDone, no hint and no certificate;
//! the client names its key in ClientKeyExchange, and an identity this server does not know is
//! answered as a wrong key would be, at the client's Finished, so a prober learns nothing of
//! which identities exist.
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
const Authorities = @import("Authorities.zig");
const Possession = @import("Possession.zig");
const Transcripts = @import("Transcripts.zig");
const Ticket = @import("../resumption/Ticket.zig");
const Psk = @import("Psk.zig");
const types = certificates.types;

const Error = @import("Errors.zig").Error;
const Epoch = Flight.Epoch;

pub fn onClientHello(self: anytype, msg: []const u8, hello: *const ClientHello, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    self.version = .tls12;
    self.state.version = .tls12;
    const scratch = self.scratch.?;
    if (!hello.extended_master_secret) return error.NoExtendedMasterSecret;
    // RFC 5746 section 4.4: a server that never renegotiates may go on without the indication.
    scratch.renegotiation_info = hello.secureRenegotiation();
    if (!hello.uncompressed_points) return error.IllegalParameter;
    if (self.tls12 == null) self.tls12 = try @import("Flight.zig").Secrets12.create(self.gpa);
    scratch.client_random = hello.random[0..32].*;
    @memcpy(scratch.server_name[0..hello.server_name.len], hello.server_name);
    // safe: parsing bounds a host name at 253 bytes.
    scratch.server_name_len = @intCast(hello.server_name.len);
    self.suite12 = try chooseSuite(self, hello);
    if (self.suite12.?.authentication() == .psk) {
        // Neither side presents a certificate: no types to answer, no curve, no point formats.
        scratch.server_type = null;
        scratch.client_type = null;
        scratch.peer_raw = false;
        scratch.point_formats = false;
    } else {
        scratch.point_formats = hello.point_formats;
        self.negotiateTypes(hello);
        self.group = for (self.options.groups) |group| {
            if (group.classical() and hello.offersGroup(group)) break group;
        } else return error.NoSharedGroup;
    }
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

/// The suite in the server's order the client offers and this server can complete: a PSK suite
/// when it has provisioned keys, a certificate suite of its credential's key. A certificate suite
/// needs the client's schemes and groups (TLS 1.2 has no missing_extension alert: without them no
/// scheme or curve is shared, a handshake_failure); a PSK suite needs neither.
fn chooseSuite(self: anytype, hello: *const ClientHello) Error!suites.Suite12 {
    @setRuntimeSafety(true);
    var refusal: Error = error.NoSharedSuite;
    const wanted = if (self.options.credentials.len == 0) null else if (!hello.has_schemes) blk: {
        refusal = error.NoSignatureScheme;
        break :blk null;
    } else if (!hello.has_groups) blk: {
        refusal = error.NoSharedGroup;
        break :blk null;
    } else credentialKey(self, hello) catch |err| blk: {
        refusal = err;
        break :blk null;
    };
    for (self.options.suites) |suite| {
        const candidate = suite.tls12() orelse continue;
        if (!hello.offersSuite(@backingInt(candidate))) continue;
        const authentication = candidate.authentication();
        if (authentication == .psk) {
            if (self.options.external_psk != null) return candidate;
        } else if (wanted == authentication) return candidate;
    }
    return refusal;
}

/// The credential for the client's name and what it takes (`Server.chooseCredential`), and the
/// kind of suite its key authenticates.
fn credentialKey(self: anytype, hello: *const ClientHello) Error!suites.Suite12.Authentication {
    @setRuntimeSafety(true);
    _ = try self.chooseCredential(hello, fits12);
    // RFC 6962 section 3.3.1: the credential's SCTs, in the ServerHello, for a client that asks.
    self.sends_scts = hello.scts and self.options.credentials[self.credential.?].scts.len != 0;
    // RFC 6066 section 8: the credential's staple, as a CertificateStatus, for a client that asks.
    self.scratch.?.sends_ocsp = hello.ocsp and self.options.credentials[self.credential.?].ocsp.len != 0;
    self.state.flags.ocsp12 = self.scratch.?.sends_ocsp;
    return authenticationOf(self.options.credentials[self.credential.?].identity.publicKey(), hello) catch unreachable; // unreachable: fits12 took it
}

/// The kind of suite a key authenticates for this client.
fn authenticationOf(key: certificates.certificate.Algorithm.PublicKey, hello: *const ClientHello) Error!suites.Suite12.Authentication {
    return switch (key) {
        .rsa => .rsa,
        // An ECDSA certificate's curve must be one the client lists (RFC 8422 section 5.1).
        .ec => |ec| if (hello.offersGroup(switch (ec.curve) {
            .p256 => .p256,
            .p384 => .p384,
            .p521 => .p521,
        })) .ecdsa else error.NoSharedSuite,
        .ed25519 => .ecdsa,
        // ML-DSA authenticates TLS 1.3 only (draft-ietf-tls-mldsa); an agreement key, nothing.
        .mldsa, .x25519 => error.NoSharedSuite,
    };
}

/// TLS 1.2: a certificate suite of the key's kind both offer, and a ServerKeyExchange scheme the
/// client lists.
fn fits12(self: anytype, credential: anytype, hello: *const ClientHello) Error!Possession.Fit {
    @setRuntimeSafety(true);
    // TLS 1.2 has no delegated credentials (RFC 9345 section 4): one that signs only through its
    // own has nothing to sign with here.
    if (credential.delegated_only) return error.NoSignatureScheme;
    const key = credential.identity.publicKey();
    const kind = try authenticationOf(key, hello);
    for (self.options.suites) |suite| {
        const candidate = suite.tls12() orelse continue;
        if (candidate.authentication() == kind and hello.offersSuite(@backingInt(candidate))) break;
    } else return error.NoSharedSuite;
    return .{ .scheme = Possession.chooseServer12(key, credential.schemes, hello) orelse return error.NoSignatureScheme };
}

/// The bytes of the key an unknown identity is answered with: random, so its Finished fails as a
/// wrong key's does.
const decoy_length = 32;

/// TLS 1.2 tickets are on and the client sent the SessionTicket extension.
fn takesTickets(self: anytype, hello: *const ClientHello) bool {
    return self.options.tls12_tickets and self.options.tickets != null and hello.session_ticket != null;
}

/// The ClientHello this server answers: its ticket resumes the session if it may, a ticket is
/// promised if one can be issued, and the entropy is asked for.
pub fn answer(self: anytype, msg: []const u8, hello: *const ClientHello) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    try self.limitRecords(hello);
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
    // A provisioned key's session gets no ticket: the key, not a ticket, is how it starts again.
    const psk = !self.resumed and self.suite12.?.authentication() == .psk;
    if (psk) {
        try self.state.markPsk12();
        self.external = true;
        issue = false;
    }
    self.state.flags.ticket12 = issue;
    // The suite was chosen with a credential's key in view; a ticket or a provisioned key
    // authenticates this handshake instead, and no credential is presented.
    if (self.resumed or psk) self.credential = null;
    // A client may answer the CertificateRequest with Ed25519, which signs the messages themselves.
    if (self.options.client_auth != .none and !self.resumed and !psk) scratch.transcripts.keep(self.gpa);
    // DTLS 1.2 numbers both sides' messages from the client's hello.
    if (self.options.transport == .datagram) scratch.transcripts.startDatagram(self.first_sequence, self.first_sequence, false);
    try scratch.transcripts.commit(msg);
    self.answered = true;
    const exchange = if (self.resumed) 0 else if (psk) decoy_length else Exchange.entropyLength(self.group.?) + self.signNoiseLength();
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
    // A client that does not take the session's type takes no answer a resumption could give.
    if (!hello.takesServerForm(state.server_raw)) return;
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
    self.pin = state.client_pin;
    scratch.client_auth_expires = if (state.client_authenticated) state.auth_expires else std.math.maxInt(i64);
    self.resumeTypes(hello, state.server_raw);
}

/// The server random, its ECDHE share and signing noise (and a ticket's salt): send the flight.
pub fn onEntropy(self: anytype, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var random: [32]u8 = entropy[0..32].*;
    // A server that speaks TLS 1.3 marks a TLS 1.2 random (RFC 8446 section 4.1.3).
    if (self.allows13()) random[24..32].* = Hello.downgrade_tls12.*;
    const salt_at = entropy.len - @as(usize, if (self.state.flags.ticket12) Ticket.salt_length else 0);
    @memcpy(scratch.ticket_entropy[0 .. entropy.len - salt_at], entropy[salt_at..]);
    if (self.resumed) {
        self.need_now = .none;
        @memcpy(self.tls12.?.randoms[0..32], &scratch.client_random);
        @memcpy(self.tls12.?.randoms[32..64], &random);
        return sendResumed(self, &random);
    }
    if (self.external) {
        self.need_now = .none;
        @memcpy(self.tls12.?.randoms[0..32], &scratch.client_random);
        @memcpy(self.tls12.?.randoms[32..64], &random);
        @memcpy(scratch.psk.exposeMut()[0..decoy_length], entropy[32..][0..decoy_length]);
        return sendPskFlight(self, &random);
    }
    const group = self.group.?;
    const share_end = 32 + Exchange.entropyLength(group);
    scratch.share12 = Exchange.Share.init(group, entropy[32..share_end]) catch return error.InvalidEntropy;
    self.need_now = .none;
    @memcpy(self.tls12.?.randoms[0..32], &scratch.client_random);
    @memcpy(self.tls12.?.randoms[32..64], &random);
    @memcpy(scratch.sign_noise[0 .. salt_at - share_end], entropy[share_end..salt_at]);
    var hello_buffer: [1024 + Hello.max_scts]u8 = undefined;
    const scts: ?[]const u8 = if (self.sends_scts) self.options.credentials[self.credential.?].scts else null;
    const hello = try Hello.buildServer12(&hello_buffer, self.options.transport, &random, "", self.suite12.?, self.alpn, .{ .server_name = scratch.server_name_len != 0, .renegotiation_info = scratch.renegotiation_info, .record_size_limit = scratch.record_size_answer, .point_formats = scratch.point_formats, .ticket = self.state.flags.ticket12, .connection_id = self.ownConnectionId(), .srtp = self.srtp, .server_certificate_type = scratch.server_type, .client_certificate_type = scratch.client_type, .scts = scts, .ocsp = scratch.sends_ocsp });
    try self.state.advance(.server_hello, .initial, .parsed, true);
    try queue(self, hello);
    const identity = self.options.credentials[self.credential.?].identity;
    const certificate = if (identity.rawKey()) |spki|
        try Messages12.buildRawKey(try self.reserve(8 + spki.len), spki)
    else chain: {
        var total: usize = 16;
        for (identity.chain()) |der| total += der.len + 3;
        break :chain try Messages12.buildCertificate(try self.reserve(total), identity.chain());
    };
    try self.state.advance(.certificate, .initial, .parsed, true);
    try self.queueMessage(.initial, certificate);
    if (scratch.sends_ocsp) {
        const staple = self.options.credentials[self.credential.?].ocsp;
        const status = try Messages.buildCertificateStatus(try self.reserve(8 + staple.len), staple);
        try self.state.advance(.certificate_status, .initial, .parsed, true);
        try self.queueMessage(.initial, status);
    }
    const share = &scratch.share12.?;
    var params_buffer: [4 + Messages12.max_public]u8 = undefined;
    const params = try Messages12.buildParams(&params_buffer, group, share.wire());
    const content = Messages12.signedParams(&scratch.params12, &scratch.client_random, &random, params);
    // safe: the signed content is at most `Messages12.max_signed`, 201 bytes.
    scratch.params12_len = @intCast(content.len);
    // Cloak signs for a key it holds; a key held elsewhere is the caller's to sign with.
    if (identity.noiseLength()) |noise_length| {
        var out: [certificates.PrivateKey.max_signature]u8 = undefined;
        const signature = Possession.sign12(identity, self.scheme, content, scratch.sign_noise[0..noise_length], &out) catch return error.SigningFailed;
        return sendKeyExchange(self, signature);
    }
    self.need_now = .sign;
}

/// The provisioned key's flight: ServerHello and ServerHelloDone. No identity hint: keys are
/// named by the client alone.
fn sendPskFlight(self: anytype, random: *const [32]u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var hello_buffer: [1024]u8 = undefined;
    const hello = try Hello.buildServer12(&hello_buffer, self.options.transport, random, "", self.suite12.?, self.alpn, .{ .server_name = scratch.server_name_len != 0, .renegotiation_info = scratch.renegotiation_info, .record_size_limit = scratch.record_size_answer, .point_formats = false, .connection_id = self.ownConnectionId(), .srtp = self.srtp });
    try self.state.advance(.server_hello, .initial, .parsed, true);
    try queue(self, hello);
    const done = try Messages12.buildServerHelloDone(try self.reserve(4));
    try self.state.advance(.server_hello_done, .initial, .parsed, true);
    try self.queueMessage(.initial, done);
}

/// The abbreviated handshake's flight: the ServerHello echoing the client's session id (and no
/// server_name, RFC 6066 section 3), a new ticket if promised, then this server's ChangeCipherSpec and Finished from the session's master
/// secret and the new randoms.
fn sendResumed(self: anytype, random: *const [32]u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    var hello_buffer: [1024]u8 = undefined;
    const hello = try Hello.buildServer12(&hello_buffer, self.options.transport, random, scratch.session[0..scratch.session_len], self.suite12.?, self.alpn, .{ .server_name = false, .renegotiation_info = scratch.renegotiation_info, .record_size_limit = scratch.record_size_answer, .point_formats = scratch.point_formats, .ticket = self.state.flags.ticket12, .connection_id = self.ownConnectionId(), .srtp = self.srtp, .server_certificate_type = scratch.server_type });
    try self.state.advance(.server_hello, .initial, .parsed, true);
    try queue(self, hello);
    if (self.state.flags.ticket12) try sendTicket(self);
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
                .client_pin = self.pin,
                .auth_expires = if (self.authenticated) scratch.client_auth_expires else 0,
                .server_raw = self.session_raw,
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
    const own = self.options.credentials[self.credential.?].identity.publicKey();
    Possession.verifyMessage12(@backingInt(self.scheme), &.{self.scheme}, own, scratch.params12[0..scratch.params12_len], signature) catch return error.BadSignature;
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
        var taken: [Hello.max_peer_schemes]Hello.SignatureScheme = undefined;
        const allowed = Hello.peerSchemes(self.options.peer_schemes, &Hello.schemes12_verify, &taken);
        if (allowed.len == 0) return error.NoSignatureScheme;
        var schemes: [Hello.max_peer_schemes]u16 = undefined;
        for (allowed, schemes[0..allowed.len]) |scheme, *slot| slot.* = @backingInt(scheme);
        const authorities = self.options.certificate_authorities;
        const request = try Messages12.buildCertificateRequest(try self.reserve(64 + Authorities.wireLength(authorities)), schemes[0..allowed.len], authorities);
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
    if (self.state.phase() != .c_certificate12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    if (scratch.peer_raw) return onRawKey(self, msg, epoch, boundary);
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
        .leaf_key => |leaf| {
            // The leaf's key is the trust: its pin, and nothing else of the chain.
            self.pin = try Possession.pinnedLeaf(scratch.chain[0], leaf.pins);
            try self.state.advance(.verify_chain, .initial, .chain, true);
            self.authenticated = true;
        },
        // A chain where a key is pinned: the client did not list the raw key type.
        .raw_key => return error.UnsupportedCertificate,
    }
}

/// The client's Certificate of the raw key type this server selected (RFC 7250 section 3): one
/// SubjectPublicKeyInfo a pin names, or none.
fn onRawKey(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const spki = try Messages12.rawKey(msg);
    if (spki.len == 0) {
        if (self.options.client_auth == .required) return error.NoClientCertificate;
        try self.state.advance(.empty_certificate, epoch, .parsed, boundary);
        try scratch.transcripts.commit(msg);
        return;
    }
    try self.state.advance(.certificate, epoch, .parsed, boundary);
    if (self.held.len != 0) self.gpa.free(self.held);
    self.held = &.{};
    self.held = try self.gpa.dupe(u8, spki);
    scratch.chain[0] = self.held;
    scratch.chain_len = 1;
    self.pin = try Possession.pinnedKey(scratch.chain[0..1], self.options.client_verify.raw_key.pins);
    try scratch.transcripts.commit(msg);
    try self.state.advance(.verify_chain, .initial, .chain, true);
    self.authenticated = true;
}

fn onClientKeyExchange(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.external) return onPskKeyExchange(self, msg, epoch, boundary);
    try self.state.advance(.client_key_exchange, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    const public = try Messages12.clientKeyExchange(msg, self.group.?);
    try scratch.transcripts.commit(msg);
    const share = &scratch.share12.?;
    var agreed = try share.agree(public);
    defer agreed.deinit();
    share.deinit();
    scratch.share12 = null;
    deriveMaster(self, agreed.bytes());
}

/// The client's identity: its key, from the caller's lookup, makes the premaster (RFC 4279
/// section 2). An identity with no key here (unknown, of the other version, malformed) gets the
/// decoy instead: the handshake goes on and fails at the client's Finished, as a wrong key's does.
fn onPskKeyExchange(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.client_key_exchange, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    const identity = try Messages12.pskClientKeyExchange(msg);
    try scratch.transcripts.commit(msg);
    const known = knownKey(self, identity);
    self.authenticated = known != null;
    var premaster: [Messages12.max_premaster]u8 = undefined;
    defer std.crypto.secureZero(u8, &premaster);
    deriveMaster(self, Messages12.pskPremaster(&premaster, known orelse scratch.psk.expose()[0..decoy_length]));
}

/// The key the caller's lookup holds for a TLS 1.2 identity, exactly as named; null for none.
fn knownKey(self: anytype, identity: []const u8) ?[]const u8 {
    @setRuntimeSafety(true);
    if (identity.len == 0 or identity.len > Psk.max_identity) return null;
    const scratch = self.scratch.?;
    const lookup = self.options.external_psk.?;
    const query: Psk.Query = .{ .identity = identity, .server_name = scratch.server_name[0..scratch.server_name_len], .alpn = self.alpn, .transport = self.options.transport, .version = .tls12 };
    const found = lookup.find(lookup.context, query) orelse return null;
    if (!query.takes(found)) return null;
    self.psk_identity = self.gpa.dupe(u8, identity) catch return null;
    return found.secret;
}

/// The extended master secret (RFC 7627: the session hash covers the handshake through
/// ClientKeyExchange) and both directions' keys.
fn deriveMaster(self: anytype, premaster: []const u8) void {
    @setRuntimeSafety(true);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            Prf.masterSecret(Hash, self.tls12.?.master.exposeMut(), premaster, self.scratch.?.transcripts.digestOf(&digest_buf, Hash.digest_length));
            self.tls12.?.deriveKeys(Hash, suite, .server);
        },
    }
    self.keyLog("CLIENT_RANDOM", self.tls12.?.master.expose());
}

fn onCertificateVerify(self: anytype, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase() != .c_verify12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const parsed = try Messages.certificateVerify(msg);
    const scheme: Hello.SignatureScheme = @fromBackingInt(parsed.scheme);
    if (!scheme.supported()) return error.UnofferedScheme;
    const key = try Possession.peerKey(scratch.chain[0], scratch.peer_raw);
    var taken: [Hello.max_peer_schemes]Hello.SignatureScheme = undefined;
    if (scheme == .ed25519) {
        // Ed25519 signs the handshake messages, which the transcript kept whole.
        if (scratch.transcripts.keeper == null) return error.UnofferedScheme;
        try Possession.verifyMessage12(parsed.scheme, Hello.peerSchemes(self.options.peer_schemes, &Hello.schemes12_verify, &taken), key, scratch.transcripts.keptBytes(), parsed.signature);
    } else {
        const length = Possession.transcriptHash12(scheme) orelse return error.UnofferedScheme;
        var digest_buf: [Transcripts.max_digest]u8 = undefined;
        const digest = scratch.transcripts.digestOf(&digest_buf, length);
        try Possession.verifyDigest12(parsed.scheme, Hello.peerSchemes(self.options.peer_schemes, &Hello.schemes12_verify, &taken), key, digest, parsed.signature);
    }
    self.peer_scheme = scheme;
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try scratch.transcripts.commit(msg);
    if (self.options.keep_peer_leaf) try Possession.keepLeaf(self.gpa, &self.peer_leaf, scratch.chain[0], scratch.peer_raw);
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
    if (self.state.phase() != .c_finished12) return error.UnexpectedMessage;
    const scratch = self.scratch.?;
    const received = try Messages.finished(msg, Prf.verify_length);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            try Prf.checkFinished(Hash, self.tls12.?.master.expose(), true, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length), received);
            // The decoy's Finished cannot check but by a guess of 32 random bytes; refused all the same.
            if (self.external and !self.authenticated) return error.BadFinished;
            try self.state.advance(.finished, epoch, .finished, boundary);
            try scratch.transcripts.commit(msg);
            if (!self.resumed) {
                // A promised ticket, then ChangeCipherSpec, the server write keys, and its Finished under them.
                if (self.state.flags.ticket12) try sendTicket(self);
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
    // A provisioned key authenticated the client whatever the certificate policy.
    self.authenticated = self.authenticated and (self.external or self.options.client_verify != .none);
    try self.push(.complete);
}
