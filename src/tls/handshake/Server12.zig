//! The TLS 1.2 server handshake, taken by a `Server` whose client offered no TLS 1.3. One
//! flight of ServerHello, Certificate, a signed ECDHE ServerKeyExchange, an optional
//! CertificateRequest and ServerHelloDone; then the client's certificate, ClientKeyExchange,
//! CertificateVerify, ChangeCipherSpec and Finished; then the server's ChangeCipherSpec and
//! Finished. ECDHE with AEAD suites only, extended master secret and secure renegotiation
//! indication required, no renegotiation, no resumption. The server random carries the TLS 1.3
//! downgrade sentinel, since this server would have spoken TLS 1.3.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const suites = @import("../crypto/Suite.zig");
const Prf = @import("../crypto/Prf.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Client12 = @import("Client12.zig");
const ClientHello = @import("ClientHello.zig");
const Hello = @import("Hello.zig");
const Flight = @import("Flight.zig");
const Messages = @import("Messages.zig");
const Messages12 = @import("Messages12.zig");
const Possession = @import("Possession.zig");
const Transcripts = @import("Transcripts.zig");

const Error = @import("Errors.zig").Error;
const ExportError = @import("Errors.zig").ExportError;
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
    if (!hello.has_schemes or !hello.has_groups) return error.MissingExtension;
    if (self.tls12 == null) self.tls12 = try @import("Flight.zig").Secrets12.create(self.gpa);
    scratch.client_random = hello.random[0..32].*;
    @memcpy(scratch.server_name[0..hello.server_name.len], hello.server_name);
    // safe: parsing bounds a host name at 253 bytes.
    scratch.server_name_len = @intCast(hello.server_name.len);
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
        if (group != .x25519_mlkem768 and hello.offersGroup(group)) break group;
    } else return error.NoSharedGroup;
    self.scheme = Possession.chooseServer12(leaf.public_key, hello) orelse return error.NoSignatureScheme;
    self.alpn = "";
    if (self.options.alpn.len != 0) {
        if (hello.alpn.len == 0) {
            if (self.options.require_alpn) return error.NoApplicationProtocol;
        } else self.alpn = hello.selectAlpn(self.options.alpn) orelse return error.NoApplicationProtocol;
    }
    _ = epoch;
    _ = boundary;
    try scratch.transcripts.commit(msg);
    self.answered = true;
    self.need_now = .{ .entropy = .{ .len = 32 + Exchange.entropyLength(self.group.?) + self.signNoiseLength() } };
}

/// The server random, its ECDHE share and signing noise: send the flight.
pub fn onEntropy(self: anytype, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const group = self.group.?;
    const share_end = 32 + Exchange.entropyLength(group);
    scratch.share12 = Exchange.Share.init(group, entropy[32..share_end]) catch return error.InvalidEntropy;
    self.need_now = .none;
    var random: [32]u8 = entropy[0..32].*;
    // A server that speaks TLS 1.3 marks a TLS 1.2 random (RFC 8446 section 4.1.3).
    if (self.allows13()) random[24..32].* = Hello.downgrade_tls12.*;
    @memcpy(self.tls12.?.randoms[0..32], &scratch.client_random);
    @memcpy(self.tls12.?.randoms[32..64], &random);
    @memcpy(scratch.sign_noise[0 .. entropy.len - share_end], entropy[share_end..]);
    var hello_buffer: [600]u8 = undefined;
    const hello = try Hello.buildServer12(&hello_buffer, &random, self.suite12.?, self.alpn, scratch.server_name_len != 0);
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
        // A second ClientHello on a TLS 1.2 connection is renegotiation: refused.
        .client_hello => return error.Renegotiation,
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
            const keys = Client12.expand(Hash, suite, self.tls12.?.master.expose(), self.tls12.?.clientRandom(), self.tls12.?.serverRandom());
            self.tls12.?.read = keys.client;
            self.tls12.?.write = keys.server;
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
    const length = Possession.transcriptHash12(scheme) orelse return error.UnofferedScheme;
    var digest_buf: [Transcripts.max_digest]u8 = undefined;
    const digest = scratch.transcripts.digestOf(&digest_buf, length);
    try Possession.verifyDigest12(parsed.scheme, &Hello.schemes12_verify, scratch.chain[0], digest, parsed.signature);
    try self.state.advance(.certificate_verify, epoch, .possession, boundary);
    try scratch.transcripts.commit(msg);
    self.peer_certificate = true;
}

/// The client's ChangeCipherSpec: its keys protect what follows.
pub fn onCcs(self: anytype) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.ccs, .initial, .parsed, true);
    const keys = self.tls12.?.read orelse return error.UnexpectedMessage;
    self.tls12.?.read = null;
    try self.push(.{ .keys12 = .{ .direction = .read, .keys = keys } });
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
            // ChangeCipherSpec, the server write keys, then its Finished under them.
            try self.state.advance(.local_ccs, .initial, .parsed, true);
            try self.push(.change_cipher_spec);
            const keys = self.tls12.?.write orelse return error.UnexpectedMessage;
            self.tls12.?.write = null;
            try self.push(.{ .keys12 = .{ .direction = .write, .keys = keys } });
            var verify_data: [Prf.verify_length]u8 = undefined;
            Prf.finished(Hash, &verify_data, self.tls12.?.master.expose(), false, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length));
            const message = try Messages.buildFinished(try self.reserve(4 + verify_data.len), &verify_data);
            try self.state.advance(.local_finished, .application, .finished, true);
            try self.queueMessage(.application, message);
        },
    }
    self.established = true;
    self.authenticated = self.authenticated and self.options.client_verify == .full;
    try self.push(.complete);
}

pub fn exportKeyingMaterial(self: anytype, out: []u8, label: []const u8, context: []const u8) ExportError!void {
    @setRuntimeSafety(true);
    switch (self.suite12.?) {
        inline else => |suite| try Prf.exporter(suites.Hash12(suite), out, self.tls12.?.master.expose(), label, self.tls12.?.clientRandom(), self.tls12.?.serverRandom(), context),
    }
}
