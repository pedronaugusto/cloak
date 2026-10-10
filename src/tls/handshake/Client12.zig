//! The TLS 1.2 client handshake, continuing a `Client` whose ServerHello chose TLS 1.2. The
//! server's Certificate, ServerKeyExchange, optional CertificateRequest and ServerHelloDone; then
//! the client's ECDHE share, optional certificate and CertificateVerify, ChangeCipherSpec and
//! Finished; then the server's ChangeCipherSpec and Finished. Only ECDHE with AEAD suites and
//! the extended master secret (RFC 7627); no renegotiation and no resumption.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../../certificates.zig");
const suites = @import("../crypto/Suite.zig");
const Prf = @import("../crypto/Prf.zig");
const Exchange = @import("../crypto/Exchange.zig");
const Group = @import("../crypto/Group.zig").Group;
const Client = @import("Client.zig");
const Flight = @import("Flight.zig");
const Hello = @import("Hello.zig");
const Messages = @import("Messages.zig");
const Messages12 = @import("Messages12.zig");
const Possession = @import("Possession.zig");
const Transcripts = @import("Transcripts.zig");

const Error = Client.Error;
const Epoch = Client.Epoch;

/// Bits of `Scratch.cr_types`: the certificate types a CertificateRequest named.
pub const rsa_sign = 1;
pub const ecdsa_sign = 2;

pub fn onServerHello(self: *Client, msg: []const u8, hello: Hello.ServerHello12, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    self.version = .tls12;
    self.state.version = .tls12;
    try self.state.advance(.server_hello, epoch, .parsed, boundary);
    const scratch = self.scratch.?;
    self.suite12 = hello.suite;
    self.tls12 = try Flight.Secrets12.create(self.gpa);
    @memcpy(self.tls12.?.randoms[0..32], &scratch.random);
    @memcpy(self.tls12.?.randoms[32..64], hello.random);
    for (self.options.hello.alpn) |offered| if (std.mem.eql(u8, offered, hello.alpn)) {
        self.alpn = offered;
    };
    // The TLS 1.3 key shares play no part in a TLS 1.2 exchange.
    self.eraseShares();
    try scratch.transcripts.commit(msg);
}

pub fn receive(self: *Client, kind: Messages.Type, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    switch (kind) {
        .certificate => try onCertificate(self, msg, epoch, boundary),
        .server_key_exchange => try onServerKeyExchange(self, msg, epoch, boundary),
        .certificate_request => try onCertificateRequest(self, msg, epoch, boundary),
        .server_hello_done => try onServerHelloDone(self, msg, epoch, boundary),
        .finished => try onFinished(self, msg, epoch, boundary),
        // A server asking to renegotiate: refused, at any time (RFC 5746 is not enough; cloak
        // does not renegotiate at all).
        .hello_request => return error.Renegotiation,
        else => return error.UnexpectedMessage,
    }
}

fn onCertificate(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
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

fn onServerKeyExchange(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .server_key_exchange12) return error.UnexpectedMessage;
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

fn onCertificateRequest(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
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

fn onServerHelloDone(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.server_hello_done, epoch, .parsed, boundary);
    try Messages12.serverHelloDone(msg);
    try self.scratch.?.transcripts.commit(msg);
    // The client's own ECDHE key comes from fresh entropy, after the server named the group.
    self.need_now = .{ .entropy = .{ .len = Exchange.entropyLength(self.group.?) } };
}

/// The entropy for the client's ECDHE share: send the flight.
pub fn onEntropy(self: *Client, entropy: []const u8) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .local_flight12) return error.UnexpectedService;
    const scratch = self.scratch.?;
    scratch.share12 = Exchange.Share.init(self.group.?, entropy) catch return error.InvalidEntropy;
    self.need_now = .none;
    try sendFlight(self);
}

/// The scheme the client certificate signs with, or null to answer with an empty certificate.
fn chooseCredential(self: *const Client) ?Hello.SignatureScheme {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const auth = self.options.auth orelse return null;
    const cert = certificates.certificate.parse(auth.chain()[0], .{}) catch return null;
    const wanted: u8 = switch (cert.public_key) {
        .rsa => rsa_sign,
        .ec => ecdsa_sign,
        .ed25519 => return null,
    };
    if (scratch.cr_types & wanted == 0) return null;
    const request: Messages12.CertificateRequest = .{ .types = "", .schemes = scratch.cr_schemes[0..scratch.cr_len] };
    return Possession.chooseClient12(cert.public_key, request);
}

fn sendFlight(self: *Client) Error!void {
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
pub fn onSignature(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    const digest = scratch.sign_content[0..scratch.sign_content_len];
    Possession.verifyDigest12(@backingInt(self.sign_scheme), &.{self.sign_scheme}, self.options.auth.?.chain()[0], digest, signature) catch return error.BadSignature;
    self.need_now = .none;
    try sendCertificateVerify(self, signature);
}

fn sendCertificateVerify(self: *Client, signature: []const u8) Error!void {
    @setRuntimeSafety(true);
    const message = try Messages.buildCertificateVerify(try self.reserve(8 + signature.len), @backingInt(self.sign_scheme), signature);
    try self.state.advance(.local_certificate_verify, .initial, .possession, true);
    try self.queueMessage(.initial, message);
    try finishFlight(self);
}

/// ChangeCipherSpec, the client write keys, then Finished under them. The server's keys wait
/// for its ChangeCipherSpec.
fn finishFlight(self: *Client) Error!void {
    @setRuntimeSafety(true);
    const scratch = self.scratch.?;
    try self.state.advance(.local_ccs, .initial, .parsed, true);
    try self.push(.change_cipher_spec);
    switch (self.suite12.?) {
        inline else => |suite| {
            const Hash = suites.Hash12(suite);
            var keys = expand(Hash, suite, self.tls12.?.master.expose(), self.tls12.?.clientRandom(), self.tls12.?.serverRandom());
            errdefer keys.client.deinit();
            errdefer keys.server.deinit();
            try self.push(.{ .keys12 = .{ .direction = .write, .keys = keys.client } });
            self.tls12.?.read = keys.server;
            var digest_buf: [Transcripts.max_digest]u8 = undefined;
            var verify_data: [Prf.verify_length]u8 = undefined;
            Prf.finished(Hash, &verify_data, self.tls12.?.master.expose(), true, scratch.transcripts.digestOf(&digest_buf, Hash.digest_length));
            const message = try Messages.buildFinished(try self.reserve(4 + verify_data.len), &verify_data);
            try self.state.advance(.local_finished, .application, .finished, true);
            try self.queueMessage(.application, message);
        },
    }
}

/// The record keys of both directions from the key block (RFC 5246 section 6.3).
pub fn expand(comptime Hash: type, comptime suite: suites.Suite12, master: *const [Prf.master_length]u8, client_random: *const [32]u8, server_random: *const [32]u8) struct { client: Flight.Keys12, server: Flight.Keys12 } {
    @setRuntimeSafety(true);
    const cipher = comptime suite.cipher();
    const key_len = comptime Flight.Keys12.keyLength(cipher);
    const iv_len = comptime cipher.fixedIvLength12();
    var block = aegis.Secret([2 * (key_len + iv_len)]u8).init(undefined);
    defer block.deinit();
    Prf.keyBlock(Hash, block.exposeMut(), master, server_random, client_random);
    const b = block.expose();
    var client: Flight.Keys12 = .{ .cipher = cipher, .key = .init(@splat(0)), .iv = .init(@splat(0)) };
    var server: Flight.Keys12 = .{ .cipher = cipher, .key = .init(@splat(0)), .iv = .init(@splat(0)) };
    @memcpy(client.key.exposeMut()[0..key_len], b[0..key_len]);
    @memcpy(server.key.exposeMut()[0..key_len], b[key_len..][0..key_len]);
    @memcpy(client.iv.exposeMut()[0..iv_len], b[2 * key_len ..][0..iv_len]);
    @memcpy(server.iv.exposeMut()[0..iv_len], b[2 * key_len + iv_len ..][0..iv_len]);
    return .{ .client = client, .server = server };
}

/// The server's ChangeCipherSpec: its keys protect what follows.
pub fn onCcs(self: *Client) Error!void {
    @setRuntimeSafety(true);
    try self.state.advance(.ccs, .initial, .parsed, true);
    const keys = self.tls12.?.read orelse return error.UnexpectedMessage;
    self.tls12.?.read = null;
    try self.push(.{ .keys12 = .{ .direction = .read, .keys = keys } });
}

fn onFinished(self: *Client, msg: []const u8, epoch: Epoch, boundary: bool) Error!void {
    @setRuntimeSafety(true);
    if (self.state.phase != .peer_finished12) return error.UnexpectedMessage;
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
    self.established = true;
    self.authenticated = self.authenticated and self.options.verify == .full;
    try self.push(.complete);
}

/// RFC 5705 keying material over the extended master secret; the context is always included.
pub fn exportKeyingMaterial(self: *const Client, out: []u8, label: []const u8, context: []const u8) Client.ExportError!void {
    @setRuntimeSafety(true);
    switch (self.suite12.?) {
        inline else => |suite| try Prf.exporter(suites.Hash12(suite), out, self.tls12.?.master.expose(), label, self.tls12.?.clientRandom(), self.tls12.?.serverRandom(), context),
    }
}
