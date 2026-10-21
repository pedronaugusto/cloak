//! A cloak client against a cloak server in memory, each answering its own requests the way a
//! driver would: deterministic entropy, a fixed clock and the portable verifier over the test
//! root. For version and suite coverage the scripted peers do not reach (TLS 1.2); external
//! peers in the trials campaign check what two cloak ends cannot.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Connection = @import("../tls/Connection.zig");
const Server = @import("../tls/handshake/Server.zig");
const Suite = @import("../tls/crypto/Suite.zig").Suite;
const Version = @import("../tls/crypto/Suite.zig").Version;
const Group = @import("../tls/crypto/Group.zig").Group;
const SessionCache = @import("../tls/resumption/SessionCache.zig");
const TicketKeys = @import("../tls/resumption/TicketKeys.zig");
const Ech = @import("../tls/handshake/Ech.zig");
const Compression = @import("../tls/handshake/Compression.zig");
const Psk = @import("../tls/handshake/Psk.zig");
const Delegation = @import("../tls/handshake/Delegation.zig");
const Client = @import("../tls/handshake/Client.zig");
const Hello = @import("../tls/handshake/Hello.zig");
pub const pki = @import("Peer.zig").pki;

pub const Cert = enum { p256, p384, ed25519, rsa, mldsa44, mldsa65, mldsa87, mldsa44_classical, p256_pqca, dc_p256, dc_no_signature, ct_leaf, ct_plain };

pub const Options = struct {
    seed: u64 = 1,
    cert: Cert = .p256,
    /// Further server credentials after `cert`'s, each answering any name: at most two.
    server_also: []const Cert = &.{},
    client_suites: []const Suite = Suite.default,
    server_suites: []const Suite = Suite.default,
    client_min: Version = .tls12,
    client_max: Version = .tls13,
    server_max: Version = .tls13,
    server_min: Version = .tls12,
    client_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    server_groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    client_require_hybrid: bool = false,
    server_require_hybrid: bool = false,
    client_alpn: []const []const u8 = &.{},
    server_alpn: []const []const u8 = &.{},
    client_auth: Server.Auth = .none,
    /// The client offers its certificate when asked.
    client_cert: bool = false,
    /// That certificate's key is Ed25519 (P-256 otherwise).
    client_ed25519: bool = false,
    /// That certificate is ML-DSA-65 under the ML-DSA root.
    client_mldsa: bool = false,
    /// That certificate is the server's P-256 one: a server-only extended key usage.
    client_server_eku: bool = false,
    /// That certificate is `dc_no_signature` (keyAgreement alone) on the P-256 key: its key may not
    /// sign the handshake.
    client_no_signature: bool = false,
    /// Both ends' verifier takes every chain, checking nothing: a caller's verifier that does not
    /// look at key usage.
    accept_any: bool = false,
    /// Post-quantum authentication required of the server (client) and of the client (server).
    client_require_pq_auth: bool = false,
    server_require_pq_auth: bool = false,
    /// The client's key is held elsewhere: the harness signs (Ed25519 only).
    client_external: bool = false,
    /// The client puts GREASE values (RFC 8701) in its hello.
    client_grease: bool = false,
    /// Bytes moved per receive call, to cut records and messages at every boundary.
    chunk: usize = 1 << 20,
    /// Resumption: the client's ticket cache and the server's ticket keys.
    cache: ?*SessionCache = null,
    namespace: []const u8 = "",
    max_age: std.Io.Duration = .fromSeconds(7 * 24 * 60 * 60),
    tickets: ?*TicketKeys = null,
    /// TLS 1.2 tickets at the client and at the server.
    client_tls12_tickets: bool = false,
    server_tls12_tickets: bool = false,
    /// The calendar time both ends are told, in seconds.
    time: i64 = pki.time,
    /// The verification policy generations of the client and of the server's client checks.
    client_policy_generation: u64 = 1,
    server_policy_generation: u64 = 1,
    pins: []const [32]u8 = &.{},
    identity: []const u8 = "example.com",
    /// Overrides when the server's verdict on the client's certificate expires, in seconds.
    receipt_expires: ?i64 = null,
    /// Overrides when the client's verdict on the server's certificate expires, in seconds.
    server_receipt_expires: ?i64 = null,
    /// Encrypted Client Hello at the client and the server.
    client_ech: Ech.Mode = .off,
    server_ech: []const Ech.Key = &.{},
    /// Verify nothing at the client.
    client_verify_none: bool = false,
    /// Certificate codecs: the client's decoders and the server's encoders.
    client_codecs: []const Compression.Codec = &.{},
    server_codecs: []const Compression.Codec = &.{},
    /// Provisioned keys: the client's and the server's lookup.
    client_psks: []const Psk.External = &.{},
    server_psk: ?Psk.Lookup = null,
    /// The server holds no credential: provisioned keys are its only authentication.
    server_psk_only: bool = false,
    /// What the client connection allocates from, to measure it; the harness's own otherwise.
    client_gpa: ?std.mem.Allocator = null,
    /// Raw public keys (RFC 7250): the server's credentials (its certificate's, or the raw key of
    /// the same key alone, or the raw key first and the certificate after), the pins the client
    /// trusts the server's key by, the client's credential as a raw key, and the pins the server
    /// trusts the client's key by.
    server_raw: enum { none, only, both } = .none,
    client_raw_pins: ?[]const [32]u8 = null,
    client_raw: bool = false,
    server_raw_pins: ?[]const [32]u8 = null,
    /// Leaf keys trusted by their pins alone (`Verify.leaf_key`): the client's of the server's
    /// certificate, the server's of the client's.
    client_leaf_pins: ?[]const [32]u8 = null,
    server_leaf_pins: ?[]const [32]u8 = null,
    /// Delegated credentials (RFC 9345): the server's credential carries one (the certificate is
    /// `dc_p256` unless another is named), the client's certificate is `dc_client` with one, each
    /// with a P-384 key expiring `delegated_lifetime` seconds after `delegated_issued`; and
    /// whether each end takes the peer's.
    server_delegated: bool = false,
    client_delegated: bool = false,
    client_accept_delegated: bool = false,
    server_accept_delegated: bool = false,
    delegated_issued: i64 = pki.time,
    delegated_lifetime: i64 = 3 * 24 * 60 * 60,
    /// Certificate Transparency: the client's policy, and the SCT list the server's credential
    /// sends to a client that asks.
    client_transparency: ?*const certificates.types.TransparencyPolicy = null,
    server_scts: []const u8 = "",
    /// OCSP stapling: the staple the server's credential sends to a client that asks, and a
    /// client that checks no revocation (so asks for none).
    server_ocsp: []const u8 = "",
    client_revocation_off: bool = false,
    /// The signature schemes the server's first credential and the client's first sign under.
    server_schemes: []const Hello.SignatureScheme = &.{},
    client_schemes: []const Hello.SignatureScheme = &.{},
    /// Post-handshake authentication: the client offers it, the server asks with it, checking
    /// the client's chain by the test root even when the handshake asks for no certificate.
    client_post_auth: bool = false,
    server_post_auth: bool = false,
    /// record_size_limit (RFC 8449) each end names; null names the version's maximum.
    client_record_size_limit: ?u16 = null,
    server_record_size_limit: ?u16 = null,
    /// Each end's key log (NSS key log lines), to read its records or know its secrets in a test.
    client_key_log: ?Connection.KeyLog = null,
    server_key_log: ?Connection.KeyLog = null,
    /// A second client credential after the first: `dc_client` under the delegation root, with
    /// the client's key (a chain of another issuer), or with `client_second_raw` the client's key
    /// as a raw public key (RFC 7250).
    client_second: bool = false,
    client_second_raw: bool = false,
    /// certificate_authorities (RFC 8446 section 4.2.4): the names each end sends.
    client_authorities: []const []const u8 = &.{},
    server_authorities: []const []const u8 = &.{},
    /// The entropy request (counted from 0 at that end) the harness answers with a failure.
    entropy_fails: ?struct { end: enum { client, server }, at: usize } = null,
};

/// The SHA-256 of a certificate's SubjectPublicKeyInfo: the pin of its key as a raw public key.
pub fn pinOf(der: []const u8) [32]u8 {
    const cert = certificates.certificate.parse(der, .{}) catch unreachable; // unreachable: test PKI
    var pin: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(cert.spki, &pin, .{});
    return pin;
}

const Duo = @This();

gpa: std.mem.Allocator,
client: Connection,
server: Connection,
trust: certificates.Trust,
snapshot: certificates.Trust.Snapshot,
identity: certificates.Identity,
raw_identity: ?certificates.Identity = null,
/// The server's further credentials (`server_also`), and the list it is given.
also: [2]certificates.Identity = undefined,
also_count: usize = 0,
credential_list: [3]Server.Credential = undefined,
auth: ?certificates.ClientAuth = null,
second: ?certificates.ClientAuth = null,
client_credentials: [2]Client.Credential = undefined,
/// The SHA-256 of the leaf each end was asked to verify, client first; zero before.
peer_leaf: [2][32]u8 = @splat(@splat(0)),
/// The SHA-256 of the stapled OCSP response each end's verification request carried (the last of
/// its responses), client first; null when it carried none.
peer_ocsp: [2]?[32]u8 = .{ null, null },
server_dc: ?Delegation.Credential = null,
client_dc: ?Delegation.Credential = null,
rng: std.Random.DefaultPrng,
options: Options,
/// Entropy requests answered so far, client and server.
entropy_drawn: [2]usize = .{ 0, 0 },
/// The longest protected record body (content type 23) each end has sent, client first: what
/// the peer's record_size_limit bounds (RFC 8449).
longest_protected: [2]usize = .{ 0, 0 },
/// The longest record of any type each end has sent.
longest_record: [2]usize = .{ 0, 0 },

pub fn init(gpa: std.mem.Allocator, options: Options) !*Duo {
    const self = try gpa.create(Duo);
    errdefer gpa.destroy(self);
    self.* = undefined;
    self.gpa = gpa;
    self.options = options;
    self.rng = .init(options.seed);
    self.entropy_drawn = .{ 0, 0 };
    self.longest_protected = .{ 0, 0 };
    self.longest_record = .{ 0, 0 };
    self.trust = certificates.Trust.init(gpa);
    errdefer self.trust.deinit();
    try self.trust.addDer(pki.ca, .{});
    try self.trust.addDer(pki.mldsa_ca, .{});
    try self.trust.addDer(pki.mixed_ca, .{});
    try self.trust.addDer(pki.dc_ca, .{});
    try self.trust.addDer(pki.ct_ca, .{});
    self.snapshot = try self.trust.freeze();
    errdefer self.snapshot.deinit();
    const cert: Cert = if (options.server_delegated and options.cert == .p256) .dc_p256 else options.cert;
    const key = try keyOf(gpa, cert);
    defer key.deinit();
    const leaf = leafOf(cert);
    self.identity = try certificates.Identity.init(gpa, &.{ leaf, rootOf(cert) }, key, .{});
    errdefer self.identity.deinit();
    self.also_count = 0;
    errdefer for (self.also[0..self.also_count]) |identity| identity.deinit();
    for (options.server_also) |also| {
        const also_key = try keyOf(gpa, also);
        defer also_key.deinit();
        self.also[self.also_count] = try certificates.Identity.init(gpa, &.{ leafOf(also), rootOf(also) }, also_key, .{});
        self.also_count += 1;
    }
    self.raw_identity = if (options.server_raw != .none) try certificates.Identity.initRawKey(gpa, (try certificates.certificate.parse(leaf, .{})).spki, key, .{}) else null;
    errdefer if (self.raw_identity) |raw| raw.deinit();
    self.auth = null;
    if (options.client_cert) {
        const client_key = try certificates.PrivateKey.parse(gpa, if (options.client_server_eku or options.client_no_signature) pki.p256_pem else if (options.client_mldsa) pki.client_mldsa65_pem else if (options.client_ed25519) pki.client_ed25519_pem else pki.client_pem, .{});
        defer client_key.deinit();
        const chain: []const []const u8 = if (options.client_server_eku) &.{ pki.p256, pki.ca } else if (options.client_no_signature) &.{ pki.dc_no_signature, pki.dc_ca } else if (options.client_mldsa) &.{ pki.client_mldsa65, pki.mldsa_ca } else if (options.client_delegated) &.{ pki.dc_client, pki.dc_ca } else &.{ if (options.client_ed25519) pki.client_ed25519 else pki.client, pki.ca };
        self.auth = if (options.client_raw)
            try certificates.ClientAuth.initRawKey(gpa, (try certificates.certificate.parse(chain[0], .{})).spki, client_key, .{})
        else if (options.client_external)
            try certificates.ClientAuth.initExternal(gpa, chain, .{})
        else
            try certificates.ClientAuth.init(gpa, chain, client_key, .{});
    }
    errdefer if (self.auth) |auth| auth.deinit();
    self.second = null;
    if (options.client_second) {
        const client_key = try certificates.PrivateKey.parse(gpa, pki.client_pem, .{});
        defer client_key.deinit();
        self.second = if (options.client_second_raw)
            try certificates.ClientAuth.initRawKey(gpa, (try certificates.certificate.parse(pki.client, .{})).spki, client_key, .{})
        else
            try certificates.ClientAuth.init(gpa, &.{ pki.dc_client, pki.dc_ca }, client_key, .{});
    }
    errdefer if (self.second) |second| second.deinit();
    self.peer_leaf = @splat(@splat(0));
    self.server_dc = if (options.server_delegated) try self.delegate(self.identity, .server) else null;
    errdefer if (self.server_dc) |dc| dc.deinit();
    self.client_dc = if (options.client_delegated) try self.delegate(self.auth.?.identity, .client) else null;
    errdefer if (self.client_dc) |dc| dc.deinit();
    self.client = try Connection.client(options.client_gpa orelse gpa, .{
        .identity = .{ .dns = options.identity },
        .verify = if (options.client_raw_pins) |pins| .{ .raw_key = .{ .pins = pins } } else if (options.client_leaf_pins) |pins| .{ .leaf_key = .{ .pins = pins } } else if (options.client_verify_none) .none else .{ .full = .{ .trust_generation = self.snapshot.generation(), .policy_generation = .fromRaw(options.client_policy_generation), .policy = .{ .transparency = options.client_transparency, .revocation = .{ .mode = if (options.client_revocation_off) .off else .if_present } }, .pins = options.pins } },
        .ech = options.client_ech,
        .certificate_compression = options.client_codecs,
        .grease = options.client_grease,
        .external_psks = options.client_psks,
        .record_size_limit = options.client_record_size_limit,
        .resumption = if (options.cache) |cache| .{ .cache = cache, .namespace = options.namespace, .max_age = options.max_age, .tls12 = options.client_tls12_tickets } else null,
        .suites = options.client_suites,
        .min_version = options.client_min,
        .max_version = options.client_max,
        .groups = options.client_groups,
        .require_hybrid = options.client_require_hybrid,
        .require_pq_auth = options.client_require_pq_auth,
        .alpn = options.client_alpn,
        .credentials = self.clientCredentials(),
        .certificate_authorities = options.client_authorities,
        .accept_delegated = options.client_accept_delegated,
        .post_handshake_auth = options.client_post_auth,
        .key_log = options.client_key_log,
    });
    errdefer self.client.deinit();
    self.server = try Connection.server(gpa, .{
        .credentials = if (options.server_psk_only) &.{} else switch (options.server_raw) {
            .none => self.credentials(),
            .only => &.{.{ .identity = self.raw_identity.?, .scts = options.server_scts }},
            .both => &.{ .{ .identity = self.raw_identity.? }, .{ .identity = self.identity } },
        },
        .suites = options.server_suites,
        .min_version = options.server_min,
        .max_version = options.server_max,
        .groups = options.server_groups,
        .require_hybrid = options.server_require_hybrid,
        .require_pq_auth = options.server_require_pq_auth,
        .alpn = options.server_alpn,
        .client_auth = options.client_auth,
        .certificate_authorities = options.server_authorities,
        .client_verify = if (options.server_raw_pins) |pins| .{ .raw_key = .{ .pins = pins } } else if (options.server_leaf_pins) |pins| .{ .leaf_key = .{ .pins = pins } } else if (options.client_auth != .none or options.server_post_auth) .{ .full = .{ .trust_generation = self.snapshot.generation(), .policy_generation = .fromRaw(options.server_policy_generation) } } else .none,
        .tickets = options.tickets,
        .tls12_tickets = options.server_tls12_tickets,
        .ech_keys = options.server_ech,
        .certificate_compression = options.server_codecs,
        .external_psk = options.server_psk,
        .record_size_limit = options.server_record_size_limit,
        .accept_delegated = options.server_accept_delegated,
        .post_handshake_auth = options.server_post_auth,
        .key_log = options.server_key_log,
    });
    return self;
}

pub fn deinit(self: *Duo) void {
    const gpa = self.gpa;
    self.client.deinit();
    self.server.deinit();
    if (self.auth) |auth| auth.deinit();
    if (self.second) |second| second.deinit();
    if (self.server_dc) |dc| dc.deinit();
    if (self.client_dc) |dc| dc.deinit();
    if (self.raw_identity) |raw| raw.deinit();
    for (self.also[0..self.also_count]) |identity| identity.deinit();
    self.identity.deinit();
    self.snapshot.deinit();
    self.trust.deinit();
    gpa.destroy(self);
}

/// The client's credentials: its certificate (with its delegation), then the second.
fn clientCredentials(self: *Duo) []const Client.Credential {
    var n: usize = 0;
    if (self.auth) |auth| {
        self.client_credentials[n] = .{ .auth = auth, .delegated = self.client_dc, .schemes = self.options.client_schemes };
        n += 1;
    }
    if (self.second) |second| {
        self.client_credentials[n] = .{ .auth = second };
        n += 1;
    }
    return self.client_credentials[0..n];
}

/// The server's credentials: its identity (with its delegation and SCTs), then `server_also`'s.
fn credentials(self: *Duo) []const Server.Credential {
    self.credential_list[0] = .{ .identity = self.identity, .delegated = self.server_dc, .scts = self.options.server_scts, .ocsp = self.options.server_ocsp, .schemes = self.options.server_schemes };
    for (self.also[0..self.also_count], 1..) |identity, i| self.credential_list[i] = .{ .identity = identity };
    return self.credential_list[0 .. 1 + self.also_count];
}

fn keyOf(gpa: std.mem.Allocator, cert: Cert) !certificates.PrivateKey {
    return certificates.PrivateKey.parse(gpa, switch (cert) {
        .p256, .dc_p256, .dc_no_signature, .ct_leaf, .ct_plain => pki.p256_pem,
        .p384 => pki.p384_pem,
        .ed25519 => pki.ed25519_pem,
        .rsa => pki.rsa_pem,
        .mldsa44 => pki.mldsa44_pem,
        .mldsa65 => pki.mldsa65_pem,
        .mldsa87 => pki.mldsa87_pem,
        .mldsa44_classical => pki.mldsa44_classical_pem,
        .p256_pqca => pki.p256_pqca_pem,
    }, .{});
}

fn leafOf(cert: Cert) []const u8 {
    return switch (cert) {
        .dc_p256 => pki.dc_p256,
        .dc_no_signature => pki.dc_no_signature,
        .ct_leaf => pki.ct_leaf,
        .ct_plain => pki.ct_plain,
        .p256 => pki.p256,
        .p384 => pki.p384,
        .ed25519 => pki.ed25519,
        .rsa => pki.rsa,
        .mldsa44 => pki.mldsa44,
        .mldsa65 => pki.mldsa65,
        .mldsa87 => pki.mldsa87,
        .mldsa44_classical => pki.mldsa44_classical,
        .p256_pqca => pki.p256_pqca,
    };
}

fn rootOf(cert: Cert) []const u8 {
    return switch (cert) {
        .dc_p256, .dc_no_signature => pki.dc_ca,
        .ct_leaf, .ct_plain => pki.ct_ca,
        .mldsa44, .mldsa65, .mldsa87, .p256_pqca => pki.mldsa_ca,
        .mldsa44_classical => pki.mixed_ca,
        else => pki.ca,
    };
}

/// A delegated credential of `identity`'s certificate with the P-384 key, as `options` say.
fn delegate(self: *Duo, identity: certificates.Identity, role: Delegation.Role) !Delegation.Credential {
    const dc_key = try certificates.PrivateKey.parse(self.gpa, pki.p384_pem, .{});
    defer dc_key.deinit();
    var noise: [certificates.PrivateKey.max_noise]u8 = undefined;
    self.rng.random().bytes(&noise);
    const bytes = try Delegation.issue(self.gpa, identity, .{
        .role = role,
        .spki = (try certificates.certificate.parse(pki.p384, .{})).spki,
        .scheme = .ecdsa_p384_sha384,
        .algorithm = .ecdsa_p256_sha256,
        .expires = certificates.types.instant(self.options.delegated_issued + self.options.delegated_lifetime),
    }, noise[0..identity.noiseLength().?]);
    defer self.gpa.free(bytes);
    return Delegation.Credential.init(self.gpa, identity, bytes, dc_key, role);
}

fn serve(self: *Duo, conn: *Connection) !void {
    while (conn.request()) |request| switch (request.service) {
        .entropy => |len| {
            const end: usize = @intFromBool(conn == &self.server);
            defer self.entropy_drawn[end] += 1;
            if (self.options.entropy_fails) |fails| if (@backingInt(fails.end) == end and fails.at == self.entropy_drawn[end]) {
                try conn.provide(request.token, .entropy_failed);
                continue;
            };
            var bytes: [512]u8 = undefined;
            self.rng.random().bytes(bytes[0..len]);
            conn.provide(request.token, .{ .entropy = bytes[0..len] }) catch |err| switch (err) {
                // A scalar draw outside its range: draw again.
                error.InvalidEntropy => continue,
                else => return err,
            };
        },
        .time => try conn.provide(request.token, .{ .time = .fromNanoseconds(@as(i96, self.options.time) * std.time.ns_per_s) }),
        .verify => |verify_request| {
            std.crypto.hash.sha2.Sha256.hash(verify_request.chain[0], &self.peer_leaf[@intFromBool(conn == &self.server)], .{});
            const responses = verify_request.evidence.ocsp;
            self.peer_ocsp[@intFromBool(conn == &self.server)] = if (responses.len == 0) null else blk: {
                var digest: [32]u8 = undefined;
                std.crypto.hash.sha2.Sha256.hash(responses[responses.len - 1], &digest, .{});
                break :blk digest;
            };
            if (self.options.accept_any) {
                var owned = try certificates.types.Verification.init(self.gpa, verify_request, verify_request.chain, true, .{ .nanoseconds = verify_request.time.nanoseconds + std.time.ns_per_day });
                defer owned.deinit();
                try conn.provide(request.token, .{ .verified = &owned });
                continue;
            }
            if (certificates.verify.indexed(self.gpa, verify_request, self.snapshot.issuers())) |receipt| {
                var owned = receipt;
                defer owned.deinit();
                const override = if (conn == &self.server) self.options.receipt_expires else self.options.server_receipt_expires;
                if (override) |expires| owned.expires = certificates.types.instant(expires);
                try conn.provide(request.token, .{ .verified = &owned });
            } else |_| try conn.provide(request.token, .{ .verification_failed = .untrusted });
        },
        .sign => |request_| {
            if (!self.options.client_external or request_.scheme != .ed25519 or request_.prehashed) return error.UnexpectedSignRequest;
            const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(pki.client_ed25519_secret[0..32].*);
            const sig = (try kp.sign(request_.content, null)).toBytes();
            try conn.provide(request.token, .{ .signature = &sig });
        },
    };
}

/// Moves `from`'s output into `to`, `chunk` bytes per receive call.
fn move(self: *Duo, from: *Connection, to: *Connection) !bool {
    const bytes = from.output();
    if (bytes.len == 0) return false;
    var record: usize = 0;
    while (record + 5 <= bytes.len) {
        const len = std.mem.readInt(u16, bytes[record + 3 ..][0..2], .big);
        const longest = &self.longest_protected[@intFromBool(from == &self.server)];
        if (bytes[record] == 23) longest.* = @max(longest.*, len);
        const any = &self.longest_record[@intFromBool(from == &self.server)];
        any.* = @max(any.*, len);
        record += 5 + len;
    }
    var at: usize = 0;
    while (at < bytes.len) {
        const end = @min(bytes.len, at + self.options.chunk);
        const n = try to.receive(bytes[at..end]);
        at += n;
        if (n == 0) {
            if (to.request() == null) return error.Stalled;
            try self.serve(to);
        }
    }
    from.acknowledge(bytes.len);
    return true;
}

/// Runs both ends until both are connected and nothing is left to send.
pub fn handshake(self: *Duo) !void {
    for (0..64) |_| {
        try self.serve(&self.client);
        const sent = try self.move(&self.client, &self.server);
        try self.serve(&self.server);
        const answered = try self.move(&self.server, &self.client);
        if (self.client.phase() == .connected and self.server.phase() == .connected and
            self.client.output().len == 0 and self.server.output().len == 0) return;
        if (!sent and !answered) return error.Stalled;
    }
    return error.Stalled;
}

/// Moves output both ways, answering requests, until neither end has anything to send.
pub fn pump(self: *Duo) !void {
    for (0..64) |_| {
        try self.serve(&self.client);
        const sent = try self.move(&self.client, &self.server);
        try self.serve(&self.server);
        const answered = try self.move(&self.server, &self.client);
        if (!sent and !answered and self.client.output().len == 0 and self.server.output().len == 0) return;
    }
    return error.Stalled;
}

/// Sends `message` from `from` to `to` and reads it back out.
pub fn echo(self: *Duo, from: *Connection, to: *Connection, message: []const u8, out: []u8) ![]u8 {
    var at: usize = 0;
    while (at < message.len) at += try from.send(message[at..]);
    _ = try self.move(from, to);
    var got: usize = 0;
    while (got < message.len) {
        const view = to.readable();
        if (view.len == 0) return error.Stalled;
        @memcpy(out[got..][0..view.len], view);
        to.consume(view.len);
        got += view.len;
    }
    return out[0..got];
}

/// Runs until the server's first flight is waiting in its output, not yet delivered.
pub fn handshakeUntilServerFlight(self: *Duo) !void {
    try self.serve(&self.client);
    _ = try self.move(&self.client, &self.server);
    try self.serve(&self.server);
    if (self.server.output().len == 0) return error.Stalled;
}

/// Moves the client's pending output to the server, after `edit` changes it in place.
pub fn deliverEdited(self: *Duo, edit: *const fn (bytes: []u8) void) !void {
    try self.serve(&self.client);
    const bytes = self.client.output();
    const copy = try self.gpa.dupe(u8, bytes);
    defer self.gpa.free(copy);
    self.client.acknowledge(bytes.len);
    edit(copy);
    var at: usize = 0;
    while (at < copy.len) {
        const n = try self.server.receive(copy[at..]);
        at += n;
        if (n == 0) {
            if (self.server.request() == null) return error.Stalled;
            try self.serve(&self.server);
        }
    }
    try self.serve(&self.server);
}

/// Moves the server's pending output to the client and answers what it then asks for.
pub fn deliverServer(self: *Duo) !void {
    _ = try self.move(&self.server, &self.client);
    try self.serve(&self.client);
}

/// Moves the server's pending output to the client after `edit` changes it in place.
pub fn deliverServerEdited(self: *Duo, edit: *const fn (bytes: []u8) void) !void {
    const bytes = self.server.output();
    const copy = try self.gpa.dupe(u8, bytes);
    defer self.gpa.free(copy);
    self.server.acknowledge(bytes.len);
    edit(copy);
    var at: usize = 0;
    while (at < copy.len) {
        const n = try self.client.receive(copy[at..]);
        at += n;
        if (n == 0) {
            if (self.client.request() == null) return error.Stalled;
            try self.serve(&self.client);
        }
    }
    try self.serve(&self.client);
}

/// Answers whatever the client asks for now.
pub fn serveClient(self: *Duo) !void {
    try self.serve(&self.client);
}

/// Answers whatever the server asks for now.
pub fn serveServer(self: *Duo) !void {
    try self.serve(&self.server);
}
