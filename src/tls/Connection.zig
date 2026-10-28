//! A sans-I/O TLS connection, client or server, TLS 1.3 or 1.2. The caller feeds wire bytes to
//! `receive`, writes what `output` holds and acknowledges it, answers each `request` through
//! `provide`, and reads authenticated plaintext from `readable`. The connection owns record
//! keys, sequence numbers and the handshake; it never touches a socket, a clock or a random
//! source.
//!
//! The handshake runs on one task. Once it completes the connection is two halves with record
//! states of their own: the read half (`receive`, `readable`, `consume`, `trim`, `receiveEof`)
//! and the write half (`send`, `keyUpdate`, `finish`, `output`, `acknowledge`, `trimOutput`).
//! One task may use each at the same time as another uses the other. What the read half owes the
//! write half (the KeyUpdate a peer's request asks for, a key update of its own, a warning, the
//! fatal alert a read failure sends) crosses through atomic state and is written by the write
//! half at its next call, `output` included; status (`phase`, `diagnostics`, `readClosed`) may be
//! read from either. `info`, `certificateRequested` and `exportKeyingMaterial` read what the
//! handshake fixed and may be called from either task while the connection lives.
//!
//! Either half may then move to a kernel record layer (kTLS, `offload`): the kernel seals or
//! opens that direction's records, the application's data passes the connection by, and the
//! connection keeps the rest of TLS for that direction through `receiveControl` and `control`.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../certificates.zig");
const types = certificates.types;
const Client = @import("handshake/Client.zig");
const Machine = @import("handshake/Machine.zig");
const Server = @import("handshake/Server.zig");
const Services = @import("handshake/Services.zig");
const Messages = @import("handshake/Messages.zig");
const Group = @import("crypto/Group.zig").Group;
const Suite = @import("crypto/Suite.zig").Suite;
const Version = @import("crypto/Suite.zig").Version;
const Protection = @import("record/Protection.zig");
const Alert = @import("wire/Alert.zig").Alert;
const Outbox = @import("connection/Outbox.zig");
const Buffer = @import("wire/Buffer.zig");
const Flight = @import("handshake/Flight.zig");
const Ech = @import("handshake/Ech.zig");
const Compression = @import("handshake/Compression.zig");
const Psk = @import("handshake/Psk.zig");
const Keys = @import("offload/Keys.zig");
const RecordLimits = @import("handshake/RecordLimits.zig");

pub const Epoch = Client.Epoch;
pub const Verify = Client.Verify;
pub const Resumption = Client.Resumption;
pub const SessionCache = @import("resumption/SessionCache.zig");
pub const TicketKeys = Server.TicketKeys;
pub const KeyLog = Client.KeyLog;
pub const Info = Client.Info;
pub const SignRequest = Client.SignRequest;

pub const Limits = struct {
    handshake: Client.Limits = .{},
    /// Records and plaintext bytes per direction and epoch before a key update; tests lower them.
    records: u64 = 1 << 24,
    bytes: u64 = 1 << 38,
    /// Committed ciphertext awaiting the transport.
    output: usize = 128 * 1024,
    /// Control messages (tickets, key updates) accepted in a row without application data.
    control: usize = 64,
    /// Records processed by one `receive` before it returns.
    step_records: usize = 64,
};

pub const ServerName = union(enum) {
    /// The reference identity when it is a DNS name; none for an address.
    identity,
    name: []const u8,
    none,
};

pub const ClientCredential = Client.Credential;

pub const ClientOptions = struct {
    /// What the server certificate must identify. Required for full verification.
    identity: types.Identity,
    /// The peer-verification policy. Required: there is no implicit default.
    verify: Verify,
    server_name: ServerName = .identity,
    /// Suites of both versions in preference order; the version follows from the suite.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions. `min_version = .tls13` refuses TLS 1.2 peers;
    /// `max_version = .tls12` speaks only TLS 1.2.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = Group.default,
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    /// The peer authenticates with ML-DSA, its whole path to the anchor (TLS 1.3); a server
    /// requiring it of clients needs a required, verified client certificate.
    require_pq_auth: bool = false,
    /// The signature schemes taken from the peer, in this end's order, restricting cloak's and
    /// never adding to them (FIPS, CNSA or the caller's own policy); borrowed, at most 16.
    peer_schemes: []const @import("handshake/Hello.zig").SignatureScheme = &.{},
    /// What a CertificateRequest is answered with, in this client's order, each with its
    /// delegated credential (RFC 9345): the first the request takes that chains to an authority
    /// it names (RFC 8446 section 4.2.4), else the first; borrowed. At most 32, certificates or
    /// raw keys (RFC 7250) or both, of the type the server selects.
    credentials: []const @import("handshake/Client.zig").Credential = &.{},
    /// certificate_authorities (RFC 8446 section 4.2.4): the DER Names of the anchors this client
    /// trusts, named in a hello offering TLS 1.3, a server's preference among its credentials;
    /// borrowed. None by default; at most 8 KiB on the wire.
    certificate_authorities: []const []const u8 = &.{},
    /// Take a server's delegated credential (RFC 9345): its key proves possession for the
    /// verified certificate that signed it. TLS 1.3, with full verification.
    accept_delegated: bool = false,
    /// TLS 1.3 session resumption from a ticket cache.
    resumption: ?Resumption = null,
    /// Answer CertificateRequests after the handshake (RFC 8446 section 4.6.2), TLS 1.3: with
    /// a credential when the request takes one, an empty Certificate otherwise.
    post_handshake_auth: bool = false,
    /// Encrypted Client Hello (RFC 9849). With a config list it is required: the connection is
    /// TLS 1.3 only, and fails with `EchRejected` when the server does not accept it.
    ech: Ech.Mode = .off,
    /// GREASE (RFC 8701): reserved values in the hello, which servers must ignore, drawn per
    /// connection; a server that refuses them is found now rather than when a real one comes.
    grease: bool = false,
    /// The hello's extensions in a random order per connection (`Hello.Permutation`), so a server
    /// that depends on one order is found now rather than when a new extension moves it.
    permute_extensions: bool = false,
    /// Certificate decoders to offer (RFC 8879), TLS 1.3 only; borrowed.
    certificate_compression: []const Compression.Codec = &.{},
    /// Provisioned keys to offer, borrowed: TLS 1.3 PSK-DHE, plain or imported (RFC 9258), or one
    /// TLS 1.2 plain PSK key with its suites listed (no forward secrecy).
    external_psks: []const Psk.External = &.{},
    /// record_size_limit (RFC 8449): the most plaintext a protected record sent to this end may
    /// carry, as the extension counts it (64 to 2^14 + 1; TLS 1.3 counts the inner content type).
    /// Always offered; null names the version's maximum. Records are held to it only when the
    /// server answers the extension; this end holds its own records to the limit the peer names.
    record_size_limit: ?u16 = null,
    /// The most plaintext one record this end sends carries, 64 to 2^14 (BoringSSL's and
    /// OpenSSL's max_send_fragment): smaller records for a peer's small buffers or a stream's
    /// latency, handshake records included. A lower record_size_limit from the peer holds over
    /// it; null is 2^14.
    max_fragment: ?u16 = null,
    limits: Limits = .{},
    /// Send a random legacy session id and one change_cipher_spec for middleboxes.
    compat: bool = true,
    key_log: ?KeyLog = null,
    /// Keep the server's leaf certificate for `peerLeaf` (RFC 8705's certificate binding, a
    /// pin checked after the handshake): a copy the connection holds until `deinit`. Off, a
    /// connection keeps none and `peerLeaf` is null.
    keep_peer_leaf: bool = false,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

pub const Service = Services.Service;
pub const Request = Services.Request;
pub const VerifyFailure = Services.VerifyFailure;
pub const Answer = Services.Answer;

pub const Phase = enum(u8) { handshaking, connected, closed, failed };

pub const Diagnostics = struct {
    phase: Phase,
    reason: ?Error,
    alert_sent: ?Alert,
    alert_received: ?Alert,
};

pub const InitError = Client.InitError || error{InvalidOptions};
/// Everything that ends a connection, local or from the peer.
pub const Error = Client.Error || Protection.InitError || Protection.SealError || Protection.OpenError || Protection.UpdateError || Outbox.Error || error{
    BadRecord,
    RecordOverflow,
    RecordLimit,
    PeerAlert,
    UnexpectedRecord,
    ControlFlood,
    Truncated,
    Closed,
    EarlyDataLimit,
};
pub const ProvideError = Error || error{ StaleToken, NoRequest };
pub const ReceiveError = Error;
pub const SendError = Error || error{ NotConnected, WriteClosed };
pub const FinishError = SendError;

const max_content = 1 << 14;
/// Early data a server skips, in record bytes, before the client's real flight (design 5.5).
pub const max_early_skip = 64 * 1024;
const max_record = 5 + max_content + 256;
/// The most a record adds around a plaintext fragment: header, TLS 1.3 inner content type or
/// TLS 1.2 explicit nonce, and AEAD tag.
const record_overhead = Protection.max_overhead;
const Connection = @This();

gpa: std.mem.Allocator,
hs: Machine,
limits: Limits,
rx: ?Protection = null,
tx: ?Protection = null,
rx_epoch: Epoch = .initial,
tx_epoch: Epoch = .initial,
/// RFC 8449: what protected records may carry each way, as the handshake negotiated.
record_limits: RecordLimits = .{},
/// The most plaintext one record this end sends carries (`max_fragment`).
max_fragment: u16 = 1 << 14,
phase_now: aegis.Atomic(Phase) = .init(.handshaking),
/// Set once the handshake completes: from then on the halves may run on two tasks.
split: bool = false,
/// What the handshake negotiated, taken as it completes, before the halves may run on two
/// tasks: either may read it while the read half goes on using the handshake's state.
negotiated: ?Info = null,
services: Services,
// Inbound record and handshake message reassembly.
record: Buffer = .{},
head: [5]u8 = undefined,
record_have: usize = 0,
plain_kind: ?Protection.Content = null,
plain_pos: usize = 0,
plain_end: usize = 0,
header: [4]u8 = undefined,
header_have: u8 = 0,
message: Buffer = .{},
message_total: usize = 0,
message_have: usize = 0,
seen_ccs: bool = false,
sent_hello: bool = false,
control_run: usize = 0,
alerts_ignored: u8 = 0,
/// Early data skipped so far, and whether the client's handshake records have begun.
early_skipped: usize = 0,
early_done: bool = false,
// Outbound.
outbox: Outbox = .{},
read_done: aegis.Atomic(Done) = .init(.open),
write_done: aegis.Atomic(Done) = .init(.open),
rx_asked_update: bool = false,
/// The first failure.
failure: aegis.Atomic(Failure) = .init(.none),
alert_sent: aegis.Atomic(AlertCode) = .init(.none),
alert_received: aegis.Atomic(AlertCode) = .init(.none),
/// What the read half owes the write half (`owe_*` bits), and the fatal alert it owes, which is
/// the last this side sends.
owed: aegis.Guarded(u8) = .init(0),
owed_alert: aegis.Atomic(AlertCode) = .init(.none),
/// The directions a kernel record layer holds: it seals or opens their records from then on.
rx_kernel: bool = false,
tx_kernel: bool = false,
/// Whether the kernel holding each direction takes its keys again (`Installer.rekeys`): one
/// that does not cannot follow a KeyUpdate, so the connection closes before needing one.
rx_rekeys: bool = false,
tx_rekeys: bool = false,
/// With the write keys in a kernel and a key update made: the pending control bytes the kernel
/// sends under the old keys (the KeyUpdate and what came before it) before it takes the new.
rekey_at: ?u32 = null,

/// Whether a half is done: closed by close_notify, or shut.
const Done = enum(u8) { open, done };
/// An error of the connection, as its integer, for an atomic cell.
const Failure = enum(u16) { none = 0, _ };
/// An alert's byte, or none.
const AlertCode = enum(u16) {
    none = 0x100,
    _,

    fn of(value: Alert) AlertCode {
        return @fromBackingInt(@as(u16, @backingInt(value)));
    }

    fn alert(code: AlertCode) ?Alert {
        if (code == .none) return null;
        return @fromBackingInt(@as(u8, @intCast(@backingInt(code)))); // safe: stored codes are alert bytes or none
    }
};
/// A KeyUpdate message: its type, and its length with the header.
const key_update_type: u8 = 24;
const key_update_len: usize = 5;
const owe_key_update: u8 = 1;
const owe_update_request: u8 = 2;
const owe_no_renegotiation: u8 = 4;
const owe_fatal: u8 = 8;
/// The connection failed in the read half: the write half erases its keys.
const owe_teardown: u8 = 16;
/// A client's answer to a post-handshake CertificateRequest, to end with its Finished and send.
const owe_auth: u8 = 32;

pub fn client(gpa: std.mem.Allocator, options: ClientOptions) InitError!Connection {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    const max_fragment = try RecordLimits.fragment(options.max_fragment);
    // A fully qualified name's trailing dot names the same host; neither the server name
    // sent (RFC 6066 section 3) nor a certificate's names carry it.
    const identity: types.Identity = switch (options.identity) {
        .dns => |name| if (name.len > 1 and name[name.len - 1] == '.') .{ .dns = name[0 .. name.len - 1] } else options.identity,
        else => options.identity,
    };
    const sni: []const u8 = switch (options.server_name) {
        .identity => switch (identity) {
            .dns => |name| name,
            else => "",
        },
        .name => |name| name,
        .none => "",
    };
    const hs = try Client.init(gpa, .{
        .hello = .{
            .suites = options.suites,
            .min_version = options.min_version,
            .max_version = options.max_version,
            .groups = options.groups,
            .sni = sni,
            .alpn = options.alpn,
            .require_alpn = options.require_alpn,
            .require_hybrid = options.require_hybrid,
            .require_pq_auth = options.require_pq_auth,
            .peer_schemes = options.peer_schemes,
            .accept_delegated = options.accept_delegated,
            .certificate_authorities = options.certificate_authorities,
            .certificate_compression = options.certificate_compression,
            .post_handshake_auth = options.post_handshake_auth,
            .record_size_limit = options.record_size_limit,
        },
        .resumption = options.resumption,
        .ech = options.ech,
        .external_psks = options.external_psks,
        .grease = options.grease,
        .permute_extensions = options.permute_extensions,
        .identity = identity,
        .verify = options.verify,
        .credentials = options.credentials,
        .limits = options.limits.handshake,
        .compat = options.compat,
        .key_log = options.key_log,
        .keep_peer_leaf = options.keep_peer_leaf,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = .{ .state = .{ .client = hs } }, .limits = options.limits, .max_fragment = max_fragment, .services = .init(options.generation) };
}

pub const ServerOptions = struct {
    /// Chains the server can present, with the names each answers for. At least one.
    credentials: []const Server.Credential,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    /// Suites of both versions in preference order; the version follows from the suite.
    suites: []const Suite = Suite.default,
    /// The lowest and highest versions. `min_version = .tls13` refuses TLS 1.2 peers;
    /// `max_version = .tls12` speaks only TLS 1.2.
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = Group.default,
    /// Application protocols in the server's order of preference.
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    /// The peer authenticates with ML-DSA, its whole path to the anchor (TLS 1.3); a server
    /// requiring it of clients needs a required, verified client certificate.
    require_pq_auth: bool = false,
    /// The signature schemes taken from the peer, in this end's order, restricting cloak's and
    /// never adding to them (FIPS, CNSA or the caller's own policy); borrowed, at most 16.
    peer_schemes: []const @import("handshake/Hello.zig").SignatureScheme = &.{},
    client_auth: Server.Auth = .none,
    /// How a presented client chain is checked; required for authenticated client identities.
    client_verify: Verify = .none,
    /// certificate_authorities (RFC 8446 section 4.2.4; RFC 5246 section 7.4.4 in TLS 1.2): the
    /// DER Names of the client anchors every CertificateRequest names, a client's preference
    /// among its credentials; borrowed. None by default; at most 8 KiB on the wire.
    certificate_authorities: []const []const u8 = &.{},
    /// Take a client's delegated credential (RFC 9345): TLS 1.3, a client certificate asked for
    /// and fully verified.
    accept_delegated: bool = false,
    /// Session tickets to issue and resume from; shared, and outliving the connection.
    tickets: ?*Server.TicketKeys = null,
    /// TLS 1.2 session tickets too (RFC 5077): an abbreviated TLS 1.2 handshake reuses the
    /// session's master secret with no new key exchange, so they are off unless asked for.
    tls12_tickets: bool = false,
    /// Ask for a client certificate after the handshake (`requestCertificate`), TLS 1.3, when
    /// the client offers it; its answer is checked by `client_verify`.
    post_handshake_auth: bool = false,
    /// Encrypted Client Hello keys (RFC 9849), borrowed for the life of the connection.
    ech_keys: []const Ech.Key = &.{},
    /// Certificate encoders (RFC 8879) in the server's order of preference; borrowed.
    certificate_compression: []const Compression.Codec = &.{},
    /// Provisioned keys, looked up by the offered identity: TLS 1.3 PSK-DHE, TLS 1.2 plain PSK
    /// when its suites are listed. With them a server needs no credential.
    external_psk: ?Psk.Lookup = null,
    /// record_size_limit (RFC 8449), answered to a client that offers one: the most plaintext a
    /// protected record sent to this server may carry, as the extension counts it (64 to
    /// 2^14 + 1). Null names the version's maximum. The client's own limit bounds every record
    /// this server seals for it.
    record_size_limit: ?u16 = null,
    /// The most plaintext one record this end sends carries, 64 to 2^14 (BoringSSL's and
    /// OpenSSL's max_send_fragment): smaller records for a peer's small buffers or a stream's
    /// latency, handshake records included. A lower record_size_limit from the peer holds over
    /// it; null is 2^14.
    max_fragment: ?u16 = null,
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    /// Keep the client's leaf certificate for `peerLeaf` (RFC 8705's certificate-bound access
    /// tokens): a copy the connection holds until `deinit`, replaced by a post-handshake answer
    /// that proves another. Off, a connection keeps none and `peerLeaf` is null.
    keep_peer_leaf: bool = false,
    generation: types.ConnectionGeneration = .fromRaw(0),
};

/// A server connection: the same record, request and key handling around the server handshake.
pub fn server(gpa: std.mem.Allocator, options: ServerOptions) InitError!Connection {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    const max_fragment = try RecordLimits.fragment(options.max_fragment);
    const hs = try Server.init(gpa, .{
        .suites = options.suites,
        .min_version = options.min_version,
        .max_version = options.max_version,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .require_pq_auth = options.require_pq_auth,
        .peer_schemes = options.peer_schemes,
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .client_auth = options.client_auth,
        .client_verify = options.client_verify,
        .certificate_authorities = options.certificate_authorities,
        .accept_delegated = options.accept_delegated,
        .tickets = options.tickets,
        .tls12_tickets = options.tls12_tickets,
        .post_handshake_auth = options.post_handshake_auth,
        .ech_keys = options.ech_keys,
        .certificate_compression = options.certificate_compression,
        .external_psk = options.external_psk,
        .record_size_limit = options.record_size_limit,
        .limits = options.limits.handshake,
        .key_log = options.key_log,
        .keep_peer_leaf = options.keep_peer_leaf,
        .generation = options.generation,
    });
    return .{ .gpa = gpa, .hs = .{ .state = .{ .server = hs } }, .limits = options.limits, .max_fragment = max_fragment, .services = .init(options.generation) };
}

pub fn deinit(self: *Connection) void {
    @setRuntimeSafety(true);
    if (self.rx) |*p| p.deinit();
    if (self.tx) |*p| p.deinit();
    self.hs.deinit();
    self.record.free(self.gpa);
    self.message.free(self.gpa);
    self.outbox.deinit(self.gpa);
    self.* = undefined;
}

// ---------------------------------------------------------------- status

pub fn phase(self: *const Connection) Phase {
    return self.phase_now.load(.acquire);
}

pub fn diagnostics(self: *const Connection) Diagnostics {
    // A fatal alert the read half owes is the one this side sends, written or not yet.
    const owed = self.owed_alert.load(.acquire);
    const sent = if (owed != .none) owed else self.alert_sent.load(.acquire);
    return .{ .phase = self.phase(), .reason = self.failureError(), .alert_sent = sent.alert(), .alert_received = self.alert_received.load(.acquire).alert() };
}

fn failureError(self: *const Connection) ?Error {
    const code = self.failure.load(.acquire);
    if (code == .none) return null;
    return @errorCast(@errorFromInt(@backingInt(code)));
}

/// Records the first failure; a later one, from the other half, keeps it.
fn recordFailure(self: *Connection, err: Error) void {
    _ = self.failure.cmpxchgStrong(.none, @fromBackingInt(@intFromError(err)), .acq_rel, .acquire);
    self.phase_now.store(.failed, .release);
}

/// Whether the server asked this client for a certificate (or this server asks its client for
/// one), whether or not the handshake completed.
pub fn certificateRequested(self: *const Connection) bool {
    return self.hs.certificateRequested();
}

/// The peer's leaf certificate (DER), once the handshake proved it: the chain passed the
/// verification policy (under `.none` nothing checked it) and the leaf's key signed the
/// handshake (CertificateVerify, or a TLS 1.2 server's ServerKeyExchange). A server's later
/// post-handshake answer that proves a certificate replaces it as that answer settles. Null
/// before the handshake completes, after a failure, when the peer proved no certificate (none
/// asked for, an empty Certificate, a raw public key), and on resumption: tickets do not carry
/// the leaf, and do not grow to. Only the leaf is kept (what RFC 8705 binds a token to). Valid
/// until `deinit`; at a server, until the answer to its next `requestCertificate` settles.
pub fn peerLeaf(self: *const Connection) ?[]const u8 {
    if (self.info() == null) return null;
    if (self.hs.postAuth()) |post| if (post.latestLeaf()) |leaf| return leaf;
    const leaf = self.hs.peerLeaf();
    return if (leaf.len == 0) null else leaf;
}

/// Negotiated parameters; null before the handshake completes and after a failure.
pub fn info(self: *const Connection) ?Info {
    if (self.phase() == .failed) return null;
    return self.negotiated;
}

/// After a failure with `EchRejected`: the ECHConfigList the server offered for a retry on a new
/// connection, authenticated by its public name, or empty when it offered none (ECH securely
/// disabled for it). Null for every other outcome. Valid until `deinit`.
pub fn echRetryConfigs(self: *const Connection) ?[]const u8 {
    return self.hs.echRetryConfigs();
}

/// True once the peer sent close_notify: no more plaintext will arrive.
pub fn readClosed(self: *const Connection) bool {
    return (self.read_done.load(.acquire) == .done);
}

pub const ExportError = Client.ExportError;
/// Keying material (RFC 5705, RFC 8446 section 7.5) under `label`. In TLS 1.2 a context, even
/// an empty one, enters with its length and null leaves it out, which RFC 5705 tells apart; in
/// TLS 1.3 null and empty are the same.
pub fn exportKeyingMaterial(self: *const Connection, out: []u8, label: []const u8, context: ?[]const u8) ExportError!void {
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase() == .failed) return error.WrongPhase;
    return self.hs.exportKeyingMaterial(out, label, context);
}

/// Returns the read half's idle buffers: the record and message buffers when no partial input
/// is held, and the handshake scratch once it is established; before the handshake completes,
/// the output buffer too. Safe to call at any time; the next input acquires them again.
pub fn trim(self: *Connection) void {
    @setRuntimeSafety(true);
    if (self.record_have == 0 and self.plain_kind == null) self.record.free(self.gpa);
    if (self.message_total == 0 and self.header_have == 0) self.message.free(self.gpa);
    if (!self.split) self.outbox.trim(self.gpa);
    self.hs.settle();
}

/// Returns the output buffer when nothing is pending; the write half's `trim`.
pub fn trimOutput(self: *Connection) void {
    self.outbox.trim(self.gpa);
}

// ---------------------------------------------------------------- services

/// The service the engine is waiting for, if any. Answer it with `provide`.
pub fn request(self: *Connection) ?Request {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Connection, token: types.Token, answer: Answer) ProvideError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase() == .failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        // These leave the request open: a wrong token or a rejected scalar draw is not fatal.
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.readFailed(fatal),
    };
    self.drain() catch |err| return self.readFailed(err);
    // Plaintext buffered while the engine waited continues without new input.
    _ = self.receiveChecked(&.{}) catch |err| return self.readFailed(err);
}

// ---------------------------------------------------------------- failure

fn alertFor(self: *const Connection, err: Error) Alert {
    return switch (err) {
        error.BadRecord => .bad_record_mac,
        error.RecordOverflow => .record_overflow,
        error.UnexpectedRecord, error.ControlFlood, error.EarlyDataLimit => .unexpected_message,
        else => self.services.alertFor(err),
    };
}

/// Whether a failure tells the peer with a fatal alert: not the peer's own alert, nor a close.
fn alerts(err: Error) bool {
    return err != error.PeerAlert and err != error.Closed;
}

/// A failure of the read half (or of the handshake): it ends the connection. Before the
/// handshake completes one task holds both halves, and the fatal alert goes out now; after it,
/// the alert is owed to the write half, which sends it at its next call and erases its keys.
fn failRead(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (!self.split) return self.failWhole(err);
    if (self.phase() == .failed and self.rx == null) return;
    self.recordFailure(err);
    if (alerts(err)) self.owed_alert.store(.of(self.alertFor(err)), .release);
    self.addOwed(if (alerts(err)) owe_fatal | owe_teardown else owe_teardown);
    if (self.rx) |*p| p.deinit();
    self.rx = null;
    self.plain_kind = null;
}

/// A failure of the write half ends the connection: one fatal alert under the write keys while
/// they last, then they are erased. The read half sees the failure at its next call.
fn failWrite(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (!self.split) return self.failWhole(err);
    if (self.phase() == .failed and self.tx == null) return;
    self.recordFailure(err);
    if (alerts(err) and self.tx != null) self.sendAlert(2, self.alertFor(err));
    if (self.tx) |*p| p.deinit();
    self.tx = null;
}

/// Ends a connection one task holds whole: one fatal alert when keys allow it, and every secret
/// erased.
fn failWhole(self: *Connection, err: Error) void {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return;
    self.recordFailure(err);
    if (alerts(err)) self.sendAlert(2, self.alertFor(err));
    if (self.rx) |*p| p.deinit();
    if (self.tx) |*p| p.deinit();
    self.rx = null;
    self.tx = null;
    self.hs.wipe();
    self.plain_kind = null;
}

fn sendAlert(self: *Connection, level: u8, alert: Alert) void {
    @setRuntimeSafety(true);
    const body = [2]u8{ level, @backingInt(alert) };
    const dst = self.outbox.tail(self.gpa, body.len + record_overhead, self.limits.output + max_record) catch return;
    const wire = self.sealRecord(.alert, &body, dst) catch return;
    self.outbox.commit(wire.len);
    self.alert_sent.store(.of(alert), .release);
}

/// Writes what the read half owes, in the write half: a fatal alert (then the write keys go), a
/// KeyUpdate answering or asking for one, a warning no_renegotiation.
fn writeOwed(self: *Connection) void {
    @setRuntimeSafety(true);
    const bits = bits: {
        var held = self.owed.acquire();
        defer held.deinit();
        const taken = held.value().*;
        held.value().* = 0;
        break :bits taken;
    };
    if (bits & owe_fatal != 0) {
        if (self.tx != null) self.sendAlert(2, self.owed_alert.load(.acquire).alert().?);
    }
    if (self.phase() == .failed) {
        if (self.tx) |*p| p.deinit();
        self.tx = null;
        return;
    }
    if ((self.write_done.load(.acquire) == .done)) {
        // Nothing more goes out: an answer never sent frees the next request all the same.
        if (bits & owe_auth != 0) self.hs.postAuth().?.sent();
        return;
    }
    if (bits & owe_no_renegotiation != 0) self.sendAlert(1, .no_renegotiation);
    if (bits & (owe_key_update | owe_update_request) != 0) {
        self.sendKeyUpdate(bits & owe_update_request != 0) catch |err| self.failWrite(err);
    }
    if (bits & owe_auth != 0 and self.phase() != .failed) self.sendAuthResponse() catch |err| self.failWrite(err);
}

/// Owes the write half `bits`; written at once before the handshake completes.
fn owe(self: *Connection, bits: u8) Error!void {
    self.addOwed(bits);
    if (!self.split) {
        self.writeOwed();
        if (self.failureError()) |err| return err;
    }
}

fn addOwed(self: *Connection, bits: u8) void {
    var held = self.owed.acquire();
    defer held.deinit();
    held.value().* |= bits;
}

/// One record of `content` in the current transmit epoch.
fn sealRecord(self: *Connection, content: Protection.Content, body: []const u8, dst: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (self.tx_kernel) {
        // The kernel seals it: the record waits as its type, length and plaintext (`control`).
        dst[0] = @backingInt(content);
        // safe: control records are at most 2^14 bytes.
        std.mem.writeInt(u16, dst[1..3], @intCast(body.len), .big);
        @memcpy(dst[3..][0..body.len], body);
        return dst[0 .. 3 + body.len];
    }
    if (self.tx) |*protection| return protection.seal(content, body, 0, dst);
    dst[0] = @backingInt(content);
    dst[1..3].* = .{ 3, 3 };
    // safe: plaintext fragments are at most 2^14 bytes.
    std.mem.writeInt(u16, dst[3..5], @intCast(body.len), .big);
    @memcpy(dst[5..][0..body.len], body);
    return dst[0 .. 5 + body.len];
}

// ---------------------------------------------------------------- outbound

/// Whether the read half owes the write half something to send now: a KeyUpdate asking for the
/// peer's, a warning, the fatal alert of a failure, a post-handshake answer. `output` writes it.
/// The KeyUpdate answering the peer's request waits for the next application data, which `send`
/// writes it before: requests received while this end is silent get one answer (RFC 8446 section
/// 4.6.3). A kernel holding the write keys sends that data unseen, so there the answer is owed at
/// once. Read under the lock the other task owes under, so a task that releases the write half
/// and then asks cannot miss what the other task owed meanwhile.
pub fn owes(self: *Connection) bool {
    const bits = bits: {
        var held = self.owed.acquire();
        defer held.deinit();
        break :bits held.value().*;
    };
    return bits & ~owe_key_update != 0 or (bits != 0 and self.tx_kernel);
}

/// Ciphertext to write to the transport, after what the read half owes is written.
pub fn output(self: *Connection) []const u8 {
    aegis.assert.pre(!self.tx_kernel, "a kernel that holds the write keys writes the records");
    if (self.owes()) self.writeOwed();
    return self.outbox.pending();
}

pub fn acknowledge(self: *Connection, n: usize) void {
    aegis.assert.pre(!self.tx_kernel, "a kernel that holds the write keys writes the records");
    self.outbox.acknowledge(n);
}

fn sealMessage(self: *Connection, epoch: Epoch, message: []const u8) Error!void {
    @setRuntimeSafety(true);
    // Handshake messages are the handshake's; after it the read half queues none.
    aegis.assert.invariant(!self.split, "a split connection seals no handshake message");
    if (epoch != self.tx_epoch) return error.UnexpectedRecord;
    // The first record of a ClientHello may carry the older legacy version.
    const legacy = self.tx == null and !self.sent_hello and self.hs.role() == .client;
    try self.sealHandshake(message, legacy);
    if (epoch == .initial) self.sent_hello = true;
}

/// The most plaintext one record of the current write epoch carries: 2^14 bytes, or fewer when the
/// peer named a record_size_limit (RFC 8449). The RFC binds protected records only; plaintext
/// ones sent once the peer's limit is known (a server's after the ClientHello, a TLS 1.2 client's
/// after the ServerHello) are cut to it too, for a constrained peer's buffer takes no larger
/// record whatever protects it, and GnuTLS refuses one.
fn sealLimit(self: *const Connection) usize {
    const protection = if (self.tx) |*p| p else return @min(RecordLimits.content(self.record_limits.send, false), self.max_fragment);
    return @min(RecordLimits.content(self.record_limits.send, !protection.tls12()), self.max_fragment);
}

/// A protected record whose plaintext would pass the record_size_limit this end named is
/// record_overflow (RFC 8449 section 4), told by its length before any decryption.
fn checkLimit(self: *const Connection, protection: *const Protection, record_len: usize) Error!void {
    if (record_len - 5 > protection.expansion() + self.record_limits.receive) return error.RecordOverflow;
}

/// Handshake bytes in records of the current write epoch, at most `sealLimit` bytes each.
fn sealHandshake(self: *Connection, bytes: []const u8, legacy: bool) Error!void {
    @setRuntimeSafety(true);
    var rest = bytes;
    const limit = self.sealLimit();
    while (rest.len != 0) {
        const n = @min(rest.len, limit);
        const dst = try self.outbox.tail(self.gpa, n + record_overhead, self.limits.output + max_record);
        const wire = try self.sealRecord(.handshake, rest[0..n], dst);
        if (legacy) dst[1..3].* = .{ 3, 1 };
        self.outbox.commit(wire.len);
        rest = rest[n..];
    }
}

fn sealCompatCcs(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const dst = try self.outbox.tail(self.gpa, 6, self.limits.output + max_record);
    dst[0..6].* = .{ 20, 3, 3, 0, 1, 1 };
    self.outbox.commit(6);
}

/// Installs a traffic secret; `drain` erases the output that carried it.
fn install(self: *Connection, s: anytype) Error!void {
    @setRuntimeSafety(true);
    const traffic = &s.traffic;
    const slot = self.claim(s.direction);
    errdefer slot.* = null;
    try slot.*.?.init(traffic.suite, traffic.secret.expose()[0..traffic.len], .{ .records = self.limits.records, .bytes = self.limits.bytes });
    switch (s.direction) {
        .read => {
            self.rx_epoch = s.epoch;
            self.rx_asked_update = false;
        },
        .write => self.tx_epoch = s.epoch,
    }
}

/// TLS 1.2 record keys for one direction; they protect the application epoch.
fn install12(self: *Connection, direction: Flight.Direction, keys: *const Flight.Keys12) Error!void {
    @setRuntimeSafety(true);
    const slot = self.claim(direction);
    errdefer slot.* = null;
    try slot.*.?.init12(keys.cipher, keys.keyBytes(), keys.ivBytes(), .{ .records = self.limits.records, .bytes = self.limits.bytes });
    switch (direction) {
        .read => self.rx_epoch = .application,
        .write => self.tx_epoch = .application,
    }
}

/// The protection slot of `direction`, its old keys erased, for the next keys to be made in.
fn claim(self: *Connection, direction: Flight.Direction) *?Protection {
    const slot = switch (direction) {
        .read => &self.rx,
        .write => &self.tx,
    };
    if (slot.*) |*old| old.deinit();
    slot.* = @as(Protection, undefined);
    return slot;
}

/// Moves everything the handshake queued onto the wire and into the key slots, in order.
fn drain(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    // One named copy of each output, erased once used: a secret or key passes through here.
    var emit: Flight.Emit = undefined;
    while (self.hs.pop(&emit)) {
        defer Flight.eraseEmit(&emit);
        switch (emit) {
            .message => |m| try self.sealMessage(m.epoch, self.hs.flightBytes(m.start, m.len)),
            .secret => |*s| try self.install(s),
            .compat_ccs, .change_cipher_spec => try self.sealCompatCcs(),
            .keys12 => |*k| try self.install12(k.direction, &k.keys),
            .key_update => |u| try self.onPeerKeyUpdate(u.request_peer),
            .ticket => try self.onControl(),
            .auth_response => {
                try self.onControl();
                try self.owe(owe_auth);
            },
            .auth_finished => try self.checkAuthFinished(),
            .record_limits => |limits| self.record_limits = limits,
            .refuse_renegotiation => {
                try self.onControl();
                try self.owe(owe_no_renegotiation);
            },
            .complete => {
                self.hs.settle();
                self.negotiated = self.hs.info();
                self.phase_now.store(.connected, .release);
                self.split = true;
            },
            .rejected => return error.EchRejected,
        }
    }
    self.hs.recycle();
}

fn onControl(self: *Connection) Error!void {
    self.control_run += 1;
    if (self.control_run > self.limits.control) return error.ControlFlood;
}

fn onPeerKeyUpdate(self: *Connection, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    try self.onControl();
    // Under a kernel, a KeyUpdate is its record's whole plaintext (`controlChecked`).
    if (self.rx_kernel and (self.plain_end != key_update_len or self.record.bytes()[0] != key_update_type)) return error.UnexpectedRecord;
    try self.rx.?.update();
    self.rx_asked_update = false;
    if (request_peer) try self.owe(owe_key_update);
}

/// KeyUpdate under the old write key, then the next write secret (RFC 8446 section 4.6.3).
fn sendKeyUpdate(self: *Connection, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    // TLS 1.2 has no key update; its connection closes before the record or byte cap instead.
    if (self.tx.?.tls12()) return error.NoKeyUpdate;
    // A kernel that takes the write keys once cannot follow a KeyUpdate: the peer would read on
    // under the next keys and the stream end there. The write side closes cleanly instead,
    // before the epoch runs out, the peer's request for one included.
    if (self.tx_kernel and !self.tx_rekeys) return self.closeWrite();
    if (self.tx.?.owner() == .next) {
        // A kernel has yet to take the keys of the last update: this one waits for it.
        self.addOwed(if (request_peer) owe_update_request else owe_key_update);
        return;
    }
    var message_buf: [5]u8 = undefined;
    const message = try Messages.buildKeyUpdate(&message_buf, request_peer);
    const dst = try self.outbox.tail(self.gpa, message.len + record_overhead, self.limits.output + max_record);
    const wire = try self.sealRecord(.handshake, message, dst);
    self.outbox.commit(wire.len);
    try self.tx.?.update();
    // safe: pending output is bounded by the output limit plus one record.
    if (self.tx_kernel) self.rekey_at = @intCast(self.outbox.pending().len);
}

/// Queues a key update before the write epoch can run out of records or bytes: `records` and
/// `bytes` must fit in what is left.
fn budgetWrite(self: *Connection, records: u64, bytes: u64) Error!void {
    @setRuntimeSafety(true);
    const left = self.tx.?.remaining();
    if (left.records < records or left.bytes < bytes) {
        if (self.tx.?.tls12()) return error.RecordLimit;
        try self.sendKeyUpdate(false);
    }
}

// ---------------------------------------------------------------- post-handshake authentication

pub const PostAuthOutcome = Machine.PostAuth.Outcome;
pub const RequestError = SendError || error{
    /// The client did not offer post-handshake authentication, or this server does not ask for
    /// it (`post_handshake_auth`), or the connection is not TLS 1.3 over a stream.
    PostAuthUnavailable,
    /// The last request has no checked answer yet.
    RequestOutstanding,
};

/// Asks the client for a certificate (RFC 8446 section 4.6.2), as the write half: a
/// CertificateRequest with a context of its own goes out. Returns the generation its answer
/// completes: once `postAuthentication` reaches it, that answer was checked, and its
/// `authenticated` says whether the client proved a certificate the policy authenticates. A
/// chain the policy refuses, a bad signature or Finished ends the connection; an empty
/// Certificate is a refusal the application weighs. One request is outstanding at a time.
pub fn requestCertificate(self: *Connection) RequestError!u64 {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    self.writeOwed();
    if (self.phase() == .failed) return error.Closed;
    if (self.phase() != .connected) return error.NotConnected;
    if ((self.write_done.load(.acquire) == .done)) return error.WriteClosed;
    if (self.hs.role() != .server) return error.PostAuthUnavailable;
    const post = self.hs.postAuth() orelse return error.PostAuthUnavailable;
    var buf: [256 + @import("handshake/Authorities.zig").max_bytes]u8 = undefined;
    const made = post.request(&buf) catch |err| switch (err) {
        error.RequestOutstanding => return error.RequestOutstanding,
        else => |e| return self.writeFailed(e),
    };
    self.budgetWrite(4, 2 * max_content) catch |err| return self.writeFailed(err);
    self.sealHandshake(made.message, false) catch |err| return self.writeFailed(err);
    post.publish();
    return made.number;
}

/// The post-handshake authentications completed so far and the last one's verdict; null when
/// the connection keeps none. From either task.
pub fn postAuthentication(self: *const Connection) ?PostAuthOutcome {
    if (self.phase() == .failed) return null;
    const post = self.hs.postAuth() orelse return null;
    return post.result();
}

/// The client's answer, in the write half: its Certificate and CertificateVerify, then a
/// Finished under the current write keys (RFC 8446 section 4.4: client_application_traffic_secret_N),
/// all three in that epoch: room is made in its budget first, so no key update falls among them.
fn sendAuthResponse(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const post = self.hs.postAuth().?;
    defer post.sent();
    const answer = post.response();
    try self.budgetWrite(answer.flight.len / max_content + 6, answer.flight.len + 4 * max_content);
    var finished: [4 + 48]u8 = undefined;
    const mac = self.tx.?.finished(answer.transcript, finished[4..]);
    finished[0] = 20;
    std.mem.writeInt(u24, finished[1..4], @intCast(mac.len), .big); // safe: 32 or 48
    try self.sealHandshake(answer.flight, false);
    try self.sealHandshake(finished[0 .. 4 + mac.len], false);
}

/// A client's post-handshake Finished, in the read half: the MAC of the exchange under the
/// current read keys, before the exchange counts.
fn checkAuthFinished(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const post = self.hs.postAuth().?;
    const check = post.finishedCheck();
    try self.rx.?.checkFinished(check.transcript, check.received);
    post.settled();
}

/// Whether the read half is inside a client's post-handshake answer, where no other record may
/// come between its messages (RFC 8446 section 4.6.2).
fn midAuth(self: *const Connection) bool {
    const post = self.hs.postAuth() orelse return false;
    return self.hs.role() == .server and post.midFlight();
}

/// Accepts the longest prefix of `plaintext` that fits one record; returns its length. Zero
/// means the output backlog must drain first.
pub fn send(self: *Connection, plaintext: []const u8) SendError!usize {
    @setRuntimeSafety(true);
    aegis.assert.pre(!self.tx_kernel, "a kernel that holds the write keys seals application data");
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    self.writeOwed();
    if (self.phase() == .failed) return error.Closed;
    if (self.phase() != .connected) return error.NotConnected;
    if ((self.write_done.load(.acquire) == .done)) return error.WriteClosed;
    if (plaintext.len == 0) return 0;
    const n = @min(plaintext.len, self.sealLimit());
    if (self.outbox.pending().len + n + record_overhead > self.limits.output) return 0;
    self.budgetWrite(4, 2 * max_content) catch |err| return self.writeFailed(err);
    const dst = self.outbox.tail(self.gpa, n + record_overhead, self.limits.output + max_record) catch |err| return self.writeFailed(err);
    const wire = self.tx.?.seal(.application, plaintext[0..n], 0, dst) catch |err| return self.writeFailed(err);
    self.outbox.commit(wire.len);
    return n;
}

/// A local failure while writing is terminal for the connection.
fn writeFailed(self: *Connection, err: Error) Error {
    self.failWrite(err);
    return err;
}

/// A failure while reading or in the handshake is terminal for the connection.
fn readFailed(self: *Connection, err: Error) Error {
    self.failRead(err);
    return err;
}

/// Asks for new keys in one direction or both (`request_peer`).
pub fn keyUpdate(self: *Connection, request_peer: bool) SendError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    self.writeOwed();
    if (self.phase() != .connected) return error.NotConnected;
    if ((self.write_done.load(.acquire) == .done)) return error.WriteClosed;
    // TLS 1.2 has none, and nor has a kernel that takes keys once: a refusal, not a failure
    // of the connection.
    if (self.tx.?.tls12()) return error.NoKeyUpdate;
    if (self.tx_kernel and !self.tx_rekeys) return error.NoKeyUpdate;
    if (request_peer and self.rx_kernel and !self.rx_rekeys) return error.NoKeyUpdate;
    self.sendKeyUpdate(request_peer) catch |err| return self.writeFailed(err);
}

/// Queues close_notify. The write side is finished; reading continues until the peer's own.
pub fn finish(self: *Connection) FinishError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    self.writeOwed();
    if (self.phase() == .failed) return error.Closed;
    if ((self.write_done.load(.acquire) == .done)) return;
    self.closeWrite();
}

/// close_notify, and the write side done.
fn closeWrite(self: *Connection) void {
    if (self.phase() == .connected) {
        self.sendAlert(1, .close_notify);
    }
    self.write_done.store(.done, .release);
    self.settlePhase();
}

/// Closed once both halves are done; either half may be the second.
fn settlePhase(self: *Connection) void {
    if ((self.read_done.load(.acquire) == .done) and (self.write_done.load(.acquire) == .done)) {
        _ = self.phase_now.cmpxchgStrong(.connected, .closed, .acq_rel, .acquire);
    }
}

// ---------------------------------------------------------------- kernel record layer

pub const Direction = Keys.Direction;
pub const OffloadError = Keys.InstallError || error{
    /// The handshake has not completed.
    NotConnected,
    /// The connection failed, or this direction is closed.
    Closed,
    /// Bytes are staged in this direction: output not yet acknowledged, or part of a record or
    /// message read, or plaintext not yet consumed. Drain them and call again.
    Unclean,
    /// The kernel already holds this direction's current keys.
    Offloaded,
};

/// Moves `direction`'s record protection to a kernel record layer (kTLS) through `installer`,
/// or gives the kernel the keys a key update made (`offloadPending`). The read direction belongs
/// to the read half, the write direction to the write half.
///
/// The first move needs a clean boundary: every byte read from the transport given to
/// `receive` and every record and message in it complete, every plaintext byte consumed, every
/// byte of `output` acknowledged. When the installer fails nothing has moved and the connection
/// goes on in software. Once the kernel holds the keys they are erased here; the kernel seals
/// or opens application data, and the connection keeps the rest: control records the kernel
/// opens come in through `receiveControl`, records the connection sends go out through
/// `control`, and `offloadRecords` keeps each epoch within its record limit.
///
/// A key update in a kernel direction (TLS 1.3) turns the epoch here at once: a KeyUpdate
/// received, or one sent once the kernel has written it. The kernel takes the next keys
/// through this call. Under a kernel that takes a direction's keys once (`Installer.rekeys`:
/// FreeBSD, Linux before 6.14) this end sends no KeyUpdate: `keyUpdate` refuses
/// (`NoKeyUpdate`), and where one is due (the record budget, the peer's request) the write side
/// closes with close_notify instead. A peer's KeyUpdate still ends the connection, since the
/// old read keys are gone and the kernel cannot take the next.
///
/// record_size_limit (RFC 8449): the write direction hands the kernel the peer's limit, which it
/// must take before the keys; a read direction under a limit of this end's own below the version's
/// maximum stays here (`Unsupported`): the kernel opens records of any size the protocol allows.
pub fn offload(self: *Connection, direction: Direction, installer: Keys.Installer) OffloadError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase() == .failed) return error.Closed;
    if (!self.split) return error.NotConnected;
    const slot = switch (direction) {
        .read => &self.rx,
        .write => &self.tx,
    };
    const protection = if (slot.*) |*p| p else return error.Closed;
    const rekey = switch (protection.owner()) {
        .software => false,
        .kernel => return error.Offloaded,
        .next => true,
    };
    if (rekey) {
        // The KeyUpdate goes out under the keys the kernel holds before it takes the next.
        if (direction == .write and self.rekey_at != 0) return error.Unclean;
    } else {
        const done = switch (direction) {
            .read => (self.read_done.load(.acquire) == .done),
            .write => (self.write_done.load(.acquire) == .done),
        };
        if (done) return error.Closed;
        if (protection.kernelCipher() == null) return error.Unsupported;
        if (!self.cleanFor(direction)) return error.Unclean;
    }
    var keys: Keys = .{ .version = .tls13, .cipher = .aes_128_gcm, .key = .init(@splat(0)), .iv = .init(@splat(0)), .sequence = 0 };
    defer keys.deinit();
    // RFC 8449 under a kernel: it opens records up to 2^14 bytes whatever this end named, so a
    // read direction under a lower limit stays here; the write direction takes the peer's limit
    // or this end's `max_fragment`, the lower.
    const max = RecordLimits.max(if (protection.tls12()) .tls12 else .tls13);
    switch (direction) {
        .read => if (self.record_limits.receive < max) return error.Unsupported,
        .write => if (!rekey) {
            // The peer's limit and this end's `max_fragment`, the lower.
            const content = @min(RecordLimits.content(self.record_limits.send, !protection.tls12()), self.max_fragment);
            if (content < 1 << 14) keys.max_payload = @intCast(content); // safe: below 2^14
        },
    }
    protection.exportKeys(&keys);
    installer.install(direction, &keys) catch |err| {
        if (rekey) self.failRekey(direction);
        return err;
    };
    protection.release();
    switch (direction) {
        .read => {
            self.rx_kernel = true;
            self.rx_rekeys = installer.rekeys(.read);
        },
        .write => {
            self.tx_kernel = true;
            self.tx_rekeys = installer.rekeys(.write);
            self.rekey_at = null;
        },
    }
}

/// Whether a kernel record layer holds `direction`.
pub fn offloaded(self: *const Connection, direction: Direction) bool {
    return switch (direction) {
        .read => self.rx_kernel,
        .write => self.tx_kernel,
    };
}

/// Whether a key update made keys the kernel must take, through `offload`, before the
/// direction goes on: after a KeyUpdate received, and after one sent once `control` has handed
/// it out and it is acknowledged.
pub fn offloadPending(self: *const Connection, direction: Direction) bool {
    return switch (direction) {
        .read => if (self.rx) |*p| self.rx_kernel and p.owner() == .next else false,
        .write => if (self.tx) |*p| self.tx_kernel and p.owner() == .next and self.rekey_at == 0 else false,
    };
}

/// Every byte of the direction is settled: nothing a kernel would see half of.
fn cleanFor(self: *const Connection, direction: Direction) bool {
    return switch (direction) {
        .read => self.record_have == 0 and self.plain_kind == null and self.header_have == 0 and self.message_total == 0 and self.hs.need() == .none,
        .write => self.outbox.pending().len == 0,
    };
}

/// A kernel refused the keys of a key update the connection had already made: no keys are left
/// for the direction, and the connection ends. Nothing more goes out under the write keys the
/// kernel kept, since the peer reads under the next ones.
fn failRekey(self: *Connection, direction: Direction) void {
    @setRuntimeSafety(true);
    switch (direction) {
        .read => self.failRead(error.NoKeyUpdate),
        .write => {
            if (self.tx) |*p| p.deinit();
            self.tx = null;
            self.outbox.acknowledge(self.outbox.pending().len);
            self.rekey_at = null;
            self.failWrite(error.NoKeyUpdate);
        },
    }
}

/// A record the kernel opened that is not application data, given by its record type (alert
/// 21, handshake 22) and plaintext: an alert, a NewSessionTicket, a KeyUpdate, a TLS 1.2
/// HelloRequest. Each is taken as `receive` takes it; answer what it asks (`request`) before
/// the next. Only with the read direction offloaded.
pub fn receiveControl(self: *Connection, record_type: u8, plaintext: []const u8) ReceiveError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    aegis.assert.pre(self.rx_kernel, "control records come from a kernel that holds the read keys");
    aegis.assert.pre(self.plain_kind == null and self.hs.need() == .none, "a control record waits until the last one's request is answered");
    if (self.phase() == .failed) {
        if (self.rx) |*p| p.deinit();
        self.rx = null;
        return error.Closed;
    }
    if ((self.read_done.load(.acquire) == .done)) return error.Closed;
    self.controlChecked(record_type, plaintext) catch |err| return self.readFailed(err);
}

fn controlChecked(self: *Connection, record_type: u8, plaintext: []const u8) ReceiveError!void {
    @setRuntimeSafety(true);
    const protection = &self.rx.?;
    // After the peer's KeyUpdate every record is under its next keys, which the kernel does not
    // hold yet: one it opened under the old keys is out of order.
    if (protection.owner() == .next) return error.UnexpectedRecord;
    const content: Protection.Content = switch (record_type) {
        21 => .alert,
        22 => .handshake,
        else => return error.UnexpectedRecord,
    };
    if (plaintext.len == 0) return error.UnexpectedRecord;
    if (plaintext.len > max_content) return error.RecordOverflow;
    // Linux stops its receive path after a handshake record whose first byte is KeyUpdate's
    // type, and nowhere else. So a KeyUpdate comes as a record of its own: one that starts
    // with the type but is not a whole KeyUpdate would stop the kernel with no keys to give
    // it, and one later in a record would leave the kernel opening under the old keys.
    if (content == .handshake and plaintext[0] == key_update_type and
        (plaintext.len != key_update_len or self.message_total != 0 or self.header_have != 0)) return error.UnexpectedRecord;
    // The record took one number of the kernel's count.
    protection.account(protection.records() + 1);
    if (self.record.view().len < plaintext.len) _ = try self.record.ensure(self.gpa, max_content);
    @memcpy(self.record.bytes()[0..plaintext.len], plaintext);
    self.plain_kind = content;
    self.plain_pos = 0;
    self.plain_end = plaintext.len;
    _ = try self.receiveChecked(&.{});
}

/// A record the connection sends while a kernel holds the write keys: the kernel seals it with
/// its record type (Linux: `sendmsg` with a TLS_SET_RECORD_TYPE control message).
pub const Control = struct {
    record_type: u8,
    bytes: []const u8,
};

/// With the write direction offloaded: the next record to send (an alert, a KeyUpdate, the
/// close_notify of `finish`), after what the read half owes is queued; null when none, or when
/// the kernel must take the keys of a key update first (`offloadPending`). Send it whole, in
/// order, and `acknowledgeControl` it.
pub fn control(self: *Connection) ?Control {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    aegis.assert.pre(self.tx_kernel, "control records go to a kernel that holds the write keys");
    if (self.owes()) self.writeOwed();
    const pending = self.outbox.pending();
    if (pending.len == 0 or self.rekey_at == 0) return null;
    const len = std.mem.readInt(u16, pending[1..3], .big);
    return .{ .record_type = pending[0], .bytes = pending[3..][0..len] };
}

/// The record `control` handed out is sent.
pub fn acknowledgeControl(self: *Connection) void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    aegis.assert.pre(self.tx_kernel, "control records go to a kernel that holds the write keys");
    const pending = self.outbox.pending();
    aegis.assert.pre(pending.len != 0 and self.rekey_at != 0, "the caller acknowledges a record control handed out");
    const n = 3 + @as(usize, std.mem.readInt(u16, pending[1..3], .big));
    self.outbox.acknowledge(n);
    // safe: the KeyUpdate's bytes end at `rekey_at`, past every whole record before it.
    if (self.rekey_at) |*at| at.* -= @intCast(n);
}

/// The most records a kernel may seal or open in `direction` between two `offloadRecords`.
pub fn offloadInterval(self: *const Connection, direction: Direction) u64 {
    const slot = switch (direction) {
        .read => &self.rx,
        .write => &self.tx,
    };
    return if (slot.*) |*p| p.recordLimit() / 4 else 0;
}

/// Reports the kernel's count of records in an offloaded direction under its current keys (the
/// next record's number, as the kernel's crypto state holds it), at least every
/// `offloadInterval` records, read after the direction's last `offload`. A kernel that cannot
/// count its records reports `Keys.equivalentRecords` of the bytes it has been handed under the
/// current keys (design C9.1). With a quarter of the epoch's record limit left, a TLS 1.3
/// connection updates its write keys or asks the peer to update its own; TLS 1.2, which has no
/// key update, ends the connection there, before the limit, and so does a TLS 1.3 direction
/// whose kernel takes its keys once (the write side with close_notify).
pub fn offloadRecords(self: *Connection, direction: Direction, records: u64) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    switch (direction) {
        .read => {
            aegis.assert.pre(self.rx_kernel, "records are counted by a kernel that holds the read keys");
            if (self.phase() == .failed) return error.Closed;
            if ((self.read_done.load(.acquire) == .done)) return;
            const p = if (self.rx) |*x| x else return error.Closed;
            if (p.owner() != .kernel) return;
            // Records past the control ones: application data came in between.
            if (records > p.records()) self.control_run = 0;
            p.account(records);
            if (p.remaining().records > p.recordLimit() / 4) return;
            // No key update to ask for: TLS 1.2, or a kernel that takes the read keys once.
            if (p.tls12() or !self.rx_rekeys) return self.readFailed(error.RecordLimit);
            if (self.rx_asked_update or (self.write_done.load(.acquire) == .done)) return;
            self.rx_asked_update = true;
            self.owe(owe_update_request) catch |err| return self.readFailed(err);
        },
        .write => {
            aegis.assert.pre(self.tx_kernel, "records are counted by a kernel that holds the write keys");
            self.writeOwed();
            if (self.phase() == .failed) return error.Closed;
            // After close_notify nothing more is sealed, so nothing more is counted.
            if ((self.write_done.load(.acquire) == .done)) return;
            const p = if (self.tx) |*x| x else return error.Closed;
            if (p.owner() != .kernel) return;
            p.account(records);
            if (p.remaining().records > p.recordLimit() / 4) return;
            if (p.tls12()) return self.writeFailed(error.RecordLimit);
            self.sendKeyUpdate(false) catch |err| return self.writeFailed(err);
        },
    }
}

// ---------------------------------------------------------------- inbound

/// Plaintext waiting for the application; empty when none.
pub fn readable(self: *const Connection) []const u8 {
    @setRuntimeSafety(true);
    if (self.plain_kind != .application) return &.{};
    return self.record.view()[self.plain_pos..self.plain_end];
}

pub fn consume(self: *Connection, n: usize) void {
    @setRuntimeSafety(true);
    aegis.assert.pre(n <= self.plain_end - self.plain_pos, "the caller consumes at most what is readable");
    self.plain_pos += n;
    if (self.plain_pos == self.plain_end and self.plain_kind == .application) self.clearRecord();
}

fn clearRecord(self: *Connection) void {
    self.plain_kind = null;
    self.plain_pos = 0;
    self.plain_end = 0;
    self.record_have = 0;
}

fn blocked(self: *const Connection) bool {
    @setRuntimeSafety(true);
    if (self.phase() == .failed) return true;
    if (self.plain_kind == .application) return true;
    if (self.hs.need() != .none) return true;
    // The handshake's output must drain before more input; after it, the output is the write
    // half's, and what the read half owes it is a few bits that do not grow.
    return !self.split and self.outbox.pending().len > self.limits.output;
}

/// Consumes wire bytes, decrypting and processing whole records. It returns early when the
/// engine is waiting for an answer, plaintext is unread, or output must drain; call it again
/// with the unconsumed remainder.
pub fn receive(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    aegis.assert.pre(!self.rx_kernel, "a kernel that holds the read keys opens the records");
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase() == .failed) {
        // The write half failed: the read keys go too.
        if (self.rx) |*p| p.deinit();
        self.rx = null;
        self.plain_kind = null;
        return error.Closed;
    }
    if ((self.read_done.load(.acquire) == .done)) return error.Closed;
    return self.receiveChecked(input) catch |err| return self.readFailed(err);
}

fn receiveChecked(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    var consumed: usize = 0;
    var records: usize = 0;
    while (true) {
        if (self.blocked() or (self.read_done.load(.acquire) == .done)) return consumed;
        if (self.plain_kind != null) {
            try self.dispatch();
            continue;
        }
        if (consumed == input.len or records == self.limits.step_records) return consumed;
        consumed += try self.fill(input[consumed..]);
        if (self.recordComplete()) {
            records += 1;
            try self.openRecord();
        }
    }
}

fn recordComplete(self: *const Connection) bool {
    return self.record_have >= 5 and self.record_have == 5 + std.mem.readInt(u16, self.record.view()[3..5], .big);
}

/// Copies the next part of a record: its header first, then a buffer sized to its length.
fn fill(self: *Connection, input: []const u8) ReceiveError!usize {
    @setRuntimeSafety(true);
    var used: usize = 0;
    if (self.record_have < 5) {
        const n = @min(5 - self.record_have, input.len);
        @memcpy(self.head[self.record_have..][0..n], input[0..n]);
        self.record_have += n;
        used = n;
        if (self.record_have < 5) return used;
        try self.checkHeader();
        const total = 5 + @as(usize, std.mem.readInt(u16, self.head[3..5], .big));
        @memcpy((try self.record.ensure(self.gpa, total))[0..5], &self.head);
    }
    const total = 5 + @as(usize, std.mem.readInt(u16, self.record.bytes()[3..5], .big));
    const n = @min(total - self.record_have, input.len - used);
    @memcpy(self.record.bytes()[self.record_have..][0..n], input[used..][0..n]);
    self.record_have += n;
    return used + n;
}

fn checkHeader(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    const kind = self.head[0];
    const length = std.mem.readInt(u16, self.head[3..5], .big);
    // Under TLS 1.2 keys, alerts and handshake records are encrypted like application data.
    const sealed12 = if (self.rx) |*p| p.tls12() else false;
    // A plaintext record's version is legacy and ignored (RFC 8446 section 5.1), any {03,XX}
    // (RFC 5246 appendix E.1: SSL 3.0-era clients open with 03,00): it must only look like TLS.
    // That holds before any key and for TLS 1.3's plaintext records after them: a
    // change_cipher_spec or an alert the client sent before it saw the ServerHello carries its
    // hello's version. Protected records say TLS 1.2.
    const plaintext = kind != 23 and !sealed12;
    const version_ok = std.mem.eql(u8, self.head[1..3], &.{ 3, 3 }) or (plaintext and self.head[1] == 3);
    if (!version_ok) return error.UnexpectedRecord;
    switch (kind) {
        // An empty change_cipher_spec, alert or handshake fragment is a record this end cannot
        // take (RFC 8446 sections 5 and 5.1, RFC 5246 section 6.2.1), not one that overflows.
        20 => if (length == 0) return error.UnexpectedRecord else if (length > max_content) return error.RecordOverflow,
        21, 22 => if (sealed12) {
            if (length > max_content + 256) return error.RecordOverflow;
            if (length < 16) return error.BadRecord;
        } else if (length == 0) return error.UnexpectedRecord else if (length > max_content) return error.RecordOverflow,
        23 => {
            if (length > max_content + 256) return error.RecordOverflow;
            // A TLS 1.3 record holds at least its content type and tag; a TLS 1.2 one its tag.
            // Declined early data is the exception: any record of it fails deprotection and is
            // skipped within the bound (RFC 8446 section 4.2.10).
            const early = !self.early_done and self.hs.earlySkip() != .none;
            // Before any read key it is a record this end cannot take at all, whatever its length.
            if (length < @as(u16, if (sealed12) 16 else 17) and !early) return if (self.rx == null) error.UnexpectedRecord else error.BadRecord;
        },
        else => return error.UnexpectedRecord,
    }
}

/// Where opened plaintext starts in the record buffer: after the header, and after a TLS 1.2
/// explicit nonce.
fn offsetOf(self: *const Connection, plain: []const u8) usize {
    return @intFromPtr(plain.ptr) - @intFromPtr(self.record.view().ptr); // the plaintext is a slice of the record buffer, so its address is not below the buffer's
}

fn openRecord(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const wire = self.record.bytes()[0..self.record_have];
    switch (wire[0]) {
        20 => {
            if (self.hs.version() == .tls12) {
                // TLS 1.2: the one ChangeCipherSpec, plaintext, between messages, where the state
                // table expects it; anywhere else it is an injection (CVE-2014-0224).
                if (wire.len != 6 or wire[5] != 1 or self.rx != null or self.message_total != 0 or self.header_have != 0) return error.UnexpectedRecord;
                self.record_have = 0;
                try self.hs.receiveCcs();
                try self.drain();
                return;
            }
            // A single change_cipher_spec after the first hello, only before the peer's Finished
            // and only between messages, is ignored (RFC 8446 section 5 and appendix D.4).
            const allowed = self.hs.helloSeen() and !self.seen_ccs and self.phase() == .handshaking and
                self.message_total == 0 and self.header_have == 0 and wire.len == 6 and wire[5] == 1;
            if (!allowed) return error.UnexpectedRecord;
            self.seen_ccs = true;
            self.record_have = 0;
        },
        21, 22 => {
            if (self.rx) |*protection| {
                if (!protection.tls12()) {
                    // A client refusing the ServerHello writes its alert before it has keys: until
                    // a record opens under its handshake keys, a plaintext alert is its own (RFC
                    // 8446 section 6: alerts go under the sender's current state).
                    const before_keys = wire[0] == 21 and self.hs.role() == .server and
                        self.rx_epoch == .handshake and protection.records() == 0;
                    if (!before_keys) return error.UnexpectedRecord;
                    self.plain_kind = .alert;
                    self.plain_pos = 5;
                    self.plain_end = wire.len;
                    return;
                }
                try self.checkLimit(protection, wire.len);
                const plain = try protection.open(wire, self.record.bytes()[5..]);
                self.plain_kind = plain.content;
                self.plain_pos = self.offsetOf(plain.bytes);
                self.plain_end = self.plain_pos + plain.bytes.len;
                return;
            }
            self.plain_kind = if (wire[0] == 21) .alert else .handshake;
            self.plain_pos = 5;
            self.plain_end = wire.len;
        },
        else => {
            const skip = if (self.early_done) .none else self.hs.earlySkip();
            const protection = &(self.rx orelse {
                // Early data before the server's handshake keys: after a retry request, every
                // protected record before the second hello is the client's declined early data.
                if (skip != .none) return self.skipEarly(wire.len);
                return error.UnexpectedRecord;
            });
            const plain = if (skip == .trial and self.rx_epoch == .handshake) trial: {
                // Declined early data fails under the handshake keys and is skipped; the first
                // record that opens begins the client's flight, and skipping ends.
                const opened = protection.trialOpen(wire, self.record.bytes()[5..]) catch |err| switch (err) {
                    error.Undecryptable => return self.skipEarly(wire.len),
                    else => |e| return e,
                };
                self.early_done = true;
                try self.checkLimit(protection, wire.len);
                break :trial opened;
            } else open: {
                try self.checkLimit(protection, wire.len);
                break :open try protection.open(wire, self.record.bytes()[5..]);
            };
            if (plain.content == .application) {
                // Nothing comes between a handshake message's fragments (RFC 8446 section 5.1).
                if (self.phase() != .connected or self.midAuth() or self.message_total != 0 or self.header_have != 0) return error.UnexpectedRecord;
                self.control_run = 0;
            }
            self.plain_kind = plain.content;
            self.plain_pos = self.offsetOf(plain.bytes);
            self.plain_end = self.plain_pos + plain.bytes.len;
            if (plain.content == .application and plain.bytes.len == 0) self.clearRecord();
            try self.askForUpdate();
        },
    }
}

/// Passes over one record of declined early data, within the bound, and only between messages:
/// nothing comes between a handshake message's fragments (RFC 8446 section 5.1).
fn skipEarly(self: *Connection, len: usize) Error!void {
    if (self.message_total != 0 or self.header_have != 0) return error.UnexpectedRecord;
    self.early_skipped += len;
    if (self.early_skipped > max_early_skip) return error.EarlyDataLimit;
    self.record_have = 0;
}

/// Requests the peer's next write keys before this read epoch runs out.
fn askForUpdate(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    if (self.rx_asked_update or self.phase() != .connected or (self.write_done.load(.acquire) == .done) or self.rx.?.tls12()) return;
    const left = self.rx.?.remaining();
    if (left.records < 1024 or left.bytes < 64 * max_content) {
        self.rx_asked_update = true;
        try self.owe(owe_update_request);
    }
}

fn dispatch(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    switch (self.plain_kind.?) {
        .handshake => try self.feedHandshake(),
        .alert => try self.onAlert(),
        .application => unreachable, // `blocked` holds the loop while plaintext is unread
    }
}

fn onAlert(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    const body = self.record.bytes()[self.plain_pos..self.plain_end];
    self.clearRecord();
    if (body.len != 2) return error.UnexpectedRecord;
    // Only a warning can be passed over: any other level makes an error alert, as RFC 8446
    // section 6.2 has every alert whatever its level, and a level TLS 1.2 does not define (RFC
    // 5246 section 7.2) warns of nothing.
    const warning = body[0] == 1;
    const alert: Alert = @fromBackingInt(@intCast(body[1]));
    self.alert_received.store(.of(alert), .release);
    if (alert == .close_notify and self.phase() == .connected) {
        self.read_done.store(.done, .release);
        self.settlePhase();
        return;
    }
    // A warning is passed over a few times, then the run of them is a flood: this end's bound,
    // refused as such (the peer's warning ended nothing).
    const ignorable = alert == .user_canceled or (alert != .close_notify and self.hs.warningsAllowed());
    if (ignorable and warning) {
        if (self.alerts_ignored == 4) return error.ControlFlood;
        self.alerts_ignored += 1;
        return;
    }
    return error.PeerAlert;
}

fn feedHandshake(self: *Connection) ReceiveError!void {
    @setRuntimeSafety(true);
    while (self.plain_pos < self.plain_end) {
        if (self.message_total == 0) {
            const take = @min(4 - self.header_have, self.plain_end - self.plain_pos);
            @memcpy(self.header[self.header_have..][0..take], self.record.bytes()[self.plain_pos..][0..take]);
            self.header_have += @intCast(take);
            self.plain_pos += take;
            if (self.header_have < 4) break;
            const total = 4 + @as(usize, std.mem.readInt(u24, self.header[1..4], .big));
            if (total > self.limits.handshake.message) return error.HandshakeLimit;
            @memcpy((try self.message.ensure(self.gpa, total))[0..4], &self.header);
            self.message_total = total;
            self.message_have = 4;
            self.header_have = 0;
        }
        const take = @min(self.message_total - self.message_have, self.plain_end - self.plain_pos);
        @memcpy(self.message.bytes()[self.message_have..][0..take], self.record.bytes()[self.plain_pos..][0..take]);
        self.message_have += take;
        self.plain_pos += take;
        if (self.message_have == self.message_total) {
            const total = self.message_total;
            self.message_total = 0;
            self.message_have = 0;
            const boundary = self.plain_pos == self.plain_end and self.header_have == 0;
            try self.hs.receive(self.message.bytes()[0..total], self.rx_epoch, boundary);
            try self.drain();
            if (self.hs.need() != .none) break;
        }
    }
    if (self.plain_pos == self.plain_end) self.clearRecord();
}

/// The transport ended. A close_notify must have arrived; anything else is truncation.
pub fn receiveEof(self: *Connection) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if ((self.read_done.load(.acquire) == .done)) return;
    if (self.phase() != .failed) {
        self.failRead(error.Truncated);
    }
    return error.Truncated;
}

test {
    _ = @import("Connection_test.zig");
    _ = @import("ServerConnection_test.zig");
}
