//! A TLS client stream over `std.Io` readers and writers. It drives a `Connection`: it
//! answers the engine's requests with the system's entropy and clock and the configured
//! verifier (and a signer, for a key cloak does not hold), moves ciphertext between the
//! connection and the transport, and presents plaintext as a `std.Io.Reader` and
//! `std.Io.Writer`.
//!
//! After `open` or `accept` returns, one task may read (`reader`) while another writes
//! (`writer`, `keyUpdate`, `finish`): the connection's halves keep their own record states, and
//! what crosses them (the KeyUpdate a peer's request owes, a key update of its own, an alert) is
//! written under the session's write lock by whichever task holds it. The reading task never
//! waits for that lock: while the writing task holds it (blocked, perhaps, on a peer that is not
//! reading) what the read owes is left for the writer, which writes it before its next record
//! or as it lets the lock go, so neither end can wait on the other's reader. The transport's reader is
//! the reading task's alone, its writer is used under the write lock. Two tasks may not read at
//! once, nor two write at once; `rebind` and `deinit` run with neither. `info`, `diagnostics`,
//! `closeNotified`, `failure` and `exportKeyingMaterial` may be called from either task. The
//! session stores `io` for the entropy and clock requests and for the adapters' vtables; open it
//! in place and do not move it afterwards.
const std = @import("std");
const certificates = @import("../certificates.zig");
const Connection = @import("Connection.zig");
const Server = @import("handshake/Server.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Version = @import("crypto/Suite.zig").Version;
const Alert = @import("wire/Alert.zig").Alert;
const Group = @import("crypto/Group.zig").Group;

const Session = @This();

/// How the server certificate is checked.
pub const Trust = union(enum) {
    /// No verification: the connection reports itself unauthenticated.
    none,
    /// A retained root snapshot, checked as its policy says: by the portable verifier, or,
    /// for the system's policy on macOS and Windows, by the system's verifier and then the
    /// portable one over the path it chose, with the snapshot's own roots trusted besides.
    snapshot: certificates.Trust.Snapshot,
    /// The caller's verifier, for native or custom policy.
    custom: Custom,
    /// A raw public key (RFC 7250, TLS 1.3 and 1.2) trusted by its pin, the SHA-256 of its
    /// SubjectPublicKeyInfo; no certificate is taken. `Info.raw_key_pin` names the one proved.
    raw_keys: []const [32]u8,
};

pub const Custom = struct {
    context: ?*anyopaque = null,
    generation: certificates.types.TrustGeneration,
    verify: *const fn (context: ?*anyopaque, gpa: std.mem.Allocator, request: certificates.types.Request) VerifyError!certificates.types.Verification,
};

pub const VerifyError = certificates.verify.VerifyError || error{ OutOfMemory, Failed };

/// Signs the CertificateVerify content for a certificate whose key cloak does not hold: an
/// identity made with `initExternal`, or a key kind cloak does not sign with yet (RSA).
pub const Signer = struct {
    context: ?*anyopaque = null,
    /// Signs `request.content` under `request.scheme` into `out` and returns the length. Content
    /// marked `prehashed` is already the digest of the scheme's hash (a TLS 1.2
    /// CertificateVerify): sign it without hashing again.
    sign: *const fn (context: ?*anyopaque, request: SignRequest, out: []u8) error{SigningFailed}!usize,
};

/// What a signer is asked to sign.
pub const SignRequest = Connection.SignRequest;

/// A client's cache of session tickets; see `Options.resumption`.
pub const SessionCache = Connection.SessionCache;
/// A server's session-ticket keys; see `ServerOptions.tickets`.
pub const TicketKeys = Connection.TicketKeys;

/// What a connection saw, for a caller that maps it to errors of its own.
pub const Diagnostics = struct {
    /// What ended the connection, when it ended.
    reason: ?Connection.Error = null,
    /// The alert this side sent for a failure of its own.
    alert_sent: ?Alert = null,
    /// The alert the peer sent.
    alert_received: ?Alert = null,
    /// The peer asked for a certificate (or, for a server, this one asks).
    certificate_requested: bool = false,
};

/// What the transport's end of stream means for application data.
pub const Eof = enum {
    /// Only an authenticated close_notify ends the stream cleanly.
    strict,
    /// A bare transport end also ends it; for protocols whose framing detects truncation.
    allow,
};

/// The calendar clock behind certificate validity.
pub const Clock = union(enum) {
    real,
    /// A fixed calendar time, for replay and tests.
    fixed: std.Io.Timestamp,
};

pub const Options = struct {
    identity: certificates.types.Identity,
    trust: Trust,
    policy: certificates.types.Policy = .{},
    pins: []const [32]u8 = &.{},
    evidence: certificates.types.Evidence = .{},
    server_name: Connection.ServerName = .identity,
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
    auth: ?certificates.ClientAuth = null,
    /// Required when `auth` is an identity cloak holds no signing key for.
    signer: ?Signer = null,
    /// TLS 1.3 resumption from a ticket cache. Under the system's verifier (macOS, Windows) a
    /// session is resumed for at most an hour after the full handshake that verified it: the
    /// system's trust can change without a generation to show it.
    resumption: ?Connection.Resumption = null,
    /// Encrypted Client Hello (RFC 9849): GREASE, or the server's ECHConfigList, which makes it
    /// required (TLS 1.3 only; `EchRejected` when the server does not accept it).
    ech: @import("handshake/Ech.zig").Mode = .off,
    /// After `open` fails with `EchRejected` and the server authenticated as the config's public
    /// name: the ECHConfigList it offered for a retry on a new connection, or empty when it
    /// offered none (ECH securely disabled). Allocated with the session's allocator; the caller
    /// frees it. Untouched for any other outcome.
    ech_retry: ?*[]u8 = null,
    /// Certificate decoders to offer (RFC 8879), TLS 1.3 only; borrowed.
    certificate_compression: []const @import("handshake/Compression.zig").Codec = &.{},
    /// A provisioned key to offer (PSK-DHE, TLS 1.3); borrowed. A server that selects it is
    /// authenticated by it, with no certificate.
    external_psk: ?@import("handshake/Psk.zig").External = null,
    limits: Connection.Limits = .{},
    compat: bool = true,
    key_log: ?Connection.KeyLog = null,
    eof: Eof = .strict,
    clock: Clock = .real,
    /// Filled when the handshake fails, since the session is gone by then.
    diagnostics: ?*Diagnostics = null,
};

pub const OpenError = Connection.InitError || Connection.Error || Connection.ProvideError || error{
    ReadFailed,
    WriteFailed,
    EndOfStream,
    EntropyUnavailable,
    SignerRequired,
    Stalled,
    InvalidOptions,
};

pub const ReadError = error{ ReadFailed, EndOfStream };

gpa: std.mem.Allocator,
io: std.Io,
conn: Connection,
input: *std.Io.Reader,
output: *std.Io.Writer,
trust: Trust,
signer: ?Signer,
eof: Eof,
clock: Clock,
/// The first failure behind a `ReadFailed` or `WriteFailed` from an adapter, as an error's
/// integer; zero for none. Read it with `failure`.
failure_code: std.atomic.Value(u16) = .init(0),
/// Held by the reading task through each read.
read_lock: std.Io.Mutex = .init,
/// Held by whichever task writes to the connection's write half or the transport's writer.
write_lock: std.Io.Mutex = .init,
reader_interface: std.Io.Reader,
writer_interface: std.Io.Writer,

/// Performs the handshake over `input` and `output`. The session must stay at this address.
pub fn open(
    session: *Session,
    gpa: std.mem.Allocator,
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    read_buffer: []u8,
    write_buffer: []u8,
    options: Options,
) OpenError!void {
    @setRuntimeSafety(true);
    if (options.auth) |auth| if (auth.identity.noiseLength() == null and options.signer == null) return error.SignerRequired;
    const policy: Connection.Verify = switch (options.trust) {
        .none => .none,
        .snapshot => |snapshot| .{ .full = .{ .trust_generation = snapshot.generation(), .policy = options.policy, .pins = options.pins, .evidence = options.evidence } },
        .custom => |custom| .{ .full = .{ .trust_generation = custom.generation, .policy = options.policy, .pins = options.pins, .evidence = options.evidence } },
        .raw_keys => |pins| .{ .raw_key = .{ .pins = pins } },
    };
    const conn = try Connection.client(gpa, .{
        .identity = options.identity,
        .verify = policy,
        .server_name = options.server_name,
        .suites = options.suites,
        .min_version = options.min_version,
        .max_version = options.max_version,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .require_pq_auth = options.require_pq_auth,
        .auth = options.auth,
        .resumption = resumptionFor(options),
        .ech = options.ech,
        .certificate_compression = options.certificate_compression,
        .external_psk = options.external_psk,
        .limits = options.limits,
        .compat = options.compat,
        .key_log = options.key_log,
    });
    session.* = .{
        .gpa = gpa,
        .io = io,
        .conn = conn,
        .input = input,
        .output = output,
        .trust = options.trust,
        .signer = options.signer,
        .eof = options.eof,
        .clock = options.clock,
        .reader_interface = .{ .vtable = &reader_vtable, .buffer = read_buffer, .seek = 0, .end = 0 },
        .writer_interface = .{ .vtable = &writer_vtable, .buffer = write_buffer },
    };
    errdefer {
        if (options.diagnostics) |report| report.* = session.diagnostics();
        if (options.ech_retry) |out| if (session.conn.echRetryConfigs()) |list| {
            if (gpa.dupe(u8, list)) |copy| {
                out.* = copy;
            } else |_| {}
        };
        session.conn.deinit();
    }
    try session.handshake();
}

/// The native verifier's verdict is reused for an hour at most (design 5.5).
pub const native_max_age: std.Io.Duration = .fromSeconds(60 * 60);

fn resumptionFor(options: Options) ?Connection.Resumption {
    var resumption = options.resumption orelse return null;
    const native = switch (options.trust) {
        .snapshot => |snapshot| snapshot.systemPolicy() != .portable,
        else => false,
    };
    if (native and resumption.max_age.nanoseconds > native_max_age.nanoseconds) resumption.max_age = native_max_age;
    return resumption;
}

/// What a server session needs: the chains it presents and how it treats a client's certificate.
/// Cloak signs with the keys of its credentials; a `signer` covers the ones it does not hold.
pub const ServerOptions = struct {
    credentials: []const Server.Credential,
    /// Required when a credential is an identity cloak holds no signing key for.
    signer: ?Signer = null,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
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
    client_auth: Server.Auth = .none,
    /// How a presented client chain is checked.
    client_trust: Trust = .none,
    client_policy: certificates.types.Policy = .{},
    /// Session tickets to issue and resume from (TLS 1.3, PSK-DHE, never early data). The ring
    /// is shared between sessions and must outlive them; rotate it on the caller's schedule.
    tickets: ?*Connection.TicketKeys = null,
    /// TLS 1.2 session tickets too (RFC 5077), from the same ring: an abbreviated TLS 1.2
    /// handshake reuses the session's master secret with no new key exchange. Off unless asked.
    tls12_tickets: bool = false,
    /// Encrypted Client Hello keys (RFC 9849), borrowed for the life of the session.
    ech_keys: []const @import("handshake/Ech.zig").Key = &.{},
    /// Certificate encoders (RFC 8879) in the server's order of preference; borrowed.
    certificate_compression: []const @import("handshake/Compression.zig").Codec = &.{},
    /// Provisioned keys, looked up by the offered identity (PSK-DHE, TLS 1.3).
    external_psk: ?@import("handshake/Psk.zig").Lookup = null,
    limits: Connection.Limits = .{},
    key_log: ?Connection.KeyLog = null,
    eof: Eof = .strict,
    clock: Clock = .real,
    /// Filled when the handshake fails, since the session is gone by then.
    diagnostics: ?*Diagnostics = null,
};

/// Performs the server handshake over `input` and `output`. The session must stay at this address.
pub fn accept(
    session: *Session,
    gpa: std.mem.Allocator,
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    read_buffer: []u8,
    write_buffer: []u8,
    options: ServerOptions,
) OpenError!void {
    @setRuntimeSafety(true);
    if (options.signer == null) for (options.credentials) |credential| {
        if (credential.identity.noiseLength() == null) return error.SignerRequired;
    };
    const policy: Connection.Verify = switch (options.client_trust) {
        .none => .none,
        .snapshot => |snapshot| .{ .full = .{ .trust_generation = snapshot.generation(), .policy = options.client_policy } },
        .custom => |custom| .{ .full = .{ .trust_generation = custom.generation, .policy = options.client_policy } },
        .raw_keys => |pins| .{ .raw_key = .{ .pins = pins } },
    };
    const conn = try Connection.server(gpa, .{
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .suites = options.suites,
        .min_version = options.min_version,
        .max_version = options.max_version,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .require_pq_auth = options.require_pq_auth,
        .client_auth = options.client_auth,
        .client_verify = policy,
        .tickets = options.tickets,
        .tls12_tickets = options.tls12_tickets,
        .ech_keys = options.ech_keys,
        .certificate_compression = options.certificate_compression,
        .external_psk = options.external_psk,
        .limits = options.limits,
        .key_log = options.key_log,
    });
    session.* = .{
        .gpa = gpa,
        .io = io,
        .conn = conn,
        .input = input,
        .output = output,
        .trust = options.client_trust,
        .signer = options.signer,
        .eof = options.eof,
        .clock = options.clock,
        .reader_interface = .{ .vtable = &reader_vtable, .buffer = read_buffer, .seek = 0, .end = 0 },
        .writer_interface = .{ .vtable = &writer_vtable, .buffer = write_buffer },
    };
    errdefer {
        if (options.diagnostics) |report| report.* = session.diagnostics();
        session.conn.deinit();
    }
    try session.handshake();
}

pub fn deinit(session: *Session) void {
    session.conn.deinit();
    session.* = undefined;
}

/// Negotiated parameters; null once the session failed, which erases what the handshake held.
pub fn info(session: *const Session) ?Connection.Info {
    return session.conn.info();
}

/// Why the connection ended and the alerts that crossed it, after a failure or a close.
pub fn diagnostics(session: *const Session) Diagnostics {
    const seen = session.conn.diagnostics();
    return .{
        .reason = seen.reason,
        .alert_sent = seen.alert_sent,
        .alert_received = seen.alert_received,
        .certificate_requested = session.conn.certificateRequested(),
    };
}

/// Names the `Io` later reads and writes use for entropy and the clock, for a session that
/// outlives the task that opened it. The session itself stays where it is.
/// Whether the peer ended its writing with close_notify. Under `eof = .allow` a bare transport
/// end is also `EndOfStream`; this tells a caller whose framing cannot detect truncation (an
/// HTTP body that runs to the close) whether the end was authenticated.
pub fn closeNotified(session: *const Session) bool {
    return session.conn.readClosed();
}

/// The first failure behind a `ReadFailed` or `WriteFailed` from the reader or the writer.
pub fn failure(session: *const Session) ?anyerror {
    const code = session.failure_code.load(.acquire);
    if (code == 0) return null;
    return @errorFromInt(code);
}

/// Keeps the first failure; a later one, from the other task, does not replace it.
fn noteFailure(session: *Session, err: anyerror) void {
    _ = session.failure_code.cmpxchgStrong(0, @intFromError(err), .acq_rel, .acquire);
}

/// RFC 5705/8446 keying material; see `Connection.exportKeyingMaterial`.
pub fn exportKeyingMaterial(session: *const Session, out: []u8, label: []const u8, context: ?[]const u8) Connection.ExportError!void {
    return session.conn.exportKeyingMaterial(out, label, context);
}

pub fn rebind(session: *Session, io: std.Io) void {
    session.io = io;
}

pub fn reader(session: *Session) *std.Io.Reader {
    return &session.reader_interface;
}

pub fn writer(session: *Session) *std.Io.Writer {
    return &session.writer_interface;
}

// ---------------------------------------------------------------- handshake

fn handshake(session: *Session) OpenError!void {
    @setRuntimeSafety(true);
    session.handshakeLoop() catch |err| {
        // A failed handshake leaves an alert queued; the peer is owed it, best effort.
        if (session.pushOutput()) {} else |push_err| session.noteFailure(push_err);
        return err;
    };
}

fn handshakeLoop(session: *Session) OpenError!void {
    @setRuntimeSafety(true);
    var stalls: usize = 0;
    while (session.conn.phase() == .handshaking) {
        const served = try session.serve();
        const wrote = try session.flushOutput();
        if (wrote) session.output.flush() catch return session.transportFailed(error.WriteFailed);
        if (session.conn.phase() != .handshaking) break;
        if (session.conn.request() != null) continue;
        const data = session.input.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => {
                session.conn.receiveEof() catch |eof_err| return session.transportFailedWith(eof_err);
                return error.EndOfStream;
            },
            error.ReadFailed => return session.transportFailed(error.ReadFailed),
        };
        const n = try session.conn.receive(data);
        session.input.toss(n);
        if (n == 0 and !served and !wrote) {
            stalls += 1;
            if (stalls > 2) return error.Stalled;
        } else stalls = 0;
    }
    _ = try session.flushOutput();
    try session.output.flush();
    // Release the handshake's scratch here, on one task, before two may share the session:
    // `info` reads what it held.
    session.conn.trim();
}

fn transportFailedWith(session: *Session, err: anyerror) error{ReadFailed} {
    session.noteFailure(err);
    return error.ReadFailed;
}

fn transportFailed(session: *Session, err: error{ ReadFailed, WriteFailed }) @TypeOf(err) {
    session.noteFailure(err);
    return err;
}

/// Answers every open request. Returns whether any was answered.
fn serve(session: *Session) OpenError!bool {
    @setRuntimeSafety(true);
    var answered = false;
    while (session.conn.request()) |request| {
        answered = true;
        switch (request.service) {
            .entropy => |len| {
                var bytes: [512]u8 = undefined;
                defer std.crypto.secureZero(u8, &bytes);
                if (len > bytes.len) return error.EntropyUnavailable;
                if (session.io.randomSecure(bytes[0..len])) {
                    try session.conn.provide(request.token, .{ .entropy = bytes[0..len] });
                } else |_| try session.conn.provide(request.token, .entropy_failed);
            },
            .time => try session.conn.provide(request.token, .{ .time = switch (session.clock) {
                .real => std.Io.Clock.real.now(session.io),
                .fixed => |at| at,
            } }),
            .verify => |verify_request| try session.verify(request.token, verify_request),
            .sign => |sign_request| {
                const signer = session.signer orelse {
                    try session.conn.provide(request.token, .signing_failed);
                    continue;
                };
                var signature: [1024]u8 = undefined;
                const len = signer.sign(signer.context, sign_request, &signature) catch {
                    try session.conn.provide(request.token, .signing_failed);
                    continue;
                };
                try session.conn.provide(request.token, .{ .signature = signature[0..len] });
            },
        }
    }
    return answered;
}

fn verify(session: *Session, token: certificates.types.Token, request: certificates.types.Request) OpenError!void {
    @setRuntimeSafety(true);
    const result: VerifyError!certificates.types.Verification = switch (session.trust) {
        // A pinned raw key is checked by the engine and never asks.
        .none, .raw_keys => error.Failed,
        .snapshot => |snapshot| switch (snapshot.systemPolicy()) {
            .portable => certificates.verify.indexed(session.gpa, request, snapshot.issuers()),
            .macos, .windows => session.verifyNative(request, snapshot),
        },
        .custom => |custom| custom.verify(custom.context, session.gpa, request),
    };
    if (result) |verified| {
        var receipt = verified;
        defer receipt.deinit();
        try session.conn.provide(token, .{ .verified = &receipt });
    } else |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        const why: Connection.VerifyFailure = switch (err) {
            error.NoTrustedPath => .untrusted,
            error.InvalidValidity => .expired,
            else => .bad_certificate,
        };
        session.conn.provide(token, .{ .verification_failed = why }) catch |provide_err| switch (provide_err) {
            // The connection reports the rejection as its own failure.
            error.VerificationRejected => return error.VerificationRejected,
            else => return provide_err,
        };
    }
}

/// The system's verdict on `request`, then the portable verifier's over the path the system
/// chose; failing that, a path to one of the snapshot's own roots.
fn verifyNative(session: *Session, request: certificates.types.Request, snapshot: certificates.Trust.Snapshot) VerifyError!certificates.types.Verification {
    @setRuntimeSafety(true);
    const native = session.systemVerdict(request);
    if (native) |receipt| return receipt else |err| {
        if (err == error.OutOfMemory) return error.OutOfMemory;
        if (snapshot.anchors().len != 0) return certificates.verify.indexed(session.gpa, request, snapshot.issuers());
        return switch (err) {
            error.VerificationExpired => error.InvalidValidity,
            else => error.NoTrustedPath,
        };
    }
}

fn systemVerdict(session: *Session, request: certificates.types.Request) (certificates.NativeVerification.InitError || certificates.NativeVerification.TakeError)!certificates.types.Verification {
    @setRuntimeSafety(true);
    // One job at a time, run here: no executor means the system is asked on this task.
    var budget: certificates.services.Budget = .init(.{ .max_jobs = 1 });
    const job = try certificates.NativeVerification.init(session.gpa, &budget, request, .{});
    defer job.deinit();
    const now = switch (session.clock) {
        .real => std.Io.Clock.real.now(session.io),
        .fixed => |at| at,
    };
    return job.take(session.gpa, request, now);
}

/// Moves committed ciphertext to the transport writer. Returns whether any moved.
fn flushOutput(session: *Session) OpenError!bool {
    @setRuntimeSafety(true);
    const pending = session.conn.output();
    if (pending.len == 0) return false;
    session.output.writeAll(pending) catch return session.transportFailed(error.WriteFailed);
    session.conn.acknowledge(pending.len);
    return true;
}

/// Moves committed ciphertext to the transport and flushes it.
fn pushOutput(session: *Session) OpenError!void {
    @setRuntimeSafety(true);
    if (try session.flushOutput()) session.output.flush() catch return session.transportFailed(error.WriteFailed);
}

/// What the read half owes the peer, written by the reading task when the write lock is free;
/// when the writing task holds it, that task writes it (`releaseWrite`).
fn pushOwed(session: *Session) OpenError!void {
    @setRuntimeSafety(true);
    if (!session.write_lock.tryLock()) return;
    defer session.releaseWrite();
    try session.pushOutput();
}

/// Lets the write lock go, then takes it back for what the read half came to owe while it was
/// held: the reader found it held and left it.
fn releaseWrite(session: *Session) void {
    session.write_lock.unlock(session.io);
    while (session.conn.owes()) {
        if (!session.write_lock.tryLock()) return;
        const pushed = session.pushOutput();
        session.write_lock.unlock(session.io);
        pushed catch |err| return session.noteFailure(err);
    }
}

// ---------------------------------------------------------------- reading

const reader_vtable: std.Io.Reader.VTable = .{ .stream = readerStream };

fn fromReader(r: *std.Io.Reader) *Session {
    return @alignCast(@fieldParentPtr("reader_interface", r)); // safe: the interface is a field of a Session, aligned for the Session
}

fn readerStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const session = fromReader(r);
    session.read_lock.lock(session.io) catch |err| {
        session.noteFailure(err);
        return error.ReadFailed;
    };
    defer session.read_lock.unlock(session.io);
    const view = session.plaintext() catch |err| return switch (err) {
        error.EndOfStream => error.EndOfStream,
        else => error.ReadFailed,
    };
    const n = limit.minInt(view.len);
    const written = try w.write(view[0..n]);
    session.conn.consume(written);
    return written;
}

/// Blocks until plaintext is available; a clean close is `EndOfStream`.
fn plaintext(session: *Session) (ReadError || OpenError)![]const u8 {
    @setRuntimeSafety(true);
    while (true) {
        const view = session.conn.readable();
        if (view.len != 0) return view;
        if (session.conn.readClosed()) return error.EndOfStream;
        // About to wait: an idle session holds no record or message buffers.
        session.conn.trim();
        const data = session.input.peekGreedy(1) catch |err| switch (err) {
            error.EndOfStream => {
                if (session.eof == .allow) return error.EndOfStream;
                session.conn.receiveEof() catch |eof_err| return session.remember(eof_err);
                return error.EndOfStream;
            },
            error.ReadFailed => return session.remember(error.ReadFailed),
        };
        const n = session.conn.receive(data) catch |err| {
            // The fatal alert the failure owes the peer.
            session.pushOwed() catch |push_err| return session.remember(push_err);
            return session.remember(err);
        };
        session.input.toss(n);
        _ = session.serve() catch |err| return session.remember(err);
        // A KeyUpdate or a warning the read owes the peer.
        if (session.conn.owes()) session.pushOwed() catch |err| return session.remember(err);
    }
}

fn remember(session: *Session, err: anyerror) error{ReadFailed} {
    session.noteFailure(err);
    return error.ReadFailed;
}

// ---------------------------------------------------------------- writing

const writer_vtable: std.Io.Writer.VTable = .{ .drain = writerDrain, .flush = writerFlush };

fn fromWriter(w: *std.Io.Writer) *Session {
    return @alignCast(@fieldParentPtr("writer_interface", w)); // safe: the interface is a field of a Session, aligned for the Session
}

fn writerDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const session = fromWriter(w);
    session.write_lock.lock(session.io) catch |err| {
        session.noteFailure(err);
        return error.WriteFailed;
    };
    defer session.releaseWrite();
    session.sendAll(w.buffer[0..w.end]) catch return error.WriteFailed;
    w.end = 0;
    var consumed: usize = 0;
    for (data[0 .. data.len - 1]) |slice| {
        session.sendAll(slice) catch return error.WriteFailed;
        consumed += slice.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| {
        session.sendAll(last) catch return error.WriteFailed;
        consumed += last.len;
    }
    return consumed;
}

fn writerFlush(w: *std.Io.Writer) std.Io.Writer.Error!void {
    const session = fromWriter(w);
    session.write_lock.lock(session.io) catch |err| {
        session.noteFailure(err);
        return error.WriteFailed;
    };
    defer session.releaseWrite();
    return session.flushLocked();
}

fn flushLocked(session: *Session) std.Io.Writer.Error!void {
    const w = &session.writer_interface;
    session.sendAll(w.buffer[0..w.end]) catch return error.WriteFailed;
    w.end = 0;
    _ = session.flushOutput() catch |err| {
        session.noteFailure(err);
        return error.WriteFailed;
    };
    session.output.flush() catch return error.WriteFailed;
    // Idle until the next write: no output buffer held.
    session.conn.trimOutput();
}

fn sendAll(session: *Session, bytes: []const u8) !void {
    @setRuntimeSafety(true);
    var rest = bytes;
    while (rest.len != 0) {
        const n = session.conn.send(rest) catch |err| {
            session.noteFailure(err);
            return err;
        };
        if (n == 0) {
            // The output backlog is full: move it to the transport first.
            if (!try session.flushOutput()) return error.Stalled;
            continue;
        }
        rest = rest[n..];
    }
    _ = try session.flushOutput();
}

pub const FinishError = std.Io.Writer.Error || Connection.FinishError || OpenError || std.Io.Cancelable;

pub const KeyUpdateError = Connection.SendError || OpenError || std.Io.Writer.Error || std.Io.Cancelable;

/// New write keys, as the writing task, after what was written so far; with `request_peer` the
/// peer is asked for new keys of its own too. TLS 1.3 only (`NoKeyUpdate` in TLS 1.2).
pub fn keyUpdate(session: *Session, request_peer: bool) KeyUpdateError!void {
    try session.write_lock.lock(session.io);
    defer session.releaseWrite();
    try session.flushLocked();
    try session.conn.keyUpdate(request_peer);
    _ = try session.flushOutput();
    try session.output.flush();
}

/// Sends close_notify and flushes, as the writing task. Reading may continue until the peer
/// closes too.
pub fn finish(session: *Session) FinishError!void {
    try session.write_lock.lock(session.io);
    defer session.releaseWrite();
    try session.flushLocked();
    try session.conn.finish();
    _ = try session.flushOutput();
    try session.output.flush();
}

test {
    _ = @import("Session_test.zig");
    _ = @import("Duplex_test.zig");
}
