//! A TLS client stream over `std.Io` readers and writers. It drives a `Connection`: it
//! answers the engine's requests with the system's entropy and clock and the configured
//! verifier and signer, moves ciphertext between the connection and the transport, and
//! presents plaintext as a `std.Io.Reader` and `std.Io.Writer`.
//!
//! A session is used from one task at a time: the reader and the writer share one
//! connection and are not synchronized. The session stores `io` for the entropy and clock
//! requests and for the adapters' vtables; open it in place and do not move it afterwards.
const std = @import("std");
const certificates = @import("cloak.certificates");
const Connection = @import("Connection.zig");
const Server = @import("handshake/Server.zig");
const Suite = @import("crypto/Suite.zig").Suite;
const Group = @import("crypto/Group.zig").Group;

const Session = @This();

/// How the server certificate is checked.
pub const Trust = union(enum) {
    /// No verification: the connection reports itself unauthenticated.
    none,
    /// The portable verifier over a retained root snapshot.
    snapshot: certificates.Trust.Snapshot,
    /// The caller's verifier, for native or custom policy.
    custom: Custom,
};

pub const Custom = struct {
    context: ?*anyopaque = null,
    generation: certificates.types.TrustGeneration,
    verify: *const fn (context: ?*anyopaque, gpa: std.mem.Allocator, request: certificates.types.Request) VerifyError!certificates.types.Verification,
};

pub const VerifyError = certificates.verify.VerifyError || error{ OutOfMemory, Failed };

/// Signs the CertificateVerify content for the client certificate with its private key.
pub const Signer = struct {
    context: ?*anyopaque = null,
    sign: *const fn (context: ?*anyopaque, scheme: u16, content: []const u8, out: []u8) error{SigningFailed}!usize,
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
    /// A fixed time in seconds, for replay and tests.
    fixed: i64,
};

pub const Options = struct {
    identity: certificates.types.Identity,
    trust: Trust,
    policy: certificates.types.Policy = .{},
    pins: []const [32]u8 = &.{},
    evidence: certificates.types.Evidence = .{},
    server_name: Connection.ServerName = .identity,
    suites: []const Suite = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    auth: ?certificates.ClientAuth = null,
    signer: ?Signer = null,
    limits: Connection.Limits = .{},
    compat: bool = true,
    key_log: ?Connection.KeyLog = null,
    eof: Eof = .strict,
    clock: Clock = .real,
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
/// The last failure behind a `ReadFailed` or `WriteFailed` from an adapter.
failure: ?anyerror = null,
reader_interface: std.Io.Reader,
writer_interface: std.Io.Writer,

/// Performs the handshake over `input` and `output`. The session must stay at this address.
pub fn open(
    session: *Session,
    gpa: std.mem.Allocator,
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    options: Options,
    read_buffer: []u8,
    write_buffer: []u8,
) OpenError!void {
    @setRuntimeSafety(true);
    const policy: Connection.Verify = switch (options.trust) {
        .none => .none,
        .snapshot => |snapshot| .{ .full = .{ .trust_generation = snapshot.generation(), .policy = options.policy, .pins = options.pins, .evidence = options.evidence } },
        .custom => |custom| .{ .full = .{ .trust_generation = custom.generation, .policy = options.policy, .pins = options.pins, .evidence = options.evidence } },
    };
    const conn = try Connection.client(gpa, .{
        .identity = options.identity,
        .verify = policy,
        .server_name = options.server_name,
        .suites = options.suites,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .auth = options.auth,
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
    errdefer session.conn.deinit();
    try session.handshake();
}

/// What a server session needs: the chains it presents, a signer for their keys (cloak holds no
/// signing code; the key stays with the signer), and how it treats a client's certificate.
pub const ServerOptions = struct {
    credentials: []const Server.Credential,
    signer: Signer,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    suites: []const Suite = &.{ .aes_128_gcm_sha256, .chacha20_poly1305_sha256, .aes_256_gcm_sha384 },
    groups: []const Group = &.{ .x25519_mlkem768, .x25519, .p256, .p384 },
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    client_auth: Server.Auth = .none,
    /// How a presented client chain is checked.
    client_trust: Trust = .none,
    client_policy: certificates.types.Policy = .{},
    limits: Connection.Limits = .{},
    key_log: ?Connection.KeyLog = null,
    eof: Eof = .strict,
    clock: Clock = .real,
};

/// Performs the server handshake over `input` and `output`. The session must stay at this address.
pub fn accept(
    session: *Session,
    gpa: std.mem.Allocator,
    io: std.Io,
    input: *std.Io.Reader,
    output: *std.Io.Writer,
    options: ServerOptions,
    read_buffer: []u8,
    write_buffer: []u8,
) OpenError!void {
    @setRuntimeSafety(true);
    const policy: Connection.Verify = switch (options.client_trust) {
        .none => .none,
        .snapshot => |snapshot| .{ .full = .{ .trust_generation = snapshot.generation(), .policy = options.client_policy } },
        .custom => |custom| .{ .full = .{ .trust_generation = custom.generation, .policy = options.client_policy } },
    };
    const conn = try Connection.server(gpa, .{
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .suites = options.suites,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .client_auth = options.client_auth,
        .client_verify = policy,
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
    errdefer session.conn.deinit();
    try session.handshake();
}

pub fn deinit(session: *Session) void {
    session.conn.deinit();
    session.* = undefined;
}

/// Negotiated parameters.
pub fn info(session: *const Session) Connection.Info {
    return session.conn.info().?;
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
}

fn transportFailedWith(session: *Session, err: anyerror) error{ReadFailed} {
    session.failure = err;
    return error.ReadFailed;
}

fn transportFailed(session: *Session, err: error{ ReadFailed, WriteFailed }) @TypeOf(err) {
    session.failure = err;
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
                .real => std.Io.Clock.real.now(session.io).toSeconds(),
                .fixed => |seconds| seconds,
            } }),
            .verify => |verify_request| try session.verify(request.token, verify_request),
            .sign => |sign_request| {
                const signer = session.signer orelse {
                    try session.conn.provide(request.token, .signing_failed);
                    continue;
                };
                var signature: [1024]u8 = undefined;
                const len = signer.sign(signer.context, @backingInt(sign_request.scheme), sign_request.content, &signature) catch {
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
        .none => error.Failed,
        .snapshot => |snapshot| certificates.verify.indexed(session.gpa, request, snapshot.issuers()),
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

// ---------------------------------------------------------------- reading

const reader_vtable: std.Io.Reader.VTable = .{ .stream = readerStream };

fn fromReader(r: *std.Io.Reader) *Session {
    return @fieldParentPtr("reader_interface", r);
}

fn readerStream(r: *std.Io.Reader, w: *std.Io.Writer, limit: std.Io.Limit) std.Io.Reader.StreamError!usize {
    const session = fromReader(r);
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
        session.pushOutput() catch |err| return session.remember(err);
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
            session.pushOutput() catch |push_err| return session.remember(push_err);
            return session.remember(err);
        };
        session.input.toss(n);
        _ = session.serve() catch |err| return session.remember(err);
        session.pushOutput() catch |err| return session.remember(err);
    }
}

fn remember(session: *Session, err: anyerror) error{ReadFailed} {
    session.failure = err;
    return error.ReadFailed;
}

// ---------------------------------------------------------------- writing

const writer_vtable: std.Io.Writer.VTable = .{ .drain = writerDrain, .flush = writerFlush };

fn fromWriter(w: *std.Io.Writer) *Session {
    return @fieldParentPtr("writer_interface", w);
}

fn writerDrain(w: *std.Io.Writer, data: []const []const u8, splat: usize) std.Io.Writer.Error!usize {
    const session = fromWriter(w);
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
    session.sendAll(w.buffer[0..w.end]) catch return error.WriteFailed;
    w.end = 0;
    _ = session.flushOutput() catch |err| {
        session.failure = err;
        return error.WriteFailed;
    };
    session.output.flush() catch return error.WriteFailed;
}

fn sendAll(session: *Session, bytes: []const u8) !void {
    @setRuntimeSafety(true);
    var rest = bytes;
    while (rest.len != 0) {
        const n = session.conn.send(rest) catch |err| {
            session.failure = err;
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

/// Sends close_notify and flushes. Reading may continue until the peer closes too.
pub fn finish(session: *Session) !void {
    try session.writer_interface.flush();
    try session.conn.finish();
    _ = try session.flushOutput();
    try session.output.flush();
}

test {
    _ = @import("Session_test.zig");
}
