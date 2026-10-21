//! A DTLS association of either role, DTLS 1.3 (RFC 9147) or DTLS 1.2 (RFC 6347): the third
//! carrier of the one handshake, beside `Connection`'s stream records and `quic.Handshake`'s
//! levels. The caller hands it whole datagrams with `receive`, sends what `send` writes into its
//! buffer, calls `send` again when `timeout` passes, answers each `request` through `provide`,
//! seals application datagrams with `write` and takes received ones from `read`. It owns the
//! records, epochs, replay windows, message sequence, reassembly, the flight and its
//! retransmission timer and the DTLS 1.3 ACKs; it performs no I/O and keeps no clock: every call
//! that can arm or fire the timer takes the caller's monotonic `now`.
//!
//! Invalid datagrams are dropped, never fatal: a record that does not parse, authenticate or
//! clear the replay window leaves the association, its timer and its handshake as they were. A
//! handshake message that the engine refuses ends the association as in TLS.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const suites = @import("../crypto/Suite.zig");
const Group = @import("../crypto/Group.zig").Group;
const Client = @import("../handshake/Client.zig");
const Server = @import("../handshake/Server.zig");
const Machine = @import("../handshake/Machine.zig");
const Flight = @import("../handshake/Flight.zig");
const Services = @import("../handshake/Services.zig");
const Messages = @import("../handshake/Messages.zig");
const Alert = @import("../wire/Alert.zig").Alert;
const Record = @import("Record.zig");
const RecordLimits = @import("../handshake/RecordLimits.zig");
const Hello = @import("../handshake/Hello.zig");
const Psk = @import("../handshake/Psk.zig");
pub const Admission = @import("Admission.zig");

pub const Suite = suites.Suite;
pub const Version = suites.Version;
pub const Verify = Client.Verify;
pub const Resumption = Client.Resumption;
pub const KeyLog = Client.KeyLog;
pub const Info = Client.Info;
pub const Request = Services.Request;
pub const Answer = Services.Answer;
pub const Service = Services.Service;
pub const VerifyFailure = Services.VerifyFailure;
pub const Credential = Server.Credential;
pub const TicketKeys = Server.TicketKeys;
pub const Srtp = Hello.Srtp;

/// The retransmission timer (RFC 9147 section 5.8.2): the first wait, its doubling cap, and how
/// many retransmissions before the handshake gives up.
pub const Timing = struct {
    initial: std.Io.Duration = .fromSeconds(1),
    max: std.Io.Duration = .fromSeconds(60),
    retransmissions: u8 = 7,
};

pub const Limits = struct {
    handshake: Client.Limits = .{},
    /// Handshake messages buffered ahead of the next expected one, and their bytes.
    incomplete: usize = 16,
    reassembly: usize = 256 * 1024,
    /// The sent flight kept for retransmission.
    flight: usize = 256 * 1024,
};

pub const ServerName = union(enum) {
    identity,
    name: []const u8,
    none,
};

pub const Options = struct {
    identity: types.Identity,
    verify: Verify,
    server_name: ServerName = .identity,
    suites: []const Suite = Suite.default,
    min_version: Version = .tls12,
    max_version: Version = .tls13,
    groups: []const Group = Group.default,
    alpn: []const []const u8 = &.{},
    require_alpn: bool = false,
    require_hybrid: bool = false,
    /// The peer authenticates with ML-DSA, its whole path to the anchor (TLS 1.3); a server
    /// requiring it of clients needs a required, verified client certificate.
    require_pq_auth: bool = false,
    /// What a CertificateRequest is answered with, in this client's order, each with its
    /// delegated credential (RFC 9345): the first the request takes that chains to an authority
    /// it names (RFC 8446 section 4.2.4), else the first; borrowed. At most 32, certificates or
    /// raw keys (RFC 7250) or both, of the type the server selects.
    credentials: []const @import("../handshake/Client.zig").Credential = &.{},
    /// certificate_authorities (RFC 8446 section 4.2.4): the DER Names of the anchors this client
    /// trusts, named in a hello offering TLS 1.3, a server's preference among its credentials;
    /// borrowed. None by default; at most 8 KiB on the wire.
    certificate_authorities: []const []const u8 = &.{},
    /// Take a server's delegated credential (RFC 9345): its key proves possession for the
    /// verified certificate that signed it. TLS 1.3, with full verification.
    accept_delegated: bool = false,
    resumption: ?Resumption = null,
    /// A provisioned key to offer, borrowed: DTLS 1.3 PSK-DHE, or DTLS 1.2 plain PSK with its
    /// suites listed (CoAP's and LwM2M's PSK mode; no forward secrecy).
    external_psk: ?Psk.External = null,
    /// The largest datagram this end sends, without IP and UDP headers.
    mtu: u16 = 1200,
    timing: Timing = .{},
    /// record_size_limit (RFC 8449): the most plaintext a protected record sent to this end may
    /// carry, as the extension counts it (64 to 2^14 + 1; TLS 1.3 counts the inner content type).
    /// Always offered; null names the version's maximum. Records are held to it only when the
    /// server answers the extension; the peer's bounds this end's records; both stand beside the MTU to the limit the peer names.
    record_size_limit: ?u16 = null,
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
    /// Connection IDs (RFC 9146; RFC 9147 section 9): null offers none; otherwise the connection
    /// ID this end receives records with, borrowed for the association's life, at most 255
    /// bytes. Empty: this end puts the server's on its records but takes none. Records carry
    /// them only when the server answers.
    connection_id: ?[]const u8 = null,
    /// use_srtp (RFC 5764), for WebRTC: the SRTP profiles offered in preference order. The one
    /// the server chose is `Info.srtp`, keyed by `srtpKeys`.
    srtp: []const Srtp = &.{},
};

pub const ServerOptions = struct {
    credentials: []const Credential,
    unknown_name: @FieldType(Server.Options, "unknown_name") = .first,
    suites: []const Suite = Suite.default,
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
    client_verify: Verify = .none,
    /// certificate_authorities (RFC 8446 section 4.2.4; RFC 5246 section 7.4.4 in TLS 1.2): the
    /// DER Names of the client anchors every CertificateRequest names, a client's preference
    /// among its credentials; borrowed. None by default; at most 8 KiB on the wire.
    certificate_authorities: []const []const u8 = &.{},
    /// Take a client's delegated credential (RFC 9345): TLS 1.3, a client certificate asked for
    /// and fully verified.
    accept_delegated: bool = false,
    tickets: ?*TicketKeys = null,
    tls12_tickets: bool = false,
    /// Provisioned keys, looked up by the offered identity: DTLS 1.3 PSK-DHE, DTLS 1.2 plain PSK
    /// when its suites are listed. With them a server needs no credential.
    external_psk: ?Psk.Lookup = null,
    mtu: u16 = 1200,
    timing: Timing = .{},
    /// record_size_limit (RFC 8449), answered to a client that offers one: the most plaintext a
    /// protected record sent to this server may carry, as the extension counts it (64 to
    /// 2^14 + 1). Null names the version's maximum. The client's own limit bounds every record
    /// this server seals for it.
    record_size_limit: ?u16 = null,
    limits: Limits = .{},
    key_log: ?KeyLog = null,
    generation: types.ConnectionGeneration = .fromRaw(0),
    /// Connection IDs: null answers none; otherwise the connection ID this server receives
    /// records with when the client offers connection IDs, borrowed for the association's life,
    /// at most 255 bytes (the caller finds the association by it: `connectionIdOf`). Empty:
    /// this server puts the client's on its records but takes none.
    connection_id: ?[]const u8 = null,
    /// use_srtp: the SRTP profiles accepted in preference order; the first the client offered is
    /// chosen (`Info.srtp`). A client offering none of them gets no use_srtp answer.
    srtp: []const Srtp = &.{},
};

pub const Phase = enum(u8) { handshaking, connected, closed, failed };

pub const InitError = Client.InitError || error{InvalidOptions};
pub const Error = Client.Error || Record.SealError || error{
    PeerAlert,
    HandshakeTimeout,
    FlightLimit,
    Closed,
    NotConnected,
    /// A key failed to open as many records as its AEAD allows (RFC 9147 section 4.5.3).
    ForgeryLimit,
    /// A key update is still waiting for its acknowledgement.
    UpdatePending,
    /// A NewConnectionId or RequestConnectionId of this end still waits for its acknowledgement,
    /// or a request for connection IDs for its answer (RFC 9147 section 9).
    ConnectionIdPending,
    /// Connection IDs were not agreed, or not in the direction asked for, or one handed out
    /// differs in length from this end's own (the length its records are parsed by).
    NoConnectionIds,
    /// The peer asked for connection IDs while its last request was still unanswered.
    TooManyConnectionIdsRequested,
};
pub const ProvideError = Error || error{ StaleToken, NoRequest };
pub const SrtpError = error{ NotConnected, NoSrtp };

const Datagram = @This();

const min_mtu = 256;
const max_mtu = 16 * 1024;
/// Records of application data `receive` holds for `read` per call.
const max_readable = 32;
/// Spare connection IDs kept from the peer; more are discarded (RFC 9147 section 9).
const max_spare_cids = 4;
/// A NewConnectionId hands out at most this many.
pub const max_new_cids = 8;

/// A sent message or ChangeCipherSpec, kept until the peer's answer or ACK covers it.
const Sent = struct {
    kind: enum { message, ccs },
    sequence: u16 = 0,
    /// The record epoch it went out under: 0, 1 (DTLS 1.2) or 2 and up (DTLS 1.3).
    epoch: u64,
    /// The message in its TLS form: type, 24-bit length, body.
    bytes: []u8 = &.{},
    /// Bytes of the body this transmission has sent, and whether it has more (or, for an empty
    /// message, its one fragment) to send.
    cursor: usize = 0,
    pending: bool = true,
    acked: bool = false,
    /// DTLS 1.3: one bit per body byte an ACK covered, allocated at the first partial ACK.
    covered: []u8 = &.{},
};

/// What a flight is (RFC 9147 section 5.8.4): the handshake's, or one post-handshake message's,
/// each with a state machine of its own that no other kind interrupts.
const Category = enum { handshake, ticket, key_update, new_cid, request_cid };

/// A flight this end sent, kept until the peer's answer or ACK covers it: its messages, its
/// retransmission timer and its place among the records ACKs name.
const Outgoing = struct {
    category: Category,
    entries: std.ArrayList(Sent) = .empty,
    bytes: usize = 0,
    /// The flight goes out now: `send` writes its fragments.
    transmitting: bool = true,
    deadline: ?std.Io.Timestamp = null,
    backoff: std.Io.Duration,
    retransmissions: u8 = 0,
    /// An ACK made this flight go again before its timer did: at most once a timer period.
    early: bool = false,
    /// Tells this flight from an earlier one in the same slot.
    generation: u32,

    fn done(self: *const Outgoing) bool {
        for (self.entries.items) |entry| if (!entry.acked) return false;
        return true;
    }

    fn sent(self: *const Outgoing) bool {
        for (self.entries.items) |entry| if (!entry.acked and entry.pending) return false;
        return true;
    }
};

/// The handshake's flight, two tickets, and one each of KeyUpdate, NewConnectionId and
/// RequestConnectionId.
const max_flights = 6;

/// Which fragment a sent record carried, for the ACKs that name records (RFC 9147 section 7).
const Sent_record = struct { epoch: u64, sequence: u64, slot: u8, generation: u32, entry: u16, offset: u32, len: u32 };

/// A handshake message being reassembled, held as the TLS-form message.
const Partial = struct {
    sequence: u16,
    kind: u8,
    epoch: u64,
    /// Type and length header, then the body.
    buf: []u8,
    /// One bit per body byte received.
    have: []u8,
    received: usize = 0,

    fn total(self: *const Partial) usize {
        return self.buf.len - 4;
    }
};

const Readable = struct { bytes: []u8 };

gpa: std.mem.Allocator,
hs: Machine,
services: Services,
role: Machine.Role,
mtu: u16,
timing: Timing,
limits: Limits,
/// RFC 8449: what protected records may carry each way, as the handshake negotiated; beside the
/// MTU, which bounds whole datagrams.
record_limits: RecordLimits = .{},
phase_now: Phase = .handshaking,
failure_now: ?Error = null,
alert_sent: ?Alert = null,
alert_received: ?Alert = null,
negotiated: ?Info = null,
// Records.
/// The next record sequence of epoch 0.
plain_sequence: u64 = 0,
/// Write and read epochs, keyed by their number; at most a handshake epoch and two application
/// epochs live at once.
writers: [3]?Record.Epoch = @splat(null),
readers: [3]?Record.Epoch = @splat(null),
/// The epoch new handshake messages and application data go out under.
write_current: u64 = 0,
// Handshake messages.
send_sequence: u16 = 0,
receive_sequence: u16 = 0,
partials: std.ArrayList(Partial) = .empty,
partial_bytes: usize = 0,
/// The flights this side sent, kept for retransmission, and their bytes together.
flights: [max_flights]?Outgoing = @splat(null),
flight_bytes: usize = 0,
generations: u32 = 0,
/// The peer's first message_seq of the flight answering ours (RFC 9147 section 5.8.1): a message
/// below it is one our flight answered, one from it on answers ours.
answer_from: u16 = 0,
/// Part of the peer's answer to our flight arrived. The timer runs on until the whole answer has
/// made the engine speak again (or the handshake ends); then our flight is done.
answered: bool = false,
/// The peer's ChangeCipherSpec (DTLS 1.2) arrived before the message preceding it.
ccs_waiting: bool = false,
/// DTLS 1.3: records of the peer's handshake flight to acknowledge, and whether an ACK is due.
acks: std.ArrayList([2]u64) = .empty,
ack_due: bool = false,
/// DTLS 1.3: records arrived under keys this end does not hold yet: an ACK of nothing tells the
/// peer to send its flight again (RFC 9147 section 7.1).
empty_ack_due: bool = false,
/// A handshake record joined `acks` in the datagram being received.
acked_now: bool = false,
/// The records the flights went out in, newest last, for the peer's ACKs to name.
sent_records: [64]Sent_record = undefined,
sent_records_len: usize = 0,
sent_records_at: usize = 0,
/// The server has taken the client's first hello: its message_seq numbers the handshake.
started: bool = false,
/// The peer's address is proven (a cookie, a path validated otherwise, or its handshake keys);
/// until then a server sends at most three times what it received (RFC 9147 section 5.1).
validated: bool = true,
received_bytes: usize = 0,
sent_bytes: usize = 0,
// Application data.
readable: [max_readable]Readable = undefined,
readable_len: usize = 0,
readable_at: usize = 0,
close_due: bool = false,
fatal_due: ?Alert = null,
// Connection IDs.
/// The one this end receives with, when it offered or answers connection IDs.
own_cid: [Record.max_cid]u8 = undefined,
own_cid_len: u8 = 0,
/// The peer's, which records this end sends carry, once the hellos agreed on connection IDs.
peer_cid: [Record.max_cid]u8 = undefined,
peer_cid_len: u8 = 0,
cids_agreed: bool = false,
/// Whether the hellos' agreement has been read from the engine (at the first keys).
cids_known: bool = false,
/// The newest authenticated record, by epoch and sequence, and whether the last `receive`
/// brought one newer still (RFC 9146 section 6).
newest: ?[2]u64 = null,
received_newest: bool = false,
/// DTLS 1.3: connection IDs the peer handed out for later use, oldest first.
spare_cids: [max_spare_cids][Record.max_cid]u8 = undefined,
spare_cid_lens: [max_spare_cids]u8 = undefined,
spare_cid_count: u8 = 0,
/// Connection IDs the peer asked for and was not given yet.
cids_requested: u8 = 0,
/// This end's RequestConnectionId is unanswered.
cid_request_open: bool = false,

pub fn client(gpa: std.mem.Allocator, options: Options) InitError!Datagram {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    try checkCommon(options.mtu, options.timing);
    const sni: []const u8 = switch (options.server_name) {
        .identity => switch (options.identity) {
            .dns => |name| name,
            else => "",
        },
        .name => |name| name,
        .none => "",
    };
    const hs = try Client.init(gpa, .{
        .hello = .{
            .transport = .datagram,
            .suites = options.suites,
            .min_version = options.min_version,
            .max_version = options.max_version,
            .groups = options.groups,
            .sni = sni,
            .alpn = options.alpn,
            .require_alpn = options.require_alpn,
            .require_hybrid = options.require_hybrid,
            .require_pq_auth = options.require_pq_auth,
            .accept_delegated = options.accept_delegated,
            .certificate_authorities = options.certificate_authorities,
            .connection_id = options.connection_id,
            .srtp = options.srtp,
            .record_size_limit = options.record_size_limit,
        },
        .resumption = options.resumption,
        .external_psk = options.external_psk,
        .identity = options.identity,
        .verify = options.verify,
        .credentials = options.credentials,
        .limits = options.limits.handshake,
        .compat = false,
        .key_log = options.key_log,
        .generation = options.generation,
    });
    var self: Datagram = .{
        .gpa = gpa,
        .hs = Machine.forClient(hs),
        .services = .init(options.generation),
        .role = .client,
        .mtu = options.mtu,
        .timing = options.timing,
        .limits = options.limits,
    };
    self.keepOwnCid(options.connection_id);
    return self;
}

/// A server association for a client `Cookies.check` admitted, or one on a path validated
/// otherwise (`.{}`). With no admission the address is unproven: the association answers at most
/// three times the bytes it received until the client's handshake keys prove it.
pub fn server(gpa: std.mem.Allocator, options: ServerOptions, admission: ?Admission) InitError!Datagram {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    try checkCommon(options.mtu, options.timing);
    const hs = try Server.init(gpa, .{
        .transport = .datagram,
        .suites = options.suites,
        .min_version = options.min_version,
        .max_version = options.max_version,
        .groups = options.groups,
        .alpn = options.alpn,
        .require_alpn = options.require_alpn,
        .require_hybrid = options.require_hybrid,
        .require_pq_auth = options.require_pq_auth,
        .credentials = options.credentials,
        .unknown_name = options.unknown_name,
        .client_auth = options.client_auth,
        .client_verify = options.client_verify,
        .certificate_authorities = options.certificate_authorities,
        .accept_delegated = options.accept_delegated,
        .tickets = options.tickets,
        .tls12_tickets = options.tls12_tickets,
        .external_psk = options.external_psk,
        .limits = options.limits.handshake,
        .key_log = options.key_log,
        .generation = options.generation,
        .connection_id = options.connection_id,
        .srtp = options.srtp,
        .record_size_limit = options.record_size_limit,
    });
    var self: Datagram = .{
        .gpa = gpa,
        .hs = .{ .state = .{ .server = hs } },
        .services = .init(options.generation),
        .role = .server,
        .mtu = options.mtu,
        .timing = options.timing,
        .limits = options.limits,
        .validated = admission != null,
    };
    errdefer self.hs.deinit();
    self.keepOwnCid(options.connection_id);
    if (admission) |admitted| if (admitted.retry) |*retry| {
        // The association starts where the stateless retry request left the handshake.
        var buffer: [256]u8 = undefined;
        const hrr = Hello.buildRetry(&buffer, .datagram, "", retry.suite, if (retry.asked) retry.group else null, retry.cookieBytes(), false) catch return error.InvalidOptions;
        self.hs.resumeRetry(retry.suite, retry.group, retry.helloHash(), retry.fingerprint, hrr) catch return error.InvalidOptions;
    };
    return self;
}

/// The engine validated the option: at most 255 bytes.
fn keepOwnCid(self: *Datagram, cid: ?[]const u8) void {
    const own = cid orelse return;
    @memcpy(self.own_cid[0..own.len], own);
    self.own_cid_len = @intCast(own.len); // safe: validated at 255 bytes
}

fn checkCommon(mtu: u16, timing: Timing) InitError!void {
    if (mtu < min_mtu or mtu > max_mtu) return error.InvalidOptions;
    if (timing.initial.nanoseconds <= 0 or timing.max.nanoseconds < timing.initial.nanoseconds) return error.InvalidOptions;
}

pub fn deinit(self: *Datagram) void {
    @setRuntimeSafety(true);
    for (&self.writers) |*slot| if (slot.*) |*e| e.deinit();
    for (&self.readers) |*slot| if (slot.*) |*e| e.deinit();
    self.dropPartials();
    self.partials.deinit(self.gpa);
    self.dropFlights();
    self.acks.deinit(self.gpa);
    self.hs.deinit();
    self.* = undefined;
}

pub fn phase(self: *const Datagram) Phase {
    return self.phase_now;
}

/// The first failure, if the association failed.
pub fn failure(self: *const Datagram) ?Error {
    return self.failure_now;
}

pub fn alerts(self: *const Datagram) struct { sent: ?Alert, received: ?Alert } {
    return .{ .sent = self.alert_sent, .received = self.alert_received };
}

/// What the handshake negotiated; null before it completes and after a failure.
pub fn info(self: *const Datagram) ?Info {
    if (self.phase_now == .failed) return null;
    return self.negotiated;
}

pub fn exportKeyingMaterial(self: *const Datagram, out: []u8, label: []const u8, context: ?[]const u8) Client.ExportError!void {
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now == .failed) return error.WrongPhase;
    return self.hs.exportKeyingMaterial(out, label, context);
}

pub const ConnectionIds = struct {
    /// The one this end's records arrive with, by which the caller finds the association.
    receive: []const u8,
    /// The peer's, which this end's records carry.
    send: []const u8,
};

/// The connection IDs the hellos agreed on (RFC 9146), either of them possibly empty; null when
/// they agreed on none, or before the hellos. Records under keys carry them.
pub fn connectionIds(self: *const Datagram) ?ConnectionIds {
    if (!self.cids_agreed) return null;
    return .{ .receive = self.own_cid[0..self.own_cid_len], .send = self.peer_cid[0..self.peer_cid_len] };
}

/// The connection ID on the first record of a received datagram, for finding its association
/// before any `receive`: `length` is the length of the connection IDs this end hands out (each
/// association's own, which a deployment keeps fixed, since a record does not say it). Null for
/// a datagram whose first record carries none (a hello, a record of a connection without
/// connection IDs) or that is too short.
pub fn connectionIdOf(datagram: []const u8, length: usize) ?[]const u8 {
    @setRuntimeSafety(true);
    if (datagram.len == 0 or length == 0 or length > Record.max_cid) return null;
    const first = datagram[0];
    if (first == Record.tls12_cid) {
        if (datagram.len < Record.header12 + length) return null;
        return datagram[11..][0..length];
    }
    // DTLS 1.3's unified header with its C bit (RFC 9147 section 4).
    if (first & 0xe0 == 0x20 and first & 0x10 != 0) {
        if (datagram.len < 1 + length) return null;
        return datagram[1..][0..length];
    }
    return null;
}

/// Whether the last `receive` authenticated a record newer, by epoch and sequence, than every
/// record before it: with connection IDs, the condition on which a caller may follow the peer to
/// the address that datagram came from, once its own check shows the address can answer (RFC
/// 9146 section 6). A replayed or reordered datagram never qualifies.
pub fn receivedNewest(self: *const Datagram) bool {
    return self.received_newest;
}

/// Keys for SRTP (RFC 5764 section 4.2): the master keys and salts of the profile use_srtp
/// agreed (`Info.srtp`), from the "EXTRACTOR-dtls_srtp" exporter. The caller erases them with
/// `deinit`.
pub fn srtpKeys(self: *const Datagram) SrtpError!SrtpKeys {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now != .connected) return error.NotConnected;
    const profile = (self.negotiated orelse return error.NotConnected).srtp orelse return error.NoSrtp;
    var keys: SrtpKeys = .{ .profile = profile, .material = .init(@splat(0)), .client = self.role == .client };
    const len = 2 * (keyLength(profile) + saltLength(profile));
    // No context: in DTLS 1.2 that differs from an empty one (RFC 5764 section 4.2, RFC 5705).
    self.hs.exportKeyingMaterial(keys.material.exposeMut()[0..len], "EXTRACTOR-dtls_srtp", null) catch {
        keys.deinit();
        return error.NotConnected;
    };
    return keys;
}

/// SRTP master keys and salts for both directions (RFC 5764 section 4.2). The slices borrow
/// this value until `deinit`.
pub const SrtpKeys = struct {
    profile: Srtp,
    /// The exporter's output: the client's key, the server's key, the client's salt, the
    /// server's salt.
    material: aegis.Secret([2 * (32 + 14)]u8),
    /// This end is the client.
    client: bool,

    /// The key and salt this end protects its SRTP and SRTCP with.
    pub fn localKey(self: *const SrtpKeys) []const u8 {
        return self.part(.key, self.client);
    }
    pub fn localSalt(self: *const SrtpKeys) []const u8 {
        return self.part(.salt, self.client);
    }
    /// The key and salt the peer's packets are checked and opened with.
    pub fn remoteKey(self: *const SrtpKeys) []const u8 {
        return self.part(.key, !self.client);
    }
    pub fn remoteSalt(self: *const SrtpKeys) []const u8 {
        return self.part(.salt, !self.client);
    }

    fn part(self: *const SrtpKeys, which: enum { key, salt }, client_side: bool) []const u8 {
        const key = keyLength(self.profile);
        const salt = saltLength(self.profile);
        const bytes = self.material.expose();
        return switch (which) {
            .key => bytes[if (client_side) 0 else key..][0..key],
            .salt => bytes[2 * key + if (client_side) 0 else salt ..][0..salt],
        };
    }

    pub fn deinit(self: *SrtpKeys) void {
        self.material.deinit();
    }
};

// A negotiated profile is one this end listed, and options list only profiles cloak keys for.
fn keyLength(profile: Srtp) usize {
    return profile.keyLength() orelse aegis.assert.never("a negotiated SRTP profile is one cloak keys for");
}
fn saltLength(profile: Srtp) usize {
    return profile.saltLength() orelse aegis.assert.never("a negotiated SRTP profile is one cloak keys for");
}
/// The DTLS version, once the hellos chose it.
fn dtls13(self: *const Datagram) bool {
    return self.hs.version() == .tls13;
}

// ---------------------------------------------------------------- services

pub fn request(self: *Datagram) ?Request {
    if (self.phase_now == .failed) return null;
    return self.services.request(self.hs);
}

pub fn provide(self: *Datagram, token: types.Token, answer: Answer) ProvideError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now == .failed) return error.Closed;
    self.services.answer(self.hs, token, answer) catch |err| switch (err) {
        error.InvalidEntropy, error.StaleToken, error.NoRequest => |open| return open,
        else => |fatal| return self.fail(fatal),
    };
    self.pump() catch |err| return self.fail(err);
}

fn fail(self: *Datagram, err: Error) Error {
    @setRuntimeSafety(true);
    if (self.phase_now == .failed) return err;
    self.failure_now = err;
    if (err != error.PeerAlert and err != error.HandshakeTimeout and err != error.Closed) {
        self.fatal_due = switch (err) {
            error.FlightLimit => .internal_error,
            error.TooManyConnectionIdsRequested => .too_many_cids_requested,
            else => self.services.alertFor(err),
        };
    }
    self.phase_now = .failed;
    self.hs.wipe();
    // The read keys go now; the write keys once the fatal alert went out under them.
    eraseAll(&self.readers);
    if (self.fatal_due == null) eraseAll(&self.writers);
    self.dropPartials();
    self.dropFlights();
    return err;
}

// ---------------------------------------------------------------- the engine

/// Delivers buffered complete messages in order, then moves the engine's outputs into the flight
/// and the key slots, until the engine waits on a service or on the peer.
fn pump(self: *Datagram) Error!void {
    @setRuntimeSafety(true);
    while (true) {
        try self.drainEngine();
        if (self.phase_now == .failed) return;
        if (self.hs.need() != .none or self.hs.pending()) return;
        if (self.ccs_waiting and self.hs.awaitingCcs()) {
            self.ccs_waiting = false;
            try self.hs.receiveCcs();
            continue;
        }
        if (!try self.deliverNext()) return;
    }
}

/// Hands the engine the next message if it is complete.
fn deliverNext(self: *Datagram) Error!bool {
    @setRuntimeSafety(true);
    const index = for (self.partials.items, 0..) |p, i| {
        if (p.sequence == self.receive_sequence) break i;
    } else return false;
    const partial = &self.partials.items[index];
    if (partial.received != partial.total()) return false;
    const taken = self.partials.orderedRemove(index);
    defer self.freePartial(taken);
    self.receive_sequence +%= 1;
    // The connection-ID messages are the carrier's: the engine never sees them.
    if (taken.kind == request_connection_id or taken.kind == new_connection_id) {
        try self.onCidMessage(taken.kind, taken.buf[4..], taken.epoch);
        return true;
    }
    // A DTLS 1.3 server ACKs the client's final flight, and either side a post-handshake message.
    try self.hs.receive(taken.buf, self.engineEpoch(taken.epoch), true);
    return true;
}

/// The engine's epoch of a record epoch: plaintext, handshake keys, application keys.
fn engineEpoch(self: *const Datagram, epoch: u64) Flight.Epoch {
    if (epoch == 0) return .initial;
    if (!self.dtls13()) return .application;
    return if (epoch == 2) .handshake else .application;
}

fn drainEngine(self: *Datagram) Error!void {
    @setRuntimeSafety(true);
    var emit: Flight.Emit = undefined;
    while (self.hs.pop(&emit)) {
        defer Flight.eraseEmit(&emit);
        switch (emit) {
            .message => |m| try self.queueMessage(m.epoch, self.hs.flightBytes(m.start, m.len)),
            .secret => |*s| try self.installSecret(s.direction, s.epoch, &s.traffic),
            .keys12 => |*k| try self.install12(k.direction, &k.keys),
            .change_cipher_spec => try self.queue(.{ .kind = .ccs, .epoch = 0 }, .handshake),
            .compat_ccs => return error.UnexpectedMessage,
            .key_update => |u| try self.onPeerKeyUpdate(u.request_peer),
            .ticket => {},
            .record_limits => |limits| self.record_limits = limits,
            .refuse_renegotiation => {},
            // Post-handshake authentication is a stream's: a datagram never offers or keeps it.
            .auth_response, .auth_finished => return error.UnexpectedMessage,
            .complete => {
                self.hs.settle();
                self.negotiated = self.hs.info();
                self.phase_now = .connected;
            },
        }
    }
    self.hs.recycle();
}

/// The hellos' agreement on connection IDs, read from the engine when the first keys arrive: the
/// hellos are processed by then, and no record before them carries a connection ID.
fn learnCids(self: *Datagram) void {
    @setRuntimeSafety(true);
    if (self.cids_known) return;
    self.cids_known = true;
    const peer = self.hs.peerConnectionId() orelse return;
    @memcpy(self.peer_cid[0..peer.len], peer);
    self.peer_cid_len = @intCast(peer.len); // safe: a vector<0..255>
    self.cids_agreed = true;
}

/// The connection ID this end's protected records carry: the peer's, when agreed.
fn sendCid(self: *const Datagram) []const u8 {
    return if (self.cids_agreed) self.peer_cid[0..self.peer_cid_len] else "";
}

/// The length of the connection ID the peer's protected records carry: this end's own.
fn receiveCidLen(self: *const Datagram) usize {
    return if (self.cids_agreed) self.own_cid_len else 0;
}

fn installSecret(self: *Datagram, direction: Flight.Direction, epoch: Flight.Epoch, traffic: *const Flight.Traffic) Error!void {
    @setRuntimeSafety(true);
    self.learnCids();
    const number: u64 = switch (epoch) {
        .initial => unreachable, // the engine installs no plaintext keys
        .handshake => 2,
        .application => 3,
    };
    switch (direction) {
        .read => claim(&self.readers, number).init13(traffic.suite, number, traffic.secret.expose()[0..traffic.len]),
        .write => {
            claim(&self.writers, number).init13(traffic.suite, number, traffic.secret.expose()[0..traffic.len]);
            // Application data waits for the application epoch; the handshake epoch carries the
            // rest of the flight until then.
            if (number > self.write_current) self.write_current = number;
        },
    }
}

fn install12(self: *Datagram, direction: Flight.Direction, keys: *const Flight.Keys12) Error!void {
    @setRuntimeSafety(true);
    self.learnCids();
    switch (direction) {
        .read => claim(&self.readers, 1).init12(keys.cipher, keys.keyBytes(), keys.ivBytes()),
        .write => {
            claim(&self.writers, 1).init12(keys.cipher, keys.keyBytes(), keys.ivBytes());
            self.write_current = 1;
        },
    }
}

/// The slot epoch `number` is made in: a free one, the one holding that number, or the oldest
/// epoch's; an epoch held there is erased first. Epochs are never copied out of their slots.
fn claim(slots: *[3]?Record.Epoch, number: u64) *Record.Epoch {
    const index = for (slots, 0..) |*slot, i| {
        const held = if (slot.*) |*held| held else break i;
        if (held.number == number) break i;
    } else oldest: {
        var oldest: usize = 0;
        for (slots, 0..) |*slot, i| if (slot.*.?.number < slots[oldest].?.number) {
            oldest = i;
        };
        break :oldest oldest;
    };
    if (slots[index]) |*held| held.deinit();
    slots[index] = @as(Record.Epoch, undefined);
    return &slots[index].?;
}

fn eraseAll(slots: *[3]?Record.Epoch) void {
    for (slots) |*slot| if (slot.*) |*e| {
        e.deinit();
        slot.* = null;
    };
}

fn find(slots: *[3]?Record.Epoch, number: u64) ?*Record.Epoch {
    for (slots) |*slot| if (slot.*) |*e| if (e.number == number) return e;
    return null;
}

fn onPeerKeyUpdate(self: *Datagram, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    // The next read epoch joins the current one, which stays until a record opens under the new.
    const current = self.highestRead() orelse return error.UnexpectedMessage;
    current.next(claim(&self.readers, current.number + 1));
    // A request while our own update is still unacknowledged is answered by that one.
    if (request_peer) self.keyUpdate(false) catch |err| switch (err) {
        error.UpdatePending => {},
        else => |e| return e,
    };
}

fn highestRead(self: *Datagram) ?*Record.Epoch {
    var best: ?*Record.Epoch = null;
    for (&self.readers) |*slot| if (slot.*) |*e| {
        if (best == null or e.number > best.?.number) best = e;
    };
    return best;
}

/// The engine's message joins a flight under the epoch it names: the handshake's, or in DTLS 1.3
/// a NewSessionTicket's own.
fn queueMessage(self: *Datagram, epoch: Flight.Epoch, message: []const u8) Error!void {
    @setRuntimeSafety(true);
    const number: u64 = switch (epoch) {
        .initial => 0,
        .handshake => 2,
        .application => if (self.dtls13()) self.write_current else 1,
    };
    // DTLS 1.2's NewSessionTicket is part of the server's handshake flight (RFC 5077).
    const category: Category = if (self.dtls13() and message[0] == 4) .ticket else .handshake;
    try self.queueOwn(category, number, message);
}

/// Copies `message` into a new entry of a flight of `category` under record epoch `epoch`.
fn queueOwn(self: *Datagram, category: Category, epoch: u64, message: []const u8) Error!void {
    @setRuntimeSafety(true);
    const bytes = try self.gpa.dupe(u8, message);
    errdefer {
        std.crypto.secureZero(u8, bytes);
        self.gpa.free(bytes);
    }
    try self.queue(.{ .kind = .message, .epoch = epoch, .bytes = bytes, .sequence = self.send_sequence }, category);
    self.send_sequence +%= 1;
}

fn queue(self: *Datagram, entry: Sent, category: Category) Error!void {
    @setRuntimeSafety(true);
    const flight = switch (category) {
        .handshake => blk: {
            if (self.flightOf(.handshake)) |held| {
                // Output after the peer spoke, or after our last flight was done with, starts a
                // new flight: the old one is acknowledged by it.
                if (!self.answered and self.receive_sequence == self.answer_from and !held.done()) break :blk held;
                self.dropFlight(held);
            }
            self.answered = false;
            // A handshake flight acknowledges the peer's before it implicitly (RFC 9147 section 7.1).
            if (self.phase_now == .handshaking) self.acks.clearRetainingCapacity();
            break :blk try self.openFlight(.handshake);
        },
        // Each post-handshake message is a flight of its own (RFC 9147 section 5.8.4).
        else => try self.openFlight(category),
    };
    if (self.flight_bytes + entry.bytes.len > self.limits.flight) {
        if (flight.entries.items.len == 0) self.dropFlight(flight);
        return error.FlightLimit;
    }
    try flight.entries.append(self.gpa, entry);
    flight.bytes += entry.bytes.len;
    self.flight_bytes += entry.bytes.len;
    flight.transmitting = true;
    flight.deadline = null;
    // The peer's answer to this flight starts at the message it sends next.
    if (category == .handshake) self.answer_from = self.receive_sequence;
}

fn flightOf(self: *Datagram, category: Category) ?*Outgoing {
    for (&self.flights) |*slot| if (slot.*) |*flight| if (flight.category == category) return flight;
    return null;
}

fn openFlight(self: *Datagram, category: Category) Error!*Outgoing {
    for (&self.flights) |*slot| if (slot.* == null) {
        self.generations +%= 1;
        slot.* = .{ .category = category, .backoff = self.timing.initial, .generation = self.generations };
        return &slot.*.?;
    };
    return error.FlightLimit;
}

fn slotOf(self: *const Datagram, flight: *const Outgoing) u8 {
    for (&self.flights, 0..) |*slot, i| if (slot.*) |*held| if (held == flight) return @intCast(i);
    unreachable; // every flight lives in a slot
}

fn dropFlight(self: *Datagram, flight: *Outgoing) void {
    for (flight.entries.items) |entry| {
        if (entry.bytes.len != 0) {
            std.crypto.secureZero(u8, entry.bytes);
            self.gpa.free(entry.bytes);
        }
        if (entry.covered.len != 0) self.gpa.free(entry.covered);
    }
    flight.entries.deinit(self.gpa);
    self.flight_bytes -= flight.bytes;
    self.flights[self.slotOf(flight)] = null;
}

fn dropFlights(self: *Datagram) void {
    for (&self.flights) |*slot| if (slot.*) |*flight| self.dropFlight(flight);
}

/// A flight is being written by `send`.
fn transmitting(self: *const Datagram) bool {
    for (self.flights) |slot| if (slot) |flight| if (flight.transmitting) return true;
    return false;
}

fn dropPartials(self: *Datagram) void {
    for (self.partials.items) |p| self.freePartial(p);
    self.partials.clearRetainingCapacity();
}

fn freePartial(self: *Datagram, p: Partial) void {
    std.crypto.secureZero(u8, p.buf);
    self.gpa.free(p.buf);
    self.gpa.free(p.have);
    self.partial_bytes -= p.buf.len + p.have.len;
}

// ---------------------------------------------------------------- receiving

/// Processes one datagram from the peer, in place: its records are opened in `datagram`, and the
/// application data `read` returns points into it until the next `receive`.
pub fn receive(self: *Datagram, datagram: []u8, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now == .failed or self.phase_now == .closed) return error.Closed;
    self.readable_len = 0;
    self.readable_at = 0;
    self.received_bytes +|= datagram.len;
    self.acked_now = false;
    self.received_newest = false;
    const connected_before = self.phase_now == .connected;
    var rest = datagram;
    while (Record.split(rest, self.receiveCidLen())) |next| {
        rest = next.rest;
        self.onRecord(next, now) catch |err| return self.fail(err);
        if (self.phase_now == .failed or self.phase_now == .closed) return;
        // Each record's messages reach the engine before the next record is opened: the keys a
        // ServerHello or ChangeCipherSpec brings open the records after it in the same datagram.
        self.pump() catch |err| return self.fail(err);
    }
    if (self.phase_now == .connected) {
        // The handshake is over and the peer answered our last flight: it needs no more.
        if (self.answered) {
            if (self.flightOf(.handshake)) |flight| self.dropFlight(flight);
            self.answered = false;
        }
        // What no flight of ours answers is ACKed: the client's final flight at a server, and
        // every message after the handshake (RFC 9147 section 7.1). The server's last
        // handshake flight is answered by the client's final one, never ACKed.
        if (self.dtls13() and self.acked_now and (connected_before or self.role == .server)) self.ack_due = true;
    }
}

/// RFC 8449: a protected record whose plaintext would pass the record_size_limit this end named,
/// told by its length; DTLS may drop it (section 4), as it drops any record it cannot take.
fn overLimit(self: *const Datagram, keys: *const Record.Epoch, body_len: usize) bool {
    const explicit = if (keys.version == .dtls12) keys.cipher.explicitNonceLength12() else 0;
    return body_len > explicit + keys.cipher.tagLength() + self.record_limits.receive;
}

/// The most content a record of write epoch `epoch` carries: 2^14 bytes, or what the peer's
/// record_size_limit leaves (RFC 8449), which binds protected records only. DTLS 1.3 records, and
/// DTLS 1.2 records with a connection ID (RFC 9146), carry their content type inside.
fn sealLimit(self: *const Datagram, epoch: u64) usize {
    // Plaintext records are cut to the peer's limit too, once it is known (`Connection.sealLimit`).
    if (epoch == 0) return RecordLimits.content(self.record_limits.send, false);
    const keys = for (&self.writers) |*slot| {
        if (slot.*) |*e| if (e.number == epoch) break e;
    } else return Record.max_content;
    return RecordLimits.content(self.record_limits.send, keys.version == .dtls13 or self.sendCid().len != 0);
}

/// The most plaintext one `write` takes: 2^14 bytes, or fewer under the peer's record_size_limit
/// (RFC 8449). The MTU bounds it too: the record is the whole of a datagram.
pub fn writeLimit(self: *const Datagram) usize {
    return self.sealLimit(self.write_current);
}

fn onRecord(self: *Datagram, next: Record.Split, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    switch (next.kind) {
        .classic => |header| {
            if (header.epoch == 0) return self.onPlaintext(next.record, header, now);
            // With a connection ID of its own agreed, this end takes protected records only with
            // it, and never one without (RFC 9146 section 3).
            if (header.cid_len != self.receiveCidLen()) return;
            const keys = find(&self.readers, header.epoch) orelse return;
            if (keys.version != .dtls12 or self.overLimit(keys, next.record.len - header.length)) return;
            const opened = keys.open12(next.record, header) catch {
                if (keys.exhausted()) return error.ForgeryLimit;
                return;
            };
            self.validated = true;
            self.noteNewest(header.epoch, opened.sequence);
            try self.onOpened(opened, header.epoch, now);
        },
        .unified => |header| {
            // A connection ID only when one of this end's was agreed (RFC 9147 section 9).
            if (header.cid.len != self.receiveCidLen()) return;
            const keys = self.readEpoch(header.epoch_bits) orelse {
                // A client without the keys yet, as when the datagram with the ServerHello was
                // lost: an ACK of what it has, or of nothing, asks for the flight again (RFC 9147
                // section 7.1). A server has its client's handshake keys from its own hello on.
                if (self.phase_now == .handshaking and self.role == .client) {
                    if (self.acks.items.len != 0 and self.write_current >= 2) self.ack_due = true else self.empty_ack_due = true;
                }
                return;
            };
            if (self.overLimit(keys, next.record.len - header.length)) return;
            const opened = keys.open13(next.record, header) catch {
                if (keys.exhausted()) return error.ForgeryLimit;
                return;
            };
            const number = keys.number;
            // Only the client's handshake keys open this: its address is proven.
            self.validated = true;
            self.noteNewest(number, opened.sequence);
            // A record under a newer read epoch retires the ones before it (RFC 9147 section 8).
            if (number >= 3) self.retireReadBefore(number);
            try self.onOpened(opened, number, now);
        },
    }
}

fn noteNewest(self: *Datagram, epoch: u64, sequence: u64) void {
    if (self.newest) |held| if (epoch < held[0] or (epoch == held[0] and sequence <= held[1])) return;
    self.newest = .{ epoch, sequence };
    self.received_newest = true;
}

/// The read epoch whose low two bits match: the newest, during and after the handshake.
fn readEpoch(self: *Datagram, bits: u2) ?*Record.Epoch {
    var best: ?*Record.Epoch = null;
    for (&self.readers) |*slot| if (slot.*) |*e| {
        if (e.version != .dtls13 or @as(u2, @truncate(e.number)) != bits) continue;
        if (best == null or e.number > best.?.number) best = e;
    };
    return best;
}

fn retireReadBefore(self: *Datagram, number: u64) void {
    for (&self.readers) |*slot| if (slot.*) |*e| {
        // The handshake epoch stays while the handshake may still retransmit into it.
        if (e.number >= 3 and e.number < number) {
            e.deinit();
            slot.* = null;
        }
    };
}

fn onPlaintext(self: *Datagram, record: []u8, header: Record.Header12, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    const body = record[header.length..];
    switch (record[0]) {
        22 => try self.onHandshake(body, 0, header.sequence, now),
        20 => {
            // DTLS 1.2's ChangeCipherSpec: one byte, 1. It takes effect in message order.
            if (body.len != 1 or body[0] != 1 or self.dtls13()) return;
            if (self.hs.awaitingCcs()) try self.hs.receiveCcs() else self.ccs_waiting = true;
        },
        21 => {
            // An alert before any key: believed only while the handshake has no keys to check it.
            if (body.len != 2 or self.readers[0] != null or self.readers[1] != null or self.readers[2] != null) return;
            try self.onAlert(body);
        },
        26 => {
            // An ACK in the clear, from a DTLS 1.3 peer with no keys to send it under: unproven,
            // so what it names counts for nothing, but it may make the handshake flight go again
            // early, once a timer period (RFC 9147 section 7.1).
            if (self.phase_now != .handshaking or !self.dtls13()) return;
            if (self.flightOf(.handshake)) |flight| retransmitEarly(flight);
        },
        else => {},
    }
}

fn onOpened(self: *Datagram, opened: Record.Opened, epoch: u64, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    switch (opened.content) {
        .handshake => try self.onHandshake(opened.bytes, epoch, opened.sequence, now),
        .application => {
            // Application data only once the peer's Finished has been verified. It does not stand
            // for an ACK of a client's final flight: a server may send it before that flight
            // arrives (RFC 9147 section 5.8.1).
            if (self.phase_now != .connected or self.readable_len == max_readable) return;
            self.readable[self.readable_len] = .{ .bytes = opened.bytes };
            self.readable_len += 1;
        },
        .alert => if (opened.bytes.len == 2) try self.onAlert(opened.bytes),
        .ack => if (self.dtls13()) try self.onAck(opened.bytes, now),
        else => {},
    }
}

fn onAlert(self: *Datagram, body: []const u8) Error!void {
    const alert: Alert = @fromBackingInt(@intCast(body[1]));
    self.alert_received = alert;
    if (alert == .close_notify) {
        self.phase_now = .closed;
        // Nothing is read or written after it: the keys go.
        eraseAll(&self.readers);
        eraseAll(&self.writers);
        return;
    }
    // A warning is passed over in DTLS 1.2; every other alert ends the association.
    if (body[0] == 1 and !self.dtls13() and alert != .close_notify) return;
    return error.PeerAlert;
}

/// Handshake fragments of one record (RFC 9147 section 5.5).
fn onHandshake(self: *Datagram, body: []const u8, epoch: u64, record_sequence: ?u64, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    var rest = body;
    var any_new = false;
    var any_repeat = false;
    while (rest.len != 0) {
        if (rest.len < 12) return;
        const kind = rest[0];
        const length = std.mem.readInt(u24, rest[1..4], .big);
        const sequence = std.mem.readInt(u16, rest[4..6], .big);
        const offset = std.mem.readInt(u24, rest[6..9], .big);
        const fragment_len = std.mem.readInt(u24, rest[9..12], .big);
        if (rest.len - 12 < fragment_len) return;
        const fragment = rest[12..][0..fragment_len];
        rest = rest[12 + fragment_len ..];
        // The fragment must lie inside its message.
        if (@as(u32, offset) + fragment_len > length) return;
        // In usize: a 24-bit length plus its header can pass 2^24 (F77).
        if (@as(usize, length) + 4 > self.limits.handshake.message) return;
        // A server numbers the handshake from the client's first hello it takes: 0, or 1 and up
        // after a cookie exchange (RFC 6347 section 4.2.2).
        if (self.role == .server and !self.started) {
            if (kind != 1 or epoch != 0 or sequence > 3) continue;
            self.started = true;
            self.receive_sequence = sequence;
            self.send_sequence = sequence;
            self.answer_from = sequence;
            self.hs.firstSequence(sequence);
            // The server's first record carries the hello's record sequence (RFC 6347 section
            // 4.2.1), whatever a stateless exchange before it used.
            if (record_sequence) |number| self.plain_sequence = number;
        }
        const ahead = sequence -% self.receive_sequence;
        if (ahead >= 0x8000) {
            // An older message: the peer retransmitted, so our answer to it was lost.
            if (self.phase_now == .connected and epoch >= 2) {
                // After the handshake each record of a peer's message is ACKed, a repeat too
                // (RFC 9147 section 7.1).
                any_repeat = true;
            }
            self.onRetransmission(sequence, now);
            continue;
        }
        // New plaintext messages end where keys begin: once the peer's keys are in, a plaintext
        // message can only be forged, and it is dropped rather than refused, which would end the
        // association (F82).
        if (epoch == 0 and self.plaintextClosed()) continue;
        if (ahead >= self.limits.incomplete) continue;
        if (try self.absorb(kind, length, sequence, offset, fragment, epoch)) any_new = true;
    }
    // Part of the peer's answer: our flight need not go again whole, but the timer runs on until
    // the answer is complete (DTLS 1.3 then ACKs what it has instead).
    // Part of the peer's handshake answers our handshake flight; a message after the handshake
    // answers no flight (RFC 9147 section 7.1).
    if (any_new and self.phase_now == .handshaking) self.answered = true;
    if (any_new or any_repeat) if (epoch != 0) if (record_sequence) |number| try self.noteAck(epoch, number);
}

/// Whether the peer's plaintext messages are over: its handshake (DTLS 1.3) or ChangeCipherSpec
/// (DTLS 1.2) keys are in, or the handshake is done.
fn plaintextClosed(self: *const Datagram) bool {
    if (self.phase_now != .handshaking) return true;
    for (&self.readers) |*slot| if (slot.* != null) return true;
    return false;
}

/// Copies a fragment into its message; true when it brought bytes not held before.
///
/// Every fragment of a message names the same type, length and epoch, and bytes that overlap
/// agree (F77). A fragment that disagrees with what is held is dropped when what is held came
/// under keys; plaintext held is no evidence against plaintext arriving, so there the newer wins
/// and a forged fragment that came first is undone by the genuine one after it; a fragment under
/// keys always wins over plaintext.
fn absorb(self: *Datagram, kind: u8, length: u24, sequence: u16, offset: u24, fragment: []const u8, epoch: u64) Error!bool {
    @setRuntimeSafety(true);
    for (self.partials.items, 0..) |*p, i| {
        if (p.sequence != sequence) continue;
        const agrees = p.kind == kind and p.total() == length and p.epoch == epoch and overlapAgrees(p, offset, fragment);
        if (agrees) break;
        if (epoch < p.epoch or (epoch == p.epoch and epoch != 0)) return false;
        self.freePartial(self.partials.orderedRemove(i));
        break;
    }
    const partial = for (self.partials.items) |*p| {
        if (p.sequence == sequence) break p;
    } else blk: {
        const need = 4 + @as(usize, length) + (@as(usize, length) + 7) / 8;
        if (self.partials.items.len == self.limits.incomplete or self.partial_bytes + need > self.limits.reassembly) return false;
        const buf = try self.gpa.alloc(u8, 4 + @as(usize, length));
        errdefer self.gpa.free(buf);
        const have = try self.gpa.alloc(u8, (@as(usize, length) + 7) / 8);
        errdefer self.gpa.free(have);
        @memset(have, 0);
        buf[0] = kind;
        std.mem.writeInt(u24, buf[1..4], length, .big);
        try self.partials.append(self.gpa, .{ .sequence = sequence, .kind = kind, .epoch = epoch, .buf = buf, .have = have });
        self.partial_bytes += buf.len + have.len;
        break :blk &self.partials.items[self.partials.items.len - 1];
    };
    var added = false;
    for (fragment, 0..) |byte, i| {
        const at = @as(usize, offset) + i;
        const bit = @as(u8, 1) << @intCast(at % 8);
        if (partial.have[at / 8] & bit != 0) continue;
        partial.buf[4 + at] = byte;
        partial.have[at / 8] |= bit;
        partial.received += 1;
        added = true;
    }
    return added;
}

/// Whether the bytes of a fragment that are already held are the same.
fn overlapAgrees(partial: *const Partial, offset: u24, fragment: []const u8) bool {
    for (fragment, 0..) |byte, i| {
        const at = @as(usize, offset) + i;
        if (partial.have[at / 8] & (@as(u8, 1) << @intCast(at % 8)) != 0 and partial.buf[4 + at] != byte) return false;
    }
    return true;
}

/// The peer sent an old message again. One our handshake flight answers means our flight was
/// lost: it goes again, at most once a half timer period. One that answered our flight was
/// covered by our ACK (DTLS 1.3), which was lost: the ACK goes again.
fn onRetransmission(self: *Datagram, sequence: u16, now: std.Io.Timestamp) void {
    if (sequence -% self.answer_from < 0x8000) {
        if (self.dtls13() and self.acks.items.len != 0) self.ack_due = true;
        return;
    }
    const flight = self.flightOf(.handshake) orelse return;
    if (flight.transmitting) return;
    if (flight.deadline) |when| if (when.nanoseconds - now.nanoseconds > @divTrunc(flight.backoff.nanoseconds, 2)) {
        // Retransmitted within half a period of our own: the timer will do it.
        return;
    };
    restartTransmission(flight);
}

fn restartTransmission(flight: *Outgoing) void {
    for (flight.entries.items) |*entry| if (!entry.acked) {
        entry.cursor = 0;
        entry.pending = true;
    };
    flight.transmitting = true;
}

/// An ACK left part of a flight unacknowledged, or named nothing: the rest goes again now
/// rather than at the timer (RFC 9147 section 7.2), once a timer period, so that ACKs, forged
/// ones in the clear included, never make a flight go more than twice a period.
fn retransmitEarly(flight: *Outgoing) void {
    if (flight.transmitting or flight.early or flight.done()) return;
    flight.early = true;
    restartTransmission(flight);
}

fn noteAck(self: *Datagram, epoch: u64, sequence: u64) Error!void {
    if (!self.dtls13() or epoch < 2) return;
    for (self.acks.items) |held| if (held[0] == epoch and held[1] == sequence) {
        self.acked_now = true;
        return;
    };
    // The newest 64 records: an older one dropped from the list is ACKed no more, and its sender
    // retransmits it.
    if (self.acks.items.len == 64) _ = self.acks.orderedRemove(0);
    try self.acks.append(self.gpa, .{ epoch, sequence });
    self.acked_now = true;
}

fn onAck(self: *Datagram, body: []const u8, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    _ = now;
    if (body.len < 2) return;
    const len = std.mem.readInt(u16, body[0..2], .big);
    if (len % 16 != 0 or body.len != 2 + @as(usize, len)) return;
    if (len == 0) {
        // An ACK of nothing: the peer has none of the handshake flight it can read.
        if (self.phase_now == .handshaking) if (self.flightOf(.handshake)) |flight| retransmitEarly(flight);
        return;
    }
    var touched: [max_flights]bool = @splat(false);
    var at: usize = 2;
    while (at < body.len) : (at += 16) {
        const epoch = std.mem.readInt(u64, body[at..][0..8], .big);
        const sequence = std.mem.readInt(u64, body[at + 8 ..][0..8], .big);
        for (self.sent_records[0..self.sent_records_len]) |sent| {
            if (sent.epoch != epoch or sent.sequence != sequence) continue;
            const flight = if (self.flights[sent.slot]) |*held| held else continue;
            if (flight.generation != sent.generation) continue;
            try self.cover(flight, sent);
            touched[sent.slot] = true;
        }
    }
    for (&self.flights, touched) |*slot, hit| {
        if (!hit) continue;
        const flight = if (slot.*) |*held| held else continue;
        if (flight.done()) try self.flightAcknowledged(flight) else retransmitEarly(flight);
    }
}

/// Marks the bytes a record carried as received by the peer.
fn cover(self: *Datagram, flight: *Outgoing, sent: Sent_record) Error!void {
    @setRuntimeSafety(true);
    if (sent.entry >= flight.entries.items.len) return;
    const entry = &flight.entries.items[sent.entry];
    if (entry.acked) return;
    const body = bodyLength(entry.*);
    if (sent.offset == 0 and sent.len == body) {
        entry.acked = true;
        return;
    }
    if (entry.covered.len == 0) {
        entry.covered = try self.gpa.alloc(u8, (body + 7) / 8);
        @memset(entry.covered, 0);
    }
    for (sent.offset..sent.offset + sent.len) |i| entry.covered[i / 8] |= @as(u8, 1) << @intCast(i % 8);
    for (0..body) |i| if (entry.covered[i / 8] & (@as(u8, 1) << @intCast(i % 8)) == 0) return;
    entry.acked = true;
}

/// A whole flight is acknowledged: it is done with, and a KeyUpdate moves the write keys on.
fn flightAcknowledged(self: *Datagram, flight: *Outgoing) Error!void {
    @setRuntimeSafety(true);
    const updated = flight.category == .key_update;
    self.dropFlight(flight);
    if (updated) {
        const current = find(&self.writers, self.write_current) orelse return error.UnexpectedMessage;
        // Epochs never wrap; a sender stops at 2^48 (RFC 9147 section 8).
        if (current.number + 1 >= 1 << 48) return error.RecordLimit;
        const number = current.number + 1;
        current.next(claim(&self.writers, number));
        self.write_current = number;
    }
}

// ---------------------------------------------------------------- connection IDs

const request_connection_id = 9;
const new_connection_id = 10;

/// How a NewConnectionId's connection IDs are to be used (RFC 9147 section 9).
pub const Usage = enum(u8) {
    /// One of them from the next record on.
    immediate = 0,
    /// Kept for a later path.
    spare = 1,
};

/// DTLS 1.3: a NewConnectionId or RequestConnectionId from the peer (RFC 9147 section 9).
fn onCidMessage(self: *Datagram, kind: u8, body: []const u8, epoch: u64) Error!void {
    @setRuntimeSafety(true);
    // After the handshake and under its application keys only.
    if (!self.dtls13() or self.phase_now != .connected or epoch < 3) return error.UnexpectedMessage;
    if (kind == request_connection_id) {
        // The peer sends with this end's connection ID, so this end must have one.
        if (!self.cids_agreed or self.own_cid_len == 0) return error.UnexpectedMessage;
        if (body.len != 1) return error.InvalidLength;
        // One request at a time: the last one must have been answered.
        if (self.cids_requested != 0) return error.TooManyConnectionIdsRequested;
        self.cids_requested = body[0];
        return;
    }
    // The peer receives with connection IDs of its own: those it hands out replace them.
    if (!self.cids_agreed or self.peer_cid_len == 0) return error.UnexpectedMessage;
    if (body.len < 3) return error.InvalidLength;
    const list_len = std.mem.readInt(u16, body[0..2], .big);
    if (body.len != 2 + @as(usize, list_len) + 1) return error.InvalidLength;
    const usage = std.enums.fromInt(Usage, body[body.len - 1]) orelse return error.IllegalParameter;
    var list = body[2..][0..list_len];
    var first = true;
    var count: usize = 0;
    while (list.len != 0) {
        const len = list[0];
        if (len == 0) return error.IllegalParameter;
        if (list.len < 1 + @as(usize, len)) return error.InvalidLength;
        const cid = list[1..][0..len];
        list = list[1 + @as(usize, len) ..];
        count += 1;
        if (first and usage == .immediate) {
            @memcpy(self.peer_cid[0..len], cid);
            self.peer_cid_len = len;
        } else if (self.spare_cid_count < max_spare_cids) {
            const i = self.spare_cid_count;
            @memcpy(self.spare_cids[i][0..len], cid);
            self.spare_cid_lens[i] = len;
            self.spare_cid_count += 1;
        }
        first = false;
    }
    if (usage == .immediate and count == 0) return error.IllegalParameter;
    self.cid_request_open = false;
}

/// DTLS 1.3: hands the peer connection IDs to send with, `usage` saying when (RFC 9147 section
/// 9). Each must have the length of this end's own, by which its records are parsed; the caller
/// routes datagrams carrying any of them to this association. One NewConnectionId at a time;
/// it also answers the peer's request (`connectionIdsRequested`).
pub fn newConnectionIds(self: *Datagram, cids: []const []const u8, usage: Usage) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now != .connected) return error.NotConnected;
    if (!self.dtls13()) return error.UnexpectedMessage;
    if (!self.cids_agreed or self.own_cid_len == 0) return error.NoConnectionIds;
    if (cids.len > max_new_cids or (usage == .immediate and cids.len == 0)) return error.NoConnectionIds;
    for (cids) |cid| if (cid.len != self.own_cid_len) return error.NoConnectionIds;
    if (self.flightOf(.new_cid) != null) return error.ConnectionIdPending;
    var buffer: [4 + 2 + max_new_cids * (1 + Record.max_cid) + 1]u8 = undefined;
    const body_len = 2 + cids.len * (1 + @as(usize, self.own_cid_len)) + 1;
    buffer[0] = new_connection_id;
    std.mem.writeInt(u24, buffer[1..4], @intCast(body_len), .big); // safe: at most 2,051 bytes
    std.mem.writeInt(u16, buffer[4..6], @intCast(body_len - 3), .big); // safe: as above
    var at: usize = 6;
    for (cids) |cid| {
        buffer[at] = self.own_cid_len;
        @memcpy(buffer[at + 1 ..][0..cid.len], cid);
        at += 1 + cid.len;
    }
    buffer[at] = @backingInt(usage);
    try self.queueOwn(.new_cid, self.write_current, buffer[0 .. at + 1]);
    self.cids_requested -|= @intCast(@min(cids.len, 255)); // safe: bounded just above
}

/// DTLS 1.3: asks the peer for `count` connection IDs to send with (RFC 9147 section 9); they
/// arrive as spares (`useSpareConnectionId`). One request at a time, until the peer answers.
pub fn requestConnectionIds(self: *Datagram, count: u8) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now != .connected) return error.NotConnected;
    if (!self.dtls13()) return error.UnexpectedMessage;
    // Never while sending with an empty connection ID.
    if (!self.cids_agreed or self.peer_cid_len == 0 or count == 0) return error.NoConnectionIds;
    if (self.cid_request_open or self.flightOf(.request_cid) != null) return error.ConnectionIdPending;
    try self.queueOwn(.request_cid, self.write_current, &.{ request_connection_id, 0, 0, 1, count });
    self.cid_request_open = true;
}

/// How many connection IDs the peer asked for and has not been given (`newConnectionIds`).
pub fn connectionIdsRequested(self: *const Datagram) u8 {
    return self.cids_requested;
}

/// How many connection IDs the peer handed out for later are held.
pub fn spareConnectionIds(self: *const Datagram) usize {
    return self.spare_cid_count;
}

/// Sends with the oldest spare connection ID from now on, as on a new path, where a fresh one
/// keeps the paths unlinkable (RFC 9147 section 9). False when none is held.
pub fn useSpareConnectionId(self: *Datagram) bool {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.spare_cid_count == 0) return false;
    const len = self.spare_cid_lens[0];
    @memcpy(self.peer_cid[0..len], self.spare_cids[0][0..len]);
    self.peer_cid_len = len;
    for (1..self.spare_cid_count) |i| {
        self.spare_cids[i - 1] = self.spare_cids[i];
        self.spare_cid_lens[i - 1] = self.spare_cid_lens[i];
    }
    self.spare_cid_count -= 1;
    return true;
}

/// The next application datagram the last `receive` opened, or null.
pub fn read(self: *Datagram) ?[]const u8 {
    if (self.readable_at == self.readable_len) return null;
    defer self.readable_at += 1;
    return self.readable[self.readable_at].bytes;
}

// ---------------------------------------------------------------- sending

/// When `send` must be called again to retransmit, if a flight waits on the peer.
pub fn timeout(self: *const Datagram) ?std.Io.Timestamp {
    if (self.phase_now == .failed or self.transmitting()) return null;
    var earliest: ?std.Io.Timestamp = null;
    for (self.flights) |slot| if (slot) |flight| if (flight.deadline) |when| {
        if (earliest == null or when.nanoseconds < earliest.?.nanoseconds) earliest = when;
    };
    return earliest;
}

/// Writes the next datagram to send into `out` (at least the MTU), or returns null when nothing
/// is due. A passed `timeout` makes its flight due again, with the wait doubled.
pub fn send(self: *Datagram, out: []u8, now: std.Io.Timestamp) Error!?[]u8 {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (out.len < self.mtu) return error.BufferTooSmall;
    if (self.fatal_due) |alert| {
        self.fatal_due = null;
        // The alert goes under the write keys, which then go too.
        defer eraseAll(&self.writers);
        return self.alertDatagram(2, alert, out);
    }
    if (self.phase_now == .failed) return null;
    for (&self.flights) |*slot| if (slot.*) |*flight| try self.expire(flight, now);
    if (self.phase_now == .failed) return null;
    var budget: usize = self.mtu;
    if (!self.validated) {
        // An unproven address gets three times what it sent, and no more (RFC 9147 section 5.1).
        const allowance = (3 *| self.received_bytes) -| self.sent_bytes;
        if (allowance < min_mtu) return null;
        budget = @min(budget, allowance);
    }
    const datagram = out[0..budget];
    var used: usize = 0;
    // The handshake's flight first, then the post-handshake messages'.
    if (self.flightOf(.handshake)) |flight| used += try self.transmit(flight, datagram[used..], now);
    for (&self.flights) |*slot| if (slot.*) |*flight| if (flight.category != .handshake) {
        used += try self.transmit(flight, datagram[used..], now);
    };
    if (self.ack_due and self.dtls13()) {
        const written = self.writeAck(datagram[used..]) catch 0;
        if (written != 0) {
            used += written;
            self.ack_due = false;
            self.empty_ack_due = false;
            // During the handshake the records stay listed: a peer that lost this ACK repeats
            // its flight and gets it again. After it, a repeat is ACKed by its own record.
            if (self.phase_now == .connected) self.acks.clearRetainingCapacity();
        }
    }
    if (self.empty_ack_due) {
        const written = self.writeEmptyAck(datagram[used..]) catch 0;
        if (written != 0) {
            used += written;
            self.empty_ack_due = false;
        }
    }
    if (self.close_due and !self.transmitting() and used == 0) {
        self.close_due = false;
        const alert = try self.alertDatagram(1, .close_notify, out);
        self.phase_now = .closed;
        eraseAll(&self.writers);
        eraseAll(&self.readers);
        return alert;
    }
    if (used == 0) return null;
    self.sent_bytes +|= used;
    return datagram[0..used];
}

/// A flight whose timer passed goes again with its wait doubled, or is given up on.
fn expire(self: *Datagram, flight: *Outgoing, now: std.Io.Timestamp) Error!void {
    @setRuntimeSafety(true);
    if (flight.transmitting) return;
    const when = flight.deadline orelse return;
    if (now.nanoseconds < when.nanoseconds) return;
    flight.retransmissions += 1;
    if (flight.retransmissions > self.timing.retransmissions) {
        // A handshake gives up; after it, a flight whose ACK never came (the final flight, a
        // ticket, a key update, a connection ID message) is only given up on: the association
        // is established.
        if (flight.category == .handshake and self.phase_now != .connected) return self.fail(error.HandshakeTimeout);
        self.dropFlight(flight);
        return;
    }
    flight.backoff = .{ .nanoseconds = @min(flight.backoff.nanoseconds * 2, self.timing.max.nanoseconds) };
    flight.deadline = null;
    flight.early = false;
    if (flight.category == .handshake and self.answered and self.dtls13() and self.acks.items.len != 0) {
        // Part of the answer came: ACK it, and the peer resends the rest (RFC 9147 section 7.1).
        self.ack_due = true;
        flight.deadline = .{ .nanoseconds = now.nanoseconds + flight.backoff.nanoseconds };
    } else restartTransmission(flight);
}

/// Writes what is due of `flight` into `out`, and arms its timer once all of it went.
fn transmit(self: *Datagram, flight: *Outgoing, out: []u8, now: std.Io.Timestamp) Error!usize {
    @setRuntimeSafety(true);
    if (!flight.transmitting) return 0;
    const used = try self.packFlight(flight, out);
    if (flight.sent()) {
        flight.transmitting = false;
        if (self.expectsAnswer(flight)) flight.deadline = .{ .nanoseconds = now.nanoseconds + flight.backoff.nanoseconds };
    }
    return used;
}

fn bodyLength(entry: Sent) usize {
    return switch (entry.kind) {
        .message => entry.bytes.len - 4,
        .ccs => 1,
    };
}

/// Whether a flight just sent waits for an answer or an ACK: every flight but DTLS 1.2's last
/// (RFC 6347 section 4.2.4), which is resent only when the peer repeats its own.
fn expectsAnswer(self: *const Datagram, flight: *const Outgoing) bool {
    if (flight.category != .handshake or self.phase_now != .connected) return true;
    return self.dtls13();
}

/// Fragments of a flight into `out`, record by record, until it is full.
fn packFlight(self: *Datagram, flight: *Outgoing, out: []u8) Error!usize {
    @setRuntimeSafety(true);
    const slot = self.slotOf(flight);
    var used: usize = 0;
    for (flight.entries.items, 0..) |*entry, index| {
        if (entry.acked) continue;
        // Keys a later update retired cannot resend what went under them: given up on.
        if (entry.epoch != 0 and find(&self.writers, entry.epoch) == null) {
            entry.acked = true;
            entry.pending = false;
            continue;
        }
        while (entry.pending) {
            const overhead = self.recordOverhead(entry.epoch);
            const room = out.len - used;
            switch (entry.kind) {
                .ccs => {
                    if (room < Record.header12 + 1) return used;
                    const record = try Record.plaintext(.change_cipher_spec, self.nextPlainSequence(), &.{1}, out[used..]);
                    used += record.len;
                    entry.cursor = 1;
                    entry.pending = false;
                },
                .message => {
                    const body = entry.bytes[4..];
                    const left = body.len - entry.cursor;
                    // A fragment worth sending: the rest, or at least 64 bytes of it.
                    if (room <= overhead + 12 or (room - overhead - 12 < left and room - overhead - 12 < 64)) return used;
                    const n = @min(left, room - overhead - 12, self.sealLimit(entry.epoch) - 12);
                    var fragment: [12]u8 = undefined;
                    fragment[0] = entry.bytes[0];
                    fragment[1..4].* = entry.bytes[1..4].*;
                    std.mem.writeInt(u16, fragment[4..6], entry.sequence, .big);
                    // safe: offsets and lengths are below the 24-bit message length.
                    std.mem.writeInt(u24, fragment[6..9], @intCast(entry.cursor), .big);
                    std.mem.writeInt(u24, fragment[9..12], @intCast(n), .big);
                    const number = self.nextRecordNumber(entry.epoch);
                    const record = try self.sealHandshake(entry.epoch, &fragment, body[entry.cursor..][0..n], out[used..]);
                    used += record.len;
                    // safe: a flight holds at most a few dozen entries and 256 KiB.
                    self.logRecord(.{ .epoch = entry.epoch, .sequence = number, .slot = slot, .generation = flight.generation, .entry = @intCast(index), .offset = @intCast(entry.cursor), .len = @intCast(n) });
                    entry.cursor += n;
                    if (entry.cursor == body.len) entry.pending = false;
                },
            }
        }
    }
    return used;
}

/// The record number the next record of `epoch` gets.
fn nextRecordNumber(self: *Datagram, epoch: u64) u64 {
    if (epoch == 0) return self.plain_sequence;
    const keys = find(&self.writers, epoch) orelse return 0;
    return keys.sequence;
}

fn logRecord(self: *Datagram, record: Sent_record) void {
    self.sent_records[self.sent_records_at] = record;
    self.sent_records_at = (self.sent_records_at + 1) % self.sent_records.len;
    self.sent_records_len = @min(self.sent_records_len + 1, self.sent_records.len);
}

fn nextPlainSequence(self: *Datagram) u64 {
    defer self.plain_sequence += 1;
    return self.plain_sequence;
}

/// What a record of `epoch` adds around its content.
fn recordOverhead(self: *Datagram, epoch: u64) usize {
    if (epoch == 0) return Record.header12;
    const keys = find(&self.writers, epoch) orelse return Record.header12 + 64;
    return switch (keys.version) {
        .dtls13 => Record.overhead13(self.sendCid().len),
        .dtls12 => Record.overhead12(keys.cipher, self.sendCid().len),
    };
}

/// One handshake fragment as a record of `epoch`: the twelve-byte DTLS header, then its bytes.
fn sealHandshake(self: *Datagram, epoch: u64, header: *const [12]u8, bytes: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    if (epoch == 0) {
        if (out.len < Record.header12 + 12 + bytes.len) return error.BufferTooSmall;
        @memcpy(out[Record.header12..][0..12], header);
        @memcpy(out[Record.header12 + 12 ..][0..bytes.len], bytes);
        return Record.plaintext(.handshake, self.nextPlainSequence(), out[Record.header12..][0 .. 12 + bytes.len], out);
    }
    const keys = find(&self.writers, epoch) orelse return error.UnexpectedMessage;
    // The content is assembled where the record's body goes, then sealed in place.
    const cid = self.sendCid();
    const at = switch (keys.version) {
        .dtls13 => 5 + cid.len,
        .dtls12 => Record.header12 + cid.len + keys.cipher.explicitNonceLength12(),
    };
    if (out.len < at + 12 + bytes.len + Record.tag_length + 1) return error.BufferTooSmall;
    @memcpy(out[at..][0..12], header);
    @memcpy(out[at + 12 ..][0..bytes.len], bytes);
    const content = out[at..][0 .. 12 + bytes.len];
    return switch (keys.version) {
        .dtls13 => keys.seal13(.handshake, content, cid, out),
        .dtls12 => keys.seal12(.handshake, content, cid, out),
    };
}

/// An ACK of the records listed, the newest of them when not all fit `out` (RFC 9147 section
/// 7.1).
fn writeAck(self: *Datagram, out: []u8) Error!usize {
    @setRuntimeSafety(true);
    const keys = find(&self.writers, self.write_current) orelse return 0;
    const overhead = Record.overhead13(self.sendCid().len);
    if (out.len < overhead + 2 + 16) return 0;
    const count = @min(self.acks.items.len, (out.len - overhead - 2) / 16, (self.sealLimit(self.write_current) - 2) / 16);
    const listed = self.acks.items[self.acks.items.len - count ..];
    var body: [2 + 16 * 64]u8 = undefined;
    // safe: at most 64 records.
    std.mem.writeInt(u16, body[0..2], @intCast(count * 16), .big);
    // In numerically increasing order (RFC 9147 section 7).
    var sorted: [64][2]u64 = undefined;
    @memcpy(sorted[0..count], listed);
    std.mem.sort([2]u64, sorted[0..count], {}, lessRecord);
    for (sorted[0..count], 0..) |number, i| {
        std.mem.writeInt(u64, body[2 + 16 * i ..][0..8], number[0], .big);
        std.mem.writeInt(u64, body[2 + 16 * i + 8 ..][0..8], number[1], .big);
    }
    const record = try keys.seal13(.ack, body[0 .. 2 + 16 * count], self.sendCid(), out);
    return record.len;
}

fn lessRecord(_: void, a: [2]u64, b: [2]u64) bool {
    return a[0] < b[0] or (a[0] == b[0] and a[1] < b[1]);
}

/// An ACK of no record: under the newest write keys, or in the clear before any (RFC 9147
/// section 7.1).
fn writeEmptyAck(self: *Datagram, out: []u8) Error!usize {
    @setRuntimeSafety(true);
    if (self.write_current >= 2) {
        const keys = find(&self.writers, self.write_current) orelse return 0;
        if (out.len < Record.overhead13(self.sendCid().len) + 2) return 0;
        return (try keys.seal13(.ack, &.{ 0, 0 }, self.sendCid(), out)).len;
    }
    if (out.len < Record.header12 + 2) return 0;
    return (try Record.plaintext(.ack, self.nextPlainSequence(), &.{ 0, 0 }, out)).len;
}

fn alertDatagram(self: *Datagram, level: u8, alert: Alert, out: []u8) Error!?[]u8 {
    @setRuntimeSafety(true);
    const body = [2]u8{ level, @backingInt(alert) };
    self.alert_sent = alert;
    if (self.write_current == 0) return try Record.plaintext(.alert, self.nextPlainSequence(), &body, out);
    const keys = find(&self.writers, self.write_current) orelse return null;
    return switch (keys.version) {
        .dtls13 => try keys.seal13(.alert, &body, self.sendCid(), out),
        .dtls12 => try keys.seal12(.alert, &body, self.sendCid(), out),
    };
}

/// Seals `plaintext` as one application record, the whole of a datagram, into `out`.
pub fn write(self: *Datagram, plaintext: []const u8, out: []u8) Error![]u8 {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now != .connected) return if (self.phase_now == .handshaking) error.NotConnected else error.Closed;
    // DTLS 1.3 updates its keys while an eighth of their records is left; DTLS 1.2 has no update
    // and its association ends at the limit.
    if (find(&self.writers, self.write_current)) |current| if (current.version == .dtls13 and current.remaining() < current.record_limit / 8) self.keyUpdate(false) catch |err| switch (err) {
        error.UpdatePending => {},
        else => |e| return e,
    };
    const keys = find(&self.writers, self.write_current) orelse return error.NotConnected;
    if (plaintext.len > self.writeLimit()) return error.InvalidLength;
    return switch (keys.version) {
        .dtls13 => keys.seal13(.application, plaintext, self.sendCid(), out),
        .dtls12 => keys.seal12(.application, plaintext, self.sendCid(), out),
    };
}

/// Sets the largest datagram from now on, as the path's MTU changes (RFC 9147 section 4.4): a
/// flight being sent or resent is cut anew from its cached messages, never from what went before.
pub fn setMtu(self: *Datagram, mtu: u16) InitError!void {
    if (mtu < min_mtu or mtu > max_mtu) return error.InvalidOptions;
    self.mtu = mtu;
}

/// Ends the association with close_notify, which the next `send` writes.
pub fn close(self: *Datagram) void {
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now == .connected) self.close_due = true;
}

/// DTLS 1.3: updates this end's write keys, asking the peer to update its own when
/// `request_peer`. The KeyUpdate goes out under the current keys; the new ones take over when the
/// peer acknowledges it.
pub fn keyUpdate(self: *Datagram, request_peer: bool) Error!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (self.phase_now != .connected) return error.NotConnected;
    if (!self.dtls13()) return error.UnexpectedMessage;
    // One at a time: the next waits for the last one's ACK (RFC 9147 section 8).
    if (self.flightOf(.key_update) != null) return error.UpdatePending;
    var buffer: [5]u8 = undefined;
    const message = try Messages.buildKeyUpdate(&buffer, request_peer);
    try self.queueOwn(.key_update, self.write_current, message);
}

test {
    _ = @import("Datagram_test.zig");
}
