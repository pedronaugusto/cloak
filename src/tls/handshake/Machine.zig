//! One handshake machine of either role behind the surface the drivers use. Connection and
//! the QUIC handshake hold a machine, ask it for outputs and requests, and answer through it.
const std = @import("std");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const Client = @import("Client.zig");
const Flight = @import("Flight.zig");
const Server = @import("Server.zig");

pub const Epoch = Flight.Epoch;
pub const Emit = Flight.Emit;
pub const Need = Client.Need;
pub const Info = Client.Info;
pub const SignRequest = Client.SignRequest;
pub const Error = Client.Error;
pub const ExportError = Client.ExportError;

const Machine = @This();

pub const Role = enum { client, server };

state: union(Role) { client: *Client, server: *Server },

pub fn forClient(hs: *Client) Machine {
    return .{ .state = .{ .client = hs } };
}

pub fn role(self: Machine) Role {
    return std.meta.activeTag(self.state);
}

pub fn deinit(self: Machine) void {
    switch (self.state) {
        inline else => |m| m.deinit(),
    }
}

pub fn wipe(self: Machine) void {
    switch (self.state) {
        inline else => |m| m.wipe(),
    }
}

/// The negotiated version; TLS 1.3 until a hello says otherwise.
pub fn version(self: Machine) @import("../crypto/Suite.zig").Version {
    return switch (self.state) {
        inline else => |m| m.version,
    };
}

/// A ChangeCipherSpec record arrived at a message boundary.
pub fn receiveCcs(self: Machine) Error!void {
    return switch (self.state) {
        inline else => |m| m.receiveCcs(),
    };
}

pub fn need(self: Machine) Need {
    return switch (self.state) {
        inline else => |m| m.need(),
    };
}

/// Whether the peer asked for middlebox compatibility: a legacy session id was sent.
pub fn compat(self: Machine) bool {
    return switch (self.state) {
        inline else => |m| m.compat(),
    };
}

/// Whether the client was asked for a certificate, or the server asks for one.
pub fn certificateRequested(self: Machine) bool {
    return switch (self.state) {
        .client => |m| m.requested_certificate,
        .server => |m| m.options.client_auth != .none,
    };
}

pub fn receive(self: Machine, bytes: []const u8, epoch: Epoch, boundary: bool) Error!void {
    return switch (self.state) {
        inline else => |m| m.receive(bytes, epoch, boundary),
    };
}

/// Moves the next output into `out`; see `Flight.pop`.
pub fn pop(self: Machine, out: *Emit) bool {
    return switch (self.state) {
        inline else => |m| m.pop(out),
    };
}

pub fn pending(self: Machine) bool {
    return switch (self.state) {
        inline else => |m| m.pending(),
    };
}

pub fn flightBytes(self: Machine, start: u32, len: u32) []const u8 {
    return switch (self.state) {
        inline else => |m| m.flightBytes(start, len),
    };
}

pub fn recycle(self: Machine) void {
    switch (self.state) {
        inline else => |m| m.recycle(),
    }
}

pub fn settle(self: Machine) void {
    switch (self.state) {
        inline else => |m| m.settle(),
    }
}

pub fn info(self: Machine) ?Info {
    return switch (self.state) {
        inline else => |m| m.info(),
    };
}

/// A client's authenticated ECH retry configurations after a rejection; see `Client.echRetryConfigs`.
pub fn echRetryConfigs(self: Machine) ?[]const u8 {
    return switch (self.state) {
        .client => |m| m.echRetryConfigs(),
        .server => null,
    };
}

pub fn exportKeyingMaterial(self: Machine, out: []u8, label: []const u8, context: ?[]const u8) ExportError!void {
    return switch (self.state) {
        inline else => |m| m.exportKeyingMaterial(out, label, context),
    };
}

pub fn provideEntropy(self: Machine, entropy: []const u8) Error!void {
    return switch (self.state) {
        inline else => |m| m.provideEntropy(entropy),
    };
}

pub fn provideTime(self: Machine, now: std.Io.Timestamp) Error!void {
    return switch (self.state) {
        inline else => |m| m.provideTime(now),
    };
}

pub fn verification(self: Machine, token: types.Token) types.Request {
    return switch (self.state) {
        inline else => |m| m.verification(token),
    };
}

pub fn provideVerification(self: Machine, token: types.Token, receipt: *const types.Verification) Error!void {
    return switch (self.state) {
        inline else => |m| m.provideVerification(token, receipt),
    };
}

pub fn rejectVerification(self: Machine) void {
    switch (self.state) {
        inline else => |m| m.rejectVerification(),
    }
}

pub fn signRequest(self: Machine) SignRequest {
    return switch (self.state) {
        inline else => |m| m.signRequest(),
    };
}

pub fn provideSignature(self: Machine, signature: []const u8) Error!void {
    return switch (self.state) {
        inline else => |m| m.provideSignature(signature),
    };
}

pub fn provideParameters(self: Machine, accept: bool) Error!void {
    return switch (self.state) {
        inline else => |m| m.provideParameters(accept),
    };
}

/// The largest handshake message either role accepts, in bytes.
pub fn messageLimit(self: Machine) usize {
    return switch (self.state) {
        inline else => |m| m.options.limits.message,
    };
}

/// The peer's QUIC transport parameters; empty before they arrive.
pub fn peerParameters(self: Machine) []const u8 {
    return switch (self.state) {
        inline else => |m| m.peer_parameters,
    };
}

/// Whether a warning-level alert may be passed over. TLS 1.2 has warnings (RFC 5246 section
/// 7.2: a server may warn unrecognized_name before its ServerHello); TLS 1.3 treats every alert
/// but close_notify and user_canceled as fatal (RFC 8446 section 6.2).
pub fn warningsAllowed(self: Machine) bool {
    return switch (self.state) {
        .client => |m| m.version == .tls12 or (m.group == null and m.options.hello.allows12()),
        .server => |m| m.version == .tls12,
    };
}

/// Whether the ServerHello (not a retry request) has been sent or processed: the keys changed.
pub fn negotiated(self: Machine) bool {
    return switch (self.state) {
        .client => |m| m.group != null,
        .server => |m| m.answered,
    };
}

/// How a server skips the early data its client offered and it never accepts (RFC 8446 section
/// 4.2.10): after a retry request, every protected record before the second hello (`keyless`);
/// otherwise each record that fails to open under the handshake keys, until one opens (`trial`).
pub const EarlySkip = enum { none, keyless, trial };

pub fn earlySkip(self: Machine) EarlySkip {
    return switch (self.state) {
        .client => .none,
        .server => |m| skip: {
            const scratch = m.scratch orelse break :skip .none;
            if (m.version != .tls13 or !scratch.early_offered) break :skip .none;
            break :skip if (m.retried) .keyless else .trial;
        },
    };
}

/// DTLS: the message_seq of the hello a server's first message is, from which DTLS 1.2 numbers
/// its transcript. The datagram carrier sets it before the hello; a client starts at zero.
/// DTLS: the connection ID records this end sends carry, when the hellos agreed on connection
/// IDs (RFC 9146), and null when they did not; known once the hellos are processed and until
/// the handshake completes.
pub fn peerConnectionId(self: Machine) ?[]const u8 {
    return switch (self.state) {
        inline else => |m| {
            const scratch = m.scratch orelse return null;
            if (!scratch.cid_agreed) return null;
            return scratch.peer_cid[0..scratch.peer_cid_len];
        },
    };
}

pub fn firstSequence(self: Machine, sequence: u16) void {
    switch (self.state) {
        .client => {},
        .server => |m| m.first_sequence = sequence,
    }
}

/// DTLS: a server that answered the first hello with a stateless retry request starts from it
/// (`Server.resumeRetry`).
pub fn resumeRetry(self: Machine, suite: @import("../crypto/Suite.zig").Suite13, group: @import("../crypto/Group.zig").Group, hello_hash: []const u8, fingerprint: [32]u8, retry: []const u8) Error!void {
    return switch (self.state) {
        .client => error.UnexpectedMessage,
        .server => |m| m.resumeRetry(suite, group, hello_hash, fingerprint, retry),
    };
}

/// TLS 1.2: whether the peer's ChangeCipherSpec is the next thing the table takes. A datagram
/// carrier holds one that arrives early (it has no message sequence) until then.
pub fn awaitingCcs(self: Machine) bool {
    return switch (self.state) {
        .client => |m| m.version == .tls12 and ((m.state.phase == .peer_ccs12 and !m.state.ticket12) or m.state.phase == .ticket_seen12),
        .server => |m| m.version == .tls12 and m.state.phase == .c_ccs12,
    };
}

/// The state table's phase, for the callers that must not act on a failed machine.
pub fn failed(self: Machine) bool {
    return switch (self.state) {
        inline else => |m| m.state.phase == .failed,
    };
}
