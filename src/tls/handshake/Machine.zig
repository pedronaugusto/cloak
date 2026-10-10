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

pub fn pop(self: Machine) ?Emit {
    return switch (self.state) {
        inline else => |m| m.pop(),
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

pub fn exportKeyingMaterial(self: Machine, out: []u8, label: []const u8, context: []const u8) ExportError!void {
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

/// Whether the ServerHello (not a retry request) has been sent or processed: the keys changed.
pub fn negotiated(self: Machine) bool {
    return switch (self.state) {
        .client => |m| m.group != null,
        .server => |m| m.answered,
    };
}

/// The state table's phase, for the callers that must not act on a failed machine.
pub fn failed(self: Machine) bool {
    return switch (self.state) {
        inline else => |m| m.state.phase == .failed,
    };
}
