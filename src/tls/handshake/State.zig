//! Checked TLS 1.3 full-handshake transitions. No record or QUIC owner here.
//! Published aegis has no typestate module; this table remains always checked.
const std = @import("std");
pub const Role = enum { client, server };
pub const Mode = enum { stream, quic };
pub const Epoch = enum { initial, handshake, application };
pub const Auth = enum { none, optional, required };
pub const Phase = enum {
    start,
    hello,
    retry,
    extensions,
    certificate_request,
    certificate,
    chain,
    possession,
    finished,
    local_flight,
    client_certificate,
    client_chain,
    client_possession,
    client_finished,
    connected,
    failed,
};
pub const Action = enum {
    client_hello,
    hello_retry,
    server_hello,
    encrypted_extensions,
    certificate_request,
    certificate,
    verify_chain,
    certificate_verify,
    finished,
    local_finished,
    local_certificate,
    local_empty_certificate,
    local_certificate_verify,
    empty_certificate,
    key_update,
    ticket,
};
pub const Proof = enum { parsed, chain, possession, finished };
const Edge = struct { role: Role, from: Phase, action: Action, epoch: Epoch, proof: Proof = .parsed, to: Phase, boundary: bool = false };
/// Transcript commitment follows successful parsing/proof, once per wire message.
/// verify_chain is a service completion and contributes no transcript bytes.
const edges = [_]Edge{
    .{ .role = .client, .from = .start, .action = .client_hello, .epoch = .initial, .to = .hello },
    .{ .role = .client, .from = .hello, .action = .hello_retry, .epoch = .initial, .to = .retry, .boundary = true },
    .{ .role = .client, .from = .retry, .action = .client_hello, .epoch = .initial, .to = .hello },
    .{ .role = .client, .from = .hello, .action = .server_hello, .epoch = .initial, .to = .extensions, .boundary = true },
    .{ .role = .client, .from = .extensions, .action = .encrypted_extensions, .epoch = .handshake, .to = .certificate_request },
    .{ .role = .client, .from = .certificate_request, .action = .certificate_request, .epoch = .handshake, .to = .certificate },
    .{ .role = .client, .from = .certificate_request, .action = .certificate, .epoch = .handshake, .to = .chain },
    .{ .role = .client, .from = .certificate, .action = .certificate, .epoch = .handshake, .to = .chain },
    .{ .role = .client, .from = .chain, .action = .verify_chain, .epoch = .handshake, .proof = .chain, .to = .possession },
    .{ .role = .client, .from = .possession, .action = .certificate_verify, .epoch = .handshake, .proof = .possession, .to = .finished },
    .{ .role = .client, .from = .finished, .action = .finished, .epoch = .handshake, .proof = .finished, .to = .local_flight, .boundary = true },
    .{ .role = .client, .from = .local_flight, .action = .local_finished, .epoch = .handshake, .proof = .finished, .to = .connected, .boundary = true },
    .{ .role = .client, .from = .local_flight, .action = .local_certificate, .epoch = .handshake, .to = .client_possession },
    .{ .role = .client, .from = .local_flight, .action = .local_empty_certificate, .epoch = .handshake, .to = .client_finished },
    .{ .role = .client, .from = .client_possession, .action = .local_certificate_verify, .epoch = .handshake, .proof = .possession, .to = .client_finished },
    .{ .role = .client, .from = .client_finished, .action = .local_finished, .epoch = .handshake, .proof = .finished, .to = .connected, .boundary = true },
    .{ .role = .server, .from = .start, .action = .client_hello, .epoch = .initial, .to = .hello },
    .{ .role = .server, .from = .hello, .action = .hello_retry, .epoch = .initial, .to = .retry, .boundary = true },
    .{ .role = .server, .from = .retry, .action = .client_hello, .epoch = .initial, .to = .hello },
    .{ .role = .server, .from = .hello, .action = .server_hello, .epoch = .initial, .to = .extensions, .boundary = true },
    .{ .role = .server, .from = .extensions, .action = .encrypted_extensions, .epoch = .handshake, .to = .certificate_request },
    .{ .role = .server, .from = .certificate_request, .action = .certificate_request, .epoch = .handshake, .to = .certificate },
    .{ .role = .server, .from = .certificate_request, .action = .certificate, .epoch = .handshake, .to = .possession },
    .{ .role = .server, .from = .certificate, .action = .certificate, .epoch = .handshake, .to = .possession },
    .{ .role = .server, .from = .possession, .action = .certificate_verify, .epoch = .handshake, .proof = .possession, .to = .finished },
    .{ .role = .server, .from = .finished, .action = .local_finished, .epoch = .handshake, .proof = .finished, .to = .client_certificate, .boundary = true },
    .{ .role = .server, .from = .client_certificate, .action = .certificate, .epoch = .handshake, .to = .client_chain },
    .{ .role = .server, .from = .client_certificate, .action = .empty_certificate, .epoch = .handshake, .to = .client_finished },
    .{ .role = .server, .from = .client_chain, .action = .verify_chain, .epoch = .handshake, .proof = .chain, .to = .client_possession },
    .{ .role = .server, .from = .client_possession, .action = .certificate_verify, .epoch = .handshake, .proof = .possession, .to = .client_finished },
    .{ .role = .server, .from = .client_finished, .action = .finished, .epoch = .handshake, .proof = .finished, .to = .connected, .boundary = true },
};
pub const AdvanceError = error{ UnexpectedMessage, WrongEpoch, MissingProof, RecordAlignment, Closed };
pub const State = struct {
    role: Role,
    mode: Mode,
    auth: Auth = .none,
    phase: Phase = .start,
    retried: bool = false,
    requested_certificate: bool = false,
    pub fn advance(self: *State, action: Action, epoch: Epoch, proof: Proof, boundary: bool) AdvanceError!void {
        @setRuntimeSafety(true);
        if (self.phase == .failed) return error.Closed;
        errdefer self.phase = .failed;
        if (self.phase == .connected) {
            if (epoch != .application) return error.WrongEpoch;
            if (proof != .parsed) return error.MissingProof;
            if (action == .ticket and self.role == .client) return;
            if (action == .key_update and self.mode == .stream) {
                if (!boundary) return error.RecordAlignment;
                return;
            }
            return error.UnexpectedMessage;
        }
        for (edges) |edge| {
            if (edge.role != self.role or edge.from != self.phase or edge.action != action) continue;
            if (edge.epoch != epoch) return error.WrongEpoch;
            if (edge.proof != proof) return error.MissingProof;
            if (edge.boundary and !boundary) return error.RecordAlignment;
            if (self.role == .client and self.phase == .local_flight) {
                if (action == .local_finished and self.requested_certificate) return error.MissingProof;
                if (action != .local_finished and !self.requested_certificate) return error.UnexpectedMessage;
            }
            if (action == .hello_retry and self.retried) return error.UnexpectedMessage;
            if (self.role == .server and action == .certificate_request and self.auth == .none) return error.UnexpectedMessage;
            if (self.role == .server and action == .certificate and self.phase == .certificate_request and self.auth != .none) return error.MissingProof;
            if (action == .empty_certificate and self.auth == .required) return error.MissingProof;
            if (action == .hello_retry) self.retried = true;
            if (action == .certificate_request) self.requested_certificate = true;
            self.phase = edge.to;
            if (self.role == .server and action == .local_finished and !self.requested_certificate) self.phase = .client_finished;
            return;
        }
        return error.UnexpectedMessage;
    }
    pub fn fail(self: *State) void {
        self.phase = .failed;
    }
};
comptime {
    std.debug.assert(@sizeOf(State) <= 16);
}
test {
    _ = @import("State_test.zig");
}
