//! Checked full-handshake transitions of TLS 1.3 and TLS 1.2, both roles. No record or QUIC
//! owner here.
//! Published aegis has no typestate module; this table remains always checked.
const std = @import("std");
pub const Role = enum { client, server };
pub const Mode = enum { stream, quic };
pub const Epoch = enum { initial, handshake, application };
pub const Auth = enum { none, optional, required };
pub const Version = enum { tls13, tls12 };
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
    // TLS 1.2, client role.
    server_certificate12,
    server_chain12,
    server_key_exchange12,
    server_request12,
    server_done12,
    local_flight12,
    local_key_exchange12,
    local_verify12,
    local_ccs12,
    local_finished12,
    peer_ccs12,
    peer_finished12,
    // TLS 1.2, server role.
    s_certificate12,
    s_key_exchange12,
    s_request12,
    s_done12,
    c_certificate12,
    c_chain12,
    c_key_exchange12,
    c_verify12,
    c_ccs12,
    c_finished12,
    s_ccs12,
    s_finished12,
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
    // TLS 1.2.
    server_key_exchange,
    server_hello_done,
    client_key_exchange,
    local_key_exchange,
    local_ccs,
    ccs,
};
pub const Proof = enum { parsed, chain, possession, finished };
const Edge = struct { version: Version = .tls13, role: Role, from: Phase, action: Action, epoch: Epoch, proof: Proof = .parsed, to: Phase, boundary: bool = false };
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
    // TLS 1.2 client. Everything before ChangeCipherSpec is plaintext (initial); the Finished
    // messages travel under the new keys (application). A CertificateVerify follows the key
    // exchange exactly when a certificate was sent (see `advance`).
    .{ .version = .tls12, .role = .client, .from = .hello, .action = .server_hello, .epoch = .initial, .to = .server_certificate12 },
    .{ .version = .tls12, .role = .client, .from = .server_certificate12, .action = .certificate, .epoch = .initial, .to = .server_chain12 },
    .{ .version = .tls12, .role = .client, .from = .server_chain12, .action = .verify_chain, .epoch = .initial, .proof = .chain, .to = .server_key_exchange12 },
    .{ .version = .tls12, .role = .client, .from = .server_key_exchange12, .action = .server_key_exchange, .epoch = .initial, .proof = .possession, .to = .server_request12 },
    .{ .version = .tls12, .role = .client, .from = .server_request12, .action = .certificate_request, .epoch = .initial, .to = .server_done12 },
    .{ .version = .tls12, .role = .client, .from = .server_request12, .action = .server_hello_done, .epoch = .initial, .to = .local_flight12, .boundary = true },
    .{ .version = .tls12, .role = .client, .from = .server_done12, .action = .server_hello_done, .epoch = .initial, .to = .local_flight12, .boundary = true },
    .{ .version = .tls12, .role = .client, .from = .local_flight12, .action = .local_certificate, .epoch = .initial, .to = .local_key_exchange12 },
    .{ .version = .tls12, .role = .client, .from = .local_flight12, .action = .local_empty_certificate, .epoch = .initial, .to = .local_key_exchange12 },
    .{ .version = .tls12, .role = .client, .from = .local_flight12, .action = .local_key_exchange, .epoch = .initial, .to = .local_ccs12 },
    .{ .version = .tls12, .role = .client, .from = .local_key_exchange12, .action = .local_key_exchange, .epoch = .initial, .to = .local_ccs12 },
    .{ .version = .tls12, .role = .client, .from = .local_verify12, .action = .local_certificate_verify, .epoch = .initial, .proof = .possession, .to = .local_ccs12 },
    .{ .version = .tls12, .role = .client, .from = .local_ccs12, .action = .local_ccs, .epoch = .initial, .to = .local_finished12 },
    .{ .version = .tls12, .role = .client, .from = .local_finished12, .action = .local_finished, .epoch = .application, .proof = .finished, .to = .peer_ccs12 },
    .{ .version = .tls12, .role = .client, .from = .peer_ccs12, .action = .ccs, .epoch = .initial, .to = .peer_finished12, .boundary = true },
    .{ .version = .tls12, .role = .client, .from = .peer_finished12, .action = .finished, .epoch = .application, .proof = .finished, .to = .connected, .boundary = true },
    // TLS 1.2 server.
    .{ .version = .tls12, .role = .server, .from = .hello, .action = .server_hello, .epoch = .initial, .to = .s_certificate12 },
    .{ .version = .tls12, .role = .server, .from = .s_certificate12, .action = .certificate, .epoch = .initial, .to = .s_key_exchange12 },
    .{ .version = .tls12, .role = .server, .from = .s_key_exchange12, .action = .server_key_exchange, .epoch = .initial, .proof = .possession, .to = .s_request12 },
    .{ .version = .tls12, .role = .server, .from = .s_request12, .action = .certificate_request, .epoch = .initial, .to = .s_done12 },
    .{ .version = .tls12, .role = .server, .from = .s_request12, .action = .server_hello_done, .epoch = .initial, .to = .c_key_exchange12 },
    .{ .version = .tls12, .role = .server, .from = .s_done12, .action = .server_hello_done, .epoch = .initial, .to = .c_certificate12 },
    .{ .version = .tls12, .role = .server, .from = .c_certificate12, .action = .certificate, .epoch = .initial, .to = .c_chain12 },
    .{ .version = .tls12, .role = .server, .from = .c_certificate12, .action = .empty_certificate, .epoch = .initial, .to = .c_key_exchange12 },
    .{ .version = .tls12, .role = .server, .from = .c_chain12, .action = .verify_chain, .epoch = .initial, .proof = .chain, .to = .c_key_exchange12 },
    .{ .version = .tls12, .role = .server, .from = .c_key_exchange12, .action = .client_key_exchange, .epoch = .initial, .to = .c_ccs12 },
    .{ .version = .tls12, .role = .server, .from = .c_verify12, .action = .certificate_verify, .epoch = .initial, .proof = .possession, .to = .c_ccs12 },
    .{ .version = .tls12, .role = .server, .from = .c_ccs12, .action = .ccs, .epoch = .initial, .to = .c_finished12, .boundary = true },
    .{ .version = .tls12, .role = .server, .from = .c_finished12, .action = .finished, .epoch = .application, .proof = .finished, .to = .s_ccs12, .boundary = true },
    .{ .version = .tls12, .role = .server, .from = .s_ccs12, .action = .local_ccs, .epoch = .initial, .to = .s_finished12 },
    .{ .version = .tls12, .role = .server, .from = .s_finished12, .action = .local_finished, .epoch = .application, .proof = .finished, .to = .connected },
};
pub const AdvanceError = error{ UnexpectedMessage, WrongEpoch, MissingProof, RecordAlignment, Closed };
pub const State = struct {
    role: Role,
    mode: Mode,
    version: Version = .tls13,
    auth: Auth = .none,
    phase: Phase = .start,
    retried: bool = false,
    requested_certificate: bool = false,
    /// TLS 1.2: a certificate was sent (client) or verified (server), so its CertificateVerify
    /// must follow the key exchange.
    certificate_proof: bool = false,
    pub fn advance(self: *State, action: Action, epoch: Epoch, proof: Proof, boundary: bool) AdvanceError!void {
        @setRuntimeSafety(true);
        if (self.phase == .failed) return error.Closed;
        errdefer self.phase = .failed;
        if (self.phase == .connected) {
            if (epoch != .application) return error.WrongEpoch;
            if (proof != .parsed) return error.MissingProof;
            // TLS 1.2 has no post-handshake handshake messages: no renegotiation, tickets or updates.
            if (self.version == .tls12) return error.UnexpectedMessage;
            if (action == .ticket and self.role == .client) return;
            if (action == .key_update and self.mode == .stream) {
                if (!boundary) return error.RecordAlignment;
                return;
            }
            return error.UnexpectedMessage;
        }
        for (edges) |edge| {
            if (edge.version != self.version or edge.role != self.role or edge.from != self.phase or edge.action != action) continue;
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
            if (self.role == .client and self.phase == .local_flight12) {
                if (action == .local_key_exchange and self.requested_certificate) return error.MissingProof;
                if (action != .local_key_exchange and !self.requested_certificate) return error.UnexpectedMessage;
            }
            // A server asking for a certificate sends the request before ServerHelloDone.
            if (self.role == .server and self.phase == .s_request12 and action == .server_hello_done and self.auth != .none) return error.MissingProof;
            if (action == .hello_retry) self.retried = true;
            if (action == .certificate_request) self.requested_certificate = true;
            self.phase = edge.to;
            if (self.version == .tls12) {
                if (self.role == .client and action == .local_certificate) self.certificate_proof = true;
                if (self.role == .server and action == .verify_chain) self.certificate_proof = true;
                if (self.certificate_proof and (action == .local_key_exchange or action == .client_key_exchange)) {
                    self.phase = if (self.role == .client) .local_verify12 else .c_verify12;
                }
            }
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
