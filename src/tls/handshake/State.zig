//! Checked full-handshake transitions of TLS 1.3 and TLS 1.2, both roles. No record or QUIC
//! owner here.
//!
//! Each role is an aegis typestate machine: its topology is validated when it is analyzed (one
//! edge per state and event, every state reachable, no dead end) and a step is one table load.
//! Its states keep the history the protocol depends on (a resumed handshake, a certificate that
//! was asked for or sent), so no transition is rewritten after it is taken; `Phase` is what
//! callers see, the projection of a machine state. The policy the table cannot carry (epoch,
//! proof and record boundary per edge, the client-auth policy, a promised ticket, one retry) is
//! checked here before an edge is committed.
const std = @import("std");
const aegis = @import("aegis");
pub const Role = enum { client, server };
pub const Mode = @import("../crypto/Suite.zig").Transport;
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
    /// The server's NewSessionTicket came; its ChangeCipherSpec is next.
    ticket_seen12,
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
    /// This server's NewSessionTicket went out; its ChangeCipherSpec is next.
    s_ticket_sent12,
    s_finished12,
    connected,
    failed,
};
pub const Action = enum {
    client_hello,
    /// DTLS 1.2: a HelloVerifyRequest asks the hello again with a cookie.
    hello_verify,
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
    /// A TLS 1.2 server sends its NewSessionTicket.
    local_ticket,
};
pub const Proof = enum { parsed, chain, possession, finished };
/// What moves a machine: the handshake actions, plus the events no message names. A TLS 1.2
/// ServerHello is its own event (`server_hello12`), and so are the decisions to resume a session
/// (`resumed` in TLS 1.3, `resumed12` in TLS 1.2) and to authenticate by a provisioned key in
/// TLS 1.2 (`psk12`), each taken before the edges that differ.
pub const Event = blk: {
    const actions = @typeInfo(Action).@"enum".field_names;
    var names: [actions.len + 4][:0]const u8 = undefined;
    for (actions, 0..) |name, i| names[i] = name;
    names[actions.len] = "server_hello12";
    names[actions.len + 1] = "resumed";
    names[actions.len + 2] = "resumed12";
    names[actions.len + 3] = "psk12";
    var values: [names.len]u8 = undefined;
    for (&values, 0..) |*v, i| v.* = i;
    break :blk @Enum(u8, .exhaustive, &names, &values);
};

/// The client's states. Several project onto one `Phase`: the resumed TLS 1.3 extensions
/// (`extensions_psk`), and in TLS 1.2 the resumed path (`r_` states), the provisioned-key path
/// (`p_` states, no certificate either way) and the key exchange after a sent certificate
/// (`local_key_exchange_proof12`), whose CertificateVerify must follow.
pub const ClientState = enum {
    start,
    hello,
    retry,
    extensions,
    extensions_psk,
    certificate_request,
    certificate,
    chain,
    possession,
    finished,
    local_flight,
    client_possession,
    client_finished,
    server_certificate12,
    server_chain12,
    server_key_exchange12,
    server_request12,
    server_done12,
    local_flight12,
    local_key_exchange12,
    local_key_exchange_proof12,
    local_verify12,
    local_ccs12,
    local_finished12,
    peer_ccs12,
    ticket_seen12,
    peer_finished12,
    hello_resumed12,
    r_peer_ccs12,
    r_ticket_seen12,
    r_peer_finished12,
    r_local_ccs12,
    r_local_finished12,
    hello_psk12,
    p_server_key_exchange12,
    p_server_done12,
    p_local_flight12,
    connected,
};

/// The server's states. A TLS 1.3 server that asks for a certificate goes through the
/// `_asking` states, so its Finished leads to the client's certificate; TLS 1.2's verified
/// client chain leads to `c_key_exchange_proof12`, whose CertificateVerify must follow.
pub const ServerState = enum {
    start,
    hello,
    retry,
    hello_psk,
    extensions,
    extensions_psk,
    certificate_request,
    certificate,
    possession,
    possession_asking,
    finished,
    finished_asking,
    client_certificate,
    client_chain,
    client_possession,
    client_finished,
    s_certificate12,
    s_key_exchange12,
    s_request12,
    s_done12,
    c_certificate12,
    c_chain12,
    c_key_exchange12,
    c_key_exchange_proof12,
    c_verify12,
    c_ccs12,
    c_finished12,
    s_ccs12,
    s_ticket_sent12,
    s_finished12,
    hello_resumed12,
    r_s_ccs12,
    r_s_ticket_sent12,
    r_s_finished12,
    r_c_ccs12,
    r_c_finished12,
    hello_psk12,
    p_s_done12,
    connected,
};

/// What a step requires besides being declared: the epoch it arrives or leaves under, the
/// proof that completed it, and whether it must end its record (or QUIC level).
pub const Rule = struct { epoch: Epoch = .handshake, proof: Proof = .parsed, boundary: bool = false };
pub fn Line(comptime S: type) type {
    return struct { from: S, on: Event, to: S, rule: Rule = .{} };
}
const init_rule: Rule = .{ .epoch = .initial };
const init_end: Rule = .{ .epoch = .initial, .boundary = true };
/// The internal decisions carry no message, so no rule; they are taken by `markResumed`.
const decision: Rule = .{ .epoch = .initial };

/// Transcript commitment follows successful parsing/proof, once per wire message.
/// verify_chain is a service completion and contributes no transcript bytes.
pub const client_lines = [_]Line(ClientState){
    .{ .from = .start, .on = .client_hello, .to = .hello, .rule = init_rule },
    .{ .from = .hello, .on = .hello_retry, .to = .retry, .rule = init_end },
    // A datagram hello may be asked again with a cookie, before any version is chosen.
    .{ .from = .hello, .on = .hello_verify, .to = .start, .rule = init_end },
    .{ .from = .retry, .on = .client_hello, .to = .hello, .rule = init_rule },
    .{ .from = .hello, .on = .server_hello, .to = .extensions, .rule = init_end },
    .{ .from = .extensions, .on = .resumed, .to = .extensions_psk, .rule = decision },
    .{ .from = .extensions, .on = .encrypted_extensions, .to = .certificate_request },
    // A resumed handshake is authenticated by the PSK: no certificate flight in either direction.
    .{ .from = .extensions_psk, .on = .encrypted_extensions, .to = .finished },
    .{ .from = .certificate_request, .on = .certificate_request, .to = .certificate },
    .{ .from = .certificate_request, .on = .certificate, .to = .chain },
    .{ .from = .certificate, .on = .certificate, .to = .chain },
    .{ .from = .chain, .on = .verify_chain, .to = .possession, .rule = .{ .proof = .chain } },
    .{ .from = .possession, .on = .certificate_verify, .to = .finished, .rule = .{ .proof = .possession } },
    .{ .from = .finished, .on = .finished, .to = .local_flight, .rule = .{ .proof = .finished, .boundary = true } },
    .{ .from = .local_flight, .on = .local_finished, .to = .connected, .rule = .{ .proof = .finished, .boundary = true } },
    .{ .from = .local_flight, .on = .local_certificate, .to = .client_possession },
    .{ .from = .local_flight, .on = .local_empty_certificate, .to = .client_finished },
    .{ .from = .client_possession, .on = .local_certificate_verify, .to = .client_finished, .rule = .{ .proof = .possession } },
    .{ .from = .client_finished, .on = .local_finished, .to = .connected, .rule = .{ .proof = .finished, .boundary = true } },
    // TLS 1.2. Everything before ChangeCipherSpec is plaintext (initial); the Finished messages
    // travel under the new keys (application).
    .{ .from = .hello, .on = .server_hello12, .to = .server_certificate12, .rule = init_rule },
    .{ .from = .server_certificate12, .on = .certificate, .to = .server_chain12, .rule = init_rule },
    .{ .from = .server_chain12, .on = .verify_chain, .to = .server_key_exchange12, .rule = .{ .epoch = .initial, .proof = .chain } },
    .{ .from = .server_key_exchange12, .on = .server_key_exchange, .to = .server_request12, .rule = .{ .epoch = .initial, .proof = .possession } },
    .{ .from = .server_request12, .on = .certificate_request, .to = .server_done12, .rule = init_rule },
    .{ .from = .server_request12, .on = .server_hello_done, .to = .local_flight12, .rule = init_end },
    .{ .from = .server_done12, .on = .server_hello_done, .to = .local_flight12, .rule = init_end },
    .{ .from = .local_flight12, .on = .local_certificate, .to = .local_key_exchange_proof12, .rule = init_rule },
    .{ .from = .local_flight12, .on = .local_empty_certificate, .to = .local_key_exchange12, .rule = init_rule },
    .{ .from = .local_flight12, .on = .local_key_exchange, .to = .local_ccs12, .rule = init_rule },
    .{ .from = .local_key_exchange12, .on = .local_key_exchange, .to = .local_ccs12, .rule = init_rule },
    // A certificate sent means its CertificateVerify follows the key exchange.
    .{ .from = .local_key_exchange_proof12, .on = .local_key_exchange, .to = .local_verify12, .rule = init_rule },
    .{ .from = .local_verify12, .on = .local_certificate_verify, .to = .local_ccs12, .rule = .{ .epoch = .initial, .proof = .possession } },
    .{ .from = .local_ccs12, .on = .local_ccs, .to = .local_finished12, .rule = init_rule },
    .{ .from = .local_finished12, .on = .local_finished, .to = .peer_ccs12, .rule = .{ .epoch = .application, .proof = .finished } },
    .{ .from = .peer_ccs12, .on = .ticket, .to = .ticket_seen12, .rule = init_rule },
    .{ .from = .ticket_seen12, .on = .ccs, .to = .peer_finished12, .rule = init_end },
    .{ .from = .peer_ccs12, .on = .ccs, .to = .peer_finished12, .rule = init_end },
    .{ .from = .peer_finished12, .on = .finished, .to = .connected, .rule = .{ .epoch = .application, .proof = .finished, .boundary = true } },
    // An abbreviated handshake (RFC 5077 section 3.1): the server's ChangeCipherSpec and Finished,
    // after its NewSessionTicket when it said one follows, then the client's.
    .{ .from = .hello, .on = .resumed12, .to = .hello_resumed12, .rule = decision },
    .{ .from = .hello_resumed12, .on = .server_hello12, .to = .r_peer_ccs12, .rule = init_rule },
    .{ .from = .r_peer_ccs12, .on = .ticket, .to = .r_ticket_seen12, .rule = init_rule },
    .{ .from = .r_ticket_seen12, .on = .ccs, .to = .r_peer_finished12, .rule = init_end },
    .{ .from = .r_peer_ccs12, .on = .ccs, .to = .r_peer_finished12, .rule = init_end },
    .{ .from = .r_peer_finished12, .on = .finished, .to = .r_local_ccs12, .rule = .{ .epoch = .application, .proof = .finished, .boundary = true } },
    .{ .from = .r_local_ccs12, .on = .local_ccs, .to = .r_local_finished12, .rule = init_rule },
    .{ .from = .r_local_finished12, .on = .local_finished, .to = .connected, .rule = .{ .epoch = .application, .proof = .finished } },
    // A provisioned key (RFC 4279): no Certificate or CertificateRequest either way; a
    // ServerKeyExchange only to carry an identity hint, unsigned; then the client's identity,
    // and the rest as in a full handshake.
    .{ .from = .hello, .on = .psk12, .to = .hello_psk12, .rule = decision },
    .{ .from = .hello_psk12, .on = .server_hello12, .to = .p_server_key_exchange12, .rule = init_rule },
    .{ .from = .p_server_key_exchange12, .on = .server_key_exchange, .to = .p_server_done12, .rule = init_rule },
    .{ .from = .p_server_key_exchange12, .on = .server_hello_done, .to = .p_local_flight12, .rule = init_end },
    .{ .from = .p_server_done12, .on = .server_hello_done, .to = .p_local_flight12, .rule = init_end },
    .{ .from = .p_local_flight12, .on = .local_key_exchange, .to = .local_ccs12, .rule = init_rule },
};

pub const server_lines = [_]Line(ServerState){
    .{ .from = .start, .on = .client_hello, .to = .hello, .rule = init_rule },
    .{ .from = .hello, .on = .hello_retry, .to = .retry, .rule = init_end },
    .{ .from = .retry, .on = .client_hello, .to = .hello, .rule = init_rule },
    .{ .from = .hello, .on = .server_hello, .to = .extensions, .rule = init_end },
    .{ .from = .extensions, .on = .encrypted_extensions, .to = .certificate_request },
    .{ .from = .hello, .on = .resumed, .to = .hello_psk, .rule = decision },
    .{ .from = .hello_psk, .on = .server_hello, .to = .extensions_psk, .rule = init_end },
    .{ .from = .extensions_psk, .on = .encrypted_extensions, .to = .finished },
    // Asking for a client certificate takes the `_asking` path to the client's certificate.
    .{ .from = .certificate_request, .on = .certificate_request, .to = .certificate },
    .{ .from = .certificate, .on = .certificate, .to = .possession_asking },
    .{ .from = .possession_asking, .on = .certificate_verify, .to = .finished_asking, .rule = .{ .proof = .possession } },
    .{ .from = .finished_asking, .on = .local_finished, .to = .client_certificate, .rule = .{ .proof = .finished, .boundary = true } },
    // A server that asks for none waits only for the client's Finished.
    .{ .from = .certificate_request, .on = .certificate, .to = .possession },
    .{ .from = .possession, .on = .certificate_verify, .to = .finished, .rule = .{ .proof = .possession } },
    .{ .from = .finished, .on = .local_finished, .to = .client_finished, .rule = .{ .proof = .finished, .boundary = true } },
    .{ .from = .client_certificate, .on = .certificate, .to = .client_chain },
    .{ .from = .client_certificate, .on = .empty_certificate, .to = .client_finished },
    .{ .from = .client_chain, .on = .verify_chain, .to = .client_possession, .rule = .{ .proof = .chain } },
    .{ .from = .client_possession, .on = .certificate_verify, .to = .client_finished, .rule = .{ .proof = .possession } },
    .{ .from = .client_finished, .on = .finished, .to = .connected, .rule = .{ .proof = .finished, .boundary = true } },
    // TLS 1.2 server. A TLS 1.2 server sends its Finished last in a full handshake.
    .{ .from = .hello, .on = .server_hello12, .to = .s_certificate12, .rule = init_rule },
    .{ .from = .s_certificate12, .on = .certificate, .to = .s_key_exchange12, .rule = init_rule },
    .{ .from = .s_key_exchange12, .on = .server_key_exchange, .to = .s_request12, .rule = .{ .epoch = .initial, .proof = .possession } },
    .{ .from = .s_request12, .on = .certificate_request, .to = .s_done12, .rule = init_rule },
    .{ .from = .s_request12, .on = .server_hello_done, .to = .c_key_exchange12, .rule = init_rule },
    .{ .from = .s_done12, .on = .server_hello_done, .to = .c_certificate12, .rule = init_rule },
    .{ .from = .c_certificate12, .on = .certificate, .to = .c_chain12, .rule = init_rule },
    .{ .from = .c_certificate12, .on = .empty_certificate, .to = .c_key_exchange12, .rule = init_rule },
    // A verified client chain means its CertificateVerify follows the key exchange.
    .{ .from = .c_chain12, .on = .verify_chain, .to = .c_key_exchange_proof12, .rule = .{ .epoch = .initial, .proof = .chain } },
    .{ .from = .c_key_exchange12, .on = .client_key_exchange, .to = .c_ccs12, .rule = init_rule },
    .{ .from = .c_key_exchange_proof12, .on = .client_key_exchange, .to = .c_verify12, .rule = init_rule },
    .{ .from = .c_verify12, .on = .certificate_verify, .to = .c_ccs12, .rule = .{ .epoch = .initial, .proof = .possession } },
    .{ .from = .c_ccs12, .on = .ccs, .to = .c_finished12, .rule = init_end },
    .{ .from = .c_finished12, .on = .finished, .to = .s_ccs12, .rule = .{ .epoch = .application, .proof = .finished, .boundary = true } },
    .{ .from = .s_ccs12, .on = .local_ticket, .to = .s_ticket_sent12, .rule = init_rule },
    .{ .from = .s_ticket_sent12, .on = .local_ccs, .to = .s_finished12, .rule = init_rule },
    .{ .from = .s_ccs12, .on = .local_ccs, .to = .s_finished12, .rule = init_rule },
    .{ .from = .s_finished12, .on = .local_finished, .to = .connected, .rule = .{ .epoch = .application, .proof = .finished } },
    // Abbreviated: the server's ticket, ChangeCipherSpec and Finished, then the client's two.
    .{ .from = .hello, .on = .resumed12, .to = .hello_resumed12, .rule = decision },
    .{ .from = .hello_resumed12, .on = .server_hello12, .to = .r_s_ccs12, .rule = init_rule },
    .{ .from = .r_s_ccs12, .on = .local_ticket, .to = .r_s_ticket_sent12, .rule = init_rule },
    .{ .from = .r_s_ticket_sent12, .on = .local_ccs, .to = .r_s_finished12, .rule = init_rule },
    .{ .from = .r_s_ccs12, .on = .local_ccs, .to = .r_s_finished12, .rule = init_rule },
    .{ .from = .r_s_finished12, .on = .local_finished, .to = .r_c_ccs12, .rule = .{ .epoch = .application, .proof = .finished } },
    .{ .from = .r_c_ccs12, .on = .ccs, .to = .r_c_finished12, .rule = init_end },
    .{ .from = .r_c_finished12, .on = .finished, .to = .connected, .rule = .{ .epoch = .application, .proof = .finished, .boundary = true } },
    // A provisioned key: ServerHello and ServerHelloDone (no identity hint), then the client's
    // identity, and the rest as in a full handshake without a client certificate.
    .{ .from = .hello, .on = .psk12, .to = .hello_psk12, .rule = decision },
    .{ .from = .hello_psk12, .on = .server_hello12, .to = .p_s_done12, .rule = init_rule },
    .{ .from = .p_s_done12, .on = .server_hello_done, .to = .c_key_exchange12, .rule = init_rule },
};

/// One role's machine: the aegis topology and, beside it, each edge's rule.
fn Table(comptime S: type, comptime lines: []const Line(S)) type {
    return struct {
        pub const Machine = aegis.state.Machine(S, Event, .{
            .initial = .start,
            .terminal = &.{.connected},
            .edges = edges: {
                var out: [lines.len]aegis.state.Edge(S, Event) = undefined;
                for (lines, 0..) |line, i| out[i] = .{ .from = line.from, .on = line.on, .to = line.to };
                const final = out;
                break :edges &final;
            },
        });
        const states = @typeInfo(S).@"enum".field_names.len;
        const events = @typeInfo(Event).@"enum".field_names.len;
        const rules = blk: {
            @setEvalBranchQuota(20_000);
            var out: [states][events]Rule = @splat(@splat(.{}));
            for (lines) |line| out[@backingInt(line.from)][@backingInt(line.on)] = line.rule;
            break :blk out;
        };
        pub fn rule(from: S, on: Event) Rule {
            return rules[@backingInt(from)][@backingInt(on)];
        }
        /// The Phase a state shows callers: the name it shares, or the one listed beside it.
        pub fn phase(state: S) Phase {
            return switch (state) {
                inline else => |t| comptime projected(@tagName(t)),
            };
        }
    };
}
fn projected(comptime name: []const u8) Phase {
    const aliases = .{
        .{ "extensions_psk", .extensions },
        .{ "hello_psk", .hello },
        .{ "hello_resumed12", .hello },
        .{ "hello_psk12", .hello },
        .{ "possession_asking", .possession },
        .{ "finished_asking", .finished },
        .{ "local_key_exchange_proof12", .local_key_exchange12 },
        .{ "c_key_exchange_proof12", .c_key_exchange12 },
    };
    inline for (aliases) |alias| if (std.mem.eql(u8, alias[0], name)) return alias[1];
    // A resumed or provisioned-key TLS 1.2 state shows the phase of the full handshake it mirrors.
    if (std.mem.startsWith(u8, name, "r_") or std.mem.startsWith(u8, name, "p_")) return @field(Phase, name[2..]);
    return @field(Phase, name);
}
pub const Client = Table(ClientState, &client_lines);
pub const Server = Table(ServerState, &server_lines);

pub const AdvanceError = error{ UnexpectedMessage, WrongEpoch, MissingProof, RecordAlignment, Closed };
pub const State = struct {
    role: Role,
    mode: Mode,
    version: Version = .tls13,
    auth: Auth = .none,
    machine: union(Role) { client: Client.Machine.Runtime(void), server: Server.Machine.Runtime(void) },
    /// Set by a refused step or `fail`; nothing moves the machine again.
    failed: bool = false,
    retried: bool = false,
    requested_certificate: bool = false,
    /// TLS 1.2: the ServerHello said a NewSessionTicket follows, which then must, before the
    /// server's ChangeCipherSpec; without it none may come.
    ticket12: bool = false,
    /// DTLS: HelloVerifyRequests answered so far.
    verified: u2 = 0,

    pub fn init(role: Role, mode: Mode) State {
        return .{ .role = role, .mode = mode, .machine = switch (role) {
            .client => .{ .client = .init({}) },
            .server => .{ .server = .init({}) },
        } };
    }

    /// Where the handshake stands, as callers name it.
    pub fn phase(self: *const State) Phase {
        if (self.failed) return .failed;
        return switch (self.machine) {
            .client => |*m| Client.phase(m.current()),
            .server => |*m| Server.phase(m.current()),
        };
    }

    /// Marks the handshake resumed: in TLS 1.3 as the ServerHello is received (client) or chosen
    /// (server), before EncryptedExtensions; in TLS 1.2 before the ServerHello's edge is taken.
    /// Anywhere else the machine has no such edge, and the handshake fails.
    pub fn markResumed(self: *State) AdvanceError!void {
        if (self.failed) return error.Closed;
        errdefer self.failed = true;
        const event: Event = if (self.version == .tls12) .resumed12 else .resumed;
        switch (self.machine) {
            inline else => |*m| _ = m.step(event) catch return error.UnexpectedMessage,
        }
    }

    /// Marks a TLS 1.2 handshake authenticated by a provisioned key, before the ServerHello's
    /// edge is taken: the client as it reads a ServerHello choosing a PSK suite, the server as
    /// it chooses one. Anywhere else the machine has no such edge, and the handshake fails.
    pub fn markPsk12(self: *State) AdvanceError!void {
        if (self.failed) return error.Closed;
        errdefer self.failed = true;
        if (self.version != .tls12) return error.UnexpectedMessage;
        switch (self.machine) {
            inline else => |*m| _ = m.step(.psk12) catch return error.UnexpectedMessage,
        }
    }

    pub fn advance(self: *State, action: Action, epoch: Epoch, proof: Proof, boundary: bool) AdvanceError!void {
        @setRuntimeSafety(true);
        if (self.failed) return error.Closed;
        errdefer self.failed = true;
        const current = self.phase();
        if (current == .connected) {
            if (epoch != .application) return error.WrongEpoch;
            if (proof != .parsed) return error.MissingProof;
            // TLS 1.2 has no post-handshake handshake messages: no renegotiation, tickets or updates.
            if (self.version == .tls12) return error.UnexpectedMessage;
            if (action == .ticket and self.role == .client) return;
            if (action == .key_update and self.mode == .stream) {
                if (!boundary) return error.RecordAlignment;
                return;
            }
            // A DTLS record names its epoch, so what follows a KeyUpdate is under the keys it says.
            if (action == .key_update and self.mode == .datagram) return;
            return error.UnexpectedMessage;
        }
        const event: Event = if (self.version == .tls12 and action == .server_hello) .server_hello12 else @fromBackingInt(@intCast(@backingInt(action)));
        switch (self.machine) {
            inline else => |*m, role| {
                const T = if (role == .client) Client else Server;
                const edge = m.plan(event) catch return error.UnexpectedMessage;
                try self.admit(current, action, T.rule(edge.from, event), epoch, proof, boundary);
                // unreachable: the edge was planned from the current state a moment ago.
                m.commit(edge) catch unreachable;
            },
        }
    }

    /// The policy on an edge the machine declares: its rule, the client-auth policy, the
    /// promised ticket, one retry and DTLS's HelloVerifyRequests.
    fn admit(self: *State, current: Phase, action: Action, rule: Rule, epoch: Epoch, proof: Proof, boundary: bool) AdvanceError!void {
        // TLS 1.2: a NewSessionTicket exactly when the ServerHello promised one.
        if (self.version == .tls12 and (action == .ticket or action == .local_ticket) and !self.ticket12) return error.UnexpectedMessage;
        if (self.version == .tls12 and self.ticket12 and ((self.role == .client and current == .peer_ccs12 and action == .ccs) or (self.role == .server and current == .s_ccs12 and action == .local_ccs))) return error.MissingProof;
        if (rule.epoch != epoch) return error.WrongEpoch;
        if (rule.proof != proof) return error.MissingProof;
        if (rule.boundary and !boundary) return error.RecordAlignment;
        if (self.role == .client and current == .local_flight) {
            if (action == .local_finished and self.requested_certificate) return error.MissingProof;
            if (action != .local_finished and !self.requested_certificate) return error.UnexpectedMessage;
        }
        // A retry request is TLS 1.3's, once, and not after a HelloVerifyRequest.
        if (action == .hello_retry and (self.version != .tls13 or self.retried or self.verified != 0)) return error.UnexpectedMessage;
        // A HelloVerifyRequest is DTLS's alone, never after a retry request, at most three.
        if (action == .hello_verify) {
            if (self.mode != .datagram or self.retried or self.verified == 3) return error.UnexpectedMessage;
            self.verified += 1;
        }
        if (self.role == .server and action == .certificate_request and self.auth == .none) return error.UnexpectedMessage;
        if (self.role == .server and action == .certificate and current == .certificate_request and self.auth != .none) return error.MissingProof;
        if (action == .empty_certificate and self.auth == .required) return error.MissingProof;
        if (self.role == .client and current == .local_flight12) {
            if (action == .local_key_exchange and self.requested_certificate) return error.MissingProof;
            if (action != .local_key_exchange and !self.requested_certificate) return error.UnexpectedMessage;
        }
        // A server asking for a certificate sends the request before ServerHelloDone.
        if (self.role == .server and current == .s_request12 and action == .server_hello_done and self.auth != .none) return error.MissingProof;
        if (action == .hello_retry) self.retried = true;
        if (action == .certificate_request) self.requested_certificate = true;
    }

    pub fn fail(self: *State) void {
        self.failed = true;
    }
};
comptime {
    std.debug.assert(@sizeOf(State) <= 16);
}
test {
    _ = @import("State_test.zig");
}
