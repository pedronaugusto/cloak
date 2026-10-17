//! A handshake `State` driven to a named phase through the machine's own edges, for tests that
//! start in the middle of a handshake. The path is the shortest one the table declares, without
//! a resumption or a provisioned key unless the phase needs one; on the way, the policy flags are set so each edge is
//! admitted, then set to what the test asks for.
const std = @import("std");
const S = @import("../tls/handshake/State.zig");

pub const Setup = struct {
    version: S.Version = .tls13,
    auth: S.Auth = .none,
    requested_certificate: bool = false,
    ticket12: bool = false,
    retried: bool = false,
};

pub fn at(role: S.Role, mode: S.Mode, phase: S.Phase, setup: Setup) S.State {
    var state = S.State.init(role, mode);
    switch (role) {
        .client => drive(S.ClientState, &S.client_lines, &state, phase, setup),
        .server => drive(S.ServerState, &S.server_lines, &state, phase, setup),
    }
    state.version = setup.version;
    state.auth = setup.auth;
    state.requested_certificate = setup.requested_certificate;
    state.ticket12 = setup.ticket12;
    state.retried = setup.retried;
    return state;
}

fn drive(comptime T: type, lines: anytype, state: *S.State, phase: S.Phase, setup: Setup) void {
    const path = route(T, lines, phase, setup.version, false) orelse route(T, lines, phase, setup.version, true) orelse @panic("StateAt: no path to the phase");
    for (path.lines[0..path.len]) |line| take(state, line) catch |err| std.debug.panic("StateAt: {s} on .{s}: {s}", .{ line.from, @tagName(line.on), @errorName(err) });
}

const Path = struct { lines: [64]Line, len: usize };
const Line = struct { from: []const u8, on: S.Event, rule_epoch: S.Epoch, rule_proof: S.Proof };

fn route(comptime T: type, lines: anytype, phase: S.Phase, version: S.Version, resume_ok: bool) ?Path {
    const Table = if (T == S.ClientState) S.Client else S.Server;
    const n = @typeInfo(T).@"enum".field_names.len;
    var previous: [n]?usize = @splat(null);
    var seen: [n]bool = @splat(false);
    var queue: [n]T = undefined;
    var head: usize = 0;
    var tail: usize = 0;
    queue[tail] = .start;
    tail += 1;
    seen[@backingInt(T.start)] = true;
    while (head < tail) {
        const at_state = queue[head];
        head += 1;
        if (Table.phase(at_state) == phase) {
            var reversed: Path = .{ .lines = undefined, .len = 0 };
            var cursor = at_state;
            while (previous[@backingInt(cursor)]) |i| {
                const line = lines[i];
                const rule = Table.rule(line.from, line.on);
                reversed.lines[reversed.len] = .{ .from = @tagName(line.from), .on = line.on, .rule_epoch = rule.epoch, .rule_proof = rule.proof };
                reversed.len += 1;
                cursor = line.from;
            }
            std.mem.reverse(Line, reversed.lines[0..reversed.len]);
            return reversed;
        }
        for (lines, 0..) |line, i| {
            if (line.from != at_state or seen[@backingInt(line.to)]) continue;
            // The decisions (a resumption, a provisioned key) only when no plain path reaches it.
            if (!resume_ok and (line.on == .resumed or line.on == .resumed12 or line.on == .psk12)) continue;
            // A version's own edges: TLS 1.2 events only on the way to a TLS 1.2 phase, and back.
            const twelve = line.on == .server_hello12 or line.on == .resumed12 or line.on == .psk12;
            if (twelve and version != .tls12) continue;
            if ((line.on == .server_hello or line.on == .resumed) and version == .tls12) continue;
            seen[@backingInt(line.to)] = true;
            previous[@backingInt(line.to)] = i;
            queue[tail] = line.to;
            tail += 1;
        }
    }
    return null;
}

fn take(state: *S.State, line: Line) S.AdvanceError!void {
    if (line.on == .resumed or line.on == .resumed12) {
        state.version = if (line.on == .resumed12) .tls12 else .tls13;
        return state.markResumed();
    }
    if (line.on == .psk12) {
        state.version = .tls12;
        return state.markPsk12();
    }
    if (line.on == .server_hello12) state.version = .tls12;
    const action: S.Action = if (line.on == .server_hello12) .server_hello else @fromBackingInt(@intCast(@backingInt(line.on)));
    const current = state.phase();
    // Policy flags that admit this edge.
    switch (action) {
        .local_certificate, .local_empty_certificate => state.requested_certificate = true,
        .local_finished => if (current == .local_flight) {
            state.requested_certificate = false;
        },
        .local_key_exchange => if (current == .local_flight12) {
            state.requested_certificate = false;
        },
        .certificate_request => if (state.role == .server and state.auth == .none) {
            state.auth = .optional;
        },
        .certificate => if (state.role == .server and current == .certificate_request) {
            state.auth = .none;
        },
        .empty_certificate => state.auth = .optional,
        .server_hello_done => if (state.role == .server and current == .s_request12) {
            state.auth = .none;
        },
        .ticket, .local_ticket => state.ticket12 = true,
        .ccs, .local_ccs => if (current == .peer_ccs12 or current == .s_ccs12) {
            state.ticket12 = false;
        },
        else => {},
    }
    const boundary = true;
    return state.advance(action, line.rule_epoch, line.rule_proof, boundary);
}
