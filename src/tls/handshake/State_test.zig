const std = @import("std");
const S = @import("State.zig");
const at = @import("../../testing/StateAt.zig").at;
test "C2 catalogue_smack_authentication_skip_edges" {
    // Independent oracle: next inbound action for the normal full client path.
    const phases = [_]S.Phase{ .hello, .extensions, .certificate, .chain, .possession, .finished };
    const allowed = [_]S.Action{ .server_hello, .encrypted_extensions, .certificate, .verify_chain, .certificate_verify, .finished };
    const proofs = [_]S.Proof{ .parsed, .parsed, .parsed, .chain, .possession, .finished };
    const epochs = [_]S.Epoch{ .initial, .handshake, .handshake, .handshake, .handshake, .handshake };
    for (phases, allowed, proofs, epochs) |phase, legal, proof, epoch| {
        for (std.enums.values(S.Action)) |action| {
            if (action == legal or (phase == .hello and action == .hello_retry)) continue;
            var state: S.State = at(.client, .stream, phase, .{});
            try std.testing.expectError(error.UnexpectedMessage, state.advance(action, epoch, proof, true));
            try std.testing.expectEqual(.failed, state.phase());
            try std.testing.expectError(error.Closed, state.advance(legal, epoch, proof, true));
        }
    }
}
test "C2 catalogue_possession_verification_cannot_be_skipped" {
    for ([_]S.Role{ .client, .server }) |role| {
        for ([_]S.Proof{ .parsed, .chain, .finished }) |bad_proof| {
            var state: S.State = at(role, .stream, .possession, .{});
            try std.testing.expectError(error.MissingProof, state.advance(.certificate_verify, .handshake, bad_proof, true));
            try std.testing.expectEqual(.failed, state.phase());
        }
        var state: S.State = at(role, .stream, .finished, .{});
        const action: S.Action = if (role == .client) .finished else .local_finished;
        try std.testing.expectError(error.MissingProof, state.advance(action, .handshake, .parsed, true));
    }
}
test "C2 catalogue_key_change_record_alignment" {
    for ([_]S.Role{ .client, .server }) |role| {
        var hello: S.State = at(role, .stream, .hello, .{});
        try std.testing.expectError(error.RecordAlignment, hello.advance(.server_hello, .initial, .parsed, false));
        var finished: S.State = at(role, .stream, .finished, .{});
        try std.testing.expectError(error.RecordAlignment, finished.advance(if (role == .client) .finished else .local_finished, .handshake, .finished, false));
        var extensions: S.State = at(role, .stream, .extensions, .{});
        try std.testing.expectError(error.WrongEpoch, extensions.advance(.encrypted_extensions, .initial, .parsed, true));
    }
}
test "C2 retry once optional client absence and QUIC controls" {
    var state: S.State = S.State.init(.client, .stream);
    try state.advance(.client_hello, .initial, .parsed, true);
    try state.advance(.hello_retry, .initial, .parsed, true);
    try state.advance(.client_hello, .initial, .parsed, true);
    try std.testing.expectError(error.UnexpectedMessage, state.advance(.hello_retry, .initial, .parsed, true));
    for ([_]S.Auth{ .optional, .required }) |auth| {
        var server: S.State = at(.server, .stream, .client_certificate, .{ .auth = auth, .requested_certificate = true });
        if (auth == .required) try std.testing.expectError(error.MissingProof, server.advance(.empty_certificate, .handshake, .parsed, true)) else try server.advance(.empty_certificate, .handshake, .parsed, true);
    }
    var quic: S.State = at(.client, .quic, .connected, .{});
    try std.testing.expectError(error.UnexpectedMessage, quic.advance(.key_update, .application, .parsed, true));
}

test "C2 requested client authentication cannot skip its response" {
    var requested: S.State = at(.client, .stream, .local_flight, .{ .requested_certificate = true });
    try std.testing.expectError(error.MissingProof, requested.advance(.local_finished, .handshake, .finished, true));
    try std.testing.expectEqual(.failed, requested.phase());
    var absent: S.State = at(.client, .stream, .local_flight, .{});
    try std.testing.expectError(error.UnexpectedMessage, absent.advance(.local_certificate, .handshake, .parsed, true));
}
const Step = struct { action: S.Action, phase: S.Phase, proof: S.Proof = .parsed, epoch: S.Epoch = .handshake, boundary: bool = false };
const hello_flight = [_]Step{
    .{ .action = .client_hello, .phase = .hello, .epoch = .initial },
    .{ .action = .hello_retry, .phase = .retry, .epoch = .initial, .boundary = true },
    .{ .action = .client_hello, .phase = .hello, .epoch = .initial },
    .{ .action = .server_hello, .phase = .extensions, .epoch = .initial, .boundary = true },
    .{ .action = .encrypted_extensions, .phase = .certificate_request },
};
fn trace(state: *S.State, steps: []const Step) !void {
    for (steps) |step| {
        const before = state.*;
        var wrong = before;
        try std.testing.expectError(error.WrongEpoch, wrong.advance(step.action, if (step.epoch == .initial) .handshake else .initial, step.proof, true));
        try std.testing.expectEqual(.failed, wrong.phase());
        if (step.boundary) {
            wrong = before;
            try std.testing.expectError(error.RecordAlignment, wrong.advance(step.action, step.epoch, step.proof, false));
        }
        wrong = before;
        try std.testing.expectError(error.MissingProof, wrong.advance(step.action, step.epoch, if (step.proof == .parsed) .chain else .parsed, true));
        for (std.enums.values(S.Action)) |action| {
            if (action == step.action or alternative(before, action)) continue;
            wrong = before;
            const proof: S.Proof = switch (action) {
                .verify_chain => .chain,
                .certificate_verify, .local_certificate_verify => .possession,
                .finished, .local_finished => .finished,
                else => .parsed,
            };
            if (wrong.advance(action, step.epoch, proof, true)) |_| {
                try std.testing.expect(false);
            } else |_| {
                try std.testing.expectEqual(.failed, wrong.phase());
                try std.testing.expectError(error.Closed, wrong.advance(step.action, step.epoch, step.proof, true));
            }
        }
        try state.advance(step.action, step.epoch, step.proof, true);
        try std.testing.expectEqual(step.phase, state.phase());
    }
}
// Alternatives come from the independent flight scenarios, not implementation edges.
fn alternative(state: S.State, action: S.Action) bool {
    return switch (state.phase()) {
        .hello => action == .server_hello or (action == .hello_retry and !state.retried),
        .certificate_request => if (state.role == .client) action == .certificate or action == .certificate_request else if (state.auth == .none) action == .certificate else action == .certificate_request,
        .local_flight => state.role == .client and state.requested_certificate and (action == .local_certificate or action == .local_empty_certificate),
        .client_certificate => state.role == .server and state.auth == .optional and (action == .certificate or action == .empty_certificate),
        else => false,
    };
}
test "C2 independent full client traces absent empty and supplied credentials" {
    for ([_]S.Mode{ .stream, .quic }) |mode| for (0..3) |response| {
        var state: S.State = S.State.init(.client, mode);
        try trace(&state, &hello_flight);
        if (response != 0) try trace(&state, &.{.{ .action = .certificate_request, .phase = .certificate }});
        try trace(&state, &.{
            .{ .action = .certificate, .phase = .chain },
            .{ .action = .verify_chain, .phase = .possession, .proof = .chain },
            .{ .action = .certificate_verify, .phase = .finished, .proof = .possession },
            .{ .action = .finished, .phase = .local_flight, .proof = .finished, .boundary = true },
        });
        if (response == 1) try trace(&state, &.{.{ .action = .local_empty_certificate, .phase = .client_finished }});
        if (response == 2) try trace(&state, &.{
            .{ .action = .local_certificate, .phase = .client_possession },
            .{ .action = .local_certificate_verify, .phase = .client_finished, .proof = .possession },
        });
        try trace(&state, &.{.{ .action = .local_finished, .phase = .connected, .proof = .finished, .boundary = true }});
        try state.advance(.ticket, .application, .parsed, false);
        if (mode == .stream) try state.advance(.key_update, .application, .parsed, true) else try std.testing.expectError(error.UnexpectedMessage, state.advance(.key_update, .application, .parsed, true));
    };
}
test "C2 independent full server traces optional required and no client auth" {
    for ([_]S.Auth{ .none, .optional, .required }) |auth| for ([_]bool{ false, true }) |supplied| {
        if (auth == .required and !supplied) continue;
        var state: S.State = at(.server, .stream, .start, .{ .auth = auth });
        try trace(&state, &hello_flight);
        if (auth != .none) try trace(&state, &.{.{ .action = .certificate_request, .phase = .certificate }});
        try trace(&state, &.{
            .{ .action = .certificate, .phase = .possession },
            .{ .action = .certificate_verify, .phase = .finished, .proof = .possession },
            .{ .action = .local_finished, .phase = if (auth == .none) .client_finished else .client_certificate, .proof = .finished, .boundary = true },
        });
        if (auth != .none) {
            if (supplied) try trace(&state, &.{
                .{ .action = .certificate, .phase = .client_chain },
                .{ .action = .verify_chain, .phase = .client_possession, .proof = .chain },
                .{ .action = .certificate_verify, .phase = .client_finished, .proof = .possession },
            }) else try trace(&state, &.{.{ .action = .empty_certificate, .phase = .client_finished }});
        }
        try trace(&state, &.{.{ .action = .finished, .phase = .connected, .proof = .finished, .boundary = true }});
        try state.advance(.key_update, .application, .parsed, true);
        try std.testing.expectError(error.UnexpectedMessage, state.advance(.ticket, .application, .parsed, true));
    };
}
test "C5 resumed handshakes: no certificate flight either way, and resumption marked only at the hello" {
    // Client: after the ServerHello accepted a PSK, EncryptedExtensions leads straight to Finished.
    var client: S.State = S.State.init(.client, .stream);
    try client.advance(.client_hello, .initial, .parsed, true);
    try client.advance(.server_hello, .initial, .parsed, true);
    try client.markResumed();
    try client.advance(.encrypted_extensions, .handshake, .parsed, true);
    for ([_]S.Action{ .certificate_request, .certificate, .verify_chain, .certificate_verify }) |action| {
        var copy = client;
        try std.testing.expectError(error.UnexpectedMessage, copy.advance(action, .handshake, .parsed, true));
    }
    try client.advance(.finished, .handshake, .finished, true);
    try client.advance(.local_finished, .handshake, .finished, true);
    try std.testing.expectEqual(.connected, client.phase());
    // Server: no CertificateRequest or Certificate, its Finished after EncryptedExtensions, then
    // the client's Finished alone.
    var server: S.State = at(.server, .stream, .start, .{ .auth = .required });
    try server.advance(.client_hello, .initial, .parsed, true);
    try server.markResumed();
    try server.advance(.server_hello, .initial, .parsed, true);
    try server.advance(.encrypted_extensions, .handshake, .parsed, true);
    var request = server;
    try std.testing.expectError(error.UnexpectedMessage, request.advance(.certificate_request, .handshake, .parsed, true));
    try server.advance(.local_finished, .handshake, .finished, true);
    try std.testing.expectEqual(.client_finished, server.phase());
    try server.advance(.finished, .handshake, .finished, true);
    try std.testing.expectEqual(.connected, server.phase());
    // Marking a resumption anywhere else fails the state.
    var late: S.State = at(.client, .stream, .certificate_request, .{});
    try std.testing.expectError(error.UnexpectedMessage, late.markResumed());
    try std.testing.expectEqual(.failed, late.phase());
    var tls12: S.State = at(.server, .stream, .s_certificate12, .{ .version = .tls12 });
    try std.testing.expectError(error.UnexpectedMessage, tls12.markResumed());
}

test "C5 TLS 1.2 abbreviated handshakes and tickets: a NewSessionTicket exactly where promised" {
    // Client, resumed: the server's ticket, ChangeCipherSpec and Finished, then the client's.
    var client: S.State = at(.client, .stream, .hello, .{ .version = .tls12, .ticket12 = true });
    try client.markResumed();
    try client.advance(.server_hello, .initial, .parsed, true);
    try std.testing.expectEqual(.peer_ccs12, client.phase());
    var early_ccs = client;
    // The promised ticket cannot be skipped.
    try std.testing.expectError(error.MissingProof, early_ccs.advance(.ccs, .initial, .parsed, true));
    try client.advance(.ticket, .initial, .parsed, true);
    try client.advance(.ccs, .initial, .parsed, true);
    try client.advance(.finished, .application, .finished, true);
    try client.advance(.local_ccs, .initial, .parsed, true);
    try client.advance(.local_finished, .application, .finished, true);
    try std.testing.expectEqual(.connected, client.phase());
    // No ticket that was not promised, and none after the handshake.
    var unpromised: S.State = at(.client, .stream, .peer_ccs12, .{ .version = .tls12 });
    try std.testing.expectError(error.UnexpectedMessage, unpromised.advance(.ticket, .initial, .parsed, true));
    var after: S.State = at(.client, .stream, .connected, .{ .version = .tls12, .ticket12 = true });
    try std.testing.expectError(error.UnexpectedMessage, after.advance(.ticket, .application, .parsed, true));
    // A resumed client sends no certificate or key exchange.
    var resumed: S.State = at(.client, .stream, .hello, .{ .version = .tls12 });
    try resumed.markResumed();
    try resumed.advance(.server_hello, .initial, .parsed, true);
    var cert = resumed;
    try std.testing.expectError(error.UnexpectedMessage, cert.advance(.certificate, .initial, .parsed, true));
    // Server, resumed: its ticket, ChangeCipherSpec and Finished, then the client's two.
    var server: S.State = at(.server, .stream, .hello, .{ .version = .tls12, .ticket12 = true });
    try server.markResumed();
    try server.advance(.server_hello, .initial, .parsed, true);
    var no_ticket = server;
    try std.testing.expectError(error.MissingProof, no_ticket.advance(.local_ccs, .initial, .parsed, true));
    try server.advance(.local_ticket, .initial, .parsed, true);
    try server.advance(.local_ccs, .initial, .parsed, true);
    try server.advance(.local_finished, .application, .finished, true);
    try std.testing.expectEqual(.c_ccs12, server.phase());
    try server.advance(.ccs, .initial, .parsed, true);
    try server.advance(.finished, .application, .finished, true);
    try std.testing.expectEqual(.connected, server.phase());
}

test "C4 a TLS 1.2 handshake takes no retry request, and the table holds no rewritten step" {
    // Once TLS 1.2 is chosen at the hello, a retry request is TLS 1.3's alone.
    for ([_]S.Role{ .client, .server }) |role| {
        var state = at(role, .stream, .hello, .{});
        state.version = .tls12;
        try std.testing.expectError(error.UnexpectedMessage, state.advance(.hello_retry, .initial, .parsed, true));
        try std.testing.expectEqual(.failed, state.phase());
    }
    // A TLS 1.2 client that sent its certificate owes the CertificateVerify after its key exchange;
    // one that sent none goes straight to its ChangeCipherSpec.
    var sent = at(.client, .stream, .local_flight12, .{ .version = .tls12, .requested_certificate = true });
    try sent.advance(.local_certificate, .initial, .parsed, true);
    try sent.advance(.local_key_exchange, .initial, .parsed, true);
    try std.testing.expectEqual(.local_verify12, sent.phase());
    var empty = at(.client, .stream, .local_flight12, .{ .version = .tls12, .requested_certificate = true });
    try empty.advance(.local_empty_certificate, .initial, .parsed, true);
    try empty.advance(.local_key_exchange, .initial, .parsed, true);
    try std.testing.expectEqual(.local_ccs12, empty.phase());
    try std.testing.expectError(error.UnexpectedMessage, empty.advance(.local_certificate_verify, .initial, .possession, true));
}

test "C10 TLS 1.2 PSK path: no certificate or request either way, an unsigned hint at most" {
    // The client: after a ServerHello choosing a PSK suite, a Certificate or CertificateRequest
    // has no edge; a hint may come once, before ServerHelloDone.
    for ([_]S.Action{ .certificate, .certificate_request }) |action| {
        var client = S.State.init(.client, .stream);
        client.version = .tls12;
        try client.advance(.client_hello, .initial, .parsed, true);
        try client.markPsk12();
        try client.advance(.server_hello, .initial, .parsed, false);
        try std.testing.expectEqual(.server_key_exchange12, client.phase());
        try std.testing.expectError(error.UnexpectedMessage, client.advance(action, .initial, .parsed, false));
    }
    var client = S.State.init(.client, .stream);
    client.version = .tls12;
    try client.advance(.client_hello, .initial, .parsed, true);
    try client.markPsk12();
    try client.advance(.server_hello, .initial, .parsed, false);
    try client.advance(.server_key_exchange, .initial, .parsed, false);
    try std.testing.expectError(error.UnexpectedMessage, client.advance(.server_key_exchange, .initial, .parsed, false));
    client = S.State.init(.client, .stream);
    client.version = .tls12;
    try client.advance(.client_hello, .initial, .parsed, true);
    try client.markPsk12();
    try client.advance(.server_hello, .initial, .parsed, false);
    try client.advance(.server_hello_done, .initial, .parsed, true);
    // The client's flight is its identity alone: no certificate of its own.
    try std.testing.expectError(error.UnexpectedMessage, client.advance(.local_certificate, .initial, .parsed, true));
    // The server: ServerHello, ServerHelloDone, then the client's key exchange, never a certificate.
    var server = S.State.init(.server, .stream);
    server.version = .tls12;
    try server.advance(.client_hello, .initial, .parsed, true);
    try server.markPsk12();
    try std.testing.expectError(error.UnexpectedMessage, server.advance(.certificate, .initial, .parsed, true));
    server = S.State.init(.server, .stream);
    server.version = .tls12;
    try server.advance(.client_hello, .initial, .parsed, true);
    try server.markPsk12();
    try server.advance(.server_hello, .initial, .parsed, true);
    try server.advance(.server_hello_done, .initial, .parsed, true);
    try std.testing.expectEqual(.c_key_exchange12, server.phase());
    try std.testing.expectError(error.UnexpectedMessage, server.advance(.certificate, .initial, .parsed, true));
    // The decision is TLS 1.2's, before the ServerHello only.
    var late = S.State.init(.server, .stream);
    try late.advance(.client_hello, .initial, .parsed, true);
    try std.testing.expectError(error.UnexpectedMessage, late.markPsk12());
    var after = S.State.init(.client, .stream);
    after.version = .tls12;
    try after.advance(.client_hello, .initial, .parsed, true);
    try after.advance(.server_hello, .initial, .parsed, false);
    try std.testing.expectError(error.UnexpectedMessage, after.markPsk12());
}
