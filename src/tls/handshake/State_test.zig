const std = @import("std");
const S = @import("State.zig");
test "C2 catalogue_smack_authentication_skip_edges" {
    // Independent oracle: next inbound action for the normal full client path.
    const phases = [_]S.Phase{ .hello, .extensions, .certificate, .chain, .possession, .finished };
    const allowed = [_]S.Action{ .server_hello, .encrypted_extensions, .certificate, .verify_chain, .certificate_verify, .finished };
    const proofs = [_]S.Proof{ .parsed, .parsed, .parsed, .chain, .possession, .finished };
    const epochs = [_]S.Epoch{ .initial, .handshake, .handshake, .handshake, .handshake, .handshake };
    for (phases, allowed, proofs, epochs) |phase, legal, proof, epoch| {
        for (std.enums.values(S.Action)) |action| {
            if (action == legal or (phase == .hello and action == .hello_retry)) continue;
            var state: S.State = .{ .role = .client, .mode = .stream, .phase = phase };
            try std.testing.expectError(error.UnexpectedMessage, state.advance(action, epoch, proof, true));
            try std.testing.expectEqual(.failed, state.phase);
            try std.testing.expectError(error.Closed, state.advance(legal, epoch, proof, true));
        }
    }
}
test "C2 catalogue_possession_verification_cannot_be_skipped" {
    for ([_]S.Role{ .client, .server }) |role| {
        for ([_]S.Proof{ .parsed, .chain, .finished }) |bad_proof| {
            var state: S.State = .{ .role = role, .mode = .stream, .phase = .possession };
            try std.testing.expectError(error.MissingProof, state.advance(.certificate_verify, .handshake, bad_proof, true));
            try std.testing.expectEqual(.failed, state.phase);
        }
        var state: S.State = .{ .role = role, .mode = .stream, .phase = .finished };
        const action: S.Action = if (role == .client) .finished else .local_finished;
        try std.testing.expectError(error.MissingProof, state.advance(action, .handshake, .parsed, true));
    }
}
test "C2 catalogue_key_change_record_alignment" {
    for ([_]S.Role{ .client, .server }) |role| {
        var hello: S.State = .{ .role = role, .mode = .stream, .phase = .hello };
        try std.testing.expectError(error.RecordAlignment, hello.advance(.server_hello, .initial, .parsed, false));
        var finished: S.State = .{ .role = role, .mode = .stream, .phase = .finished };
        try std.testing.expectError(error.RecordAlignment, finished.advance(if (role == .client) .finished else .local_finished, .handshake, .finished, false));
        var extensions: S.State = .{ .role = role, .mode = .stream, .phase = .extensions };
        try std.testing.expectError(error.WrongEpoch, extensions.advance(.encrypted_extensions, .initial, .parsed, true));
    }
}
test "C2 retry once optional client absence and QUIC controls" {
    var state: S.State = .{ .role = .client, .mode = .stream };
    try state.advance(.client_hello, .initial, .parsed, true);
    try state.advance(.hello_retry, .initial, .parsed, true);
    try state.advance(.client_hello, .initial, .parsed, true);
    try std.testing.expectError(error.UnexpectedMessage, state.advance(.hello_retry, .initial, .parsed, true));
    for ([_]S.Auth{ .optional, .required }) |auth| {
        var server: S.State = .{ .role = .server, .mode = .stream, .phase = .client_certificate, .auth = auth, .requested_certificate = true };
        if (auth == .required) try std.testing.expectError(error.MissingProof, server.advance(.empty_certificate, .handshake, .parsed, true)) else try server.advance(.empty_certificate, .handshake, .parsed, true);
    }
    var quic: S.State = .{ .role = .client, .mode = .quic, .phase = .connected };
    try std.testing.expectError(error.UnexpectedMessage, quic.advance(.key_update, .application, .parsed, true));
}
