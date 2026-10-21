//! The service requests of a client handshake and their answers. One gateway per
//! connection issues tokens, so a stale or repeated answer cannot reach a newer request.
const std = @import("std");
const aegis = @import("aegis");
const certificates = @import("../../certificates.zig");
const types = certificates.types;
const Client = @import("Client.zig");
const Machine = @import("Machine.zig");
const Alert = @import("../wire/Alert.zig").Alert;

pub const SignRequest = Client.SignRequest;

pub const Service = union(enum) {
    /// Exactly this many fresh CSPRNG bytes.
    entropy: usize,
    /// Real (calendar) time.
    time,
    /// Verify this chain and answer with the receipt or the failure.
    verify: types.Request,
    /// Sign this CertificateVerify content for the client certificate.
    sign: SignRequest,
};

pub const Request = struct { token: types.Token, service: Service };

/// Why the caller's verifier refused a chain, and the alert that says it (RFC 8446 section 6.2):
/// `untrusted` unknown_ca, `bad_certificate` bad_certificate (corrupt, or a signature that does
/// not verify), `expired` certificate_expired, `revoked` certificate_revoked, `bad_status`
/// bad_certificate_status_response (revocation evidence missing, stale or unacceptable: a staple
/// above all, RFC 6066 section 8), `unsupported` unsupported_certificate, `unknown`
/// certificate_unknown (any other reason the verifier gives: its own policy said no), `internal`
/// internal_error.
pub const VerifyFailure = enum { untrusted, bad_certificate, expired, revoked, bad_status, unsupported, unknown, internal };

pub const Answer = union(enum) {
    entropy: []const u8,
    entropy_failed,
    time: std.Io.Timestamp,
    verified: *const types.Verification,
    verification_failed: VerifyFailure,
    signature: []const u8,
    signing_failed,
};

pub const AnswerError = Client.Error || error{ StaleToken, NoRequest };

const Services = @This();

generation: types.ConnectionGeneration,
issued: u64 = 0,
open: ?types.Token = null,
rejection: VerifyFailure = .internal,

pub fn init(generation: types.ConnectionGeneration) Services {
    return .{ .generation = generation };
}

/// The service the handshake is waiting for, if any. Parameters wait on the QUIC owner.
pub fn request(self: *Services, client: Machine) ?Request {
    @setRuntimeSafety(true);
    const need = client.need();
    if (need == .none or need == .parameters) return null;
    if (self.open == null) {
        aegis.assert.invariant(self.issued != std.math.maxInt(u64), "a connection's request numbers never repeat");
        self.issued += 1;
        self.open = .{ .generation = self.generation, .id = .fromRaw(self.issued) };
    }
    const token = self.open.?;
    return .{
        .token = token,
        .service = switch (need) {
            .entropy => |e| .{ .entropy = e.len },
            .time => .time,
            .verify => .{ .verify = client.verification(token) },
            .sign => .{ .sign = client.signRequest() },
            .none, .parameters => unreachable, // filtered above
        },
    };
}

/// Delivers an answer to the request `token` names. A rejected scalar draw
/// (`InvalidEntropy`) is public and leaves the request open for a fresh one; every other
/// error is the caller's to treat as terminal.
pub fn answer(self: *Services, client: Machine, token: types.Token, response: Answer) AnswerError!void {
    @setRuntimeSafety(true);
    const open = self.open orelse return error.NoRequest;
    if (!token.eql(open)) return error.StaleToken;
    switch (response) {
        .entropy => |bytes| try client.provideEntropy(bytes),
        .time => |now| try client.provideTime(now),
        .verified => |receipt| try client.provideVerification(token, receipt),
        .signature => |signature| try client.provideSignature(signature),
        .entropy_failed => return error.EntropyUnavailable,
        .signing_failed => return error.SigningFailed,
        .verification_failed => |why| {
            client.rejectVerification();
            self.rejection = why;
            return error.VerificationRejected;
        },
    }
    self.open = null;
}

/// The alert that reports `err`, with the verifier's own verdict for a rejected chain.
pub fn alertFor(self: *const Services, err: anyerror) Alert {
    return switch (err) {
        error.VerificationRejected => switch (self.rejection) {
            .untrusted => .unknown_ca,
            .bad_certificate => .bad_certificate,
            .expired => .certificate_expired,
            .revoked => .certificate_revoked,
            .bad_status => .bad_certificate_status_response,
            .unsupported => .unsupported_certificate,
            .unknown => .certificate_unknown,
            .internal => .internal_error,
        },
        else => Client.alertFor(err),
    };
}
