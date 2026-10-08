//! Immutable credentials and certificate verification for TLS consumers.
const std = @import("std");

/// Builds and retains immutable trust material before traffic.
pub const Trust = @import("Trust.zig");
/// Parses and retains bounded immutable private-key material.
pub const PrivateKey = @import("PrivateKey.zig");
/// Retains a key-matched certificate chain for server or client use.
pub const Identity = @import("Identity.zig");
/// Constructs immutable client authentication material.
pub const ClientAuth = @import("ClientAuth.zig");

/// Portable bounded certificate verification.
pub const verify = @import("verify.zig");
/// Request vocabulary and accepted-path evidence.
pub const types = @import("types.zig");
/// Native policy plus portable floors and owned request-bound receipt.
pub const NativeVerification = @import("NativeVerification.zig");
/// Caller-owned native verification jobs.
pub const services = @import("services.zig");

test {
    @setRuntimeSafety(true);
    std.testing.refAllDecls(@This());
    _ = @import("Trust.zig");
    _ = @import("verify.zig");
    _ = @import("services.zig");
    _ = @import("NativeVerification.zig");
    _ = @import("credentials.zig");
    _ = @import("PrivateKey.zig");
    _ = @import("Identity.zig");
    _ = @import("ClientAuth.zig");
    _ = @import("credentials/Key.zig");
    _ = @import("credentials/Rsa.zig");
    _ = @import("credentials/Des3.zig");
    _ = @import("credentials/Pem.zig");
    _ = @import("credentials/Cbc.zig");
    _ = @import("credentials/Parser_test.zig");
    _ = @import("Verification.zig");
    _ = @import("wire.zig");
    _ = @import("types.zig");
    _ = @import("certificate.zig");
    _ = @import("credentials/Primality.zig");
    _ = @import("credentials/Montgomery.zig");
    _ = @import("services/Budget.zig");
    _ = @import("services/Job.zig");
    _ = @import("services/Path.zig");
    _ = @import("services/macos.zig");
    _ = @import("services/windows.zig");
}
