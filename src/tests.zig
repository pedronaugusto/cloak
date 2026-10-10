//! Package-wide test entry.
const std = @import("std");
const certificates = @import("certificates.zig");
test {
    @setRuntimeSafety(true);
    std.testing.refAllDecls(certificates);
    _ = @import("tls.zig");
    _ = @import("Trust.zig");
    _ = @import("verify.zig");
    _ = @import("services.zig");
    _ = @import("NativeVerification.zig");
    _ = @import("credentials.zig");
    _ = @import("PrivateKey.zig");
    _ = @import("Identity.zig");
    _ = @import("ClientAuth.zig");
    _ = @import("credentials/Key.zig");
    _ = @import("credentials/Sign.zig");
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
    _ = @import("crypto.zig");
}
