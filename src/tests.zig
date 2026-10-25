//! Package-wide test entry.
const std = @import("std");
const certificates = @import("certificates.zig");
test {
    @setRuntimeSafety(true);
    std.testing.refAllDecls(certificates);
    _ = @import("tls.zig");
    _ = @import("cipher.zig");
    _ = @import("Trust.zig");
    _ = @import("verify.zig");
    _ = @import("services.zig");
    _ = @import("NativeVerification.zig");
    _ = @import("credentials.zig");
    _ = @import("PrivateKey.zig");
    _ = @import("Roca_test.zig");
    _ = @import("Identity.zig");
    _ = @import("Pkcs12.zig");
    _ = @import("credentials/Pbe.zig");
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
    _ = @import("services/Budget.zig");
    _ = @import("services/Job.zig");
    _ = @import("services/Path.zig");
    _ = @import("services/macos.zig");
    _ = @import("services/windows.zig");
    _ = @import("crypto.zig");
    _ = @import("RsaHandshake_test.zig");
}

test "the cipher kernels erase what the record kernels erase" {
    const Kernels = @import("tls/crypto/Kernels.zig");
    const aes = @import("crypto/aes.zig");
    try std.testing.expectEqual(Kernels.record_depth, aes.record_depth);
    try std.testing.expectEqual(Kernels.software_aes_depth, aes.software_depth);
}
