//! Certificates, private keys and trust policy, independent of TLS/DTLS transports.
pub const Trust = @import("Trust.zig");
pub const PrivateKey = @import("PrivateKey.zig");
pub const Identity = @import("Identity.zig");
pub const ClientAuth = @import("ClientAuth.zig");
/// PKCS#12 (PFX) files read into a key and its certificates.
pub const Pkcs12 = @import("Pkcs12.zig");
pub const verify = @import("verify.zig");
/// Strict DER certificate parsing with borrowed public-key metadata.
pub const certificate = @import("certificate.zig");
/// Public-key signature verification over parsed certificate keys; no private operations.
pub const signature = @import("verify/signature.zig");
/// Public-key encryption to parsed keys (RSAES-OAEP); decryption is `PrivateKey.decrypt`'s.
pub const encryption = @import("verify/encryption.zig");
pub const types = @import("types.zig");
pub const NativeVerification = @import("NativeVerification.zig");
pub const services = @import("services.zig");
