//! Certificates, keys and trust policy, and TLS: one module, two namespaces.

/// Certificates, keys and trust policy independent of transport.
pub const certificates = @import("certificates.zig");
/// TLS 1.3, sans-I/O and over `std.Io`.
pub const tls = @import("tls.zig");

/// Builds and retains immutable trust material before traffic.
pub const Trust = certificates.Trust;
/// Parses and retains bounded immutable private-key material.
pub const PrivateKey = certificates.PrivateKey;
/// Retains a key-matched certificate chain for server or client use.
pub const Identity = certificates.Identity;
/// Constructs immutable client authentication material.
pub const ClientAuth = certificates.ClientAuth;

/// Portable bounded certificate verification.
pub const verify = certificates.verify;
/// Request vocabulary and accepted-path evidence.
pub const types = certificates.types;
/// Native policy plus portable floors and owned request-bound receipt.
pub const NativeVerification = certificates.NativeVerification;
/// Caller-owned native verification jobs.
pub const services = certificates.services;
