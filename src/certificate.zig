//! Strict DER certificates and borrowed public-key metadata.
pub const Certificate = @import("certificate/Certificate.zig");
pub const Limits = Certificate.Limits;
pub const ParseError = Certificate.ParseError;
pub const parse = Certificate.parse;
pub const Algorithm = @import("certificate/Algorithm.zig");
pub const PublicKey = Algorithm.PublicKey;
pub const parsePublicKey = Algorithm.publicKey;
pub const Name = @import("certificate/Name.zig");
pub const Issuers = @import("certificate/Issuers.zig");
pub const Extensions = @import("certificate/Extensions.zig");
test {
    _ = @import("certificate/Certificate.zig");
    _ = @import("certificate/Extensions.zig");
    _ = @import("certificate/Issuers.zig");
    _ = @import("certificate/Name.zig");
    _ = @import("certificate/Algorithm.zig");
    _ = @import("certificate/fields.zig");
    _ = @import("certificate/Certificate_test.zig");
    _ = @import("certificate/Name_test.zig");
    _ = @import("certificate/Extensions_test.zig");
    _ = @import("certificate/Issuers_test.zig");
}
