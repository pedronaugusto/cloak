//! Certificate value vocabulary shared by the parser and extension decoders.
const Algorithm = @import("Algorithm.zig");
const Name = @import("Name.zig");
pub const Limits = struct { bytes: usize = 65536, elements: usize = 4096, depth: usize = 24, extensions: usize = 64 };
pub const ParseError = Algorithm.Error || Name.Error || error{ InvalidCertificate, InvalidTime, DuplicateExtension, UnknownCriticalExtension };
pub const Extension = struct { oid: []const u8, critical: bool, value: []const u8 };
