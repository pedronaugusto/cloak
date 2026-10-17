pub const Der = @import("wire/Der.zig");
/// The TLS presentation language's length-prefixed fields, shared by TLS and by the certificate
/// evidence that uses its encoding (RFC 6962 timestamps).
pub const Reader = @import("wire/Reader.zig");
test {
    _ = @import("wire/Der.zig");
    _ = @import("wire/Der_test.zig");
}
