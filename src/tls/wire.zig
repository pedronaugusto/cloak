//! Private TLS wire parsers. All borrows end when the enclosing input lease ends.
pub const Extensions = @import("wire/Extensions.zig");
pub const Buffer = @import("wire/Buffer.zig");
test {
    _ = Extensions;
    _ = Buffer;
}
pub const Writer = @import("wire/Writer.zig");
pub const Alert = @import("wire/Alert.zig").Alert;
