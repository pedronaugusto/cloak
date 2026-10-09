//! Private TLS wire parsers. All borrows end when the enclosing input lease ends.
pub const Reader = @import("wire/Reader.zig");
pub const Extensions = @import("wire/Extensions.zig");
test {
    _ = Extensions;
}
