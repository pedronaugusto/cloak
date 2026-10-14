//! DTLS 1.3 (RFC 9147) and DTLS 1.2 (RFC 6347) over datagrams: the same handshake as TLS,
//! carried by `Datagram`.
pub const Datagram = @import("dtls/Datagram.zig");
/// A DTLS server's stateless check of its client's address.
pub const Cookies = @import("dtls/Cookies.zig");
test {
    _ = Cookies;
    _ = Datagram;
    _ = @import("dtls/Window.zig");
    _ = @import("dtls/Record.zig");
    _ = @import("dtls/catalogue_test.zig");
    _ = @import("dtls/fuzz_test.zig");
}
