//! The record-free TLS 1.3 handshake for QUIC: handshake messages and traffic secrets per
//! encryption level, never records. Packet protection, CRYPTO offsets and retransmission
//! belong to the QUIC implementation that drives it.
pub const Handshake = @import("quic/Handshake.zig");
pub const Level = Handshake.Level;
test {
    _ = Handshake;
}
