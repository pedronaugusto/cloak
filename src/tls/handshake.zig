//! Private checked handshake machinery; no stream record or QUIC transport state.
pub const State = @import("handshake/State.zig");
test {
    _ = State;
}
pub const Transcript = @import("handshake/Transcript.zig");
test {
    _ = Transcript;
}
pub const Hello = @import("handshake/Hello.zig");
test {
    _ = Hello;
}
pub const Schedule = @import("handshake/Schedule.zig");
test {
    _ = Schedule;
}
