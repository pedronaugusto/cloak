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
pub const Messages = @import("handshake/Messages.zig");
test {
    _ = Messages;
}
pub const Possession = @import("handshake/Possession.zig");
test {
    _ = Possession;
}
pub const Transcripts = @import("handshake/Transcripts.zig");
test {
    _ = Transcripts;
}
pub const Client = @import("handshake/Client.zig");
test {
    _ = Client;
}
