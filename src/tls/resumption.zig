//! Session resumption state outside any one connection: the client's ticket cache and the
//! server's ticket keys, and the sealed state a ticket carries.
pub const SessionCache = @import("resumption/SessionCache.zig");
pub const TicketKeys = @import("resumption/TicketKeys.zig");
pub const Ticket = @import("resumption/Ticket.zig");
test {
    _ = SessionCache;
    _ = TicketKeys;
    _ = Ticket;
}
