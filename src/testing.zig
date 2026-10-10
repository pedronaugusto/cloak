//! Test support shared by the TLS suites and the handshake benchmark: a scripted peer, and
//! drivers that run a client against it in memory.
pub const Suite = @import("tls/crypto/Suite.zig").Suite;
pub const Peer = @import("testing/Peer.zig");
pub const Pair = @import("testing/Pair.zig");
pub const QuicPair = @import("testing/QuicPair.zig");
pub const Loopback = @import("testing/Loopback.zig");
pub const ClientPeer = @import("testing/ClientPeer.zig");
pub const ServerPair = @import("testing/ServerPair.zig");
