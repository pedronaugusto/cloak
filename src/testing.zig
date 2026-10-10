//! Test support shared by the TLS suites and the handshake benchmark: a scripted peer, and
//! drivers that run a client against it in memory.
pub const Suite = @import("tls/crypto/Suite.zig").Suite;
pub const Peer = @import("testing/Peer.zig");
pub const Pair = @import("testing/Pair.zig");
pub const QuicPair = @import("testing/QuicPair.zig");
pub const QuicLoop = @import("testing/QuicLoop.zig");
pub const Loopback = @import("testing/Loopback.zig");
pub const ClientPeer = @import("testing/ClientPeer.zig");
pub const ServerPair = @import("testing/ServerPair.zig");
/// The public surface and the private kernels the benchmarks measure, reached from this module
/// so a benchmark never imports the same file through two modules.
pub const cloak = @import("root.zig");
pub const ecdh = @import("credentials/Ecdh.zig");
pub const p256 = @import("crypto/p256.zig");
pub const suites = @import("tls/crypto/Suite.zig");
