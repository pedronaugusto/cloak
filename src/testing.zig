//! Test support shared by the TLS suites and the handshake benchmark: a scripted peer, and
//! drivers that run a client against it in memory.
pub const Suite13 = @import("tls/crypto/Suite.zig").Suite13;
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
pub const p521_field = @import("crypto/field/p521.zig");
pub const nist_field = @import("crypto/field/nist.zig");
pub const s2n = @import("crypto/field/s2n.zig");
pub const x25519 = @import("crypto/x25519.zig");
pub const suites = @import("tls/crypto/Suite.zig");
pub const Exchange = @import("tls/crypto/Exchange.zig");
pub const Hpke = @import("tls/crypto/Hpke.zig");
pub const Duo = @import("testing/Duo.zig");
