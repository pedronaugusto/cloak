//! What a DTLS server's stateless cookie check (`Cookies.check`) admits: for DTLS 1.3, the
//! retry request the association starts from. A caller on a path validated otherwise (ICE)
//! admits with `.{}`.
const suites = @import("../crypto/Suite.zig");
const Group = @import("../crypto/Group.zig").Group;

/// The longest cookie: kind, key id, time, suite, group, hash length, fingerprint, hello hash and
/// MAC.
pub const max_cookie = 15 + 32 + 48 + 32;

retry: ?Retry = null,

pub const Retry = struct {
    suite: suites.Suite13,
    group: Group,
    /// Whether the retry request asked for `group`'s share (else it carried only the cookie).
    asked: bool,
    hello_hash: [48]u8,
    hash_len: u8,
    fingerprint: [32]u8,
    cookie: [max_cookie]u8,
    cookie_len: u8,

    pub fn cookieBytes(self: *const Retry) []const u8 {
        return self.cookie[0..self.cookie_len];
    }

    pub fn helloHash(self: *const Retry) []const u8 {
        return self.hello_hash[0..self.hash_len];
    }
};
