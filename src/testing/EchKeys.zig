//! An ECH key pair for tests: its ECHConfig, a list of that one config, and the server's key.
const Ech = @import("../tls/handshake/Ech.zig");
const Hpke = @import("../tls/crypto/Hpke.zig");

const EchKeys = @This();

pair: Hpke.KeyPair,
config_buf: [128]u8,
config: []u8,
list_buf: [140]u8,
list: []u8,

/// A pair from `seed`, config id `id`, answering for `name`.
pub fn init(self: *EchKeys, seed: u8, id: u8, name: []const u8) !void {
    self.pair = Hpke.deriveKeyPair(&(@as([32]u8, @splat(seed))));
    self.config = try Ech.writeConfig(&self.config_buf, .{ .id = id, .public_key = self.pair.public, .public_name = name, .max_name_length = 24 });
    self.list = try Ech.writeList(&self.list_buf, &.{self.config});
}

pub fn deinit(self: *EchKeys) void {
    self.pair.deinit();
}

pub fn key(self: *const EchKeys) Ech.Key {
    return .{ .config = self.config, .secret = self.pair.secret.expose() };
}
