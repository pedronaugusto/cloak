//! A kernel record layer the tests play: it takes a connection's keys through an installer, as
//! a kernel would, and seals and opens that direction's records with cloak's own record code
//! from those keys alone. A connection that hands out a wrong key, IV or record number shows it
//! at the software peer, which opens the records with the keys it derived itself.
const std = @import("std");
const Keys = @import("../tls/offload/Keys.zig");
const Protection = @import("../tls/record/Protection.zig");
const suites = @import("../tls/crypto/Suite.zig");

const Kernel = @This();

rx: ?Protection = null,
tx: ?Protection = null,
/// Whether it takes a second install of a direction (a TLS 1.3 key update), as Linux 6.14 does.
rekeys: bool = true,
/// The next install fails with this.
refuse: ?Keys.InstallError = null,
installs: usize = 0,
/// What the last install carried, for the tests that check the hand-over itself.
last: ?struct { version: Keys.Version, cipher: Keys.Cipher, sequence: u64, iv: [12]u8, max_payload: ?u16 } = null,
/// What `Connection.offload` installs through.
installer: Keys.Installer = .{ .installFn = install },

pub fn deinit(self: *Kernel) void {
    if (self.rx) |*p| p.deinit();
    if (self.tx) |*p| p.deinit();
    self.* = undefined;
}

fn install(installer: *Keys.Installer, direction: Keys.Direction, keys: *const Keys) Keys.InstallError!void {
    const self: *Kernel = @fieldParentPtr("installer", installer);
    if (self.refuse) |err| {
        self.refuse = null;
        return err;
    }
    const slot = switch (direction) {
        .read => &self.rx,
        .write => &self.tx,
    };
    if (slot.* != null and !self.rekeys) return error.RekeyUnsupported;
    if (!acceptable(keys)) return error.Unsupported;
    if (slot.*) |*old| old.deinit();
    slot.* = @as(Protection, undefined);
    errdefer slot.* = null;
    protectionOf(&slot.*.?, keys) catch return error.Unsupported;
    self.installs += 1;
    self.last = .{ .version = keys.version, .cipher = keys.cipher, .sequence = keys.sequence, .iv = keys.iv.expose().*, .max_payload = keys.max_payload };
}

fn suiteOf(comptime cipher: Keys.Cipher) suites.Suite13 {
    return switch (cipher) {
        .aes_128_gcm => .aes_128_gcm_sha256,
        .aes_256_gcm => .aes_256_gcm_sha384,
        .chacha20_poly1305 => .chacha20_poly1305_sha256,
        .aes_128_ccm => .aes_128_ccm_sha256,
    };
}

/// Whether handed-out keys alone make record protection: TLS 1.2 GCM and CCM records carry
/// their number as the explicit nonce, so the IV's tail must be that number.
fn acceptable(keys: *const Keys) bool {
    if (keys.version != .tls12) return true;
    const fixed = keys.cipher.record().fixedIvLength12();
    return fixed != 4 or std.mem.readInt(u64, keys.iv.expose()[4..12], .big) == keys.sequence;
}

/// Makes `protection` from handed-out keys, at their record number.
fn protectionOf(protection: *Protection, keys: *const Keys) !void {
    switch (keys.version) {
        .tls12 => {
            const cipher = keys.cipher.record();
            try protection.init12(cipher, keys.keyBytes(), keys.iv.expose()[0..cipher.fixedIvLength12()], .{});
        },
        .tls13 => switch (keys.cipher) {
            inline else => |cipher| {
                const suite = comptime suiteOf(cipher);
                const len = comptime cipher.keyLength();
                protection.* = .{ .state = @unionInit(@FieldType(Protection, "state"), @tagName(suite), undefined) };
                try @field(protection.state, @tagName(suite)).init(keys.key.expose()[0..len], keys.iv.expose(), .{});
            },
        },
    }
    switch (protection.state) {
        inline else => |*e| e.sequence = .fromRaw(keys.sequence),
    }
}

/// Seals what the application writes to the socket: one record of `content`.
pub fn seal(self: *Kernel, gpa: std.mem.Allocator, record_type: u8, plaintext: []const u8) ![]u8 {
    const out = try gpa.alloc(u8, plaintext.len + Protection.max_overhead);
    errdefer gpa.free(out);
    const content: Protection.Content = @fromBackingInt(record_type);
    const wire = try self.tx.?.seal(content, plaintext, 0, out);
    return gpa.realloc(out, wire.len);
}

pub const Opened = struct { record_type: u8, bytes: []u8 };

/// Opens one record from the peer, as the kernel's receive path does.
pub fn open(self: *Kernel, gpa: std.mem.Allocator, wire: []const u8) !Opened {
    const out = try gpa.alloc(u8, wire.len);
    errdefer gpa.free(out);
    const plain = try self.rx.?.open(wire, out);
    const copy = try gpa.dupe(u8, plain.bytes);
    gpa.free(out);
    return .{ .record_type = @backingInt(plain.content), .bytes = copy };
}

/// The number of the next record the kernel seals or opens in `direction`.
pub fn records(self: *const Kernel, direction: Keys.Direction) u64 {
    const slot = switch (direction) {
        .read => &self.rx,
        .write => &self.tx,
    };
    return slot.*.?.records();
}
