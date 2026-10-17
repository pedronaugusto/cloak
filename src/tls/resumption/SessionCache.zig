//! A client's resumption cache: tickets from servers, kept by a key that binds everything the
//! session's authority depended on (the caller's namespace, the server name and reference
//! identity, ALPN, transport, verification policy and trust generation, the client identity).
//! A connection takes at most one ticket and uses it once: a ticket is a bearer token that links
//! connections, so it is never offered twice. Bounded by entries, bytes and tickets per key, with
//! expiry; one lock covers bounded sections, and allocation and erasure happen outside it.
//! There is no process-global cache and no persistence.
const std = @import("std");
const aegis = @import("aegis");
const suites = @import("../crypto/Suite.zig");
const Group = @import("../crypto/Group.zig").Group;

pub const Options = struct {
    /// Tickets kept across every key.
    max_entries: usize = 256,
    /// Bytes of tickets and their records across every key.
    max_bytes: usize = 1 << 20,
    /// Tickets kept for one key; the oldest goes first.
    per_key: usize = 4,
};

/// The longest ticket kept; a server sending a longer one gets no resumption.
pub const max_ticket = 16 * 1024;

/// One ticket and what the client knows of its session.
pub const Entry = struct {
    key: [32]u8,
    sequence: u64 = 0,
    ticket: []u8,
    /// A TLS 1.3 ticket carries a PSK of its suite's hash; a TLS 1.2 one the master secret.
    version: suites.Version,
    suite: suites.Suite,
    secret: aegis.Secret([48]u8),
    /// TLS 1.2: the key exchange group of the session's full handshake.
    group: Group = .x25519,
    /// TLS 1.3: the ticket age obfuscator.
    age_add: u32,
    /// When it was received, in milliseconds of the calendar clock, for the ticket age.
    received_ms: i64,
    /// Seconds: when it may no longer be offered; when its session's full handshake ran; when the
    /// server's authentication of that handshake expires.
    expires: i64,
    origin: i64,
    auth_expires: i64,
    /// The server was authenticated under the key's verification policy.
    authenticated: bool,
    /// Private: the entry's bytes in the cache's byte budget, held while a slot holds it.
    charge: Bytes.Reservation = undefined,

    pub fn secretBytes(entry: *const Entry) []const u8 {
        return entry.secret.expose()[0..switch (entry.version) {
            .tls13 => suites.digestLength(entry.suite.tls13().?),
            .tls12 => 48,
        }];
    }
};

/// A ticket taken from the cache for one connection. Release it once the hello is answered.
pub const Taken = struct {
    cache: *SessionCache,
    entry: *Entry,

    pub fn release(taken: *Taken) void {
        taken.cache.free(taken.entry);
        taken.* = undefined;
    }
};

const SessionCache = @This();

const Bytes = aegis.bounded.Budget(usize);

const Table = struct {
    slots: []?*Entry,
    /// Bytes of the entries in slots, each charged by its own reservation.
    bytes: Bytes,
    sequence: u64 = 0,
};

gpa: std.mem.Allocator,
options: Options,
table: aegis.Guarded(Table),

pub const InitError = std.mem.Allocator.Error || error{InvalidOptions};

/// An empty cache; keep it at a stable address while connections use it.
pub fn init(gpa: std.mem.Allocator, options: Options) InitError!SessionCache {
    @setRuntimeSafety(true);
    if (options.max_entries == 0 or options.max_entries > 1 << 20 or options.per_key == 0 or options.per_key > 16 or options.max_bytes < @sizeOf(Entry) + 64) return error.InvalidOptions;
    const slots = try gpa.alloc(?*Entry, options.max_entries);
    @memset(slots, null);
    return .{ .gpa = gpa, .options = options, .table = .init(.{ .slots = slots, .bytes = .init(options.max_bytes) }) };
}

/// Erases every ticket. No connection may be using the cache.
pub fn deinit(self: *SessionCache) void {
    @setRuntimeSafety(true);
    const table = self.table.teardown();
    for (table.slots) |*slot| if (slot.*) |entry| {
        self.free(entry);
        slot.* = null;
    };
    self.gpa.free(table.slots);
    self.* = undefined;
}

/// Forgets every ticket, as when trust or policy changed under keys that cannot show it.
pub fn clear(self: *SessionCache) void {
    @setRuntimeSafety(true);
    var dropped: [64]?*Entry = @splat(null);
    while (true) {
        var n: usize = 0;
        {
            var guard = self.table.acquire();
            defer guard.deinit();
            const table = guard.value();
            for (table.slots) |*slot| if (slot.*) |entry| {
                if (n == dropped.len) break;
                dropped[n] = entry;
                n += 1;
                entry.charge.release();
                slot.* = null;
            };
        }
        for (dropped[0..n]) |entry| self.free(entry.?);
        if (n < dropped.len) return;
    }
}

/// Tickets held now.
pub fn count(self: *SessionCache) usize {
    var guard = self.table.acquire();
    defer guard.deinit();
    var n: usize = 0;
    for (guard.value().slots) |slot| n += @intFromBool(slot != null);
    return n;
}

fn cost(entry: *const Entry) usize {
    return @sizeOf(Entry) + entry.ticket.len;
}

fn free(self: *SessionCache, entry: *Entry) void {
    @setRuntimeSafety(true);
    entry.secret.deinit();
    std.crypto.secureZero(u8, entry.ticket);
    self.gpa.free(entry.ticket);
    std.crypto.secureZero(u8, std.mem.asBytes(entry));
    self.gpa.destroy(entry);
}

/// Takes the newest ticket of `version` for `key` that has not expired at `now` (seconds),
/// removing it. Expired tickets met on the way are dropped.
pub fn take(self: *SessionCache, key: *const [32]u8, version: suites.Version, now: i64) ?Taken {
    @setRuntimeSafety(true);
    var expired: [16]?*Entry = @splat(null);
    var expired_count: usize = 0;
    var found: ?*Entry = null;
    {
        var guard = self.table.acquire();
        defer guard.deinit();
        const table = guard.value();
        var best: ?usize = null;
        for (table.slots, 0..) |*slot, i| {
            const entry = slot.* orelse continue;
            if (!std.mem.eql(u8, &entry.key, key)) continue;
            if (entry.expires <= now) {
                if (expired_count < expired.len) {
                    expired[expired_count] = entry;
                    expired_count += 1;
                    entry.charge.release();
                    slot.* = null;
                }
                continue;
            }
            if (entry.version != version) continue;
            if (best == null or table.slots[best.?].?.sequence < entry.sequence) best = i;
        }
        if (best) |i| {
            found = table.slots[i];
            found.?.charge.release();
            table.slots[i] = null;
        }
    }
    for (expired[0..expired_count]) |entry| self.free(entry.?);
    return .{ .cache = self, .entry = found orelse return null };
}

pub const StoreError = std.mem.Allocator.Error || error{TicketTooLong};

/// What `store` copies in; the ticket and PSK are copied, the caller keeps its own.
pub const Fields = struct {
    key: *const [32]u8,
    ticket: []const u8,
    version: suites.Version = .tls13,
    suite: suites.Suite,
    secret: []const u8,
    group: Group = .x25519,
    age_add: u32,
    received_ms: i64,
    expires: i64,
    origin: i64,
    auth_expires: i64,
    authenticated: bool,
};

/// Keeps a ticket, displacing the key's oldest past `per_key` and the cache's oldest past
/// the entry or byte bound.
pub fn store(self: *SessionCache, fields: Fields) StoreError!void {
    @setRuntimeSafety(true);
    if (fields.ticket.len == 0 or fields.ticket.len > max_ticket) return error.TicketTooLong;
    const entry = try self.gpa.create(Entry);
    errdefer self.gpa.destroy(entry);
    const ticket = try self.gpa.dupe(u8, fields.ticket);
    entry.* = .{
        .key = fields.key.*,
        .ticket = ticket,
        .version = fields.version,
        .suite = fields.suite,
        .group = fields.group,
        .secret = .init(@splat(0)),
        .age_add = fields.age_add,
        .received_ms = fields.received_ms,
        .expires = fields.expires,
        .origin = fields.origin,
        .auth_expires = fields.auth_expires,
        .authenticated = fields.authenticated,
    };
    @memcpy(entry.secret.exposeMut()[0..fields.secret.len], fields.secret);
    if (cost(entry) > self.options.max_bytes) {
        self.free(entry);
        return;
    }
    var displaced: [16]?*Entry = @splat(null);
    var displaced_count: usize = 0;
    var placed = false;
    {
        var guard = self.table.acquire();
        defer guard.deinit();
        const table = guard.value();
        table.sequence += 1;
        entry.sequence = table.sequence;
        // The key's oldest tickets beyond its share, then the cache's oldest beyond its bounds.
        while (true) {
            var same: usize = 0;
            var used: usize = 0;
            var oldest: ?usize = null;
            var oldest_same: ?usize = null;
            for (table.slots, 0..) |slot, i| {
                const held = slot orelse continue;
                used += 1;
                if (oldest == null or table.slots[oldest.?].?.sequence > held.sequence) oldest = i;
                if (std.mem.eql(u8, &held.key, &entry.key)) {
                    same += 1;
                    if (oldest_same == null or table.slots[oldest_same.?].?.sequence > held.sequence) oldest_same = i;
                }
            }
            const victim = if (same >= self.options.per_key)
                oldest_same
            else if (used >= table.slots.len or table.bytes.remaining() < cost(entry))
                oldest
            else
                null;
            const i = victim orelse break;
            if (displaced_count == displaced.len) break;
            displaced[displaced_count] = table.slots[i];
            displaced_count += 1;
            table.slots[i].?.charge.release();
            table.slots[i] = null;
        }
        if (table.bytes.remaining() >= cost(entry)) for (table.slots) |*slot| if (slot.* == null) {
            entry.charge = table.bytes.reserve(cost(entry)) catch break;
            slot.* = entry;
            placed = true;
            break;
        };
    }
    for (displaced[0..displaced_count]) |held| self.free(held.?);
    if (!placed) self.free(entry);
}

test {
    _ = @import("SessionCache_test.zig");
}
