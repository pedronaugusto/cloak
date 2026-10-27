//! A server's session-ticket keys: a ring the caller rotates with key material of its own
//! drawing, read by every server connection that shares it. Each rotation publishes an immutable
//! snapshot; a handshake borrows the current one for the length of one call. There is no thread,
//! timer or file here: the caller drives rotation and the clock.
//!
//! A key issues tickets for `rotation` after it is installed (or until the next rotation) and
//! opens them until its last ticket can have expired, `lifetime` later. A ring whose newest key
//! has stopped issuing issues nothing, so a forgotten rotation costs full handshakes, never a stale
//! key. Each ticket is sealed under a key derived from the ring key and a fresh 128-bit salt drawn
//! with the handshake's entropy, so no two tickets share a (key, nonce) pair however many
//! processes or restarts share one ring key, and there is no nonce state to coordinate.
const std = @import("std");
const aegis = @import("aegis");
const Kernels = @import("../crypto/Kernels.zig");
const types = @import("../../certificates.zig").types;

pub const Options = struct {
    /// How long a ticket lives, counted from the full handshake its session began with. At most
    /// seven days (RFC 8446 section 4.6.1).
    lifetime: std.Io.Duration = .fromSeconds(24 * 60 * 60),
    /// How long a key issues tickets after it is installed.
    rotation: std.Io.Duration = .fromSeconds(6 * 60 * 60),
};

/// Keys a snapshot holds: the issuing key and those still opening tickets.
pub const max_keys = 8;
pub const max_lifetime = 7 * 24 * 60 * 60;

pub const Key = struct {
    /// Names the key in its tickets; derived from the material, so it says nothing of it.
    id: [8]u8,
    material: aegis.Secret([32]u8),
    /// Seconds of the calendar clock.
    installed: i64,
    issue_until: i64,
    decrypt_until: i64,
};

/// One immutable ring of keys, newest first.
pub const Ring = struct {
    keys: [max_keys]Key = undefined,
    count: usize = 0,
    /// Seconds a ticket lives from its session's full handshake.
    lifetime: i64,

    /// The key that issues tickets at `now`, if any.
    pub fn issuing(ring: *const Ring, now: i64) ?*const Key {
        if (ring.count == 0) return null;
        const key = &ring.keys[0];
        if (now < key.installed or now >= key.issue_until) return null;
        return key;
    }

    /// The key named `id` that still opens tickets at `now`.
    pub fn find(ring: *const Ring, id: *const [8]u8, now: i64) ?*const Key {
        for (ring.keys[0..ring.count]) |*key| {
            if (std.mem.eql(u8, &key.id, id) and now < key.decrypt_until) return key;
        }
        return null;
    }

    /// Moves the keys into `destination`, each material by its owner's `moveInto`, which erases
    /// the source: how a ring built on the stack enters its shared block.
    pub fn moveInto(ring: *Ring, destination: *Ring) void {
        destination.* = .{ .count = ring.count, .lifetime = ring.lifetime };
        for (ring.keys[0..ring.count], destination.keys[0..ring.count]) |*from, *to| {
            to.* = .{ .id = from.id, .material = undefined, .installed = from.installed, .issue_until = from.issue_until, .decrypt_until = from.decrypt_until };
            from.material.moveInto(&to.material);
        }
        ring.* = undefined;
    }
};

/// The keys' material is the ring's only secret: an id is derived from its key and says nothing
/// of it, and the times are public.
fn erase(ring: *Ring) void {
    for (ring.keys[0..ring.count]) |*key| key.material.deinit();
    ring.* = undefined;
}

const Handle = aegis.Shared(Ring, erase);

/// A borrowed snapshot; release it at the end of the call that acquired it.
pub const Snapshot = struct {
    handle: Handle,

    pub fn ring(snapshot: *const Snapshot) *const Ring {
        return snapshot.handle.get();
    }

    pub fn release(snapshot: *Snapshot) void {
        snapshot.handle.release();
    }
};

const TicketKeys = @This();

gpa: std.mem.Allocator,
lifetime: i64,
rotation: i64,
current: aegis.Guarded(?Handle) = .init(null),

pub const InitError = error{InvalidOptions};

/// An empty ring: it issues and opens nothing until the first `rotate`. Keep it at a stable
/// address while connections use it.
pub fn init(gpa: std.mem.Allocator, options: Options) InitError!TicketKeys {
    @setRuntimeSafety(true);
    const lifetime = types.spanSeconds(options.lifetime);
    const rotation = types.spanSeconds(options.rotation);
    if (lifetime <= 0 or lifetime > max_lifetime or rotation <= 0 or rotation > max_lifetime) return error.InvalidOptions;
    // safe: both were just bounded by seven days.
    return .{ .gpa = gpa, .lifetime = @intCast(lifetime), .rotation = @intCast(rotation) };
}

/// Erases every key. No connection may be using the ring.
pub fn deinit(self: *TicketKeys) void {
    @setRuntimeSafety(true);
    const slot = self.current.teardown();
    if (slot.*) |*handle| handle.release();
    slot.* = null;
}

pub const RotateError = std.mem.Allocator.Error || error{ InvalidKey, DuplicateKey };

/// Installs `material` as the issuing key at `now`. The previous key stops issuing and keeps
/// opening its tickets until they expire; keys past that are erased. Material is the caller's
/// fresh 32 random bytes (`std.Io.randomSecure`, or a key service's); all zeros, a missing
/// key's usual stand-in, is refused, and so is material the ring already holds.
pub fn rotate(self: *TicketKeys, material: *const [32]u8, now: std.Io.Timestamp) RotateError!void {
    @setRuntimeSafety(true);
    const timing = aegis.secret.Timing.begin();
    defer timing.end();
    if (std.mem.allEqual(u8, material, 0)) return error.InvalidKey;
    const at = types.seconds(now);
    var digest: [32]u8 = undefined;
    aegis.secret.scrubbed(Kernels.depth, std.crypto.auth.hmac.sha2.HmacSha256.create, .{ &digest, "cloak ticket key id", material });
    const id = digest[0..8].*;
    while (true) {
        var old = self.acquire();
        defer if (old) |*snapshot| snapshot.release();
        var next: Ring = .{ .lifetime = self.lifetime };
        next.keys[0] = .{
            .id = id,
            .material = .init(material.*),
            .installed = at,
            .issue_until = at +| self.rotation,
            .decrypt_until = at +| self.rotation +| self.lifetime,
        };
        next.count = 1;
        if (old) |*snapshot| for (snapshot.ring().keys[0..snapshot.ring().count]) |*key| {
            if (std.mem.eql(u8, &key.id, &id)) {
                erase(&next);
                return error.DuplicateKey;
            }
            if (at >= key.decrypt_until or next.count == max_keys) continue;
            // A key issues until the next one is installed; the tickets it issued live on.
            const stopped = @min(key.issue_until, at);
            next.keys[next.count] = .{
                .id = key.id,
                .material = .init(key.material.expose().*),
                .installed = key.installed,
                .issue_until = stopped,
                .decrypt_until = @min(key.decrypt_until, stopped +| self.lifetime),
            };
            next.count += 1;
        };
        var made = Handle.createFrom(self.gpa, &next) catch |err| {
            erase(&next);
            return err;
        };
        // Publish only over the snapshot this was built from; a concurrent rotation means rebuilding.
        var replaced: ?Handle = null;
        var swapped = false;
        {
            var guard = self.current.acquire();
            defer guard.deinit();
            const slot = guard.value();
            const same = if (slot.*) |*h| (if (old) |*o| h.get() == o.ring() else false) else old == null;
            if (same) {
                replaced = slot.*;
                slot.* = made;
                swapped = true;
            }
        }
        if (swapped) {
            if (replaced) |*handle| handle.release();
            return;
        }
        made.release();
    }
}

/// The current snapshot, retained until released; null before the first rotation.
pub fn acquire(self: *TicketKeys) ?Snapshot {
    @setRuntimeSafety(true);
    var guard = self.current.acquire();
    defer guard.deinit();
    const slot = guard.value();
    const handle = if (slot.*) |*h| h else return null;
    return .{ .handle = handle.retain() };
}

test {
    _ = @import("TicketKeys_test.zig");
}
