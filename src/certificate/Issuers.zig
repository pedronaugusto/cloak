//! Immutable borrowed-DER issuer index, prepared before traffic by the trust owner.
const std = @import("std");
const aegis = @import("aegis");
const Certificate = @import("Certificate.zig");
const Name = @import("Name.zig");
const Issuers = @This();
gpa: std.mem.Allocator,
/// The caller retains all DER and this descriptor list throughout the index lifetime.
anchors: []const []const u8,
storage: []Entry,
entries: []const Entry,
pub const Entry = struct { key: [32]u8, der: []const u8, index: usize };
pub const Limits = struct { anchors: usize = 4096, bytes: usize = 16 * 1024 * 1024 };
pub const InitError = Certificate.ParseError || std.mem.Allocator.Error || error{VerificationLimit};
pub fn init(gpa: std.mem.Allocator, anchors: []const []const u8, limits: Limits) InitError!Issuers {
    @setRuntimeSafety(true);
    if (anchors.len > limits.anchors) return error.VerificationLimit;
    var bytes: usize = 0;
    for (anchors) |der| bytes = (aegis.int.Checked(usize).init(bytes).add(der.len) catch return error.VerificationLimit).raw();
    if (bytes > limits.bytes) return error.VerificationLimit;
    const storage = try gpa.alloc(Entry, anchors.len);
    errdefer gpa.free(storage);
    var parsed: usize = 0;
    for (anchors, 0..) |der, index| {
        // Unusable anchors cannot pass verification; do not let an unrelated
        // malformed/unsupported candidate poison every other issuer bucket.
        const cert = Certificate.parse(der, .{}) catch continue;
        storage[parsed] = .{ .key = try Name.key(cert.subject), .der = der, .index = index };
        parsed += 1;
    }
    std.mem.sortUnstable(Entry, storage[0..parsed], {}, less);
    var count: usize = 0;
    for (storage[0..parsed]) |entry| {
        if (count != 0 and std.mem.eql(u8, storage[count - 1].der, entry.der)) continue;
        storage[count] = entry;
        count += 1;
    }
    return .{ .gpa = gpa, .anchors = anchors, .storage = storage, .entries = storage[0..count] };
}
pub fn find(self: *const Issuers, name: []const u8) Name.Error![]const Entry {
    @setRuntimeSafety(true);
    const id = try Name.key(name);
    return self.entries[self.bound(id, false)..self.bound(id, true)];
}
fn bound(self: *const Issuers, id: [32]u8, upper: bool) usize {
    @setRuntimeSafety(true);
    var start: usize = 0;
    var end = self.entries.len;
    while (start < end) {
        const middle = start + (end - start) / 2;
        const order = std.mem.order(u8, &self.entries[middle].key, &id);
        if (order == .lt or (upper and order == .eq)) start = middle + 1 else end = middle;
    }
    return start;
}
fn less(_: void, a: Entry, b: Entry) bool {
    @setRuntimeSafety(true);
    const order = std.mem.order(u8, &a.key, &b.key);
    if (order != .eq) return order == .lt;
    const der_order = std.mem.order(u8, a.der, b.der);
    return if (der_order == .eq) a.index < b.index else der_order == .lt;
}
pub fn deinit(self: *Issuers) void {
    @setRuntimeSafety(true);
    self.gpa.free(self.storage);
    self.* = undefined;
}
test {
    _ = @import("Issuers_test.zig");
}
