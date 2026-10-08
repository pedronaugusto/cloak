const std = @import("std");
const builtin = @import("builtin");
const shakedown = @import("shakedown");
const Pem = @import("Pem.zig");
test "credential PEM strict armor and bounded inputs" {
    @setRuntimeSafety(true);
    var pem = Pem.init("junk-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----");
    try std.testing.expectError(error.InvalidPem, pem.next(std.testing.allocator, 1024));
    pem = Pem.init("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----");
    try std.testing.expectError(error.InputLimit, pem.next(std.testing.allocator, 8));
    var block = (try pem.next(std.testing.allocator, 1024)).?;
    defer block.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &.{0}, block.der);
    try std.testing.expectEqual(@as(?Pem.Block, null), try pem.next(std.testing.allocator, 1024));
}
test "credential PEM allocation failures" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    try std.testing.checkAllAllocationFailures(no_resize.allocator(), parse, .{});
}
fn parse(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var pem = Pem.init("-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----");
    var block = (try pem.next(gpa, 1024)).?;
    defer block.deinit(gpa);
}

test "catalogue_key_import_armor_limit_precedes_whitespace_scan" {
    @setRuntimeSafety(true);
    var pem = Pem.init("                  ");
    try std.testing.expectError(error.InputLimit, pem.next(std.testing.failing_allocator, 8));
    pem = Pem.init("        ");
    try std.testing.expectEqual(@as(?Pem.Block, null), try pem.next(std.testing.failing_allocator, 8));
}

// Observe erasure at the domain boundary where known synthetic private armor
// buffers are released. NoResize owns scheduling; this observer adds no faults.
const Erasure = struct {
    backing: std.mem.Allocator,
    observed: usize = 0,
    dirty: usize = 0,
    zeros: usize = 0,
    poisons: usize = 0,
    fn allocator(owner: *Erasure) std.mem.Allocator {
        @setRuntimeSafety(true);
        return .{ .ptr = owner, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn context(raw: *anyopaque) *Erasure {
        @setRuntimeSafety(true);
        return @ptrCast(@alignCast(raw)); // safe: this vtable receives the live aligned Erasure owned by the test
    }
    fn alloc(raw: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        @setRuntimeSafety(true);
        return context(raw).backing.rawAlloc(len, alignment, ret);
    }
    fn resize(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) bool {
        @setRuntimeSafety(true);
        return context(raw).backing.rawResize(bytes, alignment, len, ret);
    }
    fn remap(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, len: usize, ret: usize) ?[*]u8 {
        @setRuntimeSafety(true);
        return context(raw).backing.rawRemap(bytes, alignment, len, ret);
    }
    fn free(raw: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
        @setRuntimeSafety(true);
        const owner = context(raw);
        // This fixture allocates exactly six compact bytes and one DER byte.
        // The public END marker has a different length and is not secret-owned.
        if (bytes.len == 6 or bytes.len == 1) {
            owner.observed += 1;
            const zero = std.mem.allEqual(u8, bytes, 0);
            // std.mem.Allocator.free writes undefined before rawFree. The safe
            // compiler poisons that storage; rawFree cannot observe the prior wipe.
            const mode = builtin.mode;
            const poison = (mode == .safe or mode == .debug) and std.mem.allEqual(u8, bytes, 0xaa);
            owner.zeros += @intFromBool(zero);
            owner.poisons += @intFromBool(poison);
            owner.dirty += @intFromBool(!zero and !poison);
        }
        owner.backing.rawFree(bytes, alignment, ret);
    }
};
test "catalogue_key_import_pem_owned_buffers_clear_before_raw_free" {
    @setRuntimeSafety(true);
    var no_resize = shakedown.alloc.NoResize.init(std.testing.allocator);
    var erasure: Erasure = .{ .backing = no_resize.allocator() };
    try std.testing.checkAllAllocationFailures(erasure.allocator(), erased, .{});
    try std.testing.expect(erasure.observed >= 4);
    try std.testing.expectEqual(@as(usize, 0), erasure.dirty);
    std.debug.print("PEM release observations zero={d} allocator_poison={d} dirty={d}\n", .{ erasure.zeros, erasure.poisons, erasure.dirty });
}
fn erased(gpa: std.mem.Allocator) !void {
    @setRuntimeSafety(true);
    var pem = Pem.init("-----BEGIN PRIVATE KEY-----\nAQ==\n-----END PRIVATE KEY-----");
    var block = (try pem.next(gpa, 1024)).?;
    block.deinit(gpa);
    pem = Pem.init("-----BEGIN PRIVATE KEY-----\nAB==\n-----END PRIVATE KEY-----");
    const result = pem.next(gpa, 1024) catch |err| {
        if (err == error.OutOfMemory) return err;
        try std.testing.expect(err == error.InvalidPem);
        return;
    };
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit(gpa);
    }
    return error.InvalidArmorAccepted;
}
