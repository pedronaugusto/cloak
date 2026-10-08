//! Deep-owned inputs, retained by the executor until its last completion.
const std = @import("std");
const types = @import("../types.zig");
const OwnedRequest = @This();
gpa: std.mem.Allocator,
storage: []align(@alignOf(types.AnchorPolicy)) u8,
request: types.Request,
anchors: []const []const u8,
pub const InitError = std.mem.Allocator.Error || error{ServiceLimit};
pub fn init(gpa: std.mem.Allocator, request: types.Request, anchors: []const []const u8) InitError!OwnedRequest {
    @setRuntimeSafety(true);
    const storage = try gpa.alignedAlloc(u8, .of(types.AnchorPolicy), try byteSize(request, anchors));
    errdefer gpa.free(storage);
    var buffer = std.heap.FixedBufferAllocator.init(storage);
    const a = buffer.allocator();
    var owned = request;
    owned.chain = try slices(a, request.chain);
    if (request.identity == .dns) owned.identity = .{ .dns = try a.dupe(u8, request.identity.dns) };
    owned.pins = try a.dupe([32]u8, request.pins);
    owned.policy.required_policies = try slices(a, request.policy.required_policies);
    owned.evidence.crls = try slices(a, request.evidence.crls);
    owned.evidence.ocsp = try slices(a, request.evidence.ocsp);
    const policies = try a.dupe(types.AnchorPolicy, request.anchor_policies);
    for (policies) |*p| {
        p.name_constraints = try a.dupe(u8, p.name_constraints);
        p.required_policies = try slices(a, p.required_policies);
    }
    owned.anchor_policies = policies;
    return .{ .gpa = gpa, .storage = storage, .request = owned, .anchors = try slices(a, anchors) };
}
/// An upper bound including alignment slack for every copied slice. One backing
/// allocation prevents arena growth/slack from escaping service admission.
pub fn byteSize(request: types.Request, anchors: []const []const u8) error{ServiceLimit}!usize {
    @setRuntimeSafety(true);
    var total: usize = 0;
    for ([_][]const []const u8{ request.chain, anchors, request.policy.required_policies, request.evidence.crls, request.evidence.ocsp }) |list| {
        try sizeAdd([]const u8, &total, list.len);
        for (list) |bytes| try sizeAdd(u8, &total, bytes.len);
    }
    if (request.identity == .dns) try sizeAdd(u8, &total, request.identity.dns.len);
    try sizeAdd([32]u8, &total, request.pins.len);
    try sizeAdd(types.AnchorPolicy, &total, request.anchor_policies.len);
    for (request.anchor_policies) |policy| {
        try sizeAdd(u8, &total, policy.name_constraints.len);
        try sizeAdd([]const u8, &total, policy.required_policies.len);
        for (policy.required_policies) |oid| try sizeAdd(u8, &total, oid.len);
    }
    return total;
}
fn sizeAdd(comptime T: type, total: *usize, count: usize) error{ServiceLimit}!void {
    @setRuntimeSafety(true);
    const bytes = std.math.mul(usize, @sizeOf(T), count) catch return error.ServiceLimit;
    const padded = std.math.add(usize, bytes, @alignOf(T) - 1) catch return error.ServiceLimit;
    total.* = std.math.add(usize, total.*, padded) catch return error.ServiceLimit;
}
fn slices(gpa: std.mem.Allocator, input: []const []const u8) std.mem.Allocator.Error![]const []const u8 {
    @setRuntimeSafety(true);
    const result = try gpa.alloc([]const u8, input.len);
    for (input, result) |bytes, *copy| copy.* = try gpa.dupe(u8, bytes);
    return result;
}
pub fn deinit(owned: *OwnedRequest) void {
    @setRuntimeSafety(true);
    owned.gpa.free(owned.storage);
    owned.* = undefined;
}
test {
    @setRuntimeSafety(true);
    _ = @import("OwnedRequest_test.zig");
}
