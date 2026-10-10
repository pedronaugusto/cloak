//! Bounded RFC 5280 policy tree expressed as parent edges and expected policies.
const std = @import("std");
const aegis = @import("aegis");
const C = @import("../certificate.zig");
const T = @import("../types.zig");
const Der = @import("../wire/Der.zig");
pub const Error = C.ParseError || std.mem.Allocator.Error || error{ PolicyViolation, VerificationLimit };
const Work = @import("Work.zig");
const any = C.Extensions.any_policy;
const Node = struct { valid: []const u8, origin: []const u8, expected: []const u8 };
pub fn check(gpa: std.mem.Allocator, path: []const C.Certificate, policy: T.Policy, anchor_policies: []const []const u8, limit: usize, work: *Work) Error!void {
    @setRuntimeSafety(true);
    if (limit == 0) return error.VerificationLimit;
    if (unrestricted(path, policy, anchor_policies)) return;

    const capacity = try nodeCapacity(path, limit, work);
    const a = try gpa.alloc(Node, capacity);
    defer gpa.free(a);
    const b = try gpa.alloc(Node, capacity);
    defer gpa.free(b);
    var old = a;
    var next = b;
    var count: usize = 1;
    old[0] = .{ .valid = any, .origin = any, .expected = any };
    const n = path.len - 1;
    var explicit: usize = if (policy.explicit_policy) 0 else n + 1;
    var mapping: usize = if (policy.inhibit_mapping) 0 else n + 1;
    var inhibit: usize = if (policy.inhibit_any) 0 else n + 1;
    // Anchors have explicit policy, not self-issued certificate policy processing.
    var index = n;
    while (index > 0) {
        index -= 1;
        const cert = &path[index];
        var used: usize = 0;
        if (cert.x509(32)) |extension| {
            var policies = try C.Extensions.sequence(extension.value);
            var has_any = false;
            while (!policies.empty()) {
                try work.charge(1);
                var p = (try policies.expect(0x30)).reader();
                const id = (try p.expect(6)).value;
                if (try work.equal(id, any)) {
                    has_any = true;
                    continue;
                }
                var matched = false;
                for (old[0..count]) |node| {
                    if (try work.equal(node.expected, id)) {
                        try add(next, &used, work, .{ .valid = id, .origin = try origin(node.origin, id, work), .expected = id });
                        matched = true;
                    }
                }
                if (!matched) for (old[0..count]) |node| {
                    if (try work.equal(node.valid, any)) try add(next, &used, work, .{ .valid = id, .origin = try origin(node.origin, id, work), .expected = id });
                };
            }
            if (has_any and (inhibit > 0 or (index > 0 and cert.selfIssued()))) {
                for (old[0..count]) |node| try add(next, &used, work, .{ .valid = node.expected, .origin = node.origin, .expected = node.expected });
            }
        }
        if (cert.x509(33)) |extension| {
            if (index == 0) return error.PolicyViolation;
            if (mapping == 0) {
                // Remove nodes whose issuer-domain-policy has an inhibited mapping.
                var j: usize = 0;
                while (j < used) {
                    if (try mapped(extension.value, next[j].valid, work)) {
                        used -= 1;
                        next[j] = next[used];
                    } else j += 1;
                }
            } else try applyMappings(extension.value, next, &used, work);
        }
        std.mem.swap([]Node, &old, &next);
        count = used;
        if (explicit == 0 and count == 0) return error.PolicyViolation;
        if (!cert.selfIssued() or index == 0) {
            explicit -|= 1;
            mapping -|= 1;
            inhibit -|= 1;
        }
        if (cert.x509(36)) |extension| {
            var r = try C.Extensions.sequence(extension.value);
            if (r.peek() == 0x80) explicit = @min(explicit, try Der.number((try r.next()).value));
            if (r.peek() == 0x81) mapping = @min(mapping, try Der.number((try r.next()).value));
        }
        if (cert.x509(54)) |extension| inhibit = @min(inhibit, try Der.number((try Der.single(extension.value, 2)).value));
    }
    if (explicit == 0 and count == 0) return error.PolicyViolation;
    if (policy.required_policies.len != 0 or anchor_policies.len != 0) {
        var accepted = false;
        for (old[0..count]) |node| {
            if (try intersection(node.origin, policy.required_policies, anchor_policies, work)) accepted = true;
        }
        if (!accepted) return error.PolicyViolation;
    }
}
fn nodeCapacity(path: []const C.Certificate, limit: usize, work: *Work) Error!usize {
    @setRuntimeSafety(true);
    var count: usize = 1;
    var peak: usize = 1;
    var index = path.len - 1;
    while (index > 0) {
        index -= 1;
        const cert = &path[index];
        var policies: usize = 0;
        var mappings: usize = 0;
        if (cert.x509(32)) |e| {
            var r = try C.Extensions.sequence(e.value);
            while (!r.empty()) {
                try work.charge(1);
                _ = try r.expect(0x30);
                policies += 1;
            }
        }
        if (cert.x509(33)) |e| {
            var r = try C.Extensions.sequence(e.value);
            while (!r.empty()) {
                try work.charge(1);
                _ = try r.expect(0x30);
                mappings += 1;
            }
        }
        // At most one child per old node per policy; mapping expansion adds at
        // most one node per mapping per child. Saturation preserves the work cap.
        count = @min(limit, (aegis.int.Checked(usize).init(count).mul(policies) catch aegis.int.Checked(usize).init(limit)).raw());
        count = @min(limit, (aegis.int.Checked(usize).init(count).mul(mappings + 1) catch aegis.int.Checked(usize).init(limit)).raw());
        peak = @max(peak, count);
    }
    return peak;
}
fn unrestricted(path: []const C.Certificate, policy: T.Policy, anchored: []const []const u8) bool {
    @setRuntimeSafety(true);
    if (policy.explicit_policy or policy.required_policies.len != 0 or anchored.len != 0) return false;
    for (path[0 .. path.len - 1]) |*cert| {
        for ([_]u8{ 32, 33, 36, 54 }) |id| if (cert.x509(id) != null) return false;
    }
    // With no policy extensions and no explicit-policy requirement, the RFC
    // policy tree is null and accepted. No nodes need allocation in that case.
    return true;
}
fn origin(prior: []const u8, id: []const u8, work: *Work) Error![]const u8 {
    @setRuntimeSafety(true);
    return if (try work.equal(prior, any)) id else prior;
}
fn intersection(id: []const u8, requested: []const []const u8, anchored: []const []const u8, work: *Work) Error!bool {
    @setRuntimeSafety(true);
    if (!try work.equal(id, any)) return try allowed(id, requested, work) and try allowed(id, anchored, work);
    // An anyPolicy node stands for one policy in the intersection, not two
    // independently chosen policies that could violate the anchor's restriction.
    if (requested.len == 0 or anchored.len == 0) return true;
    for (requested) |oid| if (try allowed(oid, anchored, work)) return true;
    return false;
}
fn allowed(id: []const u8, set: []const []const u8, work: *Work) Error!bool {
    @setRuntimeSafety(true);
    if (set.len == 0 or try work.equal(id, any)) return true;
    for (set) |s| if (try work.equal(s, any) or try work.equal(s, id)) return true;
    return false;
}
fn add(nodes: []Node, count: *usize, work: *Work, node: Node) Error!void {
    @setRuntimeSafety(true);
    try work.charge(1);
    for (nodes[0..count.*]) |p| if (try work.equal(p.valid, node.valid) and try work.equal(p.origin, node.origin) and try work.equal(p.expected, node.expected)) return;
    if (count.* == nodes.len) return error.VerificationLimit;
    nodes[count.*] = node;
    count.* += 1;
}
fn mapped(encoded: []const u8, issuer: []const u8, work: *Work) Error!bool {
    @setRuntimeSafety(true);
    var r = try C.Extensions.sequence(encoded);
    while (!r.empty()) {
        try work.charge(1);
        var m = (try r.expect(0x30)).reader();
        if (try work.equal((try m.expect(6)).value, issuer)) return true;
    }
    return false;
}
fn applyMappings(encoded: []const u8, nodes: []Node, count: *usize, work: *Work) Error!void {
    @setRuntimeSafety(true);
    // Snapshot before expanding one-to-many mappings. Newly mapped nodes cannot
    // become inputs to another mapping in the same certificate.
    const before = count.*;
    for (0..before) |i| {
        try work.charge(1);
        const node = nodes[i];
        var r = try C.Extensions.sequence(encoded);
        var first = true;
        while (!r.empty()) {
            try work.charge(1);
            var m = (try r.expect(0x30)).reader();
            const issuer = (try m.expect(6)).value;
            const subject = (try m.expect(6)).value;
            if (try work.equal(issuer, node.valid) or try work.equal(node.valid, any)) {
                const mapped_node: Node = .{ .valid = issuer, .origin = try origin(node.origin, issuer, work), .expected = subject };
                if (first and !try work.equal(node.valid, any)) {
                    nodes[i] = mapped_node;
                    first = false;
                } else try add(nodes, count, work, mapped_node);
            }
        }
    }
}
