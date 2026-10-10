//! Portable bounded path search. Inputs and time are supplied; no I/O or clock.
const std = @import("std");
const aegis = @import("aegis");
const Der = @import("../wire/Der.zig");
const C = @import("../certificate.zig");
const T = @import("../types.zig");
const V = @import("../types.zig").Verification;
const identity = @import("identity.zig");
const signatures = @import("signature.zig");
const constraints = @import("constraints.zig");
const policies = @import("policy.zig");
const revocation = @import("revocation.zig");
pub const Request = T.Request;
pub const VerifyError = C.ParseError || identity.Error || signatures.Error || constraints.Error || policies.Error || revocation.Error || V.InitError || error{ VerificationLimit, NoTrustedPath, InvalidValidity, InvalidCa, InvalidAnchorPolicy };
const Work = @import("Work.zig");
const Counters = struct { candidates: usize = 0, parses: usize = 0, signatures: usize = 0, rejected: usize = 0, parsed_bytes: usize = 0 };
const Search = struct {
    gpa: std.mem.Allocator,
    request: T.Request,
    anchors: []const []const u8,
    issuer_index: ?*const C.Issuers = null,
    path: []C.Certificate,
    count: usize = 0,
    work: Counters = .{},
    receipt: ?V = null,
    constraint_work: Work,
    policy_work: Work,

    fn init(gpa: std.mem.Allocator, request: T.Request, anchors: []const []const u8, index: ?*const C.Issuers, capacity: usize) VerifyError!*Search {
        @setRuntimeSafety(true);
        const self = try gpa.create(Search);
        errdefer gpa.destroy(self);
        const path = try gpa.alloc(C.Certificate, capacity);
        errdefer gpa.free(path);
        self.* = .{ .gpa = gpa, .request = request, .anchors = anchors, .issuer_index = index, .path = path, .constraint_work = .{ .remaining = request.limits.constraint_work }, .policy_work = .{ .remaining = request.limits.policy_work } };
        return self;
    }
    fn deinit(self: *Search) void {
        @setRuntimeSafety(true);
        self.gpa.free(self.path);
        const gpa = self.gpa;
        self.* = undefined;
        gpa.destroy(self);
    }
    fn charge(self: *Search, comptime field: []const u8, amount: usize) VerifyError!void {
        @setRuntimeSafety(true);
        const sum = (aegis.int.Checked(usize).init(@field(self.work, field)).add(amount) catch return error.VerificationLimit).raw();
        if (sum > @field(self.request.limits, field)) return error.VerificationLimit;
        @field(self.work, field) = sum;
    }
    fn parse(self: *Search, der: []const u8) VerifyError!C.Certificate {
        @setRuntimeSafety(true);
        try self.charge("parses", 1);
        try self.charge("parsed_bytes", der.len);
        return C.parse(der, .{ .bytes = self.request.limits.chain_bytes });
    }
    fn search(self: *Search) VerifyError!bool {
        @setRuntimeSafety(true);
        const child = &self.path[self.count - 1];
        // Charge every discovery, including unmatched same-subject floods.
        var direct = try self.anchorCandidates(child.subject);
        while (direct.next()) |candidate| {
            const der = candidate.der;
            const index = candidate.index;
            try self.charge("candidates", 1);
            if (self.issuer_index == null and try self.duplicate(self.anchors, index)) continue;
            if (std.mem.eql(u8, der, child.der)) {
                if (try self.accept(index)) return true;
                try self.charge("rejected", 1);
            }
        }
        if (self.count >= self.path.len) return false;
        // Consistent AKI/SKI candidates first; hint mismatch never suppresses a path.
        for (0..2) |priority| {
            var issuers = try self.anchorCandidates(child.issuer);
            while (issuers.next()) |candidate| {
                const der = candidate.der;
                const index = candidate.index;
                try self.charge("candidates", 1);
                if (self.cycle(der) or (self.issuer_index == null and try self.duplicate(self.anchors, index))) continue;
                const issuer = self.parse(der) catch |err| {
                    if (err == error.VerificationLimit) return err;
                    try self.charge("rejected", 1);
                    continue;
                };
                if (!C.Name.equal(child.issuer, issuer.subject) or (akiConsistent(child, &issuer) != (priority == 0))) continue;
                if (!try self.link(child, &issuer, true)) continue;
                self.path[self.count] = issuer;
                self.count += 1;
                const accepted = try self.accept(index);
                self.count -= 1;
                if (accepted) return true;
                try self.charge("rejected", 1);
            }
            for (self.request.chain[1..], 0..) |der, index| {
                try self.charge("candidates", 1);
                if (try self.duplicate(self.request.chain[1..], index) or self.cycle(der)) continue;
                const issuer = self.parse(der) catch |err| {
                    if (err == error.VerificationLimit) return err;
                    try self.charge("rejected", 1);
                    continue;
                };
                if (!C.Name.equal(child.issuer, issuer.subject) or (akiConsistent(child, &issuer) != (priority == 0))) continue;
                if (self.caBelow() + @intFromBool(!issuer.selfIssued()) > self.request.limits.intermediates) continue;
                if (!try self.link(child, &issuer, false)) continue;
                self.path[self.count] = issuer;
                self.count += 1;
                const accepted = try self.search();
                self.count -= 1;
                if (accepted) return true;
                try self.charge("rejected", 1);
            }
        }
        return false;
    }
    fn anchorCandidates(self: *Search, name: []const u8) VerifyError!AnchorIterator {
        @setRuntimeSafety(true);
        try self.charge("candidates", 1);
        return .{ .anchors = self.anchors, .selected = if (self.issuer_index) |index| try index.find(name) else null };
    }
    fn duplicate(self: *Search, candidates: []const []const u8, index: usize) VerifyError!bool {
        @setRuntimeSafety(true);
        // Each comparison is charged, including same-subject/identical floods.
        if (candidates[index].len > self.request.limits.chain_bytes) return false;
        for (candidates[0..index]) |prior| {
            try self.charge("candidates", 1);
            if (std.mem.eql(u8, prior, candidates[index])) return true;
        }
        return false;
    }
    fn cycle(self: *const Search, der: []const u8) bool {
        @setRuntimeSafety(true);
        for (self.path[0..self.count]) |cert| if (std.mem.eql(u8, der, cert.der)) return true;
        return false;
    }
    fn link(self: *Search, child: *const C.Certificate, issuer: *const C.Certificate, anchor: bool) VerifyError!bool {
        @setRuntimeSafety(true);
        if (!anchor) {
            if (issuer.serial.len == 1 and issuer.serial[0] == 0) return false;
            if (issuer.x509(35) == null) {
                if (!issuer.selfIssued()) return false;
                try self.charge("signatures", 1);
                signatures.verify(issuer.public_key, issuer.signature_algorithm, issuer.tbs, issuer.signature) catch return false;
            }
            if (issuer.x509(14) == null) return false;
            if (self.request.time < issuer.not_before or self.request.time > issuer.not_after) return false;
            const bc = issuer.x509(19) orelse return false;
            if (!bc.critical) return false;
            const basic = try C.Extensions.basic(bc.value);
            if (!basic.ca) return false;
            if (basic.path_length) |max| if (self.caBelow() > max) return false;
        }
        identity.purpose(issuer, self.request.purpose, true) catch return false;
        try self.charge("signatures", 1);
        signatures.verify(issuer.public_key, child.signature_algorithm, child.tbs, child.signature) catch {
            try self.charge("rejected", 1);
            return false;
        };
        return true;
    }
    fn caBelow(self: *const Search) usize {
        @setRuntimeSafety(true);
        var count: usize = 0;
        for (self.path[1..self.count]) |*cert| if (!cert.selfIssued()) {
            count += 1;
        };
        return count;
    }
    fn accept(self: *Search, anchor_index: usize) VerifyError!bool {
        @setRuntimeSafety(true);
        const ap: T.AnchorPolicy = if (self.request.anchor_policies.len == 0) .{} else self.request.anchor_policies[anchor_index];
        if (ap.name_constraints.len > self.request.limits.chain_bytes or ap.required_policies.len > self.request.limits.policy_nodes) return error.VerificationLimit;
        const anchor = &self.path[self.count - 1];
        if ((self.request.purpose == .server and !ap.server) or (self.request.purpose == .client and !ap.client)) return false;
        if (ap.check_validity and (self.request.time < anchor.not_before or self.request.time > anchor.not_after)) return false;
        identity.purpose(anchor, self.request.purpose, self.count > 1) catch return false;
        if (anchor.x509(19)) |bc| {
            const basic = try C.Extensions.basic(bc.value);
            if (basic.path_length) |max| {
                var below: usize = 0;
                for (self.path[@min(1, self.count - 1) .. self.count - 1]) |*cert| if (!cert.selfIssued()) {
                    below += 1;
                };
                if (below > max) return false;
            }
        }
        @call(.never_inline, constraints.check, .{ self.path[0..self.count], ap.name_constraints, &self.constraint_work }) catch |err| {
            if (err == error.DerLimit or err == error.VerificationLimit) return err;
            return false;
        };
        @call(.never_inline, policies.check, .{ self.gpa, self.path[0..self.count], self.request.policy, ap.required_policies, self.request.limits.policy_nodes, &self.policy_work }) catch |err| {
            if (err == error.OutOfMemory or err == error.VerificationLimit) return err;
            return false;
        };
        const evidence = revocation.check(self.path[0..self.count], self.request.time, self.request.policy.revocation, self.request.evidence) catch |err| {
            if (err == error.VerificationLimit) return err;
            return false;
        };
        var expires = self.path[0].not_after;
        for (self.path[0 .. self.count - 1]) |*cert| expires = @min(expires, cert.not_after);
        if (ap.check_validity) expires = @min(expires, anchor.not_after);
        if (evidence.expires) |deadline| expires = @min(expires, deadline);
        var der: [16][]const u8 = undefined;
        for (self.path[0..self.count], 0..) |*cert, i| der[i] = cert.der;
        var receipt = try V.init(self.gpa, self.request, der[0..self.count], true, expires);
        receipt.revocation = evidence.status;
        receipt.revocation_expires = evidence.expires;
        self.receipt = receipt;
        return true;
    }
};
const AnchorIterator = struct {
    anchors: []const []const u8,
    selected: ?[]const C.Issuers.Entry,
    offset: usize = 0,
    fn next(self: *AnchorIterator) ?struct { der: []const u8, index: usize } {
        @setRuntimeSafety(true);
        if (self.selected) |entries| {
            if (self.offset == entries.len) return null;
            const entry = entries[self.offset];
            self.offset += 1;
            return .{ .der = entry.der, .index = entry.index };
        }
        if (self.offset == self.anchors.len) return null;
        const index = self.offset;
        self.offset += 1;
        return .{ .der = self.anchors[index], .index = index };
    }
};
/// Use an immutable index retained by the trust owner for large root stores.
pub fn indexed(gpa: std.mem.Allocator, request: T.Request, index: *const C.Issuers) VerifyError!V {
    @setRuntimeSafety(true);
    return run(gpa, request, index.anchors, index);
}
pub fn verify(gpa: std.mem.Allocator, request: T.Request, anchors: []const []const u8) VerifyError!V {
    @setRuntimeSafety(true);
    return run(gpa, request, anchors, null);
}
fn run(gpa: std.mem.Allocator, request: T.Request, anchors: []const []const u8, index: ?*const C.Issuers) VerifyError!V {
    @setRuntimeSafety(true);
    try bounds(request, anchors.len);
    try identity.validate(request.identity, request.purpose);
    // Portable paths use supplied candidates plus at most one explicit anchor.
    // The depth cap is at most sixteen, so the addition below cannot overflow.
    const capacity = if (request.chain.len >= request.limits.depth) request.limits.depth else request.chain.len + 1;
    const state = try Search.init(gpa, request, anchors, index, capacity);
    defer state.deinit();
    state.path[0] = try state.parse(request.chain[0]);
    state.count = 1;
    try identity.pins(&state.path[0], request.pins);
    if (request.mode == .none) return V.init(gpa, request, request.chain[0..1], false, state.path[0].not_after);
    try leafFloors(&state.path[0], request);
    if (!try state.search()) return error.NoTrustedPath;
    return state.receipt.?;
}
fn leafFloors(cert: *const C.Certificate, request: T.Request) VerifyError!void {
    @setRuntimeSafety(true);
    if (cert.serial.len == 1 and cert.serial[0] == 0) return error.InvalidCertificate;
    if (!cert.selfIssued() and cert.x509(35) == null) return error.InvalidCertificate;
    if (request.time < cert.not_before or request.time > cert.not_after) return error.InvalidValidity;
    try identity.check(cert, request.identity);
    try identity.purpose(cert, request.purpose, false);
}
fn bounds(request: T.Request, anchors: usize) VerifyError!void {
    @setRuntimeSafety(true);
    if (request.chain.len == 0 or request.chain.len > request.limits.certificates or request.limits.depth == 0 or request.limits.depth > 16) return error.VerificationLimit;
    var bytes: usize = 0;
    for (request.chain) |cert| bytes = (aegis.int.Checked(usize).init(bytes).add(cert.len) catch return error.VerificationLimit).raw();
    if (bytes > request.limits.chain_bytes or request.pins.len > request.limits.candidates or request.policy.required_policies.len > request.limits.policy_nodes) return error.VerificationLimit;
    if (request.anchor_policies.len != 0 and request.anchor_policies.len != anchors) return error.InvalidAnchorPolicy;
}
fn akiConsistent(child: *const C.Certificate, issuer: *const C.Certificate) bool {
    @setRuntimeSafety(true);
    const aki = child.x509(35) orelse return true;
    const ski = issuer.x509(14) orelse return true;
    var r = C.Extensions.sequence(aki.value) catch return false;
    if (r.peek() != 0x80) return true;
    const id = (r.next() catch return false).value;
    const key = Der.single(ski.value, 4) catch return false;
    return std.mem.eql(u8, id, key.value);
}
test {
    _ = @import("Verifier_test.zig");
}

/// The driver must first establish OS policy success with retrieval disabled.
/// This checks its selected chain; it never searches or authorizes an anchor.
pub fn nativePath(gpa: std.mem.Allocator, request: T.Request, selected_chain: []const []const u8) VerifyError!V {
    @setRuntimeSafety(true);
    try bounds(request, 0);
    if (selected_chain.len == 0 or selected_chain.len > request.limits.depth or !std.mem.eql(u8, selected_chain[0], request.chain[0])) return error.InvalidAnchorPolicy;
    if (request.mode == .none) return verify(gpa, request, &.{});
    try identity.validate(request.identity, request.purpose);
    const state = try Search.init(gpa, request, &.{}, null, selected_chain.len);
    defer state.deinit();
    for (selected_chain, 0..) |der, index| {
        state.path[index] = try state.parse(der);
        state.count = index;
        if (index != selected_chain.len - 1 or index == 0) {
            if (request.time < state.path[index].not_before or request.time > state.path[index].not_after) return error.InvalidValidity;
        }
        if (index > 0 and !try state.link(&state.path[index - 1], &state.path[index], index == selected_chain.len - 1)) return error.InvalidCa;
        state.count = index + 1;
    }
    try leafFloors(&state.path[0], request);
    try identity.pins(&state.path[0], request.pins);
    if (!try state.accept(0)) return error.NoTrustedPath;
    return state.receipt.?;
}
