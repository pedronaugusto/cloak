//! Lower-layer verification vocabulary. No trust owner or handshake dependency.
const std = @import("std");
const aegis = @import("aegis");
pub const ConnectionGeneration = aegis.id.Id(struct {}, u64);
pub const RequestId = aegis.id.Id(struct {}, u64);
pub const TrustGeneration = aegis.id.Id(struct {}, u64);
pub const PolicyGeneration = aegis.id.Id(struct {}, u64);
pub const IdentityGeneration = aegis.id.Id(struct {}, u64);
pub const RealSeconds = aegis.units.Instant(.real, .second, i64);
pub const Token = struct { generation: ConnectionGeneration = .fromRaw(0), id: RequestId = .fromRaw(0) };
pub const Identity = union(enum) { none, dns: []const u8, ipv4: [4]u8, ipv6: [16]u8 };
pub const Purpose = enum { server, client };
pub const Mode = enum { full, none };
pub const Revocation = enum { off, if_present, required };
pub const Coverage = enum { leaf, whole_path };
pub const RevocationStatus = enum { unchecked, not_present, good };
pub const RevocationPolicy = struct {
    mode: Revocation = .if_present,
    coverage: Coverage = .leaf,
    clock_skew: u64 = 300,
    max_age: u64 = 86400,
};
pub const Evidence = struct { crls: []const []const u8 = &.{}, ocsp: []const []const u8 = &.{} };
pub const Policy = struct {
    /// Empty initial set means anyPolicy; otherwise DER OID contents.
    required_policies: []const []const u8 = &.{},
    explicit_policy: bool = false,
    inhibit_mapping: bool = false,
    inhibit_any: bool = false,
    revocation: RevocationPolicy = .{},
};
pub const Limits = struct {
    chain_bytes: usize = 65536,
    certificates: usize = 16,
    depth: usize = 8,
    intermediates: usize = 16,
    candidates: usize = 256,
    parses: usize = 256,
    signatures: usize = 256,
    rejected: usize = 256,
    parsed_bytes: usize = 4 * 1024 * 1024,
    receipt_bytes: usize = 65536,
    policy_nodes: usize = 256,
    /// Cumulative subtree visits and compared bytes across all candidate paths.
    constraint_work: usize = 4 * 1024 * 1024,
    /// Cumulative policy visits and compared OID bytes, separate from node storage.
    policy_work: usize = 4 * 1024 * 1024,
};
pub const AnchorPolicy = struct {
    check_validity: bool = false,
    server: bool = true,
    client: bool = true,
    /// DER nameConstraints; empty adds no constraints to those in the certificate.
    name_constraints: []const u8 = &.{},
    required_policies: []const []const u8 = &.{},
};
pub const Request = struct {
    /// Leaf first; the remainder are unordered issuer candidates.
    chain: []const []const u8,
    identity: Identity = .none,
    purpose: Purpose = .server,
    time: i64,
    trust_generation: TrustGeneration,
    policy_generation: PolicyGeneration,
    token: Token = .{},
    mode: Mode = .full,
    policy: Policy = .{},
    pins: []const [32]u8 = &.{},
    evidence: Evidence = .{},
    limits: Limits = .{},
    /// Empty uses default anchor policies, otherwise one per explicit anchor.
    anchor_policies: []const AnchorPolicy = &.{},

    /// Domain separation and length prefixes prevent concatenation ambiguity.
    /// This binds a completion to every input, including evidence and budgets.
    pub fn digest(self: Request) [32]u8 {
        @setRuntimeSafety(true);
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        part(&h, "cloak verification request v1");
        uint(&h, self.token.generation.raw());
        uint(&h, self.token.id.raw());
        uint(&h, self.trust_generation.raw());
        uint(&h, self.policy_generation.raw());
        // safe: i64 and u64 have the same bit width; preserve the signed time encoding.
        uint(&h, @bitCast(self.time));
        uint(&h, @backingInt(self.mode));
        uint(&h, @backingInt(self.purpose));
        uint(&h, @backingInt(self.identity));
        switch (self.identity) {
            .none => {},
            .dns => |v| part(&h, v),
            .ipv4 => |v| part(&h, &v),
            .ipv6 => |v| part(&h, &v),
        }
        parts(&h, self.chain);
        uint(&h, self.pins.len);
        for (self.pins) |pin| part(&h, &pin);
        parts(&h, self.policy.required_policies);
        uint(&h, @intFromBool(self.policy.explicit_policy));
        uint(&h, @intFromBool(self.policy.inhibit_mapping));
        uint(&h, @intFromBool(self.policy.inhibit_any));
        uint(&h, @backingInt(self.policy.revocation.mode));
        uint(&h, @backingInt(self.policy.revocation.coverage));
        uint(&h, self.policy.revocation.clock_skew);
        uint(&h, self.policy.revocation.max_age);
        parts(&h, self.evidence.crls);
        parts(&h, self.evidence.ocsp);
        inline for (@typeInfo(Limits).@"struct".field_names) |f| uint(&h, @field(self.limits, f));
        uint(&h, self.anchor_policies.len);
        for (self.anchor_policies) |p| {
            uint(&h, @intFromBool(p.check_validity));
            uint(&h, @intFromBool(p.server));
            uint(&h, @intFromBool(p.client));
            part(&h, p.name_constraints);
            parts(&h, p.required_policies);
        }
        return h.finalResult();
    }
};
fn part(h: *std.crypto.hash.sha2.Sha256, bytes: []const u8) void {
    @setRuntimeSafety(true);
    uint(h, bytes.len);
    h.update(bytes);
}
fn parts(h: *std.crypto.hash.sha2.Sha256, slices: []const []const u8) void {
    @setRuntimeSafety(true);
    uint(h, slices.len);
    for (slices) |s| part(h, s);
}
fn uint(h: *std.crypto.hash.sha2.Sha256, n: u64) void {
    @setRuntimeSafety(true);
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, n, .big);
    h.update(&bytes);
}

/// Owned bounded receipt shared by services and verification.
/// Move exactly once; borrow during checks and call deinit once after the final borrower.
/// This local owner/token form is a future aegis handle replacement site.
pub const Verification = struct {
    gpa: std.mem.Allocator,
    path: []const []const u8,
    identity: Identity,
    purpose: Purpose,
    trust_generation: TrustGeneration,
    policy_generation: PolicyGeneration,
    validation_time: i64,
    expires: i64,
    revocation: RevocationStatus = .unchecked,
    revocation_expires: ?i64 = null,
    authenticated: bool,
    request_digest: [32]u8,
    token: Token,
    storage: []u8,
    identity_storage: ?[]u8 = null,
    pub const InitError = std.mem.Allocator.Error || error{VerificationLimit};
    pub fn init(gpa: std.mem.Allocator, request: Request, path: []const []const u8, authenticated: bool, expires: i64) InitError!Verification {
        @setRuntimeSafety(true);
        if (path.len == 0 or request.chain.len == 0 or !std.mem.eql(u8, path[0], request.chain[0])) return error.VerificationLimit;
        const name_bytes: usize = if (request.identity == .dns) request.identity.dns.len else 0;
        if (name_bytes > 253) return error.VerificationLimit;
        var size: usize = 0;
        for (path) |der| size = std.math.add(usize, size, der.len) catch return error.VerificationLimit;
        const descriptors = (aegis.int.Checked(usize).init(path.len).mul(@sizeOf([]const u8)) catch return error.VerificationLimit).raw();
        const owned_bytes = std.math.add(usize, size, std.math.add(usize, descriptors, name_bytes) catch return error.VerificationLimit) catch return error.VerificationLimit;
        if (owned_bytes > request.limits.receipt_bytes or path.len > request.limits.depth) return error.VerificationLimit;
        const storage = try gpa.alloc(u8, size);
        errdefer gpa.free(storage);
        const chain = try gpa.alloc([]const u8, path.len);
        errdefer gpa.free(chain);
        var cursor: usize = 0;
        for (path, chain) |der, *out| {
            out.* = storage[cursor..][0..der.len];
            @memcpy(storage[cursor..][0..der.len], der);
            cursor += der.len;
        }
        var identity = request.identity;
        const identity_storage: ?[]u8 = switch (identity) {
            .dns => |name| try gpa.dupe(u8, name),
            else => null,
        };
        errdefer if (identity_storage) |copy| gpa.free(copy);
        if (identity_storage) |copy| identity = .{ .dns = copy };
        return .{ .gpa = gpa, .path = chain, .storage = storage, .identity = identity, .identity_storage = identity_storage, .purpose = request.purpose, .trust_generation = request.trust_generation, .policy_generation = request.policy_generation, .validation_time = request.time, .expires = expires, .authenticated = authenticated and request.mode == .full, .request_digest = request.digest(), .token = request.token };
    }
    pub const CheckError = error{ WrongVerificationRequest, Unauthenticated, VerificationExpired };
    pub fn check(self: Verification, request: Request) CheckError!void {
        @setRuntimeSafety(true);
        if (request.chain.len == 0) return error.WrongVerificationRequest;
        if (!std.crypto.timing_safe.eql([32]u8, self.request_digest, request.digest()) or self.token.generation != request.token.generation or self.token.id != request.token.id) return error.WrongVerificationRequest;
        if (self.purpose != request.purpose or self.trust_generation != request.trust_generation or self.policy_generation != request.policy_generation or self.path.len == 0 or !std.mem.eql(u8, self.path[0], request.chain[0])) return error.WrongVerificationRequest;
        switch (self.identity) {
            .none => if (request.identity != .none) return error.WrongVerificationRequest,
            .dns => |name| if (request.identity != .dns or !std.mem.eql(u8, name, request.identity.dns)) return error.WrongVerificationRequest,
            .ipv4 => |ip| if (request.identity != .ipv4 or !std.mem.eql(u8, &ip, &request.identity.ipv4)) return error.WrongVerificationRequest,
            .ipv6 => |ip| if (request.identity != .ipv6 or !std.mem.eql(u8, &ip, &request.identity.ipv6)) return error.WrongVerificationRequest,
        }
        if (request.mode == .full and !self.authenticated) return error.Unauthenticated;
        if (self.validation_time != request.time or self.expires < request.time) return error.VerificationExpired;
    }
    pub fn deinit(self: *Verification) void {
        @setRuntimeSafety(true);
        self.gpa.free(self.path);
        self.gpa.free(self.storage);
        if (self.identity_storage) |s| self.gpa.free(s);
        self.* = undefined;
    }
};
