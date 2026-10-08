//! CryptoAPI policy with offline-only chain building and copied selected evidence.
const std = @import("std");
const W = std.os.windows;
const C = W.crypt32;
const types = @import("../types.zig");
const Path = @import("Path.zig");
pub const Error = Path.InitError || error{ NativePolicyFailure, InvalidReferenceIdentity, InvalidValidationTime };
// Cache-only includes CTL/root retrieval; AIA and automatic roots are disabled.
const offline_flags: u32 = 0x00000004 | 0x00000100 | 0x00002000 | 0x80000000;
pub fn evaluate(gpa: std.mem.Allocator, request: types.Request, anchors: []const []const u8) Error!Path {
    @setRuntimeSafety(true);
    if (request.time < -62135596800 or request.time > 253402300799) return error.InvalidValidationTime;
    if (request.chain.len == 0 or request.chain.len > request.limits.certificates) return error.ServiceLimit;
    const additional = try store(request.chain);
    defer _ = C.CertCloseStore(additional, .{});
    const leaf = CertCreateCertificateContext(1, request.chain[0].ptr, @intCast(request.chain[0].len)) orelse return error.NativePolicyFailure; // safe: store already checked the DER length to fit the SDK u32 size
    defer _ = C.CertFreeCertificateContext(leaf);
    var engine: C.HCERTCHAINENGINE = .CURRENT_USER;
    var roots: ?C.HCERTSTORE = null;
    defer if (roots) |r| {
        CertFreeCertificateChainEngine(engine);
        _ = C.CertCloseStore(r, .{});
    };
    if (anchors.len != 0) {
        roots = try store(anchors);
        var config: EngineConfig = .{ .exclusive_root = roots, .flags = offline_flags };
        if (CertCreateCertificateChainEngine(&config, &engine) == 0) {
            _ = C.CertCloseStore(roots.?, .{});
            roots = null;
            return error.NativePolicyFailure;
        }
    }
    const ticks: i128 = (@as(i128, request.time) + 11644473600) * 10_000_000;
    if (ticks < 0 or ticks > std.math.maxInt(u64)) return error.InvalidValidationTime;
    // The range is checked before converting the Windows 100ns epoch.
    const stamp: u64 = @intCast(ticks); // safe: epoch ticks were checked to fit u64
    var time: W.FILETIME = .{ .dwLowDateTime = @truncate(stamp), .dwHighDateTime = @truncate(stamp >> 32) }; // safe: FILETIME uses low and high 32-bit words of the checked u64 epoch
    const oid: [1]W.LPCSTR = .{if (request.purpose == .server) "1.3.6.1.5.5.7.3.1" else "1.3.6.1.5.5.7.3.2"};
    const parameters: C.CERT_CHAIN.PARA = .{ .RequestedUsage = .{ .dwType = .AND, .Usage = .{ .cUsageIdentifier = 1, .rgpszUsageIdentifier = &oid } } };
    var raw: *const C.CERT_CHAIN.CONTEXT = undefined;
    if (!C.CertGetCertificateChain(engine, leaf, &time, additional, &parameters, @bitCast(offline_flags), null, &raw).toBool()) return error.NativePolicyFailure; // safe: SDK packed flags have the documented 32-bit layout
    defer C.CertFreeCertificateChain(raw);
    const name: ?[:0]u16 = switch (request.identity) {
        .dns => |dns| blk: {
            if (dns.len > 253 or std.mem.findScalar(u8, dns, 0) != null) return error.InvalidReferenceIdentity;
            const out = try gpa.allocSentinel(u16, dns.len, 0);
            errdefer gpa.free(out);
            for (dns, out) |c, *unit| {
                if (c > 127) {
                    return error.InvalidReferenceIdentity;
                }
                unit.* = c;
            }
            break :blk out;
        },
        else => null,
    };
    defer if (name) |n| gpa.free(n);
    var ssl: C.HTTPSPolicyCallbackData = .{ .dwAuthType = if (request.purpose == .server) .SERVER else .CLIENT, .pwszServerName = if (name) |n| n.ptr else null };
    const policy: C.CERT_CHAIN.POLICY.PARA = .{ .dwFlags = .{}, .pvExtraPolicyPara = &ssl };
    var status: C.CERT_CHAIN.POLICY.STATUS = .{ .dwError = .SUCCESS, .lChainIndex = 0, .lElementIndex = 0, .pvExtraPolicyStatus = null };
    if (!C.CertVerifyCertificateChainPolicy(.SSL, raw, &policy, &status).toBool() or status.dwError != .SUCCESS) return error.NativePolicyFailure;
    // The SDK defines CONTEXT as this aligned prefix; CryptoAPI owns it until the deferred free.
    const context: *const Context = @ptrCast(@alignCast(raw)); // safe: CryptoAPI returns this aligned SDK CONTEXT prefix, owned until deferred free
    if (context.count != 1 or context.status.error_status != 0) return error.NativeEvidenceUnavailable;
    const selected = context.chains[0];
    if (selected.count == 0 or selected.count > request.limits.depth) return error.NativeEvidenceUnavailable;
    const ders = try gpa.alloc([]const u8, selected.count);
    defer gpa.free(ders);
    for (ders, 0..) |*der, i| {
        const cert = selected.elements[i].certificate;
        if (cert.cbCertEncoded > request.limits.receipt_bytes) return error.ServiceLimit;
        der.* = cert.pbCertEncoded[0..cert.cbCertEncoded];
    }
    return Path.init(gpa, request, ders);
}
fn store(certificates: []const []const u8) Error!C.HCERTSTORE {
    @setRuntimeSafety(true);
    const owner = C.CertOpenStore(.MEMORY, .{}, .NULL, .{ .CREATE_NEW = true }, null) orelse return error.NativePolicyFailure;
    errdefer _ = C.CertCloseStore(owner, .{});
    for (certificates) |der| {
        if (der.len > std.math.maxInt(u32)) return error.ServiceLimit;
        if (!C.CertAddEncodedCertificateToStore(owner, .{ .CERT = .ASN }, der.ptr, @intCast(der.len), .ALWAYS, null).toBool()) return error.NativePolicyFailure; // safe: DER length was checked to fit the SDK u32 size
    }
    return owner;
}
const Status = extern struct { error_status: u32, info_status: u32 };
const Element = extern struct { size: u32, certificate: *const C.CERT_CONTEXT, status: Status, revocation: ?*anyopaque, issuance: ?*anyopaque, application: ?*anyopaque, extended_error: ?[*:0]const u16 };
const SimpleChain = extern struct { size: u32, status: Status, count: u32, elements: [*]const *const Element, trust_list: ?*anyopaque, has_freshness: i32, freshness: u32 };
const Context = extern struct { size: u32, status: Status, count: u32, chains: [*]const *const SimpleChain };
const EngineConfig = extern struct {
    size: u32 = @sizeOf(EngineConfig),
    restricted_root: ?C.HCERTSTORE = null,
    restricted_trust: ?C.HCERTSTORE = null,
    restricted_other: ?C.HCERTSTORE = null,
    additional_count: u32 = 0,
    additional: ?[*]C.HCERTSTORE = null,
    flags: u32 = 0,
    url_timeout: u32 = 0,
    cached: u32 = 0,
    cycles: u32 = 0,
    exclusive_root: ?C.HCERTSTORE = null,
    exclusive_people: ?C.HCERTSTORE = null,
    exclusive_flags: u32 = 0,
};
extern "crypt32" fn CertCreateCertificateContext(u32, [*]const u8, u32) callconv(.winapi) ?*const C.CERT_CONTEXT;
extern "crypt32" fn CertCreateCertificateChainEngine(*EngineConfig, *C.HCERTCHAINENGINE) callconv(.winapi) i32;
extern "crypt32" fn CertFreeCertificateChainEngine(C.HCERTCHAINENGINE) callconv(.winapi) void;
test {
    @setRuntimeSafety(true);
    _ = @import("windows_test.zig");
}
