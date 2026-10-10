//! SecTrust policy and its exact selected chain; no keychain mutation or networking.
const std = @import("std");
const types = @import("../types.zig");
const Path = @import("Path.zig");
const Cf = *const anyopaque;
pub const Error = Path.InitError || error{ NativePolicyFailure, InvalidReferenceIdentity, InvalidValidationTime };
pub fn evaluate(gpa: std.mem.Allocator, request: types.Request, anchors: []const []const u8) Error!Path {
    @setRuntimeSafety(true);
    const now = types.seconds(request.time);
    if (now < -62135596800 or now > 253402300799) return error.InvalidValidationTime;
    if (request.chain.len == 0 or request.chain.len > request.limits.certificates) return error.ServiceLimit;
    const certificates = try array(gpa, request.chain);
    defer CFRelease(certificates);
    const hostname: ?Cf = switch (request.identity) {
        .dns => |name| blk: {
            if (name.len > 253 or std.mem.findScalar(u8, name, 0) != null) return error.InvalidReferenceIdentity;
            break :blk CFStringCreateWithBytes(null, name.ptr, @intCast(name.len), 0x08000100, 0) orelse return error.OutOfMemory; // safe: DNS length is bounded to 253 before signed CFIndex conversion
        },
        else => null,
    };
    defer if (hostname) |name| CFRelease(name);
    const policy = SecPolicyCreateSSL(@intFromBool(request.purpose == .server), hostname) orelse return error.NativePolicyFailure;
    defer CFRelease(policy);
    var trust: ?Cf = null;
    if (SecTrustCreateWithCertificates(certificates, policy, &trust) != 0) return error.NativePolicyFailure;
    const owner = trust orelse return error.NativePolicyFailure;
    defer CFRelease(owner);
    if (SecTrustSetNetworkFetchAllowed(owner, 0) != 0) return error.NativePolicyFailure;
    var network: u8 = 1;
    if (SecTrustGetNetworkFetchAllowed(owner, &network) != 0 or network != 0) return error.NativePolicyFailure;
    const date = CFDateCreate(null, @as(f64, @floatFromInt(now)) - 978307200.0) orelse return error.OutOfMemory; // safe: validated integer seconds in year 1..9999 are exactly representable by f64
    defer CFRelease(date);
    if (SecTrustSetVerifyDate(owner, date) != 0) return error.NativePolicyFailure;
    if (anchors.len != 0) {
        const roots = try array(gpa, anchors);
        defer CFRelease(roots);
        if (SecTrustSetAnchorCertificates(owner, roots) != 0 or SecTrustSetAnchorCertificatesOnly(owner, 1) != 0) return error.NativePolicyFailure;
    }
    var failure: ?Cf = null;
    const success = SecTrustEvaluateWithError(owner, &failure);
    defer if (failure) |error_object| CFRelease(error_object);
    if (success == 0) return error.NativePolicyFailure;
    const chain = SecTrustCopyCertificateChain(owner) orelse return error.NativeEvidenceUnavailable;
    defer CFRelease(chain);
    const count = CFArrayGetCount(chain);
    if (count <= 0 or count > request.limits.depth) return error.NativeEvidenceUnavailable;
    const ders = try gpa.alloc([]const u8, @intCast(count)); // safe: positive OS chain count is bounded before usize conversion
    defer gpa.free(ders);
    const buffers = try gpa.alloc(Cf, ders.len);
    defer gpa.free(buffers);
    var populated: usize = 0;
    defer for (buffers[0..populated]) |buffer| CFRelease(buffer);
    for (ders, buffers, 0..) |*der, *buffer, index| {
        const cert = CFArrayGetValueAtIndex(chain, @intCast(index)) orelse return error.NativeEvidenceUnavailable; // safe: index is below the validated CFArray count
        buffer.* = SecCertificateCopyData(cert) orelse return error.NativeEvidenceUnavailable;
        populated += 1;
        const len = CFDataGetLength(buffer.*);
        if (len <= 0 or len > request.limits.receipt_bytes) return error.ServiceLimit;
        const ptr = CFDataGetBytePtr(buffer.*) orelse return error.NativeEvidenceUnavailable;
        der.* = ptr[0..@intCast(len)]; // safe: positive CFData length is bounded by receipt_bytes
    }
    return Path.init(gpa, request, ders);
}
fn array(gpa: std.mem.Allocator, certificates: []const []const u8) Error!Cf {
    @setRuntimeSafety(true);
    if (certificates.len > std.math.maxInt(isize)) return error.ServiceLimit;
    const refs = try gpa.alloc(Cf, certificates.len);
    defer gpa.free(refs);
    var count: usize = 0;
    defer for (refs[0..count]) |ref| CFRelease(ref);
    for (certificates, refs) |der, *ref| {
        if (der.len > std.math.maxInt(isize)) return error.ServiceLimit;
        const data = CFDataCreate(null, der.ptr, @intCast(der.len)) orelse return error.OutOfMemory; // safe: DER length was checked to fit signed CFIndex
        defer CFRelease(data);
        ref.* = SecCertificateCreateWithData(null, data) orelse return error.NativePolicyFailure;
        count += 1;
    }
    return CFArrayCreate(null, refs.ptr, @intCast(refs.len), cf_type_array_callbacks) orelse return error.OutOfMemory; // safe: array count was checked to fit signed CFIndex
}
const ArrayCallbacks = extern struct { version: isize, retain: ?*const anyopaque, release: ?*const anyopaque, description: ?*const anyopaque, equal: ?*const anyopaque };
const cf_type_array_callbacks = @extern(*const ArrayCallbacks, .{ .name = "kCFTypeArrayCallBacks", .library_name = "CoreFoundation" });
extern "CoreFoundation" fn CFArrayCreate(?Cf, [*]const Cf, isize, *const ArrayCallbacks) ?Cf;
extern "CoreFoundation" fn CFArrayGetCount(Cf) isize;
extern "CoreFoundation" fn CFArrayGetValueAtIndex(Cf, isize) ?Cf;
extern "CoreFoundation" fn CFDataCreate(?Cf, [*]const u8, isize) ?Cf;
extern "CoreFoundation" fn CFDataGetLength(Cf) isize;
extern "CoreFoundation" fn CFDataGetBytePtr(Cf) ?[*]const u8;
extern "CoreFoundation" fn CFStringCreateWithBytes(?Cf, [*]const u8, isize, u32, u8) ?Cf;
extern "CoreFoundation" fn CFDateCreate(?Cf, f64) ?Cf;
extern "CoreFoundation" fn CFRelease(Cf) void;
extern "Security" fn SecCertificateCreateWithData(?Cf, Cf) ?Cf;
extern "Security" fn SecCertificateCopyData(Cf) ?Cf;
extern "Security" fn SecPolicyCreateSSL(u8, ?Cf) ?Cf;
extern "Security" fn SecTrustCreateWithCertificates(Cf, Cf, *?Cf) i32;
extern "Security" fn SecTrustSetNetworkFetchAllowed(Cf, u8) i32;
extern "Security" fn SecTrustGetNetworkFetchAllowed(Cf, *u8) i32;
extern "Security" fn SecTrustSetVerifyDate(Cf, Cf) i32;
extern "Security" fn SecTrustSetAnchorCertificates(Cf, Cf) i32;
extern "Security" fn SecTrustSetAnchorCertificatesOnly(Cf, u8) i32;
extern "Security" fn SecTrustEvaluateWithError(Cf, *?Cf) u8;
extern "Security" fn SecTrustCopyCertificateChain(Cf) ?Cf;
test {
    @setRuntimeSafety(true);
    _ = @import("macos_test.zig");
}
