//! SecTrust policy and its exact selected chain; no keychain mutation or networking. Security is opened
//! from the system on first use, not linked.
const std = @import("std");
const aegis = @import("aegis");
const types = @import("../types.zig");
const Path = @import("Path.zig");
const Cf = *const anyopaque;
/// `SystemTrustUnavailable`: the system has no Security framework to open, or one without a symbol cloak calls.
pub const Error = Path.InitError || error{ NativePolicyFailure, InvalidReferenceIdentity, InvalidValidationTime, SystemTrustUnavailable };
pub fn evaluate(gpa: std.mem.Allocator, request: types.Request, anchors: []const []const u8) Error!Path {
    @setRuntimeSafety(true);
    const now = types.seconds(request.time);
    if (now < -62135596800 or now > 253402300799) return error.InvalidValidationTime;
    if (request.chain.len == 0 or request.chain.len > request.limits.certificates) return error.ServiceLimit;
    const sec = try Security.load();
    const certificates = try array(sec, gpa, request.chain);
    defer sec.CFRelease(certificates);
    const hostname: ?Cf = switch (request.identity) {
        .dns => |name| blk: {
            if (name.len > 253 or std.mem.findScalar(u8, name, 0) != null) return error.InvalidReferenceIdentity;
            break :blk sec.CFStringCreateWithBytes(null, name.ptr, @intCast(name.len), 0x08000100, 0) orelse return error.OutOfMemory; // DNS length is bounded to 253 before signed CFIndex conversion
        },
        else => null,
    };
    defer if (hostname) |name| sec.CFRelease(name);
    const policy = sec.SecPolicyCreateSSL(@intFromBool(request.purpose == .server), hostname) orelse return error.NativePolicyFailure;
    defer sec.CFRelease(policy);
    var trust: ?Cf = null;
    if (sec.SecTrustCreateWithCertificates(certificates, policy, &trust) != 0) return error.NativePolicyFailure;
    const owner = trust orelse return error.NativePolicyFailure;
    defer sec.CFRelease(owner);
    if (sec.SecTrustSetNetworkFetchAllowed(owner, 0) != 0) return error.NativePolicyFailure;
    var network: u8 = 1;
    if (sec.SecTrustGetNetworkFetchAllowed(owner, &network) != 0 or network != 0) return error.NativePolicyFailure;
    const date = sec.CFDateCreate(null, @as(f64, @floatFromInt(now)) - 978307200.0) orelse return error.OutOfMemory; // validated integer seconds in year 1..9999 are exactly representable by f64
    defer sec.CFRelease(date);
    if (sec.SecTrustSetVerifyDate(owner, date) != 0) return error.NativePolicyFailure;
    if (anchors.len != 0) {
        const roots = try array(sec, gpa, anchors);
        defer sec.CFRelease(roots);
        if (sec.SecTrustSetAnchorCertificates(owner, roots) != 0 or sec.SecTrustSetAnchorCertificatesOnly(owner, 1) != 0) return error.NativePolicyFailure;
    }
    var failure: ?Cf = null;
    const success = sec.SecTrustEvaluateWithError(owner, &failure);
    defer if (failure) |error_object| sec.CFRelease(error_object);
    if (success == 0) return error.NativePolicyFailure;
    const chain = sec.SecTrustCopyCertificateChain(owner) orelse return error.NativeEvidenceUnavailable;
    defer sec.CFRelease(chain);
    const count = sec.CFArrayGetCount(chain);
    if (count <= 0 or count > request.limits.depth) return error.NativeEvidenceUnavailable;
    const ders = try gpa.alloc([]const u8, @intCast(count)); // positive OS chain count is bounded before usize conversion
    defer gpa.free(ders);
    const buffers = try gpa.alloc(Cf, ders.len);
    defer gpa.free(buffers);
    var populated: usize = 0;
    defer for (buffers[0..populated]) |buffer| sec.CFRelease(buffer);
    for (ders, buffers, 0..) |*der, *buffer, index| {
        const cert = sec.CFArrayGetValueAtIndex(chain, @intCast(index)) orelse return error.NativeEvidenceUnavailable; // index is below the validated CFArray count
        buffer.* = sec.SecCertificateCopyData(cert) orelse return error.NativeEvidenceUnavailable;
        populated += 1;
        const len = sec.CFDataGetLength(buffer.*);
        if (len <= 0 or len > request.limits.receipt_bytes) return error.ServiceLimit;
        const ptr = sec.CFDataGetBytePtr(buffer.*) orelse return error.NativeEvidenceUnavailable;
        der.* = ptr[0..@intCast(len)]; // positive CFData length is bounded by receipt_bytes
    }
    return Path.init(gpa, request, ders);
}
fn array(sec: *const Security, gpa: std.mem.Allocator, certificates: []const []const u8) Error!Cf {
    @setRuntimeSafety(true);
    if (certificates.len > std.math.maxInt(isize)) return error.ServiceLimit;
    const refs = try gpa.alloc(Cf, certificates.len);
    defer gpa.free(refs);
    var count: usize = 0;
    defer for (refs[0..count]) |ref| sec.CFRelease(ref);
    for (certificates, refs) |der, *ref| {
        if (der.len > std.math.maxInt(isize)) return error.ServiceLimit;
        const data = sec.CFDataCreate(null, der.ptr, @intCast(der.len)) orelse return error.OutOfMemory; // DER length was checked to fit signed CFIndex
        defer sec.CFRelease(data);
        ref.* = sec.SecCertificateCreateWithData(null, data) orelse return error.NativePolicyFailure;
        count += 1;
    }
    return sec.CFArrayCreate(null, refs.ptr, @intCast(refs.len), sec.kCFTypeArrayCallBacks) orelse return error.OutOfMemory; // array count was checked to fit signed CFIndex
}
const ArrayCallbacks = extern struct { version: isize, retain: ?*const anyopaque, release: ?*const anyopaque, description: ?*const anyopaque, equal: ?*const anyopaque };
/// The Security and CoreFoundation symbols cloak calls, opened from the system's Security framework on
/// first use rather than linked, so a macOS build links only libSystem and needs no SDK. Each field is one
/// symbol: its name is the symbol's and its type is the declaration. The CoreFoundation symbols resolve
/// through Security, which links CoreFoundation.
pub const Security = struct {
    /// A data symbol: its address is the callbacks a certificate array retains its values with.
    kCFTypeArrayCallBacks: *const ArrayCallbacks,
    CFArrayCreate: *const fn (?Cf, [*]const Cf, isize, *const ArrayCallbacks) callconv(.c) ?Cf,
    CFArrayGetCount: *const fn (Cf) callconv(.c) isize,
    CFArrayGetValueAtIndex: *const fn (Cf, isize) callconv(.c) ?Cf,
    CFDataCreate: *const fn (?Cf, [*]const u8, isize) callconv(.c) ?Cf,
    CFDataGetLength: *const fn (Cf) callconv(.c) isize,
    CFDataGetBytePtr: *const fn (Cf) callconv(.c) ?[*]const u8,
    CFStringCreateWithBytes: *const fn (?Cf, [*]const u8, isize, u32, u8) callconv(.c) ?Cf,
    CFDateCreate: *const fn (?Cf, f64) callconv(.c) ?Cf,
    CFRelease: *const fn (Cf) callconv(.c) void,
    SecCertificateCreateWithData: *const fn (?Cf, Cf) callconv(.c) ?Cf,
    SecCertificateCopyData: *const fn (Cf) callconv(.c) ?Cf,
    SecPolicyCreateSSL: *const fn (u8, ?Cf) callconv(.c) ?Cf,
    SecTrustCreateWithCertificates: *const fn (Cf, Cf, *?Cf) callconv(.c) i32,
    SecTrustSetNetworkFetchAllowed: *const fn (Cf, u8) callconv(.c) i32,
    SecTrustGetNetworkFetchAllowed: *const fn (Cf, *u8) callconv(.c) i32,
    SecTrustSetVerifyDate: *const fn (Cf, Cf) callconv(.c) i32,
    SecTrustSetAnchorCertificates: *const fn (Cf, Cf) callconv(.c) i32,
    SecTrustSetAnchorCertificatesOnly: *const fn (Cf, u8) callconv(.c) i32,
    SecTrustEvaluateWithError: *const fn (Cf, *?Cf) callconv(.c) u8,
    SecTrustCopyCertificateChain: *const fn (Cf) callconv(.c) ?Cf,

    /// In the dyld shared cache since macOS 11, which `dlopen` reads by this path.
    const path = "/System/Library/Frameworks/Security.framework/Security";
    /// The one table in the process, filled by the first `load` to succeed.
    var loaded: aegis.Lazy(Security) = .init();

    /// The table, opened on the first call; later calls, from any thread, return the same one. A missing
    /// framework or symbol is `SystemTrustUnavailable`, and the next call tries again.
    pub fn load() error{SystemTrustUnavailable}!*const Security {
        @setRuntimeSafety(true);
        // Evaluation runs on the caller's thread or an executor's, with no `Io`. A caller arriving while
        // another opens the framework waits for that bounded load on the process futex, which the
        // threaded `Io` reaches whichever `Io` the program runs.
        return loaded.getOrInit(std.Io.Threaded.global_single_threaded.io(), @as([]const u8, path), open);
    }

    /// Every symbol, looked up in the library at `framework` into `table`, which is left alone on failure.
    pub fn open(framework: []const u8, table: *Security) error{SystemTrustUnavailable}!void {
        @setRuntimeSafety(true);
        var library = std.DynLib.open(framework) catch return error.SystemTrustUnavailable;
        var resolved: Security = undefined;
        const symbols = @typeInfo(Security).@"struct";
        inline for (symbols.field_names, symbols.field_types) |name, Symbol| {
            @field(resolved, name) = library.lookup(Symbol, name) orelse {
                library.close();
                return error.SystemTrustUnavailable;
            };
        }
        // The library stays open: the table points into it for the life of the process.
        table.* = resolved;
    }
};
test {
    @setRuntimeSafety(true);
    _ = @import("macos_test.zig");
}
