//! Native policy success followed by portable checks of exactly its selected path.
const std = @import("std");
const types = @import("types.zig");
const services = @import("services.zig");
const verify = @import("verify.zig");
const NativeVerification = @This();
job: services.Job,
pub const InitError = services.Job.InitError;
pub const InitOptions = services.Job.Options;
pub fn init(gpa: std.mem.Allocator, budget: *services.Budget, request: types.Request, options: InitOptions) InitError!NativeVerification {
    @setRuntimeSafety(true);
    return .{ .job = try services.Job.init(gpa, budget, request, options) };
}
pub const TakeError = services.Job.TakeError || types.Verification.CheckError || verify.VerifyError || error{ VerificationExpired, ValidationTimeChanged };
/// `now` is fresh real time from the caller, independent of the captured validation time.
/// Take once; successful native policy alone never becomes an authenticated receipt.
pub fn take(service: NativeVerification, gpa: std.mem.Allocator, request: types.Request, now: std.Io.Timestamp) TakeError!types.Verification {
    @setRuntimeSafety(true);
    var path = try service.job.take(request);
    defer path.deinit();
    try path.check(request);
    var receipt = try verify.nativePath(gpa, request, path.chain);
    errdefer receipt.deinit();
    try receipt.check(request);
    if (now.nanoseconds < receipt.validation_time.nanoseconds) return error.ValidationTimeChanged;
    if (types.seconds(receipt.expires) < types.seconds(now)) return error.VerificationExpired;
    return receipt;
}
pub fn abandon(service: NativeVerification) void {
    @setRuntimeSafety(true);
    service.job.abandon();
}
pub fn deinit(service: NativeVerification) void {
    @setRuntimeSafety(true);
    service.job.deinit();
}
test {
    @setRuntimeSafety(true);
    _ = @import("NativeVerification_test.zig");
}
