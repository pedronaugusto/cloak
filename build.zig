const std = @import("std");
const preflight = @import("preflight");
pub fn build(b: *std.Build) void {
    @setRuntimeSafety(true);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    _ = b.addModule("cloak", .{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    if (b.pkg_hash.len != 0) return;
    const test_step = b.step("test", "Compile the initial package floor");
    const tests = b.addTest(.{ .root_module = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize }) });
    test_step.dependOn(&b.addRunArtifact(tests).step);
    b.step("check", "Compile the package floor").dependOn(&tests.step);
    preflight.addCi(b, .{ .tests = test_step });
    const tools = b.dependencyLazy("preflight", .{}) catch return;
    const host = b.graph.host;
    const gantry = tools.builder.dependencyLazy("gantry", .{ .target = host, .optimize = .safe }) catch return;
    const plan_tool = b.addExecutable(.{ .name = "cloak-ci-plan", .root_module = b.createModule(.{
        .root_source_file = tools.path("src/main.zig"),
        .target = host,
        .optimize = .safe,
        .imports = &.{.{ .name = "gantry", .module = gantry.module("gantry") }},
    }) });
    const plan = b.addRunArtifact(plan_tool);
    plan.addArg("plan");
    plan.setCwd(b.path("."));
    plan.addPassthruArgs();
    b.step("plan", "Describe the hosted CI matrices from ci/workflow.json").dependOn(&plan.step);
}
