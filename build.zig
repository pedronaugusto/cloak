const std = @import("std");
const preflight = @import("preflight");

pub fn build(b: *std.Build) void {
    @setRuntimeSafety(true);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "test-filter", "Run tests containing this name") orelse &.{};
    _ = module(b, target, optimize);
    if (b.pkg_hash.len != 0) return;
    const test_step = b.step("test", "Run targeted credential and verification tests");
    const check = b.step("check", "Compile all declarations and tests");
    const test_module = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    const shakedown = b.dependencyLazy("shakedown", .{ .target = target, .optimize = optimize }) catch return;
    test_module.addImport("shakedown", shakedown.module("shakedown"));
    nativeLinks(test_module, target);
    const tests = b.addTest(.{ .root_module = test_module, .filters = filters });
    const check_module = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    check_module.addImport("shakedown", shakedown.module("shakedown"));
    const checked = b.addTest(.{ .name = "check", .root_module = check_module, .emit_object = true });
    if (target.result.os.tag == .freestanding) {
        const core_module = b.createModule(.{ .root_source_file = b.path("ci/core.zig"), .target = target, .optimize = optimize });
        core_module.addImport("cloak", b.modules.get("cloak").?);
        const core = b.addObject(.{ .name = "cloak-core-check", .root_module = core_module });
        check.dependOn(&core.step);
    } else check.dependOn(&checked.step);
    test_step.dependOn(&b.addRunArtifact(tests).step);
    const fuzz_module = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    fuzz_module.addImport("shakedown", shakedown.module("shakedown"));
    nativeLinks(fuzz_module, target);
    const fuzz_tests = b.addTest(.{ .name = "cloak-fuzz", .root_module = fuzz_module, .filters = filters, .use_llvm = true });
    b.step("fuzz", "Run independent parser campaigns using the compiler fuzz runner").dependOn(&b.addRunArtifact(fuzz_tests).step);
    preflight.addCi(b, .{ .tests = test_step, .portable_tests = true, .bench = .{
        .programs = &.{ .{ .name = "trust", .source = "bench/trust.zig" }, .{ .name = "credentials", .source = "bench/credentials.zig" }, .{ .name = "verification", .source = "bench/verification.zig" }, .{ .name = "constraints", .source = "bench/constraints.zig" } },
        .imports = benchImports,
        .target = target,
        .optimize = optimize,
    } });
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
    const options_checker = b.addExecutable(.{ .name = "cloak-options-check", .root_module = b.createModule(.{ .root_source_file = b.path("ci/options.zig"), .target = host, .optimize = .safe }) });
    const run_options = b.addRunArtifact(options_checker);
    run_options.addArg(b.graph.zig_exe);
    run_options.setCwd(b.path("."));
    b.step("check-options", "Reject consumers disabling private side-channel protections").dependOn(&run_options.step);
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_module = b.createModule(.{ .root_source_file = b.path("ci/core.zig"), .target = wasm_target, .optimize = .safe });
    wasm_module.addImport("cloak", b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = wasm_target, .optimize = .safe }));
    const wasm = b.addExecutable(.{ .name = "cloak-core-vectors", .root_module = wasm_module });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    wasm.stack_size = 2 * 1024 * 1024;
    const wasm_run = b.addSystemCommand(&.{ "node", "-e", "const fs = require('fs'); WebAssembly.instantiate(fs.readFileSync(process.argv[1]), {}).then(({instance}) => { const code = instance.exports.cloakCoreVectors(); if (code !== 0) throw new Error('cloak core vector failure ' + code); });" });
    wasm_run.addFileArg(wasm.getEmittedBin());
    b.step("check-wasm", "Run portable credential and authenticated path vectors without hosted Io").dependOn(&wasm_run.step);
    const example_module = b.createModule(.{ .root_source_file = b.path("ci/example.zig"), .target = host, .optimize = .safe });
    example_module.addImport("cloak", b.modules.get("cloak").?);
    const example = b.addTest(.{ .name = "cloak-readme-example", .root_module = example_module });
    b.step("check-example", "Execute the documented authentication example").dependOn(&b.addRunArtifact(example).step);
    preflight.addConsumerCheck(b, .{ .package = "cloak", .program = b.path("ci/consumer.zig") });
}

fn module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const result = b.addModule("cloak", .{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    nativeLinks(result, target);
    return result;
}

fn nativeLinks(m: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    @setRuntimeSafety(true);
    switch (target.result.os.tag) {
        .macos => {
            m.linkFramework("Security", .{});
            m.linkFramework("CoreFoundation", .{});
        },
        .windows => m.linkSystemLibrary("crypt32", .{}),
        else => {},
    }
}

fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    @setRuntimeSafety(true);
    const bench_module = b.createModule(.{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    nativeLinks(bench_module, target);
    return b.allocator.dupe(std.Build.Module.Import, &.{.{ .name = "cloak", .module = bench_module }}) catch @panic("out of memory configuring benchmark");
}
