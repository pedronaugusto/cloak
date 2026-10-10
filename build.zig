const std = @import("std");

pub fn build(b: *std.Build) void {
    @setRuntimeSafety(true);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "test-filter", "Run tests containing this name") orelse &.{};
    b.modules.put(b.allocator, "cloak", createCloak(b, target, optimize)) catch @panic("out of memory configuring cloak");
    if (b.pkg_hash.len != 0) return;
    const preflight = b.lazyImport(@This(), "preflight") orelse return;
    const test_step = b.step("test", "Run targeted credential and verification tests");
    const check = b.step("check", "Compile all declarations and tests");
    const freestanding = target.result.os.tag == .freestanding;
    if (freestanding) {
        // The core takes caller-provided services. Hosted tests and measurement
        // programs require OS I/O/threads and cannot run on a freestanding target.
        const core_module = b.createModule(.{ .root_source_file = b.path("ci/core.zig"), .target = target, .optimize = optimize });
        core_module.addImport("probes", createProbes(b, target, optimize));
        const core = b.addObject(.{ .name = "cloak-core-check", .root_module = core_module });
        check.dependOn(&core.step);
        test_step.dependOn(&core.step);
    } else {
        const shakedown = b.dependencyLazy("shakedown", .{ .target = target, .optimize = optimize }) catch return;
        const test_module = b.createModule(.{ .root_source_file = b.path("src/tests.zig"), .target = target, .optimize = optimize });
        test_module.addImport("shakedown", shakedown.module("shakedown"));
        addAegis(b, test_module, target, optimize);
        nativeLinks(test_module, target);
        const tests = b.addTest(.{ .root_module = test_module, .filters = filters });
        test_step.dependOn(&b.addRunArtifact(tests).step);
        const check_module = b.createModule(.{ .root_source_file = b.path("src/tests.zig"), .target = target, .optimize = optimize });
        check_module.addImport("shakedown", shakedown.module("shakedown"));
        addAegis(b, check_module, target, optimize);
        const checked = b.addTest(.{ .name = "check", .root_module = check_module, .emit_object = true });
        check.dependOn(&checked.step);
    }
    const host = b.graph.host;
    preflight.addCi(b, .{ .tests = test_step, .portable_tests = true, .bench = .{
        .programs = &.{ .{ .name = "trust", .source = "bench/trust.zig" }, .{ .name = "credentials", .source = "bench/credentials.zig" }, .{ .name = "verification", .source = "bench/verification.zig" }, .{ .name = "constraints", .source = "bench/constraints.zig" }, .{ .name = "armor", .source = "bench/armor.zig" }, .{ .name = "services", .source = "bench/services.zig" }, .{ .name = "records", .source = "bench/records.zig" }, .{ .name = "handshake", .source = "bench/handshake.zig" }, .{ .name = "ecdh", .source = "bench/ecdh.zig" } },
        .imports = benchImports,
        .target = if (freestanding) host else target,
        .optimize = optimize,
    } });
    const options_checker = b.addExecutable(.{ .name = "cloak-options-check", .root_module = b.createModule(.{ .root_source_file = b.path("ci/options.zig"), .target = host, .optimize = .safe }) });
    const run_options = b.addRunArtifact(options_checker);
    run_options.addArg(b.graph.zig_exe);
    run_options.addFileArg(b.dependency("aegis", .{ .target = target, .optimize = optimize }).path("src/root.zig"));
    run_options.setCwd(b.path("."));
    b.step("check-options", "Reject consumers disabling private side-channel protections").dependOn(&run_options.step);
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_module = b.createModule(.{ .root_source_file = b.path("ci/core.zig"), .target = wasm_target, .optimize = .safe });
    wasm_module.addImport("probes", createProbes(b, wasm_target, .safe));
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
    const session_module = b.createModule(.{ .root_source_file = b.path("ci/session.zig"), .target = host, .optimize = .safe });
    session_module.addImport("cloak", b.modules.get("cloak").?);
    const session_example = b.addTest(.{ .name = "cloak-readme-session", .root_module = session_module });
    b.step("check-session", "Compile the documented session example against the public surface").dependOn(&b.addRunArtifact(session_example).step);
    preflight.addConsumerCheck(b, .{ .package = "cloak", .modules = &.{"cloak"}, .packages = &.{b.dependency("aegis", .{ .target = target, .optimize = optimize })}, .program = b.path("ci/consumer.zig") });
}

/// One module: certificates and TLS are namespaces of the root. TLS builds on certificates, which
/// link the native trust store, so every TLS user links it and a second module would buy nothing.
fn createCloak(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const result = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    addAegis(b, result, target, optimize);
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
    const bench_module = createCloak(b, target, optimize);
    const records = b.createModule(.{ .root_source_file = b.path("src/tls/record.zig"), .target = target, .optimize = optimize });
    addAegis(b, records, target, optimize);
    const armor = b.createModule(.{ .root_source_file = b.path("src/credentials/Pem.zig"), .target = target, .optimize = optimize });
    addAegis(b, armor, target, optimize);
    const shakedown = b.dependencyLazy("shakedown", .{ .target = target, .optimize = optimize }) catch @panic("missing test dependency for benchmarks");
    // The scripted peer and drivers, rooted where they reach the TLS sources by relative path.
    const harness = b.createModule(.{ .root_source_file = b.path("src/testing.zig"), .target = target, .optimize = optimize });
    addAegis(b, harness, target, optimize);
    nativeLinks(harness, target);
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "harness", .module = harness },
        .{ .name = "cloak", .module = bench_module },
        .{ .name = "records", .module = records },
        .{ .name = "armor", .module = armor },
        .{ .name = "shakedown", .module = shakedown.module("shakedown") },
    }) catch @panic("out of memory configuring benchmark");
}

fn addAegis(b: *std.Build, m: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) void {
    @setRuntimeSafety(true);
    m.addImport("aegis", b.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis"));
}

/// The portable probes: certificates and the record and handshake kernels under one module, since a
/// source file belongs to one module and the probes reach files the public surface does not.
fn createProbes(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const probes = b.createModule(.{ .root_source_file = b.path("src/portable.zig"), .target = target, .optimize = optimize });
    addAegis(b, probes, target, optimize);
    nativeLinks(probes, target);
    return probes;
}
