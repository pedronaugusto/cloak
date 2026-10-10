const std = @import("std");

pub fn build(b: *std.Build) void {
    @setRuntimeSafety(true);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "test-filter", "Run tests containing this name") orelse &.{};
    _ = module(b, target, optimize);
    if (b.pkg_hash.len != 0) return;
    const preflight = b.lazyImport(@This(), "preflight") orelse return;
    const test_step = b.step("test", "Run targeted credential and verification tests");
    const check = b.step("check", "Compile all declarations and tests");
    const freestanding = target.result.os.tag == .freestanding;
    if (freestanding) {
        // The core takes caller-provided services. Hosted tests and measurement
        // programs require OS I/O/threads and cannot run on a freestanding target.
        const core_module = b.createModule(.{ .root_source_file = b.path("ci/core.zig"), .target = target, .optimize = optimize });
        core_module.addImport("cloak", b.modules.get("cloak.certificates").?);
        addTlsVectors(b, core_module, target, optimize, b.modules.get("cloak.certificates").?);
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
        // TLS is its own module, importing the certificates module by name; its tests are
        // rooted in that module rather than reaching its files through the package-wide root.
        const tls_tests = b.addTest(.{ .root_module = tlsTestModule(b, target, optimize, shakedown.module("shakedown")), .filters = filters });
        test_step.dependOn(&b.addRunArtifact(tls_tests).step);
        const check_module = b.createModule(.{ .root_source_file = b.path("src/tests.zig"), .target = target, .optimize = optimize });
        check_module.addImport("shakedown", shakedown.module("shakedown"));
        addAegis(b, check_module, target, optimize);
        const checked = b.addTest(.{ .name = "check", .root_module = check_module, .emit_object = true });
        check.dependOn(&checked.step);
        const tls_checked = b.addTest(.{ .name = "check-tls", .root_module = tlsTestModule(b, target, optimize, shakedown.module("shakedown")), .emit_object = true });
        check.dependOn(&tls_checked.step);
        const fuzz_module = b.createModule(.{ .root_source_file = b.path("src/tests.zig"), .target = target, .optimize = optimize });
        fuzz_module.addImport("shakedown", shakedown.module("shakedown"));
        addAegis(b, fuzz_module, target, optimize);
        nativeLinks(fuzz_module, target);
        const fuzz_tests = b.addTest(.{ .name = "cloak-fuzz", .root_module = fuzz_module, .filters = filters, .use_llvm = true });
        const fuzz_step = b.step("fuzz", "Run independent parser campaigns using the compiler fuzz runner");
        fuzz_step.dependOn(&b.addRunArtifact(fuzz_tests).step);
        const tls_fuzz = b.addTest(.{ .name = "cloak-tls-fuzz", .root_module = tlsTestModule(b, target, optimize, shakedown.module("shakedown")), .filters = filters, .use_llvm = true });
        fuzz_step.dependOn(&b.addRunArtifact(tls_fuzz).step);
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
    run_options.setCwd(b.path("."));
    b.step("check-options", "Reject consumers disabling private side-channel protections").dependOn(&run_options.step);
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_module = b.createModule(.{ .root_source_file = b.path("ci/core.zig"), .target = wasm_target, .optimize = .safe });
    const wasm_cloak = createCloak(b, wasm_target, .safe);
    wasm_module.addImport("cloak", wasm_cloak.import_table.get("cloak.certificates").?);
    addTlsVectors(b, wasm_module, wasm_target, .safe, wasm_cloak.import_table.get("cloak.certificates").?);
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
    preflight.addConsumerCheck(b, .{ .package = "cloak", .modules = &.{ "cloak", "cloak.certificates", "cloak.tls" }, .packages = &.{b.dependency("aegis", .{ .target = target, .optimize = optimize })}, .program = b.path("ci/consumer.zig") });
}

fn module(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const result = createCloak(b, target, optimize);
    b.modules.put(b.allocator, "cloak", result) catch @panic("out of memory configuring cloak");
    b.modules.put(b.allocator, "cloak.tls", result.import_table.get("cloak.tls").?) catch @panic("out of memory configuring TLS");
    b.modules.put(b.allocator, "cloak.certificates", result.import_table.get("cloak.certificates").?) catch @panic("out of memory configuring certificates");
    return result;
}

fn createCloak(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const result = b.createModule(.{ .root_source_file = b.path("src/root.zig"), .target = target, .optimize = optimize });
    const certificates = b.createModule(.{ .root_source_file = b.path("src/certificates.zig"), .target = target, .optimize = optimize });
    addAegis(b, certificates, target, optimize);
    nativeLinks(certificates, target);
    const tls = b.createModule(.{ .root_source_file = b.path("src/tls.zig"), .target = target, .optimize = optimize });
    addAegis(b, tls, target, optimize);
    tls.addImport("cloak.certificates", certificates);
    result.addImport("cloak.tls", tls);
    result.addImport("cloak.certificates", certificates);
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
    harness.addImport("cloak.certificates", createCloak(b, target, optimize).import_table.get("cloak.certificates").?);
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

fn addTlsVectors(b: *std.Build, m: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, certificates: *std.Build.Module) void {
    @setRuntimeSafety(true);
    const vectors = b.createModule(.{ .root_source_file = b.path("src/portable.zig"), .target = target, .optimize = optimize });
    addAegis(b, vectors, target, optimize);
    vectors.addImport("cloak.certificates", certificates);
    m.addImport("tls_vectors", vectors);
}

/// The TLS module as a test root: tests there import the certificates module by name.
fn tlsTestModule(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, shakedown: *std.Build.Module) *std.Build.Module {
    @setRuntimeSafety(true);
    const tls = createCloak(b, target, optimize).import_table.get("cloak.tls").?;
    tls.addImport("shakedown", shakedown);
    return tls;
}
