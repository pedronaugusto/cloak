const std = @import("std");

/// What a project that depends on cloak builds: the `cloak` module, with aegis.
pub fn build(b: *std.Build) void {
    @setRuntimeSafety(true);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    b.modules.put(b.allocator, "cloak", createCloak(b, b, target, optimize)) catch @panic("out of memory configuring cloak");
}

/// cloak's development: its tests, checks and benchmarks, under preflight's
/// gate. Run through bay.
pub fn dev(b: *std.Build, tools: type) void {
    @setRuntimeSafety(true);
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const filters = b.option([]const []const u8, "test-filter", "Run tests containing this name") orelse &.{};
    const package = b.dependency("cloak", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    const preflight = tools.preflight;
    const test_step = b.step("test", "Run targeted credential and verification tests");
    const check = b.step("check", "Compile all declarations and tests");
    const freestanding = target.result.os.tag == .freestanding;
    if (freestanding) {
        // The core takes caller-provided services. Hosted tests and measurement
        // programs require OS I/O/threads and cannot run on a freestanding target.
        const core_module = b.createModule(.{ .root_source_file = p.path("ci/core.zig"), .target = target, .optimize = optimize });
        core_module.addImport("probes", createProbes(b, p, target, optimize));
        const core = b.addObject(.{ .name = "cloak-core-check", .root_module = core_module });
        check.dependOn(&core.step);
        test_step.dependOn(&core.step);
    } else {
        const shakedown = b.dependency("shakedown", .{ .target = target, .optimize = optimize });
        const test_module = b.createModule(.{ .root_source_file = p.path("src/tests.zig"), .target = target, .optimize = optimize });
        test_module.addImport("shakedown", shakedown.module("shakedown"));
        addAegis(p, test_module, target, optimize);
        nativeLinks(test_module, target);
        const tests = b.addTest(.{ .root_module = test_module, .filters = filters });
        test_step.dependOn(&b.addRunArtifact(tests).step);
        // The hardened tier's suites: the parser properties the fuzzer drives, and the tests
        // whose tasks share a session, a snapshot or a job, under ThreadSanitizer.
        const fuzz_tests = b.addTest(.{ .name = "parser-fuzz", .root_module = test_module, .filters = &.{"fuzz"} });
        b.step("parser-fuzz", "Run the parser fuzz properties alone").dependOn(&b.addRunArtifact(fuzz_tests).step);
        const concurrent_tests = b.addTest(.{ .name = "concurrent", .root_module = test_module, .filters = &.{"concurrent"} });
        b.step("concurrent", "Run the tests whose tasks share a session, a snapshot or a job").dependOn(&b.addRunArtifact(concurrent_tests).step);
        const check_module = b.createModule(.{ .root_source_file = p.path("src/tests.zig"), .target = target, .optimize = optimize });
        check_module.addImport("shakedown", shakedown.module("shakedown"));
        addAegisOnly(p, check_module, target, optimize);
        const checked = b.addTest(.{ .name = "check", .root_module = check_module, .emit_object = true });
        check.dependOn(&checked.step);
    }
    const host = b.graph.host;
    preflight.addCi(b, p, .{ .tests = test_step, .portable_tests = true, .hardened = if (freestanding) null else .{ .fuzz_step = "parser-fuzz", .tsan_step = "concurrent", .fuzz_iterations = 1000 }, .bench = .{
        .programs = &.{ .{ .name = "trust", .source = "bench/trust.zig" }, .{ .name = "credentials", .source = "bench/credentials.zig" }, .{ .name = "verification", .source = "bench/verification.zig" }, .{ .name = "constraints", .source = "bench/constraints.zig" }, .{ .name = "armor", .source = "bench/armor.zig" }, .{ .name = "services", .source = "bench/services.zig" }, .{ .name = "records", .source = "bench/records.zig" }, .{ .name = "handshake", .source = "bench/handshake.zig" }, .{ .name = "ecdh", .source = "bench/ecdh.zig" }, .{ .name = "speed", .source = "bench/speed.zig" }, .{ .name = "pkcs12", .source = "bench/pkcs12.zig" }, .{ .name = "field", .source = "bench/field.zig" }, .{ .name = "jose", .source = "bench/jose.zig" } },
        .imports = benchImports,
        .target = if (freestanding) host else target,
        .optimize = optimize,
    } });
    const options_checker = b.addExecutable(.{ .name = "cloak-options-check", .root_module = b.createModule(.{ .root_source_file = p.path("ci/options.zig"), .target = host, .optimize = .safe }) });
    const run_options = b.addRunArtifact(options_checker);
    run_options.addArg(b.graph.zig_exe);
    run_options.addFileArg(p.dependency("aegis", .{ .target = target, .optimize = optimize }).path("src/root.zig"));
    run_options.setCwd(p.path("."));
    b.step("check-options", "Reject consumers disabling private side-channel protections").dependOn(&run_options.step);
    const failstop = b.addExecutable(.{ .name = "cloak-failstop", .root_module = b.createModule(.{ .root_source_file = p.path("ci/failstop.zig"), .target = host, .optimize = .fast, .imports = &.{.{ .name = "cloak", .module = createCloak(b, p, host, .fast) }} }) });
    b.step("check-failstop", "Stop a caller that breaks a precondition, in ReleaseFast too").dependOn(&b.addRunArtifact(failstop).step);
    // Timing evidence on the build that ships: a statistical test, run by hand, never a gate.
    const timing_module = b.createModule(.{ .root_source_file = p.path("bench/timing.zig"), .target = host, .optimize = .fast, .imports = benchImports(b, host, .fast) });
    addAegisOnly(p, timing_module, host, .fast);
    timing_module.addImport("shakedown", b.dependency("shakedown", .{ .target = host, .optimize = .fast }).module("shakedown"));
    const timing = b.addRunArtifact(b.addExecutable(.{ .name = "cloak-timing", .root_module = timing_module }));
    timing.addPassthruArgs();
    b.step("timing", "Test the secret kernels' time against their secret on the ReleaseFast build (dudect)").dependOn(&timing.step);
    const wasm_target = b.resolveTargetQuery(.{ .cpu_arch = .wasm32, .os_tag = .freestanding });
    const wasm_module = b.createModule(.{ .root_source_file = p.path("ci/core.zig"), .target = wasm_target, .optimize = .safe });
    wasm_module.addImport("probes", createProbes(b, p, wasm_target, .safe));
    const wasm = b.addExecutable(.{ .name = "cloak-core-vectors", .root_module = wasm_module });
    wasm.entry = .disabled;
    wasm.rdynamic = true;
    wasm.stack_size = 2 * 1024 * 1024;
    // The module must import nothing (no host Io can reach it); a runtime is not needed to see that.
    const wasm_checker = b.addExecutable(.{ .name = "cloak-wasm-check", .root_module = b.createModule(.{ .root_source_file = p.path("ci/wasm.zig"), .target = host, .optimize = .safe, .imports = &.{.{ .name = "aegis", .module = p.dependency("aegis", .{ .target = host, .optimize = .safe }).module("aegis") }} }) });
    const wasm_run = b.addRunArtifact(wasm_checker);
    wasm_run.addFileArg(wasm.getEmittedBin());
    const check_wasm = b.step("check-wasm", "Check the portable core imports nothing on wasm32 and run its vectors");
    check_wasm.dependOn(&wasm_run.step);
    check_wasm.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "cloak-wasm-checker", .root_module = wasm_checker.root_module })).step);
    // The vectors run on the host, and on 32-bit x86 where the host executes it (Linux on x86_64),
    // so usize-width arithmetic runs at 32 bits there.
    var vector_targets: [2]std.Build.ResolvedTarget = .{ host, host };
    var vector_count: usize = 1;
    if (host.result.os.tag == .linux and host.result.cpu.arch == .x86_64) {
        vector_targets[1] = b.resolveTargetQuery(.{ .cpu_arch = .x86, .os_tag = .linux, .abi = .musl });
        vector_count = 2;
    }
    for (vector_targets[0..vector_count]) |vector_target| {
        const vector_module = b.createModule(.{ .root_source_file = p.path("ci/core.zig"), .target = vector_target, .optimize = .safe });
        vector_module.addImport("probes", createProbes(b, p, vector_target, .safe));
        check_wasm.dependOn(&b.addRunArtifact(b.addTest(.{ .name = "cloak-core-vectors", .root_module = vector_module })).step);
    }
    const example_module = b.createModule(.{ .root_source_file = p.path("ci/example.zig"), .target = host, .optimize = .safe });
    example_module.addImport("cloak", package.module("cloak"));
    const example = b.addTest(.{ .name = "cloak-readme-example", .root_module = example_module });
    b.step("check-example", "Execute the documented authentication example").dependOn(&b.addRunArtifact(example).step);
    const session_module = b.createModule(.{ .root_source_file = p.path("ci/session.zig"), .target = host, .optimize = .safe });
    session_module.addImport("cloak", package.module("cloak"));
    const session_example = b.addTest(.{ .name = "cloak-readme-session", .root_module = session_module });
    b.step("check-session", "Compile the documented session example against the public surface").dependOn(&b.addRunArtifact(session_example).step);
    preflight.addConsumerCheck(b, p, .{ .package = "cloak", .modules = &.{"cloak"}, .packages = &.{p.dependency("aegis", .{ .target = target, .optimize = optimize })}, .program = p.path("ci/consumer.zig") });
}

/// One module: certificates and TLS are namespaces of the root. TLS builds on certificates, which
/// reach the native trust store, so every TLS user reaches it and a second module would buy nothing.
/// `p` is the package's own build, which holds its files and aegis.
fn createCloak(b: *std.Build, p: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const result = b.createModule(.{ .root_source_file = p.path("src/root.zig"), .target = target, .optimize = optimize });
    addAegis(p, result, target, optimize);
    nativeLinks(result, target);
    return result;
}

/// The native trust store a target links: crypt32 on Windows. macOS opens Security at run time
/// (src/services/macos.zig), so an Apple target links only libSystem and needs no SDK.
fn nativeLinks(m: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    @setRuntimeSafety(true);
    switch (target.result.os.tag) {
        .windows => m.linkSystemLibrary("crypt32", .{}),
        else => {},
    }
}

fn benchImports(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) []const std.Build.Module.Import {
    @setRuntimeSafety(true);
    const package = b.dependency("cloak", .{ .target = target, .optimize = optimize });
    const p = package.builder;
    // Every program takes `cloak`, whose module carries the assembly once; a second module
    // carrying it too gives a program each routine twice.
    const records = b.createModule(.{ .root_source_file = p.path("src/tls/record.zig"), .target = target, .optimize = optimize });
    addAegisOnly(p, records, target, optimize);
    const armor = b.createModule(.{ .root_source_file = p.path("src/credentials/Pem.zig"), .target = target, .optimize = optimize });
    addAegisOnly(p, armor, target, optimize);
    // The scripted peer and drivers, rooted where they reach the TLS sources by relative path.
    const harness = b.createModule(.{ .root_source_file = p.path("src/testing.zig"), .target = target, .optimize = optimize });
    addAegisOnly(p, harness, target, optimize);
    nativeLinks(harness, target);
    return b.allocator.dupe(std.Build.Module.Import, &.{
        .{ .name = "harness", .module = harness },
        .{ .name = "cloak", .module = package.module("cloak") },
        .{ .name = "records", .module = records },
        .{ .name = "armor", .module = armor },
        .{ .name = "aegis", .module = p.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis") },
    }) catch @panic("out of memory configuring benchmark");
}

/// What every module rooted in `src` takes: aegis, and s2n-bignum's assembly for the target.
fn addAegis(p: *std.Build, m: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) void {
    @setRuntimeSafety(true);
    addAegisOnly(p, m, target, optimize);
    addAssembly(p, m, target);
}

/// aegis without the assembly: for a module compiled to one object and never linked (`check`),
/// which COFF cannot hold together with the assembly's objects, and for a module beside `cloak`'s
/// in one program, which has the assembly already.
fn addAegisOnly(p: *std.Build, m: *std.Build.Module, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) void {
    @setRuntimeSafety(true);
    m.addImport("aegis", p.dependency("aegis", .{ .target = target, .optimize = optimize }).module("aegis"));
}

/// s2n-bignum's routines (src/crypto/vendor, PROVENANCE.md), assembled from its files unchanged:
/// x86_64 everywhere (the Microsoft x64 prologues on Windows), AArch64 where the object format is
/// ELF or Mach-O. `src/crypto/field/p521.zig`'s `assembly` names the same targets; every other
/// target computes with fiat-crypto's Zig. The shim header on the include path first names each
/// routine `cloak_<routine>`, private to the image.
/// The s2n-bignum routines cloak computes with, by upstream directory: both forms of each NIST
/// field's multiplication and squaring, its inversion, P-521's addition, subtraction and negation
/// (P-256's and P-384's are fiat-crypto's, inlined), X25519's two ladders, and RSA's Montgomery
/// multiplication and squaring (`field/bignum.zig`).
const s2n_routines = [_]struct { []const u8, []const []const u8 }{
    .{ "p256", &.{ "bignum_montmul_p256", "bignum_montmul_p256_alt", "bignum_montsqr_p256", "bignum_montsqr_p256_alt", "bignum_montinv_p256" } },
    .{ "p384", &.{ "bignum_montmul_p384", "bignum_montmul_p384_alt", "bignum_montsqr_p384", "bignum_montsqr_p384_alt", "bignum_montinv_p384" } },
    .{ "p521", &.{ "bignum_add_p521", "bignum_sub_p521", "bignum_neg_p521", "bignum_mul_p521", "bignum_mul_p521_alt", "bignum_sqr_p521", "bignum_sqr_p521_alt", "bignum_inv_p521" } },
    .{ "curve25519", &.{ "curve25519_x25519", "curve25519_x25519_alt", "curve25519_x25519base", "curve25519_x25519base_alt" } },
    .{ "fastmul", &.{ "bignum_kmul_16_32", "bignum_kmul_32_64", "bignum_ksqr_16_32", "bignum_ksqr_32_64", "bignum_emontredc_8n" } },
    .{ "generic", &.{ "bignum_mul", "bignum_sqr", "bignum_montmul", "bignum_montsqr" } },
};

fn addAssembly(p: *std.Build, m: *std.Build.Module, target: std.Build.ResolvedTarget) void {
    @setRuntimeSafety(true);
    const t = target.result;
    const directory = switch (t.cpu.arch) {
        .x86_64 => "x86",
        .aarch64 => if (t.os.tag == .windows) return else "arm",
        else => return,
    };
    m.addIncludePath(p.path("src/crypto/vendor/shim"));
    m.addIncludePath(p.path("src/crypto/vendor"));
    const windows = if (t.os.tag == .windows) "-DWINDOWS_ABI=1" else "-DWINDOWS_ABI=0";
    for (s2n_routines) |group| {
        const curve, const routines = group;
        for (routines) |routine| {
            const name = p.fmt("src/crypto/vendor/s2n-bignum/{s}/{s}/{s}.S", .{ directory, curve, routine });
            m.addCSourceFile(.{ .file = p.path(name), .flags = &.{windows}, .language = .assembly_with_preprocessor });
        }
    }
}

/// The portable probes: certificates and the record and handshake kernels under one module, since a
/// source file belongs to one module and the probes reach files the public surface does not.
fn createProbes(b: *std.Build, p: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize) *std.Build.Module {
    @setRuntimeSafety(true);
    const probes = b.createModule(.{ .root_source_file = p.path("src/portable.zig"), .target = target, .optimize = optimize });
    addAegis(p, probes, target, optimize);
    nativeLinks(probes, target);
    return probes;
}
