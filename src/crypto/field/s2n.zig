//! s2n-bignum's routines as `build.zig` assembles them, each named `cloak_<routine>`, and the
//! one choice between the two forms of its multiplication and squaring that every curve's field
//! shares. On x86_64 the plain routines use BMI2 and ADX (mulx, adcx, adox) and the `_alt` ones
//! only the base instruction set. On AArch64 both run everywhere and the `_alt` ones suit cores
//! with a wide multiplier, which AWS-LC takes them on (Apple M, Neoverse V1/V2), one flag for
//! every curve as here. The choice is made once per process: at compile
//! time where the target decides it (x86_64 with BMI2 and ADX; an Apple OS), else at run time:
//! on x86_64 ladar's answer for BMI2 and ADX, on AArch64 Linux the core's model, cached.
const std = @import("std");
const builtin = @import("builtin");
const aegis = @import("aegis");
const ladar = @import("ladar");

/// Whether s2n-bignum's assembly is in this build: x86_64, and AArch64 where the object format
/// is ELF or Mach-O (its AArch64 files carry no COFF directives).
pub const assembly = switch (builtin.cpu.arch) {
    .x86_64 => true,
    .aarch64 => builtin.os.tag != .windows,
    else => false,
};

/// The plain multiplication and squaring, or the `_alt` ones.
pub const Variant = enum { plain, alt };

/// The routine `cloak_<name>` with the type `F` (a C-calling-convention function type).
pub fn routine(comptime F: type, comptime name: []const u8) *const F {
    if (!assembly) @compileError("s2n-bignum's assembly is not in this build");
    return @extern(*const F, .{ .name = "cloak_" ++ name });
}

/// The variant this process runs.
pub inline fn chosen() Variant {
    if (comptime fixed) |variant| return variant;
    return asked.get();
}

/// Whether this processor runs the plain routines at all: on x86_64 they need BMI2 and ADX.
pub fn plainRuns() bool {
    if (builtin.cpu.arch != .x86_64) return true;
    return ladar.has(.x86_bmi2_adx);
}

/// The variant the target alone decides, if it does.
const fixed: ?Variant = switch (builtin.cpu.arch) {
    .x86_64 => if (ladar.guaranteed.contains(.x86_bmi2_adx)) .plain else null,
    .aarch64 => if (builtin.os.tag.isDarwin()) .alt else if (builtin.os.tag == .linux) null else .plain,
    else => null,
};

/// The processor's answer, asked once. Racing first calls reach the same answer.
const asked = struct {
    const Answer = enum(u8) { unasked, plain, alt };
    var state: aegis.Atomic(Answer) = .init(.unasked);

    fn get() Variant {
        switch (state.load(.monotonic)) {
            .unasked => {},
            .plain => return .plain,
            .alt => return .alt,
        }
        const variant: Variant = switch (builtin.cpu.arch) {
            .x86_64 => if (ladar.has(.x86_bmi2_adx)) .plain else .alt,
            .aarch64 => if (wideMultiplier()) .alt else .plain,
            else => unreachable, // unreachable: `assembly` holds only on x86_64 and AArch64
        };
        remember(variant);
        return variant;
    }

    fn remember(variant: Variant) void {
        state.store(switch (variant) {
            .plain => .plain,
            .alt => .alt,
        }, .monotonic);
    }
};

test "s2n-bignum's cached choice holds either variant" {
    if (!assembly) return error.SkipZigTest;
    const saved = asked.state.load(.monotonic);
    defer asked.state.store(saved, .monotonic);
    for ([_]Variant{ .plain, .alt }) |variant| {
        asked.remember(variant);
        try std.testing.expectEqual(variant, asked.get());
    }
}

test "on x86_64 the plain routines run exactly where ladar finds BMI2 and ADX" {
    if (builtin.cpu.arch != .x86_64) return error.SkipZigTest;
    try std.testing.expectEqual(ladar.has(.x86_bmi2_adx), plainRuns());
    try std.testing.expectEqual(@as(Variant, if (ladar.has(.x86_bmi2_adx)) .plain else .alt), chosen());
}

/// AArch64 Linux: a core with a wide multiplier by its MIDR_EL1, which the kernel emulates
/// for user space when it says so (HWCAP_CPUID, bit 11): Apple's (implementer 0x61) and
/// Arm's Neoverse V1 (0xd40) and V2 (0xd4f).
fn wideMultiplier() bool {
    if (builtin.os.tag != .linux) return false;
    if (std.os.linux.getauxval(std.elf.AT.HWCAP) & (1 << 11) == 0) return false;
    // MIDR_EL1, which the kernel emulates for user space under HWCAP_CPUID
    const midr = asm volatile ("mrs %[midr], midr_el1"
        : [midr] "=r" (-> u64),
    );
    const implementer = (midr >> 24) & 0xff;
    const part = (midr >> 4) & 0xfff;
    return implementer == 0x61 or (implementer == 0x41 and (part == 0xd40 or part == 0xd4f));
}
