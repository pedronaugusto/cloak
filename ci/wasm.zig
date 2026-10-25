//! The portable core's wasm32 module takes nothing from its host: no import at all, so no Io,
//! clock, entropy or allocator reaches it but what the caller passes, and it exports the vectors.
//! Read from the built module's sections (WebAssembly core spec 5.5), no runtime needed.
const std = @import("std");
const aegis = @import("aegis");

pub fn main(init: std.process.Init) !void {
    @setRuntimeSafety(true);
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    if (args.len != 2) return error.WasmModuleRequired;
    const module = try aegis.own.readFile(init.io, .cwd(), args[1], init.arena.allocator(), .fromRaw(16 * 1024 * 1024));
    try check(module);
}

fn check(module: []const u8) !void {
    @setRuntimeSafety(true);
    if (module.len < 8 or !std.mem.eql(u8, module[0..8], "\x00asm\x01\x00\x00\x00")) return error.NotAWasmModule;
    var reader: Reader = .{ .bytes = module, .at = 8 };
    var exported = false;
    while (reader.at < module.len) {
        const id = try reader.byte();
        const size = try reader.uleb();
        const body = try reader.take(size);
        var section: Reader = .{ .bytes = body, .at = 0 };
        switch (id) {
            2 => if (try section.uleb() != 0) return error.ModuleImportsFromHost,
            7 => {
                var count = try section.uleb();
                while (count > 0) : (count -= 1) {
                    const name = try section.take(try section.uleb());
                    const kind = try section.byte();
                    _ = try section.uleb();
                    if (kind == 0 and std.mem.eql(u8, name, "cloakCoreVectors")) exported = true;
                }
            },
            else => {},
        }
    }
    if (!exported) return error.VectorsNotExported;
}

const Reader = struct {
    bytes: []const u8,
    at: usize,

    fn byte(r: *Reader) !u8 {
        @setRuntimeSafety(true);
        if (r.at >= r.bytes.len) return error.TruncatedModule;
        defer r.at += 1;
        return r.bytes[r.at];
    }

    fn take(r: *Reader, n: usize) ![]const u8 {
        @setRuntimeSafety(true);
        if (n > r.bytes.len - r.at) return error.TruncatedModule;
        defer r.at += n;
        return r.bytes[r.at..][0..n];
    }

    fn uleb(r: *Reader) !usize {
        @setRuntimeSafety(true);
        var result: u32 = 0;
        var shift: u5 = 0;
        while (true) {
            const b = try r.byte();
            if (shift == 28 and b > 0x0f) return error.MalformedModule;
            result |= @as(u32, b & 0x7f) << shift;
            if (b & 0x80 == 0) return result;
            shift += 7;
        }
    }
};

test "an import is refused, the vectors' export found" {
    // Type section omitted: the checker reads only imports and exports.
    const bare = "\x00asm\x01\x00\x00\x00";
    try std.testing.expectError(error.VectorsNotExported, check(bare));
    const exports = bare ++ "\x07\x14\x01\x10cloakCoreVectors\x00\x00";
    try check(exports);
    const imports = exports ++ "\x02\x0b\x01\x03env\x03now\x00\x00";
    try std.testing.expectError(error.ModuleImportsFromHost, check(imports));
}
