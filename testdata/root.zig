//! cloak's test data: the fixtures, vectors and keys its tests, probes and benchmarks read. It
//! stays out of src/ and of the package a project fetches (build.zig.zon's paths), and reaches
//! the tests only as the development build's module `testdata`.

/// The file at `path` under testdata/, embedded: `file("verify/fixtures/limbo.json")`.
pub fn file(comptime path: []const u8) @TypeOf(@embedFile(path)) {
    return @embedFile(path);
}
