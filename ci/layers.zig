const gantry = @import("gantry");
pub const layers: []const gantry.rules.Layer = &.{.{ .name = "cloak", .patterns = &.{"src/root.zig"} }};
pub const entries: []const []const u8 = &.{"src/root.zig"};
pub const required = [_][]const u8{"src/root.zig"};
pub const modules: []const gantry.NamedModule = &.{};
pub const references: []const gantry.rules.ReferenceRule = &.{};
