//! A mutable trust builder and immutable, retained trust snapshots.
const std = @import("std");
const builtin = @import("builtin");
const certificate = @import("certificate.zig");
const Trust = @This();

gpa: std.mem.Allocator,
/// Private: only the builder may mutate these certificate buffers.
roots: std.ArrayList([]const u8) = .empty,
/// Private: bytes charged against the bounded root store.
bytes: usize = 0,
/// Private: the next generation published by this builder.
next_generation: u64 = 1,
/// Private: native policy is evaluated by an owned service job.
system: System = .portable,

pub const System = enum { portable, macos, windows };
pub const Limits = struct {
    roots: usize = 4096,
    bytes: usize = 16 * 1024 * 1024,
    file_bytes: usize = 1024 * 1024,
    certificate_bytes: usize = 64 * 1024,
    directory_entries: usize = 8192,
};
pub const AddDerError = std.mem.Allocator.Error || certificate.ParseError || error{ TrustLimit, MixedTrustPolicies };
pub const AddPemError = AddDerError || error{ InvalidPem, InvalidPadding, InvalidCharacter };
pub const LoadOptions = struct { limits: Limits = .{}, timeout: std.Io.Timeout = .none };
pub const AddFileError = AddPemError || std.Io.Dir.ReadFileAllocError || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error || std.Io.ConcurrentError || std.Io.Event.WaitTimeoutError;
pub const AddDirError = AddFileError || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error;
pub const AddSystemError = AddDirError || error{ SystemTrustUnavailable, UnsupportedPlatform };
pub const FreezeError = certificate.Issuers.InitError || error{ NoTrustAnchors, GenerationExhausted };

pub fn init(gpa: std.mem.Allocator) Trust {
    @setRuntimeSafety(true);
    return .{ .gpa = gpa };
}

pub fn deinit(t: *Trust) void {
    @setRuntimeSafety(true);
    t.rollback(0, 0);
    t.roots.deinit(t.gpa);
    t.* = undefined;
}

pub fn addDer(t: *Trust, der: []const u8, limits: Limits) AddDerError!void {
    @setRuntimeSafety(true);
    if (t.system != .portable) return error.MixedTrustPolicies;
    if (der.len > limits.certificate_bytes) return error.TrustLimit;
    _ = try certificate.parse(der, .{});
    for (t.roots.items) |root| if (std.mem.eql(u8, root, der)) return;
    if (t.roots.items.len >= limits.roots or der.len > limits.bytes -| t.bytes) return error.TrustLimit;
    const copy = try t.gpa.dupe(u8, der);
    errdefer t.gpa.free(copy);
    try t.roots.append(t.gpa, copy);
    t.bytes += copy.len;
}

/// Atomic import: malformed later blocks leave the previous store intact.
pub fn addPem(t: *Trust, pem: []const u8, limits: Limits) AddPemError!void {
    @setRuntimeSafety(true);
    if (pem.len > limits.file_bytes) return error.TrustLimit;
    const count = t.roots.items.len;
    const bytes = t.bytes;
    errdefer t.rollback(count, bytes);
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var remaining = std.mem.trim(u8, pem, " \t\r\n");
    if (remaining.len == 0) return error.InvalidPem;
    while (remaining.len != 0) {
        if (!std.mem.startsWith(u8, remaining, begin)) return error.InvalidPem;
        remaining = remaining[begin.len..];
        const finish = std.mem.find(u8, remaining, end) orelse return error.InvalidPem;
        const encoded = remaining[0..finish];
        const compact = try t.gpa.alloc(u8, encoded.len);
        defer t.gpa.free(compact);
        var len: usize = 0;
        for (encoded) |c| {
            if (std.ascii.isWhitespace(c)) continue;
            compact[len] = c;
            len += 1;
        }
        const decoder = std.base64.standard.Decoder;
        const der_len = decoder.calcSizeForSlice(compact[0..len]) catch return error.InvalidPem;
        if (der_len > limits.certificate_bytes) return error.TrustLimit;
        const der = try t.gpa.alloc(u8, der_len);
        defer t.gpa.free(der);
        decoder.decode(der, compact[0..len]) catch return error.InvalidPem;
        try t.addDer(der, limits);
        remaining = std.mem.trim(u8, remaining[finish + end.len ..], " \t\r\n");
    }
}

/// Loading occurs before traffic. Finite deadlines use caller-provided Io concurrency;
/// cancellation joins the loader before rolling back borrowed builder memory.
pub fn addFile(t: *Trust, io: std.Io, path: []const u8, options: LoadOptions) AddFileError!void {
    @setRuntimeSafety(true);
    try t.load(io, path, options, .file);
}
pub fn addDir(t: *Trust, io: std.Io, path: []const u8, options: LoadOptions) AddDirError!void {
    @setRuntimeSafety(true);
    try t.load(io, path, options, .directory);
}
pub fn addSystem(t: *Trust, io: std.Io, options: LoadOptions) AddSystemError!void {
    @setRuntimeSafety(true);
    if (builtin.os.tag == .macos or builtin.os.tag == .windows) return t.systemLoad(io, options.limits);
    // The system-file loader shares one deadline across all fallback paths.
    try t.systemTimed(io, options);
}
const LoadKind = enum { file, directory };
fn load(t: *Trust, io: std.Io, path: []const u8, options: LoadOptions, kind: LoadKind) AddDirError!void {
    @setRuntimeSafety(true);
    const count = t.roots.items.len;
    const bytes = t.bytes;
    errdefer t.rollback(count, bytes);
    if (options.timeout == .none) return t.perform(io, path, options.limits, kind);
    const deadline = options.timeout.toDeadline(io);
    if (deadline.deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
    var event: std.Io.Event = .unset;
    var work = try io.concurrent(loadTask, .{ t, io, path, options.limits, kind, &event });
    t.waitLoad(io, &event, deadline) catch |err| {
        _ = work.cancel(io) catch {
            // Cancellation joined the loader; preserve the expired caller deadline.
            return err;
        };
        return err;
    };
    try work.await(io);
}
fn perform(t: *Trust, io: std.Io, path: []const u8, limits: Limits, kind: LoadKind) AddDirError!void {
    @setRuntimeSafety(true);
    switch (kind) {
        .file => try t.file(io, path, limits),
        .directory => try t.directory(io, path, limits),
    }
}
fn loadTask(t: *Trust, io: std.Io, path: []const u8, limits: Limits, kind: LoadKind, event: *std.Io.Event) AddDirError!void {
    @setRuntimeSafety(true);
    defer event.set(io);
    try t.perform(io, path, limits, kind);
}
fn waitLoad(_: *Trust, io: std.Io, event: *std.Io.Event, deadline: std.Io.Timeout) std.Io.Event.WaitTimeoutError!void {
    @setRuntimeSafety(true);
    while (true) {
        event.waitTimeout(io, deadline) catch |err| switch (err) {
            error.Timeout => {
                if (deadline.deadline.durationFromNow(io).raw.nanoseconds <= 0) return err;
                continue;
            },
            else => return err,
        };
        if (deadline.deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
        return;
    }
}
fn systemTimed(t: *Trust, io: std.Io, options: LoadOptions) AddSystemError!void {
    @setRuntimeSafety(true);
    const count = t.roots.items.len;
    const bytes = t.bytes;
    errdefer t.rollback(count, bytes);
    if (options.timeout == .none) return t.systemLoad(io, options.limits);
    const deadline = options.timeout.toDeadline(io);
    if (deadline.deadline.durationFromNow(io).raw.nanoseconds <= 0) return error.Timeout;
    var event: std.Io.Event = .unset;
    var work = try io.concurrent(systemTask, .{ t, io, options.limits, &event });
    t.waitLoad(io, &event, deadline) catch |err| {
        _ = work.cancel(io) catch {
            // Cancellation joined the loader; preserve the expired caller deadline.
            return err;
        };
        return err;
    };
    try work.await(io);
}
fn systemTask(t: *Trust, io: std.Io, limits: Limits, event: *std.Io.Event) AddSystemError!void {
    @setRuntimeSafety(true);
    defer event.set(io);
    try t.systemLoad(io, limits);
}

/// Loading occurs before traffic; `io` and file ownership remain per call.
fn file(t: *Trust, io: std.Io, path: []const u8, limits: Limits) AddFileError!void {
    @setRuntimeSafety(true);
    const pem = try std.Io.Dir.cwd().readFileAlloc(io, path, t.gpa, .limited(limits.file_bytes));
    defer t.gpa.free(pem);
    try t.addPem(pem, limits);
}

/// Directory scans are explicit, bounded and transactional. Symlinks are
/// followed by openFile, as system CA directories conventionally contain them.
fn directory(t: *Trust, io: std.Io, path: []const u8, limits: Limits) AddDirError!void {
    @setRuntimeSafety(true);
    const count = t.roots.items.len;
    const bytes = t.bytes;
    errdefer t.rollback(count, bytes);
    var dir = try std.Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var iterator = dir.iterate();
    var entries: usize = 0;
    while (try iterator.next(io)) |entry| {
        if (entries >= limits.directory_entries) return error.TrustLimit;
        entries += 1;
        if (entry.kind != .file and entry.kind != .sym_link) continue;
        const pem = try dir.readFileAlloc(io, entry.name, t.gpa, .limited(limits.file_bytes));
        defer t.gpa.free(pem);
        try t.addPem(pem, limits);
    }
}

/// System policy on Apple/Windows is native policy, never a root dump.
fn systemLoad(t: *Trust, io: std.Io, limits: Limits) AddSystemError!void {
    @setRuntimeSafety(true);
    if ((builtin.os.tag == .macos or builtin.os.tag == .windows) and t.roots.items.len != 0) return error.MixedTrustPolicies;
    switch (builtin.os.tag) {
        .macos => t.system = .macos,
        .windows => t.system = .windows,
        .linux => try t.firstBundle(io, &.{ "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/cert.pem" }, limits),
        .freebsd, .openbsd => try t.firstBundle(io, &.{"/etc/ssl/cert.pem"}, limits),
        .netbsd => try t.firstBundle(io, &.{"/etc/openssl/certs/ca-certificates.crt"}, limits),
        .dragonfly => try t.firstBundle(io, &.{"/usr/local/etc/ssl/cert.pem"}, limits),
        else => return error.UnsupportedPlatform,
    }
}

fn firstBundle(t: *Trust, io: std.Io, paths: []const []const u8, limits: Limits) AddSystemError!void {
    @setRuntimeSafety(true);
    for (paths) |path| {
        t.file(io, path, limits) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return;
    }
    return error.SystemTrustUnavailable;
}

/// Freeze transfers buffers; future edits cannot change a published snapshot.
pub fn freeze(t: *Trust) FreezeError!Snapshot {
    @setRuntimeSafety(true);
    if (t.roots.items.len == 0 and t.system == .portable) return error.NoTrustAnchors;
    if (t.next_generation == std.math.maxInt(u64)) return error.GenerationExhausted;
    const state = try t.gpa.create(State);
    errdefer t.gpa.destroy(state);
    const roots = try t.gpa.dupe([]const u8, t.roots.items);
    errdefer t.gpa.free(roots);
    var index = try certificate.Issuers.init(t.gpa, roots, .{});
    errdefer index.deinit();
    state.* = .{ .gpa = t.gpa, .roots = roots, .index = index, .generation = t.next_generation, .system = t.system };
    t.roots.clearRetainingCapacity();
    t.bytes = 0;
    t.next_generation += 1;
    return .{ .state = state };
}

fn rollback(t: *Trust, count: usize, bytes: usize) void {
    @setRuntimeSafety(true);
    for (t.roots.items[count..]) |root| t.gpa.free(root);
    t.roots.shrinkRetainingCapacity(count);
    t.bytes = bytes;
}

const State = struct {
    gpa: std.mem.Allocator,
    refs: std.atomic.Value(usize) = .init(1),
    roots: []const []const u8,
    index: certificate.Issuers,
    generation: u64,
    system: System,
};

pub const Snapshot = struct {
    /// Private: immutable state remains alive until its final release.
    state: *State,

    pub fn retain(s: Snapshot) Snapshot {
        @setRuntimeSafety(true);
        var old = s.state.refs.load(.monotonic);
        while (true) {
            if (old == 0 or old == std.math.maxInt(usize)) @panic("cloak retained owner exhausted");
            if (s.state.refs.cmpxchgWeak(old, old + 1, .monotonic, .monotonic)) |actual| old = actual else break;
        }
        return s;
    }

    pub fn deinit(s: Snapshot) void {
        @setRuntimeSafety(true);
        if (s.state.refs.fetchSub(1, .acq_rel) != 1) return;
        s.state.index.deinit();
        for (s.state.roots) |root| s.state.gpa.free(root);
        s.state.gpa.free(s.state.roots);
        const gpa = s.state.gpa;
        gpa.destroy(s.state);
    }

    pub fn anchors(s: Snapshot) []const []const u8 {
        @setRuntimeSafety(true);
        return s.state.roots;
    }

    /// Borrowed index remains valid while this snapshot is retained.
    pub fn issuers(s: Snapshot) *const certificate.Issuers {
        @setRuntimeSafety(true);
        return &s.state.index;
    }

    pub fn generation(s: Snapshot) u64 {
        @setRuntimeSafety(true);
        return s.state.generation;
    }

    pub fn systemPolicy(s: Snapshot) System {
        @setRuntimeSafety(true);
        return s.state.system;
    }
};

test {
    @setRuntimeSafety(true);
    _ = @import("Trust_test.zig");
}
