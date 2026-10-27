//! A mutable trust builder and immutable, retained trust snapshots.
const std = @import("std");
const aegis = @import("aegis");
const types = @import("types.zig");
const TrustGeneration = types.TrustGeneration;
const builtin = @import("builtin");
const certificate = @import("certificate.zig");
const Pem = @import("credentials/Pem.zig");
const Trust = @This();
const tests = @import("Trust_test.zig");

gpa: std.mem.Allocator,
/// Private: only the builder may mutate these certificate buffers.
roots: std.ArrayList([]const u8) = .empty,
/// Private: bytes charged against the bounded root store.
bytes: usize = 0,
/// Private: the next generation published by this builder.
next_generation: TrustGeneration = .fromRaw(1),
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
pub const AddDerError = std.mem.Allocator.Error || certificate.ParseError || error{TrustLimit};
pub const AddPemError = AddDerError || error{ InvalidPem, InvalidPadding, InvalidCharacter };
pub const LoadOptions = struct { limits: Limits = .{}, timeout: std.Io.Timeout = .none };
pub const AddFileError = AddPemError || aegis.own.ReadFileError || std.Io.Dir.OpenError || std.Io.Dir.Iterator.Error || std.Io.ConcurrentError || std.Io.Cancelable || std.Io.Timeout.Error;
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
    try importPem(false, t, pem, limits);
}

// System bundles retain only roots the strict verifier can use. Explicit input
// remains transactional; no malformed root becomes an authorization candidate.
fn importPem(comptime system_bundle: bool, t: *Trust, pem: []const u8, limits: Limits) AddPemError!void {
    @setRuntimeSafety(true);
    if (pem.len > limits.file_bytes) return error.TrustLimit;
    const count = t.roots.items.len;
    const bytes = t.bytes;
    errdefer t.rollback(count, bytes);
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    var at: usize = 0;
    var blocks: usize = 0;
    var certificates: usize = 0;
    // Text before a block is skipped (RFC 7468 section 5.2): bundles name each root in a
    // comment before it. Text after the last block is not.
    while (Pem.boundary(pem, at)) |start| {
        if (system_bundle) {
            if (blocks >= limits.roots) return error.TrustLimit;
            blocks += 1;
        }
        const rest = pem[start..];
        if (!std.mem.startsWith(u8, rest, begin)) {
            // Another kind of block: refused when named, passed over in a system bundle.
            if (!system_bundle) return error.InvalidPem;
            const close = std.mem.findPos(u8, pem, start, "-----END ") orelse return error.InvalidPem;
            at = (std.mem.findPos(u8, pem, close + "-----END ".len, "-----") orelse return error.InvalidPem) + "-----".len;
            continue;
        }
        const body = rest[begin.len..];
        const finish = std.mem.find(u8, body, end) orelse return error.InvalidPem;
        const encoded = body[0..finish];
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
        t.addDer(der, limits) catch |err| switch (err) {
            error.OutOfMemory, error.TrustLimit => return err,
            else => if (!system_bundle) return err,
        };
        certificates += 1;
        at = start + begin.len + finish + end.len;
    }
    if (certificates == 0 or std.mem.trim(u8, pem[at..], " \t\r\n").len != 0) return error.InvalidPem;
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
    if (expired(io, deadline)) return error.Timeout;
    var loading: Loading = .{};
    var work = try io.concurrent(loadTask, .{ t, io, path, options.limits, kind, &loading });
    loading.wait(io, deadline) catch |err| {
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
fn loadTask(t: *Trust, io: std.Io, path: []const u8, limits: Limits, kind: LoadKind, loading: *Loading) AddDirError!void {
    @setRuntimeSafety(true);
    defer loading.finish(io);
    try t.perform(io, path, limits, kind);
}

/// A load running on a task of its own, and whether it has finished: the caller waits for it up
/// to its deadline, then cancels it.
const Loading = struct {
    done: aegis.BlockingGuarded(bool) = .init(false),
    finished: aegis.Condition = .init(),

    fn finish(self: *Loading, io: std.Io) void {
        var held = self.done.acquireUncancelable(io);
        defer held.deinit(io);
        held.value().* = true;
        self.finished.signal(io);
    }

    /// Until the load finishes, or `deadline` passes: a load that finishes after it is late all
    /// the same.
    fn wait(self: *Loading, io: std.Io, deadline: std.Io.Timeout) (std.Io.Cancelable || std.Io.Timeout.Error)!void {
        @setRuntimeSafety(true);
        {
            var held = try self.done.acquire(io);
            defer held.deinit(io);
            while (!held.value().*) self.finished.wait(io, &held, deadline) catch |err| switch (err) {
                error.Timeout => if (expired(io, deadline)) return error.Timeout,
                error.Canceled => return error.Canceled,
                error.WaiterLimit => unreachable, // unreachable: the caller is the one waiter
            };
        }
        if (expired(io, deadline)) return error.Timeout;
    }
};

/// Whether `deadline` has passed.
fn expired(io: std.Io, deadline: std.Io.Timeout) bool {
    return types.Nanoseconds.fromIoDuration(deadline.deadline.durationFromNow(io).raw, .exact).compare(.fromRaw(0)) != .gt;
}
fn systemTimed(t: *Trust, io: std.Io, options: LoadOptions) AddSystemError!void {
    @setRuntimeSafety(true);
    const count = t.roots.items.len;
    const bytes = t.bytes;
    errdefer t.rollback(count, bytes);
    if (options.timeout == .none) return t.systemLoad(io, options.limits);
    const deadline = options.timeout.toDeadline(io);
    if (expired(io, deadline)) return error.Timeout;
    var loading: Loading = .{};
    var work = try io.concurrent(systemTask, .{ t, io, options.limits, &loading });
    loading.wait(io, deadline) catch |err| {
        _ = work.cancel(io) catch {
            // Cancellation joined the loader; preserve the expired caller deadline.
            return err;
        };
        return err;
    };
    try work.await(io);
}
fn systemTask(t: *Trust, io: std.Io, limits: Limits, loading: *Loading) AddSystemError!void {
    @setRuntimeSafety(true);
    defer loading.finish(io);
    try t.systemLoad(io, limits);
}

/// Loading occurs before traffic; `io` and file ownership remain per call.
fn file(t: *Trust, io: std.Io, path: []const u8, limits: Limits) AddFileError!void {
    @setRuntimeSafety(true);
    const pem = try aegis.own.readFile(io, .cwd(), path, t.gpa, .fromRaw(limits.file_bytes));
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
        const pem = try aegis.own.readFile(io, dir, entry.name, t.gpa, .fromRaw(limits.file_bytes));
        defer t.gpa.free(pem);
        try t.addPem(pem, limits);
    }
}

/// System policy on Apple/Windows is native policy, never a root dump; roots added besides it
/// are trusted besides the system's, by the portable verifier.
fn systemLoad(t: *Trust, io: std.Io, limits: Limits) AddSystemError!void {
    @setRuntimeSafety(true);
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
        const pem = aegis.own.readFile(io, .cwd(), path, t.gpa, .fromRaw(limits.file_bytes)) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer t.gpa.free(pem);
        try importPem(true, t, pem, limits);
        return;
    }
    return error.SystemTrustUnavailable;
}

/// Freeze transfers buffers; future edits cannot change a published snapshot.
pub fn freeze(t: *Trust) FreezeError!Snapshot {
    @setRuntimeSafety(true);
    if (t.roots.items.len == 0 and t.system == .portable) return error.NoTrustAnchors;
    const following = t.next_generation.successor() catch return error.GenerationExhausted;
    const roots = try t.gpa.dupe([]const u8, t.roots.items);
    errdefer t.gpa.free(roots);
    var index = try certificate.Issuers.init(t.gpa, roots, .{});
    errdefer index.deinit();
    const state: Handle = try .create(t.gpa, .{ .gpa = t.gpa, .roots = roots, .index = index, .generation = t.next_generation, .system = t.system });
    t.roots.clearRetainingCapacity();
    t.bytes = 0;
    t.next_generation = following;
    return .{ .state = state };
}

fn rollback(t: *Trust, count: usize, bytes: usize) void {
    @setRuntimeSafety(true);
    for (t.roots.items[count..]) |root| t.gpa.free(root);
    t.roots.shrinkRetainingCapacity(count);
    t.bytes = bytes;
}

const Handle = aegis.Shared(State, release);
const State = struct {
    gpa: std.mem.Allocator,
    roots: []const []const u8,
    index: certificate.Issuers,
    generation: TrustGeneration,
    system: System,
};

/// The last snapshot's cleanup.
fn release(state: *State) void {
    @setRuntimeSafety(true);
    state.index.deinit();
    for (state.roots) |root| state.gpa.free(root);
    state.gpa.free(state.roots);
}

pub const Snapshot = struct {
    /// Private: immutable state remains alive until its final release.
    state: Handle,

    pub fn retain(s: Snapshot) Snapshot {
        return .{ .state = s.state.retain() };
    }

    pub fn deinit(s: Snapshot) void {
        var handle = s.state;
        handle.release();
    }

    pub fn anchors(s: Snapshot) []const []const u8 {
        @setRuntimeSafety(true);
        return s.state.get().roots;
    }

    /// Borrowed index remains valid while this snapshot is retained.
    pub fn issuers(s: Snapshot) *const certificate.Issuers {
        @setRuntimeSafety(true);
        return &s.state.get().index;
    }

    pub fn generation(s: Snapshot) TrustGeneration {
        @setRuntimeSafety(true);
        return s.state.get().generation;
    }

    pub fn systemPolicy(s: Snapshot) System {
        @setRuntimeSafety(true);
        return s.state.get().system;
    }
};

test {
    @setRuntimeSafety(true);
    _ = tests;
}

test "trust system bundle omits unusable roots without weakening explicit import" {
    @setRuntimeSafety(true);
    try tests.systemBundle(firstBundle);
}

test "trust bundles name their roots in text before each one" {
    @setRuntimeSafety(true);
    var trust = Trust.init(std.testing.allocator);
    defer trust.deinit();
    const root = @embedFile("credentials/testdata/p256.cert.pem");
    try trust.addPem("##\n## Bundle of CA Root Certificates\n##\n\nWork root\n=========\n" ++ root, .{});
    try std.testing.expectEqual(@as(usize, 1), trust.roots.items.len);
    // A system bundle passes over a block of another kind; a named file refuses it.
    const key = "-----BEGIN PRIVATE KEY-----\nAA==\n-----END PRIVATE KEY-----\n";
    var system = Trust.init(std.testing.allocator);
    defer system.deinit();
    try importPem(true, &system, "# key\n" ++ key ++ "# Work root\n" ++ root, .{});
    try std.testing.expectEqual(@as(usize, 1), system.roots.items.len);
    try std.testing.expectError(error.InvalidPem, trust.addPem(key ++ root, .{}));
}
