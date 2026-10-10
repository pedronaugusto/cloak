//! The rows cloak is compared on: primitives, full handshakes per endpoint and records through a
//! connection, over the bench PKI in `bench/data/chain` (a P-256 root, intermediate and leaf for
//! bench.example). Usage: `speed <primitives|handshake|bulk> --pki <dir> --samples <n>`. Each row
//! is `side workload metric value unit`, tab-separated; side `cloak` is what cloak runs, `std` the
//! Zig standard library's operation where cloak has its own. Measurements run by hand in
//! ReleaseFast; CI only compiles this.
const std = @import("std");
const harness = @import("harness");
const cloak = harness.cloak;
const ecdh = harness.ecdh;
const Connection = cloak.tls.Connection;
const Suite13 = cloak.tls.Suite13;
const Group = cloak.tls.Group;

const fixtures = .{ "message.bin", "root.der", "chain.pem", "leaf.key.pem", "leaf.der", "p384.key.pem", "p384.der", "ed25519.key.pem", "ed25519.der", "rsa2048.der", "rsa2048.pss.sig", "rsa4096.der", "rsa4096.pss.sig" };

const Context = struct {
    io: std.Io,
    gpa: std.mem.Allocator,
    out: *std.Io.Writer,
    samples: usize,
    pki: ?std.Io.Dir,
    message: []const u8,

    /// A fixture from `--pki`, or the copy built in from `bench/data/chain`.
    fn file(self: *const Context, name: []const u8) ![]u8 {
        if (self.pki) |dir| return dir.readFileAlloc(self.io, name, self.gpa, .limited(1 << 20));
        inline for (fixtures) |fixture| {
            if (std.mem.eql(u8, name, fixture)) return self.gpa.dupe(u8, @embedFile("data/chain/" ++ fixture));
        }
        return error.FileNotFound;
    }

    fn now(self: *const Context) u64 {
        // safe: monotonic nanoseconds since an arbitrary origin are positive and below 2^64.
        return @intCast(std.Io.Clock.awake.now(self.io).nanoseconds);
    }

    /// Prints min, median and p95 of per-operation nanoseconds.
    fn report(self: *const Context, side: []const u8, workload: []const u8, times: []f64) !void {
        std.mem.sort(f64, times, {}, std.sort.asc(f64));
        const p95 = times[@min(times.len - 1, times.len * 95 / 100)];
        try self.out.print("{s}\t{s}\tmin\t{d:.1}\tns\n", .{ side, workload, times[0] });
        try self.out.print("{s}\t{s}\tmedian\t{d:.1}\tns\n", .{ side, workload, times[times.len / 2] });
        try self.out.print("{s}\t{s}\tp95\t{d:.1}\tns\n", .{ side, workload, p95 });
        try self.out.flush();
    }

    /// Times `op(state)` in batches of about a millisecond, one sample per batch.
    fn primitive(self: *const Context, side: []const u8, workload: []const u8, state: anytype, comptime op: fn (@TypeOf(state)) void) !void {
        for (0..3) |_| op(state);
        var batch: usize = 1;
        while (true) {
            const start = self.now();
            for (0..batch) |_| op(state);
            if (self.now() - start >= 1_000_000 or batch >= 1 << 24) break;
            batch *= 2;
        }
        const times = try self.gpa.alloc(f64, self.samples);
        defer self.gpa.free(times);
        for (times) |*slot| {
            const start = self.now();
            for (0..batch) |_| op(state);
            slot.* = @as(f64, @floatFromInt(self.now() - start)) / @as(f64, @floatFromInt(batch));
        }
        try self.report(side, workload, times);
    }
};

pub fn main(init: std.process.Init) !void {
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var group: []const u8 = "";
    var pki_path: ?[]const u8 = null;
    var samples: usize = 31;
    var smoke = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--smoke")) {
            smoke = true;
        } else if (std.mem.eql(u8, arg, "--pki") and i + 1 < args.len) {
            i += 1;
            pki_path = args[i];
        } else if (std.mem.eql(u8, arg, "--samples") and i + 1 < args.len) {
            i += 1;
            samples = try std.fmt.parseInt(usize, args[i], 10);
        } else group = arg;
    }
    if (smoke) samples = 2;
    var buffer: [4096]u8 = undefined;
    var out = std.Io.File.stdout().writerStreaming(init.io, &buffer);
    var dir: ?std.Io.Dir = if (pki_path) |path| try std.Io.Dir.cwd().openDir(init.io, path, .{}) else null;
    defer if (dir) |*d| d.close(init.io);
    var context: Context = .{ .io = init.io, .gpa = init.gpa, .out = &out.interface, .samples = @max(samples, 1), .pki = dir, .message = &.{} };
    context.message = try context.file("message.bin");
    defer init.gpa.free(context.message);
    const all = group.len == 0 or smoke;
    if (all or std.mem.eql(u8, group, "primitives")) try primitives(&context);
    if (all or std.mem.eql(u8, group, "handshake")) try handshakes(&context);
    if (all or std.mem.eql(u8, group, "bulk")) try bulk(&context);
    try out.interface.flush();
}

// ---------------------------------------------------------------- primitives

fn primitives(ctx: *const Context) !void {
    inline for (.{ .{ Suite13.aes_128_gcm_sha256, "aes128gcm" }, .{ Suite13.aes_256_gcm_sha384, "aes256gcm" }, .{ Suite13.chacha20_poly1305_sha256, "chacha20poly1305" } }) |entry| {
        inline for (.{ 64, 1024, 16384 }) |size| try aead(ctx, entry[0], entry[1], size);
    }
    try x25519(ctx);
    try curve(ctx, ecdh.P256, std.crypto.ecc.P256, "p256", "leaf.key.pem", "leaf.der", .sha256);
    try curve(ctx, ecdh.P384, std.crypto.ecc.P384, "p384", "p384.key.pem", "p384.der", .sha384);
    try ed25519(ctx);
    try mlkem(ctx);
    inline for (.{ "rsa2048", "rsa4096" }) |name| try rsa(ctx, name);
}

fn aead(ctx: *const Context, comptime suite: Suite13, comptime name: []const u8, comptime size: usize) !void {
    const A = harness.suites.Aead(suite);
    const State = struct {
        key: [A.key_length]u8 = @splat(7),
        nonce: [12]u8 = @splat(9),
        ad: [13]u8 = @splat(3),
        plain: [size]u8 = @splat(0x5a),
        cipher: [size]u8 = undefined,
        tag: [16]u8 = undefined,
        back: [size]u8 = undefined,
        fn seal(s: *@This()) void {
            A.encrypt(&s.cipher, &s.tag, &s.plain, &s.ad, s.nonce, s.key);
            std.mem.doNotOptimizeAway(&s.tag);
        }
        fn open(s: *@This()) void {
            A.decrypt(&s.back, &s.cipher, s.tag, &s.ad, s.nonce, s.key) catch unreachable; // unreachable: sealed with the same key
            std.mem.doNotOptimizeAway(&s.back);
        }
    };
    const state = try ctx.gpa.create(State);
    defer ctx.gpa.destroy(state);
    state.* = .{};
    State.seal(state);
    State.open(state);
    if (!std.mem.eql(u8, &state.back, &state.plain)) return error.WrongPlaintext;
    const prefix = "aead/" ++ name ++ "/" ++ std.fmt.comptimePrint("{d}", .{size});
    try ctx.primitive("cloak", prefix ++ "/seal", state, State.seal);
    try ctx.primitive("cloak", prefix ++ "/open", state, State.open);
}

fn x25519(ctx: *const Context) !void {
    const X = std.crypto.dh.X25519;
    const State = struct {
        secret: [32]u8,
        peer: [32]u8,
        out: [32]u8 = undefined,
        fn keygen(s: *@This()) void {
            s.out = X.recoverPublicKey(s.secret);
            std.mem.doNotOptimizeAway(&s.out);
        }
        fn agree(s: *@This()) void {
            s.out = X.scalarmult(s.secret, s.peer) catch unreachable; // unreachable: a valid peer key
            std.mem.doNotOptimizeAway(&s.out);
        }
    };
    var state: State = .{ .secret = undefined, .peer = undefined };
    ctx.io.random(&state.secret);
    var other: [32]u8 = undefined;
    ctx.io.random(&other);
    state.peer = X.recoverPublicKey(other);
    try ctx.primitive("cloak", "x25519/keygen", &state, State.keygen);
    try ctx.primitive("cloak", "x25519/agree", &state, State.agree);
}

fn curve(ctx: *const Context, comptime G: type, comptime Point: type, comptime name: []const u8, key_file: []const u8, cert_file: []const u8, comptime hash: cloak.certificates.certificate.Algorithm.Hash) !void {
    const State = struct {
        scalar: [G.scalar_length]u8 = undefined,
        public: [G.public_length]u8 = undefined,
        peer: [G.public_length]u8 = undefined,
        peer_point: Point = undefined,
        shared: [G.scalar_length]u8 = undefined,
        key: cloak.PrivateKey = undefined,
        noise: [cloak.PrivateKey.max_noise]u8 = undefined,
        noise_len: usize = 0,
        message: []const u8 = &.{},
        signature: [cloak.PrivateKey.max_signature]u8 = undefined,
        signature_len: usize = 0,
        leaf_key: cloak.certificates.certificate.PublicKey = undefined,
        std_pair: std.crypto.sign.ecdsa.Ecdsa(Point, if (hash == .sha256) std.crypto.hash.sha2.Sha256 else std.crypto.hash.sha2.Sha384).KeyPair = undefined,
        fn keygen(s: *@This()) void {
            G.publicKey(&s.scalar, &s.public) catch unreachable; // unreachable: the scalar is in range
            std.mem.doNotOptimizeAway(&s.public);
        }
        fn agree(s: *@This()) void {
            G.agree(&s.scalar, &s.peer, &s.shared) catch unreachable; // unreachable: valid key and peer
            std.mem.doNotOptimizeAway(&s.shared);
        }
        fn sign(s: *@This()) void {
            var buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
            const signature = s.key.sign(.{ .ecdsa = hash }, s.message, s.noise[0..s.noise_len], &buffer) catch unreachable; // unreachable: the key and algorithm agree
            std.mem.doNotOptimizeAway(signature);
        }
        fn verify(s: *@This()) void {
            cloak.certificates.signature.verify(s.leaf_key, .{ .ecdsa = hash }, s.message, s.signature[0..s.signature_len]) catch unreachable; // unreachable: a valid signature
        }
        fn stdKeygen(s: *@This()) void {
            const point = Point.basePoint.mul(s.scalar, .big) catch unreachable; // unreachable: in range
            std.mem.doNotOptimizeAway(&point);
        }
        fn stdAgree(s: *@This()) void {
            const point = s.peer_point.mul(s.scalar, .big) catch unreachable; // unreachable: in range
            std.mem.doNotOptimizeAway(&point);
        }
        fn stdSign(s: *@This()) void {
            const signature = s.std_pair.sign(s.message, s.noise[0..G.scalar_length].*) catch unreachable; // unreachable: any noise signs
            std.mem.doNotOptimizeAway(&signature);
        }
    };
    const state = try ctx.gpa.create(State);
    defer ctx.gpa.destroy(state);
    state.* = .{};
    while (true) {
        ctx.io.random(&state.scalar);
        G.check(&state.scalar) catch continue;
        break;
    }
    var other: [G.scalar_length]u8 = undefined;
    while (true) {
        ctx.io.random(&other);
        G.publicKey(&other, &state.peer) catch continue;
        break;
    }
    state.peer_point = try Point.fromSec1(&state.peer);
    const pem = try ctx.file(key_file);
    defer ctx.gpa.free(pem);
    state.key = try cloak.PrivateKey.parse(ctx.gpa, pem, .{});
    defer state.key.deinit();
    state.noise_len = state.key.noiseLength().?;
    ctx.io.random(&state.noise);
    state.message = ctx.message;
    const der = try ctx.file(cert_file);
    defer ctx.gpa.free(der);
    const cert = try cloak.certificates.certificate.parse(der, .{});
    state.leaf_key = cert.public_key;
    const made = try state.key.sign(.{ .ecdsa = hash }, ctx.message, state.noise[0..state.noise_len], &state.signature);
    state.signature_len = made.len;
    State.verify(state);
    state.std_pair = @TypeOf(state.std_pair).generate(ctx.io);
    try ctx.primitive("cloak", name ++ "/keygen", state, State.keygen);
    try ctx.primitive("cloak", name ++ "/agree", state, State.agree);
    try ctx.primitive("cloak", name ++ "/sign", state, State.sign);
    try ctx.primitive("cloak", name ++ "/verify", state, State.verify);
    try ctx.primitive("std", name ++ "/keygen", state, State.stdKeygen);
    try ctx.primitive("std", name ++ "/agree", state, State.stdAgree);
    try ctx.primitive("std", name ++ "/sign", state, State.stdSign);
}

fn ed25519(ctx: *const Context) !void {
    const State = struct {
        key: cloak.PrivateKey = undefined,
        message: []const u8 = &.{},
        signature: [cloak.PrivateKey.max_signature]u8 = undefined,
        leaf_key: cloak.certificates.certificate.PublicKey = undefined,
        fn sign(s: *@This()) void {
            var buffer: [cloak.PrivateKey.max_signature]u8 = undefined;
            const signature = s.key.sign(.ed25519, s.message, "", &buffer) catch unreachable; // unreachable: the key and algorithm agree
            std.mem.doNotOptimizeAway(signature);
        }
        fn verify(s: *@This()) void {
            cloak.certificates.signature.verify(s.leaf_key, .ed25519, s.message, s.signature[0..64]) catch unreachable; // unreachable: a valid signature
        }
    };
    var state: State = .{ .message = ctx.message };
    const pem = try ctx.file("ed25519.key.pem");
    defer ctx.gpa.free(pem);
    state.key = try cloak.PrivateKey.parse(ctx.gpa, pem, .{});
    defer state.key.deinit();
    const der = try ctx.file("ed25519.der");
    defer ctx.gpa.free(der);
    state.leaf_key = (try cloak.certificates.certificate.parse(der, .{})).public_key;
    _ = try state.key.sign(.ed25519, ctx.message, "", &state.signature);
    State.verify(&state);
    try ctx.primitive("cloak", "ed25519/sign", &state, State.sign);
    try ctx.primitive("cloak", "ed25519/verify", &state, State.verify);
}

fn mlkem(ctx: *const Context) !void {
    const K = std.crypto.kem.ml_kem.MLKem768;
    const State = struct {
        seed: [K.seed_length]u8 = undefined,
        encaps_seed: [K.encaps_seed_length]u8 = undefined,
        pair: K.KeyPair = undefined,
        ciphertext: [K.ciphertext_length]u8 = undefined,
        fn keygen(s: *@This()) void {
            const pair = K.KeyPair.generateDeterministic(s.seed) catch unreachable; // unreachable: any seed
            std.mem.doNotOptimizeAway(&pair);
        }
        fn encaps(s: *@This()) void {
            const result = s.pair.public_key.encapsDeterministic(&s.encaps_seed);
            std.mem.doNotOptimizeAway(&result);
        }
        fn decaps(s: *@This()) void {
            const secret = s.pair.secret_key.decaps(&s.ciphertext) catch unreachable; // unreachable: a valid ciphertext
            std.mem.doNotOptimizeAway(&secret);
        }
    };
    const state = try ctx.gpa.create(State);
    defer ctx.gpa.destroy(state);
    state.* = .{};
    ctx.io.random(&state.seed);
    ctx.io.random(&state.encaps_seed);
    state.pair = try K.KeyPair.generateDeterministic(state.seed);
    state.ciphertext = state.pair.public_key.encapsDeterministic(&state.encaps_seed).ciphertext;
    try ctx.primitive("cloak", "mlkem768/keygen", state, State.keygen);
    try ctx.primitive("cloak", "mlkem768/encaps", state, State.encaps);
    try ctx.primitive("cloak", "mlkem768/decaps", state, State.decaps);
}

fn rsa(ctx: *const Context, comptime name: []const u8) !void {
    const State = struct {
        key: cloak.certificates.certificate.PublicKey,
        message: []const u8,
        signature: []const u8,
        fn verify(s: *@This()) void {
            cloak.certificates.signature.verify(s.key, .{ .pss = .{ .hash = .sha256, .mgf_hash = .sha256, .salt_length = 32 } }, s.message, s.signature) catch unreachable; // unreachable: a valid signature
        }
    };
    const der = try ctx.file(name ++ ".der");
    defer ctx.gpa.free(der);
    const signature = try ctx.file(name ++ ".pss.sig");
    defer ctx.gpa.free(signature);
    var state: State = .{ .key = (try cloak.certificates.certificate.parse(der, .{})).public_key, .message = ctx.message, .signature = signature };
    State.verify(&state);
    try ctx.primitive("cloak", name ++ "/verify", &state, State.verify);
}

// ---------------------------------------------------------------- connections

const Fixture = struct {
    trust: cloak.Trust,
    snapshot: cloak.Trust.Snapshot,
    identity: cloak.Identity,

    fn init(ctx: *const Context) !Fixture {
        var trust = cloak.Trust.init(ctx.gpa);
        errdefer trust.deinit();
        const root = try ctx.file("root.der");
        defer ctx.gpa.free(root);
        try trust.addDer(root, .{});
        const snapshot = try trust.freeze();
        errdefer snapshot.deinit();
        const chain = try ctx.file("chain.pem");
        defer ctx.gpa.free(chain);
        const pem = try ctx.file("leaf.key.pem");
        defer ctx.gpa.free(pem);
        const key = try cloak.PrivateKey.parse(ctx.gpa, pem, .{});
        defer key.deinit();
        const identity = try cloak.Identity.initPem(ctx.gpa, chain, key, .{});
        return .{ .trust = trust, .snapshot = snapshot, .identity = identity };
    }

    fn deinit(self: *Fixture) void {
        self.identity.deinit();
        self.snapshot.deinit();
        self.trust.deinit();
    }
};

/// One endpoint and the nanoseconds spent inside its calls and the services it asked for.
const Endpoint = struct {
    conn: Connection,
    ns: u64 = 0,
};

const Pair = struct {
    ctx: *const Context,
    fixture: *const Fixture,
    client: Endpoint,
    server: Endpoint,

    fn init(ctx: *const Context, fixture: *const Fixture, comptime suite: Suite13, comptime group: Group) !Pair {
        var start = ctx.now();
        var client = try Connection.client(ctx.gpa, .{
            .identity = .{ .dns = "bench.example" },
            .verify = .{ .full = .{ .trust_generation = fixture.snapshot.generation() } },
            .suites = &.{suite},
            .groups = &.{group},
            .compat = false,
        });
        const client_ns = ctx.now() - start;
        errdefer client.deinit();
        start = ctx.now();
        const server = try Connection.server(ctx.gpa, .{
            .credentials = &.{.{ .identity = fixture.identity }},
            .suites = &.{suite},
            .groups = &.{group},
        });
        return .{ .ctx = ctx, .fixture = fixture, .client = .{ .conn = client, .ns = client_ns }, .server = .{ .conn = server, .ns = ctx.now() - start } };
    }

    fn deinit(self: *Pair) void {
        self.client.conn.deinit();
        self.server.conn.deinit();
    }

    fn serve(self: *Pair, end: *Endpoint) !void {
        const start = self.ctx.now();
        defer end.ns += self.ctx.now() - start;
        while (end.conn.request()) |request| switch (request.service) {
            .entropy => |len| {
                var bytes: [512]u8 = undefined;
                defer std.crypto.secureZero(u8, &bytes);
                try self.ctx.io.randomSecure(bytes[0..len]);
                try end.conn.provide(request.token, .{ .entropy = bytes[0..len] });
            },
            .time => try end.conn.provide(request.token, .{ .time = std.Io.Clock.real.now(self.ctx.io) }),
            .verify => |verify_request| {
                var receipt = try cloak.verify.indexed(self.ctx.gpa, verify_request, self.fixture.snapshot.issuers());
                defer receipt.deinit();
                try end.conn.provide(request.token, .{ .verified = &receipt });
            },
            .sign => return error.UnexpectedSignRequest,
        };
    }

    /// Moves `from`'s committed output into `to`; each side is charged for its own calls.
    fn move(self: *Pair, from: *Endpoint, to: *Endpoint) !bool {
        const bytes = from.conn.output();
        if (bytes.len == 0) return false;
        var at: usize = 0;
        while (at < bytes.len) {
            const start = self.ctx.now();
            const n = try to.conn.receive(bytes[at..]);
            to.ns += self.ctx.now() - start;
            at += n;
            if (n == 0) try self.serve(to);
        }
        const start = self.ctx.now();
        from.conn.acknowledge(bytes.len);
        from.ns += self.ctx.now() - start;
        return true;
    }

    fn handshake(self: *Pair) !void {
        for (0..64) |_| {
            try self.serve(&self.client);
            const sent = try self.move(&self.client, &self.server);
            try self.serve(&self.server);
            const answered = try self.move(&self.server, &self.client);
            if (self.client.conn.phase() == .connected and self.server.conn.phase() == .connected and
                self.client.conn.output().len == 0 and self.server.conn.output().len == 0) return;
            if (!sent and !answered) return error.Stalled;
        }
        return error.Stalled;
    }
};

fn handshakes(ctx: *const Context) !void {
    var fixture = try Fixture.init(ctx);
    defer fixture.deinit();
    inline for (.{ .{ Group.x25519, "x25519" }, .{ Group.x25519_mlkem768, "hybrid" } }) |entry| {
        const clients = try ctx.gpa.alloc(f64, ctx.samples);
        defer ctx.gpa.free(clients);
        const servers = try ctx.gpa.alloc(f64, ctx.samples);
        defer ctx.gpa.free(servers);
        for (0..20 + ctx.samples) |n| {
            var pair = try Pair.init(ctx, &fixture, .aes_128_gcm_sha256, entry[0]);
            defer pair.deinit();
            try pair.handshake();
            const info = pair.client.conn.info() orelse return error.NotConnected;
            if (!info.peer_authenticated) return error.NotAuthenticated;
            if (n < 20) continue;
            clients[n - 20] = @floatFromInt(pair.client.ns);
            servers[n - 20] = @floatFromInt(pair.server.ns);
        }
        try ctx.report("cloak", "handshake/" ++ entry[1] ++ "/client", clients);
        try ctx.report("cloak", "handshake/" ++ entry[1] ++ "/server", servers);
    }
}

fn bulk(ctx: *const Context) !void {
    var fixture = try Fixture.init(ctx);
    defer fixture.deinit();
    inline for (.{ .{ Suite13.aes_128_gcm_sha256, "aes128gcm" }, .{ Suite13.aes_256_gcm_sha384, "aes256gcm" }, .{ Suite13.chacha20_poly1305_sha256, "chacha20poly1305" } }) |entry| {
        inline for (.{ 64, 1024, 16384 }) |size| {
            var pair = try Pair.init(ctx, &fixture, entry[0], .x25519);
            defer pair.deinit();
            try pair.handshake();
            const State = struct {
                pair: *Pair,
                plain: [size]u8 = @splat(0x5a),
                wire: [size + 64]u8 = undefined,
                wire_len: usize = 0,
                fn seal(s: *@This()) void {
                    const conn = &s.pair.client.conn;
                    const n = conn.send(&s.plain) catch unreachable; // unreachable: a connected client with room
                    std.debug.assert(n == size);
                    const bytes = conn.output();
                    s.wire_len = bytes.len;
                    @memcpy(s.wire[0..bytes.len], bytes);
                    conn.acknowledge(bytes.len);
                }
                fn open(s: *@This()) void {
                    openWire(s, s.wire[0..s.wire_len]);
                }
                fn openWire(s: *@This(), wire: []const u8) void {
                    const conn = &s.pair.server.conn;
                    var at: usize = 0;
                    while (at < wire.len) at += conn.receive(wire[at..]) catch unreachable; // unreachable: an authentic record
                    const view = conn.readable();
                    std.debug.assert(view.len == size);
                    std.mem.doNotOptimizeAway(view.ptr);
                    conn.consume(view.len);
                }
                fn both(s: *@This()) void {
                    seal(s);
                    open(s);
                }
            };
            var state: State = .{ .pair = &pair };
            State.both(&state);
            if (state.wire_len != size + 22) return error.NotOneRecord;
            const prefix = "bulk/" ++ entry[1] ++ "/" ++ std.fmt.comptimePrint("{d}", .{size});
            try ctx.primitive("cloak", prefix ++ "/seal", &state, State.seal);
            // The sealed records above never reached the server: open on a fresh pair.
            var fresh = try Pair.init(ctx, &fixture, entry[0], .x25519);
            defer fresh.deinit();
            try fresh.handshake();
            state.pair = &fresh;
            // Open needs fresh records: seal a batch outside the clock, then time opening it.
            const per = 64;
            const records = try ctx.gpa.alloc([size + 64]u8, per);
            defer ctx.gpa.free(records);
            const times = try ctx.gpa.alloc(f64, ctx.samples);
            defer ctx.gpa.free(times);
            for (times) |*slot| {
                for (records) |*record| {
                    State.seal(&state);
                    record.* = state.wire;
                }
                const start = ctx.now();
                for (records) |*record| State.openWire(&state, record[0..state.wire_len]);
                slot.* = @as(f64, @floatFromInt(ctx.now() - start)) / per;
            }
            try ctx.report("cloak", prefix ++ "/open", times);
        }
    }
}
