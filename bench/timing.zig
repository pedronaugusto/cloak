//! Timing evidence on the built binary: for each kernel that handles a secret, whether its time
//! depends on that secret, by shakedown's leak test (dudect: a fixed and a random class of the
//! secret input, measured interleaved, Welch's t). Run it in the build that ships, ReleaseFast:
//! `bay dev timing`, or `bay dev timing -- ROW` for the rows whose names start with ROW.
//! Each line: the row, |t|, which test gave it, the class means in nanoseconds, and the verdict.
//! A run finds a leak with some confidence and never proves there is none.
const std = @import("std");
const harness = @import("harness");
const cloak = harness.cloak;
const ecdh = harness.ecdh;
const aegis = @import("aegis");
const leak = @import("shakedown").leak;

const slots = 1 << 10;

/// The 32-byte comparison every Finished, binder, tag and confirmation check goes through.
const Equal = struct {
    reference: [32]u8 = @splat(0x6b),
    inputs: [slots][32]u8 = undefined,
    sink: u8 = 0,
    failures: usize = 0,
    pub fn prepare(self: *Equal, slot: usize, class: leak.Class, random: std.Random) void {
        switch (class) {
            .fixed => self.inputs[slot] = self.reference,
            .random => random.bytes(&self.inputs[slot]),
        }
    }
    pub fn call(self: *Equal, slot: usize) void {
        self.sink +%= @intFromBool(aegis.secret.equal(32, &self.reference, &self.inputs[slot]).declassify("timing evidence"));
    }
};

/// A private scalar times a fixed peer point, P-256 (cloak's kernel) or P-384. The fixed class is
/// the scalar 1, the edge a windowed walk must not shortcut.
fn Agree(comptime G: type) type {
    return struct {
        const Self = @This();
        peer: [G.public_length]u8 = undefined,
        scalars: [slots][G.scalar_length]u8 = undefined,
        out: [G.scalar_length]u8 = undefined,
        failures: usize = 0,
        pub fn init(self: *Self) void {
            var other: [G.scalar_length]u8 = @splat(0x35);
            other[0] = 0x21;
            G.publicKey(&other, &self.peer) catch unreachable; // unreachable: a fixed in-range scalar
        }
        pub fn prepare(self: *Self, slot: usize, class: leak.Class, random: std.Random) void {
            const scalar = &self.scalars[slot];
            switch (class) {
                .fixed => {
                    scalar.* = @splat(0);
                    scalar[G.scalar_length - 1] = 1;
                },
                .random => {
                    random.bytes(scalar);
                    scalar[0] &= 0x7f;
                },
            }
        }
        pub fn call(self: *Self, slot: usize) void {
            G.agree(&self.scalars[slot], &self.peer, &self.out) catch {
                self.failures += 1;
            };
            std.mem.doNotOptimizeAway(&self.out);
        }
    };
}

/// A private scalar times the base point: the key share and the signing nonce's point.
fn Public(comptime G: type) type {
    return struct {
        const Self = @This();
        agree: Agree(G) = .{},
        out: [G.public_length]u8 = undefined,
        failures: usize = 0,
        pub fn prepare(self: *Self, slot: usize, class: leak.Class, random: std.Random) void {
            self.agree.prepare(slot, class, random);
        }
        pub fn call(self: *Self, slot: usize) void {
            G.publicKey(&self.agree.scalars[slot], &self.out) catch {
                self.failures += 1;
            };
            std.mem.doNotOptimizeAway(&self.out);
        }
    };
}

/// X25519 (std): a clamped secret of zeros against random secrets.
const X25519 = struct {
    const X = std.crypto.dh.X25519;
    peer: [32]u8 = undefined,
    secrets: [slots][32]u8 = undefined,
    out: [32]u8 = undefined,
    failures: usize = 0,
    pub fn init(self: *X25519) void {
        self.peer = X.recoverPublicKey(@splat(0x41));
    }
    pub fn prepare(self: *X25519, slot: usize, class: leak.Class, random: std.Random) void {
        switch (class) {
            .fixed => self.secrets[slot] = @splat(0),
            .random => random.bytes(&self.secrets[slot]),
        }
    }
    pub fn call(self: *X25519, slot: usize) void {
        self.out = X.scalarmult(self.secrets[slot], self.peer) catch blk: {
            self.failures += 1;
            break :blk @splat(0);
        };
        std.mem.doNotOptimizeAway(&self.out);
    }
};

/// ML-KEM-768 decapsulation (std): a valid ciphertext against random ones, which implicit
/// rejection must answer in the same time.
const Decaps = struct {
    const K = std.crypto.kem.ml_kem.MLKem768;
    pair: K.KeyPair = undefined,
    valid: [K.ciphertext_length]u8 = undefined,
    ciphertexts: [slots][K.ciphertext_length]u8 = undefined,
    out: [K.shared_length]u8 = undefined,
    failures: usize = 0,
    pub fn init(self: *Decaps) void {
        self.pair = K.KeyPair.generateDeterministic(@splat(7)) catch unreachable; // unreachable: a fixed seed
        self.valid = self.pair.public_key.encapsDeterministic(&@as([K.encaps_seed_length]u8, @splat(9))).ciphertext;
    }
    pub fn prepare(self: *Decaps, slot: usize, class: leak.Class, random: std.Random) void {
        switch (class) {
            .fixed => self.ciphertexts[slot] = self.valid,
            .random => random.bytes(&self.ciphertexts[slot]),
        }
    }
    pub fn call(self: *Decaps, slot: usize) void {
        self.out = self.pair.secret_key.decaps(&self.ciphertexts[slot]) catch blk: {
            self.failures += 1;
            break :blk @splat(0);
        };
        std.mem.doNotOptimizeAway(&self.out);
    }
};

/// cloak's key shares: an X25519 private half from fixed entropy against random entropy, agreeing
/// with a fixed server share (the client's half of the TLS exchange).
const ShareAgree = struct {
    const Exchange = harness.Exchange;
    server: [32]u8 = undefined,
    entropy: [slots][32]u8 = undefined,
    out: [Exchange.max_secret]u8 = undefined,
    failures: usize = 0,
    pub fn init(self: *ShareAgree) void {
        self.server = std.crypto.dh.X25519.recoverPublicKey(@splat(0x42));
    }
    pub fn prepare(self: *ShareAgree, slot: usize, class: leak.Class, random: std.Random) void {
        switch (class) {
            .fixed => self.entropy[slot] = @splat(0x5c),
            .random => random.bytes(&self.entropy[slot]),
        }
    }
    pub fn call(self: *ShareAgree, slot: usize) void {
        var share = Exchange.Share.init(.x25519, &self.entropy[slot]) catch {
            self.failures += 1;
            return;
        };
        defer share.deinit();
        var agreed = share.agree(&self.server) catch {
            self.failures += 1;
            return;
        };
        defer agreed.deinit();
        @memcpy(self.out[0..agreed.len], agreed.bytes());
        std.mem.doNotOptimizeAway(&self.out);
    }
};

/// cloak's HPKE recipient (an ECH server opening a client's hello): the server's X25519 key held
/// fixed against random keys, the client's encapsulated key fixed.
const HpkeOpen = struct {
    const Hpke = harness.Hpke;
    enc: [32]u8 = undefined,
    secrets: [slots][32]u8 = undefined,
    failures: usize = 0,
    pub fn init(self: *HpkeOpen) void {
        self.enc = std.crypto.dh.X25519.recoverPublicKey(@splat(0x43));
    }
    pub fn prepare(self: *HpkeOpen, slot: usize, class: leak.Class, random: std.Random) void {
        switch (class) {
            .fixed => self.secrets[slot] = @splat(0x5c),
            .random => random.bytes(&self.secrets[slot]),
        }
    }
    pub fn call(self: *HpkeOpen, slot: usize) void {
        var context = Hpke.setupRecipient(.{ .kdf = .hkdf_sha256, .aead = .aes_128_gcm }, &self.enc, &self.secrets[slot], "tls ech") catch {
            self.failures += 1;
            return;
        };
        context.deinit();
    }
};

/// A record's AEAD seal under a traffic key held fixed against random keys (std's kernels, as the
/// record layer calls them): 1 KiB of plaintext.
fn Seal(comptime A: type) type {
    return struct {
        const Self = @This();
        keys: [slots][A.key_length]u8 = undefined,
        plaintext: [1024]u8 = @splat(0x17),
        ciphertext: [1024]u8 = undefined,
        tag: [A.tag_length]u8 = undefined,
        failures: usize = 0,
        pub fn prepare(self: *Self, slot: usize, class: leak.Class, random: std.Random) void {
            switch (class) {
                .fixed => self.keys[slot] = @splat(0x5c),
                .random => random.bytes(&self.keys[slot]),
            }
        }
        pub fn call(self: *Self, slot: usize) void {
            A.encrypt(&self.ciphertext, &self.tag, &self.plaintext, "", @splat(0), self.keys[slot]);
            std.mem.doNotOptimizeAway(&self.tag);
        }
    };
}

/// HMAC-SHA256 under a key held fixed against random keys: every HKDF step of the key schedule,
/// the Finished and binder MACs, the cookie MAC.
const Mac = struct {
    const H = std.crypto.auth.hmac.sha2.HmacSha256;
    keys: [slots][32]u8 = undefined,
    out: [32]u8 = undefined,
    failures: usize = 0,
    pub fn prepare(self: *Mac, slot: usize, class: leak.Class, random: std.Random) void {
        switch (class) {
            .fixed => self.keys[slot] = @splat(0x5c),
            .random => random.bytes(&self.keys[slot]),
        }
    }
    pub fn call(self: *Mac, slot: usize) void {
        H.create(&self.out, "tls13 derived", &self.keys[slot]);
        std.mem.doNotOptimizeAway(&self.out);
    }
};

/// Signing with a held key: ECDSA's hedged nonce from fixed noise (zeros) against random noise;
/// RSA's blinded private operation over a fixed message against random ones.
const Sign = struct {
    key: cloak.PrivateKey,
    algorithm: cloak.certificates.certificate.Algorithm.Signature,
    over_message: bool,
    noise: [slots][cloak.PrivateKey.max_noise]u8 = undefined,
    messages: [slots][32]u8 = undefined,
    out: [cloak.PrivateKey.max_signature]u8 = undefined,
    failures: usize = 0,
    pub fn prepare(self: *Sign, slot: usize, class: leak.Class, random: std.Random) void {
        random.bytes(&self.noise[slot]);
        random.bytes(&self.messages[slot]);
        switch (class) {
            .fixed => if (self.over_message) {
                self.messages[slot] = @splat(0);
            } else {
                self.noise[slot] = @splat(0);
            },
            .random => {},
        }
    }
    pub fn call(self: *Sign, slot: usize) void {
        const signature = self.key.sign(self.algorithm, &self.messages[slot], self.noise[slot][0..self.key.noiseLength()], &self.out) catch {
            self.failures += 1;
            return;
        };
        std.mem.doNotOptimizeAway(signature.ptr);
    }
};

const Row = struct { name: []const u8, measurements: usize, batch: usize };

fn report(out: *std.Io.Writer, row: Row, r: leak.Report) !void {
    try out.print("{s}: |t| {d:.2} (test {d}), means {d:.1} / {d:.1} ns, {d} measurements: {s}\n", .{ row.name, r.t, r.test_index, r.mean[0], r.mean[1], r.measurements, if (r.leak) "LEAK" else "no leak seen" });
    try out.flush();
}

/// Data-independent timing (Arm FEAT_DIT): on, the listed instructions take time independent of
/// their data, and on Apple's M3 and later the data-memory prefetcher stops reading secrets.
fn setDit() void {
    if (@import("builtin").cpu.arch != .aarch64) return;
    asm volatile ("msr s3_3_c4_c2_5, %[on]"
        :
        : [on] "r" (@as(u64, 1 << 24)),
    );
}

fn failed(out: *std.Io.Writer, row: Row, failures: usize) error{ RowFailed, WriteFailed }!void {
    try out.print("{s}: {d} calls failed; the row timed an error path\n", .{ row.name, failures });
    try out.flush();
    return error.RowFailed;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const args = try init.minimal.args.toSlice(init.arena.allocator());
    var dit = false;
    var prefix: []const u8 = "";
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--dit")) dit = true else prefix = arg;
    }
    if (dit) setDit();
    var buffer: [1024]u8 = undefined;
    var stdout = std.Io.File.stdout().writerStreaming(io, &buffer);
    const out = &stdout.interface;
    var leaks: usize = 0;
    const want = struct {
        fn row(p: []const u8, name: []const u8) bool {
            return std.mem.startsWith(u8, name, p);
        }
    }.row;

    const rows = .{
        .{ Row{ .name = "equal 32 bytes (Choice)", .measurements = 1 << 20, .batch = 32 }, Equal },
        .{ Row{ .name = "P-256 agree (cloak)", .measurements = 1 << 17, .batch = 1 }, Agree(ecdh.P256) },
        .{ Row{ .name = "P-256 public key (cloak)", .measurements = 1 << 17, .batch = 1 }, Public(ecdh.P256) },
        .{ Row{ .name = "P-384 agree", .measurements = 1 << 16, .batch = 1 }, Agree(ecdh.P384) },
        .{ Row{ .name = "X25519 (std)", .measurements = 1 << 17, .batch = 1 }, X25519 },
        .{ Row{ .name = "X25519 share and agree (cloak)", .measurements = 1 << 17, .batch = 1 }, ShareAgree },
        .{ Row{ .name = "HPKE recipient setup (cloak, ECH)", .measurements = 1 << 17, .batch = 1 }, HpkeOpen },
        .{ Row{ .name = "AES-128-GCM seal 1 KiB (std)", .measurements = 1 << 18, .batch = 1 }, Seal(std.crypto.aead.aes_gcm.Aes128Gcm) },
        .{ Row{ .name = "ChaCha20-Poly1305 seal 1 KiB (std)", .measurements = 1 << 18, .batch = 1 }, Seal(std.crypto.aead.chacha_poly.ChaCha20Poly1305) },
        .{ Row{ .name = "HMAC-SHA256 (std)", .measurements = 1 << 19, .batch = 4 }, Mac },
        .{ Row{ .name = "ML-KEM-768 decaps (std)", .measurements = 1 << 17, .batch = 1 }, Decaps },
    };
    inline for (rows) |entry| {
        const row = entry[0];
        if (want(prefix, row.name)) {
            const context = try gpa.create(entry[1]);
            defer gpa.destroy(context);
            context.* = .{};
            if (@hasDecl(entry[1], "init")) context.init();
            if (@hasField(entry[1], "agree")) context.agree.init();
            const r = try leak.run(gpa, io, context, .{ .measurements = row.measurements, .slots = slots, .batch = row.batch, .seed = 0x7175 });
            // A row that timed failures timed the wrong thing.
            if (context.failures != 0) return failed(out, row, context.failures);
            leaks += @intFromBool(r.leak);
            try report(out, row, r);
        }
    }
    const pki = harness.Peer.pki;
    const signers = .{
        .{ Row{ .name = "ECDSA P-256 sign, noise", .measurements = 1 << 16, .batch = 1 }, pki.p256_pem, cloak.certificates.certificate.Algorithm.Signature{ .ecdsa = .sha256 }, false },
        .{ Row{ .name = "ECDSA P-384 sign, noise", .measurements = 1 << 15, .batch = 1 }, pki.p384_pem, cloak.certificates.certificate.Algorithm.Signature{ .ecdsa = .sha384 }, false },
        .{ Row{ .name = "Ed25519 sign (std), message", .measurements = 1 << 16, .batch = 1 }, pki.ed25519_pem, cloak.certificates.certificate.Algorithm.Signature.ed25519, true },
        .{ Row{ .name = "RSA-2048 PKCS#1 sign, message", .measurements = 1 << 13, .batch = 1 }, pki.rsa_pem, cloak.certificates.certificate.Algorithm.Signature{ .rsa = .sha256 }, true },
    };
    inline for (signers) |entry| {
        const row = entry[0];
        if (want(prefix, row.name)) {
            const key = try cloak.PrivateKey.parse(gpa, entry[1], .{});
            defer key.deinit();
            const context = try gpa.create(Sign);
            defer gpa.destroy(context);
            context.* = .{ .key = key, .algorithm = entry[2], .over_message = entry[3] };
            const r = try leak.run(gpa, io, context, .{ .measurements = row.measurements, .slots = @min(slots, row.measurements / 2), .batch = row.batch, .seed = 0x7175 });
            if (context.failures != 0) return failed(out, row, context.failures);
            leaks += @intFromBool(r.leak);
            try report(out, row, r);
        }
    }
    if (leaks != 0) std.process.exit(1);
}
