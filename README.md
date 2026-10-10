# cloak

Work in progress: credentials, certificate verification and a TLS 1.3 client and server for Zig. Both roles exist as a stream, a sans-I/O connection and a QUIC handshake; TLS 1.2, resumption and datagrams are not built yet.

## Install

Requires Zig 0.17.0. Pin a reviewed commit:

```sh
zig fetch --save git+https://github.com/pedronaugusto/cloak#<commit>
```

## Usage

Load trust before traffic and retain a snapshot while using its issuer index. The verifier takes explicit time, name, policy generations and a completion token:

<!-- BEGIN GENERATED zig build docs -- usage -->
```zig
const std = @import("std");
const cloak = @import("cloak");

pub fn authenticate(
    gpa: std.mem.Allocator,
    roots: []const []const u8,
    chain: []const []const u8,
    name: []const u8,
    time: std.Io.Timestamp,
    token: cloak.types.Token,
) !cloak.types.Verification {
    @setRuntimeSafety(true);
    var trust = cloak.Trust.init(gpa);
    defer trust.deinit();
    for (roots) |der| try trust.addDer(der, .{});
    const snapshot = try trust.freeze();
    defer snapshot.deinit();
    return cloak.verify.indexed(gpa, .{
        .chain = chain,
        .identity = .{ .dns = name },
        .time = time,
        .trust_generation = snapshot.generation(),
        .policy_generation = .fromRaw(1),
        .token = token,
    }, snapshot.issuers());
}
```
<!-- END GENERATED zig build docs -- usage -->

The returned receipt owns the selected DER path; its caller calls `deinit()`. Check it against the unchanged request before accepting a service completion. Snapshot generations are scoped to their builder; reload across owners also changes the caller's policy generation and completion token.

`PrivateKey.parse` owns its material and wipes it on final release. RSA parsing requires fresh caller CSPRNG witnesses through `PrivateKey.Entropy.fromIo(&io)`. Passphrases and Io are borrowed only for the parse call. `Identity.init` copies the chain, checks the leaf key and retains the key; `ClientAuth` shares that immutable identity.

Native system trust uses `NativeVerification` with an empty explicit-anchor list. A finite timeout requires a bounded caller executor before inputs are copied. The executor owns the completion until it runs and releases it, including after abandonment and during shutdown. The driver applies portable floors to the exact OS-selected chain before returning a receipt. See [ownership and integration](docs/design.md).

A TLS client over any `std.Io` reader and writer:

<!-- BEGIN GENERATED zig build docs -- session -->
```zig
const std = @import("std");
const cloak = @import("cloak");

pub fn fetch(
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    roots: cloak.Trust.Snapshot,
    host: []const u8,
) !void {
    @setRuntimeSafety(true);
    var transport_in: [16 * 1024]u8 = undefined;
    var transport_out: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &transport_in);
    var writer = stream.writer(io, &transport_out);
    var session: cloak.tls.Session = undefined;
    var plain_in: [4096]u8 = undefined;
    var plain_out: [4096]u8 = undefined;
    try session.open(gpa, io, &reader.interface, &writer.interface, &plain_in, &plain_out, .{
        .identity = .{ .dns = host },
        .trust = .{ .snapshot = roots },
        .alpn = &.{"http/1.1"},
    });
    defer session.deinit();
    try session.writer().print("GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host});
    try session.writer().flush();
    var response: [4096]u8 = undefined;
    const n = try session.reader().readSliceShort(&response);
    std.mem.doNotOptimizeAway(response[0..n]);
    try session.finish();
}
```
<!-- END GENERATED zig build docs -- session -->

The server side of the same session. Cloak signs the CertificateVerify with the key of the chosen credential for ECDSA on P-256 and P-384 and for Ed25519. A credential made with `Identity.initExternal` holds no key, and so does an RSA one for now (RSA-PSS signing comes with TLS 1.2): `signer` signs for those, and the connection checks the signature against the leaf before it sends it.

<!-- BEGIN GENERATED zig build docs -- serve -->
```zig
const std = @import("std");
const cloak = @import("cloak");

pub fn serve(
    gpa: std.mem.Allocator,
    io: std.Io,
    stream: std.Io.net.Stream,
    credentials: []const cloak.tls.Credential,
) !void {
    @setRuntimeSafety(true);
    var transport_in: [16 * 1024]u8 = undefined;
    var transport_out: [16 * 1024]u8 = undefined;
    var reader = stream.reader(io, &transport_in);
    var writer = stream.writer(io, &transport_out);
    var session: cloak.tls.Session = undefined;
    var plain_in: [4096]u8 = undefined;
    var plain_out: [4096]u8 = undefined;
    try session.accept(gpa, io, &reader.interface, &writer.interface, &plain_in, &plain_out, .{
        .credentials = credentials,
        .alpn = &.{"http/1.1"},
    });
    defer session.deinit();
    const request = try session.reader().peekGreedy(1);
    std.mem.doNotOptimizeAway(request);
    try session.writer().writeAll("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n");
    try session.writer().flush();
    try session.finish();
}
```
<!-- END GENERATED zig build docs -- serve -->

The same client without I/O is `cloak.tls.Connection`: feed it bytes, write what it holds, and answer its requests for entropy, time and peer verification, and for signing when a key is held elsewhere. `cloak.tls.quic.Handshake` is the record-free form for QUIC. Verification has no default: pass a trust snapshot, a verifier of your own, or `.none` and accept an unauthenticated connection.

## Design

One owner per state. Runtime code uses [aegis](https://github.com/pedronaugusto/aegis), Zig's standard library and native platform trust APIs. Credentials, verification and native services import only lower certificate, wire and value layers. The portable core takes explicit time and trust; it performs no network discovery.

## Scope

Cloak implements credentials and certificate verification, and a TLS 1.3 client and server: X25519MLKEM768, X25519, P-256 and P-384 key exchange, AES-GCM and ChaCha20-Poly1305, ALPN, SNI, client certificates, key updates and exporters, as a stream, a sans-I/O connection and a QUIC handshake. The server holds no private key: it asks its caller to sign. It has no TLS 1.2, resumption, early data or datagram transport yet, and has had no independent security review. No application protocol, dialer or resolver lives here.

The build exposes one module, `cloak`, with `cloak.certificates` for certificates, keys and trust and
`cloak.tls` for TLS as namespaces; the credential names are also at the root. TLS builds on the certificates, which link the native trust store, so a separate module for either would link the same code and fetch the same packages. Zig analyzes only what you use. DTLS will be another namespace when its datagram implementation is built.

## Platforms

Portable verification uses explicit trust. Linux and BSD system policy loads bounded root files. macOS and Windows system policy requires native verification with network retrieval disabled.

## Built with

[preflight](https://github.com/pedronaugusto/preflight) supplies the build and CI gate. [shakedown](https://github.com/pedronaugusto/shakedown) is a lazy test-only dependency. Neither belongs to the runtime closure.

## Testing

```sh
zig build test -Dtest-filter=trust
zig build lint
zig build check
zig build bench
```

CI plans come from `zig build plan`. Benchmarks compile in CI; measurements run by hand in ReleaseFast. `zig build check-wasm` executes portable vectors without hosted Io. `zig build fuzz -Dtest-filter="credential key parser fuzz" --fuzz=100K` uses the compiler fuzz runner. Source functions explicitly retain runtime safety in ReleaseFast; optimized parser, credential and service checks are part of lint.

## Licence

MIT; see [LICENSE](LICENSE).

## Security

Report vulnerabilities privately through GitHub private vulnerability reporting,
never in public issues. See [SECURITY.md](SECURITY.md) for supported versions and
the reporting policy.
